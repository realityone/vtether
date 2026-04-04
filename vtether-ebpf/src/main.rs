#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use core::mem;
use core::ptr::{addr_of, addr_of_mut};

// ---- Constants ----

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const ETH_HDR_LEN: usize = 14;

// TCP checksum offset within TCP header
const TCP_CSUM_OFF: usize = 16;
// UDP checksum offset within UDP header
const UDP_CSUM_OFF: usize = 6;

// ---- Packet headers ----

#[repr(C, packed)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16,
}

#[repr(C, packed)]
struct Ipv4Hdr {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C, packed)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C, packed)]
struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    check: u16,
}

// ---- Map key/value types ----

#[repr(C)]
pub struct NatKey {
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

#[repr(C)]
pub struct NatConfigEntry {
    pub dst_ip: u32,
    pub snat_ip: u32,
}

#[repr(C)]
pub struct ConntrackKey {
    pub client_ip: u32,
    pub client_port: u16,
    pub svc_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct ConntrackValue {
    pub snat_ip: u32,
    pub dst_ip: u32,
}

#[repr(C)]
pub struct ConntrackRevKey {
    pub dst_ip: u32,
    pub svc_port: u16,
    pub client_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct ConntrackRevValue {
    pub client_ip: u32,
    pub snat_ip: u32,
}

// ---- Maps ----

#[map]
static NAT_CONFIG: HashMap<NatKey, NatConfigEntry> = HashMap::with_max_entries(128, 0);

#[map]
static CONNTRACK_OUT: LruHashMap<ConntrackKey, ConntrackValue> =
    LruHashMap::with_max_entries(65536, 0);

#[map]
static CONNTRACK_IN: LruHashMap<ConntrackRevKey, ConntrackRevValue> =
    LruHashMap::with_max_entries(65536, 0);

// ---- Checksum helpers ----

#[inline(always)]
fn csum_fold(mut csum: u64) -> u16 {
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    !(csum as u16)
}

/// Incrementally update a checksum when a 32-bit field changes.
/// All values are raw from the packet (network byte order).
#[inline(always)]
fn csum_replace4(check_ptr: *mut u16, old: u32, new: u32) {
    let old_check = unsafe { core::ptr::read_unaligned(check_ptr) };
    let mut csum = !(old_check) as u64;
    csum += !((old >> 16) as u16) as u64 + !((old & 0xFFFF) as u16) as u64;
    csum += ((new >> 16) as u16) as u64 + ((new & 0xFFFF) as u16) as u64;
    let folded = csum_fold(csum);
    unsafe { core::ptr::write_unaligned(check_ptr, folded) };
}

// ---- Helpers for packed struct field access ----

#[inline(always)]
fn read_field<T: Copy>(ptr: *const T) -> T {
    unsafe { core::ptr::read_unaligned(ptr) }
}

#[inline(always)]
fn write_field<T>(ptr: *mut T, val: T) {
    unsafe { core::ptr::write_unaligned(ptr, val) };
}

// ---- XDP program ----

#[xdp]
pub fn vtether_xdp(ctx: XdpContext) -> u32 {
    match try_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => aya_ebpf::bindings::xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = start + offset;
    if ptr + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok(ptr as *mut T)
}

/// Update the transport-layer (TCP or UDP) checksum after IP address rewrites.
#[inline(always)]
fn update_transport_csum(
    ctx: &XdpContext,
    transport_offset: usize,
    protocol: u8,
    old1: u32,
    new1: u32,
    old2: u32,
    new2: u32,
) -> Result<(), ()> {
    if protocol == IPPROTO_TCP {
        let ck: *mut u16 = ptr_at(ctx, transport_offset + TCP_CSUM_OFF)?;
        csum_replace4(ck, old1, new1);
        csum_replace4(ck, old2, new2);
    } else {
        // UDP: checksum of 0 means "not computed", don't touch it
        let ck: *mut u16 = ptr_at(ctx, transport_offset + UDP_CSUM_OFF)?;
        if read_field(ck as *const u16) != 0 {
            csum_replace4(ck, old1, new1);
            csum_replace4(ck, old2, new2);
        }
    }
    Ok(())
}

fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;

    // --- Parse Ethernet ---
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    let ether_type = read_field(unsafe { addr_of!((*eth).ether_type) });
    if u16::from_be(ether_type) != ETH_P_IP {
        return Ok(pass);
    }

    // --- Parse IPv4 ---
    let ip: *mut Ipv4Hdr = ptr_at(ctx, ETH_HDR_LEN)?;
    let protocol = read_field(unsafe { addr_of!((*ip).protocol) });
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(pass);
    }
    let ver_ihl = read_field(unsafe { addr_of!((*ip).ver_ihl) });
    let ihl = (ver_ihl & 0x0F) as usize;
    let ip_hdr_len = ihl * 4;
    if ip_hdr_len < 20 || ip_hdr_len > 60 {
        return Ok(pass);
    }

    let transport_offset = ETH_HDR_LEN + ip_hdr_len;

    // --- Read ports (same layout for TCP and UDP) ---
    let src_port_ptr: *const u16 = ptr_at(ctx, transport_offset)?;
    let dst_port_ptr: *const u16 = ptr_at(ctx, transport_offset + 2)?;

    let src_ip = read_field(unsafe { addr_of!((*ip).src_addr) });
    let dst_ip = read_field(unsafe { addr_of!((*ip).dst_addr) });
    let src_port = read_field(src_port_ptr);
    let dst_port = read_field(dst_port_ptr);
    let dst_port_host = u16::from_be(dst_port);

    // === FORWARD PATH: client -> THIS_MACHINE:svc_port ===
    let nat_key = NatKey {
        port: dst_port_host,
        protocol,
        _pad: 0,
    };
    if let Some(config) = unsafe { NAT_CONFIG.get(&nat_key) } {
        let new_dst = config.dst_ip;
        let new_src = config.snat_ip;

        // DNAT + SNAT
        write_field(unsafe { addr_of_mut!((*ip).dst_addr) }, new_dst);
        write_field(unsafe { addr_of_mut!((*ip).src_addr) }, new_src);

        // Update IP header checksum
        let ip_ck = unsafe { addr_of_mut!((*ip).check) };
        csum_replace4(ip_ck, dst_ip, new_dst);
        csum_replace4(ip_ck, src_ip, new_src);

        // Update transport checksum
        update_transport_csum(ctx, transport_offset, protocol, dst_ip, new_dst, src_ip, new_src)?;

        // Insert conntrack entries
        let fwd_key = ConntrackKey {
            client_ip: src_ip,
            client_port: src_port,
            svc_port: dst_port,
            protocol,
            _pad: [0; 3],
        };
        let fwd_val = ConntrackValue {
            snat_ip: config.snat_ip,
            dst_ip: config.dst_ip,
        };
        let _ = CONNTRACK_OUT.insert(&fwd_key, &fwd_val, 0);

        let rev_key = ConntrackRevKey {
            dst_ip: config.dst_ip,
            svc_port: dst_port,
            client_port: src_port,
            protocol,
            _pad: [0; 3],
        };
        let rev_val = ConntrackRevValue {
            client_ip: src_ip,
            snat_ip: config.snat_ip,
        };
        let _ = CONNTRACK_IN.insert(&rev_key, &rev_val, 0);

        return Ok(pass);
    }

    // === RETURN PATH: DST_IP:svc_port -> THIS_MACHINE:client_port ===
    let rev_key = ConntrackRevKey {
        dst_ip: src_ip,
        svc_port: src_port,
        client_port: dst_port,
        protocol,
        _pad: [0; 3],
    };
    if let Some(rev) = unsafe { CONNTRACK_IN.get(&rev_key) } {
        let new_src = rev.snat_ip;
        let new_dst = rev.client_ip;

        // Reverse SNAT + DNAT
        write_field(unsafe { addr_of_mut!((*ip).src_addr) }, new_src);
        write_field(unsafe { addr_of_mut!((*ip).dst_addr) }, new_dst);

        // Update checksums
        let ip_ck = unsafe { addr_of_mut!((*ip).check) };
        csum_replace4(ip_ck, src_ip, new_src);
        csum_replace4(ip_ck, dst_ip, new_dst);

        update_transport_csum(ctx, transport_offset, protocol, src_ip, new_src, dst_ip, new_dst)?;

        return Ok(pass);
    }

    Ok(pass)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
