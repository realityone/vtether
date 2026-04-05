/// Packet parsing helpers -- ETH/IPv4/TCP header types, pointer bounds checking,
/// and field read/write for packed structs.
///
/// Simplified from vtether-xdp: requires IHL==5 (no IP options), so L4_OFF=34
/// is constant. A single bounds check of `data + 54 <= data_end` upfront
/// satisfies the eBPF verifier.
use aya_ebpf::programs::XdpContext;
use core::mem;
use core::ptr::addr_of;

use crate::conntrack::Ipv4CtTuple;

// ---- Constants ----

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_HDR_LEN: usize = 14;
pub const IPPROTO_TCP: u8 = 6;

// Constant L4 offset: ETH (14) + IPv4 with IHL=5 (20) = 34
pub const L4_OFF: usize = ETH_HDR_LEN + 20;

// TCP header field offsets (bytes from start of TCP header)
pub const TCP_SPORT_OFF: usize = 0;
pub const TCP_DPORT_OFF: usize = 2;
pub const TCP_FLAGS_OFF: usize = 13;
pub const TCP_CSUM_OFF: usize = 16;

// TCP flags
#[allow(dead_code)]
pub const TCP_FIN: u8 = 0x01;
#[allow(dead_code)]
pub const TCP_SYN: u8 = 0x02;
#[allow(dead_code)]
pub const TCP_RST: u8 = 0x04;
#[allow(dead_code)]
pub const TCP_ACK: u8 = 0x10;

// ---- Packet headers ----

/// Ethernet header (14 bytes).
#[repr(C, packed)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

/// IPv4 header (20 bytes without options).
#[repr(C, packed)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

// ---- Pointer helpers ----

/// Bounds-checked pointer into the XDP packet buffer.
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = start + offset;
    if ptr + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok(ptr as *mut T)
}

/// Read a potentially-unaligned field from a packed struct.
#[inline(always)]
pub fn read_field<T: Copy>(ptr: *const T) -> T {
    unsafe { core::ptr::read_unaligned(ptr) }
}

/// Write a potentially-unaligned field in a packed struct.
#[inline(always)]
pub fn write_field<T>(ptr: *mut T, val: T) {
    unsafe { core::ptr::write_unaligned(ptr, val) };
}

// ---- Parsing ----

/// Parse ETH + IPv4 + TCP with a single bounds check.
/// Requires IHL==5 (no IP options), so L4 offset is constant at 34.
/// Returns (ip_ptr, L4_OFF).
#[inline(always)]
pub fn parse_ipv4_tcp_validated(ctx: &XdpContext) -> Result<(*mut Ipv4Hdr, usize), ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // Single bounds check: ETH (14) + IPv4 (20) + TCP header (20) = 54 bytes.
    if start + L4_OFF + 20 > end {
        return Err(());
    }

    // Check ethertype is IPv4
    let eth: *const EthHdr = start as *const EthHdr;
    let proto = u16::from_be(read_field(unsafe { addr_of!((*eth).h_proto) }));
    if proto != ETH_P_IP {
        return Err(());
    }

    let ip: *mut Ipv4Hdr = (start + ETH_HDR_LEN) as *mut Ipv4Hdr;

    let protocol = read_field(unsafe { addr_of!((*ip).protocol) });
    if protocol != IPPROTO_TCP {
        return Err(());
    }

    // Reject non-initial fragments
    let frag_off = u16::from_be(read_field(unsafe { addr_of!((*ip).frag_off) }));
    if frag_off & 0x1FFF != 0 {
        return Err(());
    }

    // Reject IP options (IHL != 5). Keeps l4_off constant at 34.
    let ver_ihl = read_field(unsafe { addr_of!((*ip).ver_ihl) });
    if ver_ihl & 0x0F != 5 {
        return Err(());
    }

    Ok((ip, L4_OFF))
}

/// Extract a CT tuple from parsed IPv4 + TCP headers.
/// The `flags` field is NOT set here -- the caller sets it.
#[inline(always)]
pub fn extract_tuple(
    ctx: &XdpContext,
    ip: *const Ipv4Hdr,
    l4_off: usize,
) -> Result<Ipv4CtTuple, ()> {
    let daddr = read_field(unsafe { addr_of!((*ip).daddr) });
    let saddr = read_field(unsafe { addr_of!((*ip).saddr) });

    let sport = read_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)? as *const u16);
    let dport = read_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)? as *const u16);

    Ok(Ipv4CtTuple {
        daddr,
        saddr,
        dport,
        sport,
        nexthdr: IPPROTO_TCP,
        flags: 0,
    })
}

/// Load TCP flags byte from the packet.
#[inline(always)]
pub fn load_tcp_flags(ctx: &XdpContext, l4_off: usize) -> Result<u8, ()> {
    let flags_ptr = ptr_at::<u8>(ctx, l4_off + TCP_FLAGS_OFF)?;
    Ok(read_field(flags_ptr as *const u8))
}
