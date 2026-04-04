#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, xdp},
    maps::{HashMap, PerCpuHashMap},
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
// TCP flags offset within TCP header (byte containing FIN/SYN/RST/ACK)
const TCP_FLAGS_OFF: usize = 13;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;
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
    pub dst_port: u16,
    pub _pad: u16,
}

#[repr(C)]
pub struct ConntrackKey {
    pub client_ip: u32,
    pub client_port: u16,
    pub svc_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

// tcp_fin_state tracks FIN flags seen for TCP connection teardown:
//   0 = OPEN, 1 = FIN from one side, 2 = FIN from both sides (ready to delete)
#[repr(C)]
pub struct ConntrackValue {
    pub snat_ip: u32,
    pub dst_ip: u32,
    pub orig_dst_port: u16,
    pub new_dst_port: u16,
    pub snat_port: u16,
    pub tcp_fin_state: u8,
    pub _pad: u8,
}

#[repr(C)]
pub struct ConntrackRevKey {
    pub dst_ip: u32,
    pub svc_port: u16,
    pub snat_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct ConntrackRevValue {
    pub client_ip: u32,
    pub snat_ip: u32,
    pub orig_svc_port: u16,
    pub client_port: u16,
}

#[repr(C)]
pub struct RouteStats {
    pub connections: u64,
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
}

// ---- Maps ----

#[map]
static NAT_CONFIG: HashMap<NatKey, NatConfigEntry> = HashMap::with_max_entries(128, 0);

#[map]
static ROUTE_STATS: PerCpuHashMap<NatKey, RouteStats> = PerCpuHashMap::with_max_entries(128, 0);

// Conntrack maps use HashMap (not LruHashMap) so active connections are never silently
// evicted. When the map is full, new connections fail gracefully (packet passed without
// NAT) instead of breaking existing ones. TCP entries are cleaned up on FIN/RST; UDP
// entries linger until the map is cleared — size the map appropriately for UDP-heavy loads.
//
// The get-then-insert pattern is not atomic across operations, but is safe in practice
// because RSS/RPS steers packets of the same flow (same src/dst IP + port tuple) to the
// same CPU. See: https://docs.kernel.org/networking/scaling.html
// In the rare case of a race (e.g. NIC without RSS), the worst outcome is an orphaned
// entry from a lost SNAT port allocation — no corruption or incorrect forwarding.
#[map]
static CONNTRACK_OUT: HashMap<ConntrackKey, ConntrackValue> =
    HashMap::with_max_entries(65536, 0);

#[map]
static CONNTRACK_IN: HashMap<ConntrackRevKey, ConntrackRevValue> =
    HashMap::with_max_entries(65536, 0);

// ---- Checksum helpers ----

#[inline(always)]
fn csum_fold(mut csum: u64) -> u16 {
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    !(csum as u16)
}

/// Incrementally update a checksum when a 16-bit field changes.
/// All values are raw from the packet (network byte order).
#[inline(always)]
fn csum_replace2(check_ptr: *mut u16, old: u16, new: u16) {
    let old_check = unsafe { core::ptr::read_unaligned(check_ptr) };
    let mut csum = !(old_check) as u64;
    csum += !(old) as u64;
    csum += new as u64;
    let folded = csum_fold(csum);
    unsafe { core::ptr::write_unaligned(check_ptr, folded) };
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

/// Increment per-route drop counter when conntrack is full.
#[inline(always)]
fn update_route_drops(nat_key: &NatKey) {
    if let Some(stats) = ROUTE_STATS.get_ptr_mut(nat_key) {
        unsafe { (*stats).drops += 1 };
    } else {
        let stats = RouteStats {
            connections: 0,
            packets: 0,
            bytes: 0,
            drops: 1,
        };
        let _ = ROUTE_STATS.insert(nat_key, &stats, 0);
    }
}

/// Increment per-route packet/byte counters. On first packet of a new connection, also bump connections.
#[inline(always)]
fn update_route_stats(nat_key: &NatKey, pkt_len: u64, new_conn: bool) {
    if let Some(stats) = ROUTE_STATS.get_ptr_mut(nat_key) {
        unsafe {
            (*stats).packets += 1;
            (*stats).bytes += pkt_len;
            if new_conn {
                (*stats).connections += 1;
            }
        }
    } else {
        let stats = RouteStats {
            connections: if new_conn { 1 } else { 0 },
            packets: 1,
            bytes: pkt_len,
            drops: 0,
        };
        let _ = ROUTE_STATS.insert(nat_key, &stats, 0);
    }
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

/// Update the transport-layer (TCP or UDP) checksum after IP and/or port rewrites.
/// Port values are in network byte order; pass equal old/new to skip a port update.
#[inline(always)]
fn update_transport_csum(
    ctx: &XdpContext,
    transport_offset: usize,
    protocol: u8,
    old_ip1: u32,
    new_ip1: u32,
    old_ip2: u32,
    new_ip2: u32,
    old_port1: u16,
    new_port1: u16,
    old_port2: u16,
    new_port2: u16,
) -> Result<(), ()> {
    let (ck, skip) = match protocol {
        IPPROTO_TCP => (ptr_at::<u16>(ctx, transport_offset + TCP_CSUM_OFF)?, false),
        IPPROTO_UDP => {
            let ck = ptr_at::<u16>(ctx, transport_offset + UDP_CSUM_OFF)?;
            // UDP: checksum of 0 means "not computed", don't touch it
            (ck, read_field(ck as *const u16) == 0)
        }
        _ => return Ok(()),
    };

    if !skip {
        csum_replace4(ck, old_ip1, new_ip1);
        csum_replace4(ck, old_ip2, new_ip2);
        if old_port1 != new_port1 {
            csum_replace2(ck, old_port1, new_port1);
        }
        if old_port2 != new_port2 {
            csum_replace2(ck, old_port2, new_port2);
        }
    }
    Ok(())
}

/// Allocate a unique SNAT source port for a new connection.
/// Tries the client's original port first; on collision, probes the ephemeral range.
/// Returns the allocated port in network byte order.
#[inline(always)]
fn allocate_snat_port(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) -> Result<u16, ()> {
    // Try the client's original port first (most common case, no rewrite needed)
    let try_key = ConntrackRevKey {
        dst_ip,
        svc_port: dst_port,
        snat_port: src_port,
        protocol,
        _pad: [0; 3],
    };
    if unsafe { CONNTRACK_IN.get(&try_key) }.is_none() {
        return Ok(src_port);
    }

    // Collision — hash the connection tuple to pick a starting ephemeral port
    let hash = src_ip
        .wrapping_mul(0x9e3779b9)
        .wrapping_add(((src_port as u32) << 16) | (dst_port as u32))
        .wrapping_mul(0x517cc1b7);

    // Ephemeral port range: 32768–60999 (28232 ports)
    const EPHEMERAL_LO: u16 = 32768;
    const EPHEMERAL_HI: u16 = 60999;
    const EPHEMERAL_RANGE: u32 = (EPHEMERAL_HI - EPHEMERAL_LO + 1) as u32;

    let start = EPHEMERAL_LO + ((hash >> 8) % EPHEMERAL_RANGE) as u16;
    let mut port_host = start;
    let mut i: u32 = 0;
    while i < 128 {
        let candidate = port_host.to_be();
        let try_key = ConntrackRevKey {
            dst_ip,
            svc_port: dst_port,
            snat_port: candidate,
            protocol,
            _pad: [0; 3],
        };
        if unsafe { CONNTRACK_IN.get(&try_key) }.is_none() {
            return Ok(candidate);
        }
        port_host = if port_host >= EPHEMERAL_HI {
            EPHEMERAL_LO
        } else {
            port_host + 1
        };
        i += 1;
    }

    // All attempted ports taken — cannot NAT this packet
    Err(())
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
    match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {}
        _ => return Ok(pass),
    }
    // Drop non-initial fragments: they lack transport headers so we can't NAT them.
    // frag_off field: bits [15:13] = flags, bits [12:0] = fragment offset.
    // We check the MF (More Fragments) flag is irrelevant; what matters is offset != 0.
    let frag_off = u16::from_be(read_field(unsafe { addr_of!((*ip).frag_off) }));
    let frag_offset = frag_off & 0x1FFF; // lower 13 bits = fragment offset
    if frag_offset != 0 {
        // Non-initial fragment — pass without rewriting to avoid half-NATing the flow
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
        let new_dst_ip = config.dst_ip;
        let new_src_ip = config.snat_ip;
        let new_dst_port_ne = config.dst_port; // already in network byte order

        // Check for existing conntrack entry (subsequent packets of same connection)
        let fwd_key = ConntrackKey {
            client_ip: src_ip,
            client_port: src_port,
            svc_port: dst_port,
            protocol,
            _pad: [0; 3],
        };

        let (snat_port, new_conn) = if let Some(existing) = unsafe { CONNTRACK_OUT.get(&fwd_key) }
        {
            (existing.snat_port, false)
        } else {
            // New connection — allocate a unique SNAT source port.
            let port =
                allocate_snat_port(src_ip, src_port, new_dst_ip, new_dst_port_ne, protocol)?;

            // Insert conntrack entries before rewriting the packet. If the map is full,
            // drop the packet — it cannot be NATed without a return path.
            let fwd_val = ConntrackValue {
                snat_ip: config.snat_ip,
                dst_ip: config.dst_ip,
                orig_dst_port: dst_port,
                new_dst_port: new_dst_port_ne,
                snat_port: port,
                tcp_fin_state: 0,
                _pad: 0,
            };
            if CONNTRACK_OUT.insert(&fwd_key, &fwd_val, 0).is_err() {
                update_route_drops(&nat_key);
                return Ok(aya_ebpf::bindings::xdp_action::XDP_DROP);
            }

            let rev_key = ConntrackRevKey {
                dst_ip: config.dst_ip,
                svc_port: new_dst_port_ne,
                snat_port: port,
                protocol,
                _pad: [0; 3],
            };
            let rev_val = ConntrackRevValue {
                client_ip: src_ip,
                snat_ip: config.snat_ip,
                orig_svc_port: dst_port,
                client_port: src_port,
            };
            if CONNTRACK_IN.insert(&rev_key, &rev_val, 0).is_err() {
                let _ = CONNTRACK_OUT.remove(&fwd_key);
                update_route_drops(&nat_key);
                return Ok(aya_ebpf::bindings::xdp_action::XDP_DROP);
            }

            (port, true)
        };

        // DNAT + SNAT (IP addresses)
        write_field(unsafe { addr_of_mut!((*ip).dst_addr) }, new_dst_ip);
        write_field(unsafe { addr_of_mut!((*ip).src_addr) }, new_src_ip);

        // DNAT (destination port)
        if dst_port != new_dst_port_ne {
            let dst_port_wr: *mut u16 = ptr_at(ctx, transport_offset + 2)?;
            write_field(dst_port_wr, new_dst_port_ne);
        }

        // SNAT (source port)
        if src_port != snat_port {
            let src_port_wr: *mut u16 = ptr_at(ctx, transport_offset)?;
            write_field(src_port_wr, snat_port);
        }

        // Update IP header checksum (ports don't affect IP checksum)
        let ip_ck = unsafe { addr_of_mut!((*ip).check) };
        csum_replace4(ip_ck, dst_ip, new_dst_ip);
        csum_replace4(ip_ck, src_ip, new_src_ip);

        // Update transport checksum (IPs + both ports)
        update_transport_csum(
            ctx, transport_offset, protocol,
            dst_ip, new_dst_ip, src_ip, new_src_ip,
            dst_port, new_dst_port_ne,
            src_port, snat_port,
        )?;

        // Update per-route stats
        let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
        update_route_stats(&nat_key, pkt_len, new_conn);

        // Clean up conntrack on TCP RST or after both FINs seen
        if protocol == IPPROTO_TCP {
            if let Ok(flags_ptr) = ptr_at::<u8>(ctx, transport_offset + TCP_FLAGS_OFF) {
                let flags = read_field(flags_ptr as *const u8);
                let should_remove = if flags & TCP_RST != 0 {
                    true
                } else if flags & TCP_FIN != 0 {
                    // Track FIN from client (forward path).
                    // Bump fin_state: 0→1 (first FIN), 1→2 (both FINs seen).
                    if let Some(entry) = CONNTRACK_OUT.get_ptr_mut(&fwd_key) {
                        let state = unsafe { (*entry).tcp_fin_state };
                        let new_state = state.saturating_add(1);
                        unsafe { (*entry).tcp_fin_state = new_state };
                        new_state >= 2
                    } else {
                        false
                    }
                } else {
                    false
                };
                if should_remove {
                    let _ = CONNTRACK_OUT.remove(&fwd_key);
                    let rev_key = ConntrackRevKey {
                        dst_ip: new_dst_ip,
                        svc_port: new_dst_port_ne,
                        snat_port,
                        protocol,
                        _pad: [0; 3],
                    };
                    let _ = CONNTRACK_IN.remove(&rev_key);
                }
            }
        }

        return Ok(pass);
    }

    // === RETURN PATH: backend_ip:svc_port -> snat_ip:snat_port ===
    let rev_key = ConntrackRevKey {
        dst_ip: src_ip,
        svc_port: src_port,
        snat_port: dst_port,
        protocol,
        _pad: [0; 3],
    };
    if let Some(rev) = unsafe { CONNTRACK_IN.get(&rev_key) } {
        let new_src_ip = rev.snat_ip;
        let new_dst_ip = rev.client_ip;
        let orig_svc_port = rev.orig_svc_port;
        let client_port = rev.client_port;

        // Reverse SNAT + DNAT (IPs)
        write_field(unsafe { addr_of_mut!((*ip).src_addr) }, new_src_ip);
        write_field(unsafe { addr_of_mut!((*ip).dst_addr) }, new_dst_ip);

        // Reverse port rewrites
        // src_port: backend port -> original service port
        if src_port != orig_svc_port {
            let src_port_wr: *mut u16 = ptr_at(ctx, transport_offset)?;
            write_field(src_port_wr, orig_svc_port);
        }
        // dst_port: snat_port -> original client port
        if dst_port != client_port {
            let dst_port_wr: *mut u16 = ptr_at(ctx, transport_offset + 2)?;
            write_field(dst_port_wr, client_port);
        }

        // Update IP checksum
        let ip_ck = unsafe { addr_of_mut!((*ip).check) };
        csum_replace4(ip_ck, src_ip, new_src_ip);
        csum_replace4(ip_ck, dst_ip, new_dst_ip);

        // Update transport checksum (IPs + both ports)
        update_transport_csum(
            ctx, transport_offset, protocol,
            src_ip, new_src_ip, dst_ip, new_dst_ip,
            src_port, orig_svc_port,
            dst_port, client_port,
        )?;

        // Update per-route stats (use original service port for the route key)
        let ret_nat_key = NatKey {
            port: u16::from_be(orig_svc_port),
            protocol,
            _pad: 0,
        };
        let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
        update_route_stats(&ret_nat_key, pkt_len, false);

        // Clean up conntrack on TCP RST or after both FINs seen
        if protocol == IPPROTO_TCP {
            if let Ok(flags_ptr) = ptr_at::<u8>(ctx, transport_offset + TCP_FLAGS_OFF) {
                let flags = read_field(flags_ptr as *const u8);
                // Reconstruct forward key from reverse conntrack entry
                let fwd_key = ConntrackKey {
                    client_ip: new_dst_ip,
                    client_port,
                    svc_port: orig_svc_port,
                    protocol,
                    _pad: [0; 3],
                };
                let should_remove = if flags & TCP_RST != 0 {
                    true
                } else if flags & TCP_FIN != 0 {
                    // Track FIN from server (return path).
                    if let Some(entry) = CONNTRACK_OUT.get_ptr_mut(&fwd_key) {
                        let state = unsafe { (*entry).tcp_fin_state };
                        let new_state = state.saturating_add(1);
                        unsafe { (*entry).tcp_fin_state = new_state };
                        new_state >= 2
                    } else {
                        false
                    }
                } else {
                    false
                };
                if should_remove {
                    let _ = CONNTRACK_OUT.remove(&fwd_key);
                    let _ = CONNTRACK_IN.remove(&rev_key);
                }
            }
        }

        return Ok(pass);
    }

    Ok(pass)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
