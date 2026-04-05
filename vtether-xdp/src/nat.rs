/// NAT module — SNAT state tracking, port allocation, and header rewrite.
///
/// Cilium equivalents:
/// - `bpf/lib/nat.h` — `__snat_v4_nat()`, `snat_v4_new_mapping()`,
///   `snat_v4_rewrite_headers()`, `snat_v4_rev_nat()`
///
/// # SNAT Port Allocation
///
/// Cilium's `snat_v4_new_mapping()` allocates ports by:
/// 1. Try to keep the client's original port (`__snat_try_keep_port`)
/// 2. On collision, hash-probe the ephemeral range with `SNAT_COLLISION_RETRIES` (128)
///
/// vtether follows the same approach.
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use core::ptr::{addr_of, addr_of_mut};

use crate::conntrack::Ipv4CtTuple;
use crate::csum::{csum_replace2, csum_replace4};
use crate::parse::{
    ptr_at, read_field, write_field, Ipv4Hdr, IPV4_DADDR_OFF, IPV4_SADDR_OFF, TCP_CSUM_OFF,
    TCP_DPORT_OFF, TCP_SPORT_OFF,
};

/// Maximum SNAT port allocation retries.
/// Cilium: `SNAT_COLLISION_RETRIES = 128`.
const SNAT_COLLISION_RETRIES: u32 = 128;

// ---- SNAT direction flags ----

/// Forward direction: used for the SNAT entry (client -> backend path).
/// Cilium: `TUPLE_F_OUT = 0`.
const TUPLE_F_OUT: u8 = 0;
/// Reverse direction: used for the reverse SNAT entry (backend -> client path).
/// Cilium: `TUPLE_F_IN = 1`.
const TUPLE_F_IN: u8 = 1;

// ---- SNAT map key/value types ----

/// SNAT mapping key — reuses the same tuple layout as CT.
///
/// Cilium reuses `struct ipv4_ct_tuple` for SNAT map keys.
/// For the forward SNAT entry: tuple matches the post-DNAT packet
///   {saddr=client, daddr=backend, sport=client_port, dport=backend_port}
/// For the reverse SNAT entry: tuple matches the reply packet
///   {saddr=backend, daddr=snat_ip, sport=backend_port, dport=snat_ephemeral_port}
pub type SnatKey = Ipv4CtTuple;

/// SNAT mapping entry — the map value.
///
/// Cilium equivalent: `struct ipv4_nat_entry`.
/// ```c
/// struct ipv4_nat_entry {
///     struct nat_entry common;  // { created, needs_ct, ... }
///     union {
///         struct { __be32 to_saddr; __be16 to_sport; };  // forward
///         struct { __be32 to_daddr; __be16 to_dport; };  // reverse
///     };
/// };
/// ```
///
/// For forward entry: `to_saddr` = SNAT IP, `to_sport` = ephemeral port.
/// For reverse entry: `to_daddr` = original client IP, `to_dport` = original client port.
#[repr(C)]
pub struct SnatEntry {
    /// Creation timestamp (ns from `bpf_ktime_get_ns()`).
    pub created: u64,
    /// Rewritten IP address (network byte order).
    pub to_addr: u32,
    /// Rewritten port (network byte order).
    pub to_port: u16,
    pub _pad: u16,
}

/// SNAT target configuration — tells SNAT which IP/port range to use.
///
/// Cilium equivalent: `struct ipv4_nat_target`.
pub struct SnatTarget {
    /// SNAT IP address (network byte order).
    pub addr: u32,
    /// Minimum ephemeral port (host byte order).
    pub min_port: u16,
    /// Maximum ephemeral port (host byte order).
    pub max_port: u16,
}

// ---- SNAT map ----

/// Bidirectional SNAT state map.
/// Cilium equivalent: `cilium_snat_v4_external` (LRU_HASH).
#[map]
pub static SNAT4: HashMap<SnatKey, SnatEntry> = HashMap::with_max_entries(131072, 0);

// ---- SNAT key construction ----

/// Build the forward SNAT key from the post-DNAT packet state.
///
/// The forward SNAT key represents the connection as seen after DNAT:
///   {saddr=client_ip, daddr=backend_ip, sport=client_port, dport=backend_port}
///
/// Cilium builds this in `__snat_v4_nat` by extracting the tuple after DNAT
/// and swapping ports to match the packet direction.
#[inline(always)]
fn snat_v4_make_fwd_key(
    client_ip: u32,
    backend_ip: u32,
    client_port: u16,
    backend_port: u16,
) -> SnatKey {
    Ipv4CtTuple {
        saddr: client_ip,
        daddr: backend_ip,
        sport: client_port,
        dport: backend_port,
        nexthdr: crate::parse::IPPROTO_TCP,
        flags: TUPLE_F_OUT,
    }
}

/// Build the reverse SNAT key for reply-path lookup.
///
/// The reverse key matches the reply packet from the backend:
///   {saddr=snat_ip, daddr=backend_ip, sport=snat_port, dport=backend_port}
///
/// Cilium builds this via `set_v4_rtuple()`:
/// ```c
/// rtuple.saddr = ostate->to_saddr;  // SNAT IP
/// rtuple.daddr = otuple->daddr;     // backend IP
/// rtuple.sport = /* selected */;    // ephemeral port
/// rtuple.dport = otuple->dport;     // backend port
/// ```
#[inline(always)]
fn snat_v4_make_rev_key(
    snat_ip: u32,
    backend_ip: u32,
    snat_port: u16,
    backend_port: u16,
) -> SnatKey {
    Ipv4CtTuple {
        saddr: snat_ip,
        daddr: backend_ip,
        sport: snat_port,
        dport: backend_port,
        nexthdr: crate::parse::IPPROTO_TCP,
        flags: TUPLE_F_IN,
    }
}

// ---- SNAT port allocation ----

/// Try to keep the client's original port.
///
/// Cilium equivalent: `__snat_try_keep_port()`.
/// If the original port falls within the ephemeral range, use it.
/// Otherwise, clamp to the range.
#[inline(always)]
fn snat_try_keep_port(min_port: u16, max_port: u16, port: u16) -> u16 {
    if port >= min_port && port <= max_port {
        port
    } else {
        // Clamp: use the port modulo the range
        min_port + (port % (max_port - min_port + 1))
    }
}

/// Clamp a port to the ephemeral range, wrapping on overflow.
///
/// Cilium equivalent: `__snat_clamp_port_range()`.
#[inline(always)]
fn snat_clamp_port_range(min_port: u16, max_port: u16, port: u16) -> u16 {
    if port >= min_port && port <= max_port {
        port
    } else {
        min_port + (port % (max_port - min_port + 1))
    }
}

/// Allocate a new SNAT mapping (forward + reverse entries).
///
/// Cilium equivalent: `snat_v4_new_mapping()`.
///
/// Algorithm:
/// 1. Try the client's original port (most connections avoid collision)
/// 2. On collision, probe the ephemeral range with up to 128 retries
/// 3. Create reverse entry first, then forward entry (with rollback)
///
/// ```c
/// port = __snat_try_keep_port(min, max, ntohs(otuple->sport));
/// for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
///     rtuple.dport = htons(port);
///     if (__snat_create(map, &rtuple, &rstate, true) == 0)
///         goto create_nat_entry;
///     port = __snat_clamp_port_range(min, max, retries ? port+1 : prandom());
/// }
/// ```
#[inline(always)]
fn snat_v4_new_mapping(
    client_ip: u32,
    backend_ip: u32,
    client_port: u16,
    backend_port: u16,
    target: &SnatTarget,
) -> Result<u16, ()> {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Reverse entry value: restores original client IP:port on reply path
    let rstate = SnatEntry {
        created: now,
        to_addr: client_ip,   // to_daddr = original client IP
        to_port: client_port, // to_dport = original client port
        _pad: 0,
    };

    // Try client's original port first
    let orig_port_host = u16::from_be(client_port);
    let mut port = snat_try_keep_port(target.min_port, target.max_port, orig_port_host);

    let mut i: u32 = 0;
    while i < SNAT_COLLISION_RETRIES {
        let snat_port_be = port.to_be();
        let rev_key = snat_v4_make_rev_key(target.addr, backend_ip, snat_port_be, backend_port);

        // Try to create the reverse entry (BPF_NOEXIST = don't overwrite).
        // Cilium: `__snat_create(map, &rtuple, &rstate, true)` where true = BPF_NOEXIST
        if SNAT4.insert(&rev_key, &rstate, aya_ebpf::bindings::BPF_NOEXIST as u64).is_ok() {
            // Success — now create the forward entry
            let fwd_key = snat_v4_make_fwd_key(client_ip, backend_ip, client_port, backend_port);
            let fwd_state = SnatEntry {
                created: now,
                to_addr: target.addr,   // to_saddr = SNAT IP
                to_port: snat_port_be,  // to_sport = ephemeral port
                _pad: 0,
            };

            if SNAT4.insert(&fwd_key, &fwd_state, 0).is_err() {
                // Rollback reverse entry
                let _ = SNAT4.remove(&rev_key);
                return Err(());
            }

            return Ok(snat_port_be);
        }

        // Collision — try next port
        // Cilium: first retry uses prandom, subsequent retries increment
        port = if i == 0 {
            let rand = unsafe { aya_ebpf::helpers::bpf_get_prandom_u32() } as u16;
            snat_clamp_port_range(target.min_port, target.max_port, rand)
        } else {
            snat_clamp_port_range(target.min_port, target.max_port, port + 1)
        };

        i += 1;
    }

    Err(()) // Exhausted all retries
}

// ---- Public SNAT API ----

/// Perform SNAT on the forward path: allocate or reuse a mapping, rewrite headers.
///
/// Cilium equivalent: `__snat_v4_nat()`.
///
/// Flow:
/// 1. `snat_v4_nat_handle_mapping()` — lookup or create SNAT mapping
/// 2. `snat_v4_rewrite_headers()` — rewrite saddr + sport, fix checksums
///
/// This function combines both steps. The `client_ip` and `client_port` are
/// the **original** (pre-SNAT) values from the packet. `backend_ip` and
/// `backend_port` are the post-DNAT values.
#[inline(always)]
pub fn snat_v4_nat(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    client_ip: u32,
    client_port: u16,
    backend_ip: u32,
    backend_port: u16,
    target: &SnatTarget,
) -> Result<u16, ()> {
    // Step 1: Lookup existing SNAT mapping or create new one.
    // Cilium: `snat_v4_nat_handle_mapping()` -> `__snat_lookup()` first.
    let fwd_key = snat_v4_make_fwd_key(client_ip, backend_ip, client_port, backend_port);

    let snat_port = if let Some(existing) = unsafe { SNAT4.get(&fwd_key) } {
        // Existing mapping found. Cilium also checks if the target addr matches
        // and if the reverse entry still exists (recreating if evicted by LRU).
        // Since vtether uses HashMap (no LRU eviction), we skip that check.
        existing.to_port
    } else {
        // No existing mapping — allocate a new one.
        snat_v4_new_mapping(client_ip, backend_ip, client_port, backend_port, target)?
    };

    // Step 2: Rewrite headers.
    // Cilium: `snat_v4_rewrite_headers(ctx, ..., old_saddr, new_saddr, IPV4_SADDR_OFF,
    //          old_sport, new_sport, TCP_SPORT_OFF, 0)`
    snat_v4_rewrite_egress(ctx, ip, l4_off, client_ip, target.addr, client_port, snat_port)?;

    Ok(snat_port)
}

/// Rewrite source IP + port on the egress (forward) path.
///
/// Cilium equivalent: `snat_v4_rewrite_headers()` with addr_off=IPV4_SADDR_OFF,
/// port_off=TCP_SPORT_OFF.
///
/// ```c
/// sum = csum_diff(&old_addr, 4, &new_addr, 4, 0);
/// ctx_store_bytes(ctx, l3_off + addr_off, &new_addr, 4, 0);
/// ipv4_csum_update_by_diff(ctx, l3_off, sum);
/// if (old_port != new_port) l4_modify_port(...);
/// if (csum.offset) csum_l4_replace(ctx, ..., sum, BPF_F_PSEUDO_HDR);
/// ```
#[inline(always)]
fn snat_v4_rewrite_egress(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    old_saddr: u32,
    new_saddr: u32,
    old_sport: u16,
    new_sport: u16,
) -> Result<(), ()> {
    if old_saddr == new_saddr && old_sport == new_sport {
        return Ok(());
    }

    // Rewrite source IP
    write_field(unsafe { addr_of_mut!((*ip).saddr) }, new_saddr);

    // Update IP checksum
    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_saddr, new_saddr);

    // Update TCP checksum for saddr change (pseudo-header)
    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_saddr, new_saddr);

    // Rewrite source port if changed
    if old_sport != new_sport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)?, new_sport);
        csum_replace2(tcp_ck, old_sport, new_sport);
    }

    Ok(())
}

/// Perform reverse SNAT on the reply path: restore original client IP + port.
///
/// Cilium equivalent: `snat_v4_rev_nat()`.
///
/// Flow:
/// 1. Build reverse key from the reply packet
/// 2. Lookup in SNAT4
/// 3. Rewrite daddr + dport back to original client values
///
/// Returns the restored (client_ip, client_port) or Err if no mapping found.
#[inline(always)]
pub fn snat_v4_rev_nat(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
) -> Result<(u32, u16), ()> {
    // Build the reverse lookup key from the reply packet.
    // Reply packet: src=backend_ip:backend_port -> dst=snat_ip:snat_port
    //
    // Cilium's `snat_v4_init_tuple(ip, NAT_DIR_INGRESS, &tuple)` sets:
    //   tuple.saddr = ip->daddr (snat_ip)
    //   tuple.daddr = ip->saddr (backend_ip)
    // Then `ipv4_load_l4_ports` + `ipv4_ct_tuple_swap_ports` produces:
    //   tuple.sport = TCP dport (snat_port)
    //   tuple.dport = TCP sport (backend_port)
    let snat_ip = read_field(unsafe { addr_of!((*ip).daddr) });
    let backend_ip = read_field(unsafe { addr_of!((*ip).saddr) });
    let snat_port = read_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)? as *const u16);
    let backend_port = read_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)? as *const u16);

    let rev_key = snat_v4_make_rev_key(snat_ip, backend_ip, snat_port, backend_port);

    let state = unsafe { SNAT4.get(&rev_key) }.ok_or(())?;

    let client_ip = state.to_addr;   // to_daddr
    let client_port = state.to_port; // to_dport

    // Rewrite destination IP + port back to client's original values.
    // Cilium: `snat_v4_rewrite_headers(ctx, ..., old_daddr, new_daddr, IPV4_DADDR_OFF,
    //          old_dport, new_dport, TCP_DPORT_OFF, ...)`
    let old_daddr = snat_ip;
    let new_daddr = client_ip;
    let old_dport = snat_port;
    let new_dport = client_port;

    if old_daddr == new_daddr && old_dport == new_dport {
        return Ok((client_ip, client_port));
    }

    // Rewrite destination IP
    write_field(unsafe { addr_of_mut!((*ip).daddr) }, new_daddr);

    // Update IP checksum
    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_daddr, new_daddr);

    // Update TCP checksum for daddr change (pseudo-header)
    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_daddr, new_daddr);

    // Rewrite destination port if changed
    if old_dport != new_dport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)?, new_dport);
        csum_replace2(tcp_ck, old_dport, new_dport);
    }

    Ok((client_ip, client_port))
}
