/// NAT module -- SNAT state tracking, port allocation, and header rewrite.
///
/// Cilium equivalents:
/// - `bpf/lib/nat.h` -- `__snat_v4_nat()`, `snat_v4_new_mapping()`,
///   `snat_v4_rewrite_headers()`, `snat_v4_rev_nat()`
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use core::ptr::{addr_of, addr_of_mut};

use crate::conntrack::Ipv4CtTuple;
use crate::csum::{csum_replace2, csum_replace4};
use crate::parse::{
    IPPROTO_TCP, Ipv4Hdr, TCP_CSUM_OFF, TCP_DPORT_OFF, TCP_SPORT_OFF, ptr_at, read_field,
    write_field,
};

/// Maximum SNAT port allocation retries.
const SNAT_COLLISION_RETRIES: u32 = 128;

// ---- SNAT direction flags ----

const TUPLE_F_OUT: u8 = 0;
const TUPLE_F_IN: u8 = 1;

// ---- SNAT map key/value types ----

pub type SnatKey = Ipv4CtTuple;

/// SNAT mapping entry -- the map value.
#[repr(C)]
pub struct SnatEntry {
    pub created: u64,
    pub to_addr: u32,
    pub to_port: u16,
    pub _pad: u16,
}

/// SNAT target configuration.
pub struct SnatTarget {
    pub addr: u32,
    pub min_port: u16,
    pub max_port: u16,
}

// ---- SNAT map ----

#[map]
pub static SNAT4: HashMap<SnatKey, SnatEntry> = HashMap::with_max_entries(131072, 0);

// ---- SNAT key construction ----

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
        nexthdr: IPPROTO_TCP,
        flags: TUPLE_F_OUT,
    }
}

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
        nexthdr: IPPROTO_TCP,
        flags: TUPLE_F_IN,
    }
}

// ---- SNAT port allocation ----

#[inline(always)]
fn snat_try_keep_port(min_port: u16, max_port: u16, port: u16) -> u16 {
    if port >= min_port && port <= max_port {
        return port;
    }
    let range = (max_port - min_port) as u32 + 1;
    if range == 0 {
        unsafe { core::hint::unreachable_unchecked() };
    }
    min_port + (port as u32 % range) as u16
}

#[inline(always)]
fn snat_clamp_port_range(min_port: u16, max_port: u16, port: u16) -> u16 {
    if port >= min_port && port <= max_port {
        return port;
    }
    let range = (max_port - min_port) as u32 + 1;
    if range == 0 {
        unsafe { core::hint::unreachable_unchecked() };
    }
    min_port + (port as u32 % range) as u16
}

/// Allocate a new SNAT mapping (forward + reverse entries).
#[inline(always)]
fn snat_v4_new_mapping(
    client_ip: u32,
    backend_ip: u32,
    client_port: u16,
    backend_port: u16,
    target: &SnatTarget,
) -> Result<u16, ()> {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let rstate = SnatEntry {
        created: now,
        to_addr: client_ip,
        to_port: client_port,
        _pad: 0,
    };

    let orig_port_host = u16::from_be(client_port);
    let mut port = snat_try_keep_port(target.min_port, target.max_port, orig_port_host);

    let mut i: u32 = 0;
    while i < SNAT_COLLISION_RETRIES {
        let snat_port_be = port.to_be();
        let rev_key = snat_v4_make_rev_key(target.addr, backend_ip, snat_port_be, backend_port);

        if SNAT4
            .insert(&rev_key, &rstate, aya_ebpf::bindings::BPF_NOEXIST as u64)
            .is_ok()
        {
            let fwd_key = snat_v4_make_fwd_key(client_ip, backend_ip, client_port, backend_port);
            let fwd_state = SnatEntry {
                created: now,
                to_addr: target.addr,
                to_port: snat_port_be,
                _pad: 0,
            };

            if SNAT4.insert(&fwd_key, &fwd_state, 0).is_err() {
                let _ = SNAT4.remove(&rev_key);
                return Err(());
            }

            return Ok(snat_port_be);
        }

        port = match i {
            0 => {
                let rand = unsafe { aya_ebpf::helpers::bpf_get_prandom_u32() } as u16;
                snat_clamp_port_range(target.min_port, target.max_port, rand)
            }
            _ => snat_clamp_port_range(target.min_port, target.max_port, port + 1),
        };

        i += 1;
    }

    Err(())
}

// ---- Public SNAT API ----

/// Perform SNAT on the forward path: allocate or reuse a mapping, rewrite headers.
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
    let fwd_key = snat_v4_make_fwd_key(client_ip, backend_ip, client_port, backend_port);

    let snat_port = if let Some(existing) = unsafe { SNAT4.get(&fwd_key) } {
        existing.to_port
    } else {
        snat_v4_new_mapping(client_ip, backend_ip, client_port, backend_port, target)?
    };

    snat_v4_rewrite_egress(
        ctx,
        ip,
        l4_off,
        client_ip,
        target.addr,
        client_port,
        snat_port,
    )?;

    Ok(snat_port)
}

/// Rewrite source IP + port on the egress (forward) path.
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

    write_field(unsafe { addr_of_mut!((*ip).saddr) }, new_saddr);

    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_saddr, new_saddr);

    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_saddr, new_saddr);

    if old_sport != new_sport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)?, new_sport);
        csum_replace2(tcp_ck, old_sport, new_sport);
    }

    Ok(())
}

/// Perform reverse SNAT on the reply path: restore original client IP + port.
///
/// Returns the restored (client_ip, client_port) or Err if no mapping found.
#[inline(always)]
pub fn snat_v4_rev_nat(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
) -> Result<(u32, u16), ()> {
    let snat_ip = read_field(unsafe { addr_of!((*ip).daddr) });
    let backend_ip = read_field(unsafe { addr_of!((*ip).saddr) });
    let snat_port = read_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)? as *const u16);
    let backend_port = read_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)? as *const u16);

    let rev_key = snat_v4_make_rev_key(snat_ip, backend_ip, snat_port, backend_port);

    let state = unsafe { SNAT4.get(&rev_key) }.ok_or(())?;

    let client_ip = state.to_addr;
    let client_port = state.to_port;

    let old_daddr = snat_ip;
    let new_daddr = client_ip;
    let old_dport = snat_port;
    let new_dport = client_port;

    if old_daddr == new_daddr && old_dport == new_dport {
        return Ok((client_ip, client_port));
    }

    write_field(unsafe { addr_of_mut!((*ip).daddr) }, new_daddr);

    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_daddr, new_daddr);

    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_daddr, new_daddr);

    if old_dport != new_dport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)?, new_dport);
        csum_replace2(tcp_ck, old_dport, new_dport);
    }

    Ok((client_ip, client_port))
}
