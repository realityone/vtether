/// Load balancer module -- service lookup, backend selection, and DNAT rewrite.
///
/// Cilium equivalents:
/// - `bpf/lib/lb.h` -- `lb4_lookup_service()`, `lb4_select_backend_id()`,
///   `lb4_lookup_backend()`, `lb4_xlate()`, `lb_l4_xlate()`, `lb4_rev_nat()`
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use core::ptr::{addr_of, addr_of_mut};

use crate::conntrack::Ipv4CtTuple;
use crate::csum::{csum_replace2, csum_replace4};
use crate::parse::{
    Ipv4Hdr, TCP_CSUM_OFF, TCP_DPORT_OFF, TCP_SPORT_OFF, ptr_at, read_field, write_field,
};

// ---- Service lookup types ----

/// Service lookup key.
#[repr(C)]
pub struct Lb4Key {
    pub address: u32,
    pub dport: u16,
    pub backend_slot: u16,
    pub proto: u8,
    pub scope: u8,
    pub _pad: [u8; 2],
}

/// Service descriptor -- value in the service map.
#[repr(C)]
pub struct Lb4Service {
    pub backend_id: u32,
    pub count: u16,
    pub rev_nat_index: u16,
    pub flags: u8,
    pub flags2: u8,
    pub qcount: u16,
}

// ---- Backend types ----

/// Backend descriptor.
#[repr(C)]
pub struct Lb4Backend {
    pub address: u32,
    pub port: u16,
    pub proto: u8,
    pub flags: u8,
}

// ---- Reverse NAT types ----

/// Reverse NAT entry -- restores the original VIP on the reply path.
#[repr(C)]
pub struct Lb4ReverseNat {
    pub address: u32,
    pub port: u16,
    pub _pad: u16,
}

// ---- Maps ----

#[map]
pub static LB4_SERVICES: HashMap<Lb4Key, Lb4Service> = HashMap::with_max_entries(65536, 0);

#[map]
pub static LB4_BACKENDS: HashMap<u32, Lb4Backend> = HashMap::with_max_entries(65536, 0);

#[map]
pub static LB4_REVERSE_NAT: HashMap<u16, Lb4ReverseNat> = HashMap::with_max_entries(65536, 0);

// ---- LB key construction ----

/// Fill an LB4 key from a CT tuple.
///
/// vtether stores ports in natural packet order: dport = TCP dport.
#[inline(always)]
pub fn lb4_fill_key(key: &mut Lb4Key, tuple: &Ipv4CtTuple) {
    key.proto = tuple.nexthdr;
    key.address = tuple.daddr;
    key.dport = tuple.dport;
    key.backend_slot = 0;
    key.scope = 0;
    key._pad = [0; 2];
}

// ---- Service lookup ----

#[inline(always)]
pub fn lb4_lookup_service(key: &Lb4Key) -> Option<&Lb4Service> {
    unsafe { LB4_SERVICES.get(key) }
}

// ---- Backend selection ----

/// Select a backend for a new connection using random slot selection.
#[inline(always)]
pub fn lb4_select_backend_id(key: &Lb4Key, svc: &Lb4Service) -> u32 {
    if svc.count == 0 {
        return 0;
    }

    let count = svc.count as u32;
    if count == 0 {
        unsafe { core::hint::unreachable_unchecked() };
    }
    let rand = unsafe { aya_ebpf::helpers::bpf_get_prandom_u32() };
    let slot = (rand % count) + 1;

    let slot_key = Lb4Key {
        address: key.address,
        dport: key.dport,
        backend_slot: slot as u16,
        proto: key.proto,
        scope: key.scope,
        _pad: [0; 2],
    };
    match unsafe { LB4_SERVICES.get(&slot_key) } {
        Some(be) => be.backend_id,
        None => 0,
    }
}

/// Lookup a backend by ID.
#[inline(always)]
pub fn lb4_lookup_backend(backend_id: u32) -> Option<&'static Lb4Backend> {
    unsafe { LB4_BACKENDS.get(&backend_id) }
}

// ---- DNAT rewrite ----

/// Perform DNAT: rewrite destination IP and port to the backend's address.
#[inline(always)]
pub fn lb4_xlate_dnat(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    old_daddr: u32,
    new_daddr: u32,
    old_dport: u16,
    new_dport: u16,
) -> Result<(), ()> {
    write_field(unsafe { addr_of_mut!((*ip).daddr) }, new_daddr);

    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_daddr, new_daddr);

    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_daddr, new_daddr);

    if old_dport != new_dport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)?, new_dport);
        csum_replace2(tcp_ck, old_dport, new_dport);
    }

    Ok(())
}

// ---- Reverse DNAT (reply path) ----

/// Perform reverse DNAT on the reply path: restore the original VIP as source.
#[inline(always)]
pub fn lb4_rev_nat(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    rev_nat_index: u16,
) -> Result<(), ()> {
    let rev = unsafe { LB4_REVERSE_NAT.get(&rev_nat_index) }.ok_or(())?;

    let old_saddr = read_field(unsafe { addr_of!((*ip).saddr) });
    let old_sport = read_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)? as *const u16);

    let new_saddr = rev.address;
    let new_sport = rev.port;

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
