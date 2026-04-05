/// Load balancer module — service lookup, backend selection, and DNAT rewrite.
///
/// Cilium equivalents:
/// - `bpf/lib/lb.h` — `lb4_lookup_service()`, `lb4_select_backend_id()`,
///   `lb4_lookup_backend()`, `lb4_xlate()`, `lb_l4_xlate()`, `lb4_rev_nat()`
/// - `bpf/lib/nodeport.h` — orchestration
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;

use crate::conntrack::Ipv4CtTuple;
use crate::csum::{csum_replace2, csum_replace4};
use crate::parse::{
    ptr_at, read_field, write_field, Ipv4Hdr, TCP_CSUM_OFF, TCP_DPORT_OFF, TCP_SPORT_OFF,
};
use core::ptr::{addr_of, addr_of_mut};

// ---- Service lookup types ----

/// Service lookup key.
///
/// Cilium equivalent: `struct lb4_key` from `bpf/include/lib/common.h`.
///
/// ```c
/// struct lb4_key {
///     __be32 address;
///     __be16 dport;
///     __u16 backend_slot;
///     __u8 proto;
///     __u8 scope;
///     __u8 pad[2];
/// };
/// ```
#[repr(C)]
pub struct Lb4Key {
    /// Service virtual IP address (network byte order).
    pub address: u32,
    /// Service port (network byte order).
    pub dport: u16,
    /// Backend slot index. 0 = service-level entry, >0 = specific backend slot.
    pub backend_slot: u16,
    /// L4 protocol (IPPROTO_TCP = 6).
    pub proto: u8,
    /// Scope: 0 = external, 1 = internal.
    pub scope: u8,
    pub _pad: [u8; 2],
}

/// Service descriptor — value in the service map.
///
/// Cilium equivalent: `struct lb4_service`.
///
/// For service-level entry (slot 0): `count` = number of backends,
/// `rev_nat_index` = index into reverse NAT table.
///
/// For backend-slot entry (slot > 0): `backend_id` = references LB4_BACKENDS.
#[repr(C)]
pub struct Lb4Service {
    /// Union: backend_id (slot > 0) or affinity_timeout (slot 0).
    pub backend_id: u32,
    /// Number of backends (only valid on slot 0).
    pub count: u16,
    /// Index into `LB4_REVERSE_NAT` for reply-path rewriting.
    pub rev_nat_index: u16,
    /// Service flags.
    pub flags: u8,
    pub flags2: u8,
    /// Number of quarantined backends.
    pub qcount: u16,
}

// ---- Backend types ----

/// Backend descriptor.
///
/// Cilium equivalent: `struct lb4_backend`.
#[repr(C)]
pub struct Lb4Backend {
    /// Backend IP address (network byte order).
    pub address: u32,
    /// Backend port (network byte order).
    pub port: u16,
    /// L4 protocol.
    pub proto: u8,
    /// Backend state: 0 = active.
    pub flags: u8,
}

// ---- Reverse NAT types ----

/// Reverse NAT entry — restores the original VIP on the reply path.
///
/// Cilium equivalent: `struct lb4_reverse_nat`.
#[repr(C)]
pub struct Lb4ReverseNat {
    /// Original service VIP (network byte order).
    pub address: u32,
    /// Original service port (network byte order).
    pub port: u16,
    pub _pad: u16,
}

// ---- Maps ----

/// Service lookup map.
/// Cilium equivalent: `cilium_lb4_services_v2` (HASH).
#[map]
pub static LB4_SERVICES: HashMap<Lb4Key, Lb4Service> = HashMap::with_max_entries(65536, 0);

/// Backend lookup map.
/// Cilium equivalent: `cilium_lb4_backends_v3` (HASH).
#[map]
pub static LB4_BACKENDS: HashMap<u32, Lb4Backend> = HashMap::with_max_entries(65536, 0);

/// Reverse NAT map — used on reply path to restore original VIP.
/// Cilium equivalent: `cilium_lb4_reverse_nat` (HASH).
#[map]
pub static LB4_REVERSE_NAT: HashMap<u16, Lb4ReverseNat> = HashMap::with_max_entries(65536, 0);

// ---- LB key construction ----

/// Fill an LB4 key from a CT tuple.
///
/// Cilium equivalent: `lb4_fill_key()` from `bpf/lib/lb.h`:
/// ```c
/// static __always_inline void
/// lb4_fill_key(struct lb4_key *key, const struct ipv4_ct_tuple *tuple) {
///     key->proto = tuple->nexthdr;
///     key->address = tuple->daddr;
///     key->dport = tuple->sport;  // CT tuple has ports in reverse order
/// }
/// ```
///
/// Note: Cilium's CT tuple stores ports "reversed" for the service lookup direction.
/// In the forward path, the CT tuple has `sport = TCP dport` (the service port) and
/// `dport = TCP sport` (the client port). So `key->dport = tuple->sport` maps the
/// service port into the key.
///
/// However, vtether's `extract_tuple()` stores ports in natural packet order:
/// `dport = TCP dport`, `sport = TCP sport`. So we use `tuple.dport` directly.
#[inline(always)]
pub fn lb4_fill_key(key: &mut Lb4Key, tuple: &Ipv4CtTuple) {
    key.proto = tuple.nexthdr;
    key.address = tuple.daddr;
    // vtether stores ports in natural order, so the service port is dport.
    key.dport = tuple.dport;
    key.backend_slot = 0;
    key.scope = 0; // LB_LOOKUP_SCOPE_EXT
    key._pad = [0; 2];
}

// ---- Service lookup ----

/// Lookup a service by key.
///
/// Cilium equivalent: `lb4_lookup_service()` from `bpf/lib/lb.h`.
/// Simplified: we only do external-scope lookup (no wildcard fallback, no
/// two-scope logic since vtether doesn't have internal/external scopes).
#[inline(always)]
pub fn lb4_lookup_service(key: &Lb4Key) -> Option<&Lb4Service> {
    unsafe { LB4_SERVICES.get(key) }
}

// ---- Backend selection ----

/// Select a backend for a new connection.
///
/// Cilium equivalent: `lb4_select_backend_id_random()` from `bpf/lib/lb.h`:
/// ```c
/// __u16 slot = (get_prandom_u32() % svc->count) + 1;
/// be = lb4_lookup_backend_slot(ctx, key, slot);
/// return be ? be->backend_id : 0;
/// ```
///
/// Uses random selection: pick a random slot in [1, count], look up that slot
/// in the service map to get the backend_id.
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

    // Look up the backend slot entry in the service map.
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
///
/// Cilium equivalent: `lb4_lookup_backend()` -> `__lb4_lookup_backend()`.
#[inline(always)]
pub fn lb4_lookup_backend(backend_id: u32) -> Option<&'static Lb4Backend> {
    unsafe { LB4_BACKENDS.get(&backend_id) }
}

// ---- DNAT rewrite ----

/// Perform DNAT: rewrite destination IP and port to the backend's address.
///
/// Cilium equivalent: `lb4_xlate()` + `lb_l4_xlate()` from `bpf/lib/lb.h`.
///
/// `lb4_xlate()` does:
/// 1. `ctx_store_bytes(ctx, l3_off + offsetof(iphdr, daddr), new_daddr, 4, 0)`
/// 2. `sum = csum_diff(&old_daddr, 4, new_daddr, 4, 0)`
/// 3. `ipv4_csum_update_by_diff(ctx, l3_off, sum)` — fix IP checksum
/// 4. `csum_l4_replace(ctx, l4_off, &csum_off, 0, sum, BPF_F_PSEUDO_HDR)` — fix TCP checksum for IP change
/// 5. `lb_l4_xlate()` — rewrite dport if changed, with TCP checksum update
///
/// vtether uses direct pointer writes + incremental checksum helpers instead of
/// `ctx_store_bytes` / `csum_diff` since we have direct XDP packet access.
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
    // 1. Rewrite destination IP
    write_field(unsafe { addr_of_mut!((*ip).daddr) }, new_daddr);

    // 2. Update IP header checksum for daddr change
    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_daddr, new_daddr);

    // 3. Update TCP checksum for daddr change (pseudo-header)
    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_daddr, new_daddr);

    // 4. Rewrite destination port if changed (lb_l4_xlate)
    if old_dport != new_dport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)?, new_dport);
        csum_replace2(tcp_ck, old_dport, new_dport);
    }

    Ok(())
}

// ---- Reverse DNAT (reply path) ----

/// Perform reverse DNAT on the reply path: restore the original VIP as source.
///
/// Cilium equivalent: `lb4_rev_nat()` from `bpf/lib/lb.h`.
///
/// On the reply path, the backend's source IP:port needs to be rewritten back
/// to the service VIP:port so the client sees the response from the VIP.
///
/// This function:
/// 1. Looks up `LB4_REVERSE_NAT[rev_nat_index]` to get `{VIP, svc_port}`
/// 2. Rewrites saddr -> VIP, sport -> svc_port
/// 3. Fixes IP + TCP checksums
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

    // Rewrite source IP
    write_field(unsafe { addr_of_mut!((*ip).saddr) }, new_saddr);

    // Update IP checksum
    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, old_saddr, new_saddr);

    // Update TCP checksum for saddr change
    let tcp_ck = ptr_at::<u16>(ctx, l4_off + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, old_saddr, new_saddr);

    // Rewrite source port if changed
    if old_sport != new_sport {
        write_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)?, new_sport);
        csum_replace2(tcp_ck, old_sport, new_sport);
    }

    Ok(())
}
