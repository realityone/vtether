#![no_std]
#![no_main]

mod conntrack;
mod csum;
mod fib;
mod lb;
mod nat;
mod parse;
mod stats;

use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::XdpContext;
use core::ptr::addr_of;

use conntrack::{
    ct_create4, ct_lazy_lookup4, ipv4_ct_tuple_reverse, CtState, CtStatus, Ipv4CtTuple,
    CT_EGRESS, CT_INGRESS, CT_SERVICE,
};
use lb::{lb4_fill_key, lb4_lookup_backend, lb4_lookup_service, lb4_select_backend_id, Lb4Key};
use nat::SnatTarget;
use parse::{read_field, Ipv4Hdr, IPPROTO_TCP};

/// SNAT target configuration map — populated by userspace.
/// Index 0 contains the SNAT target (IP + port range).
///
/// This is vtether-specific — Cilium uses compile-time constants
/// (`IPV4_DIRECT_ROUTING`, `NODEPORT_PORT_MIN_NAT`, `NODEPORT_PORT_MAX_NAT`).
#[repr(C)]
pub struct SnatConfig {
    /// SNAT IP address (network byte order).
    pub snat_addr: u32,
    /// Minimum ephemeral port (host byte order).
    pub min_port: u16,
    /// Maximum ephemeral port (host byte order).
    pub max_port: u16,
}

#[map]
static SNAT_CONFIG: Array<SnatConfig> = Array::with_max_entries(1, 0);

// ---- XDP entry point ----

#[xdp]
pub fn vtether_xdp(ctx: XdpContext) -> u32 {
    match try_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => aya_ebpf::bindings::xdp_action::XDP_PASS,
    }
}

/// Main XDP processing function.
///
/// Cilium equivalent: `cil_xdp_entry()` -> `tail_lb_ipv4()` -> `nodeport_lb4()`.
///
/// Two paths:
/// 1. **Forward path** (client -> service VIP): service lookup hit -> DNAT + SNAT + redirect
/// 2. **Reply path** (backend -> snat_ip): reverse SNAT + reverse DNAT + redirect
fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    // Parse Ethernet, reject non-IPv4
    parse::parse_eth(ctx)?;

    // Parse IPv4 + validate TCP
    let (ip, l4_off) = parse::parse_ipv4(ctx)?;

    // Extract the connection tuple from the packet.
    // Cilium: `lb4_extract_tuple(ctx, ip4, fraginfo, l4_off, &tuple)`
    let tuple = parse::extract_tuple(ctx, ip, l4_off)?;

    // ---- Service lookup (forward path) ----
    // Cilium: `lb4_fill_key(&key, &tuple)` then `lb4_lookup_service(&key, false)`
    let mut key = Lb4Key {
        address: 0,
        dport: 0,
        backend_slot: 0,
        proto: 0,
        scope: 0,
        _pad: [0; 2],
    };
    lb4_fill_key(&mut key, &tuple);

    if let Some(svc) = lb4_lookup_service(&key) {
        // Service found — forward path.
        // Cilium: `nodeport_svc_lb4()` -> `lb4_local()` -> DNAT -> CT -> SNAT -> redirect
        return handle_forward(ctx, ip, l4_off, &tuple, &key, svc);
    }

    // ---- No service match — check for reply traffic ----
    // Cilium: falls through to `CILIUM_CALL_IPV4_NODEPORT_NAT_INGRESS`
    // -> `snat_v4_rev_nat()` -> `nodeport_rev_dnat_ipv4()`
    handle_reply(ctx, ip, l4_off, &tuple)
}

/// Forward path: client -> backend (DNAT + SNAT + redirect).
///
/// Cilium equivalent: `nodeport_svc_lb4()` + `tail_nodeport_nat_egress_ipv4()`.
///
/// Flow:
/// 1. `lb4_local()`: CT lookup -> select backend -> create CT entry
/// 2. `lb4_dnat_request()` -> `lb4_xlate()`: DNAT rewrite
/// 3. Create reverse CT entry for reply matching
/// 4. `__snat_v4_nat()`: SNAT rewrite
/// 5. `fib_redirect()`: FIB lookup + redirect
#[inline(always)]
fn handle_forward(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    orig_tuple: &Ipv4CtTuple,
    key: &Lb4Key,
    svc: &lb::Lb4Service,
) -> Result<u32, ()> {
    let drop = aya_ebpf::bindings::xdp_action::XDP_DROP;

    // ---- Step 1: CT lookup + backend selection (lb4_local) ----
    //
    // Cilium's `lb4_local()`:
    //   1. `ct_lazy_lookup4(map, tuple, ..., CT_SERVICE, SCOPE_REVERSE, ...)`
    //   2. CT_NEW: select backend, `ct_create4(map, NULL, tuple, ..., CT_SERVICE, state)`
    //   3. CT_REPLY: read backend_id from existing entry

    // Build the forward CT tuple with CT_SERVICE flag.
    let mut fwd_tuple = Ipv4CtTuple {
        daddr: orig_tuple.daddr,
        saddr: orig_tuple.saddr,
        dport: orig_tuple.dport,
        sport: orig_tuple.sport,
        nexthdr: IPPROTO_TCP,
        flags: CT_EGRESS | CT_SERVICE,
    };

    let mut ct_state = CtState::new();
    ct_state.rev_nat_index = svc.rev_nat_index;

    let (backend_id, is_new) = match ct_lazy_lookup4(ctx, &fwd_tuple, l4_off, CT_SERVICE, &mut ct_state)? {
        CtStatus::New => {
            // New connection: select a backend.
            // Cilium: `lb4_select_backend_id(ctx, key, tuple, svc)`
            if svc.count == 0 {
                stats::update_route_drops(svc.rev_nat_index);
                return Ok(drop);
            }

            let backend_id = lb4_select_backend_id(key, svc);
            if backend_id == 0 {
                stats::update_route_drops(svc.rev_nat_index);
                return Ok(drop);
            }

            ct_state.backend_id = backend_id;

            // Create the forward CT entry.
            // Cilium: `ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state, ext_err)`
            if ct_create4(&fwd_tuple, &ct_state).is_err() {
                stats::update_route_drops(svc.rev_nat_index);
                return Ok(drop);
            }

            (backend_id, true)
        }
        CtStatus::Established | CtStatus::Reply => {
            // Existing connection: use the backend from the CT entry.
            // Cilium: `backend_id = state->backend_id`
            let backend_id = ct_state.backend_id;
            if backend_id == 0 {
                stats::update_route_drops(svc.rev_nat_index);
                return Ok(drop);
            }
            (backend_id, false)
        }
    };

    // Look up the backend.
    // Cilium: `lb4_lookup_backend(ctx, backend_id)`
    let backend = lb4_lookup_backend(backend_id).ok_or(())?;

    // ---- Step 2: DNAT (lb4_xlate) ----
    //
    // Cilium: `lb4_dnat_request(ctx, backend, l3_off, fraginfo, l4_off, tuple, false)`
    //   -> `lb4_xlate(ctx, ..., old_daddr, old_dport, backend, has_l4_header)`
    let old_daddr = orig_tuple.daddr;
    let old_dport = orig_tuple.dport;
    let old_saddr = orig_tuple.saddr;
    let old_sport = orig_tuple.sport;

    lb::lb4_xlate_dnat(
        ctx,
        ip,
        l4_off,
        old_daddr,
        backend.address,
        old_dport,
        backend.port,
    )?;

    // ---- Step 3: Create reverse CT entry ----
    //
    // Cilium: after DNAT, creates a CT_EGRESS entry with the forward tuple reversed.
    // `nodeport_svc_lb4()`:
    //   `__ipv4_ct_tuple_reverse(tuple)` — swap src/dst
    //   `ct_lazy_lookup4(..., CT_EGRESS, SCOPE_FORWARD, CT_ENTRY_NODEPORT, ...)`
    //   CT_NEW -> `ct_create4(..., CT_EGRESS, &ct_state, ...)`
    //
    // This reverse entry is what `nodeport_rev_dnat_ipv4()` looks up on the reply path
    // to find the `rev_nat_index` and perform reverse DNAT.
    //
    // The reversed tuple uses the post-DNAT addresses:
    //   {saddr=backend_ip, daddr=client_ip, sport=backend_port, dport=client_port, CT_INGRESS}
    let rev_ct_tuple = Ipv4CtTuple {
        daddr: old_saddr,      // client IP (will be destination on reply)
        saddr: backend.address, // backend IP (will be source on reply)
        dport: old_sport,       // client port
        sport: backend.port,    // backend port
        nexthdr: IPPROTO_TCP,
        flags: CT_EGRESS, // Cilium uses CT_EGRESS for the "nodeport" entry
    };

    let rev_ct_state = CtState {
        rev_nat_index: svc.rev_nat_index,
        backend_id,
        closing: false,
        syn: false,
    };

    // Best-effort: don't fail the whole packet if reverse CT creation fails.
    // Cilium: if CT_NEW, create; if CT_ESTABLISHED, just proceed.
    let _ = ct_create4(&rev_ct_tuple, &rev_ct_state);

    // ---- Step 4: SNAT (tail_nodeport_nat_egress_ipv4) ----
    //
    // Cilium's `tail_nodeport_nat_egress_ipv4()`:
    //   1. `ipv4_l3(ctx, ETH_HLEN, NULL, NULL, ip4)` — decrement TTL
    //   2. `__snat_v4_nat(ctx, &tuple, state, ...)` — rewrite saddr + sport
    //   3. `fib_redirect(ctx, ...)` — lookup next-hop, redirect

    // Load SNAT config from userspace-populated map.
    let snat_cfg = unsafe { SNAT_CONFIG.get(0) }.ok_or(())?;
    let target = SnatTarget {
        addr: snat_cfg.snat_addr,
        min_port: snat_cfg.min_port,
        max_port: snat_cfg.max_port,
    };

    // Decrement TTL before forwarding.
    // Cilium: `ipv4_l3(ctx, ETH_HLEN, NULL, NULL, ip4)`
    fib::ipv4_dec_ttl(ctx, ip)?;

    // SNAT: rewrite source IP + port, allocate ephemeral port.
    let _snat_port = nat::snat_v4_nat(
        ctx,
        ip,
        l4_off,
        old_saddr,   // original client IP
        old_sport,    // original client port
        backend.address,
        backend.port,
        &target,
    )?;

    // ---- Step 5: Update stats ----
    let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
    stats::update_route_stats(svc.rev_nat_index, pkt_len, is_new);

    // ---- Step 6: FIB lookup + redirect ----
    //
    // Cilium: `fib_redirect(ctx, true, &fib_params, false, &ext_err, &oif)`
    fib::fib_redirect_v4(ctx, ip)
}

/// Reply path: backend -> client (reverse SNAT + reverse DNAT + redirect).
///
/// Cilium equivalent: `tail_nodeport_nat_ingress_ipv4()` -> `nodeport_rev_dnat_ipv4()`.
///
/// Flow:
/// 1. `snat_v4_rev_nat()`: restore client IP:port as destination
/// 2. CT lookup on the reply direction to get `rev_nat_index`
/// 3. `lb4_rev_nat()`: restore VIP:svc_port as source
/// 4. FIB redirect back to client
#[inline(always)]
fn handle_reply(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    orig_tuple: &Ipv4CtTuple,
) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;

    // ---- Step 1: Reverse SNAT ----
    //
    // Cilium: `snat_v4_rev_nat(ctx, &target, &trace, &ext_err)`
    // Looks up the SNAT4 reverse entry and rewrites daddr:dport back to client values.
    //
    // If no SNAT mapping exists, this is not our traffic — pass to stack.
    // Cilium: `if (ret == NAT_PUNT_TO_STACK || ret == DROP_NAT_NO_MAPPING) goto recircle;`
    let (client_ip, client_port) = match nat::snat_v4_rev_nat(ctx, ip, l4_off) {
        Ok(result) => result,
        Err(()) => return Ok(pass), // No SNAT mapping — not our traffic
    };

    // ---- Step 2: Reverse DNAT (nodeport_rev_dnat_ipv4) ----
    //
    // Cilium's `nodeport_rev_dnat_ipv4()`:
    //   1. `lb4_extract_tuple()` — extract tuple from the post-revSNAT packet
    //   2. `ct_lazy_lookup4(..., CT_INGRESS, SCOPE_REVERSE, CT_ENTRY_NODEPORT, ...)`
    //   3. if CT_REPLY: `lb4_rev_nat(ctx, ..., ct_state.rev_nat_index, ...)`
    //
    // After reverse SNAT, the packet looks like:
    //   src=backend_ip:backend_port -> dst=client_ip:client_port
    //
    // We need to find the CT entry to get rev_nat_index, then restore the VIP.
    // The CT entry was created as:
    //   {daddr=client_ip, saddr=backend_ip, dport=client_port, sport=backend_port, CT_EGRESS}

    // Re-read the packet after reverse SNAT rewrite.
    let backend_ip = read_field(unsafe { addr_of!((*ip).saddr) });
    let backend_port = read_field(
        parse::ptr_at::<u16>(ctx, l4_off + parse::TCP_SPORT_OFF)? as *const u16,
    );

    let rev_lookup_tuple = Ipv4CtTuple {
        daddr: client_ip,
        saddr: backend_ip,
        dport: client_port,
        sport: backend_port,
        nexthdr: IPPROTO_TCP,
        flags: CT_EGRESS, // Match the entry we created on the forward path
    };

    let mut ct_state = CtState::new();
    match ct_lazy_lookup4(ctx, &rev_lookup_tuple, l4_off, CT_INGRESS, &mut ct_state)? {
        CtStatus::New => {
            // No CT entry found — not our traffic.
            return Ok(pass);
        }
        CtStatus::Established | CtStatus::Reply => {
            // Found the CT entry. Use rev_nat_index to restore the VIP.
        }
    }

    // Perform reverse DNAT: restore source to VIP:svc_port.
    // Cilium: `lb4_rev_nat(ctx, l3_off, l4_off, ct_state.rev_nat_index, ...)`
    if ct_state.rev_nat_index != 0 {
        lb::lb4_rev_nat(ctx, ip, l4_off, ct_state.rev_nat_index)?;
    }

    // ---- Step 3: Update stats ----
    let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
    if ct_state.rev_nat_index != 0 {
        stats::update_route_stats(ct_state.rev_nat_index, pkt_len, false);
    }

    // ---- Step 4: Decrement TTL + FIB redirect back to client ----
    //
    // Cilium: `ipv4_l3(ctx, l3_off, NULL, NULL, ip4)` then `fib_redirect(ctx, ...)`
    fib::ipv4_dec_ttl(ctx, ip)?;
    fib::fib_redirect_v4(ctx, ip)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
