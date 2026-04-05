#![no_std]
#![no_main]

mod conntrack;
mod csum;
mod lb;
mod nat;
mod parse;
mod stats;

use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use core::ptr::addr_of;

use conntrack::{
    ct_create4, ct_lazy_lookup4, CtState, CtStatus, Ipv4CtTuple, CT_EGRESS, CT_INGRESS,
    CT_SERVICE,
};
use lb::{lb4_fill_key, lb4_lookup_backend, lb4_lookup_service, lb4_select_backend_id, Lb4Key};
use nat::SnatTarget;
use parse::{load_tcp_flags, read_field, Ipv4Hdr, IPPROTO_TCP};

#[repr(C)]
pub struct SnatConfig {
    pub snat_addr: u32,
    pub min_port: u16,
    pub max_port: u16,
}

#[map]
static SNAT_CONFIG: Array<SnatConfig> = Array::with_max_entries(1, 0);

#[xdp]
pub fn vtether_xdp(ctx: XdpContext) -> u32 {
    match try_xdp(&ctx) {
        Ok(action) => action,
        Err(()) => aya_ebpf::bindings::xdp_action::XDP_PASS,
    }
}

fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;

    let (ip, l4_off) = parse::parse_ipv4_tcp_validated(ctx)?;
    let tuple = parse::extract_tuple(ctx, ip, l4_off)?;
    let tcp_flags = load_tcp_flags(ctx, l4_off)?;

    if matches!(SNAT_CONFIG.get(0), Some(cfg) if tuple.saddr == cfg.snat_addr) {
        return Ok(pass);
    }

    let mut key = Lb4Key {
        address: 0, dport: 0, backend_slot: 0, proto: 0, scope: 0, _pad: [0; 2],
    };
    lb4_fill_key(&mut key, &tuple);

    match lb4_lookup_service(&key) {
        Some(svc) => handle_forward(ctx, ip, l4_off, tcp_flags, &tuple, &key, svc),
        None => handle_reply(ctx, ip, l4_off, tcp_flags),
    }
}

#[inline(always)]
fn handle_forward(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    tcp_flags: u8,
    orig_tuple: &Ipv4CtTuple,
    key: &Lb4Key,
    svc: &lb::Lb4Service,
) -> Result<u32, ()> {
    let drop = aya_ebpf::bindings::xdp_action::XDP_DROP;

    let fwd_tuple = Ipv4CtTuple {
        daddr: orig_tuple.daddr, saddr: orig_tuple.saddr,
        dport: orig_tuple.dport, sport: orig_tuple.sport,
        nexthdr: IPPROTO_TCP, flags: CT_EGRESS | CT_SERVICE,
    };

    let mut ct_state = CtState::new();
    ct_state.rev_nat_index = svc.rev_nat_index;

    let (backend_id, is_new) =
        match ct_lazy_lookup4(tcp_flags, &fwd_tuple, CT_SERVICE, &mut ct_state) {
            CtStatus::New => {
                if svc.count == 0 {
                    info!(ctx, "FWD: no backends");
                    stats::update_route_drops(svc.rev_nat_index);
                    return Ok(drop);
                }
                let backend_id = lb4_select_backend_id(key, svc);
                if backend_id == 0 {
                    info!(ctx, "FWD: backend select failed");
                    stats::update_route_drops(svc.rev_nat_index);
                    return Ok(drop);
                }
                ct_state.backend_id = backend_id;
                if ct_create4(&fwd_tuple, &ct_state).is_err() {
                    info!(ctx, "FWD: ct_create4 failed");
                    stats::update_route_drops(svc.rev_nat_index);
                    return Ok(drop);
                }
                // Log only new connections (not per-packet)
                info!(ctx, "FWD: NEW conn, backend_id={}", backend_id);
                (backend_id, true)
            }
            CtStatus::Established | CtStatus::Reply => {
                let backend_id = ct_state.backend_id;
                if backend_id == 0 {
                    stats::update_route_drops(svc.rev_nat_index);
                    return Ok(drop);
                }
                (backend_id, false)
            }
        };

    let backend = lb4_lookup_backend(backend_id).ok_or(())?;

    let old_daddr = orig_tuple.daddr;
    let old_dport = orig_tuple.dport;
    let old_saddr = orig_tuple.saddr;
    let old_sport = orig_tuple.sport;

    // DNAT
    lb::lb4_xlate_dnat(ctx, ip, l4_off, old_daddr, backend.address, old_dport, backend.port)?;

    // Reverse CT entry for reply path
    let rev_ct_tuple = Ipv4CtTuple {
        daddr: old_saddr, saddr: backend.address,
        dport: old_sport, sport: backend.port,
        nexthdr: IPPROTO_TCP, flags: CT_EGRESS,
    };
    let rev_ct_state = CtState {
        rev_nat_index: svc.rev_nat_index, backend_id, closing: false, syn: false,
    };
    let _ = ct_create4(&rev_ct_tuple, &rev_ct_state);

    // SNAT
    let snat_cfg = SNAT_CONFIG.get(0).ok_or(())?;
    let target = SnatTarget {
        addr: snat_cfg.snat_addr, min_port: snat_cfg.min_port, max_port: snat_cfg.max_port,
    };
    nat::snat_v4_nat(ctx, ip, l4_off, old_saddr, old_sport, backend.address, backend.port, &target)?;

    // Stats
    let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
    stats::update_route_stats(svc.rev_nat_index, pkt_len, is_new);

    Ok(aya_ebpf::bindings::xdp_action::XDP_PASS)
}

#[inline(always)]
fn handle_reply(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    l4_off: usize,
    tcp_flags: u8,
) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;

    let (client_ip, client_port) = match nat::snat_v4_rev_nat(ctx, ip, l4_off) {
        Ok(result) => result,
        Err(()) => return Ok(pass),
    };

    let backend_ip = read_field(unsafe { addr_of!((*ip).saddr) });
    let backend_port =
        read_field(parse::ptr_at::<u16>(ctx, l4_off + parse::TCP_SPORT_OFF)? as *const u16);

    let rev_lookup_tuple = Ipv4CtTuple {
        daddr: client_ip, saddr: backend_ip,
        dport: client_port, sport: backend_port,
        nexthdr: IPPROTO_TCP, flags: CT_EGRESS,
    };

    let mut ct_state = CtState::new();
    match ct_lazy_lookup4(tcp_flags, &rev_lookup_tuple, CT_INGRESS, &mut ct_state) {
        CtStatus::New => return Ok(pass),
        CtStatus::Established | CtStatus::Reply => {}
    }

    if ct_state.rev_nat_index != 0 {
        lb::lb4_rev_nat(ctx, ip, l4_off, ct_state.rev_nat_index)?;
    }

    let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
    if ct_state.rev_nat_index != 0 {
        stats::update_route_stats(ct_state.rev_nat_index, pkt_len, false);
    }

    Ok(pass)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
