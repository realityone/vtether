#![no_std]
#![no_main]

mod conntrack;
mod csum;
mod nat;
mod parse;
mod stats;

use aya_ebpf::{macros::xdp, programs::XdpContext};
use core::ptr::{addr_of, addr_of_mut};

use conntrack::{
    ConntrackKey, ConntrackRevKey, ConntrackRevValue, ConntrackValue, CONNTRACK_IN, CONNTRACK_OUT,
    CT_SYN_TIMEOUT_NS, TCP_STATE_ESTABLISHED, TCP_STATE_FIN_CLIENT, TCP_STATE_FIN_SERVER,
};
use csum::{csum_replace2, csum_replace4};
use nat::{NatKey, NAT_CONFIG};
use parse::{ptr_at, read_field, write_field, Ipv4Hdr, IPPROTO_TCP, TCP_CSUM_OFF};
use stats::{update_route_drops, update_route_stats};

#[xdp]
pub fn vtether_xdp(ctx: XdpContext) -> u32 {
    match try_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => aya_ebpf::bindings::xdp_action::XDP_PASS,
    }
}

fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;

    // Parse Ethernet + IPv4, reject non-TCP
    parse::parse_eth(ctx)?;
    let (ip, transport_offset) = parse::parse_ipv4_tcp(ctx)?;

    // Read addresses and ports
    let src_ip = read_field(unsafe { addr_of!((*ip).src_addr) });
    let dst_ip = read_field(unsafe { addr_of!((*ip).dst_addr) });
    let src_port = read_field(ptr_at::<u16>(ctx, transport_offset)? as *const u16);
    let dst_port = read_field(ptr_at::<u16>(ctx, transport_offset + 2)? as *const u16);

    // === FORWARD PATH: client -> THIS_MACHINE:svc_port ===
    let nat_key = NatKey {
        port: u16::from_be(dst_port),
        protocol: IPPROTO_TCP,
        _pad: 0,
    };
    if let Some(config) = unsafe { NAT_CONFIG.get(&nat_key) } {
        return handle_forward(
            ctx,
            ip,
            transport_offset,
            &nat_key,
            config,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        );
    }

    // === RETURN PATH: backend_ip:svc_port -> snat_ip:snat_port ===
    let rev_key = ConntrackRevKey {
        dst_ip: src_ip,
        svc_port: src_port,
        snat_port: dst_port,
        protocol: IPPROTO_TCP,
        _pad: [0; 3],
    };
    if let Some(rev) = unsafe { CONNTRACK_IN.get(&rev_key) } {
        return handle_reverse(ctx, ip, transport_offset, &rev_key, rev, src_ip, dst_ip, src_port, dst_port);
    }

    Ok(pass)
}

// ---- Forward path: DNAT + SNAT for new/existing connections ----

#[inline(always)]
fn handle_forward(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    transport_offset: usize,
    nat_key: &NatKey,
    config: &nat::NatConfigEntry,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;
    let new_dst_ip = config.dst_ip;
    let new_src_ip = config.snat_ip;
    let new_dst_port = config.dst_port;

    // Lookup or create conntrack entry
    let fwd_key = ConntrackKey {
        client_ip: src_ip,
        client_port: src_port,
        svc_port: dst_port,
        protocol: IPPROTO_TCP,
        _pad: [0; 3],
    };

    let (snat_port, new_conn) = if let Some(existing) = CONNTRACK_OUT.get_ptr_mut(&fwd_key) {
        let snat_port = unsafe { (*existing).snat_port };
        conntrack::ct_update_lifetime(existing);
        (snat_port, false)
    } else {
        // New connection -- allocate SNAT port and create conntrack entries
        let port = conntrack::allocate_snat_port(src_ip, src_port, new_dst_ip, new_dst_port)?;

        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        let fwd_val = ConntrackValue {
            snat_ip: config.snat_ip,
            dst_ip: config.dst_ip,
            lifetime: now + CT_SYN_TIMEOUT_NS,
            orig_dst_port: dst_port,
            new_dst_port,
            snat_port: port,
            tcp_state: 0,
            _pad: 0,
        };
        if CONNTRACK_OUT.insert(&fwd_key, &fwd_val, 0).is_err() {
            update_route_drops(nat_key);
            return Ok(aya_ebpf::bindings::xdp_action::XDP_DROP);
        }

        let rev_key = ConntrackRevKey {
            dst_ip: config.dst_ip,
            svc_port: new_dst_port,
            snat_port: port,
            protocol: IPPROTO_TCP,
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
            update_route_drops(nat_key);
            return Ok(aya_ebpf::bindings::xdp_action::XDP_DROP);
        }

        (port, true)
    };

    // Rewrite IP addresses (DNAT + SNAT)
    write_field(unsafe { addr_of_mut!((*ip).dst_addr) }, new_dst_ip);
    write_field(unsafe { addr_of_mut!((*ip).src_addr) }, new_src_ip);

    // Rewrite ports
    if dst_port != new_dst_port {
        write_field(ptr_at::<u16>(ctx, transport_offset + 2)?, new_dst_port);
    }
    if src_port != snat_port {
        write_field(ptr_at::<u16>(ctx, transport_offset)?, snat_port);
    }

    // Update IP header checksum
    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, dst_ip, new_dst_ip);
    csum_replace4(ip_ck, src_ip, new_src_ip);

    // Update TCP checksum (IPs + ports)
    let tcp_ck = ptr_at::<u16>(ctx, transport_offset + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, dst_ip, new_dst_ip);
    csum_replace4(tcp_ck, src_ip, new_src_ip);
    if dst_port != new_dst_port {
        csum_replace2(tcp_ck, dst_port, new_dst_port);
    }
    if src_port != snat_port {
        csum_replace2(tcp_ck, src_port, snat_port);
    }

    // Update per-route stats
    let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
    update_route_stats(nat_key, pkt_len, new_conn);

    // Update TCP state + lifetime (FIN/RST handling; actual removal by userspace GC)
    conntrack::update_tcp_state(ctx, transport_offset, &fwd_key, TCP_STATE_FIN_CLIENT);

    Ok(pass)
}

// ---- Return path: reverse SNAT + DNAT ----

#[inline(always)]
fn handle_reverse(
    ctx: &XdpContext,
    ip: *mut Ipv4Hdr,
    transport_offset: usize,
    rev_key: &ConntrackRevKey,
    rev: &ConntrackRevValue,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
) -> Result<u32, ()> {
    let pass = aya_ebpf::bindings::xdp_action::XDP_PASS;
    let new_src_ip = rev.snat_ip;
    let new_dst_ip = rev.client_ip;
    let orig_svc_port = rev.orig_svc_port;
    let client_port = rev.client_port;

    // Reverse SNAT + DNAT (IPs)
    write_field(unsafe { addr_of_mut!((*ip).src_addr) }, new_src_ip);
    write_field(unsafe { addr_of_mut!((*ip).dst_addr) }, new_dst_ip);

    // Reverse port rewrites
    if src_port != orig_svc_port {
        write_field(ptr_at::<u16>(ctx, transport_offset)?, orig_svc_port);
    }
    if dst_port != client_port {
        write_field(ptr_at::<u16>(ctx, transport_offset + 2)?, client_port);
    }

    // Update IP checksum
    let ip_ck = unsafe { addr_of_mut!((*ip).check) };
    csum_replace4(ip_ck, src_ip, new_src_ip);
    csum_replace4(ip_ck, dst_ip, new_dst_ip);

    // Update TCP checksum
    let tcp_ck = ptr_at::<u16>(ctx, transport_offset + TCP_CSUM_OFF)?;
    csum_replace4(tcp_ck, src_ip, new_src_ip);
    csum_replace4(tcp_ck, dst_ip, new_dst_ip);
    if src_port != orig_svc_port {
        csum_replace2(tcp_ck, src_port, orig_svc_port);
    }
    if dst_port != client_port {
        csum_replace2(tcp_ck, dst_port, client_port);
    }

    // Mark connection as ESTABLISHED and refresh lifetime
    let fwd_key = ConntrackKey {
        client_ip: new_dst_ip,
        client_port,
        svc_port: orig_svc_port,
        protocol: IPPROTO_TCP,
        _pad: [0; 3],
    };
    if let Some(fwd_entry) = CONNTRACK_OUT.get_ptr_mut(&fwd_key) {
        unsafe { (*fwd_entry).tcp_state |= TCP_STATE_ESTABLISHED };
        conntrack::ct_update_lifetime(fwd_entry);
    }

    // Update per-route stats
    let ret_nat_key = NatKey {
        port: u16::from_be(orig_svc_port),
        protocol: IPPROTO_TCP,
        _pad: 0,
    };
    let pkt_len = u16::from_be(read_field(unsafe { addr_of!((*ip).tot_len) })) as u64;
    update_route_stats(&ret_nat_key, pkt_len, false);

    // Update TCP state + lifetime (FIN/RST handling; actual removal by userspace GC)
    conntrack::update_tcp_state(ctx, transport_offset, &fwd_key, TCP_STATE_FIN_SERVER);

    Ok(pass)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
