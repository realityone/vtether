/// FIB lookup and redirect module.
///
/// Cilium equivalent: `bpf/lib/fib.h` — `fib_redirect_v4()`, `fib_do_redirect()`.
///
/// After DNAT + SNAT, the packet's destination is a remote backend. The FIB
/// lookup resolves the next-hop MAC addresses and egress interface, then
/// `bpf_redirect()` forwards the packet at XDP level.
use aya_ebpf::bindings::{
    bpf_fib_lookup as BpfFibLookup, BPF_FIB_LKUP_RET_NO_NEIGH, BPF_FIB_LKUP_RET_SUCCESS,
};
use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::EbpfContext;
use core::mem;
use core::ptr::{addr_of, addr_of_mut};

use crate::parse::{ptr_at, read_field, write_field, Ipv4Hdr};

/// Debug: dump packet fields right before redirect
#[repr(C)]
pub struct PktDebug {
    pub count: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_csum: u16,
    pub tcp_csum: u16,
    pub ttl: u8,
    pub fib_ret: u8,
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub fib_ifindex: u32,
}

#[map]
pub static FIB_DEBUG: Array<PktDebug> = Array::with_max_entries(1, 0);

/// Decrement IPv4 TTL and update IP checksum.
///
/// Cilium equivalent: `ipv4_l3()` in `bpf/lib/l3.h`.
/// Must be called before FIB redirect to prevent routing loops.
///
/// Cilium's `ipv4_l3` also optionally rewrites MAC addresses, but the FIB
/// lookup fills those in, so we only decrement TTL here.
#[inline(always)]
pub fn ipv4_dec_ttl(_ctx: &XdpContext, ip: *mut Ipv4Hdr) -> Result<(), ()> {
    let ttl = read_field(unsafe { addr_of!((*ip).ttl) });
    if ttl <= 1 {
        // TTL expired — drop (Cilium returns DROP_TTL_EXCEEDED)
        return Err(());
    }

    // Decrement TTL
    write_field(unsafe { addr_of_mut!((*ip).ttl) }, ttl - 1);

    // Incremental IP checksum update for TTL change.
    // TTL is a single byte at a 16-bit boundary. The checksum adjustment:
    //   new_check = old_check + (old_ttl - new_ttl) in ones-complement
    // Since TTL decreases by 1, this is: old_check + 0x0100 (TTL is high byte of its 16-bit word).
    let check_ptr = unsafe { addr_of_mut!((*ip).check) };
    let old_check = unsafe { core::ptr::read_unaligned(check_ptr) };
    // Add 0x0100 to the checksum (TTL field is in the high byte of its 16-bit word)
    let mut sum = old_check as u32 + 0x0100u32;
    sum = (sum & 0xFFFF) + (sum >> 16);
    unsafe { core::ptr::write_unaligned(check_ptr, sum as u16) };

    Ok(())
}

/// Perform FIB lookup and redirect the packet to the resolved egress interface.
///
/// Cilium equivalent: `fib_redirect_v4()` + `fib_do_redirect()` in `bpf/lib/fib.h`.
///
/// ```c
/// fib_result = fib_lookup_v4(ctx, &fib_params, ip4->saddr, ip4->daddr, flags);
/// switch (fib_result) {
/// case BPF_FIB_LKUP_RET_SUCCESS:
/// case BPF_FIB_LKUP_RET_NO_NEIGH:
///     break;
/// default:
///     return DROP_NO_FIB;
/// }
/// // rewrite MACs from fib_params
/// // bpf_redirect(oif)
/// ```
///
/// On success: rewrites Ethernet src/dst MAC and returns XDP_REDIRECT.
/// On failure: returns Err (caller should XDP_DROP or XDP_PASS).
#[inline(always)]
pub fn fib_redirect_v4(ctx: &XdpContext, ip: *const Ipv4Hdr) -> Result<u32, ()> {
    let saddr = read_field(unsafe { addr_of!((*ip).saddr) });
    let daddr = read_field(unsafe { addr_of!((*ip).daddr) });

    // Zero-initialize the FIB lookup params.
    // Using MaybeUninit to avoid stack bloat from large struct init.
    let mut params: BpfFibLookup = unsafe { mem::zeroed() };
    params.family = 2; // AF_INET
    params.l4_protocol = crate::parse::IPPROTO_TCP;
    params.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    // Set tot_len in host byte order (the kernel compares against MTU).
    // The packet stores tot_len in network byte order, so convert it.
    unsafe { params.__bindgen_anon_1.tot_len = u16::from_be(read_field(addr_of!((*ip).tot_len))) };
    // Set tos (union field)
    unsafe { params.__bindgen_anon_2.tos = read_field(addr_of!((*ip).tos)) };
    // Set IPv4 src/dst (union fields)
    params.__bindgen_anon_3.ipv4_src = saddr;
    params.__bindgen_anon_4.ipv4_dst = daddr;

    let ret = unsafe {
        aya_ebpf::helpers::bpf_fib_lookup(
            ctx.as_ptr() as *mut _,
            &mut params as *mut BpfFibLookup as *mut _,
            mem::size_of::<BpfFibLookup>() as i32,
            0, // flags: no BPF_FIB_LOOKUP_DIRECT, use default FIB
        )
    };

    match ret as u32 {
        BPF_FIB_LKUP_RET_SUCCESS => {}
        _ => {
            return Ok(aya_ebpf::bindings::xdp_action::XDP_PASS);
        }
    }

    // Rewrite Ethernet header with resolved MACs.
    // Use raw pointer writes to avoid implicit memcpy on packed struct field assignment.
    let dst_mac_ptr = ptr_at::<[u8; 6]>(ctx, 0)?;
    let src_mac_ptr = ptr_at::<[u8; 6]>(ctx, 6)?;
    unsafe {
        core::ptr::write_unaligned(dst_mac_ptr, params.dmac);
        core::ptr::write_unaligned(src_mac_ptr, params.smac);
    }

    // Debug: only record forward-path packets (dst = Cloudflare 104.16.123.96)
    // 104.16.123.96 in network order read as LE u32: bytes 68 10 7b 60 -> 0x607b1068
    let cloudflare_ip: u32 = 0x607b1068;
    if daddr == cloudflare_ip {
        if let Some(dbg) = FIB_DEBUG.get_ptr_mut(0) {
            unsafe {
                (*dbg).count += 1;
                (*dbg).src_ip = saddr;
                (*dbg).dst_ip = daddr;
                (*dbg).ip_csum = read_field(addr_of!((*ip).check));
                (*dbg).ttl = read_field(addr_of!((*ip).ttl));
                (*dbg).fib_ret = ret as u8;
                (*dbg).dst_mac = params.dmac;
                (*dbg).src_mac = params.smac;
                (*dbg).fib_ifindex = params.ifindex;
                if let Ok(p) = ptr_at::<u16>(ctx, crate::parse::L4_OFF) {
                    (*dbg).src_port = read_field(p as *const u16);
                }
                if let Ok(p) = ptr_at::<u16>(ctx, crate::parse::L4_OFF + 2) {
                    (*dbg).dst_port = read_field(p as *const u16);
                }
                if let Ok(p) = ptr_at::<u16>(ctx, crate::parse::L4_OFF + crate::parse::TCP_CSUM_OFF) {
                    (*dbg).tcp_csum = read_field(p as *const u16);
                }
            }
        }
    }

    // Use bpf_redirect to send via the resolved egress interface.
    // NOTE: Do NOT use XDP_TX — on virtio_net, XDP_TX'd packets re-enter
    // the XDP program as RX, causing an infinite loop. bpf_redirect goes
    // through the egress path and does not re-enter XDP.
    let oif = params.ifindex;
    let action = unsafe { aya_ebpf::helpers::bpf_redirect(oif, 0) };
    Ok(action as u32)
}
