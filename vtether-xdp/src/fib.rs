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
use aya_ebpf::programs::XdpContext;
use aya_ebpf::EbpfContext;
use core::mem;
use core::ptr::{addr_of, addr_of_mut};

use crate::parse::{ptr_at, read_field, write_field, EthHdr, Ipv4Hdr};

/// Decrement IPv4 TTL and update IP checksum.
///
/// Cilium equivalent: `ipv4_l3()` in `bpf/lib/l3.h`.
/// Must be called before FIB redirect to prevent routing loops.
///
/// Cilium's `ipv4_l3` also optionally rewrites MAC addresses, but the FIB
/// lookup fills those in, so we only decrement TTL here.
#[inline(always)]
pub fn ipv4_dec_ttl(ctx: &XdpContext, ip: *mut Ipv4Hdr) -> Result<(), ()> {
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

    // Set tot_len (union field)
    unsafe { params.__bindgen_anon_1.tot_len = read_field(addr_of!((*ip).tot_len)) };
    // Set tos (union field)
    unsafe { params.__bindgen_anon_2.tos = read_field(addr_of!((*ip).tos)) };
    // Set IPv4 src/dst (union fields)
    unsafe { params.__bindgen_anon_3.ipv4_src = saddr };
    unsafe { params.__bindgen_anon_4.ipv4_dst = daddr };

    let ret = unsafe {
        aya_ebpf::helpers::bpf_fib_lookup(
            ctx.as_ptr() as *mut _,
            &mut params as *mut BpfFibLookup as *mut _,
            mem::size_of::<BpfFibLookup>() as i32,
            0, // flags: no BPF_FIB_LOOKUP_DIRECT, use default FIB
        )
    };

    // Cilium accepts SUCCESS and NO_NEIGH (where it falls back to neigh map).
    // vtether only accepts SUCCESS for now.
    match ret as u32 {
        BPF_FIB_LKUP_RET_SUCCESS => {}
        BPF_FIB_LKUP_RET_NO_NEIGH => {
            // Cilium falls back to a neighbor map here. vtether punts to stack.
            return Ok(aya_ebpf::bindings::xdp_action::XDP_PASS);
        }
        _ => return Err(()),
    }

    // Rewrite Ethernet header with resolved MACs.
    // Cilium: `ctx_store_bytes(ctx, 0, params.dmac, ...)` + `ctx_store_bytes(ctx, 6, params.smac, ...)`
    let eth: *mut EthHdr = ptr_at(ctx, 0)?;
    unsafe {
        (*eth).h_dest = params.dmac;
        (*eth).h_source = params.smac;
    }

    // Redirect to the resolved egress interface.
    let oif = params.ifindex;
    let action = unsafe { aya_ebpf::helpers::bpf_redirect(oif, 0) };
    Ok(action as u32)
}
