use aya_ebpf::programs::XdpContext;
use core::mem;
use core::ptr::addr_of;

use crate::conntrack::Ipv4CtTuple;

// ---- Constants ----

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_HDR_LEN: usize = 14;
pub const IPPROTO_TCP: u8 = 6;

// IPv4 header field offsets (bytes from start of IPv4 header)
#[allow(dead_code)]
pub const IPV4_SADDR_OFF: usize = 12;
#[allow(dead_code)]
pub const IPV4_DADDR_OFF: usize = 16;

// TCP header field offsets (bytes from start of TCP header)
pub const TCP_SPORT_OFF: usize = 0;
pub const TCP_DPORT_OFF: usize = 2;
pub const TCP_FLAGS_OFF: usize = 13;
pub const TCP_CSUM_OFF: usize = 16;

// TCP flags — matches Cilium's TCP_FLAG_* definitions.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

// ---- Packet headers ----

/// Ethernet header (14 bytes).
#[repr(C, packed)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

/// IPv4 header (20 bytes without options).
/// Matches the kernel `struct iphdr` layout.
#[repr(C, packed)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

// ---- Pointer helpers ----

/// Bounds-checked pointer into the XDP packet buffer.
/// Every dereference must pass the verifier's `data + offset + size <= data_end` check.
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = start + offset;
    if ptr + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok(ptr as *mut T)
}

/// Read a potentially-unaligned field from a packed struct.
/// Required for all reads from `#[repr(C, packed)]` headers because
/// references to packed fields are UB.
#[inline(always)]
pub fn read_field<T: Copy>(ptr: *const T) -> T {
    unsafe { core::ptr::read_unaligned(ptr) }
}

/// Write a potentially-unaligned field in a packed struct.
#[inline(always)]
pub fn write_field<T>(ptr: *mut T, val: T) {
    unsafe { core::ptr::write_unaligned(ptr, val) };
}

// ---- Parsing functions ----

/// Parse Ethernet header, return Ok if IPv4.
/// Cilium equivalent: `validate_ethertype()` in `bpf_xdp.c`.
#[inline(always)]
pub fn parse_eth(ctx: &XdpContext) -> Result<(), ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    let proto = u16::from_be(read_field(unsafe { addr_of!((*eth).h_proto) }));
    if proto != ETH_P_IP {
        return Err(());
    }
    Ok(())
}

/// Parse IPv4 header, validate it is TCP, and compute the L4 offset.
/// Returns (ip_ptr, l4_offset).
///
/// Rejects:
/// - Non-TCP protocols
/// - Non-initial fragments (no L4 headers to NAT)
/// - Invalid IHL values
///
/// Cilium equivalent: first part of `lb4_extract_tuple()` in `bpf/lib/lb.h`.
#[inline(always)]
pub fn parse_ipv4(ctx: &XdpContext) -> Result<(*mut Ipv4Hdr, usize), ()> {
    let ip: *mut Ipv4Hdr = ptr_at(ctx, ETH_HDR_LEN)?;
    let protocol = read_field(unsafe { addr_of!((*ip).protocol) });
    if protocol != IPPROTO_TCP {
        return Err(());
    }

    // Drop non-initial fragments (offset field bits 0-12 != 0).
    let frag_off = u16::from_be(read_field(unsafe { addr_of!((*ip).frag_off) }));
    if frag_off & 0x1FFF != 0 {
        return Err(());
    }

    let ver_ihl = read_field(unsafe { addr_of!((*ip).ver_ihl) });
    let ihl = ((ver_ihl & 0x0F) as usize) * 4;
    if ihl < 20 || ihl > 60 {
        return Err(());
    }

    Ok((ip, ETH_HDR_LEN + ihl))
}

/// Extract a CT tuple from parsed IPv4 + TCP headers.
///
/// Cilium equivalent: `lb4_extract_tuple()` + `ipv4_load_l4_ports()`.
///
/// Note on port ordering: Cilium's `ipv4_load_l4_ports` loads {dport, sport}
/// into the tuple's {dport, sport} fields when `dir == CT_EGRESS`. The tuple
/// stores ports in the **original packet direction** — `dport` is the TCP
/// destination port, `sport` is the TCP source port.
///
/// The `flags` field is NOT set here — the caller sets it based on the
/// lookup direction (CT_EGRESS, CT_INGRESS, CT_SERVICE).
#[inline(always)]
pub fn extract_tuple(
    ctx: &XdpContext,
    ip: *const Ipv4Hdr,
    l4_off: usize,
) -> Result<Ipv4CtTuple, ()> {
    let daddr = read_field(unsafe { addr_of!((*ip).daddr) });
    let saddr = read_field(unsafe { addr_of!((*ip).saddr) });

    // Load TCP ports. Cilium reads them as a single 32-bit read for efficiency,
    // but we read them individually for clarity — both produce the same result.
    let sport = read_field(ptr_at::<u16>(ctx, l4_off + TCP_SPORT_OFF)? as *const u16);
    let dport = read_field(ptr_at::<u16>(ctx, l4_off + TCP_DPORT_OFF)? as *const u16);

    Ok(Ipv4CtTuple {
        daddr,
        saddr,
        dport,
        sport,
        nexthdr: IPPROTO_TCP,
        flags: 0, // Caller sets this
    })
}

/// Load TCP flags byte from the packet.
///
/// Cilium equivalent: `l4_load_tcp_flags()`.
/// Returns the flags byte (contains SYN, FIN, RST, ACK, etc.)
#[inline(always)]
pub fn load_tcp_flags(ctx: &XdpContext, l4_off: usize) -> Result<u8, ()> {
    let flags_ptr = ptr_at::<u8>(ctx, l4_off + TCP_FLAGS_OFF)?;
    Ok(read_field(flags_ptr as *const u8))
}

/// Parse ETH + IPv4 + TCP with a single bounds check that satisfies the eBPF verifier.
/// Returns (ip_ptr, l4_offset).
///
/// Uses a **constant** L4 offset of 34 (ETH_HDR_LEN + 20) and rejects packets
/// with IP options (IHL != 5). This avoids variable-offset packet accesses
/// which the eBPF verifier cannot track across map lookups and function calls.
///
/// The constant offset means the verifier only needs one bounds check:
/// `data + 54 <= data_end` (ETH 14 + IP 20 + TCP 20).
pub const L4_OFF: usize = ETH_HDR_LEN + 20; // 34

#[inline(always)]
pub fn parse_ipv4_tcp_validated(ctx: &XdpContext) -> Result<(*mut Ipv4Hdr, usize), ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // Single bounds check: ETH (14) + IPv4 (20) + TCP header (20) = 54 bytes.
    if start + L4_OFF + 20 > end {
        return Err(());
    }

    // Check ethertype is IPv4
    let eth: *const EthHdr = start as *const EthHdr;
    let proto = u16::from_be(read_field(unsafe { addr_of!((*eth).h_proto) }));
    if proto != ETH_P_IP {
        return Err(());
    }

    let ip: *mut Ipv4Hdr = (start + ETH_HDR_LEN) as *mut Ipv4Hdr;

    let protocol = read_field(unsafe { addr_of!((*ip).protocol) });
    if protocol != IPPROTO_TCP {
        return Err(());
    }

    // Reject non-initial fragments
    let frag_off = u16::from_be(read_field(unsafe { addr_of!((*ip).frag_off) }));
    if frag_off & 0x1FFF != 0 {
        return Err(());
    }

    // Reject IP options (IHL != 5). This keeps l4_off constant at 34,
    // which the verifier can track. IP options are extremely rare in practice.
    let ver_ihl = read_field(unsafe { addr_of!((*ip).ver_ihl) });
    if ver_ihl & 0x0F != 5 {
        return Err(());
    }

    Ok((ip, L4_OFF))
}

/// Compute the IPv4 header length from the IHL field.
#[inline(always)]
#[allow(dead_code)]
pub fn ipv4_hdrlen(ip: *const Ipv4Hdr) -> usize {
    let ver_ihl = read_field(unsafe { addr_of!((*ip).ver_ihl) });
    ((ver_ihl & 0x0F) as usize) * 4
}
