use aya_ebpf::programs::XdpContext;
use core::mem;
use core::ptr::addr_of;

pub const ETH_P_IP: u16 = 0x0800;
pub const IPPROTO_TCP: u8 = 6;
pub const ETH_HDR_LEN: usize = 14;

// TCP header field offsets
pub const TCP_CSUM_OFF: usize = 16;
pub const TCP_FLAGS_OFF: usize = 13;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_RST: u8 = 0x04;

// ---- Packet headers ----

#[repr(C, packed)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
}

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
    pub src_addr: u32,
    pub dst_addr: u32,
}

// ---- Pointer helpers ----

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

#[inline(always)]
pub fn read_field<T: Copy>(ptr: *const T) -> T {
    unsafe { core::ptr::read_unaligned(ptr) }
}

#[inline(always)]
pub fn write_field<T>(ptr: *mut T, val: T) {
    unsafe { core::ptr::write_unaligned(ptr, val) };
}

// ---- Parsing ----

/// Parse Ethernet header, return Ok if IPv4.
#[inline(always)]
pub fn parse_eth(ctx: &XdpContext) -> Result<(), ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    match u16::from_be(read_field(unsafe { addr_of!((*eth).ether_type) })) {
        ETH_P_IP => Ok(()),
        _ => Err(()),
    }
}

/// Parse IPv4 header for TCP. Returns (ip_ptr, transport_offset).
/// Rejects non-TCP, non-initial fragments, and invalid headers.
#[inline(always)]
pub fn parse_ipv4_tcp(ctx: &XdpContext) -> Result<(*mut Ipv4Hdr, usize), ()> {
    let ip: *mut Ipv4Hdr = ptr_at(ctx, ETH_HDR_LEN)?;
    let protocol = read_field(unsafe { addr_of!((*ip).protocol) });
    if protocol != IPPROTO_TCP {
        return Err(());
    }

    // Drop non-initial fragments (no transport headers to NAT)
    let frag_off = u16::from_be(read_field(unsafe { addr_of!((*ip).frag_off) }));
    if frag_off & 0x1FFF != 0 {
        return Err(());
    }

    let ver_ihl = read_field(unsafe { addr_of!((*ip).ver_ihl) });
    let ip_hdr_len = ((ver_ihl & 0x0F) as usize) * 4;
    if ip_hdr_len < 20 || ip_hdr_len > 60 {
        return Err(());
    }

    Ok((ip, ETH_HDR_LEN + ip_hdr_len))
}
