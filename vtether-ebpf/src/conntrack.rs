use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;

use crate::parse::{ptr_at, read_field, IPPROTO_TCP, TCP_FIN, TCP_FLAGS_OFF, TCP_RST};

// TCP state bitfield tracking connection lifecycle:
//   bit 0 (0x01): ESTABLISHED -- seen return traffic
//   bit 1 (0x02): FIN from client (forward path)
//   bit 2 (0x04): FIN from server (return path)
pub const TCP_STATE_ESTABLISHED: u8 = 0x01;
pub const TCP_STATE_FIN_CLIENT: u8 = 0x02;
pub const TCP_STATE_FIN_SERVER: u8 = 0x04;

// Lifetime constants (nanoseconds) — written as absolute expiry timestamps.
// Modeled after Cilium's CT timeout scheme: short timeout during SYN handshake,
// long timeout once established, very short timeout after both FINs or RST.
pub const CT_SYN_TIMEOUT_NS: u64 = 60 * 1_000_000_000; // 60s
pub const CT_ESTABLISHED_TIMEOUT_NS: u64 = 21_600 * 1_000_000_000; // 6 hours
pub const CT_CLOSE_TIMEOUT_NS: u64 = 10 * 1_000_000_000; // 10s

// ---- Map key/value types ----

#[repr(C)]
pub struct ConntrackKey {
    pub client_ip: u32,
    pub client_port: u16,
    pub svc_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct ConntrackValue {
    pub snat_ip: u32,
    pub dst_ip: u32,
    pub lifetime: u64,
    pub orig_dst_port: u16,
    pub new_dst_port: u16,
    pub snat_port: u16,
    pub tcp_state: u8,
    pub _pad: u8,
}

#[repr(C)]
pub struct ConntrackRevKey {
    pub dst_ip: u32,
    pub svc_port: u16,
    pub snat_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct ConntrackRevValue {
    pub client_ip: u32,
    pub snat_ip: u32,
    pub orig_svc_port: u16,
    pub client_port: u16,
}

// ---- Maps ----
//
// Using HashMap (not LruHashMap) so active connections are never silently evicted.
// When the map is full, new connections fail gracefully (XDP_DROP) instead of
// breaking existing ones. TCP entries are cleaned up on FIN/RST; the userspace
// reaper handles stale entries.
//
// The get-then-insert pattern is not atomic across operations, but is safe in
// practice because RSS/RPS steers packets of the same flow to the same CPU.

#[map]
pub static CONNTRACK_OUT: HashMap<ConntrackKey, ConntrackValue> =
    HashMap::with_max_entries(65536, 0);

#[map]
pub static CONNTRACK_IN: HashMap<ConntrackRevKey, ConntrackRevValue> =
    HashMap::with_max_entries(65536, 0);

// ---- TCP state tracking ----

/// Refresh the absolute lifetime of a conntrack entry based on its current TCP state.
/// Called on every matching packet. The datapath never removes entries — userspace GC
/// deletes them once `lifetime < now`.
#[inline(always)]
pub fn ct_update_lifetime(entry: *mut ConntrackValue) {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let state = unsafe { (*entry).tcp_state };
    let both_fin = TCP_STATE_FIN_CLIENT | TCP_STATE_FIN_SERVER;
    // Don't extend lifetime for entries already in CLOSE state
    if state & both_fin == both_fin {
        return;
    }
    let timeout = if state & TCP_STATE_ESTABLISHED != 0 {
        CT_ESTABLISHED_TIMEOUT_NS
    } else {
        CT_SYN_TIMEOUT_NS
    };
    unsafe { (*entry).lifetime = now + timeout };
}

/// Check TCP flags and update conntrack state + lifetime.
/// On RST or both FINs seen, sets a short close timeout instead of removing the entry.
#[inline(always)]
pub fn update_tcp_state(
    ctx: &XdpContext,
    transport_offset: usize,
    fwd_key: &ConntrackKey,
    fin_bit: u8,
) {
    let flags_ptr = match ptr_at::<u8>(ctx, transport_offset + TCP_FLAGS_OFF) {
        Ok(p) => p,
        Err(()) => return,
    };
    let flags = read_field(flags_ptr as *const u8);

    if flags & (TCP_RST | TCP_FIN) == 0 {
        return;
    }

    if let Some(entry) = CONNTRACK_OUT.get_ptr_mut(fwd_key) {
        if flags & TCP_RST != 0 {
            // RST: mark both directions closing, short timeout
            unsafe {
                (*entry).tcp_state |= TCP_STATE_FIN_CLIENT | TCP_STATE_FIN_SERVER;
                (*entry).lifetime =
                    aya_ebpf::helpers::bpf_ktime_get_ns() + CT_CLOSE_TIMEOUT_NS;
            }
        } else {
            // FIN: set the direction bit, check if both directions are now closing
            unsafe {
                let state = (*entry).tcp_state | fin_bit;
                (*entry).tcp_state = state;
                if state & (TCP_STATE_FIN_CLIENT | TCP_STATE_FIN_SERVER)
                    == (TCP_STATE_FIN_CLIENT | TCP_STATE_FIN_SERVER)
                {
                    (*entry).lifetime =
                        aya_ebpf::helpers::bpf_ktime_get_ns() + CT_CLOSE_TIMEOUT_NS;
                }
            }
        }
    }
}

// ---- SNAT port allocation ----

/// Allocate a unique SNAT source port for a new connection.
/// Tries the client's original port first; on collision, probes the ephemeral range.
/// Returns the allocated port in network byte order.
#[inline(always)]
pub fn allocate_snat_port(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
) -> Result<u16, ()> {
    // Try the client's original port first (most common case)
    let try_key = ConntrackRevKey {
        dst_ip,
        svc_port: dst_port,
        snat_port: src_port,
        protocol: IPPROTO_TCP,
        _pad: [0; 3],
    };
    if unsafe { CONNTRACK_IN.get(&try_key) }.is_none() {
        return Ok(src_port);
    }

    // Collision -- hash the connection tuple to pick a starting ephemeral port
    let hash = src_ip
        .wrapping_mul(0x9e3779b9)
        .wrapping_add(((src_port as u32) << 16) | (dst_port as u32))
        .wrapping_mul(0x517cc1b7);

    const EPHEMERAL_LO: u16 = 32768;
    const EPHEMERAL_HI: u16 = 60999;
    const EPHEMERAL_RANGE: u32 = (EPHEMERAL_HI - EPHEMERAL_LO + 1) as u32;

    let start = EPHEMERAL_LO + ((hash >> 8) % EPHEMERAL_RANGE) as u16;
    let mut port_host = start;
    let mut i: u32 = 0;
    while i < 128 {
        let candidate = port_host.to_be();
        let try_key = ConntrackRevKey {
            dst_ip,
            svc_port: dst_port,
            snat_port: candidate,
            protocol: IPPROTO_TCP,
            _pad: [0; 3],
        };
        if unsafe { CONNTRACK_IN.get(&try_key) }.is_none() {
            return Ok(candidate);
        }
        port_host = match port_host {
            EPHEMERAL_HI.. => EPHEMERAL_LO,
            _ => port_host + 1,
        };
        i += 1;
    }

    Err(())
}
