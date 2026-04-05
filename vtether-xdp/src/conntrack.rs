/// Connection tracking module -- Cilium-inspired CT for vtether.
///
/// Cilium equivalent: `bpf/lib/conntrack.h` (~1368 lines).
///
/// # Design
///
/// Uses a single LruHashMap keyed by `Ipv4CtTuple`. Each connection has ONE entry
/// (keyed with `TUPLE_F_SERVICE`). Both forward and reply paths look up the same
/// entry; the `update_dir` parameter controls which flags (tx/rx) are updated.
///
/// # TCP State Machine
///
/// Cilium tracks TCP state via `tx_flags_seen` / `rx_flags_seen` which accumulate
/// observed TCP flags from each direction, plus `tx_closing` / `rx_closing` bitfields.
///
/// Timeout selection (from `ct_update_timeout` in Cilium):
/// - SYN-only (handshake): `CT_SYN_TIMEOUT` (60s)
/// - Non-SYN seen (`seen_non_syn`): `CT_CONNECTION_LIFETIME_TCP` (2h13m20s)
/// - After FIN/RST (`closing`): `CT_CLOSE_TIMEOUT` (10s)
use aya_ebpf::macros::map;
use aya_ebpf::maps::LruHashMap;

// ---- CT direction constants (passed to functions, NOT stored in tuple.flags) ----

/// Forward/egress direction: client -> service -> backend.
pub const CT_EGRESS: u8 = 0;
/// Reverse/reply direction: backend -> client.
pub const CT_INGRESS: u8 = 1;
/// Service connection direction (for tuple flag selection and close behavior).
pub const CT_SERVICE: u8 = 4;

// ---- Tuple flag constants (stored in Ipv4CtTuple.flags) ----

/// Service tuple flag value — the only flag used for service CT entries.
pub const TUPLE_F_SERVICE: u8 = 4;

// ---- TCP flags ----

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// ---- CT lookup result ----

/// Result of a conntrack lookup.
pub enum CtStatus {
    /// No existing entry found.
    New,
    /// Existing forward entry found.
    Established,
    /// Existing reply entry found (same entry, looked up on reply path).
    #[allow(dead_code)]
    Reply,
}

// ---- CT action selected from TCP flags ----

enum CtAction {
    Unspec,
    Create,
    Close,
}

#[inline(always)]
fn ct_tcp_select_action(flags: u8) -> CtAction {
    if flags & (TCP_RST | TCP_FIN) != 0 {
        return CtAction::Close;
    }
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
        return CtAction::Create;
    }
    CtAction::Unspec
}

// ---- Timeout constants (nanoseconds) ----

pub const CT_SYN_TIMEOUT_NS: u64 = 60 * 1_000_000_000; // 60s
pub const CT_ESTABLISHED_TIMEOUT_NS: u64 = 8000 * 1_000_000_000; // 2h13m20s (Cilium default)
pub const CT_CLOSE_TIMEOUT_NS: u64 = 10 * 1_000_000_000; // 10s

// ---- Map key/value types ----

/// CT tuple -- the map key.
///
/// All IPs and ports in **network byte order**.
#[repr(C, packed)]
pub struct Ipv4CtTuple {
    pub daddr: u32,
    pub saddr: u32,
    pub dport: u16,
    pub sport: u16,
    pub nexthdr: u8,
    pub flags: u8,
}

/// CT state passed between lookup and caller.
pub struct CtState {
    pub rev_nat_index: u16,
    pub backend_id: u32,
    pub closing: bool,
    pub syn: bool,
}

impl CtState {
    pub fn new() -> Self {
        Self {
            rev_nat_index: 0,
            backend_id: 0,
            closing: false,
            syn: false,
        }
    }
}

/// CT entry -- the map value.
#[repr(C)]
pub struct CtEntry {
    pub backend_id: u32,
    pub rev_nat_index: u16,
    pub closing: u8,
    pub seen_non_syn: u8,
    pub tx_flags_seen: u8,
    pub rx_flags_seen: u8,
    pub _pad: [u8; 2],
    pub lifetime: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

// Closing state bits
const CLOSING_RX: u8 = 0x01;
const CLOSING_TX: u8 = 0x02;

// ---- Maps ----

#[map]
pub static CT4: LruHashMap<Ipv4CtTuple, CtEntry> = LruHashMap::with_max_entries(131072, 0);

// ---- CT helpers ----

#[inline(always)]
fn ct_entry_alive(entry: &CtEntry) -> bool {
    entry.closing & (CLOSING_RX | CLOSING_TX) != (CLOSING_RX | CLOSING_TX)
}

#[inline(always)]
fn ct_entry_closing(entry: &CtEntry) -> bool {
    entry.closing & (CLOSING_RX | CLOSING_TX) != 0
}

#[inline(always)]
fn ct_entry_seen_both_syns(entry: &CtEntry) -> bool {
    (entry.rx_flags_seen & TCP_SYN != 0) && (entry.tx_flags_seen & TCP_SYN != 0)
}

#[inline(always)]
fn ct_reset_closing(entry: *mut CtEntry) {
    unsafe {
        (*entry).closing = 0;
    }
}

#[inline(always)]
fn ct_reset_seen_flags(entry: *mut CtEntry) {
    unsafe {
        (*entry).tx_flags_seen = 0;
        (*entry).rx_flags_seen = 0;
    }
}

#[inline(always)]
fn ct_select_timeout(entry: *mut CtEntry, tcp_flags: u8) -> u64 {
    let syn = tcp_flags & TCP_SYN != 0;
    if !syn {
        unsafe { (*entry).seen_non_syn = 1 };
    }
    if unsafe { (*entry).seen_non_syn } != 0 {
        CT_ESTABLISHED_TIMEOUT_NS
    } else {
        CT_SYN_TIMEOUT_NS
    }
}

#[inline(always)]
fn ct_update_timeout(entry: *mut CtEntry, lifetime_ns: u64, update_dir: u8, tcp_flags: u8) {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    unsafe { (*entry).lifetime = now + lifetime_ns };

    match update_dir {
        CT_INGRESS => unsafe { (*entry).rx_flags_seen |= tcp_flags },
        _ => unsafe { (*entry).tx_flags_seen |= tcp_flags },
    }
}

#[inline(always)]
fn ct_lookup_fill_state(ct_state: &mut CtState, entry: &CtEntry, syn: bool) {
    ct_state.rev_nat_index = entry.rev_nat_index;
    ct_state.backend_id = entry.backend_id;
    ct_state.closing = ct_entry_closing(entry);
    ct_state.syn = syn;
}

// ---- Core CT lookup ----

#[inline(always)]
fn ct_lookup_inner(
    tuple: &Ipv4CtTuple,
    action: CtAction,
    dir: u8,
    update_dir: u8,
    tcp_flags: u8,
    ct_state: &mut CtState,
) -> CtStatus {
    let entry_ptr = CT4.get_ptr_mut(tuple);
    let entry_ptr = match entry_ptr {
        Some(p) => p,
        None => return CtStatus::New,
    };

    let entry = unsafe { &*entry_ptr };
    let syn = tcp_flags & TCP_SYN != 0;

    if ct_entry_alive(entry) {
        let lifetime = ct_select_timeout(entry_ptr, tcp_flags);
        ct_update_timeout(entry_ptr, lifetime, update_dir, tcp_flags);
    }

    match action {
        CtAction::Create => {
            if ct_entry_closing(entry) {
                ct_reset_closing(entry_ptr);
                ct_reset_seen_flags(entry_ptr);
                unsafe { (*entry_ptr).seen_non_syn = 0 };

                let lifetime = ct_select_timeout(entry_ptr, tcp_flags);
                ct_update_timeout(entry_ptr, lifetime, update_dir, tcp_flags);

                return CtStatus::New;
            }
        }
        CtAction::Close => {
            let entry_ref = unsafe { &*entry_ptr };
            let both = CLOSING_RX | CLOSING_TX;
            let closing_bits = match dir {
                CT_SERVICE => both,
                _ if !ct_entry_seen_both_syns(entry_ref) && (tcp_flags & TCP_RST != 0) => both,
                CT_INGRESS => CLOSING_RX,
                _ => CLOSING_TX,
            };
            unsafe { (*entry_ptr).closing |= closing_bits };

            ct_state.closing = true;

            if !ct_entry_alive(unsafe { &*entry_ptr }) {
                ct_update_timeout(entry_ptr, CT_CLOSE_TIMEOUT_NS, update_dir, tcp_flags);
            }
        }
        CtAction::Unspec => {}
    }

    ct_lookup_fill_state(ct_state, unsafe { &*entry_ptr }, syn);
    CtStatus::Established
}

// ---- Public CT API ----

/// Lookup a CT entry for a service connection.
///
/// - `dir`: determines close behavior (CT_SERVICE closes both directions)
/// - `update_dir`: determines which flags are updated (CT_EGRESS -> tx, CT_INGRESS -> rx)
///
/// Forward path: `ct_lazy_lookup4(flags, tuple, CT_SERVICE, CT_EGRESS, state)`
/// Reply path:   `ct_lazy_lookup4(flags, tuple, CT_SERVICE, CT_INGRESS, state)`
#[inline(always)]
pub fn ct_lazy_lookup4(
    tcp_flags: u8,
    tuple: &Ipv4CtTuple,
    dir: u8,
    update_dir: u8,
    ct_state: &mut CtState,
) -> CtStatus {
    let action = ct_tcp_select_action(tcp_flags);
    ct_lookup_inner(tuple, action, dir, update_dir, tcp_flags, ct_state)
}

/// Create a new CT entry.
///
/// `update_dir` controls initial flag setup: CT_EGRESS sets tx_flags=SYN,
/// CT_INGRESS sets rx_flags=SYN.
#[inline(always)]
pub fn ct_create4(
    tuple: &Ipv4CtTuple,
    ct_state: &CtState,
    update_dir: u8,
) -> Result<(), ()> {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let entry = CtEntry {
        backend_id: ct_state.backend_id,
        rev_nat_index: ct_state.rev_nat_index,
        closing: 0,
        seen_non_syn: 0,
        tx_flags_seen: match update_dir {
            CT_INGRESS => 0,
            _ => TCP_SYN,
        },
        rx_flags_seen: match update_dir {
            CT_INGRESS => TCP_SYN,
            _ => 0,
        },
        _pad: [0; 2],
        lifetime: now + CT_SYN_TIMEOUT_NS,
        tx_packets: 0,
        tx_bytes: 0,
        rx_packets: 0,
        rx_bytes: 0,
    };

    CT4.insert(tuple, &entry, 0).map_err(|_| ())
}
