/// Connection tracking module — Cilium-inspired CT for vtether.
///
/// Cilium equivalent: `bpf/lib/conntrack.h` (~1368 lines).
///
/// # Design
///
/// Uses a single HashMap keyed by `Ipv4CtTuple`. Each connection has two entries:
/// forward (CT_EGRESS|CT_SERVICE) and reverse (CT_INGRESS), distinguished by `flags`.
///
/// # TCP State Machine
///
/// Cilium tracks TCP state via `tx_flags_seen` / `rx_flags_seen` which accumulate
/// observed TCP flags from each direction, plus `tx_closing` / `rx_closing` bitfields.
///
/// Timeout selection (from `ct_update_timeout` in Cilium):
/// - SYN-only (handshake): `CT_SYN_TIMEOUT` (60s)
/// - Non-SYN seen (`seen_non_syn`): `CT_CONNECTION_LIFETIME_TCP` (6h)
/// - After FIN/RST (`closing`): `CT_CLOSE_TIMEOUT` (10s)
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;

use crate::parse::{load_tcp_flags, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

// ---- CT direction flags (stored in Ipv4CtTuple.flags) ----

/// Forward/egress direction: client -> service -> backend.
pub const CT_EGRESS: u8 = 0;
/// Reverse/reply direction: backend -> client.
pub const CT_INGRESS: u8 = 1;
/// Service connection (used in combination with CT_EGRESS).
pub const CT_SERVICE: u8 = 4;

// ---- CT lookup result ----

/// Result of a conntrack lookup.
/// Cilium equivalent: `enum ct_status` values CT_NEW, CT_ESTABLISHED, CT_REPLY.
pub enum CtStatus {
    /// No existing entry found.
    New,
    /// Existing forward entry found.
    Established,
    /// Existing reverse (reply) entry found.
    #[allow(dead_code)]
    Reply,
}

// ---- CT action selected from TCP flags ----

/// Cilium equivalent: `ct_tcp_select_action()`.
/// ```c
/// if (flags & (TCP_FLAG_RST | TCP_FLAG_FIN)) return ACTION_CLOSE;
/// if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) return ACTION_CREATE;
/// return ACTION_UNSPEC;
/// ```
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

// ---- Timeout constants (seconds, converted to mono time by bpf_mono_now) ----
// Cilium uses `bpf_sec_to_mono()` which converts seconds to jiffies/mono.
// vtether uses nanoseconds from `bpf_ktime_get_ns()`.

pub const CT_SYN_TIMEOUT_NS: u64 = 60 * 1_000_000_000; // 60s
pub const CT_ESTABLISHED_TIMEOUT_NS: u64 = 21_600 * 1_000_000_000; // 6 hours
pub const CT_CLOSE_TIMEOUT_NS: u64 = 10 * 1_000_000_000; // 10s

// ---- Map key/value types ----

/// CT tuple — the map key.
///
/// Cilium equivalent: `struct ipv4_ct_tuple`.
/// ```c
/// struct ipv4_ct_tuple {
///     __be32 daddr;
///     __be32 saddr;
///     __be16 dport;
///     __be16 sport;
///     __u8   nexthdr;
///     __u8   flags;
/// } __packed;
/// ```
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
///
/// Cilium equivalent: fields extracted from `struct ct_state`.
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

/// CT entry — the map value.
///
/// Cilium equivalent: `struct ct_entry` (simplified for vtether).
///
/// Cilium's full `ct_entry` is 64 bytes with many bitfields. vtether keeps
/// the essential fields for TCP port forwarding.
#[repr(C)]
pub struct CtEntry {
    /// Backend ID referencing LB4_BACKENDS.
    /// Cilium stores this in `ct_entry.backend_id` (inside a union with nat_addr).
    pub backend_id: u32,
    /// Reverse NAT index for reply-path rewriting.
    pub rev_nat_index: u16,
    /// Closing state: bit 0 = rx_closing, bit 1 = tx_closing.
    /// Cilium uses separate bitfields `rx_closing:1, tx_closing:1`.
    pub closing: u8,
    /// Set to 1 once we've seen a non-SYN packet (promotes to established timeout).
    /// Cilium: `seen_non_syn:1` bitfield.
    pub seen_non_syn: u8,
    /// Accumulated TCP flags on the TX (forward/egress) direction.
    pub tx_flags_seen: u8,
    /// Accumulated TCP flags on the RX (reply/ingress) direction.
    pub rx_flags_seen: u8,
    pub _pad: [u8; 2],
    /// Absolute expiry timestamp (ns from `bpf_ktime_get_ns()`).
    /// Cilium uses `bpf_mono_now()` (seconds) — vtether uses nanoseconds for consistency
    /// with existing code.
    pub lifetime: u64,
    /// Forward packet counter.
    pub tx_packets: u64,
    /// Forward byte counter.
    pub tx_bytes: u64,
    /// Reply packet counter.
    pub rx_packets: u64,
    /// Reply byte counter.
    pub rx_bytes: u64,
}

// Closing state bits — match Cilium's rx_closing / tx_closing bitfields.
const CLOSING_RX: u8 = 0x01;
const CLOSING_TX: u8 = 0x02;

// ---- Maps ----

/// Main CT map.
/// Cilium equivalent: `cilium_ct4_global` (LRU_HASH).
/// vtether uses HashMap (not LRU) to avoid silent eviction of active connections.
#[map]
pub static CT4: HashMap<Ipv4CtTuple, CtEntry> = HashMap::with_max_entries(131072, 0);

// ---- CT helpers ----

/// Check if a CT entry is alive (not fully closed).
/// Cilium equivalent: `ct_entry_alive()` — checks `!rx_closing || !tx_closing`.
#[inline(always)]
fn ct_entry_alive(entry: &CtEntry) -> bool {
    entry.closing & (CLOSING_RX | CLOSING_TX) != (CLOSING_RX | CLOSING_TX)
}

/// Check if a CT entry is closing.
#[inline(always)]
fn ct_entry_closing(entry: &CtEntry) -> bool {
    entry.closing & (CLOSING_RX | CLOSING_TX) != 0
}

/// Check if both SYNs have been seen (full handshake).
/// Cilium: `ct_entry_seen_both_syns()`.
#[inline(always)]
fn ct_entry_seen_both_syns(entry: &CtEntry) -> bool {
    (entry.rx_flags_seen & TCP_SYN != 0) && (entry.tx_flags_seen & TCP_SYN != 0)
}

/// Reset closing state.
/// Cilium: `ct_reset_closing()`.
#[inline(always)]
fn ct_reset_closing(entry: *mut CtEntry) {
    unsafe {
        (*entry).closing = 0;
    }
}

/// Reset seen flags.
/// Cilium: `ct_reset_seen_flags()`.
#[inline(always)]
fn ct_reset_seen_flags(entry: *mut CtEntry) {
    unsafe {
        (*entry).tx_flags_seen = 0;
        (*entry).rx_flags_seen = 0;
    }
}

/// Select the timeout for this entry based on TCP state.
///
/// Cilium equivalent: `ct_update_timeout()`:
/// ```c
/// entry->seen_non_syn |= !syn;
/// if (entry->seen_non_syn)
///     lifetime = CT_CONNECTION_LIFETIME_TCP;  // 6 hours
/// else
///     lifetime = CT_SYN_TIMEOUT;              // 60s
/// ```
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

/// Update timeout and accumulate TCP flags.
///
/// Cilium equivalent: `__ct_update_timeout()`.
/// ```c
/// WRITE_ONCE(entry->lifetime, now + lifetime);
/// if (dir == CT_INGRESS) {
///     WRITE_ONCE(entry->rx_flags_seen, seen_flags | accumulated_flags);
/// } else {
///     WRITE_ONCE(entry->tx_flags_seen, seen_flags | accumulated_flags);
/// }
/// ```
#[inline(always)]
fn ct_update_timeout(entry: *mut CtEntry, lifetime_ns: u64, dir: u8, tcp_flags: u8) {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    unsafe { (*entry).lifetime = now + lifetime_ns };

    if dir == CT_INGRESS {
        unsafe { (*entry).rx_flags_seen |= tcp_flags };
    } else {
        unsafe { (*entry).tx_flags_seen |= tcp_flags };
    }
}

/// Fill ct_state from a found CT entry.
///
/// Cilium equivalent: `ct_lookup_fill_state()`.
#[inline(always)]
fn ct_lookup_fill_state(ct_state: &mut CtState, entry: &CtEntry, syn: bool) {
    ct_state.rev_nat_index = entry.rev_nat_index;
    ct_state.backend_id = entry.backend_id;
    ct_state.closing = ct_entry_closing(entry);
    ct_state.syn = syn;
}

// ---- Core CT lookup ----

/// Inner CT lookup — matches `__ct_lookup()` from Cilium's `conntrack.h`.
///
/// This function:
/// 1. Looks up the tuple in the map
/// 2. If found, processes the TCP action (CREATE/CLOSE/UNSPEC)
/// 3. Updates timeout and flags
/// 4. Returns CT_ESTABLISHED or CT_NEW
///
/// Cilium's key logic flow:
/// ```c
/// entry = map_lookup_elem(map, tuple);
/// if (entry) {
///     if (ct_entry_alive(entry))
///         ct_update_timeout(entry, ...);
///     switch (action) {
///     case ACTION_CREATE:
///         if (ct_entry_closing(entry)) { reset; return CT_NEW; }
///         break;
///     case ACTION_CLOSE:
///         set closing bits; if (!alive) lifetime = CT_CLOSE_TIMEOUT;
///         break;
///     }
///     ct_lookup_fill_state(ct_state, entry);
///     return CT_ESTABLISHED;
/// }
/// return CT_NEW;
/// ```
#[inline(always)]
fn ct_lookup_inner(
    tuple: &Ipv4CtTuple,
    action: CtAction,
    dir: u8,
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

    // Update timeout if entry is alive
    if ct_entry_alive(entry) {
        let lifetime = ct_select_timeout(entry_ptr, tcp_flags);
        ct_update_timeout(entry_ptr, lifetime, dir, tcp_flags);
    }

    // Process TCP action
    match action {
        CtAction::Create => {
            // SYN on a closing connection — recycle the entry.
            // Cilium: if (ct_entry_closing(entry)) { ct_reset_closing; return CT_NEW; }
            if ct_entry_closing(entry) {
                ct_reset_closing(entry_ptr);
                ct_reset_seen_flags(entry_ptr);
                unsafe { (*entry_ptr).seen_non_syn = 0 };

                let lifetime = ct_select_timeout(entry_ptr, tcp_flags);
                ct_update_timeout(entry_ptr, lifetime, dir, tcp_flags);

                return CtStatus::New;
            }
        }
        CtAction::Close => {
            // Cilium's ACTION_CLOSE logic:
            // For CT_SERVICE (forward only): close both directions.
            // Otherwise: if RST and haven't seen both SYNs, close both.
            //            else close the relevant direction.
            let entry_ref = unsafe { &*entry_ptr };
            if dir == CT_SERVICE {
                unsafe {
                    (*entry_ptr).closing = CLOSING_RX | CLOSING_TX;
                }
            } else if !ct_entry_seen_both_syns(entry_ref) && (tcp_flags & TCP_RST != 0) {
                unsafe {
                    (*entry_ptr).closing = CLOSING_RX | CLOSING_TX;
                }
            } else if dir == CT_INGRESS {
                unsafe {
                    (*entry_ptr).closing |= CLOSING_RX;
                }
            } else {
                unsafe {
                    (*entry_ptr).closing |= CLOSING_TX;
                }
            }

            ct_state.closing = true;

            // If entry is no longer alive, set short close timeout
            if !ct_entry_alive(unsafe { &*entry_ptr }) {
                ct_update_timeout(entry_ptr, CT_CLOSE_TIMEOUT_NS, dir, tcp_flags);
            }
        }
        CtAction::Unspec => {}
    }

    // Fill state from the entry
    ct_lookup_fill_state(ct_state, unsafe { &*entry_ptr }, syn);
    CtStatus::Established
}

// ---- Public CT API ----

/// Lookup a CT entry for the forward (egress/service) direction.
///
/// Cilium equivalent: `ct_lazy_lookup4()` with `SCOPE_REVERSE`.
///
/// Cilium's `SCOPE_REVERSE` means: look up the tuple as-is first (which matches
/// the reverse/reply entry), and if not found, that's CT_NEW.
///
/// For the service path (forward direction), Cilium does:
/// 1. Set `tuple->flags = TUPLE_F_IN` (for reverse lookup direction)
/// 2. Look up — if found, it's a CT_REPLY (existing connection's reply entry)
/// 3. If not found, return CT_NEW
///
/// vtether simplifies: on the forward path, we look up with `CT_EGRESS|CT_SERVICE`
/// flags directly. The tuple is stored in the forward direction.
#[inline(always)]
pub fn ct_lazy_lookup4(
    ctx: &XdpContext,
    tuple: &Ipv4CtTuple,
    l4_off: usize,
    dir: u8,
    ct_state: &mut CtState,
) -> Result<CtStatus, ()> {
    let tcp_flags = load_tcp_flags(ctx, l4_off)?;
    let action = ct_tcp_select_action(tcp_flags);
    Ok(ct_lookup_inner(tuple, action, dir, tcp_flags, ct_state))
}

/// Create a new CT entry.
///
/// Cilium equivalent: `ct_create4()`.
/// ```c
/// struct ct_entry entry = {};
/// ct_create_fill_entry(&entry, ct_state, dir);
/// seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
/// ct_update_timeout(&entry, is_tcp, dir, seen_flags);
/// map_update_elem(map_main, tuple, &entry, 0);
/// ```
#[inline(always)]
pub fn ct_create4(tuple: &Ipv4CtTuple, ct_state: &CtState) -> Result<(), ()> {
    let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let entry = CtEntry {
        backend_id: ct_state.backend_id,
        rev_nat_index: ct_state.rev_nat_index,
        closing: 0,
        seen_non_syn: 0, // SYN only at creation
        tx_flags_seen: if tuple.flags & CT_INGRESS == 0 { TCP_SYN } else { 0 },
        rx_flags_seen: if tuple.flags & CT_INGRESS != 0 { TCP_SYN } else { 0 },
        _pad: [0; 2],
        lifetime: now + CT_SYN_TIMEOUT_NS,
        tx_packets: 0,
        tx_bytes: 0,
        rx_packets: 0,
        rx_bytes: 0,
    };

    CT4.insert(tuple, &entry, 0).map_err(|_| ())
}

/// Update the backend_id and rev_nat_index on an existing CT entry.
///
/// Cilium equivalent: `ct_update_svc_entry()`.
/// Used when a backend changes (e.g., backend deleted, need to re-select).
#[inline(always)]
#[allow(dead_code)]
pub fn ct_update_svc_entry(tuple: &Ipv4CtTuple, backend_id: u32, rev_nat_index: u16) {
    if let Some(entry) = CT4.get_ptr_mut(tuple) {
        unsafe {
            (*entry).backend_id = backend_id;
            (*entry).rev_nat_index = rev_nat_index;
        }
    }
}

/// Reverse a CT tuple (swap src/dst addresses and ports, flip direction flag).
///
/// Cilium equivalent: `ipv4_ct_tuple_reverse()`.
/// Used to create the reverse CT entry from the forward tuple.
#[inline(always)]
#[allow(dead_code)]
pub fn ipv4_ct_tuple_reverse(tuple: &Ipv4CtTuple) -> Ipv4CtTuple {
    Ipv4CtTuple {
        daddr: tuple.saddr,
        saddr: tuple.daddr,
        dport: tuple.sport,
        sport: tuple.dport,
        nexthdr: tuple.nexthdr,
        // Flip direction: EGRESS <-> INGRESS
        flags: if tuple.flags & CT_INGRESS != 0 {
            tuple.flags & !CT_INGRESS
        } else {
            tuple.flags | CT_INGRESS
        },
    }
}
