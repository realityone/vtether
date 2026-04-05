use aya::maps::{HashMap, Map, MapData};

use anyhow::Context as _;
use log::info;

pub const IPPROTO_TCP: u8 = 6;

// Adaptive GC interval bounds
pub const GC_INTERVAL_MIN_SECS: u64 = 10;
pub const GC_INTERVAL_MAX_SECS: u64 = 300;
pub const GC_INTERVAL_DEFAULT_SECS: u64 = 30;

/// SNAT tuple direction flags (must match vtether-xdp nat.rs).
const TUPLE_F_IN: u8 = 1;
const TUPLE_F_SERVICE: u8 = 4;

// ---- BPF map types for conntrack (must match vtether-xdp eBPF layout exactly) ----

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4CtTuple {
    pub daddr: u32,
    pub saddr: u32,
    pub dport: u16,
    pub sport: u16,
    pub nexthdr: u8,
    pub flags: u8,
}
unsafe impl aya::Pod for Ipv4CtTuple {}

#[repr(C)]
#[derive(Clone, Copy)]
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
unsafe impl aya::Pod for CtEntry {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnatEntry {
    pub created: u64,
    pub to_addr: u32,
    pub to_port: u16,
    pub svc_addr: u32,
    pub svc_port: u16,
}
unsafe impl aya::Pod for SnatEntry {}

pub struct GcResult {
    pub total: u64,
    pub expired: u64,
    pub orphans: u64,
}

/// Read kernel monotonic clock (matches `bpf_ktime_get_ns` in the datapath).
/// Cilium uses `CLOCK_MONOTONIC`; `bpf_ktime_get_ns()` is also `CLOCK_MONOTONIC`.
pub fn ktime_get_ns() -> u64 {
    let ts = nix::time::ClockId::CLOCK_MONOTONIC
        .now()
        .expect("CLOCK_MONOTONIC");
    ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64
}

/// Adaptive GC interval matching Cilium's formula.
///
/// Cilium (gc.go:579-600):
///   >25%: `prevInterval * (1.0 - deleteRatio)` (proportional)
/// > <5%:  `prevInterval * 1.5`
/// > else: unchanged
#[allow(clippy::cast_precision_loss)]
pub fn adapt_gc_interval(current_secs: u64, total: u64, expired: u64) -> u64 {
    if total == 0 {
        return current_secs;
    }
    let ratio_pct = expired * 100 / total;
    let new_secs = match ratio_pct {
        26.. => {
            // Cilium: interval * (1 - ratio). Cap ratio at 90% like Cilium does.
            let ratio = (expired as f64 / total as f64).min(0.9);
            (current_secs as f64 * (1.0 - ratio)) as u64
        }
        0..5 => current_secs * 3 / 2,
        _ => current_secs,
    };
    new_secs.clamp(GC_INTERVAL_MIN_SECS, GC_INTERVAL_MAX_SECS)
}

pub fn reap_conntrack(pin_path: &std::path::Path) -> anyhow::Result<GcResult> {
    let ct4_path = pin_path.join("ct4");
    let snat4_path = pin_path.join("snat4");
    if !ct4_path.exists() {
        return Ok(GcResult {
            total: 0,
            expired: 0,
            orphans: 0,
        });
    }

    let map_data = MapData::from_pin(&ct4_path).context("failed to load pinned CT4")?;
    let map = Map::LruHashMap(map_data);
    let mut ct4: HashMap<_, Ipv4CtTuple, CtEntry> =
        HashMap::try_from(map).context("failed to parse CT4 map")?;

    let now = ktime_get_ns();

    // ---- Phase 1: Expire CT entries whose absolute lifetime has passed ----
    // Cilium (ctmap.go:551): `if entry.Lifetime < filter.Time { deleteEntry }`
    let mut expired_keys: Vec<Ipv4CtTuple> = Vec::new();
    let mut total: u64 = 0;
    for (key, val) in ct4.iter().flatten() {
        total += 1;
        if val.lifetime < now {
            expired_keys.push(key);
        }
    }

    if !expired_keys.is_empty() {
        info!(
            "gc: removing {} expired CT entries (total: {})",
            expired_keys.len(),
            total
        );
    }
    for key in &expired_keys {
        let _ = ct4.remove(key);
    }

    // ---- Phase 2: Purge orphan SNAT entries ----
    // Cilium (ctmap.go:611-713 PurgeOrphanNATEntries):
    //   For each SNAT entry, construct the corresponding CT key.
    //   If no CT entry exists, the SNAT entry is orphaned — delete it.
    let mut snat_orphans: u64 = 0;
    if snat4_path.exists() {
        let snat_map_data =
            MapData::from_pin(&snat4_path).context("failed to load pinned SNAT4")?;
        let snat_map = Map::LruHashMap(snat_map_data);
        let mut snat4: HashMap<_, Ipv4CtTuple, SnatEntry> =
            HashMap::try_from(snat_map).context("failed to parse SNAT4 map")?;

        let mut orphan_keys: Vec<Ipv4CtTuple> = Vec::new();
        for (snat_key, snat_val) in snat4.iter().flatten() {
            // Construct the CT key that should exist if this SNAT entry is alive.
            //
            // With single-entry CT model, each connection has one CT entry keyed by
            // the service tuple: {daddr=VIP, saddr=client, dport=svc_port, sport=client_port}.
            // The SNAT entry stores svc_addr/svc_port for CT key reconstruction.
            //
            // For TUPLE_F_IN (reverse SNAT entry):
            //   SNAT val contains {to_addr=client_ip, to_port=client_port, svc_addr, svc_port}
            //   CT key = {daddr=svc_addr, saddr=client_ip, dport=svc_port, sport=client_port}
            //
            // For TUPLE_F_OUT (forward SNAT entry):
            //   Check if the reverse SNAT peer still exists.
            let exists = if snat_key.flags == TUPLE_F_IN {
                let ct_key = Ipv4CtTuple {
                    daddr: snat_val.svc_addr, // VIP
                    saddr: snat_val.to_addr,  // client_ip
                    dport: snat_val.svc_port, // svc_port
                    sport: snat_val.to_port,  // client_port
                    nexthdr: IPPROTO_TCP,
                    flags: TUPLE_F_SERVICE,
                };
                ct4.get(&ct_key, 0).is_ok()
            } else {
                // Forward SNAT -> check if reverse SNAT peer exists
                let rev_key = Ipv4CtTuple {
                    saddr: snat_val.to_addr, // snat_ip
                    daddr: snat_key.daddr,   // backend_ip
                    sport: snat_val.to_port, // snat_port
                    dport: snat_key.dport,   // backend_port
                    nexthdr: IPPROTO_TCP,
                    flags: TUPLE_F_IN,
                };
                snat4.get(&rev_key, 0).is_ok()
            };

            if !exists {
                orphan_keys.push(snat_key);
            }
        }

        if !orphan_keys.is_empty() {
            info!("gc: purging {} orphan SNAT entries", orphan_keys.len());
        }
        for key in &orphan_keys {
            let _ = snat4.remove(key);
        }
        snat_orphans = orphan_keys.len() as u64;
    }

    Ok(GcResult {
        total,
        expired: expired_keys.len() as u64,
        orphans: snat_orphans,
    })
}
