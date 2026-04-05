/// Per-route statistics tracking.
///
/// Uses per-CPU maps for lock-free concurrent updates.
/// Keyed by `rev_nat_index` (stable service identity).

use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuHashMap;

/// Per-route traffic statistics.
#[repr(C)]
pub struct RouteStats {
    pub connections: u64,
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
}

/// Stats key -- keyed by rev_nat_index for stable identity across reconfigs.
#[repr(C)]
pub struct RouteStatsKey {
    pub rev_nat_index: u16,
    pub _pad: u16,
}

#[map]
pub static ROUTE_STATS: PerCpuHashMap<RouteStatsKey, RouteStats> =
    PerCpuHashMap::with_max_entries(256, 0);

/// Increment per-route packet/byte counters. On new connection, also bump connections.
#[inline(always)]
pub fn update_route_stats(rev_nat_index: u16, pkt_len: u64, new_conn: bool) {
    let key = RouteStatsKey {
        rev_nat_index,
        _pad: 0,
    };
    match ROUTE_STATS.get_ptr_mut(&key) {
        Some(stats) => unsafe {
            (*stats).packets += 1;
            (*stats).bytes += pkt_len;
            if new_conn {
                (*stats).connections += 1;
            }
        },
        None => {
            let stats = RouteStats {
                connections: u64::from(new_conn),
                packets: 1,
                bytes: pkt_len,
                drops: 0,
            };
            let _ = ROUTE_STATS.insert(&key, &stats, 0);
        }
    }
}

/// Increment per-route drop counter.
#[inline(always)]
pub fn update_route_drops(rev_nat_index: u16) {
    let key = RouteStatsKey {
        rev_nat_index,
        _pad: 0,
    };
    match ROUTE_STATS.get_ptr_mut(&key) {
        Some(stats) => unsafe { (*stats).drops += 1 },
        None => {
            let stats = RouteStats { connections: 0, packets: 0, bytes: 0, drops: 1 };
            let _ = ROUTE_STATS.insert(&key, &stats, 0);
        }
    }
}
