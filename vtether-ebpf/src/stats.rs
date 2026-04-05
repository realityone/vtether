use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuHashMap;

use crate::nat::NatKey;

#[repr(C)]
pub struct RouteStats {
    pub connections: u64,
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
}

#[map]
pub static ROUTE_STATS: PerCpuHashMap<NatKey, RouteStats> =
    PerCpuHashMap::with_max_entries(128, 0);

/// Increment per-route drop counter when conntrack is full.
#[inline(always)]
pub fn update_route_drops(nat_key: &NatKey) {
    if let Some(stats) = ROUTE_STATS.get_ptr_mut(nat_key) {
        unsafe { (*stats).drops += 1 };
    } else {
        let stats = RouteStats {
            connections: 0,
            packets: 0,
            bytes: 0,
            drops: 1,
        };
        let _ = ROUTE_STATS.insert(nat_key, &stats, 0);
    }
}

/// Increment per-route packet/byte counters. On first packet of a new connection, also bump connections.
#[inline(always)]
pub fn update_route_stats(nat_key: &NatKey, pkt_len: u64, new_conn: bool) {
    if let Some(stats) = ROUTE_STATS.get_ptr_mut(nat_key) {
        unsafe {
            (*stats).packets += 1;
            (*stats).bytes += pkt_len;
            if new_conn {
                (*stats).connections += 1;
            }
        }
    } else {
        let stats = RouteStats {
            connections: if new_conn { 1 } else { 0 },
            packets: 1,
            bytes: pkt_len,
            drops: 0,
        };
        let _ = ROUTE_STATS.insert(nat_key, &stats, 0);
    }
}
