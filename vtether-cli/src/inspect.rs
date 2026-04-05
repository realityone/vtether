use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::maps::{HashMap, Map, MapData, PerCpuHashMap, PerCpuValues};

use crate::{
    gc::{CtEntry, Ipv4CtTuple, SnatEntry, ktime_get_ns},
    helper::state_dir_for,
    proxy::{Lb4Backend, Lb4Key, Lb4Service},
};

// ---- BPF map types for route stats (must match vtether-xdp eBPF layout exactly) ----

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteStatsKey {
    rev_nat_index: u16,
    _pad: u16,
}
unsafe impl aya::Pod for RouteStatsKey {}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteStats {
    connections: u64,
    packets: u64,
    bytes: u64,
    drops: u64,
}
unsafe impl aya::Pod for RouteStats {}

#[allow(clippy::too_many_lines)]
pub fn inspect(pin_path: &std::path::Path, verbose: bool) -> anyhow::Result<()> {
    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        prog_pin.exists(),
        "no running proxy found (pin {} does not exist)",
        prog_pin.display()
    );

    let state_dir = state_dir_for(pin_path);
    let interface = std::fs::read_to_string(state_dir.join("interface"))
        .unwrap_or_else(|_| "unknown".to_string());
    println!("vtether: attached to {}", interface.trim());

    // Load route stats map (per-CPU)
    let stats_path = pin_path.join("route_stats");
    let route_stats: Option<PerCpuHashMap<_, RouteStatsKey, RouteStats>> = if stats_path.exists() {
        let map_data =
            MapData::from_pin(&stats_path).context("failed to load pinned ROUTE_STATS")?;
        let map = Map::PerCpuHashMap(map_data);
        Some(PerCpuHashMap::try_from(map).context("failed to parse ROUTE_STATS map")?)
    } else {
        None
    };

    // Read LB4_SERVICES + LB4_BACKENDS + LB4_REVERSE_NAT to show routes
    let svc_path = pin_path.join("lb4_services");
    let be_path = pin_path.join("lb4_backends");
    let _rev_path = pin_path.join("lb4_reverse_nat");

    if svc_path.exists() && be_path.exists() {
        let svc_map: HashMap<_, Lb4Key, Lb4Service> = HashMap::try_from(Map::HashMap(
            MapData::from_pin(&svc_path).context("failed to load LB4_SERVICES")?,
        ))?;
        let be_map: HashMap<_, u32, Lb4Backend> = HashMap::try_from(Map::HashMap(
            MapData::from_pin(&be_path).context("failed to load LB4_BACKENDS")?,
        ))?;

        println!("\nRoutes:");
        // Iterate service entries (slot 0 only)
        for item in svc_map.iter() {
            let (key, svc) = item.map_err(|e| anyhow::anyhow!("map iteration error: {e}"))?;
            if key.backend_slot != 0 {
                continue;
            }

            // Find the backend for slot 1
            let listen_port = u16::from_be(key.dport);
            let snat_ip = Ipv4Addr::from(u32::from_be(key.address));

            // Look up backend via slot 1
            if let Ok(slot1_svc) = svc_map.get(
                &Lb4Key {
                    address: key.address,
                    dport: key.dport,
                    backend_slot: 1,
                    proto: key.proto,
                    scope: key.scope,
                    _pad: [0; 2],
                },
                0,
            ) && let Ok(backend) = be_map.get(&slot1_svc.backend_id, 0)
            {
                let dst_ip = Ipv4Addr::from(u32::from_be(backend.address));
                let dst_port = u16::from_be(backend.port);
                println!("  tcp :{listen_port} -> {dst_ip}:{dst_port} (snat: {snat_ip})",);
            }

            // Stats
            let stats_key = RouteStatsKey {
                rev_nat_index: svc.rev_nat_index,
                _pad: 0,
            };
            if let Some(s) = route_stats
                .as_ref()
                .and_then(|m| m.get(&stats_key, 0).ok())
                .map(|v| aggregate_stats(&v))
            {
                print!(
                    "    connections: {}  packets: {}  bytes: {}",
                    s.connections,
                    s.packets,
                    format_bytes(s.bytes),
                );
                if s.drops > 0 {
                    print!("  drops: {}", s.drops);
                }
                println!();
            }
        }
    }

    // CT entries
    let ct4_path = pin_path.join("ct4");
    if ct4_path.exists() {
        match (|| -> anyhow::Result<Vec<(Ipv4CtTuple, CtEntry)>> {
            let map_data = MapData::from_pin(&ct4_path).context("failed to load pinned CT4")?;
            let map = Map::LruHashMap(map_data);
            let ct4: HashMap<_, Ipv4CtTuple, CtEntry> =
                HashMap::try_from(map).context("failed to parse CT4 map")?;
            Ok(ct4.iter().filter_map(Result::ok).collect())
        })() {
            Ok(entries) => {
                println!("\nActive connections: {} CT entries", entries.len());
                if verbose {
                    let now = ktime_get_ns();
                    println!("\nCT4 entries ({}):", entries.len());
                    for (tuple, entry) in &entries {
                        print_ct_entry(tuple, entry, now);
                    }
                }
            }
            Err(e) => println!("\nActive connections: unknown ({e:#})"),
        }
    }

    // SNAT entries (verbose only)
    if verbose {
        let snat4_path = pin_path.join("snat4");
        if snat4_path.exists() {
            match (|| -> anyhow::Result<Vec<(Ipv4CtTuple, SnatEntry)>> {
                let map_data =
                    MapData::from_pin(&snat4_path).context("failed to load pinned SNAT4")?;
                let map = Map::LruHashMap(map_data);
                let snat4: HashMap<_, Ipv4CtTuple, SnatEntry> =
                    HashMap::try_from(map).context("failed to parse SNAT4 map")?;
                Ok(snat4.iter().filter_map(Result::ok).collect())
            })() {
                Ok(entries) => {
                    println!("\nSNAT4 entries ({}):", entries.len());
                    for (tuple, entry) in &entries {
                        print_snat_entry(tuple, entry);
                    }
                }
                Err(e) => println!("\nSNAT4: unknown ({e:#})"),
            }
        }
    }

    Ok(())
}

fn ct_flags_str(flags: u8) -> String {
    const TCP_FLAGS: &[(u8, &str)] = &[
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
    ];
    let parts: Vec<&str> = TCP_FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("|")
    }
}

fn ct_dir_str(flags: u8) -> &'static str {
    match flags {
        0 => "EGRESS",
        1 => "INGRESS",
        4 => "SERVICE",
        5 => "INGRESS|SERVICE",
        _ => "UNKNOWN",
    }
}

fn closing_str(closing: u8) -> String {
    let mut parts = Vec::new();
    if closing & 0x01 != 0 {
        parts.push("RX");
    }
    if closing & 0x02 != 0 {
        parts.push("TX");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("|")
    }
}

fn format_duration_human(secs: f64) -> String {
    let abs = secs.abs();
    if abs >= 3600.0 {
        format!("{:.1}h", secs / 3600.0)
    } else if abs >= 60.0 {
        format!("{:.0}m", secs / 60.0)
    } else {
        format!("{secs:.0}s")
    }
}

#[allow(clippy::cast_precision_loss)]
fn print_ct_entry(tuple: &Ipv4CtTuple, entry: &CtEntry, now_ns: u64) {
    let saddr = Ipv4Addr::from(u32::from_be(tuple.saddr));
    let daddr = Ipv4Addr::from(u32::from_be(tuple.daddr));
    let sport = u16::from_be(tuple.sport);
    let dport = u16::from_be(tuple.dport);

    let remaining_s = (entry.lifetime as f64 - now_ns as f64) / 1e9;
    let status = if remaining_s > 0.0 {
        "ALIVE"
    } else {
        "EXPIRED"
    };

    println!(
        "  {}:{} -> {}:{}  dir={}  [{}]",
        saddr,
        sport,
        daddr,
        dport,
        ct_dir_str(tuple.flags),
        status,
    );
    println!(
        "    backend_id={}  rev_nat={}  closing={}  seen_non_syn={}",
        entry.backend_id,
        entry.rev_nat_index,
        closing_str(entry.closing),
        entry.seen_non_syn,
    );
    println!(
        "    tx_flags={}  rx_flags={}  expires in {}",
        ct_flags_str(entry.tx_flags_seen),
        ct_flags_str(entry.rx_flags_seen),
        format_duration_human(remaining_s),
    );
}

fn print_snat_entry(tuple: &Ipv4CtTuple, entry: &SnatEntry) {
    let saddr = Ipv4Addr::from(u32::from_be(tuple.saddr));
    let daddr = Ipv4Addr::from(u32::from_be(tuple.daddr));
    let sport = u16::from_be(tuple.sport);
    let dport = u16::from_be(tuple.dport);

    let dir = match tuple.flags {
        0 => "OUT",
        1 => "IN",
        _ => "???",
    };

    let to_addr = Ipv4Addr::from(u32::from_be(entry.to_addr));
    let to_port = u16::from_be(entry.to_port);
    let svc_addr = Ipv4Addr::from(u32::from_be(entry.svc_addr));
    let svc_port = u16::from_be(entry.svc_port);

    println!(
        "  {saddr}:{sport} -> {daddr}:{dport}  dir={dir}  => {to_addr}:{to_port}  svc={svc_addr}:{svc_port}",
    );
}

fn aggregate_stats(per_cpu: &PerCpuValues<RouteStats>) -> RouteStats {
    let mut total = RouteStats {
        connections: 0,
        packets: 0,
        bytes: 0,
        drops: 0,
    };
    for s in per_cpu.iter() {
        total.connections += s.connections;
        total.packets += s.packets;
        total.bytes += s.bytes;
        total.drops += s.drops;
    }
    total
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;
    match bytes {
        TIB.. => format!("{:.2} TiB", bytes as f64 / TIB as f64),
        GIB.. => format!("{:.2} GiB", bytes as f64 / GIB as f64),
        MIB.. => format!("{:.2} MiB", bytes as f64 / MIB as f64),
        KIB.. => format!("{:.2} KiB", bytes as f64 / KIB as f64),
        _ => format!("{bytes} B"),
    }
}
