use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use anyhow::Context as _;
use aya::maps::{Array, HashMap, Map, MapData, PerCpuHashMap, PerCpuValues};
use aya::programs::links::FdLink;
use aya::programs::{Xdp, XdpFlags};
use clap::{Parser, Subcommand};
use log::info;
use serde::Deserialize;

const DEFAULT_PIN_PATH: &str = "/sys/fs/bpf/vtether";
const DEFAULT_CONFIG_PATH: &str = "/etc/vtether/config.yaml";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/vtether.service";
const STATE_BASE_DIR: &str = "/run/vtether";

const IPPROTO_TCP: u8 = 6;

// Adaptive GC interval bounds
const GC_INTERVAL_MIN_SECS: u64 = 10;
const GC_INTERVAL_MAX_SECS: u64 = 300;
const GC_INTERVAL_DEFAULT_SECS: u64 = 30;

// ---- CLI ----

#[derive(Parser)]
#[command(name = "vtether", about = "eBPF-based TCP port forwarder (XDP)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage proxy forwarding
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Install systemd unit file and default config
    Setup,
    /// Disable systemd service and remove unit file
    Remove,
    /// Show version information
    Version,
    /// Inspect active forwarding rules and connection metrics
    Inspect {
        /// bpffs pin path used during `proxy up`
        #[arg(long, default_value = DEFAULT_PIN_PATH)]
        pin_path: PathBuf,

        /// Show detailed CT and SNAT entries
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Start forwarding with the given config
    Up {
        /// Path to YAML config file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,

        /// bpffs pin path for persisting the eBPF program
        #[arg(long, default_value = DEFAULT_PIN_PATH)]
        pin_path: PathBuf,
    },
    /// Destroy proxy and clean up all resources
    Destroy {
        /// bpffs pin path used during `proxy up`
        #[arg(long, default_value = DEFAULT_PIN_PATH)]
        pin_path: PathBuf,
    },
}

// ---- Config ----

#[derive(Debug, Deserialize)]
struct Config {
    /// Network interface to attach XDP program to
    interface: String,
    /// IP address used as source in SNAT (auto-detected from interface if omitted)
    snat_ip: Option<String>,
    /// Max conntrack entries (default: 131072)
    #[serde(default = "default_conntrack_size")]
    conntrack_size: u32,
    #[serde(default)]
    routes: Vec<RouteConfig>,
}

fn default_conntrack_size() -> u32 {
    131_072
}

#[derive(Debug, Deserialize)]
struct RouteConfig {
    port: u16,
    to: String,
}

// ---- BPF map types (must match vtether-xdp eBPF layout exactly) ----

#[repr(C)]
#[derive(Clone, Copy)]
struct Lb4Key {
    address: u32,
    dport: u16,
    backend_slot: u16,
    proto: u8,
    scope: u8,
    _pad: [u8; 2],
}
unsafe impl aya::Pod for Lb4Key {}

#[repr(C)]
#[derive(Clone, Copy)]
struct Lb4Service {
    backend_id: u32,
    count: u16,
    rev_nat_index: u16,
    flags: u8,
    flags2: u8,
    _pad: u16,
}
unsafe impl aya::Pod for Lb4Service {}

#[repr(C)]
#[derive(Clone, Copy)]
struct Lb4Backend {
    address: u32,
    port: u16,
    proto: u8,
    flags: u8,
}
unsafe impl aya::Pod for Lb4Backend {}

#[repr(C)]
#[derive(Clone, Copy)]
struct Lb4ReverseNat {
    address: u32,
    port: u16,
    _pad: u16,
}
unsafe impl aya::Pod for Lb4ReverseNat {}

#[repr(C)]
#[derive(Clone, Copy)]
struct SnatConfig {
    snat_addr: u32,
    min_port: u16,
    max_port: u16,
}
unsafe impl aya::Pod for SnatConfig {}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv4CtTuple {
    daddr: u32,
    saddr: u32,
    dport: u16,
    sport: u16,
    nexthdr: u8,
    flags: u8,
}
unsafe impl aya::Pod for Ipv4CtTuple {}

#[repr(C)]
#[derive(Clone, Copy)]
struct CtEntry {
    backend_id: u32,
    rev_nat_index: u16,
    closing: u8,
    seen_non_syn: u8,
    tx_flags_seen: u8,
    rx_flags_seen: u8,
    _pad: [u8; 2],
    lifetime: u64,
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
}
unsafe impl aya::Pod for CtEntry {}

#[repr(C)]
#[derive(Clone, Copy)]
struct SnatEntry {
    created: u64,
    to_addr: u32,
    to_port: u16,
    svc_addr: u32,
    svc_port: u16,
}
unsafe impl aya::Pod for SnatEntry {}

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

// ---- Map pin names ----

const MAP_PINS: &[(&str, &str)] = &[
    ("LB4_SERVICES", "lb4_services"),
    ("LB4_BACKENDS", "lb4_backends"),
    ("LB4_REVERSE_NAT", "lb4_reverse_nat"),
    ("SNAT_CONFIG", "snat_config"),
    ("CT4", "ct4"),
    ("SNAT4", "snat4"),
    ("ROUTE_STATS", "route_stats"),
];

// ---- Main ----

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.command {
        Commands::Proxy { action } => match action {
            ProxyAction::Up { config, pin_path } => proxy_up(config, pin_path).await,
            ProxyAction::Destroy { pin_path } => proxy_destroy(&pin_path),
        },
        Commands::Setup => setup(),
        Commands::Remove => remove(),
        Commands::Version => {
            print_version();
            Ok(())
        }
        Commands::Inspect { pin_path, verbose } => inspect(&pin_path, verbose),
    }
}

/// Compute a per-instance state directory under /run/vtether/ derived from the pin path.
fn state_dir_for(pin_path: &std::path::Path) -> PathBuf {
    let instance = pin_path
        .file_name()
        .map_or_else(|| "default".to_string(), |n| n.to_string_lossy().into_owned());
    PathBuf::from(STATE_BASE_DIR).join(instance)
}

fn print_version() {
    println!(
        "vtether {} (commit {}, built {})",
        env!("VT_VERSION"),
        env!("VT_COMMIT"),
        env!("VT_BUILD_DATE"),
    );
}

fn get_interface_ipv4(interface: &str) -> anyhow::Result<Ipv4Addr> {
    let addrs = nix::ifaddrs::getifaddrs().context("failed to enumerate interface addresses")?;
    for ifaddr in addrs {
        if ifaddr.interface_name != interface {
            continue;
        }
        if let Some(addr) = ifaddr.address
            && let Some(sockaddr) = addr.as_sockaddr_in()
        {
            return Ok(sockaddr.ip());
        }
    }
    anyhow::bail!("no IPv4 address found on interface '{interface}'")
}

fn get_default_interface() -> anyhow::Result<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("failed to run `ip route`")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|&p| p == "dev")
            && let Some(iface) = parts.get(idx + 1)
        {
            return Ok(iface.to_string());
        }
    }
    anyhow::bail!("no default route found")
}

fn setup() -> anyhow::Result<()> {
    let vtether_bin = std::env::current_exe().context("failed to determine vtether binary path")?;
    let vtether_bin = vtether_bin.canonicalize().unwrap_or(vtether_bin);

    let default_iface = get_default_interface().unwrap_or_else(|_| "eth0".to_string());

    let config_dir = PathBuf::from(DEFAULT_CONFIG_PATH)
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    if PathBuf::from(DEFAULT_CONFIG_PATH).exists() {
        println!("  exists  {DEFAULT_CONFIG_PATH} (not overwritten)");
    } else {
        let config_content = format!(
            "\
# vtether configuration
# See: https://github.com/realityone/vtether

# Network interface to attach XDP program to
interface: {default_iface}

# Source IP for SNAT (optional, auto-detected from interface)
# snat_ip: \"192.168.1.100\"

# Max conntrack entries (default: 131072)
# conntrack_size: 131072

# TCP forwarding routes
# routes:
#   - port: 443
#     to: \"10.0.0.1:443\"
#   - port: 8080
#     to: \"10.0.0.2:80\"
"
        );
        std::fs::write(DEFAULT_CONFIG_PATH, &config_content)
            .with_context(|| format!("failed to write {DEFAULT_CONFIG_PATH}"))?;
        println!("  created {DEFAULT_CONFIG_PATH}");
    }

    let unit_content = format!(
        "\
[Unit]
Description=vtether - eBPF/XDP port forwarder
After=network.target

[Service]
Type=simple
ExecStart={bin} proxy up --config {config}
ExecStop={bin} proxy destroy

[Install]
WantedBy=multi-user.target
",
        bin = vtether_bin.display(),
        config = DEFAULT_CONFIG_PATH,
    );
    std::fs::write(SYSTEMD_UNIT_PATH, &unit_content)
        .with_context(|| format!("failed to write {SYSTEMD_UNIT_PATH}"))?;
    println!("  created {SYSTEMD_UNIT_PATH}");

    let status = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("failed to run systemctl daemon-reload")?;
    if !status.success() {
        anyhow::bail!("systemctl daemon-reload failed");
    }

    println!("\nvtether setup complete.");
    println!("  1. Edit {DEFAULT_CONFIG_PATH}");
    println!("  2. systemctl start vtether");
    println!("  3. systemctl enable vtether  (optional, to start on boot)");

    Ok(())
}

fn remove() -> anyhow::Result<()> {
    let _ = std::process::Command::new("systemctl")
        .args(["stop", "vtether"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["disable", "vtether"])
        .status();

    if PathBuf::from(SYSTEMD_UNIT_PATH).exists() {
        std::fs::remove_file(SYSTEMD_UNIT_PATH)
            .with_context(|| format!("failed to remove {SYSTEMD_UNIT_PATH}"))?;
        println!("  removed {SYSTEMD_UNIT_PATH}");
    }

    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();

    println!("\nvtether removed.");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn proxy_up(config_path: PathBuf, pin_path: PathBuf) -> anyhow::Result<()> {
    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {}", config_path.display()))?;
    let config: Config =
        serde_yaml::from_str(&config_str).context("failed to parse config YAML")?;

    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        !prog_pin.exists(),
        "proxy already running (pin {} exists). Run `vtether proxy destroy` first.",
        prog_pin.display()
    );

    if config.routes.is_empty() {
        println!(
            "vtether: no routes defined in {}, nothing to do",
            config_path.display()
        );
        return Ok(());
    }

    let snat_ip: Ipv4Addr = match &config.snat_ip {
        Some(ip_str) => ip_str
            .parse()
            .with_context(|| format!("invalid snat_ip: {ip_str}"))?,
        None => get_interface_ipv4(&config.interface)?,
    };
    let snat_ip_be = u32::from(snat_ip).to_be();

    // Parse all routes upfront
    let parsed_routes: Vec<(u16, SocketAddrV4)> = config
        .routes
        .iter()
        .map(|r| {
            let to: SocketAddrV4 =
                r.to.parse()
                    .with_context(|| format!("invalid 'to' address: {}", r.to))?;
            Ok((r.port, to))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Check for duplicate ports
    let mut seen = std::collections::HashSet::new();
    for (port, _) in &parsed_routes {
        anyhow::ensure!(seen.insert(*port), "duplicate route: tcp/{port}");
    }

    // Load vtether-xdp eBPF with configurable conntrack map size
    let mut ebpf = aya::EbpfLoader::new()
        .set_max_entries("CT4", config.conntrack_size)
        .set_max_entries("SNAT4", config.conntrack_size)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/vtether-xdp-forward"
        )))
        .context("failed to load eBPF bytecode")?;

    // Populate LB maps (one at a time to satisfy borrow checker)
    for (i, (port, to)) in parsed_routes.iter().enumerate() {
        let backend_id = (i + 1) as u32;
        let rev_nat_index = backend_id as u16;
        let listen_port_be = port.to_be();
        let backend_ip_be = u32::from(*to.ip()).to_be();
        let backend_port_be = to.port().to_be();

        // LB4_SERVICES: slot 0 (service descriptor) + slot 1 (backend ref)
        {
            let mut svc_map: HashMap<_, Lb4Key, Lb4Service> = HashMap::try_from(
                ebpf.map_mut("LB4_SERVICES")
                    .context("LB4_SERVICES not found")?,
            )?;
            svc_map.insert(
                Lb4Key {
                    address: snat_ip_be,
                    dport: listen_port_be,
                    backend_slot: 0,
                    proto: IPPROTO_TCP,
                    scope: 0,
                    _pad: [0; 2],
                },
                Lb4Service {
                    backend_id: 0,
                    count: 1,
                    rev_nat_index,
                    flags: 0,
                    flags2: 0,
                    _pad: 0,
                },
                0,
            )?;
            svc_map.insert(
                Lb4Key {
                    address: snat_ip_be,
                    dport: listen_port_be,
                    backend_slot: 1,
                    proto: IPPROTO_TCP,
                    scope: 0,
                    _pad: [0; 2],
                },
                Lb4Service {
                    backend_id,
                    count: 0,
                    rev_nat_index,
                    flags: 0,
                    flags2: 0,
                    _pad: 0,
                },
                0,
            )?;
        }

        // LB4_BACKENDS
        {
            let mut be_map: HashMap<_, u32, Lb4Backend> = HashMap::try_from(
                ebpf.map_mut("LB4_BACKENDS")
                    .context("LB4_BACKENDS not found")?,
            )?;
            be_map.insert(
                backend_id,
                Lb4Backend {
                    address: backend_ip_be,
                    port: backend_port_be,
                    proto: IPPROTO_TCP,
                    flags: 0,
                },
                0,
            )?;
        }

        // LB4_REVERSE_NAT
        {
            let mut rev_map: HashMap<_, u16, Lb4ReverseNat> = HashMap::try_from(
                ebpf.map_mut("LB4_REVERSE_NAT")
                    .context("LB4_REVERSE_NAT not found")?,
            )?;
            rev_map.insert(
                rev_nat_index,
                Lb4ReverseNat {
                    address: snat_ip_be,
                    port: listen_port_be,
                    _pad: 0,
                },
                0,
            )?;
        }
    }

    // Populate SNAT_CONFIG
    {
        let mut snat_map: Array<_, SnatConfig> = Array::try_from(
            ebpf.map_mut("SNAT_CONFIG")
                .context("SNAT_CONFIG not found")?,
        )?;
        snat_map.set(
            0,
            SnatConfig {
                snat_addr: snat_ip_be,
                min_port: 32768,
                max_port: 60999,
            },
            0,
        )?;
    }

    // Init eBPF logger
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        log::warn!("failed to init eBPF logger: {e}");
    }

    // Pin maps
    std::fs::create_dir_all(&pin_path)
        .with_context(|| format!("failed to create pin dir: {}", pin_path.display()))?;

    for &(map_name, pin_name) in MAP_PINS {
        if let Some(map) = ebpf.map(map_name) {
            map.pin(pin_path.join(pin_name))
                .with_context(|| format!("failed to pin {map_name} map"))?;
        }
    }

    // Load and attach XDP program
    let prog: &mut Xdp = ebpf
        .program_mut("vtether_xdp")
        .context("vtether_xdp program not found")?
        .try_into()?;
    prog.load()
        .context("failed to load XDP program into kernel")?;
    let link_id = prog
        .attach(&config.interface, XdpFlags::default())
        .with_context(|| format!("failed to attach XDP to {}", config.interface))?;

    let state_dir = state_dir_for(&pin_path);
    let finish = || -> anyhow::Result<()> {
        prog.pin(&prog_pin)
            .context("failed to pin program to bpffs")?;

        let link = prog.take_link(link_id)?;
        let fd_link: FdLink = link
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to convert XDP link to FdLink: {e}"))?;
        fd_link
            .pin(pin_path.join("link"))
            .context("failed to pin XDP link to bpffs")?;

        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed to create state dir: {}", state_dir.display()))?;
        std::fs::write(state_dir.join("interface"), &config.interface)?;

        setup_sysctl(&config.interface)?;

        Ok(())
    };

    if let Err(e) = finish() {
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &config.interface, "xdp", "off"])
            .status();
        let _ = std::fs::remove_file(&prog_pin);
        let _ = std::fs::remove_file(pin_path.join("link"));
        for &(_, pin_name) in MAP_PINS {
            let _ = std::fs::remove_file(pin_path.join(pin_name));
        }
        let _ = std::fs::remove_dir(&pin_path);
        let _ = std::fs::remove_dir_all(&state_dir);
        return Err(e.context("proxy up failed, cleaned up partial state"));
    }

    info!(
        "proxy up: xdp on {}, snat_ip: {}, conntrack: {}",
        config.interface, snat_ip, config.conntrack_size
    );
    println!(
        "vtether: proxy up (xdp on {}, snat_ip: {}, conntrack: {})",
        config.interface, snat_ip, config.conntrack_size
    );
    for (port, to) in &parsed_routes {
        println!("  tcp :{port} -> {to}");
        info!("route: tcp :{port} -> {to}");
    }

    // Spawn conntrack GC task
    let reaper_pin_path = pin_path.clone();
    let reaper_handle = tokio::spawn(async move {
        let mut gc_interval_secs = GC_INTERVAL_DEFAULT_SECS;
        info!(
            "conntrack gc started (initial interval: {gc_interval_secs}s, bounds: {GC_INTERVAL_MIN_SECS}s-{GC_INTERVAL_MAX_SECS}s)",
        );
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(gc_interval_secs)).await;
            match reap_conntrack(&reaper_pin_path) {
                Ok(result) => {
                    if result.expired > 0 || result.orphans > 0 {
                        info!(
                            "gc cycle: total={} expired={} orphans={} next_interval={}s",
                            result.total,
                            result.expired,
                            result.orphans,
                            adapt_gc_interval(gc_interval_secs, result.total, result.expired),
                        );
                    }
                    gc_interval_secs =
                        adapt_gc_interval(gc_interval_secs, result.total, result.expired);
                }
                Err(e) => {
                    log::warn!("conntrack gc error: {e:#}");
                }
            }
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        () = async {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            ).expect("failed to register SIGTERM handler");
            sigterm.recv().await;
        } => {
            info!("received SIGTERM, shutting down");
        }
    }

    reaper_handle.abort();
    info!("proxy up exiting");
    Ok(())
}

// ---- Conntrack GC ----
//
// Follows Cilium's two-phase GC design (pkg/maps/ctmap/gc/gc.go):
//   Phase 1: Delete CT entries where `entry.lifetime < now`
//   Phase 2: Purge orphan SNAT entries whose corresponding CT entry no longer exists
//
// The adaptive interval formula matches Cilium's calculateIntervalWithConfig:
//   >25% deleted: interval = interval * (1 - ratio)  (proportional shrink)
//   <5% deleted:  interval = interval * 1.5           (grow slowly)
//   5-25%:        keep unchanged

/// Read kernel monotonic clock (matches `bpf_ktime_get_ns` in the datapath).
/// Cilium uses `CLOCK_MONOTONIC`; `bpf_ktime_get_ns()` is also `CLOCK_MONOTONIC`.
fn ktime_get_ns() -> u64 {
    // Note: nix doesn't expose CLOCK_MONOTONIC_RAW directly, but
    // CLOCK_MONOTONIC matches bpf_ktime_get_ns() on Linux.
    let ts = nix::time::ClockId::CLOCK_MONOTONIC
        .now()
        .expect("CLOCK_MONOTONIC");
    ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64
}

struct GcResult {
    total: u64,
    expired: u64,
    orphans: u64,
}

/// Adaptive GC interval matching Cilium's formula.
///
/// Cilium (gc.go:579-600):
///   >25%: `prevInterval * (1.0 - deleteRatio)` (proportional)
/// > <5%:  `prevInterval * 1.5`
/// > else: unchanged
#[allow(clippy::cast_precision_loss)]
fn adapt_gc_interval(current_secs: u64, total: u64, expired: u64) -> u64 {
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

/// SNAT tuple direction flags (must match vtether-xdp nat.rs).
const TUPLE_F_IN: u8 = 1;
const TUPLE_F_SERVICE: u8 = 4;

fn reap_conntrack(pin_path: &std::path::Path) -> anyhow::Result<GcResult> {
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

// ---- Other commands ----

fn proxy_destroy(pin_path: &std::path::Path) -> anyhow::Result<()> {
    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        prog_pin.exists(),
        "no running proxy found (pin {} does not exist)",
        prog_pin.display()
    );

    let state_dir = state_dir_for(pin_path);
    let interface = std::fs::read_to_string(state_dir.join("interface"))
        .context("failed to read interface; was proxy started with `proxy up`?")?;

    let link_pin = pin_path.join("link");
    if link_pin.exists() {
        let link = aya::programs::links::PinnedLink::from_pin(&link_pin)
            .context("failed to load pinned link")?;
        link.unpin().context("failed to unpin link")?;
    }

    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", interface.trim(), "xdp", "off"])
        .status();

    let _ = std::fs::remove_file(&prog_pin);
    let _ = std::fs::remove_file(pin_path.join("link"));
    for &(_, pin_name) in MAP_PINS {
        let _ = std::fs::remove_file(pin_path.join(pin_name));
    }
    let _ = std::fs::remove_dir(pin_path);
    let _ = std::fs::remove_dir_all(&state_dir);

    println!(
        "vtether: proxy destroy (detached from {})",
        interface.trim()
    );

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn inspect(pin_path: &std::path::Path, verbose: bool) -> anyhow::Result<()> {
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
            )
                && let Ok(backend) = be_map.get(&slot1_svc.backend_id, 0)
            {
                let dst_ip = Ipv4Addr::from(u32::from_be(backend.address));
                let dst_port = u16::from_be(backend.port);
                println!(
                    "  tcp :{listen_port} -> {dst_ip}:{dst_port} (snat: {snat_ip})",
                );
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

// ---- Kernel setup ----

fn setup_sysctl(interface: &str) -> anyhow::Result<()> {
    let sysctls = [
        "net.ipv4.ip_forward=1".to_string(),
        "net.ipv4.conf.all.accept_local=1".to_string(),
        format!("net.ipv4.conf.{interface}.accept_local=1"),
    ];
    for s in &sysctls {
        let output = std::process::Command::new("sysctl")
            .args(["-w", s])
            .output()
            .with_context(|| format!("failed to run sysctl -w {s}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("sysctl -w {} failed: {}", s, stderr.trim());
        }
    }
    Ok(())
}
