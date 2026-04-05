use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use serde::Deserialize;

mod gc;
mod inspect;
mod proxy;
mod setup;

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

/// SNAT tuple direction flags (must match vtether-xdp nat.rs).
const TUPLE_F_IN: u8 = 1;
const TUPLE_F_SERVICE: u8 = 4;

// ---- Main ----

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.command {
        Commands::Proxy { action } => match action {
            ProxyAction::Up { config, pin_path } => proxy::proxy_up(config, pin_path).await,
            ProxyAction::Destroy { pin_path } => proxy::proxy_destroy(&pin_path),
        },
        Commands::Setup => setup::setup(),
        Commands::Remove => setup::remove(),
        Commands::Version => {
            print_version();
            Ok(())
        }
        Commands::Inspect { pin_path, verbose } => inspect::inspect(&pin_path, verbose),
    }
}

// ---- Shared helpers ----

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
