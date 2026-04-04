use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use anyhow::Context as _;
use aya::maps::{HashMap, Map, MapData, PerCpuHashMap, PerCpuValues};
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
const IPPROTO_UDP: u8 = 17;

// Conntrack reaper interval
const REAP_INTERVAL_SECS: u64 = 120;

// State-based timeouts matching Linux nf_conntrack patterns
const TCP_TIMEOUT_SYN_SENT: u64 = 120;
const TCP_TIMEOUT_ESTABLISHED: u64 = 432_000; // 5 days
const TCP_TIMEOUT_FIN_WAIT: u64 = 120;
const TCP_TIMEOUT_CLOSE: u64 = 10;
const UDP_TIMEOUT: u64 = 180;

// tcp_state bitfield (must match eBPF)
const TCP_STATE_ESTABLISHED: u8 = 0x01;
const TCP_STATE_FIN_CLIENT: u8 = 0x02;
const TCP_STATE_FIN_SERVER: u8 = 0x04;

// ---- CLI ----

#[derive(Parser)]
#[command(name = "vtether", about = "eBPF-based TCP/UDP port forwarder (XDP)")]
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
    /// Max conntrack entries (default: 65536)
    #[serde(default = "default_conntrack_size")]
    conntrack_size: u32,
    #[serde(default)]
    routes: Vec<RouteConfig>,
}

fn default_conntrack_size() -> u32 {
    65536
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Deserialize)]
struct RouteConfig {
    #[serde(default = "default_protocol")]
    protocol: String,
    port: u16,
    to: String,
}

// ---- BPF map types (must match vtether-ebpf exactly) ----

#[repr(C)]
#[derive(Clone, Copy)]
struct NatKey {
    port: u16,
    protocol: u8,
    _pad: u8,
}

unsafe impl aya::Pod for NatKey {}

#[repr(C)]
#[derive(Clone, Copy)]
struct NatConfigEntry {
    dst_ip: u32,
    snat_ip: u32,
    dst_port: u16,
    _pad: u16,
}

unsafe impl aya::Pod for NatConfigEntry {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConntrackKey {
    client_ip: u32,
    client_port: u16,
    svc_port: u16,
    protocol: u8,
    _pad: [u8; 3],
}

unsafe impl aya::Pod for ConntrackKey {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConntrackValue {
    snat_ip: u32,
    dst_ip: u32,
    last_seen_ns: u64,
    orig_dst_port: u16,
    new_dst_port: u16,
    snat_port: u16,
    tcp_state: u8,
    _pad: u8,
}

unsafe impl aya::Pod for ConntrackValue {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConntrackRevKey {
    dst_ip: u32,
    svc_port: u16,
    snat_port: u16,
    protocol: u8,
    _pad: [u8; 3],
}

unsafe impl aya::Pod for ConntrackRevKey {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConntrackRevValue {
    client_ip: u32,
    snat_ip: u32,
    orig_svc_port: u16,
    client_port: u16,
}

unsafe impl aya::Pod for ConntrackRevValue {}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteStats {
    connections: u64,
    packets: u64,
    bytes: u64,
    drops: u64,
}

unsafe impl aya::Pod for RouteStats {}

// ---- Main ----

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.command {
        Commands::Proxy { action } => match action {
            ProxyAction::Up { config, pin_path } => proxy_up(config, pin_path).await,
            ProxyAction::Destroy { pin_path } => proxy_destroy(pin_path),
        },
        Commands::Setup => setup(),
        Commands::Remove => remove(),
        Commands::Version => {
            print_version();
            Ok(())
        }
        Commands::Inspect { pin_path } => inspect(pin_path),
    }
}

/// Compute a per-instance state directory under /run/vtether/ derived from the pin path.
/// bpffs only supports BPF object pins, so regular files (like interface name) go here.
fn state_dir_for(pin_path: &std::path::Path) -> PathBuf {
    // Use the pin path's last component as the instance name
    let instance = pin_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "default".to_string());
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

fn parse_protocol(s: &str) -> anyhow::Result<u8> {
    match s {
        "tcp" => Ok(IPPROTO_TCP),
        "udp" => Ok(IPPROTO_UDP),
        other => anyhow::bail!("unsupported protocol '{}' (expected 'tcp' or 'udp')", other),
    }
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        _ => "unknown",
    }
}

fn get_interface_ipv4(interface: &str) -> anyhow::Result<Ipv4Addr> {
    let addrs = nix::ifaddrs::getifaddrs().context("failed to enumerate interface addresses")?;
    for ifaddr in addrs {
        if ifaddr.interface_name != interface {
            continue;
        }
        if let Some(addr) = ifaddr.address {
            if let Some(sockaddr) = addr.as_sockaddr_in() {
                return Ok(Ipv4Addr::from(sockaddr.ip()));
            }
        }
    }
    anyhow::bail!("no IPv4 address found on interface '{}'", interface)
}

fn get_default_interface() -> anyhow::Result<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("failed to run `ip route`")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|&p| p == "dev") {
            if let Some(iface) = parts.get(idx + 1) {
                return Ok(iface.to_string());
            }
        }
    }
    anyhow::bail!("no default route found")
}

fn setup() -> anyhow::Result<()> {
    let vtether_bin = std::env::current_exe().context("failed to determine vtether binary path")?;
    let vtether_bin = vtether_bin.canonicalize().unwrap_or(vtether_bin);

    let default_iface = get_default_interface().unwrap_or_else(|_| "eth0".to_string());

    // Write default config
    let config_dir = PathBuf::from(DEFAULT_CONFIG_PATH)
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    if !PathBuf::from(DEFAULT_CONFIG_PATH).exists() {
        let config_content = format!(
            "\
# vtether configuration
# See: https://github.com/realityone/vtether

# Network interface to attach XDP program to
interface: {default_iface}

# Source IP for SNAT (optional, auto-detected from interface)
# snat_ip: \"192.168.1.100\"

# Max conntrack entries (default: 65536)
# conntrack_size: 65536

# Forwarding routes
# routes:
#   - protocol: tcp    # tcp or udp (default: tcp)
#     port: 443
#     to: \"10.0.0.1:443\"
#   - protocol: udp
#     port: 53
#     to: \"10.0.0.2:53\"
"
        );
        std::fs::write(DEFAULT_CONFIG_PATH, &config_content)
            .with_context(|| format!("failed to write {}", DEFAULT_CONFIG_PATH))?;
        println!("  created {}", DEFAULT_CONFIG_PATH);
    } else {
        println!("  exists  {} (not overwritten)", DEFAULT_CONFIG_PATH);
    }

    // Write systemd unit file
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
        .with_context(|| format!("failed to write {}", SYSTEMD_UNIT_PATH))?;
    println!("  created {}", SYSTEMD_UNIT_PATH);

    // Reload systemd
    let status = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .context("failed to run systemctl daemon-reload")?;
    if !status.success() {
        anyhow::bail!("systemctl daemon-reload failed");
    }

    println!("\nvtether setup complete.");
    println!("  1. Edit {}", DEFAULT_CONFIG_PATH);
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
            .with_context(|| format!("failed to remove {}", SYSTEMD_UNIT_PATH))?;
        println!("  removed {}", SYSTEMD_UNIT_PATH);
    }

    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();

    println!("\nvtether removed.");
    Ok(())
}

async fn proxy_up(config_path: PathBuf, pin_path: PathBuf) -> anyhow::Result<()> {
    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {}", config_path.display()))?;
    let config: Config =
        serde_yaml::from_str(&config_str).context("failed to parse config YAML")?;

    // Check if already running before anything else
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
            .with_context(|| format!("invalid snat_ip: {}", ip_str))?,
        None => get_interface_ipv4(&config.interface)?,
    };
    let snat_ip_be = u32::from(snat_ip).to_be();

    // Parse all routes upfront
    let parsed_routes: Vec<(u16, SocketAddrV4, u8)> = config
        .routes
        .iter()
        .map(|r| {
            let proto = parse_protocol(&r.protocol)
                .with_context(|| format!("in route :{} -> {}", r.port, r.to))?;
            let to: SocketAddrV4 = r
                .to
                .parse()
                .with_context(|| format!("invalid 'to' address: {}", r.to))?;
            Ok((r.port, to, proto))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Check for duplicate (port, protocol) pairs
    let mut seen = std::collections::HashSet::new();
    for (port, _, proto) in &parsed_routes {
        anyhow::ensure!(
            seen.insert((*port, *proto)),
            "duplicate route: {}/{}",
            protocol_name(*proto),
            port
        );
    }

    // Load eBPF with configurable conntrack map size
    let mut ebpf = aya::EbpfLoader::new()
        .set_max_entries("CONNTRACK_OUT", config.conntrack_size)
        .set_max_entries("CONNTRACK_IN", config.conntrack_size)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/vtether-forward"
        )))
        .context("failed to load eBPF bytecode")?;

    // Populate NAT_CONFIG map
    {
        let mut nat_config: HashMap<_, NatKey, NatConfigEntry> =
            HashMap::try_from(ebpf.map_mut("NAT_CONFIG").context("NAT_CONFIG map not found")?)?;

        for (port, to, proto) in &parsed_routes {
            let key = NatKey {
                port: *port,
                protocol: *proto,
                _pad: 0,
            };
            let entry = NatConfigEntry {
                dst_ip: u32::from(*to.ip()).to_be(),
                snat_ip: snat_ip_be,
                dst_port: to.port().to_be(),
                _pad: 0,
            };
            nat_config.insert(key, entry, 0)?;
        }
    }

    // Create pin directory and pin maps before taking mutable program reference
    std::fs::create_dir_all(&pin_path)
        .with_context(|| format!("failed to create pin dir: {}", pin_path.display()))?;

    for (name, pin_name) in [
        ("NAT_CONFIG", "nat_config"),
        ("CONNTRACK_OUT", "conntrack_out"),
        ("CONNTRACK_IN", "conntrack_in"),
        ("ROUTE_STATS", "route_stats"),
    ] {
        if let Some(map) = ebpf.map(name) {
            map.pin(pin_path.join(pin_name))
                .with_context(|| format!("failed to pin {} map", name))?;
        }
    }

    // Load and attach XDP program
    let prog: &mut Xdp = ebpf
        .program_mut("vtether_xdp")
        .context("vtether_xdp program not found")?
        .try_into()?;
    prog.load()
        .context("failed to load XDP program into kernel")?;

    // Attach first, then pin — so partial failures don't leave stale pins.
    let link_id = prog
        .attach(&config.interface, XdpFlags::default())
        .with_context(|| format!("failed to attach XDP to {}", config.interface))?;

    // From here on, use a closure to clean up on failure.
    let state_dir = state_dir_for(&pin_path);
    let finish = || -> anyhow::Result<()> {
        prog.pin(&prog_pin)
            .context("failed to pin program to bpffs")?;

        let link = prog.take_link(link_id)?;
        let fd_link: FdLink = link
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to convert XDP link to FdLink: {}", e))?;
        fd_link
            .pin(pin_path.join("link"))
            .context("failed to pin XDP link to bpffs")?;

        // Save state for `proxy destroy` in a regular filesystem directory
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed to create state dir: {}", state_dir.display()))?;
        std::fs::write(state_dir.join("interface"), &config.interface)?;

        // Configure kernel for XDP NAT forwarding
        setup_sysctl(&config.interface)?;

        Ok(())
    };

    if let Err(e) = finish() {
        // Clean up: detach XDP and remove any partial pins/state
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &config.interface, "xdp", "off"])
            .status();
        let _ = std::fs::remove_file(&prog_pin);
        let _ = std::fs::remove_file(pin_path.join("link"));
        for pin_name in ["nat_config", "conntrack_out", "conntrack_in", "route_stats"] {
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
    for (port, to, proto) in &parsed_routes {
        println!("  {} :{} -> {}", protocol_name(*proto), port, to);
        info!("route: {} :{} -> {}", protocol_name(*proto), port, to);
    }

    // Spawn conntrack reaper task
    let reaper_pin_path = pin_path.clone();
    let reaper_handle = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(REAP_INTERVAL_SECS));
        info!(
            "conntrack reaper started (interval: {}s, timeouts: syn_sent={}s established={}s fin_wait={}s close={}s udp={}s)",
            REAP_INTERVAL_SECS, TCP_TIMEOUT_SYN_SENT, TCP_TIMEOUT_ESTABLISHED, TCP_TIMEOUT_FIN_WAIT, TCP_TIMEOUT_CLOSE, UDP_TIMEOUT,
        );
        loop {
            interval.tick().await;
            if let Err(e) = reap_conntrack(&reaper_pin_path) {
                log::warn!("conntrack reaper error: {:#}", e);
            }
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = async {
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

// ---- Conntrack reaper ----

fn ktime_get_ns() -> u64 {
    let ts = nix::time::ClockId::CLOCK_BOOTTIME
        .now()
        .expect("CLOCK_BOOTTIME");
    ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64
}

fn tcp_state_info(tcp_state: u8) -> (&'static str, u64) {
    let est = tcp_state & TCP_STATE_ESTABLISHED != 0;
    let fin_c = tcp_state & TCP_STATE_FIN_CLIENT != 0;
    let fin_s = tcp_state & TCP_STATE_FIN_SERVER != 0;
    match (est, fin_c, fin_s) {
        (false, _, _) => ("SYN_SENT", TCP_TIMEOUT_SYN_SENT),
        (true, false, false) => ("ESTABLISHED", TCP_TIMEOUT_ESTABLISHED),
        (true, true, true) => ("CLOSE", TCP_TIMEOUT_CLOSE),
        (true, _, _) => ("FIN_WAIT", TCP_TIMEOUT_FIN_WAIT),
    }
}

/// Return the timeout in nanoseconds for a conntrack entry based on protocol and TCP state.
fn conntrack_timeout_ns(protocol: u8, tcp_state: u8) -> u64 {
    let secs = match protocol {
        IPPROTO_TCP => tcp_state_info(tcp_state).1,
        _ => UDP_TIMEOUT,
    };
    secs * 1_000_000_000
}

fn conntrack_state_name(protocol: u8, tcp_state: u8) -> &'static str {
    match protocol {
        IPPROTO_TCP => tcp_state_info(tcp_state).0,
        _ => "ACTIVE",
    }
}

fn reap_conntrack(pin_path: &std::path::Path) -> anyhow::Result<()> {
    let conntrack_out_path = pin_path.join("conntrack_out");
    let conntrack_in_path = pin_path.join("conntrack_in");
    if !conntrack_out_path.exists() || !conntrack_in_path.exists() {
        return Ok(());
    }

    let map_data = MapData::from_pin(&conntrack_out_path)
        .context("failed to load pinned CONNTRACK_OUT")?;
    let map = Map::HashMap(map_data);
    let mut conntrack_out: HashMap<_, ConntrackKey, ConntrackValue> =
        HashMap::try_from(map).context("failed to parse CONNTRACK_OUT map")?;

    let map_data = MapData::from_pin(&conntrack_in_path)
        .context("failed to load pinned CONNTRACK_IN")?;
    let map = Map::HashMap(map_data);
    let mut conntrack_in: HashMap<_, ConntrackRevKey, ConntrackRevValue> =
        HashMap::try_from(map).context("failed to parse CONNTRACK_IN map")?;

    let now = ktime_get_ns();

    // Collect stale entries (can't remove while iterating)
    let mut stale: Vec<(ConntrackKey, ConntrackValue)> = Vec::new();
    for item in conntrack_out.iter() {
        if let Ok((key, val)) = item {
            let timeout = conntrack_timeout_ns(key.protocol, val.tcp_state);
            if now.saturating_sub(val.last_seen_ns) > timeout {
                stale.push((key, val));
            }
        }
    }

    if stale.is_empty() {
        return Ok(());
    }

    info!("reaper: removing {} stale conntrack entries", stale.len());
    for (key, val) in &stale {
        let client_ip = Ipv4Addr::from(u32::from_be(key.client_ip));
        let client_port = u16::from_be(key.client_port);
        let svc_port = u16::from_be(key.svc_port);
        let idle_secs = now.saturating_sub(val.last_seen_ns) / 1_000_000_000;
        info!(
            "reaper: {} {}:{} -> :{} state={} idle={}s",
            protocol_name(key.protocol),
            client_ip,
            client_port,
            svc_port,
            conntrack_state_name(key.protocol, val.tcp_state),
            idle_secs,
        );

        let _ = conntrack_out.remove(key);

        // Remove corresponding reverse entry
        let rev_key = ConntrackRevKey {
            dst_ip: val.dst_ip,
            svc_port: val.new_dst_port,
            snat_port: val.snat_port,
            protocol: key.protocol,
            _pad: [0; 3],
        };
        let _ = conntrack_in.remove(&rev_key);
    }

    Ok(())
}

// ---- Other commands ----

fn proxy_destroy(pin_path: PathBuf) -> anyhow::Result<()> {
    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        prog_pin.exists(),
        "no running proxy found (pin {} does not exist)",
        prog_pin.display()
    );

    // Read saved interface name from state directory
    let state_dir = state_dir_for(&pin_path);
    let interface = std::fs::read_to_string(state_dir.join("interface"))
        .context("failed to read interface; was proxy started with `proxy up`?")?;

    // Unpin link (this detaches XDP from the interface)
    let link_pin = pin_path.join("link");
    if link_pin.exists() {
        let link = aya::programs::links::PinnedLink::from_pin(&link_pin)
            .context("failed to load pinned link")?;
        link.unpin().context("failed to unpin link")?;
    }

    // Fallback: also try `ip link set xdp off` in case pin was stale
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", interface.trim(), "xdp", "off"])
        .status();

    // Unpin program, maps, and clean up
    let _ = std::fs::remove_file(&prog_pin);
    for pin_name in ["nat_config", "conntrack_out", "conntrack_in", "route_stats"] {
        let _ = std::fs::remove_file(pin_path.join(pin_name));
    }
    let _ = std::fs::remove_dir(&pin_path);
    let _ = std::fs::remove_dir_all(&state_dir);

    println!("vtether: proxy destroy (detached from {})", interface.trim());

    Ok(())
}

fn inspect(pin_path: PathBuf) -> anyhow::Result<()> {
    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        prog_pin.exists(),
        "no running proxy found (pin {} does not exist)",
        prog_pin.display()
    );

    let state_dir = state_dir_for(&pin_path);
    let interface = std::fs::read_to_string(state_dir.join("interface"))
        .unwrap_or_else(|_| "unknown".to_string());
    println!("vtether: attached to {}", interface.trim());

    // Load route stats map (per-CPU)
    let stats_map = pin_path.join("route_stats");
    let route_stats: Option<PerCpuHashMap<_, NatKey, RouteStats>> = if stats_map.exists() {
        let map_data =
            MapData::from_pin(&stats_map).context("failed to load pinned ROUTE_STATS")?;
        let map = Map::PerCpuHashMap(map_data);
        Some(PerCpuHashMap::try_from(map).context("failed to parse ROUTE_STATS map")?)
    } else {
        None
    };

    // Read NAT_CONFIG map — show configured routes with stats
    let nat_config_path = pin_path.join("nat_config");
    if nat_config_path.exists() {
        let map_data =
            MapData::from_pin(&nat_config_path).context("failed to load pinned NAT_CONFIG")?;
        let map = Map::HashMap(map_data);
        let nat_config: HashMap<_, NatKey, NatConfigEntry> =
            HashMap::try_from(map).context("failed to parse NAT_CONFIG map")?;

        println!("\nRoutes:");
        for item in nat_config.iter() {
            let (key, entry) = item.map_err(|e| anyhow::anyhow!("map iteration error: {}", e))?;
            let dst_ip = Ipv4Addr::from(u32::from_be(entry.dst_ip));
            let snat_ip = Ipv4Addr::from(u32::from_be(entry.snat_ip));
            let dst_port = u16::from_be(entry.dst_port);

            // Look up stats for this route, aggregating across all CPUs
            let stats = route_stats
                .as_ref()
                .and_then(|m| m.get(&key, 0).ok())
                .map(aggregate_stats);

            println!(
                "  {} :{} -> {}:{} (snat: {})",
                protocol_name(key.protocol),
                key.port,
                dst_ip,
                dst_port,
                snat_ip,
            );
            if let Some(s) = stats {
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

    // Read CONNTRACK_OUT map — count active connections
    let conntrack_out_path = pin_path.join("conntrack_out");
    if conntrack_out_path.exists() {
        let map_data = MapData::from_pin(&conntrack_out_path)
            .context("failed to load pinned CONNTRACK_OUT")?;
        let map = Map::HashMap(map_data);
        let conntrack: HashMap<_, ConntrackKey, ConntrackValue> =
            HashMap::try_from(map).context("failed to parse CONNTRACK_OUT map")?;

        let mut count: usize = 0;
        for item in conntrack.iter() {
            if item.is_ok() {
                count += 1;
            }
        }
        println!("\nActive connections: {}", count);
    }

    Ok(())
}

fn aggregate_stats(per_cpu: PerCpuValues<RouteStats>) -> RouteStats {
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
        _ => format!("{} B", bytes),
    }
}

// ---- Kernel setup ----

fn setup_sysctl(interface: &str) -> anyhow::Result<()> {
    let sysctls = [
        "net.ipv4.ip_forward=1".to_string(),
        "net.ipv4.conf.all.accept_local=1".to_string(),
        format!("net.ipv4.conf.{}.accept_local=1", interface),
    ];
    for s in &sysctls {
        let output = std::process::Command::new("sysctl")
            .args(["-w", s])
            .output()
            .with_context(|| format!("failed to run sysctl -w {}", s))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("sysctl -w {} failed: {}", s, stderr.trim());
        }
    }
    Ok(())
}
