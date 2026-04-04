use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::links::FdLink;
use aya::programs::{Xdp, XdpFlags};
use clap::{Parser, Subcommand};
use log::info;
use serde::Deserialize;

const DEFAULT_PIN_PATH: &str = "/sys/fs/bpf/vtether";
const STATE_DIR: &str = "/run/vtether";

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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
}

#[derive(Subcommand)]
enum ProxyAction {
    /// Start forwarding with the given config
    Up {
        /// Path to YAML config file
        #[arg(short, long)]
        config: PathBuf,

        /// bpffs pin path for persisting the eBPF program
        #[arg(long, default_value = DEFAULT_PIN_PATH)]
        pin_path: PathBuf,
    },
    /// Stop all proxy routes
    Down {
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
    routes: Vec<RouteConfig>,
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

// ---- Main ----

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::init();

    match cli.command {
        Commands::Proxy { action } => match action {
            ProxyAction::Up { config, pin_path } => proxy_up(config, pin_path),
            ProxyAction::Down { pin_path } => proxy_down(pin_path),
        },
    }
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

fn proxy_up(config_path: PathBuf, pin_path: PathBuf) -> anyhow::Result<()> {
    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {}", config_path.display()))?;
    let config: Config =
        serde_yaml::from_str(&config_str).context("failed to parse config YAML")?;

    anyhow::ensure!(!config.routes.is_empty(), "no routes defined in config");

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

    // Check if already running
    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        !prog_pin.exists(),
        "proxy already running (pin {} exists). Run `vtether proxy down` first.",
        prog_pin.display()
    );

    // Load eBPF
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vtether-forward"
    )))
    .context("failed to load eBPF bytecode")?;

    // Populate NAT_CONFIG map
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

    // Load and attach XDP program
    let prog: &mut Xdp = ebpf
        .program_mut("vtether_xdp")
        .context("vtether_xdp program not found")?
        .try_into()?;
    prog.load().context("failed to load XDP program into kernel")?;

    // Attach first, then pin — so partial failures don't leave stale pins.
    let link_id = prog
        .attach(&config.interface, XdpFlags::default())
        .with_context(|| format!("failed to attach XDP to {}", config.interface))?;

    // From here on, use a closure to clean up on failure.
    let finish = || -> anyhow::Result<()> {
        std::fs::create_dir_all(&pin_path)
            .with_context(|| format!("failed to create pin dir: {}", pin_path.display()))?;

        prog.pin(&prog_pin)
            .context("failed to pin program to bpffs")?;

        let link = prog.take_link(link_id)?;
        let fd_link: FdLink = link
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to convert XDP link to FdLink: {}", e))?;
        fd_link
            .pin(pin_path.join("link"))
            .context("failed to pin XDP link to bpffs")?;

        // Save state for `proxy down`
        let state_dir = PathBuf::from(STATE_DIR);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed to create state dir: {}", state_dir.display()))?;
        std::fs::write(state_dir.join("interface"), &config.interface)?;

        Ok(())
    };

    if let Err(e) = finish() {
        // Clean up: detach XDP and remove any partial pins
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &config.interface, "xdp", "off"])
            .status();
        let _ = std::fs::remove_file(&prog_pin);
        let _ = std::fs::remove_file(pin_path.join("link"));
        let _ = std::fs::remove_dir(&pin_path);
        return Err(e.context("proxy up failed, cleaned up partial state"));
    }

    // Configure kernel for XDP NAT forwarding
    setup_sysctl(&config.interface)?;

    println!("vtether: proxy up (xdp on {}, snat_ip: {})", config.interface, snat_ip);
    for (port, to, proto) in &parsed_routes {
        println!("  {} :{} -> {}", protocol_name(*proto), port, to);
        info!("route: {} :{} -> {}", protocol_name(*proto), port, to);
    }

    Ok(())
}

fn proxy_down(pin_path: PathBuf) -> anyhow::Result<()> {
    let prog_pin = pin_path.join("prog");
    anyhow::ensure!(
        prog_pin.exists(),
        "no running proxy found (pin {} does not exist)",
        prog_pin.display()
    );

    // Read saved interface name
    let state_dir = PathBuf::from(STATE_DIR);
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

    // Unpin program and clean up
    let _ = std::fs::remove_file(&prog_pin);
    let _ = std::fs::remove_dir(&pin_path);
    let _ = std::fs::remove_dir_all(&state_dir);

    println!("vtether: proxy down (detached from {})", interface.trim());

    Ok(())
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
