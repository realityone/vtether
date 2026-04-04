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
    /// This machine's IP on that interface (used for SNAT)
    this_ip: String,
    routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize)]
struct RouteConfig {
    from: String,
    to: String,
}

// ---- BPF map value (must match vtether-ebpf NatConfigEntry exactly) ----

#[repr(C)]
#[derive(Clone, Copy)]
struct NatConfigEntry {
    dst_ip: u32,
    this_ip: u32,
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

fn proxy_up(config_path: PathBuf, pin_path: PathBuf) -> anyhow::Result<()> {
    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {}", config_path.display()))?;
    let config: Config =
        serde_yaml::from_str(&config_str).context("failed to parse config YAML")?;

    anyhow::ensure!(!config.routes.is_empty(), "no routes defined in config");

    let this_ip: Ipv4Addr = config
        .this_ip
        .parse()
        .with_context(|| format!("invalid this_ip: {}", config.this_ip))?;
    let this_ip_be = u32::from(this_ip).to_be();

    // Parse all routes upfront
    let parsed_routes: Vec<(SocketAddrV4, SocketAddrV4)> = config
        .routes
        .iter()
        .map(|r| {
            let from: SocketAddrV4 = r
                .from
                .parse()
                .with_context(|| format!("invalid 'from' address: {}", r.from))?;
            let to: SocketAddrV4 = r
                .to
                .parse()
                .with_context(|| format!("invalid 'to' address: {}", r.to))?;
            Ok((from, to))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Check for duplicate source ports
    let mut seen_ports = std::collections::HashSet::new();
    for (from, _) in &parsed_routes {
        anyhow::ensure!(
            seen_ports.insert(from.port()),
            "duplicate source port: {}",
            from.port()
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
    let mut nat_config: HashMap<_, u16, NatConfigEntry> =
        HashMap::try_from(ebpf.map_mut("NAT_CONFIG").context("NAT_CONFIG map not found")?)?;

    for (from, to) in &parsed_routes {
        let entry = NatConfigEntry {
            dst_ip: u32::from(*to.ip()).to_be(),
            this_ip: this_ip_be,
        };
        nat_config.insert(from.port(), entry, 0)?;
    }

    // Load and attach XDP program
    let prog: &mut Xdp = ebpf
        .program_mut("vtether_xdp")
        .context("vtether_xdp program not found")?
        .try_into()?;
    prog.load().context("failed to load XDP program into kernel")?;

    // Pin program to bpffs (keeps program + maps alive after exit)
    std::fs::create_dir_all(&pin_path)
        .with_context(|| format!("failed to create pin dir: {}", pin_path.display()))?;
    prog.pin(&prog_pin)
        .context("failed to pin program to bpffs")?;

    // Attach to network interface and pin the link so it persists after exit
    let link_id = prog
        .attach(&config.interface, XdpFlags::default())
        .with_context(|| format!("failed to attach XDP to {}", config.interface))?;
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

    // Configure kernel for XDP NAT forwarding
    setup_sysctl(&config.interface);

    println!("vtether: proxy up (xdp on {}, this_ip: {})", config.interface, config.this_ip);
    for (from, to) in &parsed_routes {
        println!("  {} -> {}", from, to);
        info!("route: {} -> {}", from, to);
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
        // Dropping the FdLink detaches from interface
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

// ---- Kernel / iptables setup ----

fn setup_sysctl(interface: &str) {
    let sysctls = [
        "net.ipv4.ip_forward=1",
        "net.ipv4.conf.all.accept_local=1",
    ];
    for s in &sysctls {
        let _ = std::process::Command::new("sysctl").args(["-w", s]).output();
    }
    let _ = std::process::Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.conf.{}.accept_local=1", interface)])
        .output();
}

