use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use anyhow::Context as _;
use aya::maps::{Array, HashMap};
use aya::programs::links::FdLink;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use serde::Deserialize;

use crate::{
    IPPROTO_TCP, MAP_PINS,
    gc::{adapt_gc_interval, reap_conntrack},
    get_interface_ipv4,
    setup::setup_sysctl,
    state_dir_for,
    GC_INTERVAL_DEFAULT_SECS, GC_INTERVAL_MAX_SECS, GC_INTERVAL_MIN_SECS,
};

// ---- Config ----

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Network interface to attach XDP program to
    pub interface: String,
    /// IP address used as source in SNAT (auto-detected from interface if omitted)
    pub snat_ip: Option<String>,
    /// Max conntrack entries (default: 131072)
    #[serde(default = "default_conntrack_size")]
    pub conntrack_size: u32,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

fn default_conntrack_size() -> u32 {
    131_072
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    pub port: u16,
    pub to: String,
}

// ---- BPF map types for LB/SNAT config (must match vtether-xdp eBPF layout exactly) ----

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lb4Key {
    pub address: u32,
    pub dport: u16,
    pub backend_slot: u16,
    pub proto: u8,
    pub scope: u8,
    pub _pad: [u8; 2],
}
unsafe impl aya::Pod for Lb4Key {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lb4Service {
    pub backend_id: u32,
    pub count: u16,
    pub rev_nat_index: u16,
    pub flags: u8,
    pub flags2: u8,
    pub _pad: u16,
}
unsafe impl aya::Pod for Lb4Service {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lb4Backend {
    pub address: u32,
    pub port: u16,
    pub proto: u8,
    pub flags: u8,
}
unsafe impl aya::Pod for Lb4Backend {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lb4ReverseNat {
    pub address: u32,
    pub port: u16,
    pub _pad: u16,
}
unsafe impl aya::Pod for Lb4ReverseNat {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnatConfig {
    pub snat_addr: u32,
    pub min_port: u16,
    pub max_port: u16,
}
unsafe impl aya::Pod for SnatConfig {}

#[allow(clippy::too_many_lines)]
pub async fn proxy_up(config_path: PathBuf, pin_path: PathBuf) -> anyhow::Result<()> {
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

pub fn proxy_destroy(pin_path: &std::path::Path) -> anyhow::Result<()> {
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
