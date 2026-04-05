//! Minimal vtether-xdp proxy example.
//!
//! Usage:
//!   vtether-xdp-proxy --interface eth0 --proxy 443:10.0.0.1:443
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context as _, bail};
use aya::maps::{Array, HashMap};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::info;

// ---- Map structs (must match vtether-xdp eBPF layout) ----

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

// ---- CLI ----

#[derive(Parser)]
#[command(name = "vtether-xdp-proxy")]
struct Cli {
    /// Network interface to attach XDP program to
    #[arg(long)]
    interface: String,

    /// Proxy route in the form LOCAL_PORT:DST_IP:DST_PORT
    #[arg(long)]
    proxy: String,
}

struct Route {
    listen_port: u16,
    backend: SocketAddrV4,
}

fn parse_route(s: &str) -> anyhow::Result<Route> {
    // Format: LOCAL_PORT:DST_IP:DST_PORT
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!("expected LOCAL_PORT:DST_IP:DST_PORT, got '{s}'");
    }
    let listen_port: u16 = parts[0].parse().context("invalid local port")?;
    let dst_ip: Ipv4Addr = parts[1].parse().context("invalid destination IP")?;
    let dst_port: u16 = parts[2].parse().context("invalid destination port")?;
    Ok(Route {
        listen_port,
        backend: SocketAddrV4::new(dst_ip, dst_port),
    })
}

fn get_interface_ipv4(iface: &str) -> anyhow::Result<Ipv4Addr> {
    for ifaddr in nix::ifaddrs::getifaddrs()? {
        if ifaddr.interface_name == iface {
            if let Some(addr) = ifaddr.address {
                if let Some(sin) = addr.as_sockaddr_in() {
                    return Ok(Ipv4Addr::from(sin.ip()));
                }
            }
        }
    }
    bail!("no IPv4 address on {iface}");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let route = parse_route(&cli.proxy)?;
    let snat_ip = get_interface_ipv4(&cli.interface)?;

    info!(
        "{}:{} -> {}  (SNAT {})",
        cli.interface, route.listen_port, route.backend, snat_ip
    );

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/vtether-xdp2-forward"
    )))?;

    let program: &mut Xdp = ebpf
        .program_mut("vtether_xdp")
        .context("vtether_xdp not found")?
        .try_into()?;
    program.load()?;
    program.attach(&cli.interface, XdpFlags::default())?;
    info!("XDP attached to {}", cli.interface);

    #[allow(clippy::ignored_unit_patterns)]
    aya_log::EbpfLogger::init(&mut ebpf).context("failed to init eBPF logger")?;

    let vip_be = u32::from(snat_ip).to_be();
    let backend_ip_be = u32::from(*route.backend.ip()).to_be();
    let listen_port_be = route.listen_port.to_be();
    let backend_port_be = route.backend.port().to_be();

    // LB4_SERVICES: slot 0 (service) + slot 1 (backend ref)
    let mut svc: HashMap<_, Lb4Key, Lb4Service> =
        HashMap::try_from(ebpf.map_mut("LB4_SERVICES").context("map")?)?;
    svc.insert(
        Lb4Key { address: vip_be, dport: listen_port_be, backend_slot: 0, proto: 6, scope: 0, _pad: [0; 2] },
        Lb4Service { backend_id: 0, count: 1, rev_nat_index: 1, flags: 0, flags2: 0, _pad: 0 },
        0,
    )?;
    svc.insert(
        Lb4Key { address: vip_be, dport: listen_port_be, backend_slot: 1, proto: 6, scope: 0, _pad: [0; 2] },
        Lb4Service { backend_id: 1, count: 0, rev_nat_index: 1, flags: 0, flags2: 0, _pad: 0 },
        0,
    )?;

    // LB4_BACKENDS: id=1
    let mut be: HashMap<_, u32, Lb4Backend> =
        HashMap::try_from(ebpf.map_mut("LB4_BACKENDS").context("map")?)?;
    be.insert(1u32, Lb4Backend { address: backend_ip_be, port: backend_port_be, proto: 6, flags: 0 }, 0)?;

    // LB4_REVERSE_NAT: index=1
    let mut rev: HashMap<_, u16, Lb4ReverseNat> =
        HashMap::try_from(ebpf.map_mut("LB4_REVERSE_NAT").context("map")?)?;
    rev.insert(1u16, Lb4ReverseNat { address: vip_be, port: listen_port_be, _pad: 0 }, 0)?;

    // SNAT_CONFIG
    let mut snat: Array<_, SnatConfig> =
        Array::try_from(ebpf.map_mut("SNAT_CONFIG").context("map")?)?;
    snat.set(0, SnatConfig { snat_addr: vip_be, min_port: 32768, max_port: 60999 }, 0)?;

    info!("ready — Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    info!("detaching");
    Ok(())
}
