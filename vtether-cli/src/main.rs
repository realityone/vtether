use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

mod gc;
mod inspect;
mod proxy;
mod setup;

const DEFAULT_PIN_PATH: &str = "/sys/fs/bpf/vtether";
const STATE_BASE_DIR: &str = "/run/vtether";

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
        #[arg(short, long, default_value = setup::DEFAULT_CONFIG_PATH)]
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
