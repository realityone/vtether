use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context as _;

const STATE_BASE_DIR: &str = "/run/vtether";

/// Compute a per-instance state directory under /run/vtether/ derived from the pin path.
pub fn state_dir_for(pin_path: &std::path::Path) -> PathBuf {
    let instance = pin_path
        .file_name()
        .map_or_else(|| "default".to_string(), |n| n.to_string_lossy().into_owned());
    PathBuf::from(STATE_BASE_DIR).join(instance)
}

pub fn print_version() {
    println!(
        "vtether {} (commit {}, built {})",
        env!("VT_VERSION"),
        env!("VT_COMMIT"),
        env!("VT_BUILD_DATE"),
    );
}

pub fn get_interface_ipv4(interface: &str) -> anyhow::Result<Ipv4Addr> {
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
