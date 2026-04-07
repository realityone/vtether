use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context as _;
use log::warn;

const STATE_BASE_DIR: &str = "/run/vtether";

/// Compute a per-instance state directory under /run/vtether/ derived from the pin path.
pub fn state_dir_for(pin_path: &std::path::Path) -> PathBuf {
    let instance = pin_path.file_name().map_or_else(
        || "default".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    PathBuf::from(STATE_BASE_DIR).join(instance)
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

pub fn best_effort_command(mut command: Command, description: &str) {
    match command
        .status()
        .inspect_err(|error| warn!("{description}: {error}"))
    {
        Ok(status) if !status.success() => {
            warn!("{description}: exited with status {status}");
        }
        _ => {}
    }
}

pub fn best_effort_remove_file(path: &Path) {
    std::fs::remove_file(path)
        .inspect_err(|error| {
            if error.kind() != ErrorKind::NotFound {
                warn!("failed to remove {}: {error}", path.display());
            }
        })
        .ok();
}

pub fn best_effort_remove_dir(path: &Path) {
    std::fs::remove_dir(path)
        .inspect_err(|error| {
            if error.kind() != ErrorKind::NotFound {
                warn!("failed to remove {}: {error}", path.display());
            }
        })
        .ok();
}

pub fn best_effort_remove_dir_all(path: &Path) {
    std::fs::remove_dir_all(path)
        .inspect_err(|error| {
            if error.kind() != ErrorKind::NotFound {
                warn!("failed to remove {}: {error}", path.display());
            }
        })
        .ok();
}
