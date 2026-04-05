use std::path::PathBuf;

use anyhow::Context as _;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/vtether/config.yaml";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/vtether.service";

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

pub fn setup() -> anyhow::Result<()> {
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

pub fn remove() -> anyhow::Result<()> {
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

pub fn setup_sysctl(interface: &str) -> anyhow::Result<()> {
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
