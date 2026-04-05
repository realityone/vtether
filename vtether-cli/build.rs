use std::process::Command;

fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "vtether-xdp",
            root_dir: "vtether-xdp",
            ..Default::default()
        }],
        aya_build::Toolchain::Nightly,
    )
    .expect("Failed to build eBPF programs");

    // Derive version from git tags: e.g. "v0.2.1" -> "0.2.1", "v0.2.1-3-gabcdef" -> "0.2.1-dev"
    let describe = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "0.0.0".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );

    let dirty = Command::new("git")
        .args(["diff", "--quiet", "HEAD"])
        .status()
        .is_ok_and(|s| !s.success());

    // Parse version from git describe output
    let tag = describe.strip_prefix('v').unwrap_or(&describe);
    let (version, dev) = if let Some(idx) = tag.find('-') {
        (&tag[..idx], true)
    } else {
        (tag, false)
    };
    let version = if dev || dirty {
        format!("{version}-dev")
    } else {
        version.to_string()
    };

    let commit_display = if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    };

    let build_date = Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );

    // Always rerun build script so git state is fresh
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    println!("cargo:rustc-env=VT_VERSION={version}");
    println!("cargo:rustc-env=VT_COMMIT={commit_display}");
    println!("cargo:rustc-env=VT_BUILD_DATE={build_date}");
}
