use std::process::Command;

fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "vtether-ebpf",
            root_dir: "vtether-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::Nightly,
    )
    .expect("Failed to build eBPF programs");

    // Emit git commit and dirty state for version info
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["diff", "--quiet", "HEAD"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    let build_date = Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Always rerun build script so git state is fresh
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    println!("cargo:rustc-env=VT_COMMIT={}", commit);
    println!("cargo:rustc-env=VT_DIRTY={}", dirty);
    println!("cargo:rustc-env=VT_BUILD_DATE={}", build_date);
}
