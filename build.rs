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
}
