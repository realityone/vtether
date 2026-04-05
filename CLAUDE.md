# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

vtether is an eBPF/XDP-based TCP port forwarder performing full DNAT+SNAT at the XDP layer. It rewrites incoming packets (both IP addresses and ports) at the NIC driver level and uses conntrack maps for return traffic.

## Build Commands

```bash
# Build userspace + eBPF (requires nightly Rust, rust-src, bpf-linker)
cargo build --release

# Build via Docker (for cross-compilation from macOS)
docker build -t vtether .
```

The build process has two stages: `build.rs` invokes `aya_build::build_ebpf()` to compile the eBPF program (`vtether-xdp/`) to bytecode using nightly + build-std, then the main crate embeds it via `aya::include_bytes_aligned!`.

**Toolchain prerequisites** (on Linux):
- `rustup default nightly && rustup component add rust-src`
- `cargo +nightly install bpf-linker`

## Architecture

Two crates in one workspace:

- **`vtether-xdp/`** (`no_std`, `no_main`) — XDP kernel program, organized into modules:
  - `parse.rs` — Ethernet/IPv4/TCP header parsing, pointer helpers, constants
  - `csum.rs` — Incremental IP and TCP checksum update helpers
  - `conntrack.rs` — Connection tracking map (`CT4` LruHashMap), TCP state machine, Cilium-style single-entry-per-connection model
  - `nat.rs` — SNAT state tracking (`SNAT4` LruHashMap), port allocation, header rewrite
  - `lb.rs` — Service lookup (`LB4_SERVICES`), backend selection (`LB4_BACKENDS`), DNAT/revDNAT rewrite
  - `stats.rs` — Per-route statistics map (`ROUTE_STATS`) and update helpers
  - `main.rs` — XDP entry point and forward/reply path orchestration
  Binary name is `vtether-xdp-forward`.

- **`vtether-cli/`** — Userspace loader. Loads eBPF bytecode, populates maps from YAML config, attaches XDP to a network interface, and pins program+link to bpffs for persistence after exit. Runs an adaptive conntrack GC inspired by Cilium's CT GC design. CLI: `vtether proxy up --config <file>` / `vtether proxy destroy`.

## Key Conventions

- Packed struct fields in eBPF must use `addr_of!`/`addr_of_mut!` with `read_unaligned`/`write_unaligned` (references to packed fields are UB).
- `CtEntry`, `SnatEntry`, and LB structs must match between userspace (`vtether-cli/src/main.rs`) and eBPF (`vtether-xdp/src/conntrack.rs`, `vtether-xdp/src/nat.rs`, `vtether-xdp/src/lb.rs`).
- All IP addresses and ports in maps are stored in network byte order (big-endian).
- Conntrack entries use absolute `lifetime` timestamps (ns since boot). The BPF datapath sets `lifetime = now + timeout` on every packet; userspace GC deletes entries where `lifetime < now`. The datapath never removes entries.
- `csum_fold` already negates the result — don't double-negate in `csum_replace4`.
- Both the eBPF crate and the userspace crate use edition 2024.

## Runtime Requirements

- Linux kernel with XDP-capable NIC driver and bpffs mounted at `/sys/fs/bpf`
- Root privileges
- Kernel settings configured automatically by `proxy up`: `ip_forward=1`, `accept_local=1`

## rust-analyzer on macOS

The `.vscode/settings.json` points rust-analyzer at `vtether-cli/Cargo.toml` only (excludes `vtether-xdp` eBPF crate) and sets a dummy `OUT_DIR` since eBPF can only build on Linux.
