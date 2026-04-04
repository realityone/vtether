# vtether

eBPF/XDP-based TCP/UDP port forwarder with full NAT (DNAT + SNAT).

## Build

Requires nightly Rust with `rust-src` and `bpf-linker`:

```bash
rustup default nightly
rustup component add rust-src
cargo +nightly install bpf-linker
cargo build --release
```

Or build via Docker:

```bash
docker build -t vtether .
```

## Configuration

Create a YAML config file (e.g. `vtether.yaml`):

```yaml
interface: eth0
# snat_ip: "192.168.1.100"  # optional, auto-detected from interface

routes:
  - protocol: tcp
    port: 443
    to: "10.0.0.1:443"
  - protocol: udp
    port: 53
    to: "10.0.0.2:53"
  - port: 8080
    to: "10.0.0.3:8080"
```

| Field       | Description                                              |
|-------------|----------------------------------------------------------|
| `interface` | Network interface to attach XDP program to               |
| `snat_ip`   | Source IP for SNAT (optional, auto-detected from interface)|
| `protocol`  | `tcp` or `udp` (optional, defaults to `tcp`)             |
| `port`      | Listen port on the interface                             |
| `to`        | Backend address and port to forward traffic to           |

## Usage

Start forwarding (requires root):

```bash
vtether proxy up --config vtether.yaml
```

Stop forwarding:

```bash
vtether proxy down
```

The XDP program is pinned to bpffs and persists after `vtether` exits. Kernel settings (`ip_forward`, `accept_local`) are configured automatically on `proxy up`.
