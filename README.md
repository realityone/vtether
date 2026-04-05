# vtether

eBPF/XDP-based TCP port forwarder with full NAT (DNAT + SNAT).

## Install

Download a binary from [Releases](https://github.com/realityone/vtether/releases), or build from source:

```bash
rustup default nightly
rustup component add rust-src
cargo +nightly install bpf-linker
cargo build --release
```

## Quick Start

```bash
# Install systemd service and default config
vtether setup

# Edit config
vim /etc/vtether/config.yaml

# Start / stop
systemctl start vtether
systemctl stop vtether
```

## Configuration

```yaml
interface: eth0
# snat_ip: "192.168.1.100"  # optional, auto-detected from interface
# conntrack_size: 131072     # max conntrack entries
# snat_min_port: 32768       # SNAT source port range
# snat_max_port: 60999

routes:
  - port: 443
    to: "10.0.0.1:443"
  - port: 8080
    to: "10.0.0.3:8080"
```

| Field            | Description                                                |
|------------------|------------------------------------------------------------|
| `interface`      | Network interface to attach XDP program to                 |
| `snat_ip`        | Source IP for SNAT (optional, auto-detected from interface)|
| `conntrack_size` | Max conntrack entries (default: 131072)                    |
| `snat_min_port`  | Minimum SNAT source port (default: 32768)                 |
| `snat_max_port`  | Maximum SNAT source port (default: 60999)                 |
| `port`           | Listen port on the interface                               |
| `to`             | Backend address and port to forward traffic to             |

## Usage

```bash
# Start forwarding (requires root)
vtether proxy up --config vtether.yaml

# Stop forwarding
vtether proxy destroy

# Show active routes and metrics
vtether inspect

# Show version
vtether version
```

## Requirements

- Linux with XDP-capable NIC driver and bpffs mounted at `/sys/fs/bpf`
- Root privileges

## Acknowledgements

Much of the design and implementation is inspired by [Cilium](https://github.com/cilium/cilium). Great thanks to the Cilium team.
