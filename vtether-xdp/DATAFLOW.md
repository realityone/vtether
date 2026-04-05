# vtether-xdp Data Flow

Cilium-inspired XDP TCP port forwarding architecture for vtether.

## 1. Proxy Route Creation (Userspace -> BPF Maps)

When `vtether proxy up` runs, userspace populates three maps from the YAML config:

```
config.yaml                          BPF Maps
─────────────                        ────────
routes:
  - port: 443                   ──>  LB4_SERVICES[{VIP, 443, TCP}] = {backend_id=1, count=1, rev_nat_index=1}
    to: "10.0.0.1:8443"             LB4_SERVICES[{VIP, 443, TCP, slot=1}] = {backend_id=1}
                                     LB4_BACKENDS[1] = {addr=10.0.0.1, port=8443}
                                     LB4_REVERSE_NAT[1] = {addr=VIP, port=443}
```

The `rev_nat_index` is the key innovation from Cilium — it is a stable integer that links the forward path (DNAT) to the reverse path. On the reply path, the CT entry carries this index, which the reverse NAT map resolves back to `{VIP, original_port}`.

## 2. Forward Path: Client -> Backend (DNAT + SNAT)

```
Client: 1.2.3.4:54321 -> VIP:443
                │
                ▼
        ┌─ parse ETH/IPv4/TCP ──────────────────────────────────┐
        │  extract tuple: {saddr=1.2.3.4, daddr=VIP,            │
        │                  sport=54321, dport=443, TCP}          │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ LB4_SERVICES lookup ─────────────────────────────────┐
        │  key = {VIP, 443, TCP, slot=0}                         │
        │  -> svc = {count=1, rev_nat_index=1}                   │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ CT4 lookup (forward tuple, CT_EGRESS|CT_SERVICE) ────┐
        │                                                        │
        │  CT_NEW:                    CT_ESTABLISHED:             │
        │   select backend_id=1       read backend from entry    │
        │   lookup LB4_BACKENDS[1]                               │
        │   -> {10.0.0.1, 8443}                                  │
        │   create CT forward entry   update lifetime            │
        │   create CT reverse entry                              │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ DNAT ────────────────────────────────────────────────┐
        │  dst_ip:  VIP       -> 10.0.0.1                        │
        │  dst_port: 443      -> 8443                            │
        │  fix IP checksum + TCP checksum                        │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ SNAT (nat.rs: SNAT4 map) ───────────────────────────┐
        │  allocate ephemeral port (try client's port first,     │
        │  then hash-probe 32768-60999, up to 128 retries)       │
        │                                                        │
        │  create SNAT4 forward entry:                           │
        │    {10.0.0.1, 1.2.3.4, 8443, 54321}                   │
        │      -> {SNAT_IP, 49152}                               │
        │  create SNAT4 reverse entry:                           │
        │    {SNAT_IP, 10.0.0.1, 49152, 8443}                   │
        │      -> {1.2.3.4, 54321}                               │
        │                                                        │
        │  src_ip:  1.2.3.4   -> SNAT_IP                        │
        │  src_port: 54321    -> 49152                           │
        │  fix checksums                                         │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ FIB lookup + redirect ───────────────────────────────┐
        │  bpf_fib_lookup() resolves next-hop MAC + egress iface │
        │  rewrite ETH src/dst MAC                               │
        │  bpf_redirect(oif) -> XDP_REDIRECT                    │
        └────────────────────────────────────────────────────────┘

Result: SNAT_IP:49152 -> 10.0.0.1:8443
```

## 3. Reply Path: Backend -> Client (Reverse SNAT + Reverse DNAT)

```
Backend: 10.0.0.1:8443 -> SNAT_IP:49152
                │
                ▼
        ┌─ Reverse SNAT (SNAT4 lookup) ────────────────────────┐
        │  key = {SNAT_IP, 10.0.0.1, 49152, 8443, TCP, INGRESS}│
        │  -> {to_addr=1.2.3.4, to_port=54321}                  │
        │                                                        │
        │  dst_ip:  SNAT_IP   -> 1.2.3.4                        │
        │  dst_port: 49152    -> 54321                           │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ Reverse DNAT (CT4 + LB4_REVERSE_NAT) ──────────────┐
        │  CT4 lookup (reverse tuple) -> rev_nat_index=1         │
        │  LB4_REVERSE_NAT[1] -> {VIP, 443}                     │
        │                                                        │
        │  src_ip:  10.0.0.1  -> VIP                             │
        │  src_port: 8443     -> 443                             │
        │  fix checksums                                         │
        └────────────────────────────────────────────────────────┘
                │
                ▼
        ┌─ FIB redirect back to client ─────────────────────────┐

Result: VIP:443 -> 1.2.3.4:54321  (client sees reply from VIP)
```

## 4. TCP Connection State Management

TCP state is tracked per-direction in `CtEntry` using `tx_flags_seen` (forward) and `rx_flags_seen` (reply), following Cilium's approach:

```
                    tx_flags_seen    rx_flags_seen    Effective State
                    ─────────────    ─────────────    ───────────────
SYN ->                  SYN              -            SYN_SENT
               <- SYN+ACK               SYN+ACK      SYN_RECV
ACK ->                  SYN+ACK          SYN+ACK      ESTABLISHED
... data ...            SYN+ACK          SYN+ACK      ESTABLISHED
FIN ->                  SYN+ACK+FIN      SYN+ACK      FIN_WAIT
               <- FIN                    SYN+ACK+FIN  CLOSE (both FINs)
RST (any dir)          |= RST                         CLOSE (immediate)
```

The datapath **never deletes** entries. It only updates `lifetime`:

| Event | Timeout | Lifetime |
|-------|---------|----------|
| SYN seen (new conn) | 60s | `now + CT_SYN_TIMEOUT` |
| SYN+ACK seen (reply) | 6 hours | `now + CT_ESTABLISHED_TIMEOUT` |
| Established packets | 6 hours | `now + CT_ESTABLISHED_TIMEOUT` (refreshed each packet) |
| FIN from one side | unchanged | half-close, still needs the other FIN |
| FIN from both sides | 10s | `now + CT_CLOSE_TIMEOUT` (enough for retransmits) |
| RST | 10s | `now + CT_CLOSE_TIMEOUT` (immediate close) |

## 5. Conntrack Timeout and Garbage Collection

The GC runs in userspace with an **adaptive interval** inspired by Cilium's `pkg/maps/ctmap/gc/gc.go`:

```
               Userspace GC Loop
               ─────────────────
               ┌──────────────────────────────┐
               │  1. Read bpf_ktime_get_ns()  │
               │     as `now`                  │
               │                               │
               │  2. Iterate all CT4 entries:  │
               │     if entry.lifetime < now:  │
               │       delete CT4 forward      │
               │       delete CT4 reverse      │
               │       delete SNAT4 forward    │
               │       delete SNAT4 reverse    │
               │       expired_count++         │
               │                               │
               │  3. Adapt GC interval:        │
               │     ratio = expired / total   │
               │     if ratio > 25%:           │
               │       interval /= 2  (min 10s)│
               │     elif ratio < 5%:          │
               │       interval *= 2 (max 300s)│
               │     else:                     │
               │       keep interval           │
               │                               │
               │  4. Sleep(interval)           │
               └──────────────────────────────┘
```

Key design decisions (from Cilium):

- **Datapath never deletes**: avoids map operation overhead on the hot path and race conditions with concurrent GC.
- **Absolute timestamps**: `lifetime` is `now + timeout`, so GC only needs a single comparison (`lifetime < now`), no per-state timeout table.
- **Adaptive interval**: high churn (many short connections) triggers faster GC; idle periods back off to 5 minutes, reducing CPU overhead.
- **HashMap (not LRU)**: active connections are never silently evicted. When the map is full, new connections get `XDP_DROP` — a clear signal to increase `conntrack_size`, rather than silently breaking existing connections.

## 6. Differences from Current vtether-ebpf

| Aspect | Current `vtether-ebpf` | New `vtether-xdp` |
|--------|----------------------|-------------------|
| CT maps | Two maps (`CONNTRACK_OUT` + `CONNTRACK_IN`) | Single `CT4` map, direction in tuple `flags` |
| SNAT | Embedded in CT entry (`snat_ip`, `snat_port`) | Separate `SNAT4` map (Cilium-style) |
| Service config | `NAT_CONFIG` flat map (port -> backend) | `LB4_SERVICES` + `LB4_BACKENDS` + `LB4_REVERSE_NAT` (extensible to multi-backend) |
| Reply path | Dedicated `CONNTRACK_IN` reverse map | CT reverse entry + `LB4_REVERSE_NAT` lookup via `rev_nat_index` |
| TCP state | Custom bitfield (`tcp_state`) | `tx_flags_seen` / `rx_flags_seen` (Cilium-compatible) |
| Stats key | By port number | By `rev_nat_index` (survives reconfig) |
| FIB redirect | Not implemented (XDP_PASS) | `bpf_fib_lookup()` + `bpf_redirect()` for remote backends |
