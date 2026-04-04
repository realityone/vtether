FROM rust:latest AS builder

# Install nightly toolchain with rust-src (needed for BPF build-std)
RUN rustup toolchain install nightly --component rust-src
RUN rustup default nightly

# Install bpf-linker
RUN cargo install bpf-linker

WORKDIR /build
COPY . .

# Build the project (nightly needed for edition 2024 + eBPF build-std)
RUN cargo build --release

FROM debian:bookworm-slim

COPY --from=builder /build/target/release/vtether /usr/local/bin/vtether

ENTRYPOINT ["vtether"]
