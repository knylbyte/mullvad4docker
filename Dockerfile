FROM golang:1.24-bookworm AS golang

FROM rust:1.94-bookworm AS builder

COPY --from=golang /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

RUN apt-get update >/dev/null && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        pkg-config \
        protobuf-compiler >/dev/null && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY controller/Cargo.toml controller/Cargo.toml

RUN mkdir -p controller/src/bin && \
    printf 'pub mod config;\npub mod killswitch;\n' > controller/src/lib.rs && \
    printf 'fn main() {}\n' > controller/src/main.rs && \
    printf 'fn main() {}\n' > controller/src/bin/killswitch-harness.rs && \
    cargo fetch

COPY controller controller

RUN cargo build --release -p mullvad-daita-controller

FROM debian:bookworm-slim

RUN apt-get update >/dev/null && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        dante-server \
        iproute2 \
        iptables \
        libgcc-s1 \
        wireguard-tools >/dev/null && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/mullvad-daita-controller /usr/local/bin/mullvad-daita-controller
COPY --from=builder /src/target/release/killswitch-harness /usr/local/bin/killswitch-harness
COPY src/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY src/dante/sockd.conf /etc/dante/sockd.conf

RUN chmod 0755 \
        /usr/local/bin/entrypoint.sh \
        /usr/local/bin/mullvad-daita-controller \
        /usr/local/bin/killswitch-harness && \
    mkdir -p /etc/dante /etc/wireguard

EXPOSE 1080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
