ARG GOTATUN_REF=v0.4.1

FROM rust:1.94-bookworm AS controller-builder

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
    printf 'pub mod config;\npub mod killswitch;\npub mod mtu;\npub mod uapi;\n' > controller/src/lib.rs && \
    printf 'fn main() {}\n' > controller/src/main.rs && \
    printf 'fn main() {}\n' > controller/src/bin/killswitch-harness.rs && \
    cargo fetch

COPY controller controller

RUN cargo build --release -p mullvad-daita-controller

FROM rust:1.94-bookworm AS gotatun-builder
ARG GOTATUN_REF

RUN apt-get update >/dev/null && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        python3 >/dev/null && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src/gotatun

RUN git clone --depth 1 --branch "${GOTATUN_REF}" https://github.com/mullvad/gotatun.git . && \
    python3 -c "import pathlib; path = pathlib.Path('gotatun-cli/Cargo.toml'); text = path.read_text(); text = text.replace('features = [\\\"device\\\", \\\"tun\\\"]', 'features = [\\\"device\\\", \\\"tun\\\", \\\"daita-uapi\\\"]'); path.write_text(text)" && \
    cargo build --release -p gotatun-cli

FROM debian:bookworm-slim

RUN apt-get update >/dev/null && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        dante-server \
        iproute2 \
        iptables \
        libgcc-s1 \
        tzdata \
        wireguard-tools >/dev/null && \
    rm -rf /var/lib/apt/lists/*

COPY --from=controller-builder /src/target/release/mullvad-daita-controller /usr/local/bin/mullvad-daita-controller
COPY --from=controller-builder /src/target/release/killswitch-harness /usr/local/bin/killswitch-harness
COPY --from=gotatun-builder /src/gotatun/target/release/gotatun /usr/local/bin/gotatun
COPY src/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY src/dante/sockd.conf /etc/dante/sockd.conf

RUN chmod 0755 \
        /usr/local/bin/entrypoint.sh \
        /usr/local/bin/gotatun \
        /usr/local/bin/mullvad-daita-controller \
        /usr/local/bin/killswitch-harness && \
    mkdir -p /etc/dante /etc/wireguard /var/run/wireguard

EXPOSE 1080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
