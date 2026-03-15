ARG ALPINE_VERSION=3.22

FROM rust:1.94-alpine${ALPINE_VERSION} AS builder

RUN apk add --no-cache \
    build-base \
    ca-certificates \
    git \
    go \
    linux-headers \
    protobuf \
    protobuf-dev

WORKDIR /src

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY controller/Cargo.toml controller/Cargo.toml

RUN mkdir -p controller/src && \
    printf 'fn main() {}\n' > controller/src/main.rs && \
    cargo fetch

COPY controller controller

RUN cargo build --release -p mullvad-daita-controller

FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
    ca-certificates \
    dante-server \
    iproute2 \
    iptables \
    libgcc \
    wireguard-tools-wg

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
