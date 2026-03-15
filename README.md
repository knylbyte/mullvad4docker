# wireguard-go-daita

Alpine-based container that starts a Mullvad WireGuard tunnel through `wireguard-go-rs` and optional support for Mullvad DAITA.

## What it does

- starts a userspace WireGuard tunnel through Mullvad's `libwg` / `wireguard-go-rs`
- supports Mullvad single-hop and multihop configs
- requests an ephemeral peer from Mullvad's relay config service when `DAITA_ENABLED=true`
- reconfigures the tunnel with the ephemeral key and activates DAITA
- can optionally run `dante-server` in the same container

## Current scope

- `WG_INTERFACE` defaults to `wg0`
- standard config parsing is intentionally limited to the fields needed by this runtime:
  - `[Interface] PrivateKey, Address, DNS, MTU, FwMark, PreUp, PostUp, PreDown, PostDown`
  - `[Peer] PublicKey, Endpoint, AllowedIPs, PresharedKey, PersistentKeepalive`
- up to two `[Peer]` sections are supported
  - one peer for single-hop
  - two peers for multihop, where exactly one peer must carry the default route and the entry peer must route the exit endpoint

## Build

```sh
docker buildx build --platform linux/amd64,linux/arm64 .
```

For local Rust builds outside Docker, the repo pins Rust `1.94.0` in [rust-toolchain.toml](/Users/philippmielke/Coding/gitHub/wireguard-go-daita/rust-toolchain.toml).

## Runtime

The container expects:

- `NET_ADMIN`
- `/dev/net/tun`
- a mounted WireGuard config file

Relevant environment variables:

- `DAITA_ENABLED=true|false`
- `DANTE_ENABLED=true|false`
- `KILLSWITCH_ENABLED=true|false`
- `WG_INTERFACE`
- `WG_CONFIG_FILE`

The controller:

- creates the TUN device itself
- configures addresses and routes directly with `ip`
- rewrites `/etc/resolv.conf` from `DNS` entries while the tunnel is up
- executes `PreUp`, `PostUp`, `PreDown`, `PostDown` hooks with `%i` replaced by `WG_INTERFACE`
- can install an additional container-local kill switch with `iptables`/`ip6tables`

When `KILLSWITCH_ENABLED=true`, the controller installs OUTPUT rules inside the container namespace that:

- allow loopback traffic
- allow `RELATED,ESTABLISHED`
- allow traffic exiting through `WG_INTERFACE`
- allow traffic to the entry relay endpoint outside the tunnel
- reject all other outbound traffic

## Dante config

The image contains a fixed Dante server config at `/etc/dante/sockd.conf`.

When `DANTE_ENABLED=true`, the entrypoint:

- requires `/etc/dante/sockd.conf` to exist
- verifies that `external:` matches `WG_INTERFACE`
- starts `sockd` alongside the tunnel controller
