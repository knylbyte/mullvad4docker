#!/bin/sh

set -eu

IMAGE_TAG="${IMAGE_TAG:-wireguard-go-daita:killswitch-test}"
WORKDIR="$(mktemp -d)"
NO_KS_CONTAINER="mullvad-ks-off-$$"
WITH_KS_CONTAINER="mullvad-ks-on-$$"
IPV6_KS_CONTAINER="mullvad-ks-v6-$$"
ENTRY_SERVER_CONTAINER="mullvad-ks-entry-$$"
BLOCKED_SERVER_CONTAINER="mullvad-ks-blocked-$$"
TEST_DESTINATION_IP=""
ENTRY_ENDPOINT_IP=""
ENTRY_ENDPOINT_IPV6="2606:4700:4700::1111"
TEST_SERVER_PORT="18080"

cleanup() {
    docker rm -f "$NO_KS_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$WITH_KS_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$IPV6_KS_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$ENTRY_SERVER_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$BLOCKED_SERVER_CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}

trap cleanup EXIT INT TERM

log() {
    printf '[killswitch-test] %s\n' "$*"
}

fail() {
    printf '[killswitch-test] %s\n' "$*" >&2
    exit 1
}

random_key() {
    python3 - <<'PY'
import base64
import os
print(base64.b64encode(os.urandom(32)).decode())
PY
}

write_config() {
    config_path="$1"
    endpoint="$2"
    mkdir -p "$(dirname "$config_path")"
    private_key="$(random_key)"
    peer_key="$(random_key)"
    cat >"$config_path" <<EOF
[Interface]
PrivateKey = ${private_key}
Address = 10.10.0.2/32
DNS = 10.64.0.1

[Peer]
PublicKey = ${peer_key}
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}
EOF
}

start_http_server() {
    container_name="$1"
    docker run -d \
        --name "$container_name" \
        python:3.12-alpine \
        sh -ec "mkdir -p /srv && printf 'ok' >/srv/index.html && python -m http.server ${TEST_SERVER_PORT} --bind 0.0.0.0 -d /srv" >/dev/null
}

wait_for_http_server() {
    container_name="$1"
    attempts=0
    while [ "$attempts" -lt 20 ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null || echo false)" = "true" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    docker logs "$container_name" >&2 || true
    fail "helper server ${container_name} did not stay running"
}

container_ip() {
    container_name="$1"
    docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name"
}

wait_for_running() {
    container_name="$1"
    attempts=0
    while [ "$attempts" -lt 20 ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null || echo false)" = "true" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    docker logs "$container_name" >&2 || true
    fail "container ${container_name} did not stay running"
}

assert_no_killswitch_chain() {
    container_name="$1"
    if docker exec "$container_name" iptables -S 2>/dev/null | grep -q 'MULLVAD_KILLSWITCH'; then
        fail "unexpected kill switch chain found in ${container_name}"
    fi
}

assert_ipv4_killswitch_chain() {
    container_name="$1"
    docker exec "$container_name" iptables -S OUTPUT | grep -q 'MULLVAD_KILLSWITCH_V4' \
        || fail "missing OUTPUT jump to IPv4 kill switch chain"
    docker exec "$container_name" iptables -S MULLVAD_KILLSWITCH_V4 | grep -q -- '-o lo -j RETURN' \
        || fail "missing loopback allow rule in IPv4 kill switch chain"
    docker exec "$container_name" iptables -S MULLVAD_KILLSWITCH_V4 | grep -q -- '-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN' \
        || fail "missing conntrack allow rule in IPv4 kill switch chain"
    docker exec "$container_name" iptables -S MULLVAD_KILLSWITCH_V4 | grep -q -- '-o wg0 -j RETURN' \
        || fail "missing wg0 allow rule in IPv4 kill switch chain"
    docker exec "$container_name" iptables -S MULLVAD_KILLSWITCH_V4 | grep -q -- "-d ${ENTRY_ENDPOINT_IP}/32 -j RETURN" \
        || fail "missing entry endpoint allow rule in IPv4 kill switch chain"
    docker exec "$container_name" iptables -S MULLVAD_KILLSWITCH_V4 | grep -q -- '-j REJECT' \
        || fail "missing final reject rule in IPv4 kill switch chain"
}

assert_ipv6_killswitch_chain() {
    container_name="$1"
    docker exec "$container_name" ip6tables -S OUTPUT | grep -q 'MULLVAD_KILLSWITCH_V6' \
        || fail "missing OUTPUT jump to IPv6 kill switch chain"
    docker exec "$container_name" ip6tables -S MULLVAD_KILLSWITCH_V6 | grep -q -- "-d ${ENTRY_ENDPOINT_IPV6}/128 -j RETURN" \
        || fail "missing IPv6 entry endpoint allow rule"
    docker exec "$container_name" ip6tables -S MULLVAD_KILLSWITCH_V6 | grep -q -- '-j REJECT' \
        || fail "missing final IPv6 reject rule"
}

add_bypass_route() {
    container_name="$1"
    destination_ip="$2"
    docker exec "$container_name" ip route replace "${destination_ip}/32" dev eth0 >/dev/null
}

tcp_connect_via_eth0() {
    container_name="$1"
    target_ip="$2"
    target_port="$3"
    docker run --rm \
        --network "container:${container_name}" \
        alpine:3.22 \
        sh -ec "nc -z -w2 ${target_ip} ${target_port} >/dev/null"
}

assert_loopback_allowed() {
    container_name="$1"
    docker run --rm \
        --network "container:${container_name}" \
        --cap-add NET_RAW \
        alpine:3.22 \
        sh -ec "ping -I lo -c1 -W2 127.0.0.1 >/dev/null"
}

assert_reject_counter_incremented() {
    container_name="$1"
    reject_packets="$(docker exec "$container_name" sh -ec "iptables -vnL MULLVAD_KILLSWITCH_V4 | awk '/REJECT/ { print \$1; exit }'")"
    case "$reject_packets" in
        ''|0)
            fail "expected IPv4 kill switch REJECT counter to increment"
            ;;
    esac
}

start_container() {
    container_name="$1"
    killswitch_enabled="$2"
    config_dir="$3"
    docker run -d \
        --name "$container_name" \
        --cap-add NET_ADMIN \
        --entrypoint /usr/local/bin/killswitch-harness \
        -e KILLSWITCH_ENABLED="$killswitch_enabled" \
        -e WG_INTERFACE=wg0 \
        -e WG_CONFIG_FILE=/etc/wireguard/wg0.conf \
        -v "$config_dir:/etc/wireguard:ro" \
        "$IMAGE_TAG" >/dev/null
}

assert_clean_shutdown() {
    container_name="$1"
    docker stop -t 5 "$container_name" >/dev/null
    exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$container_name")"
    [ "$exit_code" = "0" ] || fail "expected ${container_name} to exit cleanly, got ${exit_code}"
}

mkdir -p "$WORKDIR/no-ks" "$WORKDIR/with-ks" "$WORKDIR/ipv6-ks"
log "building image ${IMAGE_TAG}"
docker build -t "$IMAGE_TAG" .

log "starting helper servers for deterministic egress checks"
start_http_server "$ENTRY_SERVER_CONTAINER"
start_http_server "$BLOCKED_SERVER_CONTAINER"
wait_for_http_server "$ENTRY_SERVER_CONTAINER"
wait_for_http_server "$BLOCKED_SERVER_CONTAINER"
ENTRY_ENDPOINT_IP="$(container_ip "$ENTRY_SERVER_CONTAINER")"
TEST_DESTINATION_IP="$(container_ip "$BLOCKED_SERVER_CONTAINER")"
[ -n "$ENTRY_ENDPOINT_IP" ] || fail "failed to determine entry server IP"
[ -n "$TEST_DESTINATION_IP" ] || fail "failed to determine blocked server IP"

write_config "$WORKDIR/no-ks/wg0.conf" "${ENTRY_ENDPOINT_IP}:51820"
write_config "$WORKDIR/with-ks/wg0.conf" "${ENTRY_ENDPOINT_IP}:51820"
write_config "$WORKDIR/ipv6-ks/wg0.conf" "[${ENTRY_ENDPOINT_IPV6}]:51820"

log "scenario 1: direct egress remains possible without kill switch"
start_container "$NO_KS_CONTAINER" false "$WORKDIR/no-ks"
wait_for_running "$NO_KS_CONTAINER"
assert_no_killswitch_chain "$NO_KS_CONTAINER"
add_bypass_route "$NO_KS_CONTAINER" "$TEST_DESTINATION_IP"
if ! tcp_connect_via_eth0 "$NO_KS_CONTAINER" "$TEST_DESTINATION_IP" "$TEST_SERVER_PORT"; then
    docker logs "$NO_KS_CONTAINER" >&2 || true
    fail "expected direct eth0 TCP egress to succeed without kill switch"
fi
assert_clean_shutdown "$NO_KS_CONTAINER"

log "scenario 2: kill switch blocks direct egress but keeps allowed paths open"
start_container "$WITH_KS_CONTAINER" true "$WORKDIR/with-ks"
wait_for_running "$WITH_KS_CONTAINER"
assert_ipv4_killswitch_chain "$WITH_KS_CONTAINER"
assert_loopback_allowed "$WITH_KS_CONTAINER" \
    || fail "expected loopback traffic to remain allowed with kill switch"
add_bypass_route "$WITH_KS_CONTAINER" "$TEST_DESTINATION_IP"
if tcp_connect_via_eth0 "$WITH_KS_CONTAINER" "$TEST_DESTINATION_IP" "$TEST_SERVER_PORT"; then
    docker logs "$WITH_KS_CONTAINER" >&2 || true
    fail "expected direct eth0 TCP egress to be blocked with kill switch"
fi
if ! tcp_connect_via_eth0 "$WITH_KS_CONTAINER" "$ENTRY_ENDPOINT_IP" "$TEST_SERVER_PORT"; then
    docker logs "$WITH_KS_CONTAINER" >&2 || true
    fail "expected entry endpoint traffic to stay allowed with kill switch"
fi
assert_reject_counter_incremented "$WITH_KS_CONTAINER"
assert_clean_shutdown "$WITH_KS_CONTAINER"

log "scenario 3: IPv6 entry endpoints create IPv6 kill switch rules"
start_container "$IPV6_KS_CONTAINER" true "$WORKDIR/ipv6-ks"
wait_for_running "$IPV6_KS_CONTAINER"
assert_ipv6_killswitch_chain "$IPV6_KS_CONTAINER"
assert_clean_shutdown "$IPV6_KS_CONTAINER"

log "all kill switch scenarios passed"
