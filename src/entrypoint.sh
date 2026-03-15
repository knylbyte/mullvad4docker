#!/bin/sh

set -eu

DAITA_ENABLED="${DAITA_ENABLED:-false}"
DANTE_ENABLED="${DANTE_ENABLED:-false}"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_CONFIG_FILE="${WG_CONFIG_FILE:-/etc/wireguard/${WG_INTERFACE}.conf}"
DANTE_CONFIG="/etc/dante/sockd.conf"
CONTROLLER_BIN="/usr/local/bin/mullvad-daita-controller"

DANTE_PID=""
CONTROLLER_PID=""

log() {
    echo "[entrypoint] $*"
}

fail() {
    echo "[entrypoint] $*" >&2
    exit 1
}

cleanup() {
    status="$1"

    trap - EXIT INT TERM

    if [ -n "$DANTE_PID" ] && kill -0 "$DANTE_PID" 2>/dev/null; then
        kill "$DANTE_PID" 2>/dev/null || true
        wait "$DANTE_PID" 2>/dev/null || true
    fi

    if [ -n "$CONTROLLER_PID" ] && kill -0 "$CONTROLLER_PID" 2>/dev/null; then
        kill "$CONTROLLER_PID" 2>/dev/null || true
        wait "$CONTROLLER_PID" 2>/dev/null || true
    fi

    exit "$status"
}

trap 'cleanup $?' EXIT
trap 'exit 0' INT TERM

require_prerequisites() {
    [ -c /dev/net/tun ] || fail "missing /dev/net/tun"
    [ -f "$WG_CONFIG_FILE" ] || fail "missing WireGuard config: $WG_CONFIG_FILE"
    [ -x "$CONTROLLER_BIN" ] || fail "missing controller binary: $CONTROLLER_BIN"
    command -v ip >/dev/null 2>&1 || fail "ip not found"
}

verify_dante_config() {
    [ -f "$DANTE_CONFIG" ] || fail "missing Dante config: $DANTE_CONFIG"
    awk -v interface_name="$WG_INTERFACE" '
        function trim(value) {
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            return value
        }

        /^[[:space:]]*([#;].*)?$/ {
            next
        }

        {
            line = $0
            sub(/[[:space:]]*[#;].*$/, "", line)
            if (line !~ /^[[:space:]]*external[[:space:]]*:/) {
                next
            }

            sub(/^[[:space:]]*external[[:space:]]*:[[:space:]]*/, "", line)
            count = split(line, parts, /[[:space:]]+/)
            for (i = 1; i <= count; i++) {
                token = trim(parts[i])
                if (token == interface_name) {
                    found = 1
                }
            }
        }

        END {
            exit(found ? 0 : 1)
        }
    ' "$DANTE_CONFIG" || fail "Dante config must set external: $WG_INTERFACE"
}

start_controller() {
    log "starting tunnel controller"
    "$CONTROLLER_BIN" &
    CONTROLLER_PID="$!"
}

start_dante() {
    case "$DANTE_ENABLED" in
        true|TRUE|1|yes|YES)
            verify_dante_config
            log "starting Dante with $DANTE_CONFIG"
            sockd -f "$DANTE_CONFIG" &
            DANTE_PID="$!"
            ;;
        false|FALSE|0|no|NO)
            ;;
        *)
            fail "DANTE_ENABLED must be true or false"
            ;;
    esac
}

monitor_processes() {
    while :; do
        if [ -n "$CONTROLLER_PID" ] && ! kill -0 "$CONTROLLER_PID" 2>/dev/null; then
            wait "$CONTROLLER_PID" || true
            fail "tunnel controller exited unexpectedly"
        fi

        if [ -n "$DANTE_PID" ] && ! kill -0 "$DANTE_PID" 2>/dev/null; then
            wait "$DANTE_PID" || true
            fail "Dante exited unexpectedly"
        fi

        sleep 5
    done
}

main() {
    require_prerequisites

    case "$DANTE_ENABLED" in
        true|TRUE|1|yes|YES)
            start_controller
            start_dante
            monitor_processes
            ;;
        false|FALSE|0|no|NO)
            log "starting tunnel controller in foreground"
            exec "$CONTROLLER_BIN"
            ;;
        *)
            fail "DANTE_ENABLED must be true or false"
            ;;
    esac
}

main "$@"
