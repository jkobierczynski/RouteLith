#!/usr/bin/env bash
# Accuracy lab for `routelith check icmp` and `check tcp` (architecture doc
# §17, §21.2 and §21.4).
#
# Builds two network namespaces joined by a veth pair, then uses tc netem on
# the far side to add a known delay and a known loss rate, and checks that
# Routelith measures them within the M0 tolerances:
#   - delay: median within ±0.1 ms of (baseline + 10 ms) over 1,000 samples
#   - loss:  5 % ± 1.5 points over 2,000 samples
#   - tcp:   connect-time median within ±0.2 ms of the ICMP median under the
#            same netem delay, over 500 samples (needs python3 for the
#            listener; TCP_TOL_MS overrides the tolerance)
#
# If iputils ping is installed, the delay step also runs ping concurrently
# with Routelith and checks that Routelith's median is no later than ping's
# (+ the tolerance).
#
# On a busy or virtualised host netem itself releases packets late. When
# ping reads late too, the absolute delay check only warns.
# DELAY_TOL_MS loosens both delay checks; CI keeps the strict 0.1 ms.
#
# Usage: sudo [DELAY_TOL_MS=1] tests/lab/netem-accuracy.sh path/to/routelith
# Needs root, iproute2 and the sch_netem kernel module.
set -euo pipefail

BIN=$(realpath "${1:?usage: $0 path/to/routelith}")
A=rl-lab-a
B=rl-lab-b
ADDR_B=10.250.0.2
DELAY_MS=10
DELAY_TOL_MS=${DELAY_TOL_MS:-0.1}
LOSS_PCT=5
LOSS_TOL_PCT=1.5
TCP_PORT=7777
TCP_TOL_MS=${TCP_TOL_MS:-0.2}
for tol in "$DELAY_TOL_MS" "$TCP_TOL_MS"; do
    if ! [[ $tol =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "DELAY_TOL_MS and TCP_TOL_MS must be non-negative numbers of milliseconds (got '$tol')" >&2
        exit 2
    fi
done

cleanup() {
    if [[ -n ${ping_pid:-} ]]; then kill "$ping_pid" 2>/dev/null || true; fi
    if [[ -n ${srv_pid:-} ]]; then kill "$srv_pid" 2>/dev/null || true; fi
    if [[ -n ${ping_out:-} ]]; then rm -f "$ping_out"; fi
    ip netns del "$A" 2>/dev/null || true
    ip netns del "$B" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add "$A"
ip netns add "$B"
ip link add veth-a netns "$A" type veth peer name veth-b netns "$B"
ip -n "$A" addr add 10.250.0.1/24 dev veth-a
ip -n "$B" addr add "$ADDR_B/24" dev veth-b
for ns in "$A" "$B"; do
    ip -n "$ns" link set lo up
done
ip -n "$A" link set veth-a up
ip -n "$B" link set veth-b up
# ping_group_range is per network namespace and disabled by default.
ip netns exec "$A" sysctl -qw net.ipv4.ping_group_range="0 2147483647"

# Run a quiet check from A to B and print its summary.
measure() {
    ip netns exec "$A" "$BIN" check icmp "$ADDR_B" -q -W 1s "$@" || true
}
median_ms() { awk '/^rtt / { split($4, v, "/"); print v[2] }'; }
loss_pct() { awk '/^--- / { gsub("%", "", $6); print $6 }'; }
timing() { awk -F': ' '/^timing: / { print $2 }'; }

failures=0
check() {
    local name=$1 measured=$2 expected=$3 tol=$4
    if awk -v m="$measured" -v e="$expected" -v t="$tol" 'BEGIN { d = m - e; if (d < 0) d = -d; exit !(d <= t) }'; then
        printf 'PASS  %-6s measured %s, expected %s ± %s\n' "$name" "$measured" "$expected" "$tol"
    else
        printf 'FAIL  %-6s measured %s, expected %s ± %s\n' "$name" "$measured" "$expected" "$tol"
        failures=$((failures + 1))
    fi
}

echo "== baseline (no netem), 1000 samples"
status=0
out=$(ip netns exec "$A" "$BIN" check icmp "$ADDR_B" -q -W 1s -c 1000 -i 5ms) || status=$?
echo "$out"
if [[ $status -ne 0 ]]; then
    echo "FAIL  baseline measurement exited with status $status"
    exit 1
fi
base=$(median_ms <<<"$out")
# Without a valid baseline the delay check would compare against nothing.
if ! [[ $base =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "FAIL  baseline measurement produced no median (got '${base}')"
    exit 1
fi
echo "timing backend: $(timing <<<"$out")"

echo "== netem delay ${DELAY_MS}ms on B's egress, 1000 samples"
ip netns exec "$B" tc qdisc add dev veth-b root netem delay "${DELAY_MS}ms"
# Reference: iputils ping, if installed, runs at the same time as Routelith so
# both see the same netem behaviour (on a busy host it varies between runs).
ping_out=
ping_pid=
if command -v ping >/dev/null; then
    ping_out=$(mktemp)
    ip netns exec "$A" ping -n -c 1000 -i 0.005 -W 1 "$ADDR_B" >"$ping_out" 2>&1 &
    ping_pid=$!
fi
out=$(measure -c 1000 -i 5ms)
echo "$out"
delayed=$(median_ms <<<"$out")
if ! [[ $delayed =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "FAIL  delay measurement produced no median (got '${delayed}')"
    exit 1
fi
expected=$(awk -v b="$base" -v d="$DELAY_MS" 'BEGIN { printf "%.3f", b + d }')

ref=
if [[ -n $ping_pid ]]; then
    wait "$ping_pid" || true
    ping_pid=
    echo "== reference: iputils ping, run concurrently with the same settings"
    ref=$(sed -n 's/.*time=\([0-9.]*\).*/\1/p' "$ping_out" | sort -n |
        awk '{ v[NR] = $1 } END {
            if (NR % 2) print v[(NR + 1) / 2]
            else if (NR) printf "%.3f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2
        }')
    rm -f "$ping_out"
    ping_out=
    [[ $ref =~ ^[0-9]+(\.[0-9]+)?$ ]] || ref=
fi
late() { awk -v m="$1" -v e="$expected" -v t="$DELAY_TOL_MS" 'BEGIN { exit !(m > e + t) }'; }
within() { awk -v m="$1" -v e="$2" -v t="$3" 'BEGIN { d = m - e; if (d < 0) d = -d; exit !(d <= t) }'; }

# Absolute delay check. If ping is late too, netem on this host is releasing
# packets late and the check says nothing about Routelith, so it only warns.
# Routelith reading low is never waived, and the comparison with ping below
# (Routelith no later than ping) still has to pass.
if within "$delayed" "$expected" "$DELAY_TOL_MS"; then
    printf 'PASS  %-6s measured %s, expected %s ± %s\n' delay "$delayed" "$expected" "$DELAY_TOL_MS"
elif [[ -n $ref ]] && late "$delayed" && late "$ref"; then
    printf 'WARN  %-6s measured %s, expected %s ± %s; ping median %s is late too, so this host adds delay\n' \
        delay "$delayed" "$expected" "$DELAY_TOL_MS" "$ref"
else
    printf 'FAIL  %-6s measured %s, expected %s ± %s\n' delay "$delayed" "$expected" "$DELAY_TOL_MS"
    failures=$((failures + 1))
fi

if [[ -n $ref ]]; then
    if awk -v r="$delayed" -v p="$ref" -v t="$DELAY_TOL_MS" 'BEGIN { exit !(r <= p + t) }'; then
        printf 'PASS  vsping measured %s, ping median %s (+ %s allowed)\n' "$delayed" "$ref" "$DELAY_TOL_MS"
    else
        printf 'FAIL  vsping measured %s, ping median %s (+ %s allowed)\n' "$delayed" "$ref" "$DELAY_TOL_MS"
        failures=$((failures + 1))
    fi
elif command -v ping >/dev/null; then
    echo "FAIL  vsping: ping produced no replies"
    failures=$((failures + 1))
fi

echo "== tcp connect time under the same ${DELAY_MS}ms delay, 500 samples"
if command -v python3 >/dev/null; then
    # Accept and close at once; the probe resets each connection itself.
    ip netns exec "$B" python3 -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", '"$TCP_PORT"'))
s.listen(4096)
while True:
    c, _ = s.accept()
    c.close()
' &
    srv_pid=$!
    sleep 0.5
    # ICMP in the same window is the reference, so host-load drift since
    # the delay step above affects both alike.
    icmp_out=$(mktemp)
    measure -c 500 -i 5ms >"$icmp_out" 2>&1 &
    icmp_pid=$!
    out=$(ip netns exec "$A" "$BIN" check tcp "$ADDR_B" -p "$TCP_PORT" -q -W 1s -c 500 -i 5ms) || true
    wait "$icmp_pid" || true
    echo "$out"
    kill "$srv_pid" 2>/dev/null || true
    srv_pid=
    tcp=$(median_ms <<<"$out")
    tcp_ref=$(median_ms <"$icmp_out")
    rm -f "$icmp_out"
    received=$(awk '/^--- / { print $4 }' <<<"$out")
    if ! [[ $tcp_ref =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "FAIL  tcp: the concurrent ICMP reference produced no median (got '${tcp_ref}')"
        failures=$((failures + 1))
    elif ! [[ $tcp =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "FAIL  tcp measurement produced no median (got '${tcp}')"
        failures=$((failures + 1))
    elif [[ $received != 500 ]]; then
        echo "FAIL  tcp: ${received:-no} of 500 connections succeeded"
        failures=$((failures + 1))
    else
        check tcp "$tcp" "$tcp_ref" "$TCP_TOL_MS"
    fi
else
    echo "SKIP  tcp: python3 is not installed (needed for the listener)"
fi

echo "== netem loss ${LOSS_PCT}% on B's egress, 2000 samples"
ip netns exec "$B" tc qdisc replace dev veth-b root netem loss "${LOSS_PCT}%"
out=$(measure -c 2000 -i 2ms)
echo "$out"
check loss "$(loss_pct <<<"$out")" "$LOSS_PCT" "$LOSS_TOL_PCT"

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
