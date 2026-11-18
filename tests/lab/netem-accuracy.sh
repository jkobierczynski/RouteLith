#!/usr/bin/env bash
# Accuracy lab for `routelith check icmp` (architecture doc §17 and §21.2).
#
# Builds two network namespaces joined by a veth pair, then uses tc netem on
# the far side to add a known delay and a known loss rate, and checks that
# Routelith measures them within the M0 tolerances:
#   - delay: median within ±0.1 ms of (baseline + 10 ms) over 1,000 samples
#   - loss:  5 % ± 1.5 points over 2,000 samples
#
# If iputils ping is installed, the delay step also measures with ping and
# checks that Routelith's median is no worse than ping's (+ the tolerance).
#
# On a busy or virtualised host netem itself releases packets late, so the
# absolute delay check can fail there even though both tools agree. Set
# DELAY_TOL_MS to loosen it on such hosts; CI keeps the strict 0.1 ms.
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
if ! [[ $DELAY_TOL_MS =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "DELAY_TOL_MS must be a non-negative number of milliseconds (got '$DELAY_TOL_MS')" >&2
    exit 2
fi

cleanup() {
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
out=$(measure -c 1000 -i 5ms)
echo "$out"
delayed=$(median_ms <<<"$out")
if ! [[ $delayed =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "FAIL  delay measurement produced no median (got '${delayed}')"
    exit 1
fi
expected=$(awk -v b="$base" -v d="$DELAY_MS" 'BEGIN { printf "%.3f", b + d }')
check delay "$delayed" "$expected" "$DELAY_TOL_MS"

if command -v ping >/dev/null; then
    echo "== reference: iputils ping, same settings"
    ref=$({ ip netns exec "$A" ping -n -c 1000 -i 0.005 -W 1 "$ADDR_B" || true; } |
        sed -n 's/.*time=\([0-9.]*\).*/\1/p' | sort -n |
        awk '{ v[NR] = $1 } END {
            if (NR % 2) print v[(NR + 1) / 2]
            else if (NR) printf "%.3f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2
        }')
    if [[ $ref =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        if awk -v r="$delayed" -v p="$ref" -v t="$DELAY_TOL_MS" 'BEGIN { exit !(r <= p + t) }'; then
            printf 'PASS  vsping measured %s, ping median %s (+ %s allowed)\n' "$delayed" "$ref" "$DELAY_TOL_MS"
        else
            printf 'FAIL  vsping measured %s, ping median %s (+ %s allowed)\n' "$delayed" "$ref" "$DELAY_TOL_MS"
            failures=$((failures + 1))
        fi
    else
        echo "SKIP  vsping: ping produced no replies"
    fi
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
