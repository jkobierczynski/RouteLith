#!/usr/bin/env bash
# Accuracy lab for `routelith check icmp` (architecture doc §17 and §21.2).
#
# Builds two network namespaces joined by a veth pair, then uses tc netem on
# the far side to add a known delay and a known loss rate, and checks that
# Routelith measures them within the M0 tolerances:
#   - delay: median within ±0.1 ms of (baseline + 10 ms) over 1,000 samples
#   - loss:  5 % ± 1.5 points over 2,000 samples
#
# Usage: sudo tests/lab/netem-accuracy.sh path/to/routelith
# Needs root, iproute2 and the sch_netem kernel module.
set -euo pipefail

BIN=$(realpath "${1:?usage: $0 path/to/routelith}")
A=rl-lab-a
B=rl-lab-b
ADDR_B=10.250.0.2
DELAY_MS=10
DELAY_TOL_MS=0.1
LOSS_PCT=5
LOSS_TOL_PCT=1.5

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
out=$(measure -c 1000 -i 5ms)
echo "$out"
base=$(median_ms <<<"$out")
echo "timing backend: $(timing <<<"$out")"

echo "== netem delay ${DELAY_MS}ms on B's egress, 1000 samples"
ip netns exec "$B" tc qdisc add dev veth-b root netem delay "${DELAY_MS}ms"
out=$(measure -c 1000 -i 5ms)
echo "$out"
delayed=$(median_ms <<<"$out")
expected=$(awk -v b="$base" -v d="$DELAY_MS" 'BEGIN { printf "%.3f", b + d }')
check delay "$delayed" "$expected" "$DELAY_TOL_MS"

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
