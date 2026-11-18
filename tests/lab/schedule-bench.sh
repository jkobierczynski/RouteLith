#!/usr/bin/env bash
# Scheduler bench for `routelith server` (architecture doc §21.2, M0 "schedule").
#
# Runs 1,000 ICMP targets on loopback addresses (127.0.x.y) at 20 samples
# every 300 s for one full step plus a margin, then checks:
#   - p99 lateness of round starts against their slots <= 50 ms
#   - zero round overruns, zero dropped rounds
#   - average CPU of the server process < 5 % of one core
#
# CI runners have 4 vCPUs rather than the 2 of the criterion; the CPU figure
# is per core, which is the stricter reading.
#
# Usage: tests/lab/schedule-bench.sh path/to/routelith [seconds]
# Needs Linux with unprivileged ICMP (net.ipv4.ping_group_range) or root.
set -euo pipefail

BIN=$(realpath "${1:?usage: $0 path/to/routelith [seconds]}")
SECONDS_TO_RUN=${2:-320}
TARGETS=1000
MAX_P99_MS=50
MAX_CPU_PCT=5

work=$(mktemp -d)
cleanup() {
    if [[ -n ${pid:-} ]]; then kill "$pid" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

{
    printf '[server]\ndata_dir = "%s/data"\n\n' "$work"
    printf '[defaults]\nstep = "300s"\npings = 20\n\n[[group]]\nname = "bench"\n'
    for i in $(seq 0 $((TARGETS - 1))); do
        printf '  [[group.target]]\n  name = "t%d"\n  host = "127.0.%d.%d"\n' \
            "$i" $((i / 250)) $((i % 250 + 1))
    done
} > "$work/bench.toml"

"$BIN" ctl verify --no-resolve "$work/bench.toml"

"$BIN" server -c "$work/bench.toml" --stats-interval 60 2> "$work/server.log" &
pid=$!
start=$(date +%s.%N)
sleep "$SECONDS_TO_RUN"
if ! kill -0 "$pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    echo "FAIL: server exited early" >&2
    exit 1
fi
# utime + stime of the process (fields 14 and 15), in clock ticks.
read -r utime stime < <(awk '{print $14, $15}' "/proc/$pid/stat")
end=$(date +%s.%N)
kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=
cat "$work/server.log"
if [[ $status -ne 0 ]]; then
    echo "FAIL: server exited with status $status" >&2
    exit 1
fi

line=$(grep '^stats: ' "$work/server.log" | tail -n 1)
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<< "$line"; }
rounds=$(field rounds)
overruns=$(field overruns)
dropped=$(field dropped)
failed=$(field failed)
p99=$(field lateness_all_p99_ms)
max=$(field lateness_all_max_ms)
ticks=$(getconf CLK_TCK)
cpu=$(awk -v u="$utime" -v s="$stime" -v t="$ticks" -v a="$start" -v b="$end" \
    'BEGIN { printf "%.2f", 100 * (u + s) / t / (b - a) }')

echo
echo "rounds=$rounds overruns=$overruns dropped=$dropped failed=$failed"
echo "lateness p99=${p99} ms max=${max} ms, cpu=${cpu} % of one core over ${SECONDS_TO_RUN} s"

fail=0
check() {
    if awk "BEGIN { exit !($2) }"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1" >&2
        fail=1
    fi
}
check "every target measured at least once ($rounds >= $TARGETS rounds)" "$rounds >= $TARGETS"
check "p99 lateness $p99 ms <= $MAX_P99_MS ms" "$p99 <= $MAX_P99_MS"
check "no overruns ($overruns)" "$overruns == 0"
check "no dropped rounds ($dropped)" "$dropped == 0"
check "no failed rounds ($failed)" "$failed == 0"
check "cpu $cpu % < $MAX_CPU_PCT %" "$cpu < $MAX_CPU_PCT"
exit $fail
