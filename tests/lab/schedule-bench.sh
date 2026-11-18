#!/usr/bin/env bash
# Scheduler bench for `routelith server` (architecture doc §21.2, M0 "schedule").
#
# Runs 1,000 ICMP targets on loopback addresses (127.0.x.y) at 20 samples
# every 300 s for one full step plus the last ping's offset, its timeout and
# a margin (counted from when the server reports it is measuring), then checks:
#   - every target has at least one stored round
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
SECONDS_TO_RUN=${2:-330}
TARGETS=1000
MAX_P99_MS=50
MAX_CPU_PCT=5

work=$(mktemp -d)
cleanup() {
    # Stop and reap the server before deleting its store: it may still be
    # draining rounds. After 30 s, kill it.
    if [[ -n ${pid:-} ]]; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 300); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
# Seconds since boot: a monotonic clock, unaffected by wall-clock steps.
uptime_s() { cut -d' ' -f1 /proc/uptime; }
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
start=$(uptime_s)
# Count the run from when the scheduler is up, not from process start.
for _ in $(seq 1 600); do
    grep -q 'routelith server: measuring' "$work/server.log" && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
done
sleep "$SECONDS_TO_RUN"
if ! kill -0 "$pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    echo "FAIL: server exited early" >&2
    exit 1
fi
# utime + stime of the process (fields 14 and 15), in clock ticks. The
# process name (field 2) is in parentheses and may contain spaces, so
# count fields after its closing parenthesis (field 3 becomes $1).
read -r utime stime < <(sed 's/.*) //' "/proc/$pid/stat" | awk '{print $12, $13}')
end=$(uptime_s)
kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=
cat "$work/server.log"
if [[ $status -ne 0 ]]; then
    echo "FAIL: server exited with status $status" >&2
    exit 1
fi

# Series with at least one stored round: after a clean stop every round
# is in a segment file under series/<id>/raw/.
measured=$(find "$work/data/series" -path '*/raw/*' \( -name '*.open' -o -name '*.seg' \) -size +0 \
    -printf '%h\n' | sort -u | wc -l)

line=$(grep '^stats: ' "$work/server.log" | tail -n 1)
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<< "$line"; }
rounds=$(field rounds)
overruns=$(field overruns)
dropped=$(field dropped)
failed=$(field failed)
p99=$(field lateness_all_p99_ms)
max=$(field lateness_all_max_ms)
ticks=$(getconf CLK_TCK)
# Unrounded for the check, rounded only for display.
cpu=$(awk -v u="$utime" -v s="$stime" -v t="$ticks" -v a="$start" -v b="$end" \
    'BEGIN { printf "%.17g", 100 * (u + s) / t / (b - a) }')
cpu_shown=$(awk -v c="$cpu" 'BEGIN { printf "%.2f", c }')

echo
echo "series measured=$measured of $TARGETS, rounds=$rounds overruns=$overruns dropped=$dropped failed=$failed"
echo "lateness p99=${p99} ms max=${max} ms, cpu=${cpu_shown} % of one core over ${SECONDS_TO_RUN} s"

fail=0
check() {
    if awk "BEGIN { exit !($2) }"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1" >&2
        fail=1
    fi
}
check "every target measured at least once ($measured of $TARGETS series have stored rounds)" "$measured == $TARGETS"
check "p99 lateness $p99 ms <= $MAX_P99_MS ms" "$p99 <= $MAX_P99_MS"
check "no overruns ($overruns)" "$overruns == 0"
check "no dropped rounds ($dropped)" "$dropped == 0"
check "no failed rounds ($failed)" "$failed == 0"
check "cpu $cpu_shown % < $MAX_CPU_PCT %" "$cpu < $MAX_CPU_PCT"
exit $fail
