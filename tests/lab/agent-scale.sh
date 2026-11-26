#!/usr/bin/env bash
# Agent scale test for `routelith server` and `routelith agent` (architecture
# doc §21.8 "Scale", M3):
#
#   - 20 simulated agents x 1,000 targets (step 300 s, 20 pings) stream to
#     one server over the real protocol (crates/rl-fed/examples/sim_agents);
#     every round must be acknowledged (stored and synced), with the p99
#     delay from sending a round to its Ack within 5 s: the server keeps up.
#   - At the same time one real agent measures 500 targets (step 300 s,
#     20 pings): its peak RSS must stay under 20 MB and its CPU under 1 % of
#     one core, and every one of its series must have a round with replies.
#
# The run lasts one full step plus a margin, counted from when both the
# simulator and the agent have their assignments.
#
# Usage: tests/lab/agent-scale.sh path/to/routelith path/to/sim_agents [seconds]
# PROBE=tcp runs the real agent's targets as TCP connects to the server's
# UI port instead of ICMP, for systems without unprivileged ICMP. A quick
# smoke run: STEP=20s EXTRA_DEFAULTS='spread = "5s"' ... 45
# Needs Linux; for ICMP, unprivileged ping sockets (net.ipv4.ping_group_range).
set -euo pipefail

BIN=$(realpath "${1:?usage: $0 path/to/routelith path/to/sim_agents [seconds]}")
SIM=$(realpath "${2:?usage: $0 path/to/routelith path/to/sim_agents [seconds]}")
SECONDS_TO_RUN=${3:-330}
PROBE=${PROBE:-icmp}
STEP=${STEP:-300s}
# For a quick run with a short STEP, e.g. 'spread = "5s"'.
EXTRA_DEFAULTS=${EXTRA_DEFAULTS:-}
SIM_AGENTS=20
SIM_TARGETS=1000
REAL_TARGETS=500
MAX_ACK_P99_MS=5000
MAX_AGENT_RSS_KB=$((20 * 1024))
MAX_AGENT_CPU_PCT=1
PORT=$((20000 + RANDOM % 5000))
UI_PORT=$((PORT + 1))

work=$(mktemp -d)
pids=()
cleanup() {
    for p in "${pids[@]}"; do
        kill -TERM "$p" 2>/dev/null || true
    done
    for p in "${pids[@]}"; do
        for _ in $(seq 1 300); do
            kill -0 "$p" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT
uptime_s() { cut -d' ' -f1 /proc/uptime; }
# utime + stime of a process, in clock ticks (fields after the name).
ticks_of() { sed 's/.*) //' "/proc/$1/stat" | awk '{print $12 + $13}'; }
status_kb() { awk -v k="$2:" '$1 == k {print $2}' "/proc/$1/status"; }

names=$(for i in $(seq 0 $((SIM_AGENTS - 1))); do printf '"sim-%d", ' "$i"; done)
{
    printf '[server]\ndata_dir = "%s/data"\nvantage = "server"\n' "$work"
    printf 'listen_agents = "127.0.0.1:%d"\nlisten_ui = "0.0.0.0:%d"\n\n' "$PORT" "$UI_PORT"
    printf '[defaults]\nstep = "%s"\npings = 20\n%s\n\n' "$STEP" "$EXTRA_DEFAULTS"
    printf '[[group]]\nname = "sim"\nvantages = [%s]\n' "${names%, }"
    for i in $(seq 0 $((SIM_TARGETS - 1))); do
        printf '  [[group.target]]\n  name = "s%d"\n  host = "127.0.%d.%d"\n' \
            "$i" $((i / 250)) $((i % 250 + 1))
    done
    printf '[[group]]\nname = "real"\nvantages = ["real"]\n'
    for i in $(seq 0 $((REAL_TARGETS - 1))); do
        printf '  [[group.target]]\n  name = "r%d"\n  host = "127.1.%d.%d"\n' \
            "$i" $((i / 250)) $((i % 250 + 1))
        if [[ $PROBE == tcp ]]; then
            printf '  probe = "tcp"\n  port = %d\n' "$UI_PORT"
        fi
    done
} > "$work/server.toml"
"$BIN" ctl verify --no-resolve "$work/server.toml"

for i in $(seq 0 $((SIM_AGENTS - 1))); do
    "$BIN" ctl agent add "sim-$i" -c "$work/server.toml" | grep -o 'rlt1-[^ ]*'
done > "$work/tokens"
real_token=$("$BIN" ctl agent add real -c "$work/server.toml" | grep -o 'rlt1-[^ ]*')
printf 'server = "127.0.0.1:%d"\ndata_dir = "%s/agent"\n' "$PORT" "$work" > "$work/agent.toml"

"$BIN" server -c "$work/server.toml" --stats-interval 60 2> "$work/server.log" &
server=$!
pids+=("$server")
for _ in $(seq 1 300); do
    curl -fsS "http://127.0.0.1:$UI_PORT/healthz" > /dev/null 2>&1 && break
    sleep 0.2
done
"$BIN" agent enroll -c "$work/agent.toml" --token "$real_token"
"$BIN" agent run -c "$work/agent.toml" 2> "$work/agent.log" &
agent=$!
pids+=("$agent")
"$SIM" "127.0.0.1:$PORT" "$work/sim" "$work/tokens" "$SECONDS_TO_RUN" > "$work/sim.out" 2> "$work/sim.log" &
sim=$!
pids+=("$sim")

# Count the agent's run from when it measures.
for _ in $(seq 1 600); do
    grep -q 'measuring [0-9]* series' "$work/agent.log" && break
    kill -0 "$agent" 2>/dev/null || break
    sleep 0.1
done
if ! grep -q 'measuring [0-9]* series' "$work/agent.log"; then
    cat "$work/server.log" "$work/agent.log" >&2
    echo "FAIL: the agent did not start measuring within 60 s" >&2
    exit 1
fi
start=$(uptime_s)
agent_ticks0=$(ticks_of "$agent")
server_ticks0=$(ticks_of "$server")

# The simulator stops sending after SECONDS_TO_RUN and exits once every
# round is acknowledged (or 60 s later).
sim_status=0
wait "$sim" || sim_status=$?
end=$(uptime_s)
agent_ticks1=$(ticks_of "$agent")
server_ticks1=$(ticks_of "$server")
agent_hwm=$(status_kb "$agent" VmHWM)
agent_rss=$(status_kb "$agent" VmRSS)
server_hwm=$(status_kb "$server" VmHWM)

ids=$(curl -fsS "http://127.0.0.1:$UI_PORT/api/v1/series" | jq '[.series[] | select(.vantage == "real") | .id]')
measured=$(curl -fsS "http://127.0.0.1:$UI_PORT/api/v1/latest" |
    jq --argjson ids "$ids" '[.latest[] | select(.recv > 0 and (.series as $s | $ids | index($s)))] | length')

kill -TERM "$agent" "$server"
wait "$agent" || true
wait "$server" || true
pids=()
cat "$work/sim.out"
grep -v '^routelith server: event:' "$work/server.log" | tail -n 20
tail -n 5 "$work/agent.log"

summary=$(grep '^summary: ' "$work/sim.out" || true)
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p" <<< "$summary"; }
sent=$(field sent)
acked=$(field acked)
p99=$(field ack_p99_ms)
tck=$(getconf CLK_TCK)
cpu() { awk -v d="$1" -v t="$tck" -v a="$start" -v b="$end" 'BEGIN { printf "%.4f", 100 * d / t / (b - a) }'; }
agent_cpu=$(cpu $((agent_ticks1 - agent_ticks0)))
server_cpu=$(cpu $((server_ticks1 - server_ticks0)))
expected=$((SIM_AGENTS * SIM_TARGETS))

echo
echo "simulated: sent=$sent acked=$acked (one step = $expected rounds), ack p99=${p99} ms"
echo "server: cpu=${server_cpu} % of one core, peak rss=$((server_hwm / 1024)) MB"
echo "agent ($REAL_TARGETS $PROBE targets): measured=$measured, cpu=${agent_cpu} % of one core, rss=$((agent_rss / 1024)) MB, peak rss=$((agent_hwm / 1024)) MB"

fail=0
check() {
    if awk "BEGIN { exit !($2) }"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1" >&2
        fail=1
    fi
}
check "the simulator finished cleanly (exit $sim_status)" "$sim_status == 0"
check "a full step of simulated rounds was sent ($sent >= $expected)" "${sent:-0} >= $expected"
check "every simulated round acknowledged ($acked of $sent)" "${acked:-0} == ${sent:-1}"
check "ack p99 $p99 ms <= $MAX_ACK_P99_MS ms" "${p99:-999999} <= $MAX_ACK_P99_MS"
check "every agent series measured ($measured of $REAL_TARGETS)" "$measured == $REAL_TARGETS"
check "agent peak rss $((agent_hwm / 1024)) MB < 20 MB" "$agent_hwm < $MAX_AGENT_RSS_KB"
check "agent cpu $agent_cpu % < $MAX_AGENT_CPU_PCT %" "$agent_cpu < $MAX_AGENT_CPU_PCT"
exit $fail
