#!/usr/bin/env bash
# Tracer lab for `routelith trace` (architecture doc §21.10, "Tracer").
#
# Runs in a fresh network namespace, so it touches nothing on the host. A
# TUN device carries a fake multi-hop path (tests/lab/pathsim.py): routers
# 192.0.2.1… / 2001:db8:2::1… answer with Time Exceeded, the destination
# 198.51.100.10 / 2001:db8:100::10 with echo replies, each hop 2 ms further
# away. The trace runs as an unprivileged user (nobody, no capabilities),
# for IPv4 and IPv6, and the script checks:
#   - every hop's responder, and the destination at hop 5
#   - 30 % loss on hop 3 only (a router that rate-limits its ICMP), and
#     20 % loss from hop 3 on (loss on the link), each within 5 points
#   - each hop's median RTT within 0.5 ms of its configured delay
# Then `routelith server` traces the rate-limited path continuously, and
# `ctl report path` reads its hop series and raw sweeps back: 30 % loss on
# hop 3's series only (§21.10 "Hop series"), every sweep kept.
# The fake path's random loss is seeded, so a run is repeatable.
#
# Works where veth and netem are missing (the cloud sandbox), as long as
# /dev/net/tun exists. Needs root, python3, iproute2 and setpriv.
#
# Usage: sudo tests/lab/trace-lab.sh path/to/routelith
set -euo pipefail

BIN=$(realpath "${1:?usage: $0 path/to/routelith}")
HERE=$(cd "$(dirname "$0")" && pwd)
SWEEPS=${SWEEPS:-300}
SERVER_SECS=${SERVER_SECS:-150}
RTT_TOL_MS=${RTT_TOL_MS:-0.5}

if [[ ${RL_TRACE_LAB_INNER:-} != 1 ]]; then
    exec env RL_TRACE_LAB_INNER=1 unshare --net "$0" "$@"
fi

ip link set lo up
echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done
ip tuntap add dev rltun0 mode tun
# Some kernels (the cloud sandbox's) have no IPv6 at all.
FAMILIES="4 6"
if [[ ! -d /proc/sys/net/ipv6 ]]; then
    echo "SKIP ipv6: this kernel has no IPv6"
    FAMILIES=4
fi

SIM=
OUT=$(mktemp -d)
cleanup() {
    [[ -n $SIM ]] && kill "$SIM" 2>/dev/null || true
    [[ -n ${SERVER:-} ]] && kill "$SERVER" 2>/dev/null || true
    rm -rf "$OUT"
}
trap cleanup EXIT

start_sim() {
    [[ -n $SIM ]] && { kill "$SIM" 2>/dev/null || true; wait "$SIM" 2>/dev/null || true; }
    ip link set rltun0 down
    env "$@" python3 "$HERE/pathsim.py" rltun0 &
    SIM=$!
    sleep 0.5
    ip link set rltun0 up
    ip addr replace 10.99.0.1/24 dev rltun0
    ip route replace 198.51.100.0/24 dev rltun0
    if [[ $FAMILIES == *6* ]]; then
        ip -6 addr replace 2001:db8:99::1/64 dev rltun0 nodad
        ip -6 route replace 2001:db8:100::/64 dev rltun0
    fi
}

# check NAME JSON HOPS LOSSES(space-separated, percent per hop) DEST
check() {
    python3 - "$@" <<'EOF'
import json, sys
name, path, hops, losses, dest, tol, delay = sys.argv[1:8]
r = json.load(open(path))
hops, tol, delay = int(hops), float(tol), float(delay)
want_loss = [float(x) for x in losses.split()]
fail = []
got = r["hops"]
if len(got) != hops:
    fail.append(f"{len(got)} hops, want {hops}")
if not r["reached"]:
    fail.append("destination not reached")
for i, h in enumerate(got[:hops]):
    ttl = i + 1
    v6 = ":" in dest
    want = dest if ttl == hops else (f"2001:db8:2::{ttl:x}" if v6 else f"192.0.2.{ttl}")
    addrs = [x["addr"] for x in h["responders"]]
    if addrs != [want]:
        fail.append(f"hop {ttl}: responders {addrs}, want [{want}]")
    loss = 100.0 * (h["sent"] - h["received"]) / h["sent"]
    if abs(loss - want_loss[i]) > 5:
        fail.append(f"hop {ttl}: loss {loss:.1f} %, want {want_loss[i]:.0f} % +- 5")
    med = (h["median_us"] or 0) / 1000.0
    exp = delay * ttl
    if abs(med - exp) > tol:
        fail.append(f"hop {ttl}: median {med:.3f} ms, want {exp:.1f} +- {tol} ms")
    print(f"  {name} hop {ttl}: {','.join(addrs) or '???'} loss {loss:5.1f} % median {med:.3f} ms")
if fail:
    print(f"FAIL {name}: " + "; ".join(fail))
    sys.exit(1)
print(f"PASS {name}")
EOF
}

run_trace() { # FAMILY DEST OUTFILE
    setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all \
        "$BIN" trace --json -c "$SWEEPS" -i 100ms -W 1s "$1" "$2" > "$3"
}

status=0
start_sim HOPS=5 LOSSY=3 LOSS=0.3 FORWARD_LOSS=0 HOP_DELAY_MS=2 SEED=1
for fam in $FAMILIES; do
    dest=198.51.100.10; [[ $fam == 6 ]] && dest=2001:db8:100::10
    run_trace "-$fam" "$dest" "$OUT/rate-$fam.json" || true
    check "ipv$fam rate-limited hop" "$OUT/rate-$fam.json" 5 "0 0 30 0 0" "$dest" "$RTT_TOL_MS" 2 || status=1
done

start_sim HOPS=5 LOSSY=3 LOSS=0 FORWARD_LOSS=0.2 HOP_DELAY_MS=2 SEED=2
for fam in $FAMILIES; do
    dest=198.51.100.10; [[ $fam == 6 ]] && dest=2001:db8:100::10
    run_trace "-$fam" "$dest" "$OUT/link-$fam.json" || true
    check "ipv$fam lossy link" "$OUT/link-$fam.json" 5 "0 0 0 20 20" "$dest" "$RTT_TOL_MS" 2 || status=1
done

# The server: a continuous trace at 0.5 s with 10 s hop rounds.
start_sim HOPS=5 LOSSY=3 LOSS=0.3 FORWARD_LOSS=0 HOP_DELAY_MS=2 SEED=3
# nobody needs to reach the data directory inside mktemp's 0700 folder.
chmod 755 "$OUT"
mkdir "$OUT/data"
chown 65534:65534 "$OUT/data"
cat > "$OUT/server.toml" <<EOF
[server]
data_dir = "$OUT/data"
listen_ui = "off"

[defaults]
step = "60s"
pings = 5

[[group]]
name = "lab"

  [[group.target]]
  name = "dest"
  host = "198.51.100.10"
  trace = "continuous"
  trace_interval = "500ms"
  trace_step = "10s"
  max_ttl = 8
EOF
setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all \
    "$BIN" server -c "$OUT/server.toml" --stats-interval 0 2> "$OUT/server.log" &
SERVER=$!
sleep "$SERVER_SECS"
kill -INT "$SERVER" 2>/dev/null || true
if ! wait "$SERVER"; then
    echo "FAIL server exited with an error"
    status=1
fi
cat "$OUT/server.log"
SERVER=
setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all \
    "$BIN" ctl report path -c "$OUT/server.toml" --target dest --last 1h --json > "$OUT/path.json" || status=1
python3 - "$OUT/path.json" "$SERVER_SECS" <<'EOF' || status=1
import json, sys
r = json.load(open(sys.argv[1]))
secs = int(sys.argv[2])
fail = []
hops = r["hops"]
if [h["ttl"] for h in hops] != [1, 2, 3, 4, 5]:
    fail.append(f"hop series {[h['ttl'] for h in hops]}, want 1 to 5")
want = [0, 0, 30, 0, 0]
for h in hops[:5]:
    w = want[h["ttl"] - 1]
    if abs(h["loss_pct"] - w) > 5:
        fail.append(f"hop {h['ttl']}: loss {h['loss_pct']:.1f} %, want {w} % +- 5")
    addrs = [x["addr"] for x in h["responders"]]
    exp = "198.51.100.10" if h["ttl"] == 5 else f"192.0.2.{h['ttl']}"
    if addrs != [exp]:
        fail.append(f"hop {h['ttl']}: responders {addrs}, want [{exp}]")
    med = (h["median_us"] or 0) / 1000
    print(f"  server hop {h['ttl']}: {','.join(addrs)} loss {h['loss_pct']:5.1f} % "
          f"of {h['sent']} median {med:.3f} ms")
# Sweeps start on 10 s steps: the first may wait up to a step.
if r["sweeps"] < (secs - 12) * 2:
    fail.append(f"{r['sweeps']} raw sweeps, want at least {(secs - 12) * 2}")
if fail:
    print("FAIL server trace: " + "; ".join(fail))
    sys.exit(1)
print(f"PASS server trace ({r['sweeps']} sweeps, {r['rounds']} hop rounds)")
EOF

exit $status
