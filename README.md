# Routelith

Routelith is an open-source network latency monitor in Rust. It combines
SmokePing-style latency distributions ("smoke" graphs) with PingPlotter-style
hop-by-hop path tracing, measured from federated agents on Linux and Windows,
shipped as one self-contained binary.

**Status:** pre-alpha. M0 (ICMP, scheduler, store, SVG smoke graphs) and M1
(TCP/DNS/HTTP, rollups, web UI, services) are done; M2 (alerts, outputs,
reports) is in progress. `routelith check icmp`, `check tcp`, `check dns` and
`check http` work on Linux and Windows, and `routelith server` measures all
four kinds of target. The server also answers HTTP on `127.0.0.1:8080`
(`listen_ui` in `[server]`; `"off"` turns it off): a web UI with an overview
matrix and smoke graphs per target, a read-only JSON API under `/api/v1`,
server-rendered SVG graphs, Prometheus `/metrics` and `/healthz`.
There is no login yet, so keep it on loopback or behind a proxy that has one.
Once a minute the server also records a health snapshot of its own machine
(CPU, NIC errors and drops, default gateways, DNS servers) in
`data/health/`; the target view shows it beside the graphs, so a slow minute
can be told apart from a busy or reconfigured host.

Alert rules are `[[alert]]` tables that targets name in an `alerts` setting
(which cascades from `[defaults]` and groups like `step`): thresholds with
hysteresis (`metric = "median"`, `condition = "> 20ms"`, `for = "3 rounds"`,
`clear = "< 15ms"`) and SmokePing patterns (`type = "loss"`,
`pattern = [">0%", "*3*", ">0%"]`). Raised and cleared alerts, address
changes and server starts and stops go to an event log in `data/events/`
(kept 400 days); the overview lists the alerts raised now, the target view
the target's events, and `/api/v1/alerts`, `/api/v1/events` and `/metrics`
serve them. Sending them to syslog, the Event Log, webhooks and e-mail comes
next.

```console
$ routelith check icmp example.net -c 5 -i 200ms
ICMP example.net (192.0.2.10): 5 samples, 56-byte payload
  #1    8.412 ms
  ...
--- 5 sent, 5 received, 0.0% loss
rtt min/median/p90/max = 8.305/8.398/8.512/8.512 ms
timing: kernel timestamps (ping socket), precision ±0.05 ms
```

On Linux, ICMP runs without root through ping sockets; the user's group must
be inside `net.ipv4.ping_group_range` (most distributions allow every group by
default). On Windows it uses the ICMP helper API and needs no privileges.

## Running as a service

**Linux (systemd):** `packaging/linux/routelith.service` runs
`routelith server --config /etc/routelith/routelith.toml` as a transient
user (`DynamicUser=yes`) that can write only `/var/lib/routelith`, so set
`data_dir = "/var/lib/routelith"`. Installation steps are at the top of the
unit file. ICMP needs no capabilities; see `60-routelith-ping.conf` if your
system keeps `net.ipv4.ping_group_range` closed.

**Windows:** the MSI (`cargo wix -p routelith`, WiX Toolset 3) installs
`routelith.exe` in `Program Files\Routelith\bin`, a starter configuration in
`C:\ProgramData\Routelith\routelith.toml`, and the `Routelith` service, which
runs as `LocalService`, starts with Windows and is restarted after a
failure. Its log is `C:\ProgramData\Routelith\routelith.log`. Without the MSI,
`routelith service install --config <file>` (as Administrator) registers the
same service and `routelith service uninstall` removes it. The service runs
the `routelith.exe` you install it from, so copy it out of `target\release`
first (for example to `C:\Program Files\Routelith\bin`): a rebuild replaces
that file and the access granted to `LocalService` with it, and the service
then fails to start. Keep the configuration, `data_dir` and log outside your
user profile too, for example under `C:\ProgramData\Routelith`. The MSI is
not signed yet.

## Layout

| Path | Contents |
| --- | --- |
| `bin/routelith` | The single binary and its subcommands; `wix/` builds the MSI |
| `packaging/linux` | systemd unit and an optional sysctl drop-in |
| `crates/rl-core` | Domain types: targets, rounds, samples, config schema |
| `crates/rl-sys` | All `unsafe` and OS FFI (the only crate allowed `unsafe`) |
| `crates/rl-probe` | The `Probe` trait and probe implementations |
| `crates/rl-sched` | Round scheduler, phase spreading, rate limiting |
| `crates/rl-store` | smokestore: WAL, day segments, codecs, rollups, health and event logs |
| `crates/rl-render` | Smoke-graph algorithm and SVG rendering |
| `crates/rl-alert` | Alert engine: thresholds with hysteresis, SmokePing patterns |
| `crates/rl-web` | HTTP server: REST API, `/metrics`, the web UI (plain JS in `ui/`) |

Later milestones add `rl-path`, `rl-fed`, `rl-out` and `rl-reflector`.

## Building

Requires Rust 1.85 or newer.

```sh
cargo build --release
cargo test --workspace
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for tests, CI, ICMP permissions and
trying Routelith by hand on Linux and Windows.

Supported platforms: Linux x86_64 (glibc and static musl) and Windows x86_64.
macOS is compiled in CI but not a primary target.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
