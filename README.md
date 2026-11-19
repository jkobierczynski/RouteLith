# Routelith

Routelith is an open-source network latency monitor in Rust. It combines
SmokePing-style latency distributions ("smoke" graphs) with PingPlotter-style
hop-by-hop path tracing, measured from federated agents on Linux and Windows,
shipped as one self-contained binary.

**Status:** pre-alpha. M0 (ICMP, scheduler, store, SVG smoke graphs) is done;
M1 is in progress. `routelith check icmp`, `check tcp` and `check dns` work on
Linux and Windows, and `routelith server` measures all three kinds of target.

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

## Layout

| Path | Contents |
| --- | --- |
| `bin/routelith` | The single binary and its subcommands |
| `crates/rl-core` | Domain types: targets, rounds, samples, config schema |
| `crates/rl-sys` | All `unsafe` and OS FFI (the only crate allowed `unsafe`) |
| `crates/rl-probe` | The `Probe` trait and probe implementations |
| `crates/rl-sched` | Round scheduler, phase spreading, rate limiting |
| `crates/rl-store` | smokestore: WAL, day segments, codecs |
| `crates/rl-render` | Smoke-graph algorithm and SVG rendering |

Later milestones add `rl-path`, `rl-fed`, `rl-alert`, `rl-out`, `rl-web` and
`rl-reflector`.

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
