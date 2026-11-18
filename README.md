# Routelith

Routelith is an open-source network latency monitor in Rust. It combines
SmokePing-style latency distributions ("smoke" graphs) with PingPlotter-style
hop-by-hop path tracing, measured from federated agents on Linux and Windows,
shipped as one self-contained binary.

**Status:** pre-alpha. The workspace skeleton is in place; milestone M0
(ICMP probing, scheduler, raw-tier storage, SVG smoke graphs,
`routelith check`) is in progress. Nothing measures anything yet.

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

Supported platforms: Linux x86_64 (glibc and static musl) and Windows x86_64.
macOS is compiled in CI but not a primary target.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
