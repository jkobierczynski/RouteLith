# Developing Routelith

This guide covers building Routelith, running its tests, and trying it by hand
on Linux and Windows. For what Routelith is and how the crates are laid out,
see the [README](README.md).

## Toolchain

- **Day to day:** current stable Rust. `rust-toolchain.toml` pins the
  `stable` channel with `rustfmt` and `clippy`, so `rustup` picks it up on
  its own.
- **Minimum supported version (MSRV):** 1.85, the first release with edition
  2024. It is declared as `rust-version` in `Cargo.toml` and checked by the
  `msrv` CI job. Code must still build on 1.85, so:
  - no let-chains (`if let Some(x) = a && cond { ... }`) and no other syntax
    newer than 1.85;
  - new dependencies must have a `rust-version` of 1.85 or lower (for
    example redb 4.x needs Rust 1.90, so the workspace stays on redb 2.x).

  Check locally with:

  ```sh
  rustup toolchain install 1.85
  cargo +1.85 check --workspace --all-targets --locked
  ```

- CI runs clippy from the newest stable, which can be ahead of yours. Run
  `rustup update stable` before pushing if clippy passes locally but fails in
  CI.

## Build

```sh
cargo build                      # debug: target/debug/routelith
cargo build --release            # release: target/release/routelith
```

The release profile uses thin LTO, one codegen unit and stripped symbols, so
it is noticeably slower to build. Use it for timing work (the lab scripts,
calibration, the scheduler bench); debug builds are fine for everything else.

A fully static Linux binary:

```sh
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools          # Debian/Ubuntu
cargo build --release --target x86_64-unknown-linux-musl
```

## Before you push

These are the same checks CI runs (`.github/workflows/ci.yml`), with
`RUSTFLAGS=-D warnings`:

```sh
export RUSTFLAGS="-D warnings"   # as in CI; unset it afterwards to avoid rebuilds
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check                          # needs: cargo install cargo-deny
cargo +1.85 check --workspace --all-targets --locked
```

Workspace conventions:

- Only `rl-sys` may use `unsafe`. Every other crate has
  `#![forbid(unsafe_code)]`, and every `unsafe` block in `rl-sys` needs a
  `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks` is denied).
- Dependencies are declared once in `[workspace.dependencies]` in the root
  `Cargo.toml` and used with `{ workspace = true }` in the crates.
- New dependencies must have a licence on the allow list in `deny.toml`
  (licences compatible with GPL-3.0-or-later).

## Tests

```sh
cargo test --workspace                    # everything
cargo test -p rl-store                    # one crate
cargo test -p rl-probe --test loopback    # one test file
```

### ICMP permission for the loopback tests (Linux)

`crates/rl-probe/tests/loopback.rs` sends real ICMP echoes to `127.0.0.1`
through a Linux ping socket. It does not need root, but your group must be
inside the `net.ipv4.ping_group_range` sysctl. Without that the loopback
tests fail with `Permission denied (os error 13)` and a hint about
`ping_group_range`.

Check the current range:

```sh
cat /proc/sys/net/ipv4/ping_group_range
id -g
```

If your group id is not inside the two numbers (`1 0` means nobody is
allowed), widen it:

```sh
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

To keep it after a reboot:

```sh
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-routelith-ping.conf
sudo sysctl --system
```

Debian and most current distributions already allow every group. Containers,
some CI images and hardened hosts often do not. The sysctl is per network
namespace, so a container needs it set inside the container.

On Windows the loopback tests use the ICMP helper API and need no special
rights. The IPv6 loopback test skips itself when the host has no IPv6.

Where you cannot change the sysctl (a container, the cloud sandbox) but are
root, run the tests in a new network namespace, whose sysctl is your own:

```sh
sudo unshare --net sh -c 'ip link set lo up
  echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
  cargo test --workspace'
```

### Smoke-graph goldens

`crates/rl-render/tests/golden.rs` compares rendered SVGs byte for byte with
the files in `crates/rl-render/tests/golden/`. When you change the renderer
on purpose, regenerate them and look at the diff before committing:

```sh
UPDATE_GOLDEN=1 cargo test -p rl-render
git diff crates/rl-render/tests/golden/
```

The SVG is hand-written (no font rasterising), so the goldens are identical
on every platform.

### Lab scripts (Linux only)

These are the M0 acceptance checks from the architecture doc (§21.2). They
are slow and run as separate CI jobs, not under `cargo test`. Build a release
binary first.

```sh
cargo build --release

# Delay and loss accuracy in two network namespaces with tc netem.
# Needs root, iproute2 and the sch_netem module (linux-modules-extra on Ubuntu).
sudo tests/lab/netem-accuracy.sh target/release/routelith

# On a desktop or VM netem itself adds 1–3 ms; loosen the delay tolerance:
sudo DELAY_TOL_MS=1 tests/lab/netem-accuracy.sh target/release/routelith

# `routelith trace` over a fake 5-hop path on a TUN device, run as user
# nobody, IPv4 and IPv6 (about 2 minutes). Runs in its own network
# namespace, so it changes nothing on the host. Needs root, python3,
# iproute2 and setpriv; no veth or netem, so it also works in containers
# that have /dev/net/tun.
sudo tests/lab/trace-lab.sh target/release/routelith

# 1,000 loopback targets for one 300 s step (about 6 minutes):
# p99 round-start lateness, overruns and CPU. Needs ping_group_range.
tests/lab/schedule-bench.sh target/release/routelith
```

If iputils `ping` is installed, `netem-accuracy.sh` runs it alongside
Routelith as a reference, and the absolute delay check only warns when ping
reads late too.

## Trying it by hand

### Linux (tested on Debian)

1. Make sure your user may send ICMP (see
   [ICMP permission](#icmp-permission-for-the-loopback-tests-linux) above),
   then build:

   ```sh
   cargo build --release
   export PATH="$PWD/target/release:$PATH"
   ```

2. One-off measurement:

   ```sh
   routelith check icmp 1.1.1.1 -c 5 -i 200ms
   routelith check icmp example.net -6 -q      # IPv6, summary only
   ```

   Trace the path hop by hop (no root either; same `ping_group_range`),
   and compare with `traceroute -I` or `mtr`:

   ```sh
   routelith trace --report -c 20 1.1.1.1
   routelith trace --json -c 20 -6 example.net
   ```

3. Validate the example configuration:

   ```sh
   routelith ctl verify examples/routelith.toml
   ```

   It prints `OK: 3 targets, 4 series, ...` and exits 0. Warnings (a host
   that does not resolve, no IPv6, no ICMP permission) do not fail it; exit
   code 1 means the file is invalid and 2 that it cannot be read. Add
   `--no-resolve` to skip DNS lookups.

4. Run the server. `examples/routelith.toml` stores data in
   `/var/lib/routelith` and measures every 60–300 s, which is slow for a
   quick test. Copy it and change `data_dir` and `step`, or use a small
   config like this one (`dev.toml`):

   ```toml
   [server]
   data_dir = "./rl-data"   # relative to the directory you start in

   [defaults]
   step  = "10s"            # must be whole seconds that divide a day
   pings = 5

   [[group]]
   name = "Test"

     [[group.target]]
     name = "localhost"
     host = "127.0.0.1"

     [[group.target]]
     name = "cloudflare"
     host = "1.1.1.1"
   ```

   ```sh
   routelith ctl verify dev.toml
   routelith server -c dev.toml --stats-interval 10
   ```

   The server runs in the foreground and prints a stats line to stderr every
   `--stats-interval` seconds. Stop it with Ctrl+C (or SIGTERM); it drains
   the rounds in flight and syncs the store before exiting.

5. Render a smoke graph. Leave the server running for a few minutes, then
   open another terminal in the same directory (the one holding `dev.toml`,
   since `./rl-data` is relative to it) and set `PATH` again:

   ```sh
   cd /path/to/routelith
   export PATH="$PWD/target/release:$PATH"
   routelith ctl render -c dev.toml --target cloudflare --range 3h --out cloudflare.svg
   ```

   `--target` is the target's `name` from the config. You can point at the
   store directly with `--data-dir ./rl-data` instead of `-c`. For a target
   with `family = "both"`, pick the series with `--family v6`. Open the SVG
   in a browser. Ranges are `3h`, `30h` and `10d`.

   Rendering reads the store while the server writes it, so you do not have
   to stop the server. A target that is registered but has no rounds yet
   renders as an empty graph. `no data for target "..."` (exit 1) means the
   store has no series by that name at all: check the spelling of
   `--target`, and that `-c` or `--data-dir` points at the store the server
   writes.

### Windows

On Windows Routelith uses the ICMP helper API (`IcmpSendEcho2Ex`), which needs
no special rights for `check`, `server` and `render`. Install Rust with
[rustup](https://rustup.rs) and the MSVC build tools, then in PowerShell:

```powershell
cargo build --release
$env:PATH = "$PWD\target\release;$env:PATH"

routelith check icmp 1.1.1.1 -c 5 -i 200ms
routelith trace --report -c 20 1.1.1.1
routelith ctl verify examples\routelith.toml
```

`routelith trace` also runs as a standard user; compare its hops with
`tracert -d 1.1.1.1`.

For the server, use the same `dev.toml` as above. If you give an absolute
Windows path for `data_dir`, use a TOML literal string (single quotes) so the
backslashes are not read as escapes:

```toml
data_dir = 'C:\Users\you\rl-data'
```

```powershell
routelith server -c dev.toml --stats-interval 10
# Ctrl+C to stop
routelith ctl render -c dev.toml --target cloudflare --out cloudflare.svg
start cloudflare.svg
```

#### Timing calibration (`ctl calibrate`, Administrator)

`routelith ctl calibrate` measures how far the Windows ICMP API's round-trip
times are from a raw ICMP socket's (risk R1 in the architecture doc). It sends
pairs of echoes, one through each path, and reports the p99 of the
difference. Raw sockets need Administrator, so:

1. Open **PowerShell as Administrator** (Start menu, right-click PowerShell,
   *Run as administrator*).
2. Run it from the repository:

   ```powershell
   cd C:\path\to\routelith
   # Loopback isolates the API's own overhead:
   .\target\release\routelith.exe ctl calibrate -c 2000 -i 5ms
   # A real path, for example your gateway:
   .\target\release\routelith.exe ctl calibrate --target 192.168.1.1 -c 1000
   ```

`--target` must be an IPv4 address. The default pass mark is a p99 of 0.5 ms
(`--max-p99-ms` changes it). Exit code 0 means it passed, 1 that it measured
but missed the target, and 2 that it could not measure (most often because
it was not run as Administrator, which it reports as such). Use a
release build; a debug build adds its own overhead.

CI runs the loopback calibration on `windows-2022` and `windows-2025` and
puts the report in the job summary.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main`:

| Job | What it checks |
| --- | --- |
| `rustfmt` | `cargo fmt --all --check` |
| `test (ubuntu-latest, windows-latest)` | clippy and `cargo test --workspace`; Linux sets `ping_group_range` first so the loopback tests can run |
| `accuracy lab (netns + netem)` | `tests/lab/netem-accuracy.sh` |
| `tracer lab (TUN fake path)` | `tests/lab/trace-lab.sh` |
| `scheduler bench (1,000 targets)` | `tests/lab/schedule-bench.sh` |
| `R1 calibration (windows-2022, windows-2025)` | `ctl calibrate` on loopback; a missed target is a warning, a failure to measure fails |
| `check (macos-latest)` | `cargo check` only; macOS is best effort |
| `static build (musl)` | release build for `x86_64-unknown-linux-musl` |
| `MSRV (1.85)` | `cargo +1.85 check --workspace --all-targets` |
| `cargo-deny` | advisories, licences, bans and sources from `deny.toml` |

All jobs use stable Rust except `MSRV`. The 1.85 toolchain is passed in the
action's `with:` block rather than its ref, so Dependabot does not try to
"upgrade" the MSRV.
