# Routelith

Routelith is an open-source network latency monitor in Rust. It combines
SmokePing-style latency distributions ("smoke" graphs) with PingPlotter-style
hop-by-hop path tracing, measured from federated agents on Linux and Windows,
shipped as one self-contained binary.

**Status:** pre-alpha. M0 (ICMP, scheduler, store, SVG smoke graphs) and M1
(TCP/DNS/HTTP, rollups, web UI, services), M2 (alerts, outputs, reports)
and M3 (agents) are done; M3.5 (path monitoring) has started with
`routelith trace --report`, an unprivileged hop-by-hop trace. `routelith
check icmp`, `check tcp`, `check dns` and
`check http` work on Linux and Windows, and `routelith server` measures all
four kinds of target. The server also answers HTTP on `127.0.0.1:8080`
(`listen_ui` in `[server]`; `"off"` turns it off): a web UI with an overview
matrix and smoke graphs per target, a read-only JSON API under `/api/v1`,
server-rendered SVG and PNG graphs (`/api/v1/render/<id>.svg` or `.png`), Prometheus `/metrics` and `/healthz`.

With no users, the UI needs no login, as before; keep it on loopback then.
`routelith ctl user add NAME --role viewer|operator|admin -c routelith.toml`
adds a user (it asks for the password; `--password-stdin` reads it from a
pipe), and from then on the UI shows a login form and the API answers 401
without a caller. Users live in `users.toml` in the data directory
(`users_file` in `[server]` to move it), with Argon2id password hashes;
`ctl user passwd`, `role`, `remove` and `list` change it, and the server
picks changes up within a second, ending a removed user's sessions. A
login is a session cookie (HttpOnly, SameSite=Strict, Secure over TLS;
idle 8 h, 24 h at most) with a CSRF token for writes; scripts and
Prometheus can send HTTP Basic credentials instead. Ten failed logins in
five minutes from one address, or for one name, lock it out for the rest
of that window. `anonymous = true` lets callers without a login read, for a
wall display. `tls_cert` and `tls_key` (PEM files) serve the UI over HTTPS.
Roles: viewers read, operators also add and end silences, admins can do
everything.

Operators silence a raised alert from the overview (its rule on its
target, for 1 hour to 7 days, with a comment saying why), and end added
silences there. Scripts use `POST /api/v1/silences` with JSON
`{"targets": [...], "groups": [...], "alerts": [...], "minutes": 60,
"comment": "..."}` (or `start` and `end` in Unix milliseconds, at most 90
days; `name` is optional), and `DELETE /api/v1/silences/<name>` to end one
now. Added silences are kept in `silences.json` in the data directory, with
who added and ended them, until a week after they end; those in the
configuration file can only be changed there. Without users no one can add
silences, as anyone could reach the UI.
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
(kept 400 days). The overview lists the alerts raised now and the target view
the target's events; `/api/v1/alerts` lists the alerts raised now,
`/api/v1/events` the event history, and `/metrics` has a gauge per raised
alert plus raise and clear counters.

`[[output]]` tables send events on as they happen: to syslog (`type =
"syslog"`, RFC 5424 or RFC 3164, over UDP, TCP or TLS with octet-counting
framing per RFC 5425) or to a JSON-lines file (`type = "jsonl"`, one event
per line in the event log's shape; the file is reopened for each event, so
logrotate may move it). Each output can take only some event kinds,
targets, groups or rules. Each has its own queue (`queue`, default 1000)
and thread: an unreachable receiver fills only its queue, which then drops
events and counts them (`routelith_output_events_dropped_total`), and the
event in hand is retried with a pause that grows from 1 s to a minute. On a
clean stop the outputs get 5 seconds to send what they hold. RFC 5424
messages put the event's fields in structured data under the SD-ID
`routelith@32473` (32473 is the example enterprise number of RFC 5612;
set `sd_id` if your site has its own) and MSGID is the event kind; RFC
3164 messages have only the old header and the event's text.

On Windows, `type = "eventlog"` writes events to the Application log as
source `Routelith`, for Event Viewer and for forwarding with WEF: event ID
1000 alert raised (warning), 1001 alert cleared, 1002 address changed,
3000 server started, 3001 server stopped. The event's text is its first
insertion string; the others are its fields in a fixed order (kind, time,
vantage, target, family, series, rule, value, since, from, to; empty when
the event has none). The MSI and `routelith service install` register the
source, whose message table is built into `routelith.exe`; without that,
Event Viewer still shows the strings but says the description is missing.
The MSI's configuration has an Event Log output.

`type = "webhook"` POSTs each event to a URL, over HTTP or HTTPS
(`ca_file` adds a CA for a private one). `format` picks the body: `json`
(the default; the event as in the event log) or a message for `slack`,
`teams` (an Adaptive Card, for a Teams workflow webhook), `mattermost`,
`ntfy` or `gotify`. With `secret` set, a JSON request is signed:
`X-Routelith-Signature: sha256=<hex>` is the HMAC-SHA256 of
`<X-Routelith-Timestamp>.<body>` under the secret, so the receiver can
check it and refuse stale timestamps. `token` is the ntfy access token or
the Gotify application token; it needs an `https://` URL unless the
receiver is on the same machine (localhost or a loopback address). A 2xx answer is success; 408, 429, 5xx and
network errors are retried; any other answer drops the event and is
counted, as retrying would not help. `url`, `secret` and `token` can name
where the secret is instead of holding it: `${env:NAME}` reads an
environment variable and `${file:/path}` a file, so the configuration file
can be shared. Messages
name only the URL's host, as some URLs are secrets themselves.

`type = "email"` sends one plain-text mail per event over SMTP to the
`to` list, with a PNG of the series' smoke graph attached (the `graph`
span before sending, default `3h`; `"off"` for none). `address` is the
SMTP server; `security` is `starttls` (the default, port 587; the
upgrade must succeed), `tls` (port 465) or `none` (port 25). With
`username`, the `password` must come from `${env:NAME}` or
`${file:/path}`, never the configuration file, and needs `starttls` or
`tls` unless the server is on this machine. A permanent SMTP refusal
(5xx: unknown recipient, failed login) drops the event and counts it; a
temporary one (4xx) and network errors are retried.

A condition can follow the target's own history instead of a fixed value:
`condition = "> baseline_p50_7d * 2 + 5ms"` compares with the median of the
last week's hourly medians (`baseline_<p50|p90|min|max>_<1d|7d|28d>`, from
the hourly tier, refreshed every hour; such a rule cannot raise until the
window holds 24 hourly values, or 18 for a 1-day window). A target's
`parent` (or a group's, for its other targets) names the target it depends
on: a child alert raised while the parent has an alert raised is marked as
suppressed. The mark is decided when the child's alert is raised, and its
clear keeps it; a parent alert raised later does not mark it. `[[silence]]` tables
mark alerts raised in a window (`start` and `end`) or a recurring one (an
`rrule` with FREQ=DAILY or WEEKLY, BYDAY, BYHOUR and BYMINUTE, in UTC, plus a
`duration`), for some targets, groups or rules. A silence that comes into
force while an alert is raised marks that alert from then on, so its clear
is not sent either. Suppressed and silenced
alerts are still logged and shown, and outputs do not send them unless an
output sets `quiet = true`. See
`examples/routelith.toml`.

SLA reports check targets against `[[sla]]` tables (some `targets` or
`groups`, or every target): `availability = "99.9%"` (the share of rounds
that got at least one reply), `loss = "1%"` and `latency = "20ms"` at
`percentile = 95`. A month's report (UTC) comes from the hourly tier, kept
400 days, as a print-ready HTML page (print it to PDF from the browser) or
CSV: `routelith ctl report sla -c routelith.toml --month 2026-11
--format html|csv -o report.html`, or `GET
/api/v1/reports/sla?month=2026-11&format=csv`; the overview links last
month's and this month's. Each target also shows how much of the month was
measured, and time the server was not measuring counts neither for nor
against it. Hours stored by a version before this one did not count rounds
without a reply; they are counted from the raw rounds while those are kept
(30 days), and otherwise estimated from the hour's loss, which the report
says.

The NIS2 incident timeline builds incidents from the event log: alerts on a
target and its children (through `parent`) belong to the same incident, and
alerts that start within the gap (15 minutes by default) after the last one
ended join it too; an incident still open takes in every later alert below
the same root. Each incident shows when the degradation began, when the first
alert was raised, when it recovered, the affected targets with each alert's
peak loss and median, address changes and server restarts in between, and the
deadlines counted from detection: the early warning within 24 hours, the
notification within 72 hours and the final report a month after that.
Incidents where every alert was silenced are marked planned. Whether an
incident is significant under NIS2 is for people to decide. A month's
timeline (UTC) comes as HTML, JSON or CSV: `routelith ctl report incidents
-c routelith.toml --month 2026-11 --format html|json|csv --gap 15m -o
incidents.html`, or `GET
/api/v1/reports/incidents?month=2026-11&format=json&gap=15` (the gap in
minutes); the overview links this month's and last month's.

History from SmokePing comes over with `routelith ctl import smokeping`,
with the server stopped. It reads `rrdtool dump` XML, so the RRD files can
be dumped on the SmokePing machine and copied over:

```console
$ rrdtool dump /var/lib/smokeping/Gateway.rrd > gateway.xml
$ routelith ctl import smokeping gateway.xml --target gateway --config routelith.toml
imported local/gateway/v4: 863 rounds (2025-11-20 to 2025-11-22), 4249 hourly and 197 daily points (2025-05-07 to 2025-11-19)
```

The newest archive (5-minute rows) becomes raw rounds and the older ones
hourly and daily points. Import a target before the server first measures
it, so its live rounds continue the imported history; a series that
already has data is refused, so import under another `--target` or
`--vantage` then.

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

## Agents

Agents measure from other sites and report to one server (milestone M3). The server accepts them on `listen_agents`, and a group's
`vantages` says who measures it:

```toml
[server]
vantage       = "home"
listen_agents = "0.0.0.0:4443"

[[group]]
name     = "erp"
vantages = ["home", "plant-genk"]   # the server and agent plant-genk
# vantages = ["*"]                  # every enrolled agent and the server
```

A group without `vantages` is measured by the server only. Agents get
their targets from the server when they connect; their series appear
under the agent's name. Groups with
`"*"` include agents enrolled before the server started, so restart the
server after enrolling a new agent for them, as after any configuration
change. An HTTP target's `ca_file` is read on the agent.

At first use the server creates its own CA in `data_dir/ca/`; keep
`ca.key` private. Enrolling an agent takes one token, made on the server:

```console
$ routelith ctl agent add plant-genk -c routelith.toml
Enrollment token for agent plant-genk, valid for 24h, works once:

rlt1-…
```

The agent needs only a small configuration file, `agent.toml`:

```toml
server   = "monitor.example.be:4443"
data_dir = "/var/lib/routelith-agent"
```

```console
$ routelith agent enroll -c agent.toml --token rlt1-…
$ routelith agent run -c agent.toml
```

The token carries the fingerprint of the server's CA, so the agent trusts
only that server, and the agent's private key never leaves it. `routelith
ctl agent list` shows enrolled agents and waiting tokens; `routelith ctl
agent revoke <name>` refuses an agent's certificate from then on and drops
its stream within 10 seconds. Enrolling an agent again (with a new token)
replaces its certificate. An admin logged in to the web UI can do both on
the Agents page too (`POST /api/v1/agents/enroll-token` with `{"name":
…}`, and `DELETE /api/v1/agents/<name>`).

An agent measures only what its own `allow` list lets it, whatever the
server asks, so a server that is broken into cannot turn agents into
scanners:

```toml
allow = ["10.0.0.0/8", "erp.example.be", "*.plant.example", "icmp", "tcp:443"]
```

Entries are addresses or networks, host names (or every name under a
domain with `*.`), and probe types with an optional port (`icmp`, `tcp`,
`tcp:443`, `dns`, `http:8080`). A target must match one entry of each
kind that the list has; no list allows everything. A target given by
host name and allowed only by a network is checked against the address
each round resolves to. Refused series are reported to the server and
shown in the UI, with why.

Every round an agent measures goes to its spool, `data_dir/spool/`, before
it is sent, and stays there until the server has stored it and synced it
to disk. While the server is unreachable the agent keeps measuring; when
it is back the agent sends the backlog in order, and the server drops any
round it already has, so an outage or a restart on either side loses
nothing and stores nothing twice. The spool is bounded at 512 MB or 30
days (`spool_max_mb`, `spool_max_days` in `agent.toml`); beyond that the
oldest rounds are dropped and the agent logs how many. Alerts raised or
cleared by a round more than 10 minutes old are marked late (`"late":
true` in JSON outputs, "late:" before the message elsewhere), so a replay
does not read as something happening now. The server keeps how far it got
with each agent in `data_dir/agents.json`.

The server keeps track of each agent. `/api/v1/agents` lists every
enrolled agent with whether it is connected, from where, its version, OS
and what it can measure, its clock offset, its spool size and backlog,
and rounds it lost. An agent that cannot send ICMP (no permission) or
does not know a probe type says so when it connects; the server leaves
those series out for it and lists them, with why, under `refused`.
Every 30 seconds the server measures the agent's clock against its own,
NTP-style; an agent more than 100 ms off is flagged, as its timestamps
are then off by as much. Agents send a health snapshot (CPU, memory,
NIC errors) once a minute, kept in `data_dir/health/<agent>/` like the
server's own.

These go to the event log and the outputs, with the agent's name as
vantage:

| Event | When |
|---|---|
| `agent_enrolled` | An agent used its token. |
| `agent_connected` | First connection since the server started, or back after a reported outage. |
| `agent_disconnected` | Gone for more than 60 seconds (shorter drops are not reported). |
| `agent_revoked` | A revoked agent was turned away (once per server run). |
| `agent_clock_skew`, `agent_clock_ok` | Its clock went beyond 100 ms off, or came back. |
| `agent_rounds_lost` | Rounds it measured never arrived (its spool was full). |

In the web UI, the overview has a column per vantage; an agent's column
head shows whether it is connected, and a series it refused says so. The
target view stacks one graph per vantage, with "Same y-axis for every
graph" to compare them, and shows each vantage's health. The Agents page
lists every agent with its status, version, OS, timing, clock offset,
spool backlog, lost rounds and last contact, and the series it does not
measure. `/api/v1/health?vantage=<agent>` gives an agent's health
snapshots.

`/metrics` adds `routelith_agent_connected`,
`routelith_agent_clock_offset_seconds`, `routelith_agent_spool_bytes` and
`routelith_agent_rounds_lost_total`, each with an `agent` label.

An alert rule can ask for agreement between vantages, so a problem at
one site does not read as the target being down:

```toml
[[alert]]
name = "down-everywhere"
metric = "loss"
condition = ">= 100%"
for = "2 rounds"
min_vantages = 2   # raised when 2 or more vantages match at once
```

The rule still runs on each vantage's series, but only one alert is
raised per target and family, when `min_vantages` or more vantages match
at the same time, and it clears when fewer do. The server counts, and so
does an agent while it is connected; one gone for more than 60 seconds
(when `agent_disconnected` is logged) no longer does, so a short
reconnect does not clear an alert and raise it again. The alert names
the vantages that matched ("2 of 3 vantages match (home, plant-genk)"),
its event has them under `vantages` and the server's own vantage, and
the UI shows them next to it. For three minutes after the server starts,
a raised alert is not cleared just because an agent has not reconnected
yet. A target measured from fewer vantages than the rule needs never
raises it, and the server says so at start.

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

**Agents** use the same binary (§21.7 G14). On Linux,
`packaging/linux/routelith-agent.service` runs `routelith agent run
--config /etc/routelith/agent.toml` the same way, writing only
`/var/lib/routelith-agent` (`data_dir = "/var/lib/routelith-agent"` in
`agent.toml`). With a dynamic user, enroll as that user, so the service can
read the identity it writes:

```console
$ sudo systemd-run --pipe --wait --quiet -p DynamicUser=yes -p User=routelith-agent \
    -p StateDirectory=routelith-agent \
    /usr/bin/routelith agent enroll -c /etc/routelith/agent.toml --token rlt1-…
$ sudo systemctl enable --now routelith-agent
```

On a server that runs from `routelith.service`, run `ctl agent` commands
the same way, as `-p User=routelith -p StateDirectory=routelith`, or make
tokens on the web UI's Agents page. On Windows, enroll first, then
`routelith service install --agent --config C:\ProgramData\Routelith\agent.toml`
(as Administrator) registers the `RoutelithAgent` service, which runs as
`LocalService` and logs to `routelith-agent.log` next to its configuration;
`routelith service uninstall --agent` removes it. `data_dir` must be an
absolute path, and the install refuses an agent that is not enrolled yet.
The MSI installs the server only.

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
| `crates/rl-render` | Smoke-graph algorithm, SVG rendering and PNG (resvg, embedded Liberation Sans under `fonts/`) |
| `crates/rl-alert` | Alert engine: thresholds with hysteresis, SmokePing patterns |
| `crates/rl-web` | HTTP server: REST API, `/metrics`, the web UI (plain JS in `ui/`) |
| `crates/rl-out` | Outputs: syslog (UDP, TCP, TLS) and JSON-lines files, each with its own queue |
| `crates/rl-fed` | Agents: gRPC protocol (`proto/`, generated code checked in; `gen/` regenerates it), server CA, enrollment |

Later milestones add `rl-path` and `rl-reflector`.

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
