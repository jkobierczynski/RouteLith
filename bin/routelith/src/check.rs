//! `routelith check`: one-shot measurement for debugging and scripting.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::Args;
use rl_core::config::{
    DNS_QTYPES, DNS_RCODES, DnsConfig, DnsTransport, HttpConfig, HttpMethod, HttpMetric, TcpMode,
    parse_http_url, parse_status_ranges,
};
use rl_core::{ResolvedTarget, RoundPlan, RoundResult, RoundStats, Sample, SampleError};
use rl_probe::{DnsProbe, HttpProbe, IcmpConfig, IcmpProbe, Probe, TcpConfig, TcpProbe};

#[derive(Debug, Args)]
pub(crate) struct IcmpArgs {
    /// Host name or IP address to measure.
    host: String,
    #[command(flatten)]
    common: CommonArgs,
    /// ICMP payload size in bytes (minimum 8).
    #[arg(short = 's', long, default_value_t = 56)]
    size: u16,
}

#[derive(Debug, Args)]
pub(crate) struct TcpArgs {
    /// Host name or IP address to connect to.
    host: String,
    #[command(flatten)]
    common: CommonArgs,
    /// TCP port to connect to.
    #[arg(short, long, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// Time until the server's first byte (SSH, SMTP) instead of the handshake.
    #[arg(long)]
    banner: bool,
}

#[derive(Debug, Args)]
pub(crate) struct DnsArgs {
    /// DNS server to query (host name or IP address).
    server: String,
    #[command(flatten)]
    common: CommonArgs,
    /// Name to query; `{rand}` becomes a random label per sample.
    query: String,
    /// Record type.
    #[arg(short = 't', long = "type", default_value = "A", value_parser = upper_in(DNS_QTYPES))]
    qtype: String,
    /// Server port.
    #[arg(short, long, default_value_t = 53, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// Query over TCP (a new connection per sample) instead of UDP.
    #[arg(long)]
    tcp: bool,
    /// Clear the recursion-desired bit.
    #[arg(long)]
    no_recurse: bool,
    /// Response code that counts as success.
    #[arg(long, default_value = "NOERROR", value_parser = upper_in(DNS_RCODES))]
    expect_rcode: String,
    /// Expected answer (repeat for a set); other answers are mismatches.
    #[arg(long = "expect")]
    expect_answers: Vec<String>,
}

/// A clap parser accepting one of `allowed`, case-insensitively, as upper case.
fn upper_in(allowed: &'static [&'static str]) -> impl Fn(&str) -> Result<String, String> + Clone {
    move |s: &str| {
        let up = s.to_ascii_uppercase();
        if allowed.contains(&up.as_str()) {
            Ok(up)
        } else {
            Err(format!("expected one of {}", allowed.join(", ")))
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct HttpArgs {
    /// URL to request (http:// or https://).
    url: String,
    #[command(flatten)]
    common: CommonArgs,
    /// Time stored as the sample: ttfb, total, connect or tls.
    #[arg(long, default_value = "ttfb", value_parser = ["ttfb", "total", "connect", "tls"])]
    metric: String,
    /// Status ranges that count as success, e.g. 200-299 or "200,301-302".
    #[arg(long, default_value = "200-299")]
    expect_status: String,
    /// Send HEAD instead of GET.
    #[arg(long)]
    head: bool,
    /// Regular expression the body (first MiB) must match.
    #[arg(long)]
    body_regex: Option<String>,
    /// Accept any certificate (insecure).
    #[arg(short = 'k', long)]
    insecure: bool,
    /// Extra CA certificates to trust (PEM).
    #[arg(long)]
    ca_file: Option<std::path::PathBuf>,
    /// TLS server name to send instead of the URL's host.
    #[arg(long)]
    sni: Option<String>,
}

/// Arguments every probe takes.
#[derive(Debug, Args)]
struct CommonArgs {
    /// Number of samples in the round.
    #[arg(short = 'c', long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..))]
    count: u16,
    /// Time between samples, e.g. 1s, 200ms.
    #[arg(short = 'i', long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,
    /// Per-sample timeout, e.g. 2s.
    #[arg(short = 'W', long, default_value = "2s", value_parser = parse_duration)]
    timeout: Duration,
    /// Use IPv4 only.
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,
    /// Use IPv6 only.
    #[arg(short = '6')]
    ipv6: bool,
    /// Print only the summary.
    #[arg(short, long)]
    quiet: bool,
}

const MAX_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) async fn icmp(args: IcmpArgs) -> ExitCode {
    let probe = IcmpProbe::new(IcmpConfig {
        payload_size: args.size,
    });
    run(&args.host, &args.common, &probe, |t, r| {
        format!(
            "ICMP {} ({}): {} samples, {}-byte payload",
            t.name,
            r.meta.resolved,
            r.samples.len(),
            r.meta.payload_size
        )
    })
    .await
}

pub(crate) async fn tcp(args: TcpArgs) -> ExitCode {
    let mode = if args.banner {
        TcpMode::Banner
    } else {
        TcpMode::Connect
    };
    let port = args.port;
    let probe = TcpProbe::new(TcpConfig { port, mode });
    run(&args.host, &args.common, &probe, |t, r| {
        let what = match mode {
            TcpMode::Connect => "connect time",
            TcpMode::Banner => "time to banner",
        };
        format!(
            "TCP {} ({}) port {port}: {} samples, {what}",
            t.name,
            r.meta.resolved,
            r.samples.len(),
        )
    })
    .await
}

pub(crate) async fn dns(args: DnsArgs) -> ExitCode {
    let transport = if args.tcp {
        DnsTransport::Tcp
    } else {
        DnsTransport::Udp
    };
    let cfg = DnsConfig {
        port: args.port,
        query: args.query.clone(),
        qtype: args.qtype.clone(),
        transport,
        recursion: !args.no_recurse,
        expect_rcode: args.expect_rcode.clone(),
        expect_answers: (!args.expect_answers.is_empty()).then(|| args.expect_answers.clone()),
    };
    let probe = match DnsProbe::new(cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("routelith check: {e}");
            return ExitCode::from(2);
        }
    };
    run(&args.server, &args.common, &probe, |t, r| {
        format!(
            "DNS {} {} @{} ({}) port {} over {}: {} samples",
            args.qtype,
            args.query,
            t.name,
            r.meta.resolved,
            args.port,
            transport.as_str(),
            r.samples.len(),
        )
    })
    .await
}

pub(crate) async fn http(args: HttpArgs) -> ExitCode {
    let url = args.url.trim().to_string();
    let parsed = match parse_http_url(&url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("routelith check: url {e}");
            return ExitCode::from(2);
        }
    };
    let expect_status = match parse_status_ranges(&args.expect_status) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("routelith check: --expect-status: {e}");
            return ExitCode::from(2);
        }
    };
    let metric = match args.metric.as_str() {
        "total" => HttpMetric::Total,
        "connect" => HttpMetric::Connect,
        "tls" if parsed.tls => HttpMetric::Tls,
        "tls" => {
            eprintln!("routelith check: --metric tls needs an https URL");
            return ExitCode::from(2);
        }
        _ => HttpMetric::Ttfb,
    };
    let cfg = HttpConfig {
        url: url.clone(),
        tls: parsed.tls,
        host: parsed.host.clone(),
        port: parsed.port,
        path: parsed.path,
        method: if args.head {
            HttpMethod::Head
        } else {
            HttpMethod::Get
        },
        expect_status,
        metric,
        body_regex: args.body_regex.clone(),
        tls_verify: !args.insecure,
        ca_file: args.ca_file.clone(),
        sni: args.sni.clone(),
    };
    let probe = match HttpProbe::new(cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("routelith check: {e}");
            return ExitCode::from(2);
        }
    };
    run(&parsed.host, &args.common, &probe, |_, r| {
        format!(
            "HTTP {} {url} ({}): {} samples, {}",
            if args.head { "HEAD" } else { "GET" },
            r.meta.resolved,
            r.samples.len(),
            metric.as_str()
        )
    })
    .await
}

/// Resolve, run one round and print it under the probe's `header` line.
async fn run(
    host: &str,
    args: &CommonArgs,
    probe: &dyn Probe,
    header: impl Fn(&ResolvedTarget, &RoundResult) -> String,
) -> ExitCode {
    // Bounds that keep every offset and deadline of the round representable
    // (and match the configuration's limits).
    if args.interval > MAX_INTERVAL || args.timeout.is_zero() || args.timeout > MAX_TIMEOUT {
        eprintln!(
            "routelith check: interval must be at most {} and timeout more than 0 and at most {}",
            rl_core::duration::format(MAX_INTERVAL),
            rl_core::duration::format(MAX_TIMEOUT)
        );
        return ExitCode::from(2);
    }
    let addr = match resolve(host, args.ipv4, args.ipv6).await {
        Ok(addr) => addr,
        Err(msg) => {
            eprintln!("routelith check: {msg}");
            return ExitCode::from(2);
        }
    };
    let target = ResolvedTarget {
        name: host.to_string(),
        addr,
    };
    let spread = args.interval * u32::from(args.count);
    let plan = RoundPlan {
        count: args.count,
        spread,
        timeout: args.timeout,
        round_start: SystemTime::now(),
    };
    match probe.run_round(&target, plan).await {
        Ok(round) => {
            print!("{}", render(&header(&target, &round), &round, args.quiet));
            exit_code(&round.samples)
        }
        Err(e) => {
            eprintln!("routelith check: {e}");
            ExitCode::from(2)
        }
    }
}

/// 0 if any reply arrived; 2 if nothing came back and at least one request
/// failed locally (it never left this host); 1 for plain 100 % loss.
fn exit_code(samples: &[Sample]) -> ExitCode {
    let stats = RoundStats::from_samples(samples);
    let local_failure = samples
        .iter()
        .any(|s| matches!(s, Sample::Error(SampleError::SendFailed(_))));
    if stats.received > 0 {
        ExitCode::SUCCESS
    } else if local_failure {
        ExitCode::from(2)
    } else {
        ExitCode::from(1)
    }
}

pub(crate) async fn resolve(host: &str, v4_only: bool, v6_only: bool) -> Result<IpAddr, String> {
    let wanted = |a: &IpAddr| (!v4_only || a.is_ipv4()) && (!v6_only || a.is_ipv6());
    if let Ok(addr) = host.parse::<IpAddr>() {
        return if wanted(&addr) {
            Ok(addr)
        } else {
            Err(format!("{host} is not of the requested address family"))
        };
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .map(|sa| sa.ip())
        .filter(wanted)
        .collect();
    // Like ping: prefer IPv4 unless -6 was given.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| format!("{host} has no address of the requested family"))
}

fn ms(us: u32) -> String {
    format!("{:.3}", f64::from(us) / 1000.0)
}

/// Render a round as text. The summary lines are stable and parsed by the
/// accuracy lab script (`tests/lab/netem-accuracy.sh`).
fn render(header: &str, round: &RoundResult, quiet: bool) -> String {
    let mut out = String::new();
    let stats = RoundStats::from_samples(&round.samples);
    let _ = writeln!(out, "{header}");
    if !quiet {
        for (i, sample) in round.samples.iter().enumerate() {
            let line = match sample {
                Sample::Ok { rtt_us } => format!("{} ms", ms(*rtt_us)),
                Sample::Lost => "lost".to_owned(),
                Sample::Error(e) => format!("error: {e}"),
            };
            let phases = round
                .http
                .as_ref()
                .and_then(|h| h.phases.get(i).copied().flatten())
                .map(|p| {
                    let tls = p
                        .tls_us
                        .map(|t| format!(" tls {}", ms(t)))
                        .unwrap_or_default();
                    format!(
                        "  (connect {}{tls} ttfb {} total {})",
                        ms(p.connect_us),
                        ms(p.ttfb_us),
                        ms(p.total_us)
                    )
                })
                .unwrap_or_default();
            let _ = writeln!(out, "  #{:<4} {line}{phases}", i + 1);
        }
    }
    let _ = writeln!(
        out,
        "--- {} sent, {} received, {:.1}% loss",
        stats.sent,
        stats.received,
        stats.loss_ratio() * 100.0
    );
    if let (Some(min), Some(med), Some(p90), Some(max)) =
        (stats.min_us, stats.median_us, stats.p90_us, stats.max_us)
    {
        let _ = writeln!(
            out,
            "rtt min/median/p90/max = {}/{}/{}/{} ms",
            ms(min),
            ms(med),
            ms(p90),
            ms(max)
        );
    }
    let _ = writeln!(out, "timing: {}", round.meta.timing);
    if let Some(t) = round.http.as_ref().and_then(|h| h.cert_not_after) {
        let line = match t.duration_since(SystemTime::now()) {
            Ok(left) => format!("certificate expires in {} days", left.as_secs() / 86_400),
            Err(e) => format!(
                "certificate EXPIRED {} days ago",
                e.duration().as_secs() / 86_400
            ),
        };
        let _ = writeln!(out, "{line}");
    }
    out
}

/// Parse `1s`, `250ms`, `500us` or a bare number of seconds.
pub(crate) fn parse_duration(s: &str) -> Result<Duration, String> {
    rl_core::duration::parse(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_core::{ProbeMeta, TimingBackend, TimingSource};

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("500us"), Ok(Duration::from_micros(500)));
        assert_eq!(parse_duration("500µs"), Ok(Duration::from_micros(500)));
        assert_eq!(parse_duration("2"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn exit_codes() {
        let ok = Sample::Ok { rtt_us: 1 };
        let local = Sample::Error(SampleError::SendFailed("ENETUNREACH".into()));
        let remote = Sample::Error(SampleError::Unreachable { code: 1 });
        assert_eq!(exit_code(&[ok.clone(), local.clone()]), ExitCode::SUCCESS);
        assert_eq!(exit_code(&[Sample::Lost, local]), ExitCode::from(2));
        assert_eq!(exit_code(&[Sample::Lost, remote]), ExitCode::from(1));
        assert_eq!(exit_code(&[Sample::Lost]), ExitCode::from(1));
    }

    #[test]
    fn summary_format_is_stable() {
        let target = ResolvedTarget {
            name: "lab".into(),
            addr: "192.0.2.1".parse().unwrap(),
        };
        let round = RoundResult {
            start: SystemTime::UNIX_EPOCH,
            samples: vec![
                Sample::Ok { rtt_us: 10_100 },
                Sample::Lost,
                Sample::Ok { rtt_us: 10_300 },
            ],
            meta: ProbeMeta {
                resolved: target.addr,
                timing: TimingSource::new(TimingBackend::LinuxKernelTimestamp),
                payload_size: 56,
            },
            http: None,
        };
        let text = render(
            &format!("ICMP lab ({}): 3 samples, 56-byte payload", target.addr),
            &round,
            true,
        );
        assert_eq!(
            text,
            "ICMP lab (192.0.2.1): 3 samples, 56-byte payload\n\
             --- 3 sent, 2 received, 33.3% loss\n\
             rtt min/median/p90/max = 10.100/10.200/10.300/10.300 ms\n\
             timing: kernel timestamps (ping socket), precision ±0.05 ms\n"
        );
    }
}
