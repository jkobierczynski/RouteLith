//! `routelith ctl calibrate`: measure the Windows ICMP API timing error against
//! a raw-socket reference (architecture doc, risk R1). Windows only; needs
//! Administrator for the raw socket.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use rl_probe::calibration::{Dist, Summary};

use crate::check::parse_duration;

#[derive(Debug, Args)]
pub(crate) struct CalibrateArgs {
    /// IPv4 address to echo (default: loopback, which isolates the API overhead).
    #[arg(long, default_value = "127.0.0.1")]
    target: Ipv4Addr,
    /// Number of pairs (one API echo plus one raw-socket echo each).
    #[arg(short = 'c', long, default_value_t = 1000, value_parser = clap::value_parser!(u16).range(1..))]
    count: u16,
    /// Time between pairs, e.g. 10ms.
    #[arg(short = 'i', long, default_value = "10ms", value_parser = parse_duration)]
    interval: Duration,
    /// Per-echo timeout.
    #[arg(short = 'W', long, default_value = "1s", value_parser = parse_duration)]
    timeout: Duration,
    /// ICMP payload size in bytes (minimum 8, which holds the nonce).
    #[arg(short = 's', long, default_value_t = 56, value_parser = clap::value_parser!(u16).range(8..=65507))]
    size: u16,
    /// Pass if the p99 of |api - raw| is at most this many milliseconds.
    /// Parsed exactly, to whole nanoseconds.
    #[arg(long = "max-p99-ms", default_value = "0.5", value_parser = parse_limit_ms)]
    max_p99_ns: i64,
}

const MAX_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

/// A non-negative decimal number of milliseconds, as whole nanoseconds.
/// Digits past the sixth decimal are dropped, so the limit never rounds up
/// past what was asked for.
fn parse_limit_ms(s: &str) -> Result<i64, String> {
    const ERR: &str = "must be a decimal number of milliseconds, 0 or more (e.g. 0.5)";
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    let digits = |t: &str| t.bytes().all(|b| b.is_ascii_digit());
    if (int.is_empty() && frac.is_empty()) || !digits(int) || !digits(frac) {
        return Err(ERR.into());
    }
    let whole: i64 = if int.is_empty() {
        0
    } else {
        int.parse().map_err(|_| ERR.to_string())?
    };
    let mut ns_frac = 0i64;
    for b in frac.bytes().chain(std::iter::repeat(b'0')).take(6) {
        ns_frac = ns_frac * 10 + i64::from(b - b'0');
    }
    whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(ns_frac))
        .ok_or_else(|| ERR.to_string())
}

pub(crate) fn run(args: &CalibrateArgs) -> ExitCode {
    if args.timeout.is_zero() {
        eprintln!("routelith ctl calibrate: the timeout must be greater than zero");
        return ExitCode::from(2);
    }
    // The runner adds the interval to an Instant after every pair; keep the
    // whole schedule well inside what an Instant can hold.
    if args.interval > MAX_INTERVAL || args.timeout > MAX_TIMEOUT {
        eprintln!(
            "routelith ctl calibrate: interval must be at most {} and timeout at most {}",
            rl_core::duration::format(MAX_INTERVAL),
            rl_core::duration::format(MAX_TIMEOUT)
        );
        return ExitCode::from(2);
    }
    #[cfg(windows)]
    {
        let pairs = match rl_probe::calibration::run(
            args.target,
            args.count,
            args.interval,
            args.timeout,
            usize::from(args.size),
        ) {
            Ok(pairs) => pairs,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "routelith ctl calibrate: the raw-socket reference needs Administrator ({e})"
                );
                return ExitCode::from(2);
            }
            Err(e) => {
                eprintln!("routelith ctl calibrate: {e}");
                return ExitCode::from(2);
            }
        };
        let summary = Summary::from_pairs(&pairs);
        let (report, verdict) = render(args, &summary);
        print!("{report}");
        match verdict {
            Some(true) => ExitCode::SUCCESS,
            Some(false) => ExitCode::from(1),
            None => ExitCode::from(2),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("routelith ctl calibrate: only needed and supported on Windows");
        ExitCode::from(2)
    }
}

// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn ms(ns: i64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let v = ns as f64 / 1_000_000.0;
    format!("{v:.3}")
}

/// Milliseconds exact to the nanosecond, with at least three decimals.
// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn ms_exact(ns: i64) -> String {
    let sign = if ns < 0 { "-" } else { "" };
    let ns = ns.unsigned_abs();
    let frac = format!("{:06}", ns % 1_000_000);
    let frac = frac.trim_end_matches('0');
    let frac = format!("{frac:0<3}");
    format!("{sign}{}.{frac}", ns / 1_000_000)
}

// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn line(out: &mut String, label: &str, d: Option<Dist>) {
    match d {
        Some(d) => {
            let _ = writeln!(
                out,
                "{label:<26} min/median/p90/p99/max = {}/{}/{}/{}/{} ms (n={})",
                ms(d.min),
                ms(d.median),
                ms(d.p90),
                ms(d.p99),
                ms(d.max),
                d.count
            );
        }
        None => {
            let _ = writeln!(out, "{label:<26} no replies");
        }
    }
}

/// The report, and the verdict (`None` if there were no complete pairs).
// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn render(args: &CalibrateArgs, s: &Summary) -> (String, Option<bool>) {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "calibration {}: {} pairs, {}-byte payload, {:?} apart",
        args.target, s.pairs, args.size, args.interval
    );
    line(&mut out, "icmp api (IcmpSendEcho2Ex)", s.api);
    line(&mut out, "raw socket reference", s.raw);
    line(&mut out, "api - raw", s.diff);
    line(&mut out, "|api - raw|", s.abs_err);
    line(&mut out, "|api - raw - offset|", s.abs_err_corrected);
    let _ = writeln!(
        out,
        "api RoundTripTime field more than 1 ms off the reference: {} of {} pairs",
        s.api_field_off,
        s.diff.map_or(0, |d| d.count)
    );
    let Some(err) = s.abs_err else {
        let _ = writeln!(out, "FAIL  no pair had replies on both sides");
        return (out, None);
    };
    // Both sides are whole nanoseconds, so equality passes exactly.
    let pass = err.p99 <= args.max_p99_ns;
    let _ = writeln!(
        out,
        "{}  R1: p99 |api - raw| = {} ms, target <= {} ms",
        if pass { "PASS" } else { "FAIL" },
        ms_exact(err.p99),
        ms_exact(args.max_p99_ns)
    );
    (out, Some(pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_probe::calibration::Pair;

    fn args() -> CalibrateArgs {
        CalibrateArgs {
            target: Ipv4Addr::LOCALHOST,
            count: 2,
            interval: Duration::from_millis(10),
            timeout: Duration::from_secs(1),
            size: 56,
            max_p99_ns: 500_000,
        }
    }

    fn pair(api_us: u64, raw_us: u64) -> Pair {
        Pair {
            api: Some(Duration::from_micros(api_us)),
            api_rtt_ms: Some(0),
            raw: Some(Duration::from_micros(raw_us)),
        }
    }

    #[test]
    fn verdict_follows_the_p99_limit() {
        let ok = Summary::from_pairs(&[pair(300, 100), pair(400, 100)]);
        let (out, verdict) = render(&args(), &ok);
        assert_eq!(verdict, Some(true), "{out}");
        assert!(
            out.contains("PASS  R1: p99 |api - raw| = 0.300 ms"),
            "{out}"
        );

        let bad = Summary::from_pairs(&[pair(300, 100), pair(900, 100)]);
        assert_eq!(render(&args(), &bad).1, Some(false));
    }

    #[test]
    fn limit_must_be_finite_and_non_negative() {
        assert_eq!(parse_limit_ms("0"), Ok(0));
        assert_eq!(parse_limit_ms("0.5"), Ok(500_000));
        assert_eq!(parse_limit_ms(".5"), Ok(500_000));
        assert_eq!(parse_limit_ms("1.000001"), Ok(1_000_001));
        assert_eq!(parse_limit_ms("1.0000019"), Ok(1_000_001));
        for bad in ["-0.1", "NaN", "inf", "x", "", ".", "1e3", "1.2.3"] {
            assert!(parse_limit_ms(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn verdict_line_shows_nanoseconds() {
        assert_eq!(ms_exact(500_100), "0.5001");
        assert_eq!(ms_exact(500_000), "0.500");
        assert_eq!(ms_exact(1_000_001), "1.000001");
        let s = Summary::from_pairs(&[Pair {
            api: Some(Duration::from_nanos(600_100)),
            api_rtt_ms: Some(0),
            raw: Some(Duration::from_nanos(100_000)),
        }]);
        let (out, verdict) = render(&args(), &s);
        assert_eq!(verdict, Some(false));
        assert!(
            out.contains("p99 |api - raw| = 0.5001 ms, target <= 0.500 ms"),
            "{out}"
        );
    }

    #[test]
    fn no_complete_pair_is_an_error() {
        let s = Summary::from_pairs(&[Pair {
            api: None,
            api_rtt_ms: None,
            raw: None,
        }]);
        let (out, verdict) = render(&args(), &s);
        assert_eq!(verdict, None);
        assert!(out.contains("no replies"), "{out}");
    }
}
