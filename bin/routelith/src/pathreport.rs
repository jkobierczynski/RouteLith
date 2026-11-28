//! `routelith ctl report path`: a traced target's hops over a recent
//! window, read from the store (hop series and raw sweeps, §21.9 P6, P7),
//! with address classes and, given `asn_db`, AS numbers (P9). The server
//! may run.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use rl_core::addr::classify;
use rl_core::config;
use rl_path::enrich::{AsnDb, HopInfo};
use rl_path::report::{PathReport, ResponderRow, Source};
use rl_store::Reader;
use serde::Serialize;

use crate::check::parse_duration;

#[derive(Debug, Args)]
pub(crate) struct PathArgs {
    /// Configuration file, for the data directory and vantage.
    #[arg(short, long)]
    config: PathBuf,
    /// Target id as configured.
    #[arg(long)]
    target: String,
    /// Series of a `both` target: v4 or v6 (default: the only one, else v4).
    #[arg(long)]
    family: Option<String>,
    /// Window ending now.
    #[arg(long, default_value = "10m", value_parser = parse_duration)]
    last: Duration,
    /// Print JSON instead of a table.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    target: String,
    vantage: String,
    family: String,
    #[serde(flatten)]
    path: PathReport,
}

/// Exit codes: 0 printed, 1 no such traced target, 2 cannot read.
pub(crate) fn run(args: &PathArgs) -> ExitCode {
    match report(args, now_ms()) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => {
            eprintln!("routelith ctl report path: {msg}");
            ExitCode::from(code)
        }
    }
}

fn report(args: &PathArgs, now: i64) -> Result<String, (u8, String)> {
    let src = std::fs::read_to_string(&args.config)
        .map_err(|e| (2, format!("{}: {e}", args.config.display())))?;
    let cfg = config::parse(&src).config.ok_or_else(|| {
        (
            2,
            format!(
                "{} is invalid; check it with `routelith ctl verify`",
                args.config.display()
            ),
        )
    })?;
    let dir = &cfg.server.data_dir;
    let reader = Reader::open(dir).map_err(|e| (2, format!("{}: {e}", dir.display())))?;
    let vantage = &cfg.server.vantage;
    let raw_name = format!("{}#", args.target);
    // Families with raw sweeps of this target.
    let families: Vec<&str> = reader
        .find(&raw_name)
        .into_iter()
        .filter(|(k, _)| &k.vantage == vantage)
        .map(|(k, _)| k.family.as_str())
        .collect();
    let family = match (&args.family, families.as_slice()) {
        (Some(f), _) => f.clone(),
        (None, [only]) => (*only).to_string(),
        (None, _) => "v4".to_string(),
    };
    let Some(raw_id) = reader
        .find(&raw_name)
        .into_iter()
        .find(|(k, _)| &k.vantage == vantage && k.family == family)
        .map(|(_, id)| id)
    else {
        return Err((
            1,
            format!(
                "no trace of {:?} ({family}) from vantage {vantage:?} in the store",
                args.target
            ),
        ));
    };
    let to_ms = now;
    let from_ms = now - i64::try_from(args.last.as_millis()).unwrap_or(i64::MAX);
    let mut hop_ids: BTreeMap<u8, u64> = BTreeMap::new();
    for (k, id) in reader.series() {
        if &k.vantage != vantage || k.family != family {
            continue;
        }
        if let Some(ttl) = k
            .target
            .strip_prefix(&raw_name)
            .and_then(|t| t.parse::<u8>().ok())
        {
            hop_ids.insert(ttl, *id);
        }
    }
    // TTL 1 up, as long as there is a series for each.
    let hop_ids: Vec<u64> = (1..=u8::MAX)
        .map_while(|t| hop_ids.get(&t).copied())
        .collect();
    let mut path = rl_path::report::read(&reader, dir, raw_id, &hop_ids, from_ms, to_ms)
        .map_err(|e| (2, format!("reading the trace: {e}")))?;
    // AS numbers from `asn_db`; names need the server's lookups.
    if let Some(file) = &cfg.server.asn_db {
        match AsnDb::load(file) {
            Ok(db) => {
                let info: HashMap<IpAddr, HopInfo> = path
                    .addrs()
                    .into_iter()
                    .map(|a| {
                        let class = classify(a);
                        let asn = db.lookup(a).filter(|_| class.is_public());
                        let info = HopInfo {
                            rdns: None,
                            asn: asn.map(|i| i.asn),
                            org: asn.map(|i| i.org.clone()),
                            country: asn.map(|i| i.country.clone()),
                            class,
                        };
                        (a, info)
                    })
                    .collect();
                path.enrich(&info);
            }
            Err(e) => eprintln!(
                "routelith ctl report path: warning: asn_db {}: {e}",
                file.display()
            ),
        }
    }
    let r = Report {
        target: args.target.clone(),
        vantage: vantage.clone(),
        family,
        path,
    };
    if args.json {
        let mut s = serde_json::to_string_pretty(&r).map_err(|e| (2, e.to_string()))?;
        s.push('\n');
        Ok(s)
    } else {
        Ok(render(&r, args.last))
    }
}

fn ms(us: Option<f64>) -> String {
    us.map_or_else(|| "-".into(), |us| format!("{:.2}", us / 1000.0))
}

#[allow(clippy::cast_precision_loss)]
fn f(us: Option<u64>) -> Option<f64> {
    us.map(|u| u as f64)
}

/// An address, with its class unless it is public.
fn host(r: &ResponderRow) -> String {
    if r.class.is_public() {
        r.addr.to_string()
    } else {
        format!("{} ({})", r.addr, r.class.as_str())
    }
}

fn render(r: &Report, last: Duration) -> String {
    let p = &r.path;
    let mut out = String::new();
    let _ = write!(
        out,
        "path of {} ({}) from {}, last {}: ",
        r.target,
        r.family,
        r.vantage,
        rl_core::duration::format(last),
    );
    let _ = match p.source {
        Source::Sweeps => writeln!(out, "{} sweeps, {} hop rounds", p.sweeps, p.rounds),
        Source::HopSeries => writeln!(
            out,
            "{} hop rounds (no raw sweeps in the window, so no responders)",
            p.rounds
        ),
    };
    let _ = writeln!(
        out,
        "{:>3}  {:<39} {:>8} {:>6} {:>6} {:>6} {:>8} {:>8} {:>8} {:>8}",
        "Hop", "Host", "ASN", "Loss%", "Sent", "Recv", "Min", "Median", "Avg", "Max"
    );
    let asn = |x: &ResponderRow| x.asn.map_or_else(|| "-".into(), |a| format!("AS{a}"));
    for h in &p.hops {
        let first = h.responders.first();
        let _ = writeln!(
            out,
            "{:>3}  {:<39} {:>8} {:>6.1} {:>6} {:>6} {:>8} {:>8} {:>8} {:>8}",
            h.ttl,
            first.map_or_else(|| "???".to_string(), host),
            first.map_or_else(|| "-".to_string(), asn),
            h.loss_pct,
            h.sent,
            h.received,
            ms(f(h.min_us)),
            ms(f(h.median_us)),
            ms(h.avg_us),
            ms(f(h.max_us))
        );
        if h.responders.len() > 1 {
            for x in &h.responders {
                let _ = writeln!(
                    out,
                    "{:>3}  {:<39} {:>8} {:>5.1}% of answers",
                    "",
                    format!("  {}", host(x)),
                    asn(x),
                    x.share_pct
                );
            }
        }
    }
    out
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
