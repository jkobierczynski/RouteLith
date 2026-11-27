//! `routelith ctl report path`: a traced target's hops over a recent
//! window, read from the store (hop series and raw sweeps, §21.9 P6, P7).
//! The server may run.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use rl_core::config;
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

#[derive(Debug, Serialize, PartialEq)]
struct Responder {
    addr: IpAddr,
    replies: u64,
}

#[derive(Debug, Serialize, PartialEq)]
struct Hop {
    ttl: u8,
    sent: u64,
    received: u64,
    loss_pct: f64,
    min_us: Option<u32>,
    median_us: Option<u32>,
    max_us: Option<u32>,
    /// From the raw sweeps; most answers first.
    responders: Vec<Responder>,
}

#[derive(Debug, Serialize)]
struct Report {
    target: String,
    vantage: String,
    family: String,
    from_ms: i64,
    to_ms: i64,
    /// Hop rounds in the window (of the first hop).
    rounds: usize,
    /// Raw sweeps in the window.
    sweeps: usize,
    hops: Vec<Hop>,
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
    let sweeps = rl_store::read_trace(dir, raw_id, from_ms, to_ms)
        .map_err(|e| (2, format!("reading the sweeps: {e}")))?;
    let mut responders: BTreeMap<u8, BTreeMap<IpAddr, u64>> = BTreeMap::new();
    for s in &sweeps {
        for (i, h) in s.hops.iter().enumerate() {
            if let (Some(a), Ok(ttl)) = (h.responder(), u8::try_from(i + 1)) {
                *responders.entry(ttl).or_default().entry(a).or_default() += 1;
            }
        }
    }
    let mut hops = Vec::new();
    let mut rounds = 0;
    for (&ttl, &id) in &hop_ids {
        let rs = reader
            .read(id, from_ms, to_ms)
            .map_err(|e| (2, format!("reading hop {ttl}: {e}")))?;
        if rs.is_empty() {
            continue;
        }
        if hops.is_empty() {
            rounds = rs.len();
        }
        let mut rtts: Vec<u32> = rs.iter().flat_map(|r| r.rtts_us.iter().copied()).collect();
        rtts.sort_unstable();
        let sent: u64 = rs.iter().map(|r| u64::from(r.sent)).sum();
        let received = rtts.len() as u64;
        let mid = rtts.len() / 2;
        let median = match rtts.len() {
            0 => None,
            n if n % 2 == 1 => Some(rtts[mid]),
            _ => Some(rtts[mid - 1] / 2 + rtts[mid] / 2 + (rtts[mid - 1] % 2 + rtts[mid] % 2) / 2),
        };
        let mut rs: Vec<Responder> = responders
            .remove(&ttl)
            .unwrap_or_default()
            .into_iter()
            .map(|(addr, replies)| Responder { addr, replies })
            .collect();
        rs.sort_by(|a, b| b.replies.cmp(&a.replies).then(a.addr.cmp(&b.addr)));
        hops.push(Hop {
            ttl,
            sent,
            received,
            #[allow(clippy::cast_precision_loss)]
            loss_pct: if sent == 0 {
                0.0
            } else {
                100.0 * (sent - received) as f64 / sent as f64
            },
            min_us: rtts.first().copied(),
            median_us: median,
            max_us: rtts.last().copied(),
            responders: rs,
        });
    }
    let r = Report {
        target: args.target.clone(),
        vantage: vantage.clone(),
        family,
        from_ms,
        to_ms,
        rounds,
        sweeps: sweeps.len(),
        hops,
    };
    if args.json {
        let mut s = serde_json::to_string_pretty(&r).map_err(|e| (2, e.to_string()))?;
        s.push('\n');
        Ok(s)
    } else {
        Ok(render(&r, args.last))
    }
}

fn ms(us: Option<u32>) -> String {
    us.map_or_else(|| "-".into(), |us| format!("{:.2}", f64::from(us) / 1000.0))
}

fn render(r: &Report, last: Duration) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "path of {} ({}) from {}, last {}: {} hop rounds, {} sweeps",
        r.target,
        r.family,
        r.vantage,
        rl_core::duration::format(last),
        r.rounds,
        r.sweeps
    );
    let _ = writeln!(
        out,
        "{:>3}  {:<39} {:>6} {:>6} {:>6} {:>8} {:>8} {:>8}",
        "Hop", "Host", "Loss%", "Sent", "Recv", "Min", "Median", "Max"
    );
    for h in &r.hops {
        let host = h
            .responders
            .first()
            .map_or_else(|| "???".to_string(), |x| x.addr.to_string());
        let _ = writeln!(
            out,
            "{:>3}  {:<39} {:>6.1} {:>6} {:>6} {:>8} {:>8} {:>8}",
            h.ttl,
            host,
            h.loss_pct,
            h.sent,
            h.received,
            ms(h.min_us),
            ms(h.median_us),
            ms(h.max_us)
        );
        if h.responders.len() > 1 {
            let total: u64 = h.responders.iter().map(|x| x.replies).sum();
            for x in &h.responders {
                #[allow(clippy::cast_precision_loss)]
                let share = 100.0 * x.replies as f64 / total.max(1) as f64;
                let _ = writeln!(
                    out,
                    "{:>3}  {:<39} {share:>5.1}% of answers",
                    "",
                    format!("  {}", x.addr)
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
