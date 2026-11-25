//! `routelith ctl import smokeping`: bring a SmokePing target's history
//! into the store from `rrdtool dump` XML (architecture doc §21.5).
//!
//! A SmokePing RRD has the data sources `uptime`, `loss`, `median` and
//! `ping1` to `pingN` (the RTTs of one round, sorted, in seconds; lost
//! pings are unknown), and AVERAGE, MIN and MAX archives. Only the AVERAGE
//! archives are read:
//!
//! - the one with one row per step becomes raw rounds;
//! - the others become hourly and daily rollup points. Each hour or day
//!   is built from the archive that covers most of it, the finer one on
//!   a tie (SmokePing's 1-hour archive goes back 180 days, its 12-hour one
//!   360).
//!
//! Raw rounds start at the first UTC day boundary in the raw archive when
//! the coarser archives also cover the day before it, because a day is
//! either rolled up or raw in the store, never both.
//!
//! A row stands for the interval that ends at its time, so a round or
//! point starts one row width earlier. Consolidated rows average each
//! `pingK` over the rounds, which keeps the shape of the smoke but not
//! every sample; the store's quantiles are taken from those averages.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use rl_core::config::{self, Config};
use rl_store::{
    ErrorCounts, ImportedHistory, RollupPoint, SeriesKey, StoreError, StoredRound, Writer,
    WriterOptions, quantiles,
};

const HOUR_S: i64 = 3_600;
const DAY_S: i64 = 86_400;

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("source").required(true).args(["config", "data_dir"])))]
pub(crate) struct SmokepingArgs {
    /// `rrdtool dump` output of one SmokePing target's RRD file
    /// (`rrdtool dump Target.rrd > Target.xml`).
    file: PathBuf,
    /// Target id to store the history under. To continue it with live
    /// rounds, use the target's id in the configuration and import before
    /// the server first measures it.
    #[arg(long)]
    target: String,
    /// Configuration file, for the data directory and vantage.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Data directory, instead of --config.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Vantage to store it under (default: the config's, or "local").
    #[arg(long)]
    vantage: Option<String>,
    /// Address family: v4, v6 or prefer-v6.
    #[arg(long, default_value = "v4")]
    family: String,
}

/// Exit codes: 0 imported, 1 the file or the series is not suitable,
/// 2 cannot read or write.
pub(crate) fn run(args: &SmokepingArgs) -> ExitCode {
    match import(args) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => {
            eprintln!("routelith ctl import smokeping: {msg}");
            ExitCode::from(code)
        }
    }
}

fn import(args: &SmokepingArgs) -> Result<String, (u8, String)> {
    if !["v4", "v6", "prefer-v6"].contains(&args.family.as_str()) {
        return Err((
            1,
            format!("--family {:?}: use v4, v6 or prefer-v6", args.family),
        ));
    }
    let (data_dir, cfg) = source(args)?;
    let vantage = args
        .vantage
        .clone()
        .or_else(|| cfg.as_ref().map(|c| c.server.vantage.clone()))
        .unwrap_or_else(|| config::DEFAULT_VANTAGE.to_string());
    let path = &args.file;
    let xml = std::fs::read_to_string(path).map_err(|e| (2, format!("{}: {e}", path.display())))?;
    let dump = parse(&xml).map_err(|e| (1, format!("{}: {e}", path.display())))?;
    let today = now_ms().div_euclid(DAY_S * 1000);
    let conv = convert(&dump, today).map_err(|e| (1, format!("{}: {e}", path.display())))?;
    let h = &conv.history;
    if h.rounds.is_empty() && h.daily.is_empty() {
        return Err((
            1,
            format!("{}: no measurements in the file", path.display()),
        ));
    }

    let now = now_ms();
    let (mut w, _) = Writer::open(&data_dir, WriterOptions::default(), now).map_err(|e| {
        let hint = if matches!(e, StoreError::Locked(_)) {
            "; stop the server first"
        } else {
            ""
        };
        (2, format!("{}: {e}{hint}", data_dir.display()))
    })?;
    let key = SeriesKey::new(&vantage, &args.target, &args.family);
    let id = w
        .register(std::slice::from_ref(&key))
        .map_err(|e| (2, format!("{key}: {e}")))?[0];
    let report = match w.import(id, h) {
        Ok(r) => r,
        Err(e @ StoreError::NotEmpty(_)) => {
            return Err((
                1,
                format!("{key} already has data ({e}); import under another --target or --vantage"),
            ));
        }
        Err(e) => return Err((2, format!("{key}: {e}"))),
    };
    // The server records its own step at start; until then the RRD's
    // tells readers the cadence.
    let step = u64::try_from(dump.step_s * 1000).unwrap_or(u64::MAX);
    let done = w
        .set_steps(&[(id, step)])
        .and_then(|()| w.maintain(now))
        .and_then(|()| w.close());
    done.map_err(|e| (2, format!("{}: {e}", data_dir.display())))?;

    let span = |a: Option<i64>, b: Option<i64>| match (a, b) {
        (Some(a), Some(b)) => format!("{} to {}", date(a), date(b)),
        _ => "nothing".to_string(),
    };
    Ok(format!(
        "imported {key}: {} rounds ({}), {} hourly and {} daily points ({}){}{}",
        report.rounds,
        span(
            h.rounds.first().map(|r| r.ts_ms),
            h.rounds.last().map(|r| r.ts_ms)
        ),
        report.hourly,
        report.daily,
        span(
            h.daily.first().map(|p| p.ts_ms),
            h.daily.last().map(|p| p.ts_ms)
        ),
        if report.late > 0 {
            format!(
                "; {} rounds older than the store keeps were left out",
                report.late
            )
        } else {
            String::new()
        },
        if conv.dropped_rounds > 0 {
            format!(
                "; {} raw rows of a partly rolled-up day were left to the hourly points",
                conv.dropped_rounds
            )
        } else {
            String::new()
        }
    ))
}

/// Data directory and configuration from --config or --data-dir.
fn source(args: &SmokepingArgs) -> Result<(PathBuf, Option<Config>), (u8, String)> {
    if let Some(dir) = &args.data_dir {
        return Ok((dir.clone(), None));
    }
    let path = args
        .config
        .as_ref()
        .ok_or((2, "need --config or --data-dir".to_string()))?;
    let src = std::fs::read_to_string(path).map_err(|e| (2, format!("{}: {e}", path.display())))?;
    let cfg = config::parse(&src).config.ok_or_else(|| {
        (
            2,
            format!(
                "{} is invalid; check it with `routelith ctl verify`",
                path.display()
            ),
        )
    })?;
    Ok((cfg.server.data_dir.clone(), Some(cfg)))
}

/// What the import needs from a dump.
#[derive(Debug, Clone, PartialEq)]
struct Dump {
    step_s: i64,
    last_update_s: i64,
    /// Data source names, in column order.
    ds: Vec<String>,
    rras: Vec<Rra>,
}

#[derive(Debug, Clone, PartialEq)]
struct Rra {
    cf: String,
    pdp_per_row: i64,
    /// Oldest first; NaN for unknown.
    rows: Vec<Vec<f64>>,
}

impl Rra {
    fn width_s(&self, step_s: i64) -> i64 {
        step_s.saturating_mul(self.pdp_per_row)
    }

    /// Start of each row's interval, Unix seconds, with the row.
    fn timed_rows(&self, d: &Dump) -> impl Iterator<Item = (i64, &[f64])> {
        let w = self.width_s(d.step_s);
        let last_end = d.last_update_s - d.last_update_s.rem_euclid(w);
        let n = self.rows.len() as i64;
        self.rows
            .iter()
            .enumerate()
            .map(move |(i, r)| (last_end - (n - i as i64) * w, r.as_slice()))
    }
}

fn parse(xml: &str) -> Result<Dump, String> {
    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..Default::default()
    };
    let doc =
        roxmltree::Document::parse_with_options(xml, opts).map_err(|e| format!("not XML: {e}"))?;
    let root = doc.root_element();
    if !root.has_tag_name("rrd") {
        return Err("not an `rrdtool dump` file (no <rrd> element)".into());
    }
    let child = |n: roxmltree::Node<'_, '_>, name: &str| {
        n.children()
            .find(|c| c.has_tag_name(name))
            .and_then(|c| c.text())
            .map(str::trim)
            .map(str::to_string)
    };
    let int = |n: roxmltree::Node<'_, '_>, name: &str| -> Result<i64, String> {
        child(n, name)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("missing or bad <{name}>"))
    };
    let step_s = int(root, "step")?;
    if !(1..=DAY_S).contains(&step_s) {
        return Err(format!("step {step_s} s is not one second to one day"));
    }
    let last_update_s = int(root, "lastupdate")?;
    let ds: Vec<String> = root
        .children()
        .filter(|c| c.has_tag_name("ds"))
        .map(|c| child(c, "name").unwrap_or_default())
        .collect();
    let mut rras = Vec::new();
    for rra in root.children().filter(|c| c.has_tag_name("rra")) {
        let cf = child(rra, "cf").ok_or("an archive has no <cf>")?;
        let pdp_per_row = int(rra, "pdp_per_row")?;
        if pdp_per_row < 1 {
            return Err(format!("pdp_per_row {pdp_per_row}"));
        }
        let mut rows = Vec::new();
        if let Some(db) = rra.children().find(|c| c.has_tag_name("database")) {
            for row in db.children().filter(|c| c.has_tag_name("row")) {
                let v: Vec<f64> = row
                    .children()
                    .filter(|c| c.has_tag_name("v"))
                    .map(|c| c.text().unwrap_or("").trim().parse().unwrap_or(f64::NAN))
                    .collect();
                if v.len() != ds.len() {
                    return Err(format!(
                        "a row of a {cf} archive has {} values for {} data sources",
                        v.len(),
                        ds.len()
                    ));
                }
                rows.push(v);
            }
        }
        rras.push(Rra {
            cf,
            pdp_per_row,
            rows,
        });
    }
    Ok(Dump {
        step_s,
        last_update_s,
        ds,
        rras,
    })
}

/// A dump turned into store history.
#[derive(Debug)]
struct Converted {
    history: ImportedHistory,
    /// Raw rows left out because the coarser archives cover their day.
    dropped_rounds: usize,
}

/// The replies of one row: RTTs in µs, ascending, and the loss column
/// (lost pings per round), or `None` if the row is unknown. `raw` rows
/// are trimmed to the reply count their loss gives; consolidated rows
/// keep every known value, as their loss is an average over rounds.
fn replies(
    row: &[f64],
    loss_col: usize,
    ping_cols: &[usize],
    raw: bool,
) -> Option<(Vec<u32>, f64)> {
    let loss = row[loss_col];
    if !loss.is_finite() {
        return None;
    }
    let n = ping_cols.len();
    let mut known: Vec<u32> = ping_cols
        .iter()
        .map(|&c| row[c])
        .filter(|v| v.is_finite() && *v >= 0.0)
        // Seconds to µs; RRD values are well inside u32 (71 minutes).
        .map(|v| (v * 1e6).round().min(f64::from(u32::MAX)) as u32)
        .collect();
    let loss = loss.clamp(0.0, n as f64);
    let want = if raw {
        n - (loss.round() as usize).min(n)
    } else {
        n
    };
    // Usually the same. Where they differ, a lost ping's slot took a
    // value from the neighbouring round (rrdtool blends the two rounds a
    // step overlaps). SmokePing puts lost pings at both ends of the slots,
    // half below and the rest above, so drop the extra values there.
    if want < known.len() {
        let extra = known.len() - want;
        known.truncate(known.len() - (extra - extra / 2));
        known.drain(..extra / 2);
    }
    // Slot order is RTT order within a round, not after blending.
    known.sort_unstable();
    Some((known, loss))
}

/// `today` is the current UTC day: nothing of it is rolled up, so live
/// rounds can still be added to it.
fn convert(d: &Dump, today: i64) -> Result<Converted, String> {
    let col = |name: &str| d.ds.iter().position(|n| n == name);
    let loss_col = col("loss");
    let mut pings: Vec<(u32, usize)> =
        d.ds.iter()
            .enumerate()
            .filter_map(|(i, n)| Some((n.strip_prefix("ping")?.parse::<u32>().ok()?, i)))
            .collect();
    pings.sort_unstable();
    let (Some(loss_col), false) = (loss_col, pings.is_empty()) else {
        return Err(
            "not a SmokePing RRD: it needs the data sources loss and ping1 to pingN".into(),
        );
    };
    if pings.len() > usize::from(u16::MAX) {
        return Err("more than 65,535 pings per round".into());
    }
    let ping_cols: Vec<usize> = pings.iter().map(|&(_, c)| c).collect();
    let sent = ping_cols.len() as u16;

    let averages: Vec<&Rra> = d.rras.iter().filter(|r| r.cf == "AVERAGE").collect();
    // The finest archive of each width.
    let mut by_width: BTreeMap<i64, &Rra> = BTreeMap::new();
    for r in &averages {
        let w = r.width_s(d.step_s);
        let e = by_width.entry(w).or_insert(r);
        if r.rows.len() > e.rows.len() {
            *e = r;
        }
    }

    // Rows with a value, as (start s, width s, point).
    let mut rows: Vec<(i64, i64, RollupPoint)> = Vec::new();
    for (&w, r) in &by_width {
        // Rows that fit neither an hour nor a day evenly are not used.
        if r.pdp_per_row == 1 || w > DAY_S || DAY_S % w != 0 {
            continue;
        }
        let pdp = u32::try_from(r.pdp_per_row).unwrap_or(u32::MAX);
        for (start, row) in r.timed_rows(d) {
            let Some((rtts, loss)) = replies(row, loss_col, &ping_cols, false) else {
                continue;
            };
            let total = f64::from(pdp) * f64::from(sent);
            let mut received = (total - f64::from(pdp) * loss).round().max(0.0) as u32;
            let mut rtts = rtts;
            if received == 0 || rtts.is_empty() {
                // All lost (a slot value left by blending is not a reply),
                // or replies without any RTT to show for them.
                received = 0;
                rtts.clear();
            }
            rows.push((
                start,
                w,
                RollupPoint {
                    ts_ms: start * 1000,
                    rounds: pdp,
                    sent: pdp.saturating_mul(u32::from(sent)),
                    received,
                    quantiles_us: quantiles(&rtts),
                    // An averaged RRD row cannot tell a down round.
                    down: None,
                },
            ));
        }
    }

    let mut rounds: Vec<StoredRound> = Vec::new();
    if let Some(raw) = by_width.get(&d.step_s).filter(|r| r.pdp_per_row == 1) {
        for (start, row) in raw.timed_rows(d) {
            if let Some((rtts, _)) = replies(row, loss_col, &ping_cols, true) {
                rounds.push(StoredRound {
                    ts_ms: start * 1000,
                    sent,
                    rtts_us: rtts,
                    errors: ErrorCounts::default(),
                    resolved: None,
                    timing: None,
                    flags: 0,
                });
            }
        }
    }
    // A day is rolled up or raw, not both: raw rounds start on their
    // first day if the raw archive covers all of it, if the coarser
    // archives have nothing that day, or if it is today (a rolled-up day
    // is closed to the live rounds that follow); else on the next day.
    let day_of = |s: i64| s.div_euclid(DAY_S);
    rows.retain(|(s, _, _)| day_of(*s) < today);
    let mut dropped = 0;
    if let Some(first) = rounds.first() {
        let first_s = first.ts_ms / 1000;
        let d0 = day_of(first_s);
        let partial = first_s > d0 * DAY_S;
        let covered = rows.iter().any(|(s, _, _)| day_of(*s) == d0);
        let raw_from = if partial && covered && d0 < today {
            d0 + 1
        } else {
            d0
        };
        let before = rounds.len();
        rounds.retain(|r| day_of(r.ts_ms / 1000) >= raw_from);
        dropped = before - rounds.len();
        rows.retain(|(s, _, _)| day_of(*s) < raw_from);
    }

    let hourly = bucket(&rows, HOUR_S);
    let daily = bucket(&rows, DAY_S);
    Ok(Converted {
        history: ImportedHistory {
            hourly,
            daily,
            rounds,
        },
        dropped_rounds: dropped,
    })
}

/// One point per `width_s` bucket, from the rows of whichever archive
/// covers most of it (the finer one on a tie). Only archives whose rows
/// fit the bucket evenly are used.
fn bucket(rows: &[(i64, i64, RollupPoint)], width_s: i64) -> Vec<RollupPoint> {
    // bucket -> row width -> rows
    let mut buckets: BTreeMap<i64, BTreeMap<i64, Vec<RollupPoint>>> = BTreeMap::new();
    for (start, w, p) in rows {
        if *w > width_s || width_s % w != 0 {
            continue;
        }
        let b = start.div_euclid(width_s) * width_s;
        buckets
            .entry(b)
            .or_default()
            .entry(*w)
            .or_default()
            .push(p.clone());
    }
    buckets
        .into_iter()
        .filter_map(|(b, by_w)| {
            // Most time covered, then the finer width.
            let (_, points) = by_w
                .iter()
                .max_by_key(|(w, ps)| (*w * ps.len() as i64, -**w))?;
            Some(RollupPoint::merge(points, b * 1000))
        })
        .collect()
}

fn date(ms: i64) -> String {
    rl_store::layout::date(ms.div_euclid(86_400_000))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_store::Tier;

    const FIXTURE: &str = include_str!("testdata/smokeping-5pings.xml");

    #[test]
    fn a_real_dump_parses() {
        let d = parse(FIXTURE).unwrap();
        assert_eq!(d.step_s, 300);
        assert_eq!(&d.ds[..3], ["uptime", "loss", "median"]);
        assert_eq!(d.ds.len(), 8);
        let shape: Vec<_> = d
            .rras
            .iter()
            .map(|r| (r.cf.as_str(), r.pdp_per_row, r.rows.len()))
            .collect();
        assert_eq!(
            shape,
            [
                ("AVERAGE", 1, 144),
                ("AVERAGE", 12, 48),
                ("MAX", 12, 48),
                ("AVERAGE", 144, 8)
            ]
        );
    }

    #[test]
    fn a_real_dump_converts() {
        let d = parse(FIXTURE).unwrap();
        let c = convert(&d, i64::MAX).unwrap();
        let h = &c.history;
        // The raw archive holds the last 12 hours, all on 2025-11-22, a
        // day the hourly archive also covers: they become hourly points.
        assert!(h.rounds.is_empty());
        assert_eq!(c.dropped_rounds, 144);
        // 48 hourly rows (2025-11-21 00:00 to 2025-11-22 23:00) ...
        assert_eq!(h.hourly.len(), 48);
        assert_eq!(
            h.hourly[0].ts_ms,
            (1_763_510_400 + 2 * DAY_S - HOUR_S) * 1000
        );
        // ... and days back to the 12-hour archive's first row.
        let days: Vec<_> = h.daily.iter().map(|p| date(p.ts_ms)).collect();
        assert_eq!(
            days,
            ["2025-11-19", "2025-11-20", "2025-11-21", "2025-11-22"]
        );
        // A day of the hourly archive merges 24 hours of 12 rounds.
        assert_eq!(h.daily[2].rounds, 24 * 12);
        assert_eq!(h.daily[2].sent, 24 * 12 * 5);
        for p in h.hourly.iter().chain(&h.daily) {
            assert!(p.received <= p.sent);
            assert_eq!(p.quantiles_us.len(), rl_store::QUANTILES);
            assert!(p.quantiles_us.is_sorted());
            // The fixture's RTTs are 6 to 60 ms.
            assert!((5_000..80_000).contains(&p.quantiles_us[10]), "{p:?}");
        }
        // Some loss was generated.
        assert!(h.hourly.iter().any(|p| p.received < p.sent));
    }

    /// The raw archive's rounds give SmokePing's own median column back:
    /// SmokePing takes the reply at rank n/2 (the upper middle one), and
    /// the RTTs survive the round trip through seconds to the microsecond.
    #[test]
    fn raw_rounds_keep_smokepings_median() {
        let mut d = parse(FIXTURE).unwrap();
        // Keep only the raw archive, so its rows become rounds.
        d.rras.retain(|r| r.pdp_per_row == 1);
        let c = convert(&d, i64::MAX).unwrap();
        let rounds = &c.history.rounds;
        assert_eq!(rounds.len(), 144);
        let rows: Vec<_> = d.rras[0].timed_rows(&d).collect();
        let mut lossy = 0;
        for (r, (start, row)) in rounds.iter().zip(rows) {
            assert_eq!(r.ts_ms, start * 1000);
            lossy += usize::from(r.loss() > 0);
            let Some(&ours) = r.rtts_us.get(r.rtts_us.len() / 2) else {
                continue;
            };
            let theirs = row[2] * 1e6;
            assert!(
                (f64::from(ours) - theirs).abs() <= 1.0,
                "{ours} vs {theirs} at {start}: {r:?}"
            );
        }
        assert!(lossy > 0);
    }

    #[test]
    fn raw_rounds_start_at_a_day_boundary_when_coarser_archives_cover_it() {
        // 2 rows per hour, raw at 30 minutes, an hourly archive.
        let dump = |raw_rows: usize| Dump {
            step_s: 1800,
            last_update_s: 10 * DAY_S,
            ds: vec!["loss".into(), "ping1".into(), "ping2".into()],
            rras: vec![
                Rra {
                    cf: "AVERAGE".into(),
                    pdp_per_row: 1,
                    rows: vec![vec![0.0, 0.01, 0.02]; raw_rows],
                },
                Rra {
                    cf: "AVERAGE".into(),
                    pdp_per_row: 2,
                    rows: vec![vec![0.5, 0.01, 0.02]; 72],
                },
            ],
        };
        // 36 raw rows: the last 18 hours, a partial day 9.
        let c = convert(&dump(36), i64::MAX).unwrap();
        assert!(c.history.rounds.is_empty());
        assert_eq!(c.history.daily.len(), 3);
        // 96 raw rows: days 8 and 9 whole; hourly points end on day 7.
        let c = convert(&dump(96), i64::MAX).unwrap();
        let h = &c.history;
        assert_eq!((h.rounds.len(), c.dropped_rounds), (96, 0));
        assert_eq!(h.rounds[0].ts_ms, 8 * DAY_S * 1000);
        assert_eq!(h.hourly.last().unwrap().ts_ms, (8 * DAY_S - HOUR_S) * 1000);
        assert_eq!(h.daily.len(), 1);
        // Half a lost ping per round, two rounds: one of four lost.
        assert_eq!((h.hourly[0].sent, h.hourly[0].received), (4, 3));
        assert_eq!(h.rounds[0].rtts_us, [10_000, 20_000]);
    }

    #[test]
    fn today_stays_open_for_live_rounds() {
        let dump = Dump {
            step_s: 1800,
            last_update_s: 10 * DAY_S,
            ds: vec!["loss".into(), "ping1".into(), "ping2".into()],
            rras: vec![
                Rra {
                    cf: "AVERAGE".into(),
                    pdp_per_row: 1,
                    rows: vec![vec![0.0, 0.01, 0.02]; 36],
                },
                Rra {
                    cf: "AVERAGE".into(),
                    pdp_per_row: 2,
                    rows: vec![vec![0.0, 0.01, 0.02]; 72],
                },
            ],
        };
        // Day 9 is today: its raw rounds are kept, nothing of it rolled up.
        let c = convert(&dump, 9).unwrap();
        let h = &c.history;
        assert_eq!((h.rounds.len(), c.dropped_rounds), (36, 0));
        assert_eq!(h.daily.len(), 2);
        assert!(h.daily.iter().all(|p| p.ts_ms < 9 * DAY_S * 1000));
    }

    #[test]
    fn archives_that_fit_no_bucket_do_not_replace_raw_rounds() {
        // 7 steps of 300 s: 2100 s rows fit neither an hour nor a day.
        let dump = Dump {
            step_s: 300,
            last_update_s: 10 * DAY_S,
            ds: vec!["loss".into(), "ping1".into()],
            rras: vec![
                Rra {
                    cf: "AVERAGE".into(),
                    pdp_per_row: 1,
                    rows: vec![vec![0.0, 0.01]; 100],
                },
                Rra {
                    cf: "AVERAGE".into(),
                    pdp_per_row: 7,
                    rows: vec![vec![0.0, 0.01]; 100],
                },
            ],
        };
        let c = convert(&dump, i64::MAX).unwrap();
        assert_eq!((c.history.rounds.len(), c.dropped_rounds), (100, 0));
        assert!(c.history.daily.is_empty());
    }

    #[test]
    fn consolidated_rows_keep_their_replies_at_high_loss() {
        // 12 rounds of 5 pings, 4.5 lost on average: 6 of 60 answered,
        // and the one known slot average is kept.
        let dump = Dump {
            step_s: 300,
            last_update_s: 10 * DAY_S,
            ds: vec![
                "loss".into(),
                "ping1".into(),
                "ping2".into(),
                "ping3".into(),
                "ping4".into(),
                "ping5".into(),
            ],
            rras: vec![Rra {
                cf: "AVERAGE".into(),
                pdp_per_row: 12,
                rows: vec![vec![4.5, f64::NAN, f64::NAN, 0.02, f64::NAN, f64::NAN]],
            }],
        };
        let c = convert(&dump, i64::MAX).unwrap();
        let p = &c.history.hourly[0];
        assert_eq!((p.sent, p.received), (60, 6));
        assert_eq!(p.quantiles_us, vec![20_000; rl_store::QUANTILES]);
        // All lost: a slot value left by blending is no reply.
        let mut all_lost = dump;
        all_lost.rras[0].rows[0][0] = 5.0;
        let c = convert(&all_lost, i64::MAX).unwrap();
        let p = &c.history.hourly[0];
        assert_eq!((p.sent, p.received, p.quantiles_us.len()), (60, 0, 0));
    }

    #[test]
    fn coverage_picks_the_archive() {
        let p = |s: i64, w: i64, rounds: u32| {
            (
                s,
                w,
                RollupPoint {
                    ts_ms: s * 1000,
                    rounds,
                    sent: rounds,
                    received: rounds,
                    quantiles_us: vec![w as u32; rl_store::QUANTILES],
                    down: None,
                },
            )
        };
        // Day 0: two 12 h rows against one hour; day 1: two hours only.
        let rows = vec![
            p(0, 43_200, 144),
            p(43_200, 43_200, 144),
            p(3_600, 3_600, 12),
            p(DAY_S, 3_600, 12),
            p(DAY_S + 3_600, 3_600, 12),
        ];
        let days = bucket(&rows, DAY_S);
        assert_eq!(days[0].rounds, 288);
        assert_eq!(days[0].quantiles_us[0], 43_200);
        assert_eq!(days[1].rounds, 24);
        assert_eq!(bucket(&rows, HOUR_S).len(), 3);
    }

    #[test]
    fn other_files_are_refused() {
        assert!(parse("not xml").unwrap_err().contains("not XML"));
        assert!(parse("<html/>").unwrap_err().contains("rrdtool dump"));
        let mut d = parse(FIXTURE).unwrap();
        d.ds[1] = "lost".into();
        assert!(
            convert(&d, i64::MAX)
                .unwrap_err()
                .contains("not a SmokePing RRD")
        );
    }

    #[test]
    fn the_command_imports_into_an_empty_series_only() {
        let dir = tempfile::tempdir().unwrap();
        let xml = dir.path().join("gw.xml");
        std::fs::write(&xml, FIXTURE).unwrap();
        let args = SmokepingArgs {
            file: xml,
            target: "gw".into(),
            config: None,
            data_dir: Some(dir.path().join("data")),
            vantage: None,
            family: "v4".into(),
        };
        let msg = import(&args).unwrap();
        assert!(
            msg.starts_with("imported local/gw/v4: 0 rounds (nothing), 48 hourly and 4 daily"),
            "{msg}"
        );
        let r = rl_store::Reader::open(&dir.path().join("data")).unwrap();
        let (_, id) = r.find("gw")[0];
        assert_eq!(r.step_ms(id), Some(300_000));
        let days = r.read_tier(id, Tier::R1d, 0, i64::MAX / 2).unwrap();
        assert_eq!(days.len(), 4);
        let (code, msg) = import(&args).unwrap_err();
        assert_eq!(code, 1);
        assert!(msg.contains("already has data"), "{msg}");
    }
}
