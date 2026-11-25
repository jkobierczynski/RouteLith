//! `routelith ctl report sla`: a month's SLA report (doc §21.5 F13) as
//! print-ready HTML or CSV, read from the store; the server may run.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use rl_core::config::{self, Config};
use rl_store::Reader;
use rl_web::sla::{self, Month, ReportSeries};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    Html,
    Csv,
}

#[derive(Debug, Args)]
pub(crate) struct SlaArgs {
    /// Configuration file, for the [[sla]] tables, targets and data
    /// directory.
    #[arg(short, long)]
    config: PathBuf,
    /// The month, as 2026-11 (UTC; default: last month).
    #[arg(long)]
    month: Option<String>,
    #[arg(long, value_enum, default_value = "html")]
    format: Format,
    /// Write here instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

pub(crate) fn run(args: &SlaArgs) -> ExitCode {
    match report(args, now_ms()) {
        Ok(Some(msg)) => {
            eprintln!("{msg}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("routelith ctl report sla: {msg}");
            ExitCode::from(code)
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The series of the configured targets measured from this vantage.
pub(crate) fn report_series(cfg: &Config, reader: &Reader) -> Vec<ReportSeries> {
    let order = |t: &str| cfg.targets.iter().position(|x| x.id == t);
    let mut out: Vec<ReportSeries> = reader
        .series()
        .iter()
        .filter(|(k, _)| k.vantage == cfg.server.vantage)
        .filter_map(|(k, id)| {
            let t = cfg.targets.iter().find(|t| t.id == k.target)?;
            Some(ReportSeries {
                id: *id,
                key: k.clone(),
                group: t.group.clone(),
                step_ms: reader
                    .step_ms(*id)
                    .unwrap_or_else(|| u64::try_from(t.schedule.step.as_millis()).unwrap_or(1)),
            })
        })
        .collect();
    // In the configuration's order, as the server lists them.
    out.sort_by(|a, b| {
        (order(&a.key.target), &a.key.family).cmp(&(order(&b.key.target), &b.key.family))
    });
    out
}

fn report(args: &SlaArgs, now: i64) -> Result<Option<String>, (u8, String)> {
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
    if cfg.slas.is_empty() {
        return Err((
            1,
            format!("{} has no [[sla]] tables", args.config.display()),
        ));
    }
    let month = match &args.month {
        Some(m) => {
            Month::parse(m).ok_or_else(|| (1, format!("month {m:?}: write it as 2026-11")))?
        }
        None => Month::of(now).previous(),
    };
    let reader = Reader::open(&cfg.server.data_dir)
        .map_err(|e| (2, format!("{}: {e}", cfg.server.data_dir.display())))?;
    let series = report_series(&cfg, &reader);
    let r = sla::build(&reader, &cfg.slas, &series, &cfg.server.vantage, month, now)
        .map_err(|e| (1, e))?;
    let body = match args.format {
        Format::Html => sla::html(&r),
        Format::Csv => sla::csv(&r),
    };
    match &args.output {
        None => {
            print!("{body}");
            Ok(None)
        }
        Some(path) => {
            std::fs::write(path, body).map_err(|e| (2, format!("{}: {e}", path.display())))?;
            Ok(Some(format!(
                "wrote the SLA report of {month} to {}{}",
                path.display(),
                if r.partial() {
                    " (the month is not over)"
                } else {
                    ""
                }
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_store::{ErrorCounts, SeriesKey, StoredRound, Writer, WriterOptions};

    /// 2026-10-01T00:00:00Z.
    const OCT: i64 = 1_790_812_800_000;

    #[test]
    fn a_report_is_written_as_html_or_csv() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let cfg = dir.path().join("routelith.toml");
        std::fs::write(
            &cfg,
            format!(
                "[server]\ndata_dir = {:?}\n\n[[group]]\nname = \"isp\"\n\
                 [[group.target]]\nname = \"uplink\"\nhost = \"192.0.2.1\"\n\n\
                 [[sla]]\nname = \"isp\"\ngroups = [\"isp\"]\navailability = \"99.5%\"\n",
                data.display().to_string()
            ),
        )
        .unwrap();
        let (mut w, _) = Writer::open(&data, WriterOptions::default(), OCT).unwrap();
        let id = w
            .register(&[SeriesKey::new("local", "uplink", "v4")])
            .unwrap()[0];
        w.set_steps(&[(id, 60_000)]).unwrap();
        for i in 0..120 {
            w.append(
                id,
                StoredRound {
                    ts_ms: OCT + i * 60_000,
                    sent: 4,
                    // One round in 60 without a reply: 98.33 %.
                    rtts_us: if i % 60 == 0 {
                        Vec::new()
                    } else {
                        vec![5000; 4]
                    },
                    errors: ErrorCounts::default(),
                    resolved: None,
                    timing: None,
                    flags: 0,
                },
            )
            .unwrap();
        }
        w.close().unwrap();

        let out = dir.path().join("oct.csv");
        let args = |format, month: &str, output: Option<PathBuf>| SlaArgs {
            config: cfg.clone(),
            month: Some(month.into()),
            format,
            output,
        };
        let now = OCT + 40 * 86_400_000;
        let msg = report(&args(Format::Csv, "2026-10", Some(out.clone())), now)
            .unwrap()
            .unwrap();
        assert!(msg.contains("2026-10"), "{msg}");
        let csv = std::fs::read_to_string(&out).unwrap();
        let line = csv.lines().nth(1).unwrap();
        assert!(line.contains(",120,"), "measured rounds: {line}");
        assert!(line.contains(",98.3333,99.5000,"), "{line}");
        assert!(line.ends_with(",missed"), "{line}");

        let out = dir.path().join("oct.html");
        report(&args(Format::Html, "2026-10", Some(out.clone())), now).unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("SLA report, October 2026")
        );

        let err = report(&args(Format::Html, "October", None), now).unwrap_err();
        assert_eq!(err.0, 1, "{}", err.1);
    }
}
