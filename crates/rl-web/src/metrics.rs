//! Prometheus `/metrics` in the text exposition format (architecture doc
//! §11.1), written by hand: a handful of gauges per series, refreshed each
//! round, do not need a metrics library.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::{AppState, SeriesInfo};

/// Builds an exposition: one `# HELP`/`# TYPE` block per metric family.
#[derive(Debug, Default)]
pub struct MetricsWriter {
    out: String,
}

impl MetricsWriter {
    /// Start a metric family. `kind` is `gauge` or `counter`.
    pub fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.out, "# HELP {name} {}", escape_help(help));
        let _ = writeln!(self.out, "# TYPE {name} {kind}");
    }

    /// One sample of the current family.
    pub fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{k}=\"{}\"", escape_label(v));
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {}", format_value(value));
    }

    pub fn finish(self) -> String {
        self.out
    }
}

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_help(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\n', "\\n")
}

fn format_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf" } else { "-Inf" }.into()
    } else {
        format!("{v}")
    }
}

fn secs(us: u32) -> f64 {
    f64::from(us) / 1e6
}

pub(crate) async fn handler(State(s): State<Arc<AppState>>) -> Response {
    let body = render(&s);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub(crate) fn render(s: &AppState) -> String {
    let latest = s.latest.snapshot();
    let mut m = MetricsWriter::default();
    // Series in id order, so the output is stable.
    let mut series: Vec<&SeriesInfo> = s.series.iter().collect();
    series.sort_by_key(|i| i.id);
    let rows: Vec<(&SeriesInfo, &crate::LatestRound)> = series
        .iter()
        .filter_map(|i| latest.get(&i.id).map(|l| (*i, l)))
        .collect();
    let labels = |i: &SeriesInfo| -> [(String, String); 5] {
        [
            ("vantage".into(), i.key.vantage.clone()),
            ("target".into(), i.key.target.clone()),
            ("family".into(), i.key.family.clone()),
            ("probe".into(), i.probe.clone()),
            ("group".into(), i.group.clone()),
        ]
    };
    let emit =
        |m: &mut MetricsWriter, name: &str, i: &SeriesInfo, extra: Option<(&str, &str)>, v: f64| {
            let l = labels(i);
            let mut refs: Vec<(&str, &str)> =
                l.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            if let Some(e) = extra {
                refs.push(e);
            }
            m.sample(name, &refs, v);
        };

    m.family(
        "routelith_build_info",
        "gauge",
        "Routelith version (the value is always 1).",
    );
    m.sample(
        "routelith_build_info",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("vantage", &s.vantage),
        ],
        1.0,
    );
    m.family(
        "routelith_uptime_seconds",
        "gauge",
        "Seconds since the server started.",
    );
    m.sample(
        "routelith_uptime_seconds",
        &[],
        s.started.elapsed().as_secs_f64(),
    );

    m.family(
        "routelith_round_timestamp_seconds",
        "gauge",
        "Start of the newest round, Unix seconds.",
    );
    for (i, l) in &rows {
        #[allow(clippy::cast_precision_loss)]
        emit(
            &mut m,
            "routelith_round_timestamp_seconds",
            i,
            None,
            l.ts_ms as f64 / 1000.0,
        );
    }
    m.family(
        "routelith_rtt_seconds",
        "gauge",
        "Round-trip time (or the probe's selected time) of the newest round, by statistic.",
    );
    for (i, l) in &rows {
        for (stat, v) in [
            ("min", l.min_us),
            ("median", l.median_us),
            ("p90", l.p90_us),
            ("max", l.max_us),
        ] {
            if let Some(v) = v {
                emit(
                    &mut m,
                    "routelith_rtt_seconds",
                    i,
                    Some(("stat", stat)),
                    secs(v),
                );
            }
        }
    }
    m.family(
        "routelith_loss_ratio",
        "gauge",
        "Fraction of the newest round's samples without an answer (errors included).",
    );
    for (i, l) in &rows {
        let loss = if l.sent == 0 {
            0.0
        } else {
            f64::from(l.sent - l.received.min(l.sent)) / f64::from(l.sent)
        };
        emit(&mut m, "routelith_loss_ratio", i, None, loss);
    }
    m.family(
        "routelith_round_samples",
        "gauge",
        "Samples of the newest round, by outcome (sent, received, error).",
    );
    for (i, l) in &rows {
        for (what, v) in [
            ("sent", l.sent),
            ("received", l.received),
            ("error", l.errors),
        ] {
            emit(
                &mut m,
                "routelith_round_samples",
                i,
                Some(("outcome", what)),
                f64::from(v),
            );
        }
    }
    m.family(
        "routelith_http_phase_seconds",
        "gauge",
        "Median time of each HTTP phase in the newest round (ttfb and total from the start of connect).",
    );
    for (i, l) in &rows {
        if let Some(p) = l.http_phases_us {
            for (phase, v) in [
                ("connect", p.connect),
                ("tls", p.tls),
                ("ttfb", p.ttfb),
                ("total", p.total),
            ] {
                if let Some(v) = v {
                    emit(
                        &mut m,
                        "routelith_http_phase_seconds",
                        i,
                        Some(("phase", phase)),
                        secs(v),
                    );
                }
            }
        }
    }
    m.family(
        "routelith_tls_cert_expiry_timestamp_seconds",
        "gauge",
        "Expiry (notAfter) of the server certificate an HTTPS target presented, Unix seconds.",
    );
    for (i, l) in &rows {
        if let Some(t) = l.cert_not_after_s {
            #[allow(clippy::cast_precision_loss)]
            emit(
                &mut m,
                "routelith_tls_cert_expiry_timestamp_seconds",
                i,
                None,
                t as f64,
            );
        }
    }
    m.family(
        "routelith_mos_score",
        "gauge",
        "Estimated voice quality (ITU-T G.107 E-model, G.711) of the newest round, 1 to 4.5.",
    );
    for (i, l) in &rows {
        if let Some(mos) = crate::latest_mos(l) {
            emit(
                &mut m,
                "routelith_mos_score",
                i,
                None,
                (mos * 100.0).round() / 100.0,
            );
        }
    }
    if let Some(h) = s.host.get() {
        crate::host::metrics(&mut m, &s.vantage, &h);
    }
    crate::alerts::metrics(s, &mut m);
    if let Some(extra) = &s.extra_metrics {
        extra(&mut m);
    }
    m.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_escaped() {
        let mut m = MetricsWriter::default();
        m.family("x", "gauge", "Help with a \\ and\nnewline.");
        m.sample("x", &[("a", "q\"u\\o\nte")], 1.5);
        assert_eq!(
            m.finish(),
            "# HELP x Help with a \\\\ and\\nnewline.\n# TYPE x gauge\nx{a=\"q\\\"u\\\\o\\nte\"} 1.5\n"
        );
    }

    #[test]
    fn special_values() {
        assert_eq!(format_value(f64::NAN), "NaN");
        assert_eq!(format_value(f64::INFINITY), "+Inf");
        assert_eq!(format_value(3.0), "3");
    }
}
