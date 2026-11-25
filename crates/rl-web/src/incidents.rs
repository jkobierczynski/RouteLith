//! The NIS2 incident timeline (doc §21.5 F14): incidents built from the
//! event log, with the reporting deadlines of NIS2 article 23, as
//! print-ready HTML, JSON and CSV.
//!
//! An incident gathers the alerts on one target and the targets below it
//! (`parent`), from the first degradation to the last recovery; alerts
//! that start within the gap after the previous one ended join it. Its
//! deadlines run from detection, the first alert raised: the early
//! warning within 24 hours, the incident notification within 72, and the
//! final report within a month of the notification. Whether an incident
//! is significant, and so must be reported, is for people to judge; the
//! timeline gives them the facts.

use std::collections::HashMap;
use std::fmt::Write as _;

use rl_store::{Event, EventKind};
use serde::Serialize;

use crate::sla::Month;

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;
/// Alerts this close after the last one ended join its incident.
pub const DEFAULT_GAP_MS: i64 = 15 * 60_000;

/// One alert within an incident.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertSpan {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series: Option<u64>,
    pub rule: String,
    /// When the degradation began, Unix ms.
    pub start: i64,
    /// When the alert was raised.
    pub raised: i64,
    /// When it cleared; `None` while raised.
    pub cleared: Option<i64>,
    /// The values that raised and cleared it, in the rule's unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raised_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_value: Option<f64>,
    /// Worst loss (percent) and median (ms) of the series meanwhile, from
    /// the store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_loss_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_median_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silenced_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<String>,
}

/// A line of an incident's timeline.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub t: i64,
    pub kind: &'static str,
    pub message: String,
}

/// The NIS2 article 23 deadlines, Unix ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Deadlines {
    /// Early warning: 24 hours after detection.
    pub early_warning: i64,
    /// Incident notification: 72 hours after detection.
    pub notification: i64,
    /// Final report: a month after the notification is due, at the latest.
    pub final_report: i64,
}

/// One incident.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Incident {
    /// `gw-20261124T0812`.
    pub id: String,
    /// The topmost target involved.
    pub root: String,
    /// First degradation, Unix ms.
    pub start: i64,
    /// First alert raised: when it became known.
    pub detected: i64,
    /// Last recovery; `None` while an alert is raised.
    pub end: Option<i64>,
    pub targets: Vec<String>,
    /// Every alert was raised under a silence: planned work.
    pub planned: bool,
    pub deadlines: Deadlines,
    pub alerts: Vec<AlertSpan>,
    pub timeline: Vec<Entry>,
}

impl Incident {
    pub fn ongoing(&self) -> bool {
        self.end.is_none()
    }
}

/// The incidents of a period.
#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    /// `2026-11`.
    pub month: String,
    pub vantage: String,
    pub from: i64,
    pub to: i64,
    pub generated: i64,
    pub gap_ms: i64,
    pub incidents: Vec<Incident>,
}

/// The same instant a calendar month later (the last day of a shorter
/// month if the day is missing).
fn month_later(t: i64) -> i64 {
    let m = Month::of(t);
    let in_month = t - m.start_ms();
    let next = Month::of(m.end_ms());
    let len = next.end_ms() - next.start_ms();
    if in_month < len {
        next.start_ms() + in_month
    } else {
        // 31 January to 28 February, at the same time of day.
        next.end_ms() - DAY_MS + in_month.rem_euclid(DAY_MS)
    }
}

pub fn deadlines(detected: i64) -> Deadlines {
    let notification = detected + 72 * HOUR_MS;
    Deadlines {
        early_warning: detected + 24 * HOUR_MS,
        notification,
        final_report: month_later(notification),
    }
}

/// The topmost target above `t`.
fn root_of<'a>(t: &'a str, parents: &'a HashMap<String, String>) -> &'a str {
    let mut cur = t;
    // The configuration has no loops; the bound guards a broken one.
    for _ in 0..64 {
        match parents.get(cur) {
            Some(p) => cur = p,
            None => break,
        }
    }
    cur
}

/// `20261124T0812`.
fn compact(ms: i64) -> String {
    let s = crate::silences::stamp(ms);
    format!(
        "{}{}{}T{}{}",
        &s[0..4],
        &s[5..7],
        &s[8..10],
        &s[11..13],
        &s[14..16]
    )
}

/// Incidents overlapping `from..to`, from `events` (which should start
/// some weeks before `from`, so alerts raised earlier are known), oldest
/// first. `parents` maps a target to its parent; `peak` gives a series'
/// worst loss and median over a span.
pub fn build(
    events: &[Event],
    parents: &HashMap<String, String>,
    from: i64,
    to: i64,
    gap_ms: i64,
    mut peak: impl FnMut(u64, i64, i64) -> Option<(f64, Option<f64>)>,
) -> Vec<Incident> {
    // Alert spans, from raised to cleared.
    let mut open: HashMap<(Option<u64>, String, String), AlertSpan> = HashMap::new();
    let mut spans: Vec<AlertSpan> = Vec::new();
    for e in events {
        let (Some(target), Some(rule)) = (&e.target, &e.rule) else {
            continue;
        };
        let key = (e.series, target.clone(), rule.clone());
        match e.kind {
            EventKind::AlertRaised => {
                // A raise without a clear before it (a crash): the old one
                // ended unseen; keep it open-ended no longer.
                if let Some(mut old) = open.remove(&key) {
                    old.cleared = Some(e.t);
                    spans.push(old);
                }
                open.insert(
                    key,
                    AlertSpan {
                        target: target.clone(),
                        family: e.family.clone(),
                        series: e.series,
                        rule: rule.clone(),
                        start: e.since.unwrap_or(e.t).min(e.t),
                        raised: e.t,
                        cleared: None,
                        raised_value: e.value,
                        cleared_value: None,
                        peak_loss_pct: None,
                        peak_median_ms: None,
                        silenced_by: e.silenced_by.clone(),
                        suppressed_by: e.suppressed_by.clone(),
                    },
                );
            }
            EventKind::AlertCleared => {
                let mut s = open.remove(&key).unwrap_or_else(|| AlertSpan {
                    // Raised before the events read.
                    target: target.clone(),
                    family: e.family.clone(),
                    series: e.series,
                    rule: rule.clone(),
                    start: e.since.unwrap_or(e.t),
                    raised: e.since.unwrap_or(e.t),
                    cleared: None,
                    raised_value: None,
                    cleared_value: None,
                    peak_loss_pct: None,
                    peak_median_ms: None,
                    silenced_by: e.silenced_by.clone(),
                    suppressed_by: e.suppressed_by.clone(),
                });
                s.cleared = Some(e.t);
                s.cleared_value = e.value;
                spans.push(s);
            }
            _ => {}
        }
    }
    spans.extend(open.into_values());

    // By root target, merged within the gap.
    let mut by_root: HashMap<String, Vec<AlertSpan>> = HashMap::new();
    for s in spans {
        by_root
            .entry(root_of(&s.target, parents).to_string())
            .or_default()
            .push(s);
    }
    let mut incidents = Vec::new();
    for (root, mut spans) in by_root {
        spans.sort_by_key(|s| (s.start, s.raised));
        let mut groups: Vec<Vec<AlertSpan>> = Vec::new();
        let mut end: Option<i64> = None; // None: ongoing
        for s in spans {
            let joins = groups
                .last()
                .is_some_and(|_| end.is_none_or(|e| s.start <= e.saturating_add(gap_ms)));
            if joins {
                end = end.zip(s.cleared).map(|(a, b)| a.max(b));
                if let Some(g) = groups.last_mut() {
                    g.push(s);
                }
            } else {
                end = s.cleared;
                groups.push(vec![s]);
            }
        }
        for alerts in groups {
            let start = alerts.iter().map(|a| a.start).min().unwrap_or(0);
            let detected = alerts.iter().map(|a| a.raised).min().unwrap_or(start);
            let end = alerts
                .iter()
                .try_fold(i64::MIN, |m, a| a.cleared.map(|c| m.max(c)));
            if start >= to || end.is_some_and(|e| e < from) {
                continue;
            }
            incidents.push(Incident {
                id: format!("{root}-{}", compact(start)),
                root: root.clone(),
                start,
                detected,
                end,
                targets: Vec::new(),
                planned: alerts.iter().all(|a| a.silenced_by.is_some()),
                deadlines: deadlines(detected),
                alerts,
                timeline: Vec::new(),
            });
        }
    }
    incidents.sort_by_key(|i| (i.start, i.root.clone()));

    for inc in &mut incidents {
        let last = inc.end.unwrap_or(i64::MAX);
        for a in &mut inc.alerts {
            if let Some(series) = a.series {
                if let Some((loss, median)) =
                    peak(series, a.start, a.cleared.unwrap_or(last.min(to)))
                {
                    a.peak_loss_pct = Some(loss);
                    a.peak_median_ms = median;
                }
            }
        }
        let mut targets: Vec<String> = inc.alerts.iter().map(|a| a.target.clone()).collect();
        targets.sort();
        targets.dedup();
        // The timeline: the alerts, address changes of the targets, and
        // the server's own stops and starts meanwhile.
        let mut tl: Vec<Entry> = Vec::new();
        tl.push(Entry {
            t: inc.start,
            kind: "degradation_began",
            message: "first degradation (start of the round that began it)".into(),
        });
        for e in events {
            let mine = e.target.as_ref().is_some_and(|t| targets.contains(t));
            let within = e.t >= inc.start && e.t <= last;
            let keep = match e.kind {
                EventKind::AlertRaised | EventKind::AlertCleared => {
                    mine && inc.alerts.iter().any(|a| {
                        Some(&a.rule) == e.rule.as_ref()
                            && Some(&a.target) == e.target.as_ref()
                            && (e.t == a.raised || Some(e.t) == a.cleared)
                    })
                }
                EventKind::IpChanged => mine && within,
                EventKind::ServerStarted | EventKind::ServerStopped => within,
                // An agent's outage only matters to its own series' incidents;
                // the timeline is per target, so these stay out.
                EventKind::AgentEnrolled
                | EventKind::AgentConnected
                | EventKind::AgentDisconnected
                | EventKind::AgentRevoked
                | EventKind::AgentClockSkew
                | EventKind::AgentClockOk
                | EventKind::AgentRoundsLost
                | EventKind::Unknown => false,
            };
            if keep {
                tl.push(Entry {
                    t: e.t,
                    kind: e.kind.as_str(),
                    message: e.message.clone(),
                });
            }
        }
        tl.sort_by_key(|e| e.t);
        inc.targets = targets;
        inc.timeline = tl;
    }
    incidents
}

// ---------- output ----------

fn time(ms: i64) -> String {
    rl_core::silence::format_time(ms)
}

fn duration(ms: i64) -> String {
    let min = (ms.max(0) + 59_999) / 60_000;
    match (min / (24 * 60), min / 60 % 24, min % 60) {
        (0, 0, m) => format!("{m} min"),
        (0, h, m) => format!("{h} h {m} min"),
        (d, h, _) => format!("{d} d {h} h"),
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "
:root { color-scheme: light; --fg: #1a1d21; --muted: #5f6670; --line: #d6d9de; --alert: #b42318; --ok: #16794a; }
* { box-sizing: border-box; }
body { margin: 0; background: #fff; color: var(--fg); font: 13px/1.45 system-ui, -apple-system, 'Segoe UI', sans-serif; }
main { max-width: 1000px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 0 0 2px; }
p { margin: 4px 0; }
.muted { color: var(--muted); }
section.incident { margin: 24px 0 0; padding: 16px 0 0; border-top: 2px solid var(--line); break-inside: avoid-page; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 10px 0; }
dt { color: var(--muted); }
dd { margin: 0; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 0; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; white-space: nowrap; }
td.t { white-space: nowrap; }
tr { break-inside: avoid; }
.badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.badge.open { background: #fde8e6; color: var(--alert); }
.badge.closed { background: #e3f4eb; color: var(--ok); }
.badge.planned { background: #eef0f3; color: var(--muted); }
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11px; }
@page { size: A4; margin: 14mm; }
@media print { main { padding: 0; max-width: none; } }
";

fn value(v: Option<f64>) -> String {
    v.map_or_else(|| "–".into(), |v| format!("{v}"))
}

/// The timeline as one self-contained HTML page, ready to print.
pub fn html(t: &Timeline) -> String {
    let mut o = String::new();
    let title = format!("Incident timeline, {}", t.month);
    let _ = writeln!(
        o,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{0}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n<h1>{0}</h1>",
        esc(&title)
    );
    let _ = writeln!(
        o,
        "<p class=\"muted\">Measured from vantage {} · {} to {} · alerts within {} of each other are one incident · generated {}</p>",
        esc(&t.vantage),
        esc(&time(t.from)),
        esc(&time(t.to)),
        esc(&duration(t.gap_ms)),
        esc(&time(t.generated))
    );
    let open = t.incidents.iter().filter(|i| i.ongoing()).count();
    let _ = writeln!(
        o,
        "<p><b>{}</b> incident{}{}.</p>",
        t.incidents.len(),
        if t.incidents.len() == 1 { "" } else { "s" },
        if open > 0 {
            format!(", {open} still open")
        } else {
            String::new()
        }
    );
    for i in &t.incidents {
        let state = if i.planned {
            "<span class=\"badge planned\">planned (silenced)</span>"
        } else if i.ongoing() {
            "<span class=\"badge open\">ongoing</span>"
        } else {
            "<span class=\"badge closed\">recovered</span>"
        };
        let _ = writeln!(
            o,
            "<section class=\"incident\">\n<h2>{} {state}</h2>\n<dl>\
             <dt>Affected</dt><dd>{}</dd>\
             <dt>Began</dt><dd>{}</dd>\
             <dt>Detected</dt><dd>{}</dd>\
             <dt>Recovered</dt><dd>{}</dd>\
             <dt>Duration</dt><dd>{}</dd>\
             <dt>Early warning due</dt><dd>{}</dd>\
             <dt>Notification due</dt><dd>{}</dd>\
             <dt>Final report due</dt><dd>{} at the latest (a month after the notification)</dd>\
             </dl>",
            esc(&i.id),
            esc(&i.targets.join(", ")),
            esc(&time(i.start)),
            esc(&time(i.detected)),
            esc(&i.end.map_or_else(|| "not yet".into(), time)),
            esc(&duration(i.end.unwrap_or(t.generated) - i.start)),
            esc(&time(i.deadlines.early_warning)),
            esc(&time(i.deadlines.notification)),
            esc(&time(i.deadlines.final_report)),
        );
        o.push_str(
            "<table>\n<thead><tr><th>Target</th><th>Alert</th><th>Raised</th><th>Cleared</th>\
             <th class=\"num\">Value</th><th class=\"num\">Worst loss</th><th class=\"num\">Worst median</th>\
             <th>Note</th></tr></thead>\n<tbody>\n",
        );
        for a in &i.alerts {
            let note = match (&a.silenced_by, &a.suppressed_by) {
                (Some(s), _) => format!("silenced by {s}"),
                (None, Some(p)) => format!("parent {p} had an alert"),
                _ => String::new(),
            };
            let _ = writeln!(
                o,
                "<tr><td>{} <span class=\"muted\">{}</span></td><td>{}</td><td class=\"t\">{}</td>\
                 <td class=\"t\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
                esc(&a.target),
                esc(a.family.as_deref().unwrap_or("")),
                esc(&a.rule),
                esc(&time(a.raised)),
                esc(&a.cleared.map_or_else(|| "–".into(), time)),
                esc(&value(a.raised_value)),
                esc(&a
                    .peak_loss_pct
                    .map_or_else(|| "–".into(), |v| format!("{v:.1} %"))),
                esc(&a
                    .peak_median_ms
                    .map_or_else(|| "–".into(), |v| format!("{v:.1} ms"))),
                esc(&note)
            );
        }
        o.push_str("</tbody>\n</table>\n<table>\n<thead><tr><th>Time (UTC)</th><th>Event</th></tr></thead>\n<tbody>\n");
        for e in &i.timeline {
            let _ = writeln!(
                o,
                "<tr><td class=\"t\">{}</td><td>{}</td></tr>",
                esc(&time(e.t)),
                esc(&e.message)
            );
        }
        o.push_str("</tbody>\n</table>\n</section>\n");
    }
    o.push_str(
        "<footer>Times are UTC. Deadlines follow NIS2 article 23 and run from detection, the first \
         alert raised. Whether an incident is significant, and so must be reported, is for you to \
         judge. Worst loss and median are of a single round or rollup point while the alert was \
         raised. Generated by Routelith; print this page to PDF from the browser.</footer>\n\
         </main>\n</body>\n</html>\n",
    );
    o
}

/// The timeline as JSON.
pub fn json(t: &Timeline) -> String {
    serde_json::to_string_pretty(t).unwrap_or_default()
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// The timeline as CSV: one line per alert of each incident.
pub fn csv(t: &Timeline) -> String {
    let stamp = crate::silences::stamp;
    let opt = |v: Option<i64>| v.map_or_else(String::new, stamp);
    let num = |v: Option<f64>| v.map_or_else(String::new, |v| format!("{v}"));
    let mut o = String::from(
        "incident,root,incident_start,detected,incident_end,planned,early_warning_due,\
         notification_due,final_report_due,target,family,rule,alert_start,raised,cleared,\
         raised_value,cleared_value,peak_loss_pct,peak_median_ms,silenced_by,suppressed_by\n",
    );
    for i in &t.incidents {
        for a in &i.alerts {
            let fields = [
                i.id.clone(),
                i.root.clone(),
                stamp(i.start),
                stamp(i.detected),
                opt(i.end),
                i.planned.to_string(),
                stamp(i.deadlines.early_warning),
                stamp(i.deadlines.notification),
                stamp(i.deadlines.final_report),
                a.target.clone(),
                a.family.clone().unwrap_or_default(),
                a.rule.clone(),
                stamp(a.start),
                stamp(a.raised),
                opt(a.cleared),
                num(a.raised_value),
                num(a.cleared_value),
                num(a.peak_loss_pct.map(|v| (v * 100.0).round() / 100.0)),
                num(a.peak_median_ms.map(|v| (v * 1000.0).round() / 1000.0)),
                a.silenced_by.clone().unwrap_or_default(),
                a.suppressed_by.clone().unwrap_or_default(),
            ];
            let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
            o.push_str(&line.join(","));
            o.push('\n');
        }
    }
    o
}

/// Days of events read before the period, for alerts raised earlier.
pub const LOOKBACK_MS: i64 = 35 * DAY_MS;

/// Worst loss (percent) and median (ms) of `series` over `from..=to`.
pub fn peak(
    reader: &rl_store::Reader,
    series: u64,
    from: i64,
    to: i64,
) -> Option<(f64, Option<f64>)> {
    let (_, points) = reader.read_points(series, from, to, 2000).ok()?;
    let mut loss: Option<f64> = None;
    let mut median: Option<f64> = None;
    for p in &points {
        if p.sent > 0 {
            let l = 100.0 * f64::from(p.sent - p.received.min(p.sent)) / f64::from(p.sent);
            loss = Some(loss.map_or(l, |x| x.max(l)));
        }
        if !p.quantiles_us.is_empty() {
            let m = f64::from(p.quantiles_us[p.quantiles_us.len() / 2]) / 1000.0;
            median = Some(median.map_or(m, |x| x.max(m)));
        }
    }
    Some((loss?, median))
}

/// Build the timeline of `month` from the store in `data_dir`.
pub fn for_month(
    data_dir: &std::path::Path,
    reader: Option<&rl_store::Reader>,
    parents: &HashMap<String, String>,
    vantage: &str,
    month: Month,
    gap_ms: i64,
    now: i64,
) -> Result<Timeline, String> {
    let from = month.start_ms();
    if from > now {
        return Err(format!("{month} has not begun"));
    }
    let to = month.end_ms().min(now);
    // Up to now: an incident of the month may have recovered after it.
    let events = rl_store::read_events(data_dir, from - LOOKBACK_MS, now.saturating_add(1))
        .map_err(|e| format!("cannot read the event log: {e}"))?;
    let incidents = build(&events, parents, from, to, gap_ms, |s, a, b| {
        reader.and_then(|r| peak(r, s, a, b))
    });
    Ok(Timeline {
        month: month.to_string(),
        vantage: vantage.to_string(),
        from,
        to,
        generated: now,
        gap_ms,
        incidents,
    })
}

// ---------- HTTP ----------

#[derive(Debug, serde::Deserialize)]
pub(crate) struct Query {
    month: Option<String>,
    format: Option<String>,
    /// Minutes.
    gap: Option<u32>,
}

/// `GET /api/v1/reports/incidents?month=2026-11&format=html|json|csv`:
/// this month unless given.
pub(crate) async fn handler(
    axum::extract::State(s): axum::extract::State<std::sync::Arc<crate::AppState>>,
    q: Result<axum::extract::Query<Query>, axum::extract::rejection::QueryRejection>,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    let Ok(axum::extract::Query(q)) = q else {
        return crate::error(
            StatusCode::BAD_REQUEST,
            "use ?month=2026-11&format=html, json or csv&gap=15 (minutes)",
        );
    };
    let now = crate::api::now_ms();
    let month = match q.month.as_deref() {
        None => Month::of(now),
        Some(m) => match Month::parse(m) {
            Some(m) => m,
            None => return crate::error(StatusCode::BAD_REQUEST, "month: write it as 2026-11"),
        },
    };
    let format = q.format.unwrap_or_else(|| "html".into());
    if !matches!(format.as_str(), "html" | "json" | "csv") {
        return crate::error(StatusCode::BAD_REQUEST, "format: html, json or csv");
    }
    let gap_ms = match q.gap {
        None => DEFAULT_GAP_MS,
        Some(m) if m <= 24 * 60 => i64::from(m) * 60_000,
        Some(_) => return crate::error(StatusCode::BAD_REQUEST, "gap: at most 1440 minutes"),
    };
    let state = s.clone();
    let built = tokio::task::spawn_blocking(move || {
        for_month(
            &state.data_dir,
            Some(&state.reader),
            &state.parents,
            &state.vantage,
            month,
            gap_ms,
            now,
        )
    })
    .await;
    let t = match built {
        Ok(Ok(t)) => t,
        Ok(Err(e)) if e.ends_with("has not begun") => {
            return crate::error(StatusCode::BAD_REQUEST, e);
        }
        Ok(Err(e)) => return crate::error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => return crate::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let name = format!("routelith-incidents-{month}");
    let (kind, body, attach) = match format.as_str() {
        "json" => ("application/json", json(&t), Some(format!("{name}.json"))),
        "csv" => (
            "text/csv; charset=utf-8",
            csv(&t),
            Some(format!("{name}.csv")),
        ),
        _ => ("text/html; charset=utf-8", html(&t), None),
    };
    let mut resp = (
        [
            (header::CONTENT_TYPE, kind.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'".to_string(),
            ),
        ],
        body,
    )
        .into_response();
    if let Some(file) = attach {
        if let Ok(v) = header::HeaderValue::from_str(&format!("attachment; filename=\"{file}\"")) {
            resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
        }
    }
    resp
}
