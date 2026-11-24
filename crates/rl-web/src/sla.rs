//! SLA reports (doc §21.5 F13): for one calendar month (UTC), each
//! target's availability, loss and latency against its `[[sla]]` tables,
//! as print-ready HTML (the browser prints it to PDF) and as CSV.
//!
//! The numbers come from the hourly tier, which is kept for 400 days:
//!
//! - **availability** is the share of measured rounds that got at least
//!   one reply. Hours stored before rounds without a reply were counted
//!   are counted again from the raw rounds while those are kept (30 days);
//!   after that, such an hour counts as down only if nothing came back,
//!   and the report says how many hours were estimated so.
//! - **loss** is lost pings over sent pings.
//! - **latency** is a percentile of every reply in the month, taken from
//!   the hourly quantiles, each hour weighted by its replies.
//! - **coverage** is measured rounds over the rounds the step would give;
//!   time the server was not measuring counts neither for nor against.

use std::fmt::Write as _;

use rl_core::config::Sla;
use rl_store::{Reader, RollupPoint, SeriesKey, Tier};

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// A calendar month, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Month {
    pub year: i32,
    /// 1 to 12.
    pub month: u32,
}

impl Month {
    /// `2026-11`.
    pub fn parse(s: &str) -> Option<Month> {
        let (y, m) = s.trim().split_once('-')?;
        if y.len() != 4 || m.len() != 2 {
            return None;
        }
        let year: i32 = y.parse().ok()?;
        let month: u32 = m.parse().ok()?;
        ((1970..=9999).contains(&year) && (1..=12).contains(&month))
            .then_some(Month { year, month })
    }

    /// The month `t_ms` falls in.
    pub fn of(t_ms: i64) -> Month {
        let (y, m, _) = rl_core::silence::civil_from_days(t_ms.div_euclid(DAY_MS));
        Month {
            year: i32::try_from(y).unwrap_or(1970),
            month: u32::try_from(m).unwrap_or(1),
        }
    }

    /// The month before.
    pub fn previous(self) -> Month {
        if self.month == 1 {
            Month {
                year: self.year - 1,
                month: 12,
            }
        } else {
            Month {
                year: self.year,
                month: self.month - 1,
            }
        }
    }

    fn next(self) -> Month {
        if self.month == 12 {
            Month {
                year: self.year + 1,
                month: 1,
            }
        } else {
            Month {
                year: self.year,
                month: self.month + 1,
            }
        }
    }

    /// First millisecond, Unix.
    pub fn start_ms(self) -> i64 {
        days_from_civil(i64::from(self.year), i64::from(self.month)) * DAY_MS
    }

    /// First millisecond of the next month.
    pub fn end_ms(self) -> i64 {
        self.next().start_ms()
    }

    /// `November 2026`.
    pub fn title(self) -> String {
        const NAMES: [&str; 12] = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];
        format!("{} {}", NAMES[(self.month - 1) as usize], self.year)
    }
}

impl std::fmt::Display for Month {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}", self.year, self.month)
    }
}

/// Days since 1970-01-01 of the first of a month.
fn days_from_civil(y: i64, m: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A series the report may cover.
#[derive(Debug, Clone)]
pub struct ReportSeries {
    pub id: u64,
    pub key: SeriesKey,
    pub group: String,
    pub step_ms: u64,
}

/// One target (family) against one SLA.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub target: String,
    pub family: String,
    pub group: String,
    pub step_ms: u64,
    /// Rounds the step gives in the period.
    pub expected: u64,
    /// Rounds measured.
    pub rounds: u64,
    /// Measured rounds without any reply.
    pub down: u64,
    /// Hours whose `down` was estimated (see the module notes).
    pub estimated_hours: u32,
    pub sent: u64,
    pub received: u64,
    /// At the SLA's percentile.
    pub latency_us: Option<u32>,
    pub median_us: Option<u32>,
}

impl Row {
    pub fn coverage(&self) -> Option<f64> {
        (self.expected > 0).then(|| 100.0 * self.rounds as f64 / self.expected as f64)
    }

    pub fn availability(&self) -> Option<f64> {
        (self.rounds > 0).then(|| 100.0 * (self.rounds - self.down) as f64 / self.rounds as f64)
    }

    pub fn loss(&self) -> Option<f64> {
        (self.sent > 0)
            .then(|| 100.0 * (self.sent - self.received.min(self.sent)) as f64 / self.sent as f64)
    }

    /// Time without any reply, from the rounds.
    pub fn downtime_ms(&self) -> u64 {
        self.down.saturating_mul(self.step_ms)
    }
}

/// Whether a row meets one goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Met,
    Missed,
    /// Nothing measured.
    NoData,
}

/// The rows of one SLA.
#[derive(Debug, Clone)]
pub struct Section {
    pub sla: Sla,
    pub rows: Vec<Row>,
}

impl Section {
    pub fn availability(&self, r: &Row) -> Option<Verdict> {
        let goal = self.sla.availability?;
        Some(
            r.availability()
                .map_or(Verdict::NoData, |v| verdict(v >= goal - 1e-9)),
        )
    }

    pub fn loss(&self, r: &Row) -> Option<Verdict> {
        let goal = self.sla.loss?;
        Some(
            r.loss()
                .map_or(Verdict::NoData, |v| verdict(v <= goal + 1e-9)),
        )
    }

    pub fn latency(&self, r: &Row) -> Option<Verdict> {
        let goal = self.sla.latency_us?;
        Some(r.latency_us.map_or(Verdict::NoData, |v| verdict(v <= goal)))
    }

    /// All goals together: missed if any is, no data if any has none.
    pub fn overall(&self, r: &Row) -> Verdict {
        let all = [self.availability(r), self.loss(r), self.latency(r)];
        if all.contains(&Some(Verdict::Missed)) {
            Verdict::Missed
        } else if all.contains(&Some(Verdict::NoData)) {
            Verdict::NoData
        } else {
            Verdict::Met
        }
    }
}

fn verdict(ok: bool) -> Verdict {
    if ok { Verdict::Met } else { Verdict::Missed }
}

/// A month's report.
#[derive(Debug, Clone)]
pub struct Report {
    pub month: Month,
    pub vantage: String,
    /// Unix ms.
    pub generated_ms: i64,
    /// The end of what it covers: the month's end, or now while it lasts.
    pub until_ms: i64,
    pub sections: Vec<Section>,
}

impl Report {
    /// Whether the month is not over yet.
    pub fn partial(&self) -> bool {
        self.until_ms < self.month.end_ms()
    }
}

/// Build the report of `month` for every SLA, from the hourly tier.
pub fn build(
    reader: &Reader,
    slas: &[Sla],
    series: &[ReportSeries],
    vantage: &str,
    month: Month,
    now_ms: i64,
) -> Result<Report, String> {
    let from = month.start_ms();
    if from > now_ms {
        return Err(format!("{month} has not begun"));
    }
    let until = month.end_ms().min(now_ms);
    let mut rows_of: std::collections::HashMap<u64, (Row, Vec<RollupPoint>)> =
        std::collections::HashMap::new();
    let mut sections = Vec::new();
    for sla in slas {
        let mut rows = Vec::new();
        for s in series
            .iter()
            .filter(|s| sla.covers(&s.key.target, &s.group))
        {
            if let std::collections::hash_map::Entry::Vacant(e) = rows_of.entry(s.id) {
                e.insert(series_row(reader, s, from, until)?);
            }
            let (row, points) = &rows_of[&s.id];
            let mut row = row.clone();
            row.latency_us = percentile(points, f64::from(sla.percentile) / 100.0);
            rows.push(row);
        }
        sections.push(Section {
            sla: sla.clone(),
            rows,
        });
    }
    Ok(Report {
        month,
        vantage: vantage.to_string(),
        generated_ms: now_ms,
        until_ms: until,
        sections,
    })
}

/// A series' counts over `from..until`, and its hourly points.
fn series_row(
    reader: &Reader,
    s: &ReportSeries,
    from: i64,
    until: i64,
) -> Result<(Row, Vec<RollupPoint>), String> {
    let err = |e: rl_store::StoreError| format!("{}: {e}", s.key);
    let mut points = reader
        .read_tier(s.id, Tier::R1h, from, until - 1)
        .map_err(err)?;
    points.retain(|p| p.ts_ms >= from && p.ts_ms < until);
    // Hours stored before `down` was counted: count them again from the
    // raw rounds, where those are still kept and whole.
    if let (Some(first), Some(last)) = (
        points.iter().find(|p| p.down.is_none()),
        points.iter().rev().find(|p| p.down.is_none()),
    ) {
        let rounds = reader
            .read(s.id, first.ts_ms, last.ts_ms + HOUR_MS - 1)
            .map_err(err)?;
        let rebuilt = RollupPoint::build(&rounds, HOUR_MS);
        for p in points.iter_mut().filter(|p| p.down.is_none()) {
            if let Some(r) = rebuilt
                .iter()
                .find(|r| r.ts_ms == p.ts_ms && r.rounds == p.rounds)
            {
                p.down = r.down;
            }
        }
    }
    let step = s.step_ms.max(1);
    let mut row = Row {
        target: s.key.target.clone(),
        family: s.key.family.clone(),
        group: s.group.clone(),
        step_ms: step,
        expected: u64::try_from((until - from).max(0)).unwrap_or(0) / step,
        rounds: 0,
        down: 0,
        estimated_hours: 0,
        sent: 0,
        received: 0,
        latency_us: None,
        median_us: percentile(&points, 0.5),
    };
    for p in &points {
        row.rounds += u64::from(p.rounds);
        row.sent += u64::from(p.sent);
        row.received += u64::from(p.received.min(p.sent));
        row.down += u64::from(match p.down {
            Some(d) => d,
            None => {
                row.estimated_hours += 1;
                if p.received == 0 { p.rounds } else { 0 }
            }
        });
    }
    Ok((row, points))
}

/// The value at fraction `f` (0 to 1) of all replies, from the points'
/// quantiles, each standing for an equal share of its point's replies.
pub fn percentile(points: &[RollupPoint], f: f64) -> Option<u32> {
    let mut weighted: Vec<(u32, f64)> = Vec::new();
    for p in points {
        if !p.quantiles_us.is_empty() && p.received > 0 {
            let w = f64::from(p.received) / p.quantiles_us.len() as f64;
            weighted.extend(p.quantiles_us.iter().map(|&q| (q, w)));
        }
    }
    if weighted.is_empty() {
        return None;
    }
    weighted.sort_unstable_by_key(|&(q, _)| q);
    let total: f64 = weighted.iter().map(|&(_, w)| w).sum();
    let at = total * f.clamp(0.0, 1.0);
    let mut cum = 0.0;
    for &(q, w) in &weighted {
        cum += w;
        if cum >= at - 1e-9 {
            return Some(q);
        }
    }
    weighted.last().map(|&(q, _)| q)
}

// ---------- output ----------

fn pct(v: Option<f64>, digits: usize) -> String {
    v.map_or_else(|| "–".to_string(), |v| format!("{v:.digits$} %"))
}

fn ms(us: Option<u32>) -> String {
    us.map_or_else(
        || "–".to_string(),
        |us| {
            let ms = f64::from(us) / 1000.0;
            if ms < 10.0 {
                format!("{ms:.2} ms")
            } else if ms < 100.0 {
                format!("{ms:.1} ms")
            } else {
                format!("{ms:.0} ms")
            }
        },
    )
}

/// `3 h 20 min`, `45 min`, `0 min`.
fn span(ms: u64) -> String {
    let min = ms.div_ceil(60_000);
    match (min / 60, min % 60) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// A goal in words.
fn goals(sla: &Sla) -> String {
    let mut g = Vec::new();
    if let Some(a) = sla.availability {
        g.push(format!("availability ≥ {a} %"));
    }
    if let Some(l) = sla.loss {
        g.push(format!("loss ≤ {l} %"));
    }
    if let Some(us) = sla.latency_us {
        g.push(format!("p{} latency ≤ {}", sla.percentile, ms(Some(us))));
    }
    g.join(", ")
}

fn scope(sla: &Sla) -> String {
    let mut s = Vec::new();
    if !sla.groups.is_empty() {
        s.push(format!("groups {}", sla.groups.join(", ")));
    }
    if !sla.targets.is_empty() {
        s.push(format!("targets {}", sla.targets.join(", ")));
    }
    if s.is_empty() {
        "every target".to_string()
    } else {
        s.join("; ")
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

fn verdict_html(v: Option<Verdict>, text: String) -> String {
    match v {
        Some(Verdict::Met) => format!("<td class=\"num met\">{}</td>", esc(&text)),
        Some(Verdict::Missed) => format!("<td class=\"num missed\">{} ✗</td>", esc(&text)),
        _ => format!("<td class=\"num\">{}</td>", esc(&text)),
    }
}

const STYLE: &str = "
:root { color-scheme: light; --fg: #1a1d21; --muted: #5f6670; --line: #d6d9de; --met: #16794a; --missed: #b42318; }
* { box-sizing: border-box; }
body { margin: 0; background: #fff; color: var(--fg); font: 13px/1.45 system-ui, -apple-system, 'Segoe UI', sans-serif; }
main { max-width: 1000px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 28px 0 2px; break-after: avoid; }
p { margin: 4px 0; }
.muted { color: var(--muted); }
.summary { margin: 16px 0 0; display: flex; gap: 24px; flex-wrap: wrap; }
.summary b { font-size: 18px; display: block; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 0; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; white-space: nowrap; }
tr { break-inside: avoid; }
.met { color: var(--met); }
.missed { color: var(--missed); font-weight: 600; }
.badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.badge.met { background: #e3f4eb; }
.badge.missed { background: #fde8e6; }
.badge.none { background: #eef0f3; color: var(--muted); }
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11px; }
footer ul { margin: 4px 0; padding-left: 18px; }
@page { size: A4 landscape; margin: 14mm; }
@media print { main { padding: 0; max-width: none; } }
";

/// The report as one self-contained HTML page, ready to print.
pub fn html(r: &Report) -> String {
    let mut o = String::new();
    let title = format!("SLA report, {}", r.month.title());
    let _ = write!(
        o,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n<h1>{}</h1>\n",
        esc(&title),
        esc(&title)
    );
    let until = if r.partial() {
        format!(
            "{} to {} UTC (the month is not over)",
            rl_core::silence::format_time(r.month.start_ms()).trim_end_matches(" UTC"),
            rl_core::silence::format_time(r.until_ms).trim_end_matches(" UTC")
        )
    } else {
        format!("{} UTC, the whole month", r.month)
    };
    let _ = writeln!(
        o,
        "<p class=\"muted\">Measured from vantage {} · {} · generated {}</p>",
        esc(&r.vantage),
        esc(&until),
        esc(&rl_core::silence::format_time(r.generated_ms))
    );
    let all: Vec<(&Section, &Row)> = r
        .sections
        .iter()
        .flat_map(|s| s.rows.iter().map(move |row| (s, row)))
        .collect();
    let count = |v: Verdict| all.iter().filter(|(s, row)| s.overall(row) == v).count();
    let _ = writeln!(
        o,
        "<div class=\"summary\"><div><b>{}</b>SLA{}</div><div><b class=\"met\">{}</b>targets met</div>\
         <div><b class=\"missed\">{}</b>missed</div><div><b>{}</b>without data</div></div>",
        r.sections.len(),
        if r.sections.len() == 1 { "" } else { "s" },
        count(Verdict::Met),
        count(Verdict::Missed),
        count(Verdict::NoData)
    );
    if r.sections.is_empty() {
        o.push_str("<p>No <code>[[sla]]</code> tables are configured.</p>\n");
    }
    for s in &r.sections {
        let _ = write!(
            o,
            "<h2>{}</h2>\n<p class=\"muted\">{} · {}</p>\n",
            esc(&s.sla.name),
            esc(&scope(&s.sla)),
            esc(&goals(&s.sla))
        );
        if s.rows.is_empty() {
            o.push_str("<p>No targets measured from this vantage.</p>\n");
            continue;
        }
        let p = s.sla.percentile;
        let _ = write!(
            o,
            "<table>\n<thead><tr><th>Target</th><th>Group</th><th class=\"num\">Measured</th>\
             <th class=\"num\">Availability</th><th class=\"num\">Without reply</th>\
             <th class=\"num\">Loss</th><th class=\"num\">p{p}</th><th class=\"num\">Median</th>\
             <th>Result</th></tr></thead>\n<tbody>\n"
        );
        for row in &s.rows {
            let result = match s.overall(row) {
                Verdict::Met => "<span class=\"badge met\">met</span>",
                Verdict::Missed => "<span class=\"badge missed\">missed</span>",
                Verdict::NoData => "<span class=\"badge none\">no data</span>",
            };
            let est = if row.estimated_hours > 0 {
                format!(
                    " <span class=\"muted\" title=\"hours stored before rounds without a reply were counted\">({} h estimated)</span>",
                    row.estimated_hours
                )
            } else {
                String::new()
            };
            let _ = writeln!(
                o,
                "<tr><td>{} <span class=\"muted\">{}</span></td><td>{}</td><td class=\"num\">{}</td>{}\
                 <td class=\"num\">{}{}</td>{}{}<td class=\"num\">{}</td><td>{}</td></tr>",
                esc(&row.target),
                esc(&row.family),
                esc(&row.group),
                pct(row.coverage(), 1),
                verdict_html(s.availability(row), pct(row.availability(), 3)),
                esc(&span(row.downtime_ms())),
                est,
                verdict_html(s.loss(row), pct(row.loss(), 2)),
                verdict_html(s.latency(row), ms(row.latency_us)),
                ms(row.median_us),
                result
            );
        }
        o.push_str("</tbody>\n</table>\n");
    }
    o.push_str(
        "<footer><p>How the numbers are made:</p><ul>\
         <li><b>Measured</b>: rounds measured over the rounds the target's step gives in the period; \
         time the server was not measuring counts neither for nor against a target.</li>\
         <li><b>Availability</b>: measured rounds that got at least one reply. \
         <b>Without reply</b>: those that got none, times the step.</li>\
         <li><b>Loss</b>: lost pings over sent pings. \
         <b>Latency</b>: percentiles of every reply in the period, from hourly quantiles.</li>\
         <li>Months and times are UTC. Generated by Routelith; print this page to PDF from the browser.</li>\
         </ul></footer>\n</main>\n</body>\n</html>\n",
    );
    o
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn num(v: Option<f64>, digits: usize) -> String {
    v.map_or_else(String::new, |v| format!("{v:.digits$}"))
}

fn ms_num(us: Option<u32>) -> String {
    us.map_or_else(String::new, |us| format!("{:.3}", f64::from(us) / 1000.0))
}

/// The report as CSV: one line per SLA and target.
pub fn csv(r: &Report) -> String {
    let mut o = String::from(
        "month,sla,target,family,group,period_start,period_end,step_s,expected_rounds,\
         measured_rounds,coverage_pct,rounds_without_reply,downtime_min,availability_pct,\
         availability_goal_pct,loss_pct,loss_goal_pct,percentile,latency_ms,latency_goal_ms,\
         median_ms,estimated_hours,result\n",
    );
    for s in &r.sections {
        for row in &s.rows {
            let result = match s.overall(row) {
                Verdict::Met => "met",
                Verdict::Missed => "missed",
                Verdict::NoData => "no data",
            };
            let fields = [
                r.month.to_string(),
                s.sla.name.clone(),
                row.target.clone(),
                row.family.clone(),
                row.group.clone(),
                crate::silences::stamp(r.month.start_ms()),
                crate::silences::stamp(r.until_ms),
                (row.step_ms / 1000).to_string(),
                row.expected.to_string(),
                row.rounds.to_string(),
                num(row.coverage(), 2),
                row.down.to_string(),
                row.downtime_ms().div_ceil(60_000).to_string(),
                num(row.availability(), 4),
                num(s.sla.availability, 4),
                num(row.loss(), 4),
                num(s.sla.loss, 4),
                s.sla.percentile.to_string(),
                ms_num(row.latency_us),
                ms_num(s.sla.latency_us),
                ms_num(row.median_us),
                row.estimated_hours.to_string(),
                result.to_string(),
            ];
            let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
            o.push_str(&line.join(","));
            o.push('\n');
        }
    }
    o
}

// ---------- HTTP ----------

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ReportQuery {
    month: Option<String>,
    format: Option<String>,
}

/// `GET /api/v1/reports/sla?month=2026-11&format=html|csv`: last month
/// unless given.
pub(crate) async fn handler(
    axum::extract::State(s): axum::extract::State<std::sync::Arc<crate::AppState>>,
    q: Result<axum::extract::Query<ReportQuery>, axum::extract::rejection::QueryRejection>,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    let Ok(axum::extract::Query(q)) = q else {
        return crate::error(
            StatusCode::BAD_REQUEST,
            "use ?month=2026-11&format=html or csv",
        );
    };
    let now = crate::api::now_ms();
    let month = match q.month.as_deref() {
        None => Month::of(now).previous(),
        Some(m) => match Month::parse(m) {
            Some(m) => m,
            None => return crate::error(StatusCode::BAD_REQUEST, "month: write it as 2026-11"),
        },
    };
    let csv_wanted = match q.format.as_deref() {
        None | Some("html") => false,
        Some("csv") => true,
        Some(_) => return crate::error(StatusCode::BAD_REQUEST, "format: html or csv"),
    };
    if s.slas.is_empty() {
        return crate::error(StatusCode::NOT_FOUND, "no [[sla]] tables are configured");
    }
    let series: Vec<ReportSeries> = s
        .series
        .iter()
        .map(|i| ReportSeries {
            id: i.id,
            key: i.key.clone(),
            group: i.group.clone(),
            step_ms: i.step_ms,
        })
        .collect();
    let state = s.clone();
    let built = tokio::task::spawn_blocking(move || {
        build(
            &state.reader,
            &state.slas,
            &series,
            &state.vantage,
            month,
            now,
        )
    })
    .await;
    let r = match built {
        Ok(Ok(r)) => r,
        Ok(Err(e)) if e.ends_with("has not begun") => {
            return crate::error(StatusCode::BAD_REQUEST, e);
        }
        Ok(Err(e)) => return crate::error(StatusCode::INTERNAL_SERVER_ERROR, e),
        Err(e) => return crate::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    if csv_wanted {
        (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"routelith-sla-{month}.csv\""),
                ),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            csv(&r),
        )
            .into_response()
    } else {
        (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
                        .to_string(),
                ),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            html(&r),
        )
            .into_response()
    }
}
