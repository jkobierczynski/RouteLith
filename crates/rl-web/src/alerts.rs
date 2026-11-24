//! `/api/v1/alerts` and `/api/v1/events` (architecture doc §12, §13.2,
//! §21.5 F1–F4), and the alert lines of `/metrics`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rl_alert::ActiveAlert;
use serde::{Deserialize, Serialize};

use crate::api::now_ms;
use crate::metrics::MetricsWriter;
use crate::silences::Silences;
use crate::{AppState, error};

const DAY_MS: i64 = 86_400_000;
const DEFAULT_EVENTS: usize = 200;
const MAX_EVENTS: usize = 5_000;

/// A rule as the API lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleInfo {
    pub name: String,
    /// `threshold` or `pattern`.
    pub kind: String,
    /// The rule in one line.
    pub summary: String,
    /// Series it applies to.
    pub series: Vec<u64>,
}

/// Alert state shared by the store thread (which evaluates rules) and the
/// HTTP side.
#[derive(Debug, Default)]
pub struct AlertBoard {
    rules: Vec<RuleInfo>,
    silences: Arc<Silences>,
    active: Mutex<Vec<ActiveAlert>>,
    raised: AtomicU64,
    cleared: AtomicU64,
}

impl AlertBoard {
    pub fn new(rules: Vec<RuleInfo>) -> Self {
        Self {
            rules,
            ..Self::default()
        }
    }

    /// Only configured silences, kept in memory.
    #[must_use]
    pub fn with_silences(self, silences: Vec<rl_core::silence::Silence>) -> Self {
        self.with_shared_silences(Arc::new(Silences::configured(silences)))
    }

    /// The silences the alert engine uses too.
    #[must_use]
    pub fn with_shared_silences(mut self, silences: Arc<Silences>) -> Self {
        self.silences = silences;
        self
    }

    pub fn silences(&self) -> &Arc<Silences> {
        &self.silences
    }

    pub fn rules(&self) -> &[RuleInfo] {
        &self.rules
    }

    /// Replace the active alerts.
    pub fn set_active(&self, active: Vec<ActiveAlert>) {
        if let Ok(mut a) = self.active.lock() {
            *a = active;
        }
    }

    /// Count a transition for `/metrics`.
    pub fn count(&self, raised: bool) {
        let c = if raised { &self.raised } else { &self.cleared };
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn active(&self) -> Vec<ActiveAlert> {
        self.active.lock().map(|a| a.clone()).unwrap_or_default()
    }
}

#[derive(Serialize)]
struct ActiveJson<'a> {
    series: u64,
    vantage: &'a str,
    target: &'a str,
    family: &'a str,
    rule: &'a str,
    /// When the degradation began, Unix milliseconds.
    since: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<f64>,
    /// Raised under this silence: logged, not sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    silenced_by: Option<&'a str>,
    /// Raised while this parent target had an alert: logged, not sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressed_by: Option<&'a str>,
}

/// Active alerts, the rules and the silences, configured and added.
pub(crate) async fn alerts(State(s): State<Arc<AppState>>) -> Response {
    let active = s.alerts.active();
    let list: Vec<ActiveJson<'_>> = active
        .iter()
        .filter_map(|a| {
            let i = s.series.iter().find(|i| i.id == a.series)?;
            Some(ActiveJson {
                series: a.series,
                vantage: &i.key.vantage,
                target: &i.key.target,
                family: &i.key.family,
                rule: &a.rule,
                since: a.since_ms,
                value: a.value.map(crate::round2),
                silenced_by: a.silenced_by.as_deref(),
                suppressed_by: a.suppressed_by.as_deref(),
            })
        })
        .collect();
    let now = now_ms();
    let store = &s.alerts.silences;
    let mut silences: Vec<serde_json::Value> = store
        .configured_list()
        .iter()
        .map(|x| crate::silences::silence_json(x, None, now))
        .collect();
    silences.extend(
        store
            .added()
            .iter()
            .map(|a| crate::silences::silence_json(&a.silence, Some(a), now)),
    );
    Json(serde_json::json!({
        "now": now,
        "active": list,
        "rules": s.alerts.rules,
        "silences": silences,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct EventQuery {
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<usize>,
    /// Only this target's events (applied before `limit`).
    target: Option<String>,
}

/// Events with `from <= t < to`, newest first, at most `limit` (default
/// 200, at most 5000), of one `target` if given. Without `from`, the 7
/// days before `to`.
pub(crate) async fn events(
    State(s): State<Arc<AppState>>,
    q: Result<Query<EventQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(q)) = q else {
        return error(
            StatusCode::BAD_REQUEST,
            "from and to must be Unix milliseconds, limit a whole number",
        );
    };
    let to = q.to.unwrap_or_else(|| now_ms() + 1);
    let from = q.from.unwrap_or(to.saturating_sub(7 * DAY_MS));
    // The event log keeps 400 days; a longer range only costs time.
    if from > to || to.saturating_sub(from) > 3_653 * DAY_MS {
        return error(
            StatusCode::BAD_REQUEST,
            "from must not be after to, and the range must be at most ten years",
        );
    }
    let limit = q.limit.unwrap_or(DEFAULT_EVENTS).clamp(1, MAX_EVENTS);
    let dir = s.data_dir.clone();
    let read = tokio::task::spawn_blocking(move || rl_store::read_events(&dir, from, to)).await;
    let mut events = match read {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    if let Some(t) = &q.target {
        events.retain(|e| e.target.as_deref() == Some(t.as_str()));
    }
    events.reverse();
    let more = events.len() > limit;
    events.truncate(limit);
    Json(serde_json::json!({
        "from": from,
        "to": to,
        "events": events,
        "truncated": more,
    }))
    .into_response()
}

/// Active alerts as gauges, and transition counters.
pub(crate) fn metrics(s: &AppState, m: &mut MetricsWriter) {
    m.family(
        "routelith_alert_active",
        "gauge",
        "1 for each alert that is raised, by series and rule.",
    );
    for a in s.alerts.active() {
        let Some(i) = s.series.iter().find(|i| i.id == a.series) else {
            continue;
        };
        m.sample(
            "routelith_alert_active",
            &[
                ("vantage", &i.key.vantage),
                ("target", &i.key.target),
                ("family", &i.key.family),
                ("rule", &a.rule),
            ],
            1.0,
        );
    }
    for (name, help, c) in [
        (
            "routelith_alerts_raised_total",
            "Alerts raised since the server started.",
            &s.alerts.raised,
        ),
        (
            "routelith_alerts_cleared_total",
            "Alerts cleared since the server started.",
            &s.alerts.cleared,
        ),
    ] {
        m.family(name, "counter", help);
        #[allow(clippy::cast_precision_loss)]
        m.sample(name, &[], c.load(Ordering::Relaxed) as f64);
    }
}
