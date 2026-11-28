//! `/api/v1/paths`: traced targets and their hop tables (architecture doc
//! §21.9 P14), with names, AS numbers and address classes (P9).

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::api::RangeQuery;
use crate::{AppState, TraceInfo, error};

/// Window of the hop table unless `from` or `range` is given.
const DEFAULT_WINDOW_MS: i64 = 10 * 60_000;
/// How long a request waits for reverse DNS names it has not seen before;
/// names still out are left empty (and are there on the next request).
const RDNS_WAIT: Duration = Duration::from_millis(1500);

#[derive(Serialize)]
struct TraceJson<'a> {
    target: &'a str,
    vantage: &'a str,
    family: &'a str,
    group: &'a str,
    host: &'a str,
    mode: &'a str,
    interval_ms: u64,
    step_s: u64,
    max_ttl: u8,
    raw_series: u64,
    /// TTL 1 first.
    hop_series: Vec<u64>,
}

fn trace_json(t: &TraceInfo) -> TraceJson<'_> {
    TraceJson {
        target: &t.target,
        vantage: &t.vantage,
        family: &t.family,
        group: &t.group,
        host: &t.host,
        mode: &t.mode,
        interval_ms: t.interval_ms,
        step_s: t.step_ms / 1000,
        max_ttl: t.max_ttl,
        raw_series: t.raw_series,
        hop_series: t.hops.iter().map(|h| h.id).collect(),
    }
}

/// `GET /api/v1/paths`: every trace.
pub(crate) async fn list(State(s): State<Arc<AppState>>) -> Response {
    let list: Vec<TraceJson<'_>> = s.traces.iter().map(trace_json).collect();
    Json(serde_json::json!({ "paths": list })).into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct PathQuery {
    vantage: Option<String>,
    /// `v4` or `v6` (default: the only one, else v4).
    family: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    /// `3h`, `30h` or `10d`, ending at `to`.
    range: Option<String>,
}

/// `GET /api/v1/paths/{target}`: the hop table over a window (default the
/// last ten minutes).
pub(crate) async fn path(
    State(s): State<Arc<AppState>>,
    target: Result<Path<String>, PathRejection>,
    q: Result<Query<PathQuery>, QueryRejection>,
) -> Response {
    let (Path(target), Query(q)) = match (target, q) {
        (Ok(t), Ok(q)) => (t, q),
        (Err(e), _) => return error(StatusCode::NOT_FOUND, e.body_text()),
        (_, Err(e)) => return error(StatusCode::BAD_REQUEST, e.body_text()),
    };
    let vantage = q.vantage.as_deref().unwrap_or(&s.vantage);
    let mine: Vec<&TraceInfo> = s
        .traces
        .iter()
        .filter(|t| t.target == target && t.vantage == vantage)
        .collect();
    let trace = match (q.family.as_deref(), mine.as_slice()) {
        (Some(f), _) => mine.iter().find(|t| t.family == f).copied(),
        (None, [only]) => Some(*only),
        (None, _) => mine.iter().find(|t| t.family == "v4").copied(),
    };
    let Some(trace) = trace.cloned() else {
        return error(
            StatusCode::NOT_FOUND,
            format!("no trace of {target:?} from vantage {vantage:?}"),
        );
    };
    let from = match (q.from, &q.range) {
        (None, None) => Some(q.to.unwrap_or_else(crate::api::now_ms) - DEFAULT_WINDOW_MS),
        (f, _) => f,
    };
    let (from, to) = match RangeQuery::new(from, q.to, q.range.clone()).resolve() {
        Ok(r) => r,
        Err(r) => return r,
    };
    let reader = Arc::clone(&s.reader);
    let dir = s.data_dir.clone();
    let hop_ids: Vec<u64> = trace.hops.iter().map(|h| h.id).collect();
    let raw = trace.raw_series;
    let read = tokio::task::spawn_blocking(move || {
        rl_path::report::read(&reader, &dir, raw, &hop_ids, from, to)
    })
    .await;
    let mut report = match read {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    if let Some(en) = &s.enricher {
        let info = en.hops(&report.addrs(), RDNS_WAIT).await;
        report.enrich(&info);
    }
    Json(serde_json::json!({
        "trace": trace_json(&trace),
        "from": report.from_ms,
        "to": report.to_ms,
        "source": report.source,
        "sweeps": report.sweeps,
        "rounds": report.rounds,
        "hops": report.hops,
    }))
    .into_response()
}
