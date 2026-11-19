//! `/api/v1` and `/healthz` (architecture doc §13.2).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use rl_render::{Graph, Round};
use rl_store::{Resolution, Tier};
use serde::{Deserialize, Serialize};

use crate::{AppState, error};

const HOUR_MS: i64 = 3_600_000;
/// Longest range one request may ask for (the r1d retention).
const MAX_SPAN_MS: i64 = 3653 * 24 * HOUR_MS;
/// Times the store can hold: 0000-01-01T00:00:00Z to 9999-12-31T23:59:59.999Z.
const MIN_MS: i64 = -62_167_219_200_000;
const MAX_MS: i64 = 253_402_300_799_999;
const DEFAULT_POINTS: u32 = 800;
const MAX_POINTS: u32 = 5000;

pub(crate) async fn health(State(s): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({
        "status": "ok",
        "vantage": s.vantage,
        "series": s.series.len(),
        "uptime_s": s.started.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

pub(crate) async fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "no such endpoint")
}

#[derive(Serialize)]
struct SeriesJson<'a> {
    id: u64,
    vantage: &'a str,
    target: &'a str,
    family: &'a str,
    group: &'a str,
    probe: &'a str,
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    step_s: u64,
    pings: u16,
}

pub(crate) async fn series(State(s): State<Arc<AppState>>) -> Response {
    let list: Vec<SeriesJson<'_>> = s
        .series
        .iter()
        .map(|i| SeriesJson {
            id: i.id,
            vantage: &i.key.vantage,
            target: &i.key.target,
            family: &i.key.family,
            group: &i.group,
            probe: &i.probe,
            host: &i.host,
            url: i.url.as_deref(),
            step_s: i.step_ms / 1000,
            pings: i.pings,
        })
        .collect();
    Json(serde_json::json!({ "series": list })).into_response()
}

#[derive(Serialize)]
struct LatestJson {
    series: u64,
    /// Round start, Unix milliseconds.
    t: i64,
    sent: u32,
    recv: u32,
    errors: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    median_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p90_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_not_after_s: Option<i64>,
    /// Estimated voice quality, 1 to 4.5 (G.107 E-model).
    #[serde(skip_serializing_if = "Option::is_none")]
    mos: Option<f64>,
}

/// The newest round of every series that has one, for the overview.
pub(crate) async fn latest(State(s): State<Arc<AppState>>) -> Response {
    let snap = s.latest.snapshot();
    let mut list: Vec<LatestJson> = snap
        .into_iter()
        .map(|(id, l)| LatestJson {
            series: id,
            t: l.ts_ms,
            sent: l.sent,
            recv: l.received,
            errors: l.errors,
            min_us: l.min_us,
            median_us: l.median_us,
            p90_us: l.p90_us,
            max_us: l.max_us,
            cert_not_after_s: l.cert_not_after_s,
            mos: crate::latest_mos(&l).map(crate::round2),
        })
        .collect();
    list.sort_by_key(|l| l.series);
    Json(serde_json::json!({ "now": now_ms(), "latest": list })).into_response()
}

/// `from` and `to` are Unix milliseconds; `to` defaults to now and `from`
/// to three hours before `to`.
#[derive(Debug, Deserialize)]
pub(crate) struct RangeQuery {
    from: Option<i64>,
    to: Option<i64>,
    pub(crate) points: Option<u32>,
    /// `3h`, `30h` or `10d`, ending at `to` (instead of `from`).
    range: Option<String>,
}

impl RangeQuery {
    #[allow(clippy::result_large_err)] // the error is the response itself
    pub(crate) fn resolve(&self) -> Result<(i64, i64), Response> {
        let to = self.to.unwrap_or_else(now_ms);
        let in_store = |t: i64| (MIN_MS..=MAX_MS).contains(&t);
        if !in_store(to) || self.from.is_some_and(|f| !in_store(f)) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "from and to must be within the years 0000 to 9999",
            ));
        }
        let from = match (self.from, self.range.as_deref()) {
            (Some(f), None) => f,
            (None, None) => to - 3 * HOUR_MS,
            (None, Some(r)) => {
                to - range_ms(r)
                    .ok_or_else(|| error(StatusCode::BAD_REQUEST, "range must be 3h, 30h or 10d"))?
            }
            (Some(_), Some(_)) => {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "give from or range, not both",
                ));
            }
        };
        // `range` computes `from`, which must be in the store's years too.
        if !in_store(from) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "from and to must be within the years 0000 to 9999",
            ));
        }
        if from >= to || to.saturating_sub(from) > MAX_SPAN_MS {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "from must be before to, at most ten years apart",
            ));
        }
        Ok((from, to))
    }
}

fn range_ms(r: &str) -> Option<i64> {
    match r {
        "3h" => Some(3 * HOUR_MS),
        "30h" => Some(30 * HOUR_MS),
        "10d" => Some(240 * HOUR_MS),
        _ => None,
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[allow(clippy::result_large_err)]
fn find(s: &AppState, id: u64) -> Result<&crate::SeriesInfo, Response> {
    s.series
        .iter()
        .find(|i| i.id == id)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, format!("no series {id}")))
}

#[derive(Serialize)]
struct PointJson<'a> {
    /// Start, Unix milliseconds.
    t: i64,
    /// Rounds consolidated (1 for raw).
    n: u32,
    sent: u32,
    recv: u32,
    /// Quantiles in microseconds, minimum to maximum; empty if all lost.
    q: &'a [u32],
    /// Estimated voice quality, 1 to 4.5 (G.107 E-model).
    #[serde(skip_serializing_if = "Option::is_none")]
    mos: Option<f64>,
}

/// Quantile frames for the canvas graph: the tier is chosen from the range
/// and `points` (§13.2).
pub(crate) async fn data(
    State(s): State<Arc<AppState>>,
    id: Result<Path<u64>, PathRejection>,
    q: Result<Query<RangeQuery>, QueryRejection>,
) -> Response {
    let (Path(id), Query(q)) = match (id, q) {
        (Ok(id), Ok(q)) => (id, q),
        // A malformed id names no series.
        (Err(e), _) => return error(StatusCode::NOT_FOUND, e.body_text()),
        (_, Err(e)) => return error(StatusCode::BAD_REQUEST, e.body_text()),
    };
    let info = match find(&s, id) {
        Ok(i) => i.clone(),
        Err(r) => return r,
    };
    let (from, to) = match q.resolve() {
        Ok(r) => r,
        Err(r) => return r,
    };
    let points = q.points.unwrap_or(DEFAULT_POINTS).clamp(10, MAX_POINTS);
    let reader = Arc::clone(&s.reader);
    let read = tokio::task::spawn_blocking(move || reader.read_points(id, from, to, points)).await;
    let (res, pts) = match read {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (resolution, width_ms) = match res {
        Resolution::Raw => ("raw", i64::try_from(info.step_ms).unwrap_or(i64::MAX)),
        // Several raw rounds per point (`n`), consolidated exactly.
        Resolution::Buckets(w) => ("raw", w),
        Resolution::Rollup(t @ Tier::R1h) => ("r1h", t.width_ms()),
        Resolution::Rollup(t) => ("r1d", t.width_ms()),
    };
    let json: Vec<PointJson<'_>> = pts
        .iter()
        .map(|p| PointJson {
            t: p.ts_ms,
            n: p.rounds,
            sent: p.sent,
            recv: p.received,
            q: &p.quantiles_us,
            mos: crate::point_mos(p.sent, p.received, &p.quantiles_us).map(crate::round2),
        })
        .collect();
    Json(serde_json::json!({
        "series": id,
        "from": from,
        "to": to,
        "resolution": resolution,
        "width_ms": width_ms,
        "points": json,
    }))
    .into_response()
}

/// `GET /api/v1/render/{id}.svg`: the server-rendered smoke graph (§7.2).
pub(crate) async fn render(
    State(s): State<Arc<AppState>>,
    file: Result<Path<String>, PathRejection>,
    q: Result<Query<RangeQuery>, QueryRejection>,
) -> Response {
    let (Path(file), Query(q)) = match (file, q) {
        (Ok(f), Ok(q)) => (f, q),
        (Err(e), _) => return error(StatusCode::NOT_FOUND, e.body_text()),
        (_, Err(e)) => return error(StatusCode::BAD_REQUEST, e.body_text()),
    };
    let Some(id) = file
        .strip_suffix(".svg")
        .and_then(|i| i.parse::<u64>().ok())
    else {
        return error(StatusCode::NOT_FOUND, "expected /api/v1/render/<id>.svg");
    };
    let info = match find(&s, id) {
        Ok(i) => i.clone(),
        Err(r) => return r,
    };
    let (from, to) = match q.resolve() {
        Ok(r) => r,
        Err(r) => return r,
    };
    let reader = Arc::clone(&s.reader);
    let svg = tokio::task::spawn_blocking(move || {
        // Raw rounds while retention keeps them, else rollups, like
        // `ctl render`.
        let (resolution, rounds) = reader.read_graph(id, from, to)?;
        let view: Vec<Round<'_>> = rounds
            .iter()
            .map(|r| Round {
                ts_ms: r.ts_ms,
                sent: r.sent,
                rtts_us: &r.rtts_us,
            })
            .collect();
        let title = format!(
            "{} ({}, from {})",
            info.key.target, info.key.family, info.key.vantage
        );
        Ok::<_, rl_store::StoreError>(rl_render::render(
            &view,
            &Graph {
                title: &title,
                from_ms: from,
                to_ms: to,
                step_ms: match resolution {
                    Resolution::Rollup(tier) => Some(tier.width_ms()),
                    Resolution::Buckets(width) => Some(width),
                    Resolution::Raw => i64::try_from(info.step_ms).ok(),
                },
                width: Graph::DEFAULT_WIDTH,
                height: Graph::DEFAULT_HEIGHT,
            },
        ))
    })
    .await;
    match svg {
        Ok(Ok(svg)) => (
            [
                (header::CONTENT_TYPE, "image/svg+xml"),
                // SVG may hold script; this one never does, and must not run any.
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'",
                ),
            ],
            svg,
        )
            .into_response(),
        Ok(Err(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
