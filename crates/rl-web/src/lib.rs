//! The server's HTTP side (architecture doc §11.1, §13.2, §20, §21.3 E6–E9):
//! the REST API under `/api/v1`, Prometheus `/metrics`, `/healthz`, and
//! the web UI, whose few static files are compiled into the binary.
//!
//! It runs inside `routelith server` and reads the store directly, so it
//! shows exactly what the server stored. Everything is read-only: nothing
//! here can change the configuration or the data. There is no login yet,
//! which is why the server listens on loopback unless told otherwise.

#![forbid(unsafe_code)]

mod api;
mod host;
mod metrics;
mod ui;

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rl_store::{Reader, SeriesKey};
use tokio::net::TcpListener;

pub use host::{HostHealth, LatestHost, NicTotal};
pub use metrics::MetricsWriter;

/// A series as the API lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesInfo {
    pub id: u64,
    pub key: SeriesKey,
    pub group: String,
    /// `icmp`, `tcp`, `dns` or `http`.
    pub probe: String,
    /// Host name, address, DNS server or URL host.
    pub host: String,
    /// The URL of an HTTP target.
    pub url: Option<String>,
    pub step_ms: u64,
    /// Samples per round.
    pub pings: u16,
}

/// The newest round of a series, kept in memory for `/metrics`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LatestRound {
    pub ts_ms: i64,
    pub sent: u32,
    pub received: u32,
    pub min_us: Option<u32>,
    pub median_us: Option<u32>,
    pub p90_us: Option<u32>,
    pub max_us: Option<u32>,
    /// Samples that failed with a cause (unreachable, refused, HTTP status…).
    pub errors: u32,
    /// Median of each HTTP phase over the round's answered samples.
    pub http_phases_us: Option<HttpPhases>,
    /// Certificate expiry, Unix seconds.
    pub cert_not_after_s: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpPhases {
    pub connect: Option<u32>,
    pub tls: Option<u32>,
    pub ttfb: Option<u32>,
    pub total: Option<u32>,
}

/// Newest rounds by series id, shared with the measuring side.
#[derive(Debug, Default)]
pub struct Latest(Mutex<HashMap<u64, LatestRound>>);

impl Latest {
    pub fn record(&self, series: u64, round: LatestRound) {
        if let Ok(mut m) = self.0.lock() {
            m.insert(series, round);
        }
    }

    fn snapshot(&self) -> HashMap<u64, LatestRound> {
        self.0.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

/// MOS of a newest round (§19): `None` when it received nothing.
pub(crate) fn latest_mos(l: &LatestRound) -> Option<f64> {
    if l.sent == 0 {
        return None;
    }
    let (min, median, p90) = (l.min_us?, l.median_us?, l.p90_us?);
    let loss = f64::from(l.sent - l.received.min(l.sent)) / f64::from(l.sent);
    rl_core::mos::round_mos(min, median, p90, loss)
}

/// MOS of a point of quantiles (ascending, as the store gives them).
pub(crate) fn point_mos(sent: u32, received: u32, q: &[u32]) -> Option<f64> {
    if sent == 0 || q.is_empty() {
        return None;
    }
    let k = q.len();
    let median = if k % 2 == 1 {
        q[k / 2]
    } else {
        u32::try_from((u64::from(q[k / 2 - 1]) + u64::from(q[k / 2])) / 2).unwrap_or(u32::MAX)
    };
    let p90 = q[(k - 1) * 9 / 10];
    let loss = f64::from(sent - received.min(sent)) / f64::from(sent);
    rl_core::mos::round_mos(q[0], median, p90, loss)
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Extra lines for `/metrics` from the rest of the server (scheduler and
/// store counters).
pub type ExtraMetrics = Arc<dyn Fn(&mut MetricsWriter) + Send + Sync>;

/// Everything the handlers need.
pub struct AppState {
    pub reader: Arc<Reader>,
    /// The store directory, for the health snapshot log.
    pub data_dir: PathBuf,
    pub series: Vec<SeriesInfo>,
    pub latest: Arc<Latest>,
    /// This machine's newest health snapshot.
    pub host: Arc<LatestHost>,
    pub vantage: String,
    pub started: Instant,
    pub extra_metrics: Option<ExtraMetrics>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("series", &self.series.len())
            .field("vantage", &self.vantage)
            .finish_non_exhaustive()
    }
}

/// The routes, with the security headers every response carries.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(api::health))
        .route("/metrics", get(metrics::handler))
        .route("/", get(ui::index))
        .route("/ui/{file}", get(ui::asset))
        .route("/api/v1/latest", get(api::latest))
        .route("/api/v1/series", get(api::series))
        .route("/api/v1/series/{id}/data", get(api::data))
        .route("/api/v1/health", get(host::history))
        .route("/api/v1/render/{file}", get(api::render))
        .fallback(api::not_found)
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
    resp
}

/// Serve `router` on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

/// A JSON error body with a status code.
pub(crate) fn error(status: axum::http::StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": msg.into() })),
    )
        .into_response()
}
