//! The server's HTTP side (architecture doc §11.1, §13.2, §20, §21.3 E6–E9):
//! the REST API under `/api/v1`, Prometheus `/metrics`, `/healthz`, and
//! the web UI, whose few static files are compiled into the binary.
//!
//! It runs inside `routelith server` and reads the store directly, so it
//! shows exactly what the server stored. Once a users file names users,
//! the API needs a login (doc §21.5 F11, [`auth`]); the UI can be served
//! over TLS with certificate and key files.

#![forbid(unsafe_code)]

pub mod agents;
mod alerts;
mod api;
pub mod auth;
mod host;
pub mod incidents;
mod metrics;
mod paths;
pub mod silences;
pub mod sla;
mod ui;
pub mod users;

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use hyper_util::rt::{TokioIo, TokioTimer};
use rl_store::{Reader, SeriesKey};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

pub use auth::{Auth, AuthConfig, Caller};

pub use alerts::{AlertBoard, RuleInfo};
pub use axum::http::StatusCode;
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
    /// Alert rules and the alerts raised now.
    pub alerts: Arc<AlertBoard>,
    /// Users and sessions.
    pub auth: Arc<Auth>,
    /// The `[[sla]]` tables, for the SLA report.
    pub slas: Vec<rl_core::config::Sla>,
    /// Each target's parent, for the incident timeline.
    pub parents: std::collections::HashMap<String, String>,
    /// Enrolled agents, their state and their enrollment; `None`
    /// without `listen_agents`.
    pub agents: Option<Arc<dyn agents::AgentAdmin>>,
    /// The traces of this vantage (§21.9 P14).
    pub traces: Vec<TraceInfo>,
    /// rDNS and ASN lookups for trace hops (§21.9 P9); `None` leaves hops
    /// with their address class only.
    pub enricher: Option<Arc<rl_path::enrich::Enricher>>,
}

/// One traced target and family.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub vantage: String,
    pub target: String,
    pub group: String,
    pub host: String,
    pub family: String,
    /// `continuous` or `on_alert`.
    pub mode: String,
    pub interval_ms: u64,
    pub step_ms: u64,
    pub max_ttl: u8,
    /// The raw sweeps' series.
    pub raw_series: u64,
    /// The hop series, TTL 1 first.
    pub hops: Vec<SeriesInfo>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("series", &self.series.len())
            .field("vantage", &self.vantage)
            .finish_non_exhaustive()
    }
}

/// The routes, with the security headers every response carries. The
/// page, its files, `/healthz` and the session and login endpoints are
/// open; everything else goes through [`auth::guard`].
pub fn router(state: Arc<AppState>) -> Router {
    let guarded = Router::new()
        .route("/metrics", get(metrics::handler))
        .route("/api/v1/logout", post(auth::logout))
        .route("/api/v1/latest", get(api::latest))
        .route("/api/v1/series", get(api::series))
        .route("/api/v1/agents", get(agents::list))
        .route("/api/v1/agents/enroll-token", post(agents::enroll_token))
        .route("/api/v1/agents/{name}", delete(agents::revoke))
        .route("/api/v1/series/{id}/data", get(api::data))
        .route("/api/v1/paths", get(paths::list))
        .route("/api/v1/paths/{target}", get(paths::path))
        .route("/api/v1/health", get(host::history))
        .route("/api/v1/alerts", get(alerts::alerts))
        .route("/api/v1/events", get(alerts::events))
        .route("/api/v1/reports/sla", get(sla::handler))
        .route("/api/v1/reports/incidents", get(incidents::handler))
        .route("/api/v1/silences", post(silences::create))
        .route("/api/v1/silences/{name}", delete(silences::end_now))
        .route("/api/v1/render/{file}", get(api::render))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::guard,
        ));
    Router::new()
        .route("/healthz", get(api::health))
        .route("/", get(ui::index))
        .route("/ui/{file}", get(ui::asset))
        .route("/api/v1/session", get(auth::session))
        .route("/api/v1/login", post(auth::login))
        .merge(guarded)
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

/// How long a client may take to send a request's headers, or to finish
/// the TLS handshake.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long open connections get to finish when the server stops.
const DRAIN: Duration = Duration::from_secs(5);

/// TLS for the UI from PEM files: the certificate chain (server
/// certificate first) and its private key.
pub fn tls_acceptor(cert_file: &Path, key_file: &Path) -> Result<TlsAcceptor, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(cert_file)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("tls_cert {}: {e}", cert_file.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "tls_cert {}: no certificates found",
            cert_file.display()
        ));
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|e| format!("tls_key {}: {e}", key_file.display()))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS setup: {e}"))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| {
        format!(
            "tls_cert {} and tls_key {}: {e}",
            cert_file.display(),
            key_file.display()
        )
    })?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Serve `router` on `listener`, over TLS when `tls` is set, until
/// `shutdown` resolves; open connections then get a few seconds to
/// finish. Handlers see the client's address as `ConnectInfo`.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    tls: Option<TlsAcceptor>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut conns = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            r = listener.accept() => {
                let (stream, peer) = match r {
                    Ok(x) => x,
                    Err(_) => {
                        // Out of file descriptors and the like: wait, so
                        // the loop does not spin.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let (router, tls, stop) = (router.clone(), tls.clone(), stop_rx.clone());
                conns.spawn(async move {
                    match tls {
                        None => connection(TokioIo::new(stream), peer, router, stop).await,
                        Some(acc) => {
                            if let Ok(Ok(s)) =
                                tokio::time::timeout(HEADER_TIMEOUT, acc.accept(stream)).await
                            {
                                connection(TokioIo::new(s), peer, router, stop).await;
                            }
                        }
                    }
                });
            }
        }
    }
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(DRAIN, async { while conns.join_next().await.is_some() {} }).await;
    conns.abort_all();
    Ok(())
}

async fn connection<I>(
    io: I,
    peer: SocketAddr,
    router: Router,
    mut stop: tokio::sync::watch::Receiver<bool>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(req)
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);
    let stopping = tokio::select! {
        _ = conn.as_mut() => false,
        r = stop.wait_for(|s| *s) => r.is_ok(),
    };
    if stopping {
        conn.as_mut().graceful_shutdown();
        let _ = conn.await;
    }
}

/// A JSON error body with a status code.
pub(crate) fn error(status: axum::http::StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": msg.into() })),
    )
        .into_response()
}
