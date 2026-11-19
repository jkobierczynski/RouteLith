//! The HTTP side against a real store, without a socket.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rl_store::{ErrorCounts, Reader, SeriesKey, StoredRound, Writer, WriterOptions};
use rl_web::{AppState, HttpPhases, Latest, LatestRound, SeriesInfo};
use tower::ServiceExt;

const T0: i64 = 1_800_000_000_000;
const STEP_MS: i64 = 300_000;

struct Fixture {
    _dir: tempfile::TempDir,
    router: axum::Router,
    id: u64,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (mut w, _) = Writer::open(dir.path(), WriterOptions::default(), T0).unwrap();
    let key = SeriesKey::new("home", "gw \"main\"", "v4");
    let id = w.register(std::slice::from_ref(&key)).unwrap()[0];
    w.set_steps(&[(id, 300_000)]).unwrap();
    for i in 0..12 {
        w.append(
            id,
            StoredRound {
                ts_ms: T0 + i * STEP_MS,
                sent: 4,
                rtts_us: vec![1000, 1100, 1200],
                errors: ErrorCounts::default(),
                resolved: None,
                timing: None,
                flags: 0,
            },
        )
        .unwrap();
    }
    w.sync().unwrap();
    // The writer stays open, as in the server: reads see the WAL.
    std::mem::forget(w);
    let latest = Arc::new(Latest::default());
    latest.record(
        id,
        LatestRound {
            ts_ms: T0 + 11 * STEP_MS,
            sent: 4,
            received: 3,
            min_us: Some(1000),
            median_us: Some(1100),
            p90_us: Some(1200),
            max_us: Some(1200),
            errors: 0,
            http_phases_us: Some(HttpPhases {
                connect: Some(500),
                tls: None,
                ttfb: Some(900),
                total: Some(1000),
            }),
            cert_not_after_s: Some(1_900_000_000),
        },
    );
    let state = AppState {
        reader: Arc::new(Reader::open(dir.path()).unwrap()),
        series: vec![SeriesInfo {
            id,
            key,
            group: "lan".into(),
            probe: "http".into(),
            host: "gw.example".into(),
            url: Some("http://gw.example/".into()),
            step_ms: 300_000,
            pings: 4,
        }],
        latest,
        vantage: "home".into(),
        started: Instant::now(),
        extra_metrics: Some(Arc::new(|m: &mut rl_web::MetricsWriter| {
            m.family("routelith_test_total", "counter", "A test counter.");
            m.sample("routelith_test_total", &[], 7.0);
        })),
    };
    Fixture {
        _dir: dir,
        router: rl_web::router(Arc::new(state)),
        id,
    }
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = router
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn health_and_series() {
    let f = fixture();
    let (st, h, body) = get(&f.router, "/healthz").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    let v = json(&body);
    assert_eq!(
        (v["status"].as_str(), v["series"].as_u64()),
        (Some("ok"), Some(1))
    );

    let (st, _, body) = get(&f.router, "/api/v1/series").await;
    assert_eq!(st, StatusCode::OK);
    let s = &json(&body)["series"][0];
    assert_eq!(s["id"].as_u64(), Some(f.id));
    assert_eq!(s["target"], "gw \"main\"");
    assert_eq!(s["probe"], "http");
    assert_eq!(s["url"], "http://gw.example/");
    assert_eq!(
        (s["step_s"].as_u64(), s["pings"].as_u64()),
        (Some(300), Some(4))
    );
}

#[tokio::test]
async fn data_returns_raw_points_for_a_short_range() {
    let f = fixture();
    let uri = format!(
        "/api/v1/series/{}/data?from={T0}&to={}",
        f.id,
        T0 + 3_600_000
    );
    let (st, _, body) = get(&f.router, &uri).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    assert_eq!(v["resolution"], "raw");
    assert_eq!(v["width_ms"].as_i64(), Some(STEP_MS));
    let pts = v["points"].as_array().unwrap();
    assert_eq!(pts.len(), 12);
    assert_eq!(pts[0]["t"].as_i64(), Some(T0));
    assert_eq!(
        (pts[0]["sent"].as_u64(), pts[0]["recv"].as_u64()),
        (Some(4), Some(3))
    );
    let q = pts[0]["q"].as_array().unwrap();
    assert_eq!(q.first().unwrap().as_u64(), Some(1000));
    assert_eq!(q.last().unwrap().as_u64(), Some(1200));
}

#[tokio::test]
async fn bad_requests_are_json_errors() {
    let f = fixture();
    for (uri, status) in [
        ("/api/v1/series/999/data".to_string(), StatusCode::NOT_FOUND),
        (
            format!("/api/v1/series/{}/data?range=7d", f.id),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/v1/series/{}/data?from=10&to=5", f.id),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/v1/series/{}/data?from=1&range=3h", f.id),
            StatusCode::BAD_REQUEST,
        ),
        ("/api/v1/render/abc.svg".to_string(), StatusCode::NOT_FOUND),
        ("/api/v1/series/abc/data".to_string(), StatusCode::NOT_FOUND),
        (
            format!("/api/v1/series/{}/data?points=abc", f.id),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/v1/series/{}/data?from=abc", f.id),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/v1/render/{}.svg?from=abc", f.id),
            StatusCode::BAD_REQUEST,
        ),
        // Past the years the store holds (and the renderer's tick loop).
        (
            format!(
                "/api/v1/render/{}.svg?range=3h&to=9223372036854775807",
                f.id
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(
                "/api/v1/series/{}/data?from=-9223372036854775808&to=0",
                f.id
            ),
            StatusCode::BAD_REQUEST,
        ),
        ("/nope".to_string(), StatusCode::NOT_FOUND),
    ] {
        let (st, h, body) = get(&f.router, &uri).await;
        assert_eq!(st, status, "{uri}: {body}");
        assert_eq!(h["content-type"], "application/json", "{uri}");
        assert!(json(&body)["error"].is_string(), "{uri}");
    }
}

#[tokio::test]
async fn render_serves_svg_that_cannot_run_script() {
    let f = fixture();
    let uri = format!(
        "/api/v1/render/{}.svg?from={T0}&to={}",
        f.id,
        T0 + 3_600_000
    );
    let (st, h, body) = get(&f.router, &uri).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["content-type"], "image/svg+xml");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'")
    );
    assert!(
        body.starts_with("<svg") || body.starts_with("<?xml"),
        "{}",
        &body[..40]
    );
    assert!(!body.contains("<script"));
}

#[tokio::test]
async fn metrics_show_the_newest_round() {
    let f = fixture();
    let (st, h, body) = get(&f.router, "/metrics").await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        h["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain; version=0.0.4")
    );
    let labels = r#"vantage="home",target="gw \"main\"",family="v4",probe="http",group="lan""#;
    for line in [
        format!("routelith_rtt_seconds{{{labels},stat=\"median\"}} 0.0011"),
        format!("routelith_loss_ratio{{{labels}}} 0.25"),
        format!("routelith_round_samples{{{labels},outcome=\"received\"}} 3"),
        format!("routelith_http_phase_seconds{{{labels},phase=\"connect\"}} 0.0005"),
        format!("routelith_tls_cert_expiry_timestamp_seconds{{{labels}}} 1900000000"),
        "# TYPE routelith_test_total counter".to_string(),
        "routelith_test_total 7".to_string(),
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }
    // No TLS phase for plain HTTP.
    assert!(!body.contains("phase=\"tls\""));
}
