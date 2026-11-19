//! The HTTP side against a real store, without a socket.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rl_store::{
    ErrorCounts, HealthLog, HealthSample, NicDelta, Reader, SeriesKey, StoredRound, Writer,
    WriterOptions,
};
use rl_web::{
    AppState, HostHealth, HttpPhases, Latest, LatestHost, LatestRound, NicTotal, SeriesInfo,
};
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
    // A minute of health snapshots each, with a gateway change at 3 min.
    let mut log = HealthLog::open(dir.path(), "home", 30).unwrap();
    let mut newest = HealthSample::default();
    for i in 0..5 {
        newest = HealthSample {
            t: T0 + i * 60_000,
            interval_ms: if i == 0 { 0 } else { 60_000 },
            cpu_pct: (i > 0).then_some(10.0 * i as f64),
            load1: Some(0.5),
            nic_errors: (i > 0).then_some(0),
            nic_drops: (i > 0).then_some(if i == 2 { 4 } else { 0 }),
            nics: if i == 2 {
                vec![NicDelta {
                    name: "eth0".into(),
                    errors: 0,
                    drops: 4,
                }]
            } else {
                Vec::new()
            },
            gateways: vec![
                if i < 3 { "192.0.2.1" } else { "192.0.2.254" }
                    .parse()
                    .unwrap(),
            ],
            dns: vec!["192.0.2.53".parse().unwrap()],
        };
        log.append(&newest).unwrap();
    }
    let host = Arc::new(LatestHost::default());
    host.record(HostHealth {
        sample: newest,
        nics: vec![NicTotal {
            name: "eth0".into(),
            rx_errors: 1,
            tx_errors: 0,
            rx_drops: 9,
            tx_drops: 0,
        }],
    });
    let state = AppState {
        reader: Arc::new(Reader::open(dir.path()).unwrap()),
        data_dir: dir.path().to_path_buf(),
        host,
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
    assert!(pts[0]["mos"].as_f64().is_some());
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
        (
            format!("/api/v1/render/{}.svg?points=abc", f.id),
            StatusCode::BAD_REQUEST,
        ),
        // A `from` computed from `range` before the year 0000.
        (
            format!("/api/v1/render/{}.svg?range=3h&to=-62167219200000", f.id),
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
        // 1.1 ms RTT, 25 % loss: G.711 with PLC loses a lot to loss.
        format!("routelith_mos_score{{{labels}}} 2.32"),
    ] {
        assert!(body.lines().any(|l| l == line), "missing {line}\n{body}");
    }
    // No TLS phase for plain HTTP.
    assert!(!body.contains("phase=\"tls\""));
}

#[tokio::test]
async fn latest_lists_the_newest_rounds() {
    let f = fixture();
    let (st, _, body) = get(&f.router, "/api/v1/latest").await;
    assert_eq!(st, StatusCode::OK);
    let v = json(&body);
    assert!(v["now"].as_i64().unwrap() > 1_700_000_000_000);
    let l = &v["latest"][0];
    assert_eq!(l["series"].as_u64(), Some(f.id));
    assert_eq!((l["sent"].as_u64(), l["recv"].as_u64()), (Some(4), Some(3)));
    assert_eq!(l["median_us"].as_u64(), Some(1100));
    assert!(l["mos"].as_f64().unwrap() > 2.0);
}

#[tokio::test]
async fn the_ui_is_served_from_the_binary() {
    let f = fixture();
    let (st, h, body) = get(&f.router, "/").await;
    assert_eq!(st, StatusCode::OK);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("unsafe"),
        "{csp}"
    );
    assert!(body.contains("/ui/app.js") && body.contains("/ui/style.css"));
    for (path, ty) in [
        ("/ui/app.js", "text/javascript"),
        ("/ui/style.css", "text/css"),
        ("/ui/icon.svg", "image/svg+xml"),
    ] {
        let (st, h, body) = get(&f.router, path).await;
        assert_eq!(st, StatusCode::OK, "{path}");
        assert!(
            h["content-type"].to_str().unwrap().starts_with(ty),
            "{path}"
        );
        assert!(!body.is_empty());
    }
    let (st, _, _) = get(&f.router, "/ui/../Cargo.toml").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = get(&f.router, "/ui/other.js").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_snapshots_are_summarised_with_network_changes() {
    let f = fixture();
    let uri = format!("/api/v1/health?from={T0}&to={}", T0 + 3_600_000);
    let (st, _, body) = get(&f.router, &uri).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    assert_eq!(v["vantage"], "home");
    assert_eq!(v["width_ms"].as_i64(), Some(60_000));
    let points = v["points"].as_array().unwrap();
    assert_eq!(points.len(), 5);
    assert!(points[0].get("cpu_pct").is_none());
    assert_eq!(points[4]["cpu_pct"].as_f64(), Some(40.0));
    assert_eq!(points[2]["nic_drops"].as_u64(), Some(4));
    assert_eq!(points[2]["nics"][0]["name"], "eth0");
    let network = v["network"].as_array().unwrap();
    assert_eq!(network.len(), 2);
    assert_eq!(network[0]["gateways"][0], "192.0.2.1");
    assert_eq!(network[1]["t"].as_i64(), Some(T0 + 3 * 60_000));
    assert_eq!(network[1]["gateways"][0], "192.0.2.254");
    assert_eq!(network[1]["dns"][0], "192.0.2.53");

    // A day in few points: buckets of whole minutes.
    let uri = format!("/api/v1/health?from={T0}&to={}&points=10", T0 + 86_400_000);
    let v = json(&get(&f.router, &uri).await.2);
    assert_eq!(v["width_ms"].as_i64(), Some(144 * 60_000));
    assert_eq!(v["points"].as_array().unwrap().len(), 1);
    assert_eq!(v["points"][0]["n"].as_u64(), Some(5));
}

#[tokio::test]
async fn metrics_show_the_host_health() {
    let f = fixture();
    let (_, _, body) = get(&f.router, "/metrics").await;
    for line in [
        "routelith_host_cpu_busy_ratio{vantage=\"home\"} 0.4",
        "routelith_host_load1{vantage=\"home\"} 0.5",
        "routelith_host_nic_drops_total{vantage=\"home\",interface=\"eth0\",direction=\"rx\"} 9",
        "routelith_host_nic_errors_total{vantage=\"home\",interface=\"eth0\",direction=\"rx\"} 1",
        "routelith_host_gateway_info{vantage=\"home\",address=\"192.0.2.254\"} 1",
        "routelith_host_dns_server_info{vantage=\"home\",address=\"192.0.2.53\"} 1",
        "# TYPE routelith_host_nic_drops_total counter",
    ] {
        assert!(
            body.lines().any(|l| l == line),
            "missing {line:?} in\n{body}"
        );
    }
}
