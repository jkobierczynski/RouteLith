//! The HTTP side against a real store, without a socket.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rl_store::{
    ErrorCounts, Event, EventKind, EventLog, HealthLog, HealthSample, NicDelta, Reader, SeriesKey,
    StoredRound, Writer, WriterOptions,
};
use rl_web::{
    AlertBoard, AppState, HostHealth, HttpPhases, Latest, LatestHost, LatestRound, NicTotal,
    RuleInfo, SeriesInfo,
};
use tower::ServiceExt;

const T0: i64 = 1_800_000_000_000;
const STEP_MS: i64 = 300_000;

struct Fixture {
    _dir: tempfile::TempDir,
    router: axum::Router,
    id: u64,
    /// Hop series of the `web` trace, TTL 1 first.
    hop_ids: Vec<u64>,
}

/// A traced target `web`: 24 sweeps from T0 over a private first hop and
/// 1.1.1.1, and the hop series' rounds of that minute.
fn add_trace(dir: &std::path::Path, w: &mut Writer) -> rl_web::TraceInfo {
    use rl_store::{TraceHop, TraceLog, TraceRecord};
    let keys: Vec<SeriesKey> = ["web#", "web#1", "web#2"]
        .iter()
        .map(|t| SeriesKey::new("home", t, "v4"))
        .collect();
    let ids = w.register(&keys).unwrap();
    w.set_steps(&[(ids[1], 60_000), (ids[2], 60_000)]).unwrap();
    let gw: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let dest: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let mut log = TraceLog::open(dir, 7).unwrap();
    for i in 0..24 {
        let hops = vec![
            TraceHop::TimeExceeded {
                from: gw,
                rtt_us: 500,
            },
            // One sweep in four loses the destination.
            if i % 4 == 3 {
                TraceHop::Lost
            } else {
                TraceHop::Reply {
                    from: dest,
                    rtt_us: 9000,
                }
            },
        ];
        let rec = TraceRecord {
            ts_ms: T0 + i * 2500,
            timing: None,
            hops,
        };
        log.append(ids[0], &rec, T0).unwrap();
    }
    log.sync().unwrap();
    std::mem::forget(log);
    for (id, rtts) in [(ids[1], vec![500; 24]), (ids[2], vec![9000; 18])] {
        w.append(
            id,
            StoredRound {
                ts_ms: T0,
                sent: 24,
                rtts_us: rtts,
                errors: ErrorCounts::default(),
                resolved: None,
                timing: None,
                flags: 0,
            },
        )
        .unwrap();
    }
    let hops = keys[1..]
        .iter()
        .zip(&ids[1..])
        .map(|(k, &id)| SeriesInfo {
            id,
            key: k.clone(),
            group: "net".into(),
            probe: "trace".into(),
            host: "web.example".into(),
            url: None,
            step_ms: 60_000,
            pings: 24,
        })
        .collect();
    rl_web::TraceInfo {
        vantage: "home".into(),
        target: "web".into(),
        group: "net".into(),
        host: "web.example".into(),
        family: "v4".into(),
        mode: "continuous".into(),
        interval_ms: 2500,
        step_ms: 60_000,
        max_ttl: 2,
        raw_series: ids[0],
        hops,
    }
}

/// Names from a table and AS 13335 for 1.0.0.0/8, as an iptoasn file.
fn enricher(dir: &std::path::Path) -> Arc<rl_path::enrich::Enricher> {
    use rl_path::enrich::{AsnSource, Enricher, Rdns};
    let file = dir.join("ip2asn-combined.tsv");
    std::fs::write(&file, "1.0.0.0\t1.255.255.255\t13335\tUS\tCLOUDFLARENET\n").unwrap();
    let asn = AsnSource::new(file);
    asn.refresh().unwrap();
    Arc::new(Enricher {
        rdns: Rdns::new(Arc::new(|a: std::net::IpAddr| {
            (a.to_string() == "1.1.1.1").then(|| "one.one.one.one".to_string())
        })),
        asn: Some(asn),
    })
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
    let trace = add_trace(dir.path(), &mut w);
    let hop_ids = trace.hops.iter().map(|h| h.id).collect();
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
            nic_interval_ms: None,
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
    // One alert raised and cleared, one raised now.
    let mut events = EventLog::open(dir.path(), 400).unwrap();
    for (i, kind) in [
        EventKind::AlertRaised,
        EventKind::AlertCleared,
        EventKind::AlertRaised,
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = Event::new(T0 + i as i64 * STEP_MS, kind, "home", format!("event {i}"));
        e.series = Some(id);
        e.target = Some("gw \"main\"".into());
        e.rule = Some("slow".into());
        events.append(&e).unwrap();
    }
    // Another target's events after them.
    for i in 0..3 {
        let mut e = Event::new(
            T0 + (3 + i) * STEP_MS,
            EventKind::IpChanged,
            "home",
            "other",
        );
        e.target = Some("other".into());
        events.append(&e).unwrap();
    }
    let silence = rl_core::silence::Silence {
        name: "always".into(),
        targets: Vec::new(),
        groups: vec!["g".into()],
        alerts: Vec::new(),
        when: rl_core::silence::When::Every {
            rule: rl_core::silence::parse_rrule("FREQ=DAILY").unwrap(),
            duration_ms: 86_400_000,
            start_ms: None,
            end_ms: None,
        },
        line: 1,
    };
    let alerts = Arc::new(
        AlertBoard::new(vec![RuleInfo {
            name: "slow".into(),
            kind: "threshold".into(),
            summary: "median > 20ms".into(),
            series: vec![id],
        }])
        .with_silences(vec![silence]),
    );
    alerts.set_active(vec![rl_alert::ActiveAlert {
        series: id,
        rule: "slow".into(),
        since_ms: T0 + 2 * STEP_MS,
        value: Some(31.25),
        silenced_by: Some("always".into()),
        suppressed_by: None,
        vantages: Vec::new(),
    }]);
    alerts.count(true);
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
        alerts,
        auth: Arc::new(rl_web::Auth::open()),
        slas: vec![rl_core::config::Sla {
            name: "lan".into(),
            targets: Vec::new(),
            groups: vec!["lan".into()],
            availability: Some(99.9),
            loss: None,
            latency_us: None,
            percentile: 95,
            line: 1,
        }],
        parents: Default::default(),
        agents: None,
        traces: vec![trace],
        enricher: Some(enricher(dir.path())),
    };
    Fixture {
        _dir: dir,
        router: rl_web::router(Arc::new(state)),
        id,
        hop_ids,
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
async fn render_serves_png() {
    let f = fixture();
    let uri = format!(
        "/api/v1/render/{}.png?from={T0}&to={}&scale=2",
        f.id,
        T0 + 3_600_000
    );
    let resp = f
        .router
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "image/png");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    let width = u32::from_be_bytes(body[16..20].try_into().unwrap());
    assert_eq!(width, 2 * rl_render::Graph::DEFAULT_WIDTH);

    for (bad, want) in [
        (
            format!("/api/v1/render/{}.png?scale=3", f.id),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/api/v1/render/{}.gif", f.id),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (st, _, body) = get(&f.router, &bad).await;
        assert_eq!(st, want, "{bad}: {body}");
    }
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
async fn an_agents_health_is_read_by_its_name() {
    let f = fixture();
    // Nothing stored for this agent yet: an empty answer, under its name.
    let uri = format!(
        "/api/v1/health?from={T0}&to={}&vantage=plant-genk",
        T0 + 3_600_000
    );
    let (st, _, body) = get(&f.router, &uri).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    assert_eq!(v["vantage"], "plant-genk");
    assert!(v["points"].as_array().unwrap().is_empty());
    let uri = format!(
        "/api/v1/health?from={T0}&to={}&vantage=home",
        T0 + 3_600_000
    );
    assert_eq!(
        json(&get(&f.router, &uri).await.2)["points"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    // Not a way out of the data directory.
    let (st, _, _) = get(&f.router, "/api/v1/health?vantage=..").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
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

#[tokio::test]
async fn alerts_and_events() {
    let f = fixture();
    let (st, _, body) = get(&f.router, "/api/v1/alerts").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    let a = &v["active"][0];
    assert_eq!(a["target"], "gw \"main\"");
    assert_eq!(a["rule"], "slow");
    assert_eq!(a["since"].as_i64(), Some(T0 + 2 * STEP_MS));
    assert_eq!(a["value"].as_f64(), Some(31.25));
    assert_eq!(v["rules"][0]["summary"], "median > 20ms");
    assert_eq!(a["silenced_by"], "always");
    assert!(a.get("suppressed_by").is_none());
    let sl = &v["silences"][0];
    assert_eq!(sl["name"], "always");
    assert_eq!(sl["summary"], "FREQ=DAILY for 24h");
    assert_eq!(sl["groups"][0], "g");
    assert_eq!(sl["active"], true);

    let uri = format!("/api/v1/events?from={T0}&to={}", T0 + 86_400_000);
    let (st, _, body) = get(&f.router, &uri).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    let msgs: Vec<_> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["message"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(msgs[3..], ["event 2", "event 1", "event 0"], "newest first");
    assert_eq!(v["events"][3]["kind"], "alert_raised");
    assert_eq!(v["truncated"], false);

    let (_, _, body) = get(&f.router, &format!("{uri}&limit=1")).await;
    let v = json(&body);
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["truncated"], true);

    // The target filter applies before the limit.
    let (_, _, body) = get(&f.router, &format!("{uri}&limit=1&target=gw%20%22main%22")).await;
    let v = json(&body);
    assert_eq!(v["events"][0]["message"], "event 2");
    assert_eq!(v["truncated"], true);

    for bad in ["/api/v1/events?from=x", "/api/v1/events?from=10&to=5"] {
        let (st, _, body) = get(&f.router, bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert!(json(&body)["error"].is_string());
    }

    let (_, _, body) = get(&f.router, "/metrics").await;
    assert!(
        body.contains(
            "routelith_alert_active{vantage=\"home\",target=\"gw \\\"main\\\"\",family=\"v4\",rule=\"slow\"} 1"
        ),
        "{body}"
    );
    assert!(body.contains("routelith_alerts_raised_total 1"));
    assert!(body.contains("routelith_alerts_cleared_total 0"));
}

#[tokio::test]
async fn sla_reports_come_as_html_or_csv() {
    let f = fixture();
    // A past month the fixture has no rounds in.
    let (st, h, body) = get(&f.router, "/api/v1/reports/sla?month=2026-10").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    assert!(body.contains("SLA report, October 2026"), "{body}");
    assert!(body.contains("gw &quot;main&quot;"), "the target, escaped");
    assert!(body.contains("badge none"), "no data that month");

    let (st, h, body) = get(&f.router, "/api/v1/reports/sla?month=2026-10&format=csv").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["content-type"], "text/csv; charset=utf-8");
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .contains("routelith-sla-2026-10.csv")
    );
    let line = body.lines().nth(1).unwrap();
    assert!(
        line.starts_with("2026-10,lan,\"gw \"\"main\"\"\",v4,lan,"),
        "{line}"
    );
    assert!(line.ends_with(",no data"), "{line}");

    for bad in ["month=2026-13", "month=9999-01", "format=pdf"] {
        let (st, _, body) = get(&f.router, &format!("/api/v1/reports/sla?{bad}")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
}

#[tokio::test]
async fn incident_timelines_come_as_html_json_or_csv() {
    let f = fixture();
    let (st, h, body) = get(&f.router, "/api/v1/reports/incidents?month=2026-10").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
    assert!(body.contains("Incident timeline, 2026-10"), "{body}");
    let (st, h, body) = get(
        &f.router,
        "/api/v1/reports/incidents?month=2026-10&format=json",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        h["content-disposition"]
            .to_str()
            .unwrap()
            .contains("routelith-incidents-2026-10.json")
    );
    assert_eq!(json(&body)["incidents"].as_array().map(Vec::len), Some(0));
    for bad in ["month=2026-13", "format=pdf", "gap=5000", "month=9999-01"] {
        let (st, _, body) = get(&f.router, &format!("/api/v1/reports/incidents?{bad}")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
}

#[tokio::test]
async fn paths_give_the_hop_table_with_names_and_as_numbers() {
    let f = fixture();
    let (st, _, body) = get(&f.router, "/api/v1/paths").await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    assert_eq!(v["paths"][0]["target"], "web");
    assert_eq!(v["paths"][0]["hop_series"], serde_json::json!(f.hop_ids));

    let window = format!("from={T0}&to={}", T0 + 60_000);
    let (st, _, body) = get(&f.router, &format!("/api/v1/paths/web?{window}")).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    assert_eq!(v["source"], "sweeps");
    assert_eq!(v["sweeps"], 24);
    assert_eq!(v["rounds"], 1);
    let hops = v["hops"].as_array().unwrap();
    assert_eq!(hops.len(), 2);
    let gw = &hops[0]["responders"][0];
    assert_eq!(gw["addr"], "192.168.1.1");
    assert_eq!(gw["class"], "private");
    assert!(gw.get("asn").is_none(), "{gw}");
    assert_eq!(hops[0]["series"], f.hop_ids[0]);
    let dest = &hops[1];
    assert_eq!(dest["loss_pct"], 25.0);
    assert_eq!(dest["is_dest"], true);
    assert_eq!(dest["median_us"], 9000);
    let r = &dest["responders"][0];
    assert_eq!(r["asn"], 13335);
    assert_eq!(r["org"], "CLOUDFLARENET");
    assert_eq!(r["country"], "US");
    assert_eq!(r["rdns"], "one.one.one.one");
    assert_eq!(r["share_pct"], 100.0);

    // Past a day the hop series stand in: same loss, no responders.
    let long = format!("from={}&to={}", T0 - 2 * 86_400_000, T0 + 60_000);
    let (st, _, body) = get(&f.router, &format!("/api/v1/paths/web?{long}")).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v = json(&body);
    assert_eq!(v["source"], "hop_series");
    assert_eq!(v["hops"][1]["loss_pct"], 25.0);
    assert_eq!(v["hops"][1]["responders"], serde_json::json!([]));

    // A hop series has a timeline like any series.
    let (st, _, body) = get(
        &f.router,
        &format!("/api/v1/series/{}/data?{window}", f.hop_ids[1]),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["points"][0]["recv"], 18);

    for uri in [
        "/api/v1/paths/nope".to_string(),
        format!("/api/v1/paths/web?family=v6&{window}"),
        format!("/api/v1/paths/web?vantage=elsewhere&{window}"),
    ] {
        let (st, _, body) = get(&f.router, &uri).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{uri}: {body}");
    }
    let (st, _, _) = get(&f.router, "/api/v1/paths/web?from=5&to=1").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}
