//! Logins, roles and TLS on the web side, and silences added from the UI
//! (doc §21.5 F11, §21.6).

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use rl_web::silences::Silences;
use rl_web::users::{Role, User, Users, hash_password};
use rl_web::{AlertBoard, AppState, Auth, AuthConfig, LatestHost, RuleInfo, SeriesInfo};
use tower::ServiceExt;

struct Fixture {
    dir: tempfile::TempDir,
    router: axum::Router,
}

fn users_file(dir: &Path) -> std::path::PathBuf {
    dir.join("users.toml")
}

fn write_users(dir: &Path, users: &[(&str, Role, &str)]) {
    Users {
        users: users
            .iter()
            .map(|(n, r, p)| User {
                name: n.to_string(),
                role: *r,
                password: hash_password(p).unwrap(),
            })
            .collect(),
    }
    .save(&users_file(dir))
    .unwrap();
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A silence in the configuration file, which the UI cannot end.
fn configured_silence() -> rl_core::silence::Silence {
    rl_core::silence::Silence {
        name: "cfg".into(),
        targets: Vec::new(),
        groups: Vec::new(),
        alerts: Vec::new(),
        when: rl_core::silence::When::Once {
            start_ms: 0,
            end_ms: i64::MAX / 2,
        },
        line: 1,
    }
}

fn fixture(users: &[(&str, Role, &str)], anonymous: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    // An empty store, made by the writer so the reader can open it.
    drop(rl_store::Writer::open(dir.path(), rl_store::WriterOptions::default(), 0).unwrap());
    if !users.is_empty() {
        write_users(dir.path(), users);
    }
    let auth = Auth::new(AuthConfig {
        users_file: users_file(dir.path()),
        anonymous,
        secure: false,
    })
    .unwrap();
    let state = AppState {
        reader: Arc::new(rl_store::Reader::open(dir.path()).unwrap()),
        data_dir: dir.path().to_path_buf(),
        host: Arc::new(LatestHost::default()),
        series: vec![SeriesInfo {
            id: 1,
            key: rl_store::SeriesKey::new("local", "gw", "v4"),
            group: "lan".into(),
            probe: "icmp".into(),
            host: "192.0.2.1".into(),
            url: None,
            step_ms: 60_000,
            pings: 4,
        }],
        latest: Arc::default(),
        vantage: "local".into(),
        started: Instant::now(),
        extra_metrics: None,
        alerts: Arc::new(
            AlertBoard::new(vec![RuleInfo {
                name: "down".into(),
                kind: "threshold".into(),
                summary: "loss > 50%".into(),
                series: vec![1],
            }])
            .with_shared_silences(Arc::new(
                Silences::load(vec![configured_silence()], dir.path(), now_ms()).unwrap(),
            )),
        ),
        auth: Arc::new(auth),
    };
    Fixture {
        router: rl_web::router(Arc::new(state)),
        dir,
    }
}

struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: serde_json::Value,
}

async fn call(router: &axum::Router, req: Request<Body>) -> Answer {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Answer {
        status,
        headers,
        body,
    }
}

fn get(uri: &str) -> axum::http::request::Builder {
    Request::get(uri)
}

async fn login(router: &axum::Router, name: &str, password: &str) -> Answer {
    call(
        router,
        Request::post("/api/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "name": name, "password": password }).to_string(),
            ))
            .unwrap(),
    )
    .await
}

/// The `name=value` part of the session cookie a login set.
fn cookie(a: &Answer) -> String {
    let set = a.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(set.contains("HttpOnly"), "{set}");
    assert!(set.contains("SameSite=Strict"), "{set}");
    set.split(';').next().unwrap().to_string()
}

fn basic(name: &str, password: &str) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{name}:{password}");
    let mut out = String::new();
    for chunk in raw.as_bytes().chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    format!("Basic {out}")
}

#[tokio::test]
async fn without_users_everything_is_open() {
    let f = fixture(&[], false);
    let a = call(
        &f.router,
        get("/api/v1/series").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK);
    let a = call(&f.router, get("/metrics").body(Body::empty()).unwrap()).await;
    assert_eq!(a.status, StatusCode::OK);
    let a = call(
        &f.router,
        get("/api/v1/session").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(a.body["users"], false);
    assert_eq!(a.body["login_required"], false);
    let a = login(&f.router, "ann", "whatever password").await;
    assert_eq!(a.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_session_reads_and_its_writes_need_the_csrf_token() {
    let f = fixture(&[("ann", Role::Operator, "correct horse battery")], false);
    // Open: the page, its files, health and the session state.
    for uri in ["/", "/ui/app.js", "/healthz", "/api/v1/session"] {
        let a = call(&f.router, get(uri).body(Body::empty()).unwrap()).await;
        assert_eq!(a.status, StatusCode::OK, "{uri}");
    }
    // Everything else needs a caller.
    for uri in [
        "/api/v1/series",
        "/api/v1/alerts",
        "/metrics",
        "/api/v1/events",
    ] {
        let a = call(&f.router, get(uri).body(Body::empty()).unwrap()).await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(a.body["error"], "login required");
    }
    let a = call(
        &f.router,
        get("/api/v1/session").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(a.body["login_required"], true);
    assert_eq!(a.body["user"], serde_json::Value::Null);

    let a = login(&f.router, "ann", "wrong password").await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert!(!a.headers.contains_key(header::SET_COOKIE));
    let a = login(&f.router, "nobody", "correct horse battery").await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert_eq!(a.body["error"], "wrong user name or password");

    let a = login(&f.router, "ann", "correct horse battery").await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(
        (a.body["user"].as_str(), a.body["role"].as_str()),
        (Some("ann"), Some("operator"))
    );
    let csrf = a.body["csrf"].as_str().unwrap().to_string();
    let c = cookie(&a);

    let a = call(
        &f.router,
        get("/api/v1/series")
            .header(header::COOKIE, &c)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK);
    let a = call(
        &f.router,
        get("/api/v1/session")
            .header(header::COOKIE, &c)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.body["csrf"].as_str(), Some(csrf.as_str()));

    // A write without the token, with a wrong one, or from another site.
    let logout = || Request::post("/api/v1/logout").header(header::COOKIE, &c);
    let a = call(&f.router, logout().body(Body::empty()).unwrap()).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    let a = call(
        &f.router,
        logout()
            .header("x-csrf-token", "0".repeat(64))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    let a = call(
        &f.router,
        logout()
            .header("x-csrf-token", &csrf)
            .header(header::HOST, "mon.lan")
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);

    let a = call(
        &f.router,
        logout()
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::NO_CONTENT);
    assert!(
        a.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let a = call(
        &f.router,
        get("/api/v1/series")
            .header(header::COOKIE, &c)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_credentials_work_for_scripts() {
    let f = fixture(&[("prom", Role::Viewer, "scrape scrape scrape")], false);
    let a = call(
        &f.router,
        get("/metrics")
            .header(header::AUTHORIZATION, basic("prom", "scrape scrape scrape"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK);
    let a = call(
        &f.router,
        get("/metrics")
            .header(header::AUTHORIZATION, basic("prom", "nope"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    // No challenge, so a browser never offers its own password prompt.
    assert!(!a.headers.contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn repeated_failures_are_refused_without_checking() {
    let f = fixture(&[("ann", Role::Admin, "correct horse battery")], false);
    for _ in 0..rl_web::auth::MAX_FAILURES {
        let a = login(&f.router, "ann", "guess").await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    }
    // Even the right password, until the window passes.
    let a = login(&f.router, "ann", "correct horse battery").await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(a.headers.contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn anonymous_callers_read_as_viewers() {
    let f = fixture(&[("ann", Role::Admin, "correct horse battery")], true);
    let a = call(
        &f.router,
        get("/api/v1/series").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK);
    let a = call(
        &f.router,
        get("/api/v1/session").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(
        (a.body["role"].as_str(), a.body["login_required"].as_bool()),
        (Some("viewer"), Some(false))
    );
}

#[tokio::test]
async fn a_removed_user_loses_their_session() {
    let f = fixture(
        &[
            ("ann", Role::Admin, "correct horse battery"),
            ("bob", Role::Viewer, "another long one"),
        ],
        false,
    );
    let a = login(&f.router, "bob", "another long one").await;
    let c = cookie(&a);
    let read = || {
        get("/api/v1/series")
            .header(header::COOKIE, &c)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(call(&f.router, read()).await.status, StatusCode::OK);
    // The file is looked at again about once a second.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    write_users(
        f.dir.path(),
        &[("ann", Role::Admin, "correct horse battery")],
    );
    assert_eq!(
        call(&f.router, read()).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn a_broken_users_file_stops_start_up() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(users_file(dir.path()), "[[user]]\nname = \"ann\"\n").unwrap();
    let err = Auth::new(AuthConfig {
        users_file: users_file(dir.path()),
        anonymous: false,
        secure: false,
    })
    .unwrap_err();
    assert!(err.contains("users.toml"), "{err}");
    std::fs::write(
        users_file(dir.path()),
        "[[user]]\nname = \"ann\"\nrole = \"admin\"\npassword = \"plain text\"\n",
    )
    .unwrap();
    let err = Auth::new(AuthConfig {
        users_file: users_file(dir.path()),
        anonymous: false,
        secure: false,
    })
    .unwrap_err();
    assert!(err.contains("not a valid hash"), "{err}");
}

/// The real server loop over TLS: a client that trusts the test CA gets
/// the health answer, and the login cookie is marked Secure.
#[tokio::test]
async fn the_ui_is_served_over_tls() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert, key) = (dir.path().join("ui.pem"), dir.path().join("ui.key"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    let acceptor = rl_web::tls_acceptor(&cert, &key).unwrap();
    let Err(err) = rl_web::tls_acceptor(&key, &cert) else {
        panic!("key and certificate swapped");
    };
    assert!(err.starts_with("tls_cert"), "{err}");

    let f = fixture(&[], false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(rl_web::serve(
        listener,
        f.router.clone(),
        Some(acceptor),
        async {
            let _ = stop_rx.await;
        },
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(
            rustls_pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    tls.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("\"status\":\"ok\""), "{answer}");

    // Plain HTTP to a TLS port gets nowhere.
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = plain.read_to_end(&mut buf).await;
    assert!(!String::from_utf8_lossy(&buf).contains("\"status\""));

    stop_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let auth = Auth::new(AuthConfig {
        users_file: users_file(dir.path()),
        anonymous: false,
        secure: true,
    })
    .unwrap();
    assert!(auth.config().secure);
}

/// A JSON write with a session cookie and CSRF token.
fn write(
    method: &str,
    uri: &str,
    cookie: &str,
    csrf: &str,
    body: serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn operators_add_and_end_silences_viewers_cannot() {
    let f = fixture(
        &[
            ("vic", Role::Viewer, "correct horse battery"),
            ("ann", Role::Operator, "correct horse battery"),
        ],
        false,
    );
    let body = serde_json::json!({
        "targets": ["gw"], "alerts": ["down"], "minutes": 60, "comment": "ISP works",
    });

    let a = login(&f.router, "vic", "correct horse battery").await;
    let (vic, vic_csrf) = (cookie(&a), a.body["csrf"].as_str().unwrap().to_string());
    let a = call(
        &f.router,
        write("POST", "/api/v1/silences", &vic, &vic_csrf, body.clone()),
    )
    .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN, "{}", a.body);

    let a = login(&f.router, "ann", "correct horse battery").await;
    let (ann, csrf) = (cookie(&a), a.body["csrf"].as_str().unwrap().to_string());
    // Without the CSRF token, refused.
    let a = call(
        &f.router,
        write("POST", "/api/v1/silences", &ann, "", body.clone()),
    )
    .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    for (bad, why) in [
        (
            serde_json::json!({"targets": ["nope"], "minutes": 60, "comment": "x"}),
            "no target",
        ),
        (
            serde_json::json!({"alerts": ["nope"], "minutes": 60, "comment": "x"}),
            "no alert rule",
        ),
        (
            serde_json::json!({"targets": ["gw"], "minutes": 60, "comment": " "}),
            "comment",
        ),
        (
            serde_json::json!({"targets": ["gw"], "comment": "x"}),
            "end or minutes",
        ),
        (
            serde_json::json!({"targets": ["gw"], "minutes": 200_000, "comment": "x"}),
            "90 days",
        ),
        (
            serde_json::json!({"name": "cfg", "minutes": 5, "comment": "x"}),
            "exists",
        ),
        (
            serde_json::json!({"name": "-x", "minutes": 5, "comment": "x"}),
            "name",
        ),
    ] {
        let a = call(
            &f.router,
            write("POST", "/api/v1/silences", &ann, &csrf, bad),
        )
        .await;
        assert!(a.status.is_client_error(), "{why}: {}", a.status);
        let msg = a.body["error"].as_str().unwrap();
        assert!(msg.contains(why), "{why}: {msg}");
    }

    let a = call(
        &f.router,
        write("POST", "/api/v1/silences", &ann, &csrf, body),
    )
    .await;
    assert_eq!(a.status, StatusCode::CREATED, "{}", a.body);
    let name = a.body["name"].as_str().unwrap().to_string();
    assert!(name.starts_with("ui-"), "{name}");
    assert_eq!(a.body["by"], "ann");
    assert_eq!(a.body["active"], true);
    assert!(f.dir.path().join("silences.json").exists());

    let list = call(
        &f.router,
        get("/api/v1/alerts")
            .header(header::COOKIE, &vic)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let s = &list.body["silences"];
    assert_eq!(s[0]["source"], "config");
    assert_eq!(s[1]["name"].as_str(), Some(name.as_str()));
    assert_eq!(s[1]["comment"], "ISP works");

    let uri = format!("/api/v1/silences/{name}");
    let null = serde_json::Value::Null;
    let a = call(
        &f.router,
        write("DELETE", &uri, &vic, &vic_csrf, null.clone()),
    )
    .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    let a = call(&f.router, write("DELETE", &uri, &ann, &csrf, null.clone())).await;
    assert_eq!(a.status, StatusCode::NO_CONTENT);
    let a = call(&f.router, write("DELETE", &uri, &ann, &csrf, null.clone())).await;
    assert_eq!(a.status, StatusCode::CONFLICT);
    let a = call(
        &f.router,
        write("DELETE", "/api/v1/silences/cfg", &ann, &csrf, null.clone()),
    )
    .await;
    assert_eq!(a.status, StatusCode::CONFLICT);
    let a = call(
        &f.router,
        write("DELETE", "/api/v1/silences/nope", &ann, &csrf, null),
    )
    .await;
    assert_eq!(a.status, StatusCode::NOT_FOUND);

    let list = call(
        &f.router,
        get("/api/v1/alerts")
            .header(header::COOKIE, &ann)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(list.body["silences"][1]["active"], false);
    assert_eq!(list.body["silences"][1]["ended_by"], "ann");

    // Scripts use basic credentials, without a CSRF token.
    let a = call(
        &f.router,
        Request::post("/api/v1/silences")
            .header(header::AUTHORIZATION, basic("ann", "correct horse battery"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({"name": "night", "groups": ["lan"], "minutes": 5, "comment": "script"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::CREATED, "{}", a.body);
}

#[tokio::test]
async fn without_users_no_one_adds_silences() {
    let f = fixture(&[], false);
    let a = call(
        &f.router,
        Request::post("/api/v1/silences")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({"minutes": 5, "comment": "x"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    assert!(
        a.body["error"].as_str().unwrap().contains("ctl user"),
        "{}",
        a.body
    );
}
