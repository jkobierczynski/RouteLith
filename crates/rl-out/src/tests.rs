use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rl_core::output::{
    EmailOutput, EventFilter, Framing, JsonlOutput, Output, OutputKind, SmtpSecurity, SyslogFormat,
    SyslogOutput, Transport, WebhookFormat, WebhookOutput,
};
use rl_store::{Event, EventKind};

use super::*;

const T: i64 = 1_800_000_000_123; // 2027-01-15T08:00:00.123Z

fn raised() -> Event {
    let mut e = Event::new(
        T,
        EventKind::AlertRaised,
        "local",
        "gw (v4): loss raised: loss 25% > 10% for 3 rounds",
    );
    e.target = Some("gw".into());
    e.family = Some("v4".into());
    e.series = Some(3);
    e.rule = Some("loss".into());
    e.value = Some(25.0);
    e.since = Some(T);
    e
}

fn header() -> Header {
    Header {
        facility: 16,
        hostname: "probe1".into(),
        app_name: "routelith".into(),
        procid: 4242,
        sd_id: "routelith@32473".into(),
    }
}

fn syslog(port: u16, transport: Transport) -> SyslogOutput {
    SyslogOutput {
        host: "127.0.0.1".into(),
        port,
        transport,
        format: SyslogFormat::Rfc5424,
        facility: 16,
        hostname: Some("probe1".into()),
        app_name: "routelith".into(),
        sd_id: "routelith@32473".into(),
        framing: Framing::OctetCounting,
        ca_file: None,
        cert_file: None,
        key_file: None,
        server_name: None,
    }
}

fn output(kind: OutputKind, queue: usize) -> Output {
    Output {
        name: "o".into(),
        kind,
        filter: EventFilter::default(),
        queue,
        line: 1,
    }
}

/// Checks a message against an RFC 5424 parser and returns it parsed.
fn parse(msg: &str) -> syslog_rfc5424::SyslogMessage {
    syslog_rfc5424::parse_message(msg).unwrap_or_else(|e| panic!("{e}: {msg}"))
}

fn check_parsed(m: &syslog_rfc5424::SyslogMessage) {
    assert_eq!(m.facility, syslog_rfc5424::SyslogFacility::LOG_LOCAL0);
    assert_eq!(m.severity, syslog_rfc5424::SyslogSeverity::SEV_WARNING);
    assert_eq!(m.hostname.as_deref(), Some("probe1"));
    assert_eq!(m.appname.as_deref(), Some("routelith"));
    assert_eq!(m.msgid.as_deref(), Some("alert_raised"));
    assert_eq!(m.timestamp, Some(1_800_000_000));
    assert_eq!(m.timestamp_nanos, Some(123_000_000));
    let sd = |k: &str| {
        m.sd.find_tuple("routelith@32473", k)
            .unwrap_or_else(|| panic!("no {k}"))
            .clone()
    };
    assert_eq!(sd("target"), "gw");
    assert_eq!(sd("rule"), "loss");
    assert_eq!(sd("value"), "25");
    assert_eq!(sd("since"), "2027-01-15T08:00:00.123Z");
    assert_eq!(m.msg, "gw (v4): loss raised: loss 25% > 10% for 3 rounds");
}

#[test]
fn rfc5424_messages_parse() {
    let line = format_rfc5424(&raised(), &header());
    assert_eq!(
        line,
        "<132>1 2027-01-15T08:00:00.123Z probe1 routelith 4242 alert_raised \
         [routelith@32473 vantage=\"local\" target=\"gw\" family=\"v4\" series=\"3\" \
         rule=\"loss\" value=\"25\" since=\"2027-01-15T08:00:00.123Z\"] \
         gw (v4): loss raised: loss 25% > 10% for 3 rounds"
    );
    check_parsed(&parse(&line));

    // Escapes, a UTF-8 message with its BOM, and an unknown hostname.
    let mut e = Event::new(T, EventKind::IpChanged, "lab \"A\" ]x\\", "café\nmoved");
    e.from = Some("192.0.2.1".into());
    let mut h = header();
    h.hostname = "-".into();
    let line = format_rfc5424(&e, &h);
    assert!(line.contains(r#"vantage="lab \"A\" \]x\\""#), "{line}");
    assert!(line.ends_with("] \u{feff}café moved"), "{line}");
    let m = parse(&line);
    assert_eq!(m.hostname, None);
    assert_eq!(m.severity, syslog_rfc5424::SyslogSeverity::SEV_NOTICE);
    assert_eq!(
        m.sd.find_tuple("routelith@32473", "vantage")
            .map(String::as_str),
        Some("lab \"A\" ]x\\")
    );
}

#[test]
fn rfc3164_messages() {
    let mut e = raised();
    e.t = 1_799_712_000_000 + 5 * 3_600_000; // 2027-01-12T05:00Z
    assert_eq!(
        format_rfc3164(&e, &header()),
        "<132>Jan 12 05:00:00 probe1 routelith[4242]: gw (v4): loss raised: loss 25% > 10% for 3 rounds"
    );
}

#[test]
fn filters_pick_events() {
    let groups: HashMap<String, String> = [("gw".to_string(), "Core".to_string())].into();
    let e = raised();
    let f = |f: EventFilter| passes(&f, &e, &groups);
    assert!(f(EventFilter::default()));
    assert!(f(EventFilter {
        events: vec!["alert_raised".into()],
        ..Default::default()
    }));
    assert!(!f(EventFilter {
        events: vec!["alert_cleared".into()],
        ..Default::default()
    }));
    assert!(f(EventFilter {
        groups: vec!["Core".into()],
        ..Default::default()
    }));
    assert!(!f(EventFilter {
        targets: vec!["other".into()],
        ..Default::default()
    }));
    assert!(!f(EventFilter {
        alerts: vec!["slow".into()],
        ..Default::default()
    }));
    // A server event has no target or rule.
    let start = Event::new(T, EventKind::ServerStarted, "local", "started");
    let rules_only = EventFilter {
        alerts: vec!["slow".into()],
        ..Default::default()
    };
    assert!(passes(&rules_only, &start, &groups));
    let targets_only = EventFilter {
        targets: vec!["gw".into()],
        ..Default::default()
    };
    assert!(!passes(&targets_only, &start, &groups));
    // Silenced and suppressed alerts stay unsent unless quiet = true.
    let mut quiet = raised();
    quiet.silenced_by = Some("maint".into());
    assert!(!passes(&EventFilter::default(), &quiet, &groups));
    quiet.silenced_by = None;
    quiet.suppressed_by = Some("core".into());
    assert!(!passes(&EventFilter::default(), &quiet, &groups));
    let loud = EventFilter {
        quiet: true,
        ..Default::default()
    };
    assert!(passes(&loud, &quiet, &groups));
}

/// Reads one octet-counted frame.
fn read_frame(r: &mut impl BufRead) -> String {
    let mut len = Vec::new();
    r.read_until(b' ', &mut len).unwrap();
    let n: usize = std::str::from_utf8(&len[..len.len() - 1])
        .unwrap()
        .parse()
        .unwrap();
    let mut buf = vec![0; n];
    r.read_exact(&mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn syslog_over_udp() {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let port = rx.local_addr().unwrap().port();
    let outs = Outputs::start(
        &[output(OutputKind::Syslog(syslog(port, Transport::Udp)), 10)],
        HashMap::new(),
        None,
    )
    .unwrap();
    outs.send(&raised());
    let mut buf = [0u8; 4096];
    let n = rx.recv(&mut buf).unwrap();
    check_parsed(&parse(std::str::from_utf8(&buf[..n]).unwrap()));
    let stats = outs.stats();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
}

#[test]
fn syslog_over_tcp_reconnects() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mut cfg = syslog(port, Transport::Tcp);
    let outs = Outputs::start(
        &[output(OutputKind::Syslog(cfg.clone()), 10)],
        HashMap::new(),
        None,
    )
    .unwrap();
    outs.send(&raised());
    let (s, _) = l.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut r = BufReader::new(s);
    check_parsed(&parse(&read_frame(&mut r)));
    // The receiver restarts: the next event goes on a new connection.
    drop(r);
    std::thread::sleep(Duration::from_millis(50));
    outs.send(&raised());
    let (s, _) = l.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    check_parsed(&parse(&read_frame(&mut BufReader::new(s))));
    let stats = outs.stats();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 2);
    assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 0);
    outs.close(Duration::from_secs(1));

    // LF framing.
    cfg.framing = Framing::Lf;
    let outs =
        Outputs::start(&[output(OutputKind::Syslog(cfg), 10)], HashMap::new(), None).unwrap();
    outs.send(&raised());
    let (s, _) = l.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    check_parsed(&parse(line.strip_suffix('\n').unwrap()));
    outs.close(Duration::from_secs(1));
}

#[test]
fn syslog_over_tls() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ck.cert.pem()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(ck.cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let receiver = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut c = rustls::ServerConnection::new(Arc::new(server)).unwrap();
        let tls = rustls::Stream::new(&mut c, &mut s);
        read_frame(&mut BufReader::new(tls))
    });
    let mut cfg = syslog(port, Transport::Tls);
    cfg.ca_file = Some(ca);
    cfg.server_name = Some("localhost".into());
    let outs =
        Outputs::start(&[output(OutputKind::Syslog(cfg), 10)], HashMap::new(), None).unwrap();
    outs.send(&raised());
    check_parsed(&parse(&receiver.join().unwrap()));
    outs.close(Duration::from_secs(1));
}

#[test]
fn a_down_receiver_never_blocks_the_sender() {
    // A port nobody listens on: every connection is refused.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let outs = Outputs::start(
        &[output(OutputKind::Syslog(syslog(port, Transport::Tcp)), 5)],
        HashMap::new(),
        None,
    )
    .unwrap();
    let started = Instant::now();
    for _ in 0..1000 {
        outs.send(&raised());
    }
    assert!(started.elapsed() < Duration::from_secs(1));
    let stats = outs.stats();
    // One in hand, five queued, the rest dropped.
    assert!(stats[0].dropped.load(Ordering::Relaxed) >= 994);
    wait_for("an error", || stats[0].errors.load(Ordering::Relaxed) >= 1);
    assert!(!stats[0].up.load(Ordering::Relaxed));
    let closing = Instant::now();
    outs.close(Duration::from_millis(100));
    assert!(closing.elapsed() < Duration::from_secs(3));
    assert_eq!(stats[0].sent.load(Ordering::Relaxed), 0);
    assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 1000);
    assert_eq!(stats[0].queued.load(Ordering::Relaxed), 0);
}

#[test]
fn jsonl_appends_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let outs = Outputs::start(
        &[output(
            OutputKind::Jsonl(JsonlOutput { path: path.clone() }),
            10,
        )],
        HashMap::new(),
        None,
    )
    .unwrap();
    outs.send(&raised());
    // Rotated away between events: the next one starts a new file.
    let stats = outs.stats();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    std::fs::rename(&path, dir.path().join("events.jsonl.1")).unwrap();
    let mut e = raised();
    e.kind = EventKind::AlertCleared;
    outs.send(&e);
    outs.close(Duration::from_secs(1));
    let read = |p: &std::path::Path| -> Vec<Event> {
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    };
    assert_eq!(read(&dir.path().join("events.jsonl.1")), vec![raised()]);
    assert_eq!(read(&path), vec![e]);

    // A file that cannot be opened stops start-up.
    let bad = output(
        OutputKind::Jsonl(JsonlOutput {
            path: dir.path().join("missing/events.jsonl"),
        }),
        10,
    );
    let err = Outputs::start(&[bad], HashMap::new(), None).unwrap_err();
    assert!(err.contains("cannot open"), "{err}");
    // Two spellings of one file: their lines would interleave.
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let alias = dir.path().join("sub/../events.jsonl");
    let outs = [
        output(OutputKind::Jsonl(JsonlOutput { path: path.clone() }), 10),
        output(OutputKind::Jsonl(JsonlOutput { path: alias }), 10),
    ];
    let err = Outputs::start(&outs, HashMap::new(), None).unwrap_err();
    assert!(err.contains("already writes"), "{err}");
}

#[test]
fn queued_events_are_delivered_at_close() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let outs = Outputs::start(
        &[output(
            OutputKind::Syslog(syslog(port, Transport::Tcp)),
            100,
        )],
        HashMap::new(),
        None,
    )
    .unwrap();
    for _ in 0..50 {
        outs.send(&raised());
    }
    let reader = std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut r = BufReader::new(s);
        (0..50).map(|_| read_frame(&mut r)).count()
    });
    let stats = outs.stats();
    outs.close(Duration::from_secs(5));
    assert_eq!(reader.join().unwrap(), 50);
    assert_eq!(stats[0].sent.load(Ordering::Relaxed), 50);
}

/// Takes 20 ms per event, and always works.
struct Slow;

impl Sink for Slow {
    fn deliver(&mut self, _: &Event) -> Result<(), Failure> {
        std::thread::sleep(Duration::from_millis(20));
        Ok(())
    }
}

#[test]
fn close_keeps_to_its_grace_with_a_slow_receiver() {
    let o = output(OutputKind::Jsonl(JsonlOutput { path: "x".into() }), 1000);
    let outs = Outputs::with_sinks(vec![(&o, Box::new(Slow))], HashMap::new()).unwrap();
    for _ in 0..500 {
        outs.send(&raised());
    }
    let stats = outs.stats();
    let closing = Instant::now();
    outs.close(Duration::from_millis(200));
    assert!(
        closing.elapsed() < Duration::from_secs(1),
        "{:?}",
        closing.elapsed()
    );
    let (sent, dropped) = (
        stats[0].sent.load(Ordering::Relaxed),
        stats[0].dropped.load(Ordering::Relaxed),
    );
    assert!(sent > 0 && dropped > 0, "{sent} {dropped}");
    assert_eq!(sent + dropped, 500);
}

#[test]
fn structured_data_stays_on_one_line() {
    let e = Event::new(T, EventKind::ServerStarted, "a\nb\rc", "x");
    let line = format_rfc5424(&e, &header());
    assert!(line.contains(r#"vantage="a b c""#), "{line}");
}

#[test]
fn a_tls_receiver_that_trickles_cannot_hold_the_handshake() {
    use std::io::Write;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    // A handshake record header promising 16 KiB, then one byte of it
    // every 100 ms: each read gets data, so only the deadline stops it.
    let trickle = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        if s.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).is_err() {
            return;
        }
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(100));
            if s.write_all(&[0]).is_err() {
                return;
            }
        }
    });
    let config = crate::tls::client_config(None, None, None).or_else(|_| {
        // No system roots here: any root will do, the handshake never ends.
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, ck.cert.pem()).unwrap();
        crate::tls::client_config(Some(&ca), None, None)
    });
    let mut c =
        rustls::ClientConnection::new(config.unwrap(), "localhost".try_into().unwrap()).unwrap();
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let started = Instant::now();
    let err = syslog::handshake(&mut c, &mut sock, started + Duration::from_secs(1)).unwrap_err();
    let took = started.elapsed();
    assert!(took < Duration::from_millis(1500), "{took:?}: {err}");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    drop(sock);
    let _ = trickle.join();
}

/// One HTTP request as a test server saw it.
#[derive(Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// Read one request (head and Content-Length body) and answer `code`.
fn serve_one(s: &mut (impl std::io::Read + std::io::Write), code: u16) -> Seen {
    let mut r = BufReader::new(&mut *s);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        head += &line;
    }
    let seen = Seen {
        head,
        body: Vec::new(),
    };
    let len: usize = seen.header("content-length").unwrap().parse().unwrap();
    let mut body = vec![0u8; len];
    std::io::Read::read_exact(&mut r, &mut body).unwrap();
    drop(r);
    write!(
        s,
        "HTTP/1.1 {code} Whatever\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    s.flush().unwrap();
    Seen { body, ..seen }
}

/// A plain HTTP server that answers each connection with the next code.
fn http_server(codes: Vec<u16>) -> (u16, std::thread::JoinHandle<Vec<Seen>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        codes
            .into_iter()
            .map(|code| {
                let (mut s, _) = l.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                serve_one(&mut s, code)
            })
            .collect()
    });
    (port, t)
}

fn webhook(url: &str, format: WebhookFormat) -> WebhookOutput {
    WebhookOutput {
        url: rl_core::config::parse_http_url(url).unwrap(),
        format,
        secret: None,
        token: None,
        ca_file: None,
    }
}

#[test]
fn webhook_retries_a_busy_receiver_and_signs() {
    let (port, server) = http_server(vec![503, 200]);
    let mut w = webhook(
        &format!("http://127.0.0.1:{port}/hook?k=1"),
        WebhookFormat::Json,
    );
    w.secret = Some(rl_core::secret::Secret::new("s3cr3t"));
    let outs = Outputs::start(&[output(OutputKind::Webhook(w), 10)], HashMap::new(), None).unwrap();
    let stats = outs.stats();
    outs.send(&raised());
    let seen = server.join().unwrap();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
    assert_eq!(stats[0].errors.load(Ordering::Relaxed), 1);
    assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 0);
    assert_eq!(seen.len(), 2);
    let req = &seen[1];
    assert!(
        req.head.starts_with("POST /hook?k=1 HTTP/1.1\r\n"),
        "{}",
        req.head
    );
    assert_eq!(
        req.header("host"),
        Some(format!("127.0.0.1:{port}").as_str())
    );
    assert_eq!(req.header("content-type"), Some("application/json"));
    assert_eq!(req.header("x-routelith-event"), Some("alert_raised"));
    let back: Event = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(back.rule.as_deref(), Some("loss"));
    // The receiver's check: HMAC of "{timestamp}.{body}".
    let ts = req.header("x-routelith-timestamp").unwrap();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"s3cr3t");
    let sig = req.header("x-routelith-signature").unwrap();
    let sig = sig.strip_prefix("sha256=").unwrap();
    let raw: Vec<u8> = (0..sig.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig[i..i + 2], 16).unwrap())
        .collect();
    let signed = [ts.as_bytes(), b".", &req.body].concat();
    ring::hmac::verify(&key, &signed, &raw).unwrap();
}

#[test]
fn webhook_drops_what_the_receiver_refuses() {
    let (port, server) = http_server(vec![400, 200]);
    let w = webhook(&format!("http://127.0.0.1:{port}/"), WebhookFormat::Slack);
    let outs = Outputs::start(&[output(OutputKind::Webhook(w), 10)], HashMap::new(), None).unwrap();
    let stats = outs.stats();
    let mut second = raised();
    second.message = "second <b>&".into();
    outs.send(&raised());
    outs.send(&second);
    let seen = server.join().unwrap();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
    // The refused event was not tried again: the next request is the
    // second event.
    assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 1);
    assert_eq!(stats[0].errors.load(Ordering::Relaxed), 1);
    let v: serde_json::Value = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(
        v["text"],
        "*Routelith: gw alert raised (loss)*\nsecond &lt;b&gt;&amp;"
    );
}

#[test]
fn webhook_over_https() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ck.cert.pem()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(ck.cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let receiver = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut c = rustls::ServerConnection::new(Arc::new(server)).unwrap();
        let mut tls = rustls::Stream::new(&mut c, &mut s);
        let seen = serve_one(&mut tls, 200);
        c.send_close_notify();
        let _ = c.write_tls(&mut s);
        seen
    });
    let mut w = webhook(
        &format!("https://localhost:{port}/message"),
        WebhookFormat::Gotify,
    );
    w.ca_file = Some(ca);
    w.token = Some(rl_core::secret::Secret::new("AbC.123"));
    let outs = Outputs::start(&[output(OutputKind::Webhook(w), 10)], HashMap::new(), None).unwrap();
    let stats = outs.stats();
    outs.send(&raised());
    let seen = receiver.join().unwrap();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
    assert_eq!(
        seen.header("host"),
        Some(format!("localhost:{port}").as_str())
    );
    assert_eq!(seen.header("x-gotify-key"), Some("AbC.123"));
    let v: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(v["priority"], 8);
    assert_eq!(v["title"], "Routelith: gw alert raised (loss)");
}

#[test]
fn webhook_formats() {
    let e = raised();
    let mut w = webhook("http://ntfy.lan/alerts", WebhookFormat::Ntfy);
    w.token = Some(rl_core::secret::Secret::new("tk"));
    let r = webhook::request(&w, &e, 0);
    assert_eq!(r.body, e.message.as_bytes());
    assert!(r.headers.contains(&("Priority", "4".into())));
    assert!(r.headers.contains(&("Tags", "warning".into())));
    assert!(r.headers.contains(&("Authorization", "Bearer tk".into())));
    let mut cleared = Event::new(T, EventKind::AlertCleared, "local", "ok");
    cleared.target = Some("r\u{e9}seau".into());
    let r = webhook::request(&w, &cleared, 0);
    assert!(r.headers.contains(&("Priority", "3".into())));
    // Not ASCII: an RFC 2047 encoded word.
    let title = &r.headers.iter().find(|h| h.0 == "Title").unwrap().1;
    assert!(
        title.starts_with("=?UTF-8?B?") && title.is_ascii(),
        "{title}"
    );

    let r = webhook::request(&webhook("http://x/", WebhookFormat::Teams), &e, 0);
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    let card = &v["attachments"][0]["content"];
    assert_eq!(card["type"], "AdaptiveCard");
    let facts = card["body"][2]["facts"].as_array().unwrap();
    assert!(
        facts
            .iter()
            .any(|f| f["title"] == "Rule" && f["value"] == "loss")
    );

    let r = webhook::request(&webhook("http://x/", WebhookFormat::Mattermost), &e, 0);
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["username"], "Routelith");

    // Unsigned JSON has no signature headers.
    let r = webhook::request(&webhook("http://x/", WebhookFormat::Json), &e, 0);
    assert!(r.headers.iter().all(|h| !h.0.contains("Signature")));
}

/// What a test SMTP server saw in one session.
#[derive(Debug, Default)]
struct Mail {
    auth: Option<String>,
    rcpt: Vec<String>,
    data: String,
}

enum Next {
    Done,
    StartTls,
}

/// One SMTP dialogue: RCPT gets `rcpt_code`; STARTTLS is offered when
/// `offer_tls`, else AUTH PLAIN.
fn smtp_dialog<S: std::io::Read + std::io::Write>(
    r: &mut BufReader<S>,
    rcpt_code: u16,
    offer_tls: bool,
    m: &mut Mail,
) -> Next {
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return Next::Done;
        }
        let up = line.to_ascii_uppercase();
        let reply = if up.starts_with("EHLO") {
            if offer_tls {
                "250-test\r\n250 STARTTLS\r\n".to_string()
            } else {
                "250-test\r\n250 AUTH PLAIN\r\n".to_string()
            }
        } else if up.starts_with("STARTTLS") {
            r.get_mut().write_all(b"220 go ahead\r\n").unwrap();
            return Next::StartTls;
        } else if up.starts_with("AUTH PLAIN") {
            m.auth = Some(line[10..].trim().to_string());
            "235 ok\r\n".to_string()
        } else if up.starts_with("RCPT") {
            m.rcpt.push(line.trim().to_string());
            format!("{rcpt_code} rcpt\r\n")
        } else if up.starts_with("DATA") {
            r.get_mut().write_all(b"354 go\r\n").unwrap();
            loop {
                let mut l = String::new();
                if r.read_line(&mut l).unwrap_or(0) == 0 || l == ".\r\n" {
                    break;
                }
                m.data += &l;
            }
            "250 queued\r\n".to_string()
        } else if up.starts_with("QUIT") {
            let _ = r.get_mut().write_all(b"221 bye\r\n");
            return Next::Done;
        } else {
            "250 ok\r\n".to_string()
        };
        r.get_mut().write_all(reply.as_bytes()).unwrap();
        r.get_mut().flush().unwrap();
    }
}

/// A plain SMTP server answering RCPT on each connection with the next code.
fn smtp_server(codes: Vec<u16>) -> (u16, std::thread::JoinHandle<Vec<Mail>>) {
    use std::io::Write;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        codes
            .into_iter()
            .map(|code| {
                let (mut s, _) = l.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                s.write_all(b"220 test ESMTP\r\n").unwrap();
                let mut m = Mail::default();
                smtp_dialog(&mut BufReader::new(s), code, false, &mut m);
                m
            })
            .collect()
    });
    (port, t)
}

fn email(port: u16, security: SmtpSecurity) -> EmailOutput {
    EmailOutput {
        host: "127.0.0.1".into(),
        port,
        security,
        username: None,
        password: None,
        from: "Routelith <routelith@example.net>".into(),
        to: vec!["noc@example.net".into()],
        ca_file: None,
        graph: Some(Duration::from_secs(3600)),
    }
}

fn fake_graph() -> GraphFn {
    Arc::new(|e: &Event, span: Duration| {
        assert_eq!(span, Duration::from_secs(3600));
        Ok(e.series.map(|_| b"\x89PNG not really".to_vec()))
    })
}

#[test]
fn email_retries_a_busy_server_and_attaches_the_graph() {
    let (port, server) = smtp_server(vec![451, 250]);
    let o = output(OutputKind::Email(email(port, SmtpSecurity::None)), 10);
    let outs = Outputs::start(&[o], HashMap::new(), Some(fake_graph())).unwrap();
    let stats = outs.stats();
    outs.send(&raised());
    let mails = server.join().unwrap();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
    assert_eq!(stats[0].errors.load(Ordering::Relaxed), 1);
    assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 0);
    assert!(mails[0].data.is_empty(), "{:?}", mails[0]);
    let data = &mails[1].data;
    assert!(
        mails[1].rcpt[0].contains("<noc@example.net>"),
        "{:?}",
        mails[1]
    );
    assert!(
        data.contains("Subject: Routelith: gw alert raised (loss)"),
        "{data}"
    );
    assert!(
        data.contains("From: Routelith <routelith@example.net>"),
        "{data}"
    );
    assert!(data.contains("Rule: loss"), "{data}");
    assert!(
        data.contains("image/png") && data.contains("graph.png"),
        "{data}"
    );
}

#[test]
fn email_drops_what_the_server_refuses() {
    let (port, server) = smtp_server(vec![550, 250]);
    let o = output(OutputKind::Email(email(port, SmtpSecurity::None)), 10);
    let outs = Outputs::start(&[o], HashMap::new(), Some(fake_graph())).unwrap();
    let stats = outs.stats();
    // No series: no graph.
    let started = Event::new(T, EventKind::ServerStarted, "local", "started");
    outs.send(&raised());
    outs.send(&started);
    let mails = server.join().unwrap();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
    assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 1);
    assert!(
        mails[1].data.contains("Subject: Routelith: server started"),
        "{:?}",
        mails[1]
    );
    assert!(!mails[1].data.contains("graph.png"), "{:?}", mails[1]);
}

#[test]
fn email_with_starttls_and_login() {
    use std::io::Write;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ck.cert.pem()).unwrap();
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(ck.cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
        )
        .unwrap(),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let receiver = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(b"220 test ESMTP\r\n").unwrap();
        let mut m = Mail::default();
        let mut plain = BufReader::new(s);
        let Next::StartTls = smtp_dialog(&mut plain, 250, true, &mut m) else {
            panic!("no STARTTLS: {m:?}");
        };
        let c = rustls::ServerConnection::new(server).unwrap();
        let tls = rustls::StreamOwned::new(c, plain.into_inner());
        smtp_dialog(&mut BufReader::new(tls), 250, false, &mut m);
        m
    });
    let mut cfg = email(port, SmtpSecurity::StartTls);
    cfg.ca_file = Some(ca);
    cfg.username = Some("routelith".into());
    cfg.password = Some(rl_core::secret::Secret::new("hunter2"));
    let o = output(OutputKind::Email(cfg), 10);
    let outs = Outputs::start(&[o], HashMap::new(), None).unwrap();
    let stats = outs.stats();
    outs.send(&raised());
    let m = receiver.join().unwrap();
    wait_for("sent", || stats[0].sent.load(Ordering::Relaxed) == 1);
    outs.close(Duration::from_secs(1));
    // AUTH PLAIN: base64 of "\0routelith\0hunter2".
    assert_eq!(m.auth.as_deref(), Some("AHJvdXRlbGl0aABodW50ZXIy"), "{m:?}");
    assert!(
        m.data.contains("Subject: Routelith: gw alert raised"),
        "{m:?}"
    );
}
