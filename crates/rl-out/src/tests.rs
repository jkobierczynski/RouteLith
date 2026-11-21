use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rl_core::output::{
    EventFilter, Framing, JsonlOutput, Output, OutputKind, SyslogFormat, SyslogOutput, Transport,
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
    let outs = Outputs::start(&[output(OutputKind::Syslog(cfg), 10)], HashMap::new()).unwrap();
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
    let outs = Outputs::start(&[output(OutputKind::Syslog(cfg), 10)], HashMap::new()).unwrap();
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
    let err = Outputs::start(&[bad], HashMap::new()).unwrap_err();
    assert!(err.contains("cannot open"), "{err}");
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
    fn deliver(&mut self, _: &Event) -> Result<(), String> {
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
