//! HTTP(S) probe (architecture doc §4.6).
//!
//! Each sample is one request on a fresh connection (no keep-alive, so
//! samples are comparable): TCP connect, TLS handshake for https, request,
//! first response byte, then up to [`BODY_LIMIT`] bytes of body. Every phase
//! is timed with the monotonic clock and reported in [`HttpRound`]; the
//! sample itself stores the configured metric (ttfb by default).
//!
//! TLS uses rustls with the ring provider and the system's trust store,
//! plus an optional PEM file. The host is resolved once per round by the
//! scheduler, so name resolution is not one of the phases.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::header::{CONNECTION, HOST, USER_AGENT};
use hyper_util::rt::TokioIo;
use regex::bytes::Regex;
use rl_core::config::{BODY_LIMIT, HttpConfig, HttpMethod, HttpMetric};
use rl_core::{
    HttpRound, PhaseTimings, ProbeMeta, ResolvedTarget, RoundPlan, RoundResult, Sample,
    SampleError, TimingBackend, TimingSource,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpSocket;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_rustls::TlsConnector;

use crate::{BoxFuture, Probe, ProbeError, ProbeKind, RateLimiter};

/// HTTP(S) probe for one target's request.
#[derive(Debug)]
pub struct HttpProbe {
    shared: Arc<Shared>,
    limiter: Option<Arc<RateLimiter>>,
}

struct Shared {
    cfg: HttpConfig,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    body_regex: Option<Regex>,
    user_agent: String,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("cfg", &self.cfg)
            .field("tls_name", &self.tls.as_ref().map(|(_, n)| n))
            .finish_non_exhaustive()
    }
}

impl HttpProbe {
    /// Builds the TLS client (loading the system trust store and `ca_file`)
    /// and compiles `body_regex`.
    pub fn new(cfg: HttpConfig) -> Result<Self, ProbeError> {
        let err = |msg: String| ProbeError::Io(io::Error::other(msg));
        let body_regex = cfg
            .body_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| err(format!("body_regex: {e}")))?;
        let tls = if cfg.tls {
            let config = client_config(&cfg).map_err(err)?;
            let name = cfg.sni.as_deref().unwrap_or(&cfg.host);
            let name = ServerName::try_from(name.to_string())
                .map_err(|e| err(format!("TLS server name {name:?}: {e}")))?;
            Some((TlsConnector::from(Arc::new(config)), name))
        } else {
            None
        };
        Ok(Self {
            shared: Arc::new(Shared {
                cfg,
                tls,
                body_regex,
                user_agent: format!("routelith/{}", env!("CARGO_PKG_VERSION")),
            }),
            limiter: None,
        })
    }

    /// Share a packets-per-second ceiling with other probes (one request
    /// counts as one packet).
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    pub fn config(&self) -> &HttpConfig {
        &self.shared.cfg
    }

    async fn round(&self, target: &ResolvedTarget, plan: RoundPlan) -> RoundResult {
        let dest = SocketAddr::new(target.addr, self.shared.cfg.port);
        let t0 = Instant::now();
        let mut tasks = JoinSet::new();
        for i in 0..plan.count {
            let at = t0 + plan.sample_offset(i);
            let limiter = self.limiter.clone();
            let shared = Arc::clone(&self.shared);
            let timeout = plan.timeout;
            tasks.spawn(async move {
                sleep_until(at).await;
                if let Some(l) = limiter {
                    l.acquire().await;
                }
                (i, sample(&shared, dest, timeout).await)
            });
        }
        let n = usize::from(plan.count);
        let mut samples = vec![Sample::Lost; n];
        let mut phases = vec![None; n];
        let mut cert: Option<(u16, SystemTime)> = None;
        while let Some(joined) = tasks.join_next().await {
            // A sample task that panicked stays `Lost`.
            if let Ok((i, out)) = joined {
                samples[usize::from(i)] = out.sample;
                phases[usize::from(i)] = out.phases;
                if let Some(t) = out.cert_not_after {
                    if cert.is_none_or(|(j, _)| i > j) {
                        cert = Some((i, t));
                    }
                }
            }
        }
        RoundResult {
            start: plan.round_start,
            samples,
            meta: ProbeMeta {
                resolved: target.addr,
                timing: TimingSource::new(TimingBackend::Monotonic),
                payload_size: 0,
            },
            http: Some(HttpRound {
                phases,
                cert_not_after: cert.map(|(_, t)| t),
            }),
        }
    }
}

impl Probe for HttpProbe {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Http
    }

    fn run_round<'a>(
        &'a self,
        target: &'a ResolvedTarget,
        plan: RoundPlan,
    ) -> BoxFuture<'a, Result<RoundResult, ProbeError>> {
        Box::pin(async move { Ok(self.round(target, plan).await) })
    }
}

/// The result of one request.
struct Outcome {
    sample: Sample,
    phases: Option<PhaseTimings>,
    cert_not_after: Option<SystemTime>,
}

impl Outcome {
    fn failed(sample: Sample) -> Self {
        Self {
            sample,
            phases: None,
            cert_not_after: None,
        }
    }
}

async fn sample(s: &Shared, dest: SocketAddr, timeout: Duration) -> Outcome {
    let start = Instant::now();
    let deadline = start + timeout;
    match timeout_at(deadline, request(s, dest, start)).await {
        Err(_) => Outcome::failed(Sample::Lost),
        Ok(out) => out,
    }
}

async fn request(s: &Shared, dest: SocketAddr, start: Instant) -> Outcome {
    let socket = match open(dest) {
        Ok(sock) => sock,
        Err(e) => return Outcome::failed(Sample::Error(SampleError::SendFailed(e.to_string()))),
    };
    let tcp = match socket.connect(dest).await {
        Ok(t) => t,
        Err(e) => {
            let rtt = micros(start.elapsed());
            let err = match e.kind() {
                io::ErrorKind::ConnectionRefused => SampleError::Refused { rtt_us: rtt },
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable => {
                    SampleError::SendFailed(e.to_string())
                }
                _ => SampleError::Other(format!("connect failed: {e}")),
            };
            return Outcome::failed(Sample::Error(err));
        }
    };
    let connect = start.elapsed();
    match &s.tls {
        None => exchange(s, tcp, start, connect, None, None).await,
        Some((connector, name)) => match connector.connect(name.clone(), tcp).await {
            Err(e) => Outcome::failed(Sample::Error(SampleError::Tls(e.to_string()))),
            Ok(stream) => {
                let tls = start.elapsed() - connect;
                let cert = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .and_then(|c| crate::x509::not_after(c));
                exchange(s, stream, start, connect, Some(tls), cert).await
            }
        },
    }
}

/// Send the request on an established connection and read the response.
async fn exchange<S>(
    s: &Shared,
    stream: S,
    start: Instant,
    connect: Duration,
    tls: Option<Duration>,
    cert_not_after: Option<SystemTime>,
) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let fail = |e: SampleError| Outcome {
        sample: Sample::Error(e),
        phases: None,
        cert_not_after,
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    {
        Ok(x) => x,
        Err(e) => return fail(SampleError::Other(format!("HTTP: {e}"))),
    };
    // Drives the connection; ends when the response is done or dropped.
    let driver = tokio::spawn(conn);
    let cfg = &s.cfg;
    let host = if cfg.port == if cfg.tls { 443 } else { 80 } {
        bracket(&cfg.host)
    } else {
        format!("{}:{}", bracket(&cfg.host), cfg.port)
    };
    let req = Request::builder()
        .method(cfg.method.as_str())
        .uri(&cfg.path)
        .header(HOST, host)
        .header(USER_AGENT, &s.user_agent)
        .header(CONNECTION, "close")
        .body(Empty::<Bytes>::new());
    let req = match req {
        Ok(r) => r,
        Err(e) => return fail(SampleError::Other(format!("bad request: {e}"))),
    };
    let resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            driver.abort();
            return fail(SampleError::Other(format!("HTTP: {e}")));
        }
    };
    let ttfb = start.elapsed();
    let status = resp.status().as_u16();
    let mut body = resp.into_body();
    let mut read = Vec::new();
    if cfg.method != HttpMethod::Head {
        while read.len() < BODY_LIMIT {
            match body.frame().await {
                None => break,
                Some(Err(e)) => {
                    driver.abort();
                    return fail(SampleError::Other(format!("reading body: {e}")));
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        let room = BODY_LIMIT - read.len();
                        read.extend_from_slice(&data[..data.len().min(room)]);
                    }
                }
            }
        }
    }
    let total = start.elapsed();
    driver.abort();

    let phases = PhaseTimings {
        connect_us: micros(connect),
        tls_us: tls.map(micros),
        ttfb_us: micros(ttfb),
        total_us: micros(total),
    };
    let sample = if !cfg
        .expect_status
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&status))
    {
        Sample::Error(SampleError::HttpStatus { status })
    } else if s.body_regex.as_ref().is_some_and(|r| !r.is_match(&read)) {
        Sample::Error(SampleError::BodyMismatch)
    } else {
        let us = match cfg.metric {
            HttpMetric::Ttfb => phases.ttfb_us,
            HttpMetric::Total => phases.total_us,
            HttpMetric::Connect => phases.connect_us,
            HttpMetric::Tls => phases.tls_us.unwrap_or(0),
        };
        Sample::Ok { rtt_us: us }
    };
    Outcome {
        sample,
        phases: Some(phases),
        cert_not_after,
    }
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn open(dest: SocketAddr) -> io::Result<TcpSocket> {
    let socket = if dest.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_zero_linger()?;
    socket.set_nodelay(true)?;
    Ok(socket)
}

fn micros(d: Duration) -> u32 {
    u32::try_from(d.as_micros()).unwrap_or(u32::MAX)
}

/// The TLS client: system roots plus `ca_file`, or no verification at all
/// when `tls_verify` is off. HTTP/1.1 only.
fn client_config(cfg: &HttpConfig) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup: {e}"))?;
    let mut config = if cfg.tls_verify {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        let (added, _) = roots.add_parsable_certificates(native.certs);
        if let Some(path) = &cfg.ca_file {
            let certs = CertificateDer::pem_file_iter(path)
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map_err(|e| format!("ca_file {}: {e}", path.display()))?;
            if certs.is_empty() {
                return Err(format!("ca_file {}: no certificates found", path.display()));
            }
            let (ok, bad) = roots.add_parsable_certificates(certs);
            if ok == 0 {
                return Err(format!(
                    "ca_file {}: {bad} certificate(s), none usable",
                    path.display()
                ));
            }
        } else if added == 0 {
            return Err(
                "no trusted CA certificates: the system store is empty or unreadable; \
                 set ca_file"
                    .into(),
            );
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// `tls_verify = false`: accepts any certificate, but still checks that the
/// handshake was signed by its key.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_core::config::parse_http_url;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn cfg(url: &str) -> HttpConfig {
        let u = parse_http_url(url).unwrap();
        HttpConfig {
            url: url.into(),
            tls: u.tls,
            host: u.host,
            port: u.port,
            path: u.path,
            method: HttpMethod::Get,
            expect_status: vec![(200, 299)],
            metric: HttpMetric::Ttfb,
            body_regex: None,
            tls_verify: true,
            ca_file: None,
            sni: None,
        }
    }

    fn plan(count: u16) -> RoundPlan {
        RoundPlan {
            count,
            spread: Duration::from_millis(5 * u64::from(count)),
            timeout: Duration::from_secs(5),
            round_start: SystemTime::now(),
        }
    }

    fn target() -> ResolvedTarget {
        ResolvedTarget {
            name: "lo".into(),
            addr: Ipv4Addr::LOCALHOST.into(),
        }
    }

    /// Read a request head and answer with `status` and `body` after
    /// `delay`. Returns the request heads it saw.
    async fn serve<S>(mut s: S, status: u16, body: &'static str, delay: Duration) -> String
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        tokio::time::sleep(delay).await;
        let resp = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = s.write_all(resp.as_bytes()).await;
        let _ = s.shutdown().await;
        String::from_utf8_lossy(&head).into_owned()
    }

    async fn plain_server(
        status: u16,
        body: &'static str,
        delay: Duration,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(serve(s, status, body, delay).await);
                });
            }
        });
        (port, rx)
    }

    #[tokio::test]
    async fn http_phases_and_ttfb() {
        let (port, mut heads) = plain_server(200, "ok", Duration::from_millis(20)).await;
        let probe = HttpProbe::new(cfg(&format!("http://lab.test:{port}/health?x=1"))).unwrap();
        let round = probe.run_round(&target(), plan(3)).await.unwrap();
        let http = round.http.unwrap();
        for (s, p) in round.samples.iter().zip(&http.phases) {
            let p = p.unwrap();
            assert_eq!(s.rtt_us(), Some(p.ttfb_us), "{s:?}");
            assert!(p.ttfb_us >= 20_000, "{p:?}");
            assert!(
                p.connect_us <= p.ttfb_us && p.ttfb_us <= p.total_us,
                "{p:?}"
            );
            assert_eq!(p.tls_us, None);
        }
        let head = heads.recv().await.unwrap();
        assert!(head.starts_with("GET /health?x=1 HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains(&format!("host: lab.test:{port}\r\n")),
            "{head}"
        );
        assert_eq!(http.cert_not_after, None);
    }

    #[tokio::test]
    async fn unexpected_status_and_body_are_errors() {
        let (port, _) = plain_server(503, "down", Duration::ZERO).await;
        let probe = HttpProbe::new(cfg(&format!("http://127.0.0.1:{port}/"))).unwrap();
        let round = probe.run_round(&target(), plan(1)).await.unwrap();
        assert_eq!(
            round.samples[0],
            Sample::Error(SampleError::HttpStatus { status: 503 })
        );
        // The phases are still known.
        assert!(round.http.unwrap().phases[0].is_some());

        let (port, _) = plain_server(200, "status: degraded", Duration::ZERO).await;
        let mut c = cfg(&format!("http://127.0.0.1:{port}/"));
        c.body_regex = Some("status: (ok|fine)".into());
        let round = HttpProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(1))
            .await
            .unwrap();
        assert_eq!(round.samples[0], Sample::Error(SampleError::BodyMismatch));
    }

    #[tokio::test]
    async fn a_closed_port_is_refused() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let probe = HttpProbe::new(cfg(&format!("http://127.0.0.1:{port}/"))).unwrap();
        let round = probe.run_round(&target(), plan(1)).await.unwrap();
        assert!(
            matches!(round.samples[0], Sample::Error(SampleError::Refused { .. })),
            "{:?}",
            round.samples
        );
    }

    /// A TLS server with a fresh self-signed certificate for `lab.test`;
    /// returns its port and the certificate PEM.
    async fn tls_server() -> (u16, String) {
        let mut params = rcgen::CertificateParams::new(vec!["lab.test".into()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 6, 15);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(s).await {
                        serve(tls, 200, "ok", Duration::ZERO).await;
                    }
                });
            }
        });
        (port, pem)
    }

    #[tokio::test]
    async fn https_with_a_private_ca() {
        let (port, pem) = tls_server().await;
        let dir = std::env::temp_dir().join(format!("rl-http-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, pem).unwrap();

        let mut c = cfg(&format!("https://lab.test:{port}/"));
        c.ca_file = Some(ca);
        c.metric = HttpMetric::Tls;
        let round = HttpProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(2))
            .await
            .unwrap();
        let http = round.http.unwrap();
        for (s, p) in round.samples.iter().zip(&http.phases) {
            let tls = p.unwrap().tls_us.expect("an https sample has a TLS phase");
            assert_eq!(s.rtt_us(), Some(tls), "{s:?}");
        }
        let days = http
            .cert_not_after
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 86_400;
        // 2031-06-15
        assert_eq!(days, 22_445);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_untrusted_certificate_fails_unless_verification_is_off() {
        let (port, _) = tls_server().await;
        let dir = std::env::temp_dir().join(format!("rl-http-other-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Trust some other CA only.
        let other = rcgen::CertificateParams::new(vec!["other.test".into()])
            .unwrap()
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let ca = dir.join("other.pem");
        std::fs::write(&ca, other.pem()).unwrap();

        let mut c = cfg(&format!("https://lab.test:{port}/"));
        c.ca_file = Some(ca);
        let round = HttpProbe::new(c.clone())
            .unwrap()
            .run_round(&target(), plan(1))
            .await
            .unwrap();
        assert!(
            matches!(&round.samples[0], Sample::Error(SampleError::Tls(_))),
            "{:?}",
            round.samples
        );

        c.ca_file = None;
        c.tls_verify = false;
        let round = HttpProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(1))
            .await
            .unwrap();
        assert!(
            matches!(round.samples[0], Sample::Ok { .. }),
            "{:?}",
            round.samples
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_bad_regex_is_reported_at_start() {
        let mut c = cfg("http://h/");
        c.body_regex = Some("(".into());
        assert!(
            HttpProbe::new(c)
                .unwrap_err()
                .to_string()
                .contains("body_regex")
        );
    }
}
