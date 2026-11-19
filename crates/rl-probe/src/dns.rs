//! DNS query probe (architecture doc §4.5).
//!
//! Every sample is one real query to the configured server on its own
//! socket, bypassing any local resolver cache. Over UDP the time runs from
//! sending the query to receiving the response with the same id; over TCP a
//! fresh connection is opened per sample and the time includes the
//! handshake. `{rand}` in the query name becomes a fresh random label per
//! sample, so the server's cache cannot answer and the recursion path is
//! measured.
//!
//! A response with an unexpected rcode or answer set is
//! [`SampleError::DnsMismatch`], not a loss: the server answered.

use std::collections::BTreeSet;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use rl_core::config::{DnsConfig, DnsTransport};
use rl_core::{
    ProbeMeta, ResolvedTarget, RoundPlan, RoundResult, Sample, SampleError, TimingBackend,
    TimingSource,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::{BoxFuture, Probe, ProbeError, ProbeKind, RateLimiter};

/// Largest UDP response accepted (EDNS is not requested, so 512 is typical).
const MAX_UDP: usize = 4096;

/// DNS probe for one target's query.
#[derive(Debug)]
pub struct DnsProbe {
    config: Arc<Prepared>,
    limiter: Option<Arc<RateLimiter>>,
}

/// The configuration, parsed once.
#[derive(Debug)]
struct Prepared {
    cfg: DnsConfig,
    qtype: RecordType,
    rcode: u16,
    /// Normalised expected answers.
    answers: Option<BTreeSet<String>>,
}

impl DnsProbe {
    /// Fails if the record type or rcode is unknown; config validation
    /// accepts only known ones.
    pub fn new(cfg: DnsConfig) -> Result<Self, ProbeError> {
        let qtype = RecordType::from_str(&cfg.qtype).map_err(|_| {
            ProbeError::Io(io::Error::other(format!(
                "unknown record type {:?}",
                cfg.qtype
            )))
        })?;
        let rcode = rcode_number(&cfg.expect_rcode).ok_or_else(|| {
            ProbeError::Io(io::Error::other(format!(
                "unknown rcode {:?}",
                cfg.expect_rcode
            )))
        })?;
        if cfg.expect_answers.is_some() && matches!(qtype, RecordType::DS | RecordType::DNSKEY) {
            return Err(ProbeError::Io(io::Error::other(format!(
                "expected answers are not supported for {qtype} queries (their answers are not decoded)"
            ))));
        }
        let answers = cfg
            .expect_answers
            .as_ref()
            .map(|a| a.iter().map(|s| normalise(s)).collect());
        let prepared = Prepared {
            cfg,
            qtype,
            rcode,
            answers,
        };
        // A query name that cannot be sent fails here, not in every sample.
        build_query(&prepared, 0).map_err(|e| ProbeError::Io(io::Error::other(e)))?;
        Ok(Self {
            config: Arc::new(prepared),
            limiter: None,
        })
    }

    /// Share a packets-per-second ceiling with other probes.
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config.cfg
    }

    async fn round(&self, target: &ResolvedTarget, plan: RoundPlan) -> RoundResult {
        let dest = SocketAddr::new(target.addr, self.config.cfg.port);
        let t0 = Instant::now();
        let mut tasks = JoinSet::new();
        for i in 0..plan.count {
            let at = t0 + plan.sample_offset(i);
            let limiter = self.limiter.clone();
            let p = Arc::clone(&self.config);
            let timeout = plan.timeout;
            tasks.spawn(async move {
                sleep_until(at).await;
                if let Some(l) = limiter {
                    l.acquire().await;
                }
                (i, sample(&p, dest, timeout).await)
            });
        }
        let mut samples = vec![Sample::Lost; usize::from(plan.count)];
        while let Some(joined) = tasks.join_next().await {
            // A sample task that panicked stays `Lost`.
            if let Ok((i, s)) = joined {
                samples[usize::from(i)] = s;
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
        }
    }
}

impl Probe for DnsProbe {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Dns
    }

    fn run_round<'a>(
        &'a self,
        target: &'a ResolvedTarget,
        plan: RoundPlan,
    ) -> BoxFuture<'a, Result<RoundResult, ProbeError>> {
        Box::pin(async move { Ok(self.round(target, plan).await) })
    }
}

/// One query.
async fn sample(p: &Prepared, dest: SocketAddr, timeout: Duration) -> Sample {
    let id = random_u64() as u16;
    let query = match build_query(p, id) {
        Ok(q) => q,
        Err(e) => return Sample::Error(SampleError::SendFailed(e)),
    };
    let deadline = Instant::now() + timeout;
    // UDP is timed from the send to the answer; TCP from the start of the
    // handshake, which is part of what a TCP resolver client waits for.
    let exchanged = match p.cfg.transport {
        DnsTransport::Udp => timeout_at(deadline, udp_exchange(dest, &query, id)).await,
        DnsTransport::Tcp => {
            timeout_at(deadline, async {
                let start = Instant::now();
                let r = tcp_exchange(dest, &query).await?;
                Ok((r, start.elapsed()))
            })
            .await
        }
    };
    let (response, rtt) = match exchanged {
        Err(_) => return Sample::Lost,
        Ok(Err(Failure::Local(e))) => return Sample::Error(SampleError::SendFailed(e)),
        Ok(Err(Failure::Remote(e))) => return Sample::Error(SampleError::Other(e)),
        Ok(Ok(r)) => r,
    };
    match check(p, &response, id) {
        Ok(()) => Sample::Ok {
            rtt_us: u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX),
        },
        Err(e) => Sample::Error(e),
    }
}

enum Failure {
    /// The query never left this host.
    Local(String),
    /// The server or the network answered with something unusable.
    Remote(String),
}

fn local(e: &io::Error) -> Failure {
    Failure::Local(e.to_string())
}

async fn udp_exchange(
    dest: SocketAddr,
    query: &[u8],
    id: u16,
) -> Result<(Vec<u8>, Duration), Failure> {
    let bind: SocketAddr = if dest.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).await.map_err(|e| local(&e))?;
    socket.connect(dest).await.map_err(|e| local(&e))?;
    let start = Instant::now();
    socket.send(query).await.map_err(|e| local(&e))?;
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            // An ICMP port unreachable surfaces as a refused receive.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                return Err(Failure::Remote("port unreachable".to_owned()));
            }
            Err(e) => return Err(Failure::Remote(e.to_string())),
        };
        // A stray or spoofed datagram with another id is ignored.
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            let rtt = start.elapsed();
            buf.truncate(n);
            return Ok((buf, rtt));
        }
    }
}

async fn tcp_exchange(dest: SocketAddr, query: &[u8]) -> Result<Vec<u8>, Failure> {
    let socket = if dest.is_ipv6() {
        TcpSocket::new_v6()
    } else {
        TcpSocket::new_v4()
    }
    .map_err(|e| local(&e))?;
    socket.set_zero_linger().map_err(|e| local(&e))?;
    socket.set_nodelay(true).map_err(|e| local(&e))?;
    let mut stream = socket.connect(dest).await.map_err(|e| match e.kind() {
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable => local(&e),
        _ => Failure::Remote(format!("connect failed: {e}")),
    })?;
    let len = u16::try_from(query.len()).map_err(|_| Failure::Local("query too long".into()))?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| Failure::Remote(format!("write failed: {e}")))?;
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|e| Failure::Remote(format!("read failed: {e}")))?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Failure::Remote(format!("read failed: {e}")))?;
    Ok(buf)
}

fn build_query(p: &Prepared, id: u16) -> Result<Vec<u8>, String> {
    let name = expand_rand(&p.cfg.query);
    let name = Name::from_ascii(&name).map_err(|e| format!("bad query name {name:?}: {e}"))?;
    let mut msg = Message::new();
    msg.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(p.cfg.recursion)
        .add_query(Query::query(name, p.qtype));
    msg.to_vec().map_err(|e| e.to_string())
}

/// Check a response against the expected rcode and answer set.
fn check(p: &Prepared, bytes: &[u8], id: u16) -> Result<(), SampleError> {
    let msg = Message::from_vec(bytes)
        .map_err(|e| SampleError::Other(format!("malformed response: {e}")))?;
    if msg.id() != id || msg.message_type() != MessageType::Response {
        return Err(SampleError::Other(
            "response does not match the query".into(),
        ));
    }
    let rcode = u16::from(msg.response_code());
    if rcode != p.rcode {
        let name = RCODES
            .iter()
            .find(|(_, n)| *n == rcode)
            .map_or_else(|| rcode.to_string(), |(name, _)| (*name).to_string());
        return Err(SampleError::DnsMismatch(format!(
            "rcode {name} instead of {}",
            p.cfg.expect_rcode
        )));
    }
    if let Some(expected) = &p.answers {
        let got: BTreeSet<String> = msg
            .answers()
            .iter()
            .filter(|r| r.record_type() == p.qtype)
            .map(|r| normalise(&r.data().to_string()))
            .collect();
        if &got != expected {
            let got: Vec<&str> = got.iter().map(String::as_str).collect();
            return Err(SampleError::DnsMismatch(format!(
                "answer [{}] is not the expected set",
                got.join(", ")
            )));
        }
    }
    Ok(())
}

/// Lower case, without a trailing dot, so `Example.com.` matches `example.com`.
fn normalise(s: &str) -> String {
    let s = s.trim();
    s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase()
}

/// RFC 1035 response codes by their usual names.
const RCODES: &[(&str, u16)] = &[
    ("NOERROR", 0),
    ("FORMERR", 1),
    ("SERVFAIL", 2),
    ("NXDOMAIN", 3),
    ("NOTIMP", 4),
    ("REFUSED", 5),
];

fn rcode_number(name: &str) -> Option<u16> {
    RCODES.iter().find(|(n, _)| *n == name).map(|&(_, v)| v)
}

/// Replace each `{rand}` with a fresh 12-character label.
fn expand_rand(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let mut rest = query;
    while let Some(at) = rest.find("{rand}") {
        out.push_str(&rest[..at]);
        out.push_str(&format!("r{:011x}", random_u64() & 0xfff_ffff_ffff));
        rest = &rest[at + "{rand}".len()..];
    }
    out.push_str(rest);
    out
}

/// Unpredictable enough for query ids and cache-busting labels: SipHash
/// with a per-process random key over a counter.
fn random_u64() -> u64 {
    static STATE: std::sync::OnceLock<RandomState> = std::sync::OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = STATE.get_or_init(RandomState::new).build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use std::time::SystemTime;
    use tokio::net::TcpListener;

    fn cfg(query: &str) -> DnsConfig {
        DnsConfig {
            port: 0,
            query: query.into(),
            qtype: "A".into(),
            transport: DnsTransport::Udp,
            recursion: true,
            expect_rcode: "NOERROR".into(),
            expect_answers: None,
        }
    }

    fn plan(count: u16) -> RoundPlan {
        RoundPlan {
            count,
            spread: Duration::from_millis(5 * u64::from(count)),
            timeout: Duration::from_secs(2),
            round_start: SystemTime::now(),
        }
    }

    fn target() -> ResolvedTarget {
        ResolvedTarget {
            name: "lo".into(),
            addr: Ipv4Addr::LOCALHOST.into(),
        }
    }

    /// Answer a query: NXDOMAIN for names starting with "nx", else one A
    /// record 192.0.2.1. Returns the response bytes and the asked name.
    fn answer(query: &[u8]) -> (Vec<u8>, String) {
        let q = Message::from_vec(query).unwrap();
        let name = q.queries()[0].name().clone();
        let mut r = Message::new();
        r.set_id(q.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .add_query(q.queries()[0].clone());
        if name.to_ascii().starts_with("nx") {
            r.set_response_code(ResponseCode::NXDomain);
        } else {
            r.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A::new(192, 0, 2, 1)),
            ));
        }
        (r.to_vec().unwrap(), name.to_ascii())
    }

    /// A UDP server answering every query; first sends a datagram with a
    /// wrong id, which the probe must skip. Returns the port and the names
    /// it was asked.
    async fn udp_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let (resp, name) = answer(&buf[..n]);
                let mut stray = resp.clone();
                stray[0] ^= 0xff;
                let _ = sock.send_to(&stray, from).await;
                let _ = sock.send_to(&resp, from).await;
                let _ = tx.send(name);
            }
        });
        (port, rx)
    }

    #[test]
    fn unusable_settings_fail_when_the_probe_is_made() {
        let e = DnsProbe::new(cfg("exa mple.com")).unwrap_err();
        assert!(e.to_string().contains("bad query name"), "{e}");
        let mut c = cfg("example.com");
        c.qtype = "DS".into();
        c.expect_answers = Some(vec!["12345 13 2 abcd".into()]);
        assert!(DnsProbe::new(c).is_err());
        DnsProbe::new(cfg(".")).unwrap();
        DnsProbe::new(cfg("{rand}.example.com")).unwrap();
    }

    #[tokio::test]
    async fn udp_query_is_answered() {
        let (port, _) = udp_server().await;
        let mut c = cfg("example.com");
        c.port = port;
        c.expect_answers = Some(vec!["192.0.2.1".into()]);
        let probe = DnsProbe::new(c).unwrap();
        let round = probe.run_round(&target(), plan(4)).await.unwrap();
        assert!(
            round.samples.iter().all(|s| matches!(s, Sample::Ok { .. })),
            "{:?}",
            round.samples
        );
    }

    #[tokio::test]
    async fn rand_labels_differ_per_sample() {
        let (port, mut names) = udp_server().await;
        let mut c = cfg("{rand}.example.com");
        c.port = port;
        let probe = DnsProbe::new(c).unwrap();
        probe.run_round(&target(), plan(3)).await.unwrap();
        let mut seen = BTreeSet::new();
        for _ in 0..3 {
            let n = names.recv().await.unwrap();
            assert!(n.ends_with(".example.com."), "{n}");
            assert!(!n.contains("{rand}"), "{n}");
            seen.insert(n);
        }
        assert_eq!(seen.len(), 3, "{seen:?}");
    }

    #[tokio::test]
    async fn wrong_rcode_and_answers_are_mismatches() {
        let (port, _) = udp_server().await;
        let mut c = cfg("nx.example.com");
        c.port = port;
        let round = DnsProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(1))
            .await
            .unwrap();
        assert!(
            matches!(&round.samples[0], Sample::Error(SampleError::DnsMismatch(m)) if m.contains("rcode NXDOMAIN")),
            "{:?}",
            round.samples
        );

        let mut c = cfg("example.com");
        c.port = port;
        c.expect_answers = Some(vec!["192.0.2.99".into()]);
        let round = DnsProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(1))
            .await
            .unwrap();
        assert!(
            matches!(&round.samples[0], Sample::Error(SampleError::DnsMismatch(m)) if m.contains("192.0.2.1")),
            "{:?}",
            round.samples
        );

        let mut c = cfg("nx.example.com");
        c.port = port;
        c.expect_rcode = "NXDOMAIN".into();
        let round = DnsProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(1))
            .await
            .unwrap();
        assert!(matches!(round.samples[0], Sample::Ok { .. }));
    }

    #[tokio::test]
    async fn tcp_query_is_answered() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    s.read_exact(&mut len).await.unwrap();
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    s.read_exact(&mut q).await.unwrap();
                    let (resp, _) = answer(&q);
                    let len = u16::try_from(resp.len()).unwrap().to_be_bytes();
                    s.write_all(&len).await.unwrap();
                    s.write_all(&resp).await.unwrap();
                });
            }
        });
        let mut c = cfg("example.com");
        c.port = port;
        c.transport = DnsTransport::Tcp;
        let round = DnsProbe::new(c)
            .unwrap()
            .run_round(&target(), plan(3))
            .await
            .unwrap();
        assert!(
            round.samples.iter().all(|s| matches!(s, Sample::Ok { .. })),
            "{:?}",
            round.samples
        );
    }

    #[tokio::test]
    async fn silence_is_loss() {
        // Bound but never answering.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut c = cfg("example.com");
        c.port = sock.local_addr().unwrap().port();
        let mut p = plan(1);
        p.timeout = Duration::from_millis(100);
        let round = DnsProbe::new(c)
            .unwrap()
            .run_round(&target(), p)
            .await
            .unwrap();
        assert_eq!(round.samples, vec![Sample::Lost]);
        drop(sock);
    }

    #[test]
    fn answers_compare_without_case_or_trailing_dot() {
        assert_eq!(normalise(" Mail.Example.COM. "), "mail.example.com");
    }

    #[test]
    fn every_configurable_qtype_and_rcode_is_known() {
        for t in rl_core::config::DNS_QTYPES {
            assert!(RecordType::from_str(t).is_ok(), "{t}");
        }
        for r in rl_core::config::DNS_RCODES {
            assert!(rcode_number(r).is_some(), "{r}");
        }
    }
}
