//! TCP connect probe (architecture doc §4.3).
//!
//! Each sample opens a fresh connection and times `connect()` until the
//! handshake completes (or, in banner mode, until the server's first byte).
//! The connection is then closed with a RST (`SO_LINGER` 0), so the target
//! keeps no `TIME_WAIT` state. A RST in answer to the SYN means the host is
//! reachable but the port is closed: it is kept as
//! [`SampleError::Refused`] with its latency.
//!
//! On Windows, `connect()` to a closed port fails only after the stack has
//! retried the SYN twice (about 0.5 s apart), so a refusal is reported up
//! to ~2 s late, and as lost when the round's timeout is shorter.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rl_core::config::TcpMode;
use rl_core::{
    ProbeMeta, ResolvedTarget, RoundPlan, RoundResult, Sample, SampleError, TimingBackend,
    TimingSource,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::{BoxFuture, Probe, ProbeError, ProbeKind, RateLimiter};

/// TCP probe options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig {
    pub port: u16,
    pub mode: TcpMode,
}

/// TCP connect-time probe. Stateless: every sample is its own connection.
#[derive(Debug)]
pub struct TcpProbe {
    config: TcpConfig,
    limiter: Option<Arc<RateLimiter>>,
}

impl TcpProbe {
    pub fn new(config: TcpConfig) -> Self {
        Self {
            config,
            limiter: None,
        }
    }

    /// Share a packets-per-second ceiling with other probes (one connection
    /// attempt counts as one packet).
    pub fn with_rate_limiter(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    pub fn config(&self) -> TcpConfig {
        self.config
    }

    async fn round(&self, target: &ResolvedTarget, plan: RoundPlan) -> RoundResult {
        let dest = SocketAddr::new(target.addr, self.config.port);
        let t0 = Instant::now();
        let mut tasks = JoinSet::new();
        for i in 0..plan.count {
            let at = t0 + plan.sample_offset(i);
            let limiter = self.limiter.clone();
            let mode = self.config.mode;
            let timeout = plan.timeout;
            tasks.spawn(async move {
                sleep_until(at).await;
                if let Some(l) = limiter {
                    l.acquire().await;
                }
                (i, sample(dest, mode, timeout).await)
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
            http: None,
        }
    }
}

impl Probe for TcpProbe {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Tcp
    }

    fn run_round<'a>(
        &'a self,
        target: &'a ResolvedTarget,
        plan: RoundPlan,
    ) -> BoxFuture<'a, Result<RoundResult, ProbeError>> {
        Box::pin(async move { Ok(self.round(target, plan).await) })
    }
}

/// One connection attempt.
async fn sample(dest: SocketAddr, mode: TcpMode, timeout: Duration) -> Sample {
    let socket = match open(dest.ip()) {
        Ok(s) => s,
        Err(e) => return Sample::Error(SampleError::SendFailed(e.to_string())),
    };
    let start = Instant::now();
    let deadline = start + timeout;
    let stream = match timeout_at(deadline, socket.connect(dest)).await {
        Err(_) => return Sample::Lost,
        Ok(Err(e)) => return connect_error(&e, start.elapsed()),
        Ok(Ok(stream)) => stream,
    };
    let elapsed = match mode {
        TcpMode::Connect => start.elapsed(),
        TcpMode::Banner => match first_byte(stream, deadline).await {
            Some(Ok(())) => start.elapsed(),
            Some(Err(e)) => return Sample::Error(SampleError::Other(e)),
            None => return Sample::Lost,
        },
    };
    ok(elapsed)
}

fn open(ip: IpAddr) -> io::Result<TcpSocket> {
    let socket = if ip.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    // Close with a RST so the target keeps no TIME_WAIT (§4.3).
    socket.set_zero_linger()?;
    socket.set_nodelay(true)?;
    Ok(socket)
}

/// Wait for the server's first byte. `None` when the deadline passes first.
async fn first_byte(mut stream: TcpStream, deadline: Instant) -> Option<Result<(), String>> {
    let mut buf = [0u8; 1];
    match timeout_at(deadline, stream.read(&mut buf)).await {
        Err(_) => None,
        Ok(Ok(0)) => Some(Err("connection closed before a banner".to_owned())),
        Ok(Ok(_)) => Some(Ok(())),
        Ok(Err(e)) => Some(Err(format!("read failed: {e}"))),
    }
}

fn connect_error(e: &io::Error, elapsed: Duration) -> Sample {
    match e.kind() {
        ErrorKind::ConnectionRefused => Sample::Error(SampleError::Refused {
            rtt_us: micros(elapsed),
        }),
        // No local route or address, or a local firewall said no: the SYN
        // never left this host.
        ErrorKind::NetworkUnreachable
        | ErrorKind::AddrNotAvailable
        | ErrorKind::AddrInUse
        | ErrorKind::PermissionDenied => Sample::Error(SampleError::SendFailed(e.to_string())),
        ErrorKind::TimedOut => Sample::Lost,
        _ => Sample::Error(SampleError::Other(e.to_string())),
    }
}

fn micros(d: Duration) -> u32 {
    u32::try_from(d.as_micros()).unwrap_or(u32::MAX)
}

fn ok(d: Duration) -> Sample {
    Sample::Ok { rtt_us: micros(d) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn plan(count: u16) -> RoundPlan {
        RoundPlan {
            count,
            spread: Duration::from_millis(10 * u64::from(count)),
            timeout: Duration::from_secs(2),
            round_start: SystemTime::now(),
        }
    }

    fn target(addr: IpAddr) -> ResolvedTarget {
        ResolvedTarget {
            name: addr.to_string(),
            addr,
        }
    }

    #[tokio::test]
    async fn connect_mode_times_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        let probe = TcpProbe::new(TcpConfig {
            port,
            mode: TcpMode::Connect,
        });
        let round = probe
            .run_round(&target("127.0.0.1".parse().unwrap()), plan(5))
            .await
            .unwrap();
        assert_eq!(round.samples.len(), 5);
        assert!(
            round.samples.iter().all(|s| matches!(s, Sample::Ok { .. })),
            "{:?}",
            round.samples
        );
        assert_eq!(round.meta.timing.backend, TimingBackend::Monotonic);
    }

    #[tokio::test]
    async fn banner_mode_waits_for_the_first_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    let _ = s.write_all(b"SSH-2.0-test\r\n").await;
                });
            }
        });
        let probe = TcpProbe::new(TcpConfig {
            port,
            mode: TcpMode::Banner,
        });
        let round = probe
            .run_round(&target("127.0.0.1".parse().unwrap()), plan(3))
            .await
            .unwrap();
        for s in &round.samples {
            let rtt = s.rtt_us().unwrap_or_else(|| panic!("{s:?}"));
            assert!(rtt >= 30_000, "{rtt} µs is shorter than the banner delay");
        }
    }

    #[tokio::test]
    async fn banner_mode_reports_a_silent_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        let probe = TcpProbe::new(TcpConfig {
            port,
            mode: TcpMode::Banner,
        });
        let round = probe
            .run_round(&target("127.0.0.1".parse().unwrap()), plan(1))
            .await
            .unwrap();
        assert!(
            matches!(&round.samples[0], Sample::Error(SampleError::Other(_))),
            "{:?}",
            round.samples
        );
    }

    #[tokio::test]
    async fn a_closed_port_is_refused_with_its_latency() {
        // Bind, then close, so the port is known to be free.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let probe = TcpProbe::new(TcpConfig {
            port,
            mode: TcpMode::Connect,
        });
        // Windows retries a refused SYN twice, about half a second apart,
        // before connect() fails, so a refusal takes up to ~2 s there.
        let mut p = plan(2);
        p.timeout = Duration::from_secs(5);
        let round = probe
            .run_round(&target("127.0.0.1".parse().unwrap()), p)
            .await
            .unwrap();
        for s in &round.samples {
            assert!(
                matches!(s, Sample::Error(SampleError::Refused { .. })),
                "{s:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_unanswered_syn_is_lost_at_the_timeout() {
        // 192.0.2.0/24 (TEST-NET-1) is never routed; depending on the host
        // the connect times out or fails at once, never succeeds.
        let probe = TcpProbe::new(TcpConfig {
            port: 9,
            mode: TcpMode::Connect,
        });
        let mut p = plan(1);
        p.timeout = Duration::from_millis(200);
        let started = Instant::now();
        let round = probe
            .run_round(&target("192.0.2.1".parse().unwrap()), p)
            .await
            .unwrap();
        assert!(round.samples[0].rtt_us().is_none(), "{:?}", round.samples);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
