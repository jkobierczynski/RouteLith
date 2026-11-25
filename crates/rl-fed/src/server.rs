//! The server side of the agent link: `listen_agents` (§21.7 G2–G4).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};

use crate::ca::Ca;
use crate::pb::agent_server::{Agent, AgentServer};
use crate::pb::{self, AgentMessage, EnrollRequest, EnrollResponse, ServerMessage};
use crate::registry::{AgentRecord, Registry};
use crate::{FedError, tls};

/// How the agent listener is set up.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// This server's version, sent to agents.
    pub version: String,
    /// The server's own vantage name: no agent may use it.
    pub own_vantage: String,
    /// How often a connected agent's record is checked for revocation.
    pub recheck: Duration,
    /// How long a new stream may take to say Hello.
    pub hello_timeout: Duration,
}

impl ServerOptions {
    pub fn new(listen: SocketAddr, data_dir: PathBuf, version: &str, own_vantage: &str) -> Self {
        ServerOptions {
            listen,
            data_dir,
            version: version.to_string(),
            own_vantage: own_vantage.to_string(),
            recheck: Duration::from_secs(10),
            hello_timeout: Duration::from_secs(30),
        }
    }
}

/// Things worth a line in the server's log (and, from M3 step 4, an event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentEvent {
    Enrolled {
        name: String,
        addr: SocketAddr,
        version: String,
    },
    Connected {
        name: String,
        addr: SocketAddr,
        version: String,
        os: String,
    },
    Disconnected {
        name: String,
        addr: SocketAddr,
        reason: String,
    },
    /// An agent or would-be agent was turned away.
    Refused { addr: SocketAddr, reason: String },
}

impl std::fmt::Display for AgentEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentEvent::Enrolled {
                name,
                addr,
                version,
            } => write!(f, "agent {name} enrolled from {addr} (version {version})"),
            AgentEvent::Connected {
                name,
                addr,
                version,
                os,
            } => write!(
                f,
                "agent {name} connected from {addr} (version {version}, {os})"
            ),
            AgentEvent::Disconnected { name, addr, reason } => {
                write!(f, "agent {name} at {addr} disconnected: {reason}")
            }
            AgentEvent::Refused { addr, reason } => write!(f, "refused {addr}: {reason}"),
        }
    }
}

/// A running agent listener.
#[derive(Debug)]
pub struct AgentListener {
    pub local_addr: SocketAddr,
    /// SHA-256 of the CA certificate (what tokens carry).
    pub ca_sha256: [u8; 32],
    pub events: mpsc::Receiver<AgentEvent>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl AgentListener {
    /// Take the event receiver (for a task that logs them); later calls
    /// get a closed one.
    pub fn take_events(&mut self) -> mpsc::Receiver<AgentEvent> {
        std::mem::replace(&mut self.events, mpsc::channel(1).1)
    }

    /// Stop listening and drop every agent stream.
    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for AgentListener {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Bind `listen_agents` and start serving. Binding happens before this
/// returns, so a port in use stops start-up. Creates the CA on first use.
pub async fn bind(opts: ServerOptions) -> Result<AgentListener, FedError> {
    let data_dir = opts.data_dir.clone();
    let ca = tokio::task::spawn_blocking(move || Ca::load_or_create(&data_dir))
        .await
        .map_err(|e| FedError::Invalid(format!("CA task failed: {e}")))??;
    let (chain, key) = ca.server_identity()?;
    let config = tls::server_config(ca.cert_der(), chain, key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(opts.listen)
        .await
        .map_err(FedError::io(format!(
            "cannot listen on {} (listen_agents)",
            opts.listen
        )))?;
    let local_addr = listener
        .local_addr()
        .map_err(FedError::io("listen_agents address"))?;
    let (events_tx, events) = mpsc::channel(256);
    let (conn_tx, conn_rx) = mpsc::channel::<Result<TlsConn, std::io::Error>>(64);

    let accept_events = events_tx.clone();
    let accept = tokio::spawn(async move {
        let last_tls_note = Arc::new(AtomicI64::new(i64::MIN));
        loop {
            let (tcp, addr) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => {
                    // Out of file descriptors and the like: try again soon.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let conn_tx = conn_tx.clone();
            let events = accept_events.clone();
            let last = last_tls_note.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => {
                        let cert_sha256 = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|c| c.first())
                            .map(|c| crate::sha256(c));
                        let _ = conn_tx
                            .send(Ok(TlsConn {
                                inner: tls,
                                info: PeerInfo { addr, cert_sha256 },
                            }))
                            .await;
                    }
                    other => {
                        // Port scanners fail here too: note at most one
                        // failed handshake every 10 s.
                        let now = crate::now_ms();
                        let prev = last.load(Ordering::Relaxed);
                        if now.saturating_sub(prev) >= 10_000
                            && last
                                .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                                .is_ok()
                        {
                            let reason = match other {
                                Ok(Err(e)) => format!("TLS handshake failed: {e}"),
                                _ => "TLS handshake timed out".to_string(),
                            };
                            let _ = events.try_send(AgentEvent::Refused { addr, reason });
                        }
                    }
                }
            });
        }
    });

    let svc = Svc {
        registry: Registry::new(&opts.data_dir),
        ca: Arc::new(ca),
        events: events_tx,
        opts: Arc::new(opts),
        active: Arc::new(Mutex::new(HashMap::new())),
        next_id: Arc::new(AtomicU64::new(1)),
    };
    let ca_sha256 = svc.ca.fingerprint();
    let serve = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(Duration::from_secs(20)))
            .add_service(AgentServer::new(svc))
            .serve_with_incoming(ReceiverStream::new(conn_rx))
            .await;
    });
    Ok(AgentListener {
        local_addr,
        ca_sha256,
        events,
        tasks: vec![accept, serve],
    })
}

/// Who is on the other end of a connection.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    /// SHA-256 of the client certificate, if one was shown.
    pub cert_sha256: Option<[u8; 32]>,
}

struct TlsConn {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    info: PeerInfo,
}

impl Connected for TlsConn {
    type ConnectInfo = PeerInfo;
    fn connect_info(&self) -> PeerInfo {
        self.info.clone()
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Streams by agent name: (stream id, a signal that ends it).
type Active = Arc<Mutex<HashMap<String, (u64, watch::Sender<bool>)>>>;

struct Svc {
    registry: Registry,
    ca: Arc<Ca>,
    events: mpsc::Sender<AgentEvent>,
    opts: Arc<ServerOptions>,
    active: Active,
    next_id: Arc<AtomicU64>,
}

fn peer<T>(req: &Request<T>) -> Result<PeerInfo, Status> {
    req.extensions()
        .get::<PeerInfo>()
        .cloned()
        .ok_or_else(|| Status::internal("connection details missing"))
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl Agent for Svc {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let info = peer(&request)?;
        let req = request.into_inner();
        let registry = self.registry.clone();
        let ca = self.ca.clone();
        let own = self.opts.own_vantage.clone();
        let version = req.version.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<(String, Vec<u8>), FedError> {
            let now = crate::now_ms();
            let name = registry.claim_token(&req.secret, now)?;
            if name == own {
                return Err(FedError::Refused(format!(
                    "{name:?} is the server's own vantage name"
                )));
            }
            let cert = ca.sign_agent(&req.csr_der, &name)?;
            registry.save(&AgentRecord {
                name: name.clone(),
                cert_sha256: crate::hex(&crate::sha256(&cert)),
                enrolled_ms: now,
                cert_expires_ms: now + crate::ca::LEAF_DAYS as i64 * 86_400_000,
                version: req.version,
                revoked_ms: None,
            })?;
            Ok((name, cert.to_vec()))
        })
        .await
        .map_err(internal)?;
        match result {
            Ok((name, cert_der)) => {
                let _ = self.events.try_send(AgentEvent::Enrolled {
                    name: name.clone(),
                    addr: info.addr,
                    version,
                });
                // A stream still open with the old certificate ends now.
                self.kick(&name);
                Ok(Response::new(EnrollResponse {
                    name,
                    cert_der,
                    ca_der: self.ca.cert_der().to_vec(),
                }))
            }
            Err(e) => {
                let _ = self.events.try_send(AgentEvent::Refused {
                    addr: info.addr,
                    reason: format!("enrollment: {e}"),
                });
                Err(match e {
                    FedError::Refused(m) => Status::permission_denied(m),
                    FedError::Invalid(m) => Status::invalid_argument(m),
                    e @ FedError::Io(..) => internal(e),
                })
            }
        }
    }

    type ConnectStream = ReceiverStream<Result<ServerMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let info = peer(&request)?;
        let refuse = |status: Status| {
            let _ = self.events.try_send(AgentEvent::Refused {
                addr: info.addr,
                reason: status.message().to_string(),
            });
            Err(status)
        };
        let Some(fp) = info.cert_sha256 else {
            return refuse(Status::unauthenticated(
                "no agent certificate: run `routelith agent enroll` first",
            ));
        };
        let registry = self.registry.clone();
        let rec = tokio::task::spawn_blocking(move || registry.find_by_cert(&fp))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        let rec = match rec {
            None => {
                return refuse(Status::permission_denied(
                    "this agent certificate is not known to the server \
                     (replaced by a newer enrollment?): enroll again with a new token",
                ));
            }
            Some(r) if r.revoked_ms.is_some() => {
                return refuse(Status::permission_denied(format!(
                    "agent {} is revoked: enroll again with a new token",
                    r.name
                )));
            }
            Some(r) => r,
        };
        let mut inbound = request.into_inner();
        let hello = match tokio::time::timeout(self.opts.hello_timeout, inbound.message()).await {
            Ok(Ok(Some(AgentMessage {
                msg: Some(pb::agent_message::Msg::Hello(h)),
            }))) => h,
            Ok(Err(s)) => return Err(s),
            Ok(Ok(_)) => {
                return refuse(Status::invalid_argument("the first message must be Hello"));
            }
            Err(_) => return refuse(Status::deadline_exceeded("no Hello in time")),
        };

        let (out, out_rx) = mpsc::channel(16);
        let welcome = ServerMessage {
            msg: Some(pb::server_message::Msg::Welcome(pb::Welcome {
                name: rec.name.clone(),
                server_version: self.opts.version.clone(),
            })),
        };
        out.send(Ok(welcome)).await.map_err(internal)?;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (stop_tx, mut stop_rx) = watch::channel(false);
        if let Some((_, older)) = self
            .active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(rec.name.clone(), (id, stop_tx))
        {
            let _ = older.send(true);
        }
        let _ = self.events.try_send(AgentEvent::Connected {
            name: rec.name.clone(),
            addr: info.addr,
            version: hello.version,
            os: hello.os,
        });

        let events = self.events.clone();
        let active = self.active.clone();
        let registry = self.registry.clone();
        let recheck = self.opts.recheck;
        tokio::spawn(async move {
            let name = rec.name.clone();
            let mut tick = tokio::time::interval(recheck);
            tick.tick().await;
            let reason = loop {
                tokio::select! {
                    m = inbound.message() => match m {
                        // Nothing else to handle yet (results come in step 2).
                        Ok(Some(_)) => {}
                        Ok(None) => break "the agent closed the stream".to_string(),
                        Err(s) => break format!("stream error: {}", s.message()),
                    },
                    _ = stop_rx.changed() => {
                        let _ = out.send(Err(Status::aborted(
                            "replaced by a newer connection from the same agent",
                        ))).await;
                        break "replaced by a newer connection".to_string();
                    }
                    _ = out.closed() => break "the stream closed".to_string(),
                    _ = tick.tick() => {
                        let r = registry.clone();
                        let n = name.clone();
                        let now = tokio::task::spawn_blocking(move || r.get(&n)).await;
                        let still_ok = match now {
                            Ok(Ok(Some(cur))) => cur.revoked_ms.is_none() && cur.cert_sha256 == rec.cert_sha256,
                            Ok(Ok(None)) => false,
                            // A read error is not a revocation.
                            _ => true,
                        };
                        if !still_ok {
                            let _ = out.send(Err(Status::permission_denied(format!(
                                "agent {name} was revoked or enrolled again"
                            )))).await;
                            break "revoked or enrolled again".to_string();
                        }
                    }
                }
            };
            {
                let mut a = active.lock().unwrap_or_else(|p| p.into_inner());
                if a.get(&name).is_some_and(|(i, _)| *i == id) {
                    a.remove(&name);
                }
            }
            let _ = events.try_send(AgentEvent::Disconnected {
                name,
                addr: info.addr,
                reason,
            });
        });
        Ok(Response::new(ReceiverStream::new(out_rx)))
    }
}

impl Svc {
    fn kick(&self, name: &str) {
        if let Some((_, tx)) = self
            .active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(name)
        {
            let _ = tx.send(true);
        }
    }
}
