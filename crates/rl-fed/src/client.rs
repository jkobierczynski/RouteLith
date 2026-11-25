//! The agent side of the link: enrollment and the stream to the server
//! (§21.7 G1, G4).
//!
//! The agent keeps its identity in `<data_dir>/identity/`: `key.pem` (its
//! private key, made here and never sent anywhere), `cert.pem` (signed by
//! the server's CA) and `ca.pem` (the server's CA, pinned).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::pb::agent_client::AgentClient;
use crate::pb::{self, AgentMessage, EnrollRequest, ServerMessage};
use crate::token::Token;
use crate::{DEFAULT_PORT, FedError, SERVER_NAME, files, tls};

/// Where an agent finds its server: `host`, `host:port`, `[v6]` or
/// `[v6]:port` (default port 4443).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    pub host: String,
    pub port: u16,
}

impl ServerAddr {
    pub fn parse(s: &str) -> Result<ServerAddr, FedError> {
        let s = s.trim();
        let bad = || {
            FedError::Invalid(format!(
                "server {s:?} must be host, host:port, [IPv6] or [IPv6]:port"
            ))
        };
        if s.is_empty() || s.contains('/') || s.contains(char::is_whitespace) {
            return Err(bad());
        }
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return Ok(ServerAddr {
                host: ip.to_string(),
                port: DEFAULT_PORT,
            });
        }
        if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
            return Ok(ServerAddr {
                host: sa.ip().to_string(),
                port: sa.port(),
            });
        }
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            let ip: std::net::Ipv6Addr = inner.parse().map_err(|_| bad())?;
            return Ok(ServerAddr {
                host: ip.to_string(),
                port: DEFAULT_PORT,
            });
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(bad)?),
            None => (s, DEFAULT_PORT),
        };
        if host.is_empty() || host.contains(':') || host.contains('[') {
            return Err(bad());
        }
        Ok(ServerAddr {
            host: host.to_string(),
            port,
        })
    }
}

impl std::fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// The identity folder inside an agent's data directory.
pub fn identity_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("identity")
}

/// An enrolled agent's certificate, key and pinned CA.
pub struct Identity {
    pub name: String,
    ca: CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("name", &self.name)
            .field("ca_sha256", &crate::hex(&crate::sha256(&self.ca)))
            .finish_non_exhaustive()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityMeta {
    name: String,
    server: String,
    enrolled_ms: i64,
}

impl Identity {
    /// Load the identity saved by [`enroll`].
    pub fn load(data_dir: &Path) -> Result<Identity, FedError> {
        let dir = identity_dir(data_dir);
        let read = |f: &str| -> Result<Vec<u8>, FedError> {
            files::read_optional(&dir.join(f))?.ok_or_else(|| {
                FedError::Invalid(format!(
                    "this agent is not enrolled ({} is missing): run `routelith agent enroll` first",
                    dir.join(f).display()
                ))
            })
        };
        let meta: IdentityMeta = serde_json::from_slice(&read("identity.json")?)
            .map_err(|e| FedError::Invalid(format!("{} is damaged: {e}", dir.display())))?;
        let pem_err = |f: &str, e: rustls_pki_types::pem::Error| {
            FedError::Invalid(format!("{f} in {}: {e}", dir.display()))
        };
        Ok(Identity {
            name: meta.name,
            ca: CertificateDer::from_pem_slice(&read("ca.pem")?)
                .map_err(|e| pem_err("ca.pem", e))?,
            cert: CertificateDer::from_pem_slice(&read("cert.pem")?)
                .map_err(|e| pem_err("cert.pem", e))?,
            key: PrivateKeyDer::from_pem_slice(&read("key.pem")?)
                .map_err(|e| pem_err("key.pem", e))?,
        })
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// Enroll with a server: make a key, have the server sign it, save the
/// identity. Returns the agent's name.
pub async fn enroll(
    server: &ServerAddr,
    token: &Token,
    data_dir: &Path,
    version: &str,
) -> Result<String, FedError> {
    let key = KeyPair::generate().map_err(|e| FedError::Invalid(format!("key: {e}")))?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Routelith agent");
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&key)
        .map_err(|e| FedError::Invalid(format!("certificate request: {e}")))?;
    let channel = channel(server, tls::enroll_config(token.ca_sha256)?).await?;
    let resp = AgentClient::new(channel)
        .enroll(EnrollRequest {
            secret: token.secret.to_vec(),
            csr_der: csr.der().to_vec(),
            version: version.to_string(),
        })
        .await
        .map_err(|s| status_err(server, &s))?
        .into_inner();
    if crate::sha256(&resp.ca_der) != token.ca_sha256 {
        return Err(FedError::Refused(
            "the server sent a CA that does not match the token".into(),
        ));
    }
    crate::registry::check_name(&resp.name)?;
    let dir = identity_dir(data_dir);
    files::write_private(&dir.join("key.pem"), key.serialize_pem().as_bytes())?;
    files::write_private(
        &dir.join("cert.pem"),
        pem("CERTIFICATE", &resp.cert_der).as_bytes(),
    )?;
    files::write_private(
        &dir.join("ca.pem"),
        pem("CERTIFICATE", &resp.ca_der).as_bytes(),
    )?;
    let meta = IdentityMeta {
        name: resp.name.clone(),
        server: server.to_string(),
        enrolled_ms: crate::now_ms(),
    };
    files::write_private(
        &dir.join("identity.json"),
        &serde_json::to_vec_pretty(&meta).map_err(|e| FedError::Invalid(e.to_string()))?,
    )?;
    Ok(resp.name)
}

/// An open stream to the server.
#[derive(Debug)]
pub struct Session {
    /// The name the server knows this agent by.
    pub name: String,
    pub server_version: String,
    pub inbound: tonic::Streaming<ServerMessage>,
    pub outbound: mpsc::Sender<AgentMessage>,
}

/// Open the agent stream: Hello, then wait for Welcome.
pub async fn connect(
    server: &ServerAddr,
    id: &Identity,
    version: &str,
) -> Result<Session, FedError> {
    let config = tls::client_config(&id.ca, id.cert.clone(), id.key.clone_key())?;
    let channel = channel(server, config).await?;
    let (tx, rx) = mpsc::channel(64);
    let hello = AgentMessage {
        msg: Some(pb::agent_message::Msg::Hello(pb::Hello {
            version: version.to_string(),
            os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        })),
    };
    tx.send(hello)
        .await
        .map_err(|_| FedError::Invalid("stream closed".into()))?;
    let mut inbound = AgentClient::new(channel)
        .connect(ReceiverStream::new(rx))
        .await
        .map_err(|s| status_err(server, &s))?
        .into_inner();
    match tokio::time::timeout(Duration::from_secs(30), inbound.message()).await {
        Ok(Ok(Some(ServerMessage {
            msg: Some(pb::server_message::Msg::Welcome(w)),
        }))) => Ok(Session {
            name: w.name,
            server_version: w.server_version,
            inbound,
            outbound: tx,
        }),
        Ok(Err(s)) => Err(status_err(server, &s)),
        Ok(Ok(_)) => Err(FedError::Invalid(format!(
            "{server} did not answer with Welcome"
        ))),
        Err(_) => Err(FedError::Refused(format!(
            "{server} did not answer in time"
        ))),
    }
}

fn status_err(server: &ServerAddr, s: &tonic::Status) -> FedError {
    use std::error::Error;
    let mut msg = s.message().to_string();
    let mut src = s.source();
    while let Some(e) = src {
        let part = e.to_string();
        if !msg.ends_with(&part) {
            msg.push_str(&format!(": {part}"));
        }
        src = e.source();
    }
    match s.code() {
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            FedError::Refused(format!("{server} refused: {msg}"))
        }
        _ => FedError::Refused(format!("{server}: {msg}")),
    }
}

async fn channel(server: &ServerAddr, config: rustls::ClientConfig) -> Result<Channel, FedError> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let host = server.host.clone();
    let port = server.port;
    let endpoint = Endpoint::from_static("http://agent.routelith.invalid")
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true);
    endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let connector = connector.clone();
            let host = host.clone();
            async move {
                let tcp = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::net::TcpStream::connect((host.as_str(), port)),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
                })??;
                let _ = tcp.set_nodelay(true);
                let name = ServerName::try_from(SERVER_NAME)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let tls = connector.connect(name, tcp).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
        .await
        .map_err(|e| {
            use std::error::Error;
            let mut msg = format!("cannot reach {server}");
            let mut src: Option<&dyn Error> = Some(&e);
            while let Some(e) = src {
                let part = e.to_string();
                if !msg.ends_with(&part) {
                    msg.push_str(&format!(": {part}"));
                }
                src = e.source();
            }
            FedError::Refused(msg)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses() {
        let p = |s: &str| ServerAddr::parse(s).map(|a| a.to_string());
        assert_eq!(p("mon.example.be").unwrap(), "mon.example.be:4443");
        assert_eq!(p("mon.example.be:9000").unwrap(), "mon.example.be:9000");
        assert_eq!(p("192.0.2.7").unwrap(), "192.0.2.7:4443");
        assert_eq!(p("192.0.2.7:1").unwrap(), "192.0.2.7:1");
        assert_eq!(p("::1").unwrap(), "[::1]:4443");
        assert_eq!(p("[::1]").unwrap(), "[::1]:4443");
        assert_eq!(p("[2001:db8::1]:5").unwrap(), "[2001:db8::1]:5");
        for bad in [
            "",
            "host:",
            "host:0",
            "host:99999",
            "https://x",
            "a b",
            "[x]:1",
            ":4443",
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }
}
