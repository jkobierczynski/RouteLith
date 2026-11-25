//! Agents and federation (architecture doc §9, §21.7).
//!
//! The server runs a small CA ([`ca`]), hands out single-use enrollment
//! tokens ([`token`], [`registry`]) and accepts agents over gRPC with mutual
//! TLS ([`server`]). Agents enroll once and then hold one long-lived stream
//! to the server ([`client`]).
#![forbid(unsafe_code)]

pub mod agent_config;
pub mod ca;
pub mod client;
mod files;
pub mod pb;
pub mod registry;
pub mod server;
mod tls;
pub mod token;

/// The name in the server's certificate. Agents dial whatever address
/// they are given but always check the certificate against this name and
/// the pinned CA, so a server's address can change without new
/// certificates.
pub const SERVER_NAME: &str = "server.routelith.invalid";

/// Default port for `listen_agents` and the agent's `server` setting.
pub const DEFAULT_PORT: u16 = 4443;

/// What can go wrong in federation code. The message is meant for people.
#[derive(Debug, thiserror::Error)]
pub enum FedError {
    #[error("{0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Refused(String),
}

impl FedError {
    pub(crate) fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> Self {
        let what = what.into();
        move |e| FedError::Io(what, e)
    }
}

/// SHA-256 of some bytes (certificate fingerprints, token ids).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A certificate fingerprint as people read it: hex pairs joined by ':'.
pub fn fingerprint_text(fp: &[u8; 32]) -> String {
    fp.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
