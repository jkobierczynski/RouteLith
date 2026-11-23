//! `type = "webhook"` (doc §21.5 F10): each event is POSTed over HTTP or
//! HTTPS, as the event's JSON (optionally signed) or in the message format
//! of Slack, Microsoft Teams, Mattermost, ntfy or Gotify.
//!
//! A signed JSON request carries
//!
//! ```text
//! X-Routelith-Timestamp: 1800000000
//! X-Routelith-Signature: sha256=<hex HMAC-SHA256 of "1800000000.<body>">
//! ```
//!
//! so the receiver can check that the body came from a holder of the
//! secret, and refuse old timestamps to stop replays.
//!
//! A 2xx answer is success. 408, 425, 429 and 5xx answers, and network
//! errors, are retried; any other answer (a wrong URL or token, a body the
//! receiver will never take) drops the event, as retrying cannot help.
//! The URL may itself be a secret (Slack and Teams URLs are), so messages
//! name only its host and port.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rl_core::output::{WebhookFormat, WebhookOutput};
use rl_store::{Event, EventKind};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use serde_json::{Value, json};

use crate::syslog::{handshake, rfc3339};
use crate::{Failure, IO_TIMEOUT, Sink};

/// The longest a TLS handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest status line (or interim header block line) read.
const MAX_LINE: usize = 8 * 1024;

/// One request, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub content_type: &'static str,
    /// Extra headers, already checked to be single-line ASCII.
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

pub(crate) struct WebhookSink {
    cfg: WebhookOutput,
    tls: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    /// `host:port` for messages.
    to: String,
}

impl std::fmt::Debug for WebhookSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSink")
            .field("to", &self.to)
            .field("format", &self.cfg.format)
            .finish_non_exhaustive()
    }
}

impl WebhookSink {
    pub(crate) fn new(cfg: &WebhookOutput) -> Result<Self, String> {
        let tls = if cfg.url.tls {
            let config = crate::tls::client_config(cfg.ca_file.as_deref(), None, None)?;
            let name = ServerName::try_from(cfg.url.host.clone())
                .map_err(|e| format!("TLS server name: {e}"))?;
            Some((config, name))
        } else {
            None
        };
        let to = if cfg.url.host.contains(':') {
            format!("[{}]:{}", cfg.url.host, cfg.url.port)
        } else {
            format!("{}:{}", cfg.url.host, cfg.url.port)
        };
        Ok(Self {
            cfg: cfg.clone(),
            tls,
            to,
        })
    }

    fn addresses(&self) -> Result<Vec<SocketAddr>, String> {
        let host = self.cfg.url.host.as_str();
        let addrs: Vec<SocketAddr> = (host, self.cfg.url.port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {host}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("{host} has no address"));
        }
        Ok(addrs)
    }

    fn connect_to(&self, a: SocketAddr) -> Result<Box<dyn Stream>, String> {
        let mut sock = TcpStream::connect_timeout(&a, IO_TIMEOUT)
            .map_err(|e| format!("cannot connect to {a}: {e}"))?;
        let _ = sock.set_nodelay(true);
        let timeouts = |s: &TcpStream| {
            s.set_write_timeout(Some(IO_TIMEOUT))
                .and_then(|()| s.set_read_timeout(Some(IO_TIMEOUT)))
                .map_err(|e| e.to_string())
        };
        timeouts(&sock)?;
        let Some((config, name)) = self.tls.clone() else {
            return Ok(Box::new(sock));
        };
        let mut c = ClientConnection::new(config, name).map_err(|e| format!("TLS: {e}"))?;
        handshake(&mut c, &mut sock, Instant::now() + HANDSHAKE_TIMEOUT)
            .map_err(|e| format!("TLS handshake with {a}: {e}"))?;
        timeouts(&sock)?;
        Ok(Box::new(StreamOwned::new(c, sock)))
    }

    fn connect(&self) -> Result<Box<dyn Stream>, String> {
        let mut last = String::new();
        for a in self.addresses()? {
            match self.connect_to(a) {
                Ok(c) => return Ok(c),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The request's bytes: headers and body.
    fn bytes(&self, r: &Request) -> Vec<u8> {
        let u = &self.cfg.url;
        let path = match u.path.as_str() {
            "" => "/".to_string(),
            p if p.starts_with('?') => format!("/{p}"),
            p => p.to_string(),
        };
        let host = if u.host.contains(':') {
            format!("[{}]", u.host)
        } else {
            u.host.clone()
        };
        let default_port = if u.tls { 443 } else { 80 };
        let host = if u.port == default_port {
            host
        } else {
            format!("{host}:{}", u.port)
        };
        let mut head = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: routelith/{}\r\n\
             Content-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            env!("CARGO_PKG_VERSION"),
            r.content_type,
            r.body.len()
        );
        for (k, v) in &r.headers {
            head += &format!("{k}: {v}\r\n");
        }
        head += "\r\n";
        let mut out = head.into_bytes();
        out.extend_from_slice(&r.body);
        out
    }
}

/// A plain or TLS connection.
trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

impl Sink for WebhookSink {
    fn deliver(&mut self, e: &Event) -> Result<(), Failure> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let req = request(&self.cfg, e, now);
        let bytes = self.bytes(&req);
        let mut conn = self.connect()?;
        conn.write_all(&bytes)
            .and_then(|()| conn.flush())
            .map_err(|err| format!("cannot send to {}: {err}", self.to))?;
        let (code, reason) =
            status(&mut conn).map_err(|err| format!("no answer from {}: {err}", self.to))?;
        let what = format!("{} answered {code} {reason}", self.to);
        match code {
            200..=299 => Ok(()),
            408 | 425 | 429 | 500..=599 => Err(Failure::Retry(what)),
            _ => Err(Failure::Drop(what)),
        }
    }
}

/// Read the final status line: its code and (shortened) reason. Interim
/// 1xx answers are skipped.
fn status(r: &mut dyn Read) -> io::Result<(u16, String)> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    loop {
        let line = read_line(r)?;
        let mut parts = line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/1.") {
            return Err(bad("not an HTTP/1 answer"));
        }
        let code: u16 = parts
            .next()
            .and_then(|c| c.parse().ok())
            .filter(|c| (100..=599).contains(c))
            .ok_or_else(|| bad("no status code"))?;
        if (100..200).contains(&code) {
            // Its headers end with an empty line.
            while !read_line(r)?.is_empty() {}
            continue;
        }
        let reason: String = parts
            .next()
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
        return Ok((code, reason));
    }
}

/// One line up to CRLF (or LF), without it.
fn read_line(r: &mut dyn Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the connection closed",
                ));
            }
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) => line.push(b[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
            }
            Err(e) => return Err(e),
        }
        if line.len() > MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// The request for `e` in the output's format; `now` is Unix seconds, for
/// the signature.
pub(crate) fn request(cfg: &WebhookOutput, e: &Event, now: u64) -> Request {
    let json_body = |v: Value| v.to_string().into_bytes();
    let title = title(e);
    let raised = e.kind == EventKind::AlertRaised;
    match cfg.format {
        WebhookFormat::Json => {
            let body = serde_json::to_vec(e).unwrap_or_default();
            let mut headers = vec![("X-Routelith-Event", e.kind.as_str().to_string())];
            if let Some(secret) = &cfg.secret {
                headers.push(("X-Routelith-Timestamp", now.to_string()));
                headers.push((
                    "X-Routelith-Signature",
                    format!("sha256={}", sign(secret.expose(), now, &body)),
                ));
            }
            Request {
                content_type: "application/json",
                headers,
                body,
            }
        }
        WebhookFormat::Slack => Request {
            content_type: "application/json",
            headers: Vec::new(),
            body: json_body(json!({
                "text": format!("*{}*\n{}", slack_escape(&title), slack_escape(&e.message)),
            })),
        },
        WebhookFormat::Mattermost => Request {
            content_type: "application/json",
            headers: Vec::new(),
            body: json_body(json!({
                "username": "Routelith",
                "text": format!("**{title}**\n{}", e.message),
            })),
        },
        WebhookFormat::Teams => Request {
            content_type: "application/json",
            headers: Vec::new(),
            body: json_body(teams_card(e, &title)),
        },
        WebhookFormat::Ntfy => {
            let mut headers = vec![
                ("Title", header_text(&title)),
                ("Priority", if raised { "4" } else { "3" }.to_string()),
            ];
            let tag = match e.kind {
                EventKind::AlertRaised => Some("warning"),
                EventKind::AlertCleared => Some("white_check_mark"),
                _ => None,
            };
            if let Some(t) = tag {
                headers.push(("Tags", t.to_string()));
            }
            if let Some(t) = &cfg.token {
                headers.push(("Authorization", format!("Bearer {}", t.expose())));
            }
            Request {
                content_type: "text/plain; charset=utf-8",
                headers,
                body: e.message.clone().into_bytes(),
            }
        }
        WebhookFormat::Gotify => Request {
            content_type: "application/json",
            headers: cfg
                .token
                .as_ref()
                .map(|t| vec![("X-Gotify-Key", t.expose().to_string())])
                .unwrap_or_default(),
            body: json_body(json!({
                "title": title,
                "message": e.message,
                "priority": if raised { 8 } else { 4 },
            })),
        },
    }
}

/// A short title: what happened, and to which target.
pub(crate) fn title(e: &Event) -> String {
    let what = match e.kind {
        EventKind::AlertRaised => "alert raised",
        EventKind::AlertCleared => "alert cleared",
        EventKind::IpChanged => "address changed",
        EventKind::ServerStarted => "server started",
        EventKind::ServerStopped => "server stopped",
        EventKind::Unknown => "event",
    };
    let rule = e
        .rule
        .as_deref()
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    match &e.target {
        Some(t) => format!("Routelith: {t} {what}{rule}"),
        None => format!("Routelith: {what}{rule}"),
    }
}

/// A Teams message holding an Adaptive Card: the title, the message and
/// the event's fields.
fn teams_card(e: &Event, title: &str) -> Value {
    let mut facts = Vec::new();
    let mut fact = |name: &str, v: Option<String>| {
        if let Some(v) = v {
            facts.push(json!({ "title": name, "value": v }));
        }
    };
    fact("Target", e.target.clone());
    fact("Family", e.family.clone());
    fact("Rule", e.rule.clone());
    fact("Value", e.value.map(|v| v.to_string()));
    fact("Since", e.since.map(rfc3339));
    fact("From", e.from.clone());
    fact("To", e.to.clone());
    fact("Vantage", Some(e.vantage.clone()));
    fact("Time", Some(rfc3339(e.t)));
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    { "type": "TextBlock", "text": title, "weight": "Bolder",
                      "size": "Medium", "wrap": true },
                    { "type": "TextBlock", "text": e.message, "wrap": true },
                    { "type": "FactSet", "facts": facts },
                ],
            },
        }],
    })
}

/// Slack's three control characters.
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A header value: printable ASCII as it is, anything else as an RFC 2047
/// encoded word (which ntfy decodes).
fn header_text(s: &str) -> String {
    if s.bytes().all(|b| (32..=126).contains(&b)) {
        s.to_string()
    } else {
        format!("=?UTF-8?B?{}?=", base64(s.as_bytes()))
    }
}

fn base64(data: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ABC[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Hex HMAC-SHA256 of `"{ts}.{body}"` under `secret`.
pub(crate) fn sign(secret: &str, ts: u64, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(ts.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    ctx.sign()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(raw.as_bytes()), enc);
        }
    }

    #[test]
    fn hmac_matches_rfc4231() {
        // RFC 4231 test case 2 checks the HMAC; then `sign` must equal
        // the HMAC of "{ts}.{body}".
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"Jefe");
        let tag = ring::hmac::sign(&key, b"what do ya want for nothing?");
        let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let direct = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"k"),
            b"7.{}",
        );
        let hex: String = direct.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sign("k", 7, b"{}"), hex);
    }

    #[test]
    fn status_lines() {
        let mut r: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 503 Service Unavailable\r\n";
        assert_eq!(status(&mut r).unwrap(), (503, "Service Unavailable".into()));
        let mut r: &[u8] = b"HTTP/1.0 204\n";
        assert_eq!(status(&mut r).unwrap(), (204, String::new()));
        let mut r: &[u8] = b"SSH-2.0-OpenSSH\r\n";
        assert!(status(&mut r).is_err());
        let mut r: &[u8] = b"HTTP/1.1 200";
        assert!(status(&mut r).is_err());
    }
}
