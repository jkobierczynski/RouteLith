//! `type = "email"` (doc §21.5 F10): one e-mail per event over SMTP, sent
//! with lettre over rustls. The mail is plain text (the event's message
//! and fields); for an event with a series, a PNG of the series' smoke
//! graph is attached.
//!
//! A permanent SMTP refusal (5xx: unknown recipient, refused sender,
//! failed login) drops the event, as retrying cannot help; a transient one
//! (4xx) and network errors are retried.

use std::sync::Arc;
use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Message, SmtpTransport, Transport};
use rl_core::output::{EmailOutput, SmtpSecurity};
use rl_store::Event;

use crate::webhook::{facts, title};
use crate::{Failure, Sink};

/// How long one SMTP read or write may take.
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Draws the graph attached to an e-mail: a PNG of `e`'s series over the
/// `span` before now. `Ok(None)` when the event has no graph to draw.
pub type GraphFn = Arc<dyn Fn(&Event, Duration) -> Result<Option<Vec<u8>>, String> + Send + Sync>;

pub(crate) struct EmailSink {
    transport: SmtpTransport,
    from: Mailbox,
    to: Vec<Mailbox>,
    graph_span: Option<Duration>,
    graph: Option<GraphFn>,
    /// `host:port`, for messages.
    server: String,
}

impl std::fmt::Debug for EmailSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailSink")
            .field("server", &self.server)
            .field("to", &self.to.len())
            .finish_non_exhaustive()
    }
}

impl EmailSink {
    /// Checks now what can be checked: the addresses and the CA file.
    pub(crate) fn new(
        cfg: &EmailOutput,
        hostname: Option<&str>,
        graph: Option<GraphFn>,
    ) -> Result<Self, String> {
        let from: Mailbox = cfg
            .from
            .parse()
            .map_err(|e| format!("from {:?}: {e}", cfg.from))?;
        let to = cfg
            .to
            .iter()
            .map(|a| a.parse().map_err(|e| format!("to {a:?}: {e}")))
            .collect::<Result<Vec<Mailbox>, String>>()?;
        let tls = |cfg: &EmailOutput| -> Result<TlsParameters, String> {
            let mut b = TlsParameters::builder(cfg.host.clone());
            if let Some(path) = &cfg.ca_file {
                for der in crate::tls::certs(path, "ca_file")? {
                    let cert = Certificate::from_der(der.to_vec())
                        .map_err(|e| format!("ca_file {}: {e}", path.display()))?;
                    b = b.add_root_certificate(cert);
                }
            }
            b.build_rustls().map_err(|e| format!("TLS setup: {e}"))
        };
        let tls = match cfg.security {
            SmtpSecurity::StartTls => Tls::Required(tls(cfg)?),
            SmtpSecurity::Tls => Tls::Wrapper(tls(cfg)?),
            SmtpSecurity::None => Tls::None,
        };
        let mut b = SmtpTransport::builder_dangerous(cfg.host.clone())
            .port(cfg.port)
            .tls(tls)
            .timeout(Some(SMTP_TIMEOUT))
            .hello_name(ClientId::Domain(
                hostname.unwrap_or("localhost").to_string(),
            ));
        if let (Some(u), Some(p)) = (&cfg.username, &cfg.password) {
            b = b.credentials(Credentials::new(u.clone(), p.expose().to_string()));
        }
        let server = if cfg.host.contains(':') {
            format!("[{}]:{}", cfg.host, cfg.port)
        } else {
            format!("{}:{}", cfg.host, cfg.port)
        };
        Ok(Self {
            transport: b.build(),
            from,
            to,
            graph_span: cfg.graph,
            graph,
            server,
        })
    }

    fn message(&self, e: &Event) -> Result<Message, String> {
        let mut text = format!("{}\n\n", e.message);
        for (k, v) in facts(e) {
            text += &format!("{k}: {v}\n");
        }
        let png = match (&self.graph, self.graph_span) {
            (Some(g), Some(span)) => match g(e, span) {
                Ok(p) => p,
                Err(err) => {
                    // The mail still goes out, without the picture.
                    text += &format!("\n(The graph could not be drawn: {err})\n");
                    None
                }
            },
            _ => None,
        };
        let mut b = Message::builder()
            .from(self.from.clone())
            .subject(title(e))
            .date_now();
        for t in &self.to {
            b = b.to(t.clone());
        }
        let body = SinglePart::plain(text);
        let built = match png {
            Some(png) => b.multipart(MultiPart::mixed().singlepart(body).singlepart(
                Attachment::new("graph.png".to_string()).body(
                    png,
                    ContentType::parse("image/png").map_err(|e| e.to_string())?,
                ),
            )),
            None => b.singlepart(body),
        };
        built.map_err(|e| format!("cannot build the mail: {e}"))
    }
}

impl Sink for EmailSink {
    fn deliver(&mut self, e: &Event) -> Result<(), Failure> {
        // A mail that cannot be built (an address lettre refuses) never
        // will be.
        let msg = self.message(e).map_err(Failure::Drop)?;
        match self.transport.send(&msg) {
            Ok(_) => Ok(()),
            Err(err) => {
                let what = format!("SMTP {}: {err}", self.server);
                if err.is_permanent() {
                    Err(Failure::Drop(what))
                } else {
                    Err(Failure::Retry(what))
                }
            }
        }
    }
}
