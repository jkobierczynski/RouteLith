//! `type = "eventlog"`: events written to the Windows Application log under
//! source `Routelith` (doc §11.3, F8), for Event Viewer and for forwarding
//! with WEF.
//!
//! Each kind of event has its own event ID ([`event_id`]). The message is
//! the first insertion string; the message table built into routelith.exe
//! shows it as the event's text (`%1`) once `routelith service install` or
//! the MSI has registered the source. The other strings are the event's
//! fields, in the order of [`strings`], for forwarding rules to pick from.

use rl_store::{Event, EventKind};
use rl_sys::eventlog::{EventSource, Level};

use crate::{Failure, Sink};

/// The event source routelith writes as.
pub const SOURCE: &str = "Routelith";

/// The event ID and level of each kind of event. IDs 1000-1099 are alerts
/// and changes on targets, 2000-2099 agents (M3), 3000-3099 the server.
pub fn event_id(kind: EventKind) -> (u32, Level) {
    match kind {
        EventKind::AlertRaised => (1000, Level::Warning),
        EventKind::AlertCleared => (1001, Level::Information),
        EventKind::IpChanged => (1002, Level::Information),
        EventKind::ServerStarted => (3000, Level::Information),
        EventKind::ServerStopped => (3001, Level::Information),
        EventKind::AgentEnrolled => (2000, Level::Information),
        EventKind::AgentConnected => (2001, Level::Information),
        EventKind::AgentDisconnected => (2002, Level::Warning),
        EventKind::AgentRevoked => (2003, Level::Warning),
        EventKind::AgentClockSkew => (2004, Level::Warning),
        EventKind::AgentClockOk => (2005, Level::Information),
        EventKind::AgentRoundsLost => (2006, Level::Warning),
        EventKind::Unknown => (3099, Level::Information),
    }
}

/// The insertion strings: message, kind, time (UTC), vantage, target,
/// family, series, rule, value, since (UTC), from, to. A field the event
/// does not have is an empty string, so each keeps its position.
pub fn strings(e: &Event) -> Vec<String> {
    let opt = |v: &Option<String>| v.clone().unwrap_or_default();
    vec![
        e.message.clone(),
        e.kind.as_str().to_string(),
        crate::syslog::rfc3339(e.t),
        e.vantage.clone(),
        opt(&e.target),
        opt(&e.family),
        e.series.map(|s| s.to_string()).unwrap_or_default(),
        opt(&e.rule),
        e.value.map(|v| v.to_string()).unwrap_or_default(),
        e.since.map(crate::syslog::rfc3339).unwrap_or_default(),
        opt(&e.from),
        opt(&e.to),
    ]
}

#[derive(Debug)]
pub(crate) struct EventLogSink {
    source: Option<EventSource>,
    name: String,
}

impl EventLogSink {
    /// Checks now that the source can be opened.
    pub(crate) fn new(name: &str) -> Result<Self, String> {
        let source =
            EventSource::open(name).map_err(|e| format!("cannot open event source {name}: {e}"))?;
        Ok(Self {
            source: Some(source),
            name: name.to_string(),
        })
    }
}

impl Sink for EventLogSink {
    fn deliver(&mut self, e: &Event) -> Result<(), Failure> {
        let source = match &mut self.source {
            Some(s) => s,
            None => self.source.insert(
                EventSource::open(&self.name)
                    .map_err(|err| format!("cannot open event source {}: {err}", self.name))?,
            ),
        };
        let (id, level) = event_id(e.kind);
        let strings = strings(e);
        let refs: Vec<&str> = strings.iter().map(String::as_str).collect();
        source
            .report(level, id, &refs)
            .map_err(|err| Failure::Retry(format!("cannot write to the event log: {err}")))
    }

    fn reset(&mut self) {
        self.source = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes under a test source and reads the event back with wevtutil:
    /// its ID, level and strings.
    #[test]
    fn events_reach_the_application_log() {
        let source = format!("Routelith-test-{}", std::process::id());
        let mut sink = EventLogSink::new(&source).unwrap();
        let mut e = Event::new(
            1_795_427_500_301,
            EventKind::AlertRaised,
            "local",
            "gw (v4): down raised",
        );
        e.target = Some("gw".into());
        e.rule = Some("down".into());
        e.value = Some(100.0);
        sink.deliver(&e).unwrap();
        let query = format!("*[System[Provider[@Name='{source}']]]");
        let out = std::process::Command::new("wevtutil")
            .args([
                "qe",
                "Application",
                &format!("/q:{query}"),
                "/c:1",
                "/rd:true",
                "/f:xml",
            ])
            .output()
            .unwrap();
        let xml = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{xml} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(xml.contains(">1000</EventID>"), "{xml}");
        assert!(xml.contains("<Level>3</Level>"), "{xml}"); // warning
        for s in [
            "gw (v4): down raised",
            "alert_raised",
            "2026-11-23T09:51:40.301Z",
            "gw",
            "down",
            "100",
        ] {
            assert!(xml.contains(&format!("<Data>{s}</Data>")), "{s}: {xml}");
        }
    }
}
