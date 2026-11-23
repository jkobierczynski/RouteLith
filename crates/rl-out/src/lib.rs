//! Outputs (architecture doc §11.2, §11.3, §21.5 F7, F8): events sent on
//! from the event log to syslog receivers, JSON-lines files and (on
//! Windows) the Windows Event Log.
//!
//! Each output has its own bounded queue and its own thread. [`Outputs::send`]
//! only filters and queues, so it never waits on the network or a disk: a
//! receiver that is down fills its own queue, and further events for it are
//! dropped and counted, while the store and the other outputs go on. The
//! thread retries the event in hand with a growing pause (1 s up to a
//! minute) until it goes through.
//!
//! Alerts raised under a silence or while the target's parent had an alert
//! (§21.5 F6), and their clears, are not sent unless the output sets
//! `quiet = true`.

#![forbid(unsafe_code)]

#[cfg(windows)]
pub mod eventlog;
mod jsonl;
mod syslog;
mod tls;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rl_core::output::{EventFilter, Output, OutputKind};
use rl_store::Event;

pub use syslog::{Header, format_rfc3164, format_rfc5424, machine_hostname};

/// The first pause after a failed send; it doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How long a connection attempt or a write may take.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// What `/metrics` shows of one output.
#[derive(Debug)]
pub struct OutputStats {
    pub name: String,
    /// `syslog`, `jsonl` or `eventlog`.
    pub kind: &'static str,
    /// Events delivered.
    pub sent: AtomicU64,
    /// Events dropped: the queue was full, or the server stopped before
    /// they could be delivered.
    pub dropped: AtomicU64,
    /// Failed delivery attempts (each retry counts).
    pub errors: AtomicU64,
    /// Events waiting in the queue.
    pub queued: AtomicU64,
    /// False from a failed attempt until the next one that works.
    pub up: AtomicBool,
}

impl OutputStats {
    fn new(name: &str, kind: &'static str) -> Self {
        Self {
            name: name.to_string(),
            kind,
            sent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            up: AtomicBool::new(true),
        }
    }
}

/// Where an output delivers to. `deliver` may block; it runs on the
/// output's own thread.
pub(crate) trait Sink: Send {
    fn deliver(&mut self, e: &Event) -> Result<(), String>;
    /// Drop any connection after a failure, so the next try starts fresh.
    fn reset(&mut self) {}
}

/// Tells the output threads when the server is stopping.
#[derive(Debug, Default)]
struct Stop {
    deadline: Mutex<Option<Instant>>,
    cv: Condvar,
}

impl Stop {
    fn deadline(&self) -> Option<Instant> {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sleep for `d`, or less if a stop deadline comes first.
    fn pause(&self, d: Duration) {
        let until = Instant::now() + d;
        let mut g = self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let now = Instant::now();
            let end = g.map_or(until, |dl| dl.min(until));
            if now >= end {
                return;
            }
            g = self
                .cv
                .wait_timeout(g, end - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

#[derive(Debug)]
struct Running {
    filter: EventFilter,
    tx: SyncSender<Arc<Event>>,
    stats: Arc<OutputStats>,
    thread: JoinHandle<()>,
}

/// The configured outputs.
#[derive(Debug)]
pub struct Outputs {
    running: Vec<Running>,
    /// The group of each target, for `groups` filters.
    groups: HashMap<String, String>,
    stop: Arc<Stop>,
}

impl Outputs {
    /// No outputs.
    pub fn none() -> Self {
        Self {
            running: Vec::new(),
            groups: HashMap::new(),
            stop: Arc::default(),
        }
    }

    /// Start a thread for each output. `groups` maps each target to its
    /// group. Fails on what can be checked now: unreadable certificate
    /// files, a JSON-lines file that cannot be opened.
    pub fn start(outputs: &[Output], groups: HashMap<String, String>) -> Result<Self, String> {
        let hostname = machine_hostname();
        let mut sinks: Vec<(&Output, Box<dyn Sink>)> = Vec::new();
        // The file each JSON-lines output writes, as the system resolves it:
        // the config check compares paths as written, which misses `..` and
        // symbolic links.
        let mut files: HashMap<std::path::PathBuf, &str> = HashMap::new();
        for o in outputs {
            let sink: Box<dyn Sink> = match &o.kind {
                OutputKind::Syslog(s) => Box::new(
                    syslog::SyslogSink::new(s, hostname.as_deref())
                        .map_err(|e| format!("output {:?}: {e}", o.name))?,
                ),
                OutputKind::Jsonl(j) => {
                    let sink = jsonl::JsonlSink::new(&j.path)
                        .map_err(|e| format!("output {:?}: {e}", o.name))?;
                    let real = std::fs::canonicalize(&j.path).map_err(|e| {
                        format!(
                            "output {:?}: cannot resolve {}: {e}",
                            o.name,
                            j.path.display()
                        )
                    })?;
                    if let Some(first) = files.insert(real, &o.name) {
                        // Two writers would interleave their lines.
                        return Err(format!(
                            "output {:?}: output {first:?} already writes {}",
                            o.name,
                            j.path.display()
                        ));
                    }
                    Box::new(sink)
                }
                #[cfg(windows)]
                OutputKind::EventLog => Box::new(
                    eventlog::EventLogSink::new(eventlog::SOURCE)
                        .map_err(|e| format!("output {:?}: {e}", o.name))?,
                ),
                #[cfg(not(windows))]
                OutputKind::EventLog => {
                    return Err(format!(
                        "output {:?}: the Windows Event Log exists only on Windows",
                        o.name
                    ));
                }
            };
            sinks.push((o, sink));
        }
        Self::with_sinks(sinks, groups)
    }

    /// Start a thread for each output with its sink.
    fn with_sinks(
        sinks: Vec<(&Output, Box<dyn Sink>)>,
        groups: HashMap<String, String>,
    ) -> Result<Self, String> {
        let stop = Arc::new(Stop::default());
        let mut running = Vec::new();
        for (o, sink) in sinks {
            let (tx, rx) = std::sync::mpsc::sync_channel(o.queue);
            let stats = Arc::new(OutputStats::new(&o.name, o.kind.type_name()));
            let (st, sp) = (stats.clone(), stop.clone());
            let thread = std::thread::Builder::new()
                .name(format!("output {}", o.name))
                .spawn(move || work(&rx, sink, &st, &sp))
                .map_err(|e| format!("output {:?}: cannot start its thread: {e}", o.name))?;
            running.push(Running {
                filter: o.filter.clone(),
                tx,
                stats,
                thread,
            });
        }
        Ok(Self {
            running,
            groups,
            stop,
        })
    }

    /// Queue an event for each output whose filter takes it. Never blocks.
    pub fn send(&self, e: &Event) {
        let mut shared: Option<Arc<Event>> = None;
        for r in &self.running {
            if !passes(&r.filter, e, &self.groups) {
                continue;
            }
            let ev = shared.get_or_insert_with(|| Arc::new(e.clone())).clone();
            r.stats.queued.fetch_add(1, Ordering::Relaxed);
            match r.tx.try_send(ev) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    r.stats.queued.fetch_sub(1, Ordering::Relaxed);
                    if r.stats.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                        eprintln!(
                            "routelith server: output {}: queue full, dropping events \
                             (counted in routelith_output_events_dropped_total)",
                            r.stats.name
                        );
                    }
                }
            }
        }
    }

    pub fn stats(&self) -> Vec<Arc<OutputStats>> {
        self.running.iter().map(|r| r.stats.clone()).collect()
    }

    /// Deliver what is queued, for at most about `grace` (plus the one
    /// attempt under way then), then drop the rest and end the threads.
    pub fn close(self, grace: Duration) {
        *self
            .stop
            .deadline
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now() + grace);
        self.stop.cv.notify_all();
        let threads: Vec<_> = self
            .running
            .into_iter()
            .map(|r| {
                drop(r.tx);
                r.thread
            })
            .collect();
        for t in threads {
            let _ = t.join();
        }
    }
}

/// Whether an output with `f` takes `e`.
pub fn passes(f: &EventFilter, e: &Event, groups: &HashMap<String, String>) -> bool {
    if !f.quiet && (e.silenced_by.is_some() || e.suppressed_by.is_some()) {
        return false;
    }
    if !f.events.is_empty() && !f.events.iter().any(|k| k == e.kind.as_str()) {
        return false;
    }
    if !f.targets.is_empty() || !f.groups.is_empty() {
        let Some(t) = e.target.as_deref() else {
            return false;
        };
        let in_group = groups.get(t).is_some_and(|g| f.groups.contains(g));
        if !f.targets.iter().any(|x| x == t) && !in_group {
            return false;
        }
    }
    if let (false, Some(rule)) = (f.alerts.is_empty(), e.rule.as_deref()) {
        if !f.alerts.iter().any(|a| a == rule) {
            return false;
        }
    }
    true
}

/// An output's thread: deliver each queued event, retrying until it goes
/// through or the server stops.
fn work(rx: &Receiver<Arc<Event>>, mut sink: Box<dyn Sink>, stats: &OutputStats, stop: &Stop) {
    let mut last_error: Option<String> = None;
    // Set once the stop deadline has passed: the rest is dropped.
    let mut giving_up = false;
    while let Ok(e) = rx.recv() {
        stats.queued.fetch_sub(1, Ordering::Relaxed);
        if giving_up {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let mut backoff = FIRST_BACKOFF;
        loop {
            if stop.deadline().is_some_and(|d| Instant::now() >= d) {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                giving_up = true;
                break;
            }
            match sink.deliver(&e) {
                Ok(()) => {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats.up.store(true, Ordering::Relaxed);
                    if last_error.take().is_some() {
                        eprintln!("routelith server: output {}: sending again", stats.name);
                    }
                    break;
                }
                Err(msg) => {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    stats.up.store(false, Ordering::Relaxed);
                    sink.reset();
                    if last_error.as_deref() != Some(msg.as_str()) {
                        eprintln!(
                            "routelith server: output {}: cannot send, will retry: {msg}",
                            stats.name
                        );
                        last_error = Some(msg);
                    }
                    stop.pause(backoff);
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
