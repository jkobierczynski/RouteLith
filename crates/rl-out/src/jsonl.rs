//! `type = "jsonl"`: one JSON object per event, appended to a file, in the
//! event log's own shape.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use rl_store::Event;

use crate::Sink;

#[derive(Debug)]
pub(crate) struct JsonlSink {
    path: PathBuf,
    /// The line being written and how much of it is in the file: after a
    /// short write (disk full), the retry appends only the rest, so the
    /// line ends up whole.
    pending: Option<(Vec<u8>, usize)>,
}

impl JsonlSink {
    /// Checks now that the file can be opened for appending.
    pub(crate) fn new(path: &Path) -> Result<Self, String> {
        open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            pending: None,
        })
    }
}

fn open(path: &Path) -> Result<std::fs::File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))
}

impl Sink for JsonlSink {
    /// Opens the file for each event (events are rare), so a log rotator
    /// may move the file away at any time.
    fn deliver(&mut self, e: &Event) -> Result<(), String> {
        // The worker retries the same event until it goes through, so a
        // pending line is this event's.
        let (line, mut done) = match self.pending.take() {
            Some(p) => p,
            None => {
                let mut line = serde_json::to_vec(e).map_err(|err| err.to_string())?;
                line.push(b'\n');
                (line, 0)
            }
        };
        let mut f = match open(&self.path) {
            Ok(f) => f,
            Err(err) => {
                self.pending = Some((line, done));
                return Err(err);
            }
        };
        while done < line.len() {
            match f.write(&line[done..]) {
                Ok(0) => {
                    self.pending = Some((line, done));
                    return Err(format!("cannot write {}: no space", self.path.display()));
                }
                Ok(n) => done += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => {
                    self.pending = Some((line, done));
                    return Err(format!("cannot write {}: {err}", self.path.display()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_store::EventKind;

    #[test]
    fn a_retry_after_a_short_write_appends_only_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jsonl");
        let mut sink = JsonlSink::new(&path).unwrap();
        let e = Event::new(1, EventKind::ServerStarted, "local", "started");
        let mut line = serde_json::to_vec(&e).unwrap();
        line.push(b'\n');
        // As if the disk filled after 10 bytes.
        std::fs::write(&path, &line[..10]).unwrap();
        sink.pending = Some((line.clone(), 10));
        sink.deliver(&e).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), line);
        assert!(sink.pending.is_none());
    }
}
