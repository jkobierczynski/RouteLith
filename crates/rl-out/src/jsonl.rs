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
    /// The line being written, how much of it is in the file, and the file:
    /// after a short write (disk full), the retry appends only the rest to
    /// the same file (even if it was rotated meanwhile), so the line ends
    /// up whole.
    pending: Option<Pending>,
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

#[derive(Debug)]
struct Pending {
    line: Vec<u8>,
    done: usize,
    file: std::fs::File,
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
    /// may move the file away between events.
    fn deliver(&mut self, e: &Event) -> Result<(), String> {
        // The worker retries the same event until it goes through, so a
        // pending line is this event's.
        let mut p = match self.pending.take() {
            Some(p) => p,
            None => {
                let mut line = serde_json::to_vec(e).map_err(|err| err.to_string())?;
                line.push(b'\n');
                Pending {
                    line,
                    done: 0,
                    file: open(&self.path)?,
                }
            }
        };
        while p.done < p.line.len() {
            match p.file.write(&p.line[p.done..]) {
                Ok(0) => {
                    self.pending = Some(p);
                    return Err(format!("cannot write {}: no space", self.path.display()));
                }
                Ok(n) => p.done += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => {
                    self.pending = Some(p);
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
        // As if the disk filled after 10 bytes, and the file was rotated
        // before the retry: the rest still goes to the rotated file.
        std::fs::write(&path, &line[..10]).unwrap();
        sink.pending = Some(Pending {
            line: line.clone(),
            done: 10,
            file: open(&path).unwrap(),
        });
        let rotated = dir.path().join("e.jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        sink.deliver(&e).unwrap();
        assert_eq!(std::fs::read(&rotated).unwrap(), line);
        assert!(sink.pending.is_none());
        // The next event opens the path again.
        sink.deliver(&e).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), line);
    }
}
