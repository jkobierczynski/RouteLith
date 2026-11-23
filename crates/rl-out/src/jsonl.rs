//! `type = "jsonl"`: one JSON object per event, appended to a file, in the
//! event log's own shape.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rl_store::Event;

use crate::{Failure, Sink};

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
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))
}

/// Whether the file ends partway through a line: a write cut short and then
/// given up on (the server stopped before the retry), or another writer.
fn ends_mid_line(file: &mut std::fs::File) -> std::io::Result<bool> {
    if file.metadata()?.len() == 0 {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] != b'\n')
}

impl Sink for JsonlSink {
    /// Opens the file for each event (events are rare), so a log rotator
    /// may move the file away between events.
    fn deliver(&mut self, e: &Event) -> Result<(), Failure> {
        // The worker retries the same event until it goes through, so a
        // pending line is this event's.
        let mut p = match self.pending.take() {
            Some(p) => p,
            None => {
                let mut file = open(&self.path)?;
                // End a cut-off line first, so it cannot run into this one:
                // the cut-off line stays unreadable, but this one is whole.
                let mut line = match ends_mid_line(&mut file) {
                    Ok(true) => vec![b'\n'],
                    Ok(false) => Vec::new(),
                    Err(err) => {
                        return Err(format!("cannot read {}: {err}", self.path.display()).into());
                    }
                };
                serde_json::to_writer(&mut line, e).map_err(|err| err.to_string())?;
                line.push(b'\n');
                Pending {
                    line,
                    done: 0,
                    file,
                }
            }
        };
        while p.done < p.line.len() {
            match p.file.write(&p.line[p.done..]) {
                Ok(0) => {
                    self.pending = Some(p);
                    return Err(format!("cannot write {}: no space", self.path.display()).into());
                }
                Ok(n) => p.done += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => {
                    self.pending = Some(p);
                    return Err(format!("cannot write {}: {err}", self.path.display()).into());
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

    #[test]
    fn a_line_cut_off_before_a_restart_does_not_spoil_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.jsonl");
        let e = Event::new(1, EventKind::ServerStarted, "local", "started");
        let mut line = serde_json::to_vec(&e).unwrap();
        line.push(b'\n');
        // A short write, then the server stopped before the retry.
        std::fs::write(&path, &line[..10]).unwrap();
        let mut sink = JsonlSink::new(&path).unwrap();
        sink.deliver(&e).unwrap();
        let text = std::fs::read(&path).unwrap();
        let lines: Vec<&[u8]> = text.split(|&b| b == b'\n').collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], &line[..10]);
        assert_eq!(lines[1], &line[..line.len() - 1]);
        assert!(lines[2].is_empty());
        // A whole file gets nothing extra.
        sink.deliver(&e).unwrap();
        let mut want = text.clone();
        want.extend_from_slice(&line);
        assert_eq!(std::fs::read(&path).unwrap(), want);
    }
}
