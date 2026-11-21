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
}

impl JsonlSink {
    /// Checks now that the file can be opened for appending.
    pub(crate) fn new(path: &Path) -> Result<Self, String> {
        open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
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
    /// may move the file away at any time; one write per line, so lines
    /// from a crash are whole or missing.
    fn deliver(&mut self, e: &Event) -> Result<(), String> {
        let mut line = serde_json::to_vec(e).map_err(|err| err.to_string())?;
        line.push(b'\n');
        let mut f = open(&self.path)?;
        let before = f.metadata().map(|m| m.len()).ok();
        f.write_all(&line).map_err(|err| {
            // A short write (disk full) leaves part of the line; cut it off
            // so the retry does not append to a broken line.
            if let Some(len) = before {
                let _ = f.set_len(len);
            }
            format!("cannot write {}: {err}", self.path.display())
        })
    }
}
