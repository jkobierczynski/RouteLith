//! Series index in `meta.redb`: (vantage, target, family) → series id.
//!
//! redb holds an exclusive lock while a database is open, so the index is
//! opened only for a moment: the writer registers its series at startup,
//! and readers (such as `ctl render` while the server runs) load the whole
//! index into memory, retrying briefly if the other side has it open.

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use redb::{Database, DatabaseError, ReadableTable, TableDefinition};

use crate::StoreError;
use crate::layout::index_path;

const SERIES: TableDefinition<&str, u64> = TableDefinition::new("series");
const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("counters");
const NEXT_ID: &str = "next_series_id";
const SEP: char = '\u{1f}';
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// What a series measures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SeriesKey {
    pub vantage: String,
    pub target: String,
    /// `v4`, `v6` or `prefer-v6`.
    pub family: String,
}

impl SeriesKey {
    pub fn new(vantage: &str, target: &str, family: &str) -> Self {
        Self {
            vantage: vantage.to_string(),
            target: target.to_string(),
            family: family.to_string(),
        }
    }

    fn encode(&self) -> String {
        format!("{}{SEP}{}{SEP}{}", self.vantage, self.target, self.family)
    }

    fn decode(s: &str) -> Option<Self> {
        let mut it = s.split(SEP);
        let key = Self::new(it.next()?, it.next()?, it.next()?);
        it.next().is_none().then_some(key)
    }
}

impl fmt::Display for SeriesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.vantage, self.target, self.family)
    }
}

fn index_err(e: impl fmt::Display) -> StoreError {
    StoreError::Index(e.to_string())
}

/// Open the database, waiting up to [`LOCK_WAIT`] while another process has it.
fn open(dir: &Path, create: bool) -> Result<Option<Database>, StoreError> {
    let path = index_path(dir);
    if !create && !path.exists() {
        return Ok(None);
    }
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        let res = if create {
            Database::create(&path)
        } else {
            Database::open(&path)
        };
        match res {
            Ok(db) => return Ok(Some(db)),
            Err(DatabaseError::DatabaseAlreadyOpen) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(DatabaseError::DatabaseAlreadyOpen) => {
                return Err(StoreError::Index(format!(
                    "{} is held by another process",
                    path.display()
                )));
            }
            Err(e) => return Err(index_err(e)),
        }
    }
}

/// Look up or assign ids for `keys`, in order.
pub(crate) fn register(dir: &Path, keys: &[SeriesKey]) -> Result<Vec<u64>, StoreError> {
    let db = open(dir, true)?.ok_or_else(|| index_err("index missing"))?;
    let tx = db.begin_write().map_err(index_err)?;
    let mut ids = Vec::with_capacity(keys.len());
    {
        let mut series = tx.open_table(SERIES).map_err(index_err)?;
        let mut counters = tx.open_table(COUNTERS).map_err(index_err)?;
        let mut next = counters
            .get(NEXT_ID)
            .map_err(index_err)?
            .map_or(1, |v| v.value());
        for key in keys {
            let k = key.encode();
            let existing = series
                .get(k.as_str())
                .map_err(index_err)?
                .map(|v| v.value());
            let id = match existing {
                Some(id) => id,
                None => {
                    let id = next;
                    next += 1;
                    series.insert(k.as_str(), id).map_err(index_err)?;
                    id
                }
            };
            ids.push(id);
        }
        counters.insert(NEXT_ID, next).map_err(index_err)?;
    }
    tx.commit().map_err(index_err)?;
    Ok(ids)
}

/// Every registered series, sorted by key. Empty if there is no index yet.
pub(crate) fn load(dir: &Path) -> Result<Vec<(SeriesKey, u64)>, StoreError> {
    let Some(db) = open(dir, false)? else {
        return Ok(Vec::new());
    };
    let tx = db.begin_read().map_err(index_err)?;
    let table = match tx.open_table(SERIES) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(index_err(e)),
    };
    let mut out = Vec::new();
    for entry in table.iter().map_err(index_err)? {
        let (k, v) = entry.map_err(index_err)?;
        let key = SeriesKey::decode(k.value())
            .ok_or_else(|| index_err(format!("malformed series key {:?}", k.value())))?;
        out.push((key, v.value()));
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_unique() {
        let dir = tempfile::tempdir().unwrap();
        let a = SeriesKey::new("local", "gw", "v4");
        let b = SeriesKey::new("local", "gw", "v6");
        assert_eq!(
            register(dir.path(), &[a.clone(), b.clone()]).unwrap(),
            [1, 2]
        );
        let c = SeriesKey::new("local", "dns", "v4");
        assert_eq!(
            register(dir.path(), &[b.clone(), c.clone()]).unwrap(),
            [2, 3]
        );
        assert_eq!(load(dir.path()).unwrap(), vec![(c, 3), (a, 1), (b, 2)]);
    }

    #[test]
    fn missing_index_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn keys_round_trip() {
        let k = SeriesKey::new("v", "t", "prefer-v6");
        assert_eq!(SeriesKey::decode(&k.encode()), Some(k));
        assert_eq!(SeriesKey::decode("a"), None);
    }
}
