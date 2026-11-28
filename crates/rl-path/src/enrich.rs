//! Hop enrichment on the server (architecture doc §21.9 P9): reverse DNS
//! through the OS resolver, ASN and organisation from an offline iptoasn
//! file, and the built-in address classes. Nothing here goes out to the
//! internet except the OS resolver's own PTR lookups.

use std::collections::HashMap;
use std::io::BufRead;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use rl_core::addr::{AddrClass, classify};
use serde::Serialize;
use tokio::sync::Semaphore;

/// How long a name is kept.
pub const RDNS_TTL: Duration = Duration::from_secs(3600);
/// How long a failed lookup is kept before it is tried again.
pub const RDNS_FAIL_TTL: Duration = Duration::from_secs(600);
/// Lookups running at once.
pub const RDNS_PARALLEL: usize = 4;

/// An AS and its holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsnInfo {
    pub asn: u32,
    /// Two-letter country code as the file has it ("None" when unknown).
    pub country: Arc<str>,
    pub org: Arc<str>,
}

/// An iptoasn database (`ip2asn-combined.tsv`, optionally gzipped): one
/// line per range, `start \t end \t asn \t country \t description`.
#[derive(Debug, Default)]
pub struct AsnDb {
    v4: Vec<(u32, u32, u32)>,
    v6: Vec<(u128, u128, u32)>,
    /// Indexed by the third field of a range.
    names: Vec<AsnInfo>,
}

impl AsnDb {
    /// Load a `.tsv` or `.tsv.gz` file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let f = std::fs::File::open(path)?;
        let gz = path.extension().is_some_and(|e| e == "gz");
        if gz {
            Self::parse(std::io::BufReader::new(flate2::read::MultiGzDecoder::new(
                f,
            )))
        } else {
            Self::parse(std::io::BufReader::new(f))
        }
    }

    /// Parse the file's lines. Lines that do not parse, and ranges of AS 0
    /// ("Not routed"), are skipped.
    pub fn parse(r: impl BufRead) -> std::io::Result<Self> {
        let mut db = Self::default();
        let mut by_asn: HashMap<(u32, String, String), u32> = HashMap::new();
        for line in r.lines() {
            let line = line?;
            let mut f = line.split('\t');
            let (Some(start), Some(end), Some(asn), Some(cc), Some(desc)) =
                (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let (Ok(start), Ok(end), Ok(asn)) = (
                start.parse::<IpAddr>(),
                end.parse::<IpAddr>(),
                asn.parse::<u32>(),
            ) else {
                continue;
            };
            if asn == 0 {
                continue;
            }
            let key = (asn, cc.to_string(), desc.to_string());
            let next = u32::try_from(db.names.len()).unwrap_or(u32::MAX);
            let idx = *by_asn.entry(key).or_insert_with(|| {
                db.names.push(AsnInfo {
                    asn,
                    country: cc.into(),
                    org: desc.into(),
                });
                next
            });
            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) if s <= e => db.v4.push((s.into(), e.into(), idx)),
                (IpAddr::V6(s), IpAddr::V6(e)) if s <= e => db.v6.push((s.into(), e.into(), idx)),
                _ => {}
            }
        }
        db.v4.sort_unstable();
        db.v6.sort_unstable();
        Ok(db)
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The AS whose range holds `addr`, if any.
    pub fn lookup(&self, addr: IpAddr) -> Option<&AsnInfo> {
        fn find<T: Ord + Copy>(ranges: &[(T, T, u32)], a: T) -> Option<u32> {
            let i = ranges.partition_point(|r| r.0 <= a);
            let r = ranges.get(i.checked_sub(1)?)?;
            (a <= r.1).then_some(r.2)
        }
        let idx = match addr {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(a)),
            },
        }?;
        self.names.get(idx as usize)
    }
}

/// The iptoasn file named by `[server] asn_db`, reloaded when it changes.
#[derive(Debug)]
pub struct AsnSource {
    path: PathBuf,
    db: RwLock<Option<Arc<AsnDb>>>,
    loaded: Mutex<Option<SystemTime>>,
}

impl AsnSource {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            db: RwLock::new(None),
            loaded: Mutex::new(None),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The database as last loaded.
    pub fn get(&self) -> Option<Arc<AsnDb>> {
        self.db
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Load the file if it is new or changed since the last load. Blocking;
    /// returns the number of ranges when it loaded. A failed load keeps the
    /// database loaded before.
    pub fn refresh(&self) -> std::io::Result<Option<usize>> {
        let mtime = std::fs::metadata(&self.path)?.modified()?;
        {
            let loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
            if *loaded == Some(mtime) {
                return Ok(None);
            }
        }
        let db = AsnDb::load(&self.path)?;
        let n = db.len();
        *self.db.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(db));
        *self.loaded.lock().unwrap_or_else(PoisonError::into_inner) = Some(mtime);
        Ok(Some(n))
    }
}

#[derive(Debug, Clone)]
enum Entry {
    Pending,
    Done {
        name: Option<String>,
        until: Instant,
    },
}

/// A PTR lookup: the name of an address, or `None`.
pub type LookupFn = Arc<dyn Fn(IpAddr) -> Option<String> + Send + Sync>;

/// The OS resolver's reverse lookup (getnameinfo with NI_NAMEREQD).
pub fn system_lookup(addr: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&addr).ok()
}

/// Reverse DNS with a cache: each address is looked up at most once per
/// [`RDNS_TTL`] (once per [`RDNS_FAIL_TTL`] after a failure), at most
/// [`RDNS_PARALLEL`] at once.
pub struct Rdns {
    cache: Mutex<HashMap<IpAddr, Entry>>,
    sem: Arc<Semaphore>,
    lookup: LookupFn,
    lookups: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Rdns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rdns").finish_non_exhaustive()
    }
}

impl Rdns {
    pub fn new(lookup: LookupFn) -> Arc<Self> {
        Arc::new(Self {
            cache: Mutex::new(HashMap::new()),
            sem: Arc::new(Semaphore::new(RDNS_PARALLEL)),
            lookup,
            lookups: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Lookups started since creation.
    pub fn lookups(&self) -> u64 {
        self.lookups.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The cached name of `addr`: `Some(name or None)` when known, `None`
    /// while unknown or being looked up. Starts a lookup when the entry is
    /// missing or expired; needs a tokio runtime.
    pub fn get(self: &Arc<Self>, addr: IpAddr) -> Option<Option<String>> {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        match cache.get(&addr) {
            Some(Entry::Done { name, until }) if *until > now => return Some(name.clone()),
            Some(Entry::Pending) => return None,
            _ => {}
        }
        cache.insert(addr, Entry::Pending);
        drop(cache);
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let name = match me.sem.clone().acquire_owned().await {
                Ok(_permit) => {
                    let lookup = Arc::clone(&me.lookup);
                    tokio::task::spawn_blocking(move || lookup(addr))
                        .await
                        .ok()
                        .flatten()
                }
                Err(_) => None,
            };
            let ttl = if name.is_some() {
                RDNS_TTL
            } else {
                RDNS_FAIL_TTL
            };
            me.cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    addr,
                    Entry::Done {
                        name,
                        until: Instant::now() + ttl,
                    },
                );
        });
        None
    }

    /// Names of `addrs`, waiting up to `wait` for lookups to finish; those
    /// still unknown then are left out.
    pub async fn names(
        self: &Arc<Self>,
        addrs: &[IpAddr],
        wait: Duration,
    ) -> HashMap<IpAddr, Option<String>> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut out = HashMap::new();
        loop {
            for &a in addrs {
                if out.contains_key(&a) {
                    continue;
                }
                if let Some(n) = self.get(a) {
                    out.insert(a, n);
                }
            }
            if out.len() == addrs.len() || tokio::time::Instant::now() >= deadline {
                return out;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// What the path view shows of a responder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HopInfo {
    /// `None` when there is no name or the lookup has not finished.
    pub rdns: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<Arc<str>>,
    pub country: Option<Arc<str>>,
    pub class: AddrClass,
}

/// Enrichment for the API: reverse DNS and, when configured, ASNs.
#[derive(Debug)]
pub struct Enricher {
    pub rdns: Arc<Rdns>,
    pub asn: Option<AsnSource>,
}

impl Enricher {
    /// What is known about `addrs`, waiting up to `wait` for names.
    pub async fn hops(&self, addrs: &[IpAddr], wait: Duration) -> HashMap<IpAddr, HopInfo> {
        let names = self.rdns.names(addrs, wait).await;
        let db = self.asn.as_ref().and_then(AsnSource::get);
        addrs
            .iter()
            .map(|&a| {
                let class = classify(a);
                let asn = db
                    .as_ref()
                    .filter(|_| class.is_public())
                    .and_then(|d| d.lookup(a).cloned());
                (
                    a,
                    HopInfo {
                        rdns: names.get(&a).cloned().flatten(),
                        asn: asn.as_ref().map(|i| i.asn),
                        org: asn.as_ref().map(|i| Arc::clone(&i.org)),
                        country: asn.map(|i| i.country),
                        class,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const FIXTURE: &str = "\
1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed
8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE
2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE
bad line
";

    #[test]
    fn ranges_are_found_and_not_routed_is_left_out() {
        let db = AsnDb::parse(FIXTURE.as_bytes()).unwrap();
        assert_eq!(db.len(), 3);
        let at = |s: &str| {
            db.lookup(s.parse().unwrap())
                .map(|i| (i.asn, i.org.to_string()))
        };
        assert_eq!(at("1.0.0.1"), Some((13335, "CLOUDFLARENET".into())));
        assert_eq!(at("1.0.0.255"), Some((13335, "CLOUDFLARENET".into())));
        assert_eq!(at("1.0.2.1"), None);
        assert_eq!(at("8.8.8.8"), Some((15169, "GOOGLE".into())));
        assert_eq!(at("2001:4860:4860::8888"), Some((15169, "GOOGLE".into())));
        assert_eq!(at("::ffff:8.8.8.8"), Some((15169, "GOOGLE".into())));
        assert_eq!(at("9.9.9.9"), None);
        assert_eq!(at("0.0.0.1"), None);
    }

    #[test]
    fn gzipped_files_load_and_reload_when_changed() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ip2asn-combined.tsv.gz");
        let write = |body: &str| {
            let f = std::fs::File::create(&path).unwrap();
            let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            gz.write_all(body.as_bytes()).unwrap();
            gz.finish().unwrap();
        };
        write(FIXTURE);
        let src = AsnSource::new(path.clone());
        assert_eq!(src.refresh().unwrap(), Some(3));
        assert_eq!(src.refresh().unwrap(), None, "unchanged");
        write("9.9.9.0\t9.9.9.255\t19281\tUS\tQUAD9\n");
        // Make sure the modification time moves.
        let later = SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(src.refresh().unwrap(), Some(1));
        let db = src.get().unwrap();
        assert_eq!(db.lookup("9.9.9.9".parse().unwrap()).unwrap().asn, 19281);
    }

    #[tokio::test]
    async fn each_address_is_looked_up_once_per_ttl() {
        let calls = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&calls);
        let rdns = Rdns::new(Arc::new(move |a: IpAddr| {
            c.fetch_add(1, Ordering::Relaxed);
            (a == IpAddr::from([192, 0, 2, 1])).then(|| "gw.example.net".to_string())
        }));
        let addrs: Vec<IpAddr> = vec![[192, 0, 2, 1].into(), [192, 0, 2, 2].into()];
        for _ in 0..5 {
            let names = rdns.names(&addrs, Duration::from_secs(2)).await;
            assert_eq!(names[&addrs[0]].as_deref(), Some("gw.example.net"));
            assert_eq!(names[&addrs[1]], None);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(rdns.lookups(), 2);
    }

    #[tokio::test]
    async fn private_hops_get_a_class_and_no_asn() {
        let db = AsnDb::parse("10.0.0.0\t10.255.255.255\t64512\tZZ\tPRIVATE-IN-FILE\n".as_bytes())
            .unwrap();
        let src = AsnSource::new(PathBuf::from("unused"));
        *src.db.write().unwrap() = Some(Arc::new(db));
        let e = Enricher {
            rdns: Rdns::new(Arc::new(|_| None)),
            asn: Some(src),
        };
        let a: IpAddr = [10, 0, 0, 1].into();
        let info = &e.hops(&[a], Duration::from_millis(500)).await[&a];
        assert_eq!(info.class, AddrClass::Private);
        assert_eq!(info.asn, None);
    }
}
