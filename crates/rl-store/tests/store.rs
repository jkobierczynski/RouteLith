//! End-to-end tests of the raw tier: write, read, seal, recover.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rl_core::TimingBackend;
use rl_store::{
    Appended, ErrorCounts, Reader, SeriesKey, StoredRound, Writer, WriterOptions, layout,
};

const DAY_MS: i64 = 86_400_000;
const STEP_MS: i64 = 300_000;
/// 2026-11-18 00:00 UTC.
const T0: i64 = 20_410 * DAY_MS + 365 * DAY_MS;

/// Small deterministic PRNG (xorshift64*), so tests need no extra crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A plausible lab round: base RTT, exponential jitter, rare loss.
fn lab_round(rng: &mut Rng, ts_ms: i64, base_us: u32) -> StoredRound {
    let sent = 20u16;
    let mut rtts = Vec::new();
    for _ in 0..sent {
        if rng.unit() < 0.005 {
            continue;
        }
        let jitter = -300.0 * (1.0 - rng.unit()).ln();
        rtts.push(base_us + jitter as u32);
    }
    rtts.sort_unstable();
    StoredRound {
        ts_ms,
        sent,
        rtts_us: rtts,
        errors: ErrorCounts::default(),
        resolved: Some("192.0.2.10".parse().unwrap()),
        timing: Some(TimingBackend::LinuxKernelTimestamp),
        flags: 0,
    }
}

fn keys(n: usize) -> Vec<SeriesKey> {
    (0..n)
        .map(|i| SeriesKey::new("local", &format!("t{i}"), "v4"))
        .collect()
}

#[test]
fn write_read_seal_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        block_rounds: 8,
        ..WriterOptions::default()
    };
    let (mut w, rec) = Writer::open(dir.path(), opts, T0).unwrap();
    assert_eq!(rec.replayed, 0);
    let ids = w.register(&keys(2)).unwrap();
    let mut rng = Rng(1);
    // 300 rounds = 25 h, so they cross one UTC midnight.
    let mut written = Vec::new();
    for i in 0..300 {
        let r = lab_round(&mut rng, T0 + i * STEP_MS, 10_000);
        written.push(r.clone());
        assert_eq!(w.append(ids[0], r).unwrap(), Appended::Stored);
    }
    w.sync().unwrap();

    // Readable while the writer is open: segments plus WAL.
    let reader = Reader::open(dir.path()).unwrap();
    assert_eq!(reader.find("t0").len(), 1);
    let got = reader.read(ids[0], T0, T0 + 2 * DAY_MS).unwrap();
    assert_eq!(got, written);
    let part = reader
        .read(ids[0], T0 + 10 * STEP_MS, T0 + 12 * STEP_MS)
        .unwrap();
    assert_eq!(part, written[10..=12]);

    // Day one was sealed when day two's first block was flushed.
    let sealed = layout::segment_file_names(dir.path(), ids[0]);
    assert!(sealed.contains(&"2026-11-18.seg".to_string()), "{sealed:?}");
    assert!(
        sealed.contains(&"2026-11-19.open".to_string()),
        "{sealed:?}"
    );

    // Late and duplicate rounds are dropped.
    assert_eq!(
        w.append(ids[0], written[5].clone()).unwrap(),
        Appended::Late
    );

    // A day after the last round, maintenance seals day two as well.
    w.maintain(T0 + 3 * DAY_MS).unwrap();
    let files = layout::segment_file_names(dir.path(), ids[0]);
    assert_eq!(files, ["2026-11-18.seg", "2026-11-19.seg"]);
    w.close().unwrap();

    let (w, rec) = Writer::open(dir.path(), opts, T0 + 3 * DAY_MS).unwrap();
    assert_eq!((rec.replayed, rec.skipped, rec.torn_wal), (0, 0, 0));
    drop(w);
    let reader = Reader::open(dir.path()).unwrap();
    assert_eq!(reader.read(ids[0], 0, i64::MAX).unwrap(), written);
    let v = reader.verify().unwrap();
    assert!(v.problems.is_empty(), "{:?}", v.problems);
    assert_eq!(v.rounds, 300);
}

#[test]
fn unclean_stop_replays_the_wal_and_trims_torn_tails() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        block_rounds: 4,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    let id = w.register(&keys(1)).unwrap()[0];
    let mut rng = Rng(2);
    let rounds: Vec<_> = (0..10)
        .map(|i| lab_round(&mut rng, T0 + i * STEP_MS, 5_000))
        .collect();
    for r in &rounds {
        w.append(id, r.clone()).unwrap();
    }
    w.sync().unwrap();
    // Crash: no close, so no checkpoint. Two blocks reached the open
    // segment; two rounds are only in the WAL.
    drop(w);

    // Simulate writes cut short by the crash.
    let wal = std::fs::read_dir(dir.path().join("wal"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    append_bytes(&wal, &[9, 0, 0, 0, 1, 2]);
    let open = dir.path().join(format!("series/{id}/raw/2026-11-18.open"));
    append_bytes(&open, &[200, 0, 0]);

    let (w, rec) = Writer::open(dir.path(), opts, T0).unwrap();
    assert_eq!(rec.torn_wal, 1);
    assert_eq!(rec.truncated_segments, 1);
    assert_eq!(rec.skipped, 8, "rounds already in the segment");
    assert_eq!(rec.replayed, 2);
    w.close().unwrap();
    let reader = Reader::open(dir.path()).unwrap();
    assert_eq!(reader.read(id, 0, i64::MAX).unwrap(), rounds);
    assert!(reader.verify().unwrap().problems.is_empty());
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// §21.2: a day of 1,000 lab targets takes at most 6 MB.
#[test]
fn a_lab_day_of_1000_targets_fits_in_6_mb() {
    let dir = tempfile::tempdir().unwrap();
    let (mut w, _) = Writer::open(dir.path(), WriterOptions::default(), T0).unwrap();
    let ids = w.register(&keys(1000)).unwrap();
    let mut rng = Rng(3);
    let bases: Vec<u32> = ids
        .iter()
        .map(|_| 1_000 + (rng.next() % 80_000) as u32)
        .collect();
    for step in 0..288 {
        for (id, base) in ids.iter().zip(&bases) {
            w.append(*id, lab_round(&mut rng, T0 + step * STEP_MS, *base))
                .unwrap();
        }
    }
    w.maintain(T0 + 2 * DAY_MS).unwrap();
    w.close().unwrap();
    let r = Reader::open(dir.path()).unwrap();
    let bytes = r.segment_bytes().unwrap();
    let v = r.verify().unwrap();
    assert_eq!(v.rounds, 288_000);
    assert!(v.problems.is_empty());
    println!("1,000 targets x 288 rounds x 20 samples: {bytes} bytes in segments");
    assert!(bytes <= 6_000_000, "{bytes} bytes");
}

// ---- kill -9 ---------------------------------------------------------------

const CHILD_ENV: &str = "RL_STORE_CRASH_CHILD";
const CHILD_SERIES: usize = 20;

/// Runs only as the child of `kill_9_loses_at_most_the_last_sync`: writes
/// rounds forever, syncing every 5 steps and recording progress after each
/// sync, with small blocks and WAL so blocks, seals and checkpoints happen
/// while it is killed.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = Path::new(&dir);
    let opts = WriterOptions {
        block_rounds: 16,
        wal_max_bytes: 32 << 10,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir, opts, T0).unwrap();
    let ids = w.register(&keys(CHILD_SERIES)).unwrap();
    let mut rng = Rng(4);
    // Runs until the parent kills it.
    let mut step = 0i64;
    loop {
        let ts = T0 + step * STEP_MS;
        for id in &ids {
            w.append(*id, lab_round(&mut rng, ts, 20_000)).unwrap();
        }
        if step % 5 == 4 {
            w.sync().unwrap();
            let tmp = dir.join("progress.tmp");
            std::fs::write(&tmp, step.to_string()).unwrap();
            std::fs::rename(&tmp, dir.join("progress")).unwrap();
            w.maintain(ts).unwrap();
        }
        step += 1;
    }
}

/// §21.2: `kill -9` during writes, then restart: at most the last fsync
/// batch is lost and every segment passes its CRC check.
#[test]
fn kill_9_loses_at_most_the_last_sync() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for attempt in 0..3 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Let it run long enough to write blocks, seal days and checkpoint.
        let deadline = Instant::now() + Duration::from_secs(30);
        let progress = dir.path().join("progress");
        let target = 200 * (attempt + 1);
        while Instant::now() < deadline {
            let done: i64 = std::fs::read_to_string(&progress)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(-1);
            if done >= target {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let synced: i64 = std::fs::read_to_string(&progress).unwrap().parse().unwrap();
        assert!(
            synced >= target,
            "child reached step {synced} of {target} in 30 s, so the run proves too little"
        );

        // Restart: recovery must keep every synced round.
        let (w, rec) = Writer::open(dir.path(), WriterOptions::default(), T0).unwrap();
        assert!(rec.problems.is_empty(), "{:?}", rec.problems);
        drop(w);
        let reader = Reader::open(dir.path()).unwrap();
        let mut recovered: Vec<SeriesKey> =
            reader.series().iter().map(|(k, _)| k.clone()).collect();
        let mut expected = keys(CHILD_SERIES);
        recovered.sort();
        expected.sort();
        assert_eq!(recovered, expected, "attempt {attempt}");
        let v = reader.verify().unwrap();
        assert!(v.problems.is_empty(), "{:?}", v.problems);
        assert_eq!(v.torn_open, 0);
        for (_, id) in reader.series() {
            let rounds = reader.read(*id, 0, i64::MAX).unwrap();
            let have = rounds
                .iter()
                .filter(|r| r.ts_ms <= T0 + synced * STEP_MS)
                .count();
            assert_eq!(have as i64, synced + 1, "series {id}, attempt {attempt}");
        }
        // The next attempt continues on the recovered directory; the child
        // starts again from step 0, so all its rounds are late until it
        // passes the recovered ones. Start it on a fresh directory instead.
        std::fs::remove_dir_all(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
    }
}

#[test]
fn a_second_writer_on_the_same_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions::default();
    let (w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    match Writer::open(dir.path(), opts, T0) {
        Err(rl_store::StoreError::Locked(_)) => {}
        other => panic!("expected Locked, got {:?}", other.map(|_| ())),
    }
    w.close().unwrap();
    // Released on close.
    let (w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    drop(w);
}

#[test]
fn block_rounds_out_of_range_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for block_rounds in [0, 4097] {
        let opts = WriterOptions {
            block_rounds,
            ..WriterOptions::default()
        };
        match Writer::open(dir.path(), opts, T0) {
            Err(rl_store::StoreError::InvalidOptions(_)) => {}
            other => panic!("{block_rounds}: got {:?}", other.map(|_| ())),
        }
    }
}

#[test]
fn resolved_address_and_timing_carry_across_blocks_and_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        block_rounds: 4,
        ..WriterOptions::default()
    };
    let mut rng = Rng(7);
    let first = lab_round(&mut rng, T0, 10_000);
    let (mut w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    let id = w.register(&keys(1)).unwrap()[0];
    w.append(id, first.clone()).unwrap();
    // Later rounds carry no address or timing: they inherit the last ones,
    // including across block boundaries (every 4 rounds) and a restart.
    for i in 1..10 {
        let mut r = lab_round(&mut rng, T0 + i * STEP_MS, 10_000);
        r.resolved = None;
        r.timing = None;
        w.append(id, r).unwrap();
    }
    w.close().unwrap();
    let (mut w, _) = Writer::open(dir.path(), opts, T0 + 10 * STEP_MS).unwrap();
    for i in 10..14 {
        let mut r = lab_round(&mut rng, T0 + i * STEP_MS, 10_000);
        r.resolved = None;
        r.timing = None;
        w.append(id, r).unwrap();
    }
    w.close().unwrap();
    let got = Reader::open(dir.path())
        .unwrap()
        .read(id, 0, i64::MAX)
        .unwrap();
    assert_eq!(got.len(), 14);
    for r in &got {
        assert_eq!(r.resolved, first.resolved, "at {}", r.ts_ms);
        assert_eq!(r.timing, first.timing, "at {}", r.ts_ms);
    }
}

#[test]
fn reader_rejects_a_segment_belonging_to_another_series() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        block_rounds: 4,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    let ids = w.register(&keys(2)).unwrap();
    let mut rng = Rng(3);
    for i in 0..8 {
        for &id in &ids {
            w.append(id, lab_round(&mut rng, T0 + i * STEP_MS, 10_000))
                .unwrap();
        }
    }
    w.maintain(T0 + 2 * DAY_MS).unwrap();
    w.close().unwrap();
    // Copy series 0's sealed day into series 1's directory.
    let name = "2026-11-18.seg";
    let from = layout::raw_dir(dir.path(), ids[0]).join(name);
    let to = layout::raw_dir(dir.path(), ids[1]).join(name);
    std::fs::copy(from, to).unwrap();
    let reader = Reader::open(dir.path()).unwrap();
    assert!(reader.read(ids[0], 0, i64::MAX).is_ok());
    assert!(reader.read(ids[1], 0, i64::MAX).is_err());
}

#[test]
fn series_keys_with_the_separator_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut w, _) = Writer::open(dir.path(), WriterOptions::default(), T0).unwrap();
    let bad = SeriesKey::new("local", "a\u{1f}b", "v4");
    match w.register(&[bad]) {
        Err(rl_store::StoreError::InvalidKey(_)) => {}
        other => panic!("expected InvalidKey, got {other:?}"),
    }
    // A refused key is not an I/O failure: the writer keeps working.
    assert!(w.register(&keys(1)).is_ok());
}

fn flip_byte_near_end(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let i = bytes.len() - 10;
    bytes[i] ^= 0xff;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_damaged_sealed_segment_stops_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        block_rounds: 4,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    let id = w.register(&keys(1)).unwrap()[0];
    let mut rng = Rng(5);
    for i in 0..8 {
        w.append(id, lab_round(&mut rng, T0 + i * STEP_MS, 5_000))
            .unwrap();
    }
    w.maintain(T0 + 2 * DAY_MS).unwrap();
    w.close().unwrap();
    let seg = dir.path().join(format!("series/{id}/raw/2026-11-18.seg"));
    flip_byte_near_end(&seg);
    let before = std::fs::read(&seg).unwrap();
    match Writer::open(dir.path(), opts, T0 + 2 * DAY_MS) {
        Err(rl_store::StoreError::Corrupt { path, .. }) => assert_eq!(path, seg),
        other => panic!("expected Corrupt, got {:?}", other.map(|_| ())),
    }
    // Nothing was changed.
    assert_eq!(std::fs::read(&seg).unwrap(), before);
}

#[test]
fn a_bad_checksum_in_an_open_segment_is_an_error_for_readers() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        block_rounds: 4,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    let id = w.register(&keys(1)).unwrap()[0];
    let mut rng = Rng(6);
    for i in 0..8 {
        w.append(id, lab_round(&mut rng, T0 + i * STEP_MS, 5_000))
            .unwrap();
    }
    w.sync().unwrap();
    drop(w);
    flip_byte_near_end(&dir.path().join(format!("series/{id}/raw/2026-11-18.open")));
    assert!(
        Reader::open(dir.path())
            .unwrap()
            .read(id, 0, i64::MAX)
            .is_err()
    );
}
