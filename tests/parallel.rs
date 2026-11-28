//! Files read on several threads at once are stored exactly as files read
//! one after another on the calling thread, each stored before the next is
//! read and the store giving ids as it goes (0 threads): the same ids for files, lanes and packets, the same
//! rows in every table, the same segment files byte for byte, the same
//! answers. Threads are made to finish out of order, files to fail late,
//! and runs to be read again after their files change.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use packetlane::pure::sql::{Clock, Table};
use packetlane::pure::synth::{demo_run, packet};
use packetlane::shell::ingest::ingest_targets;
use packetlane::shell::store::{IngestSummary, Status, Store};
use packetlane::shell::workers::{Hook, Stage};

/// A scratch folder that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "packetlane-parallel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).unwrap();
        Scratch(fs::canonicalize(dir).unwrap())
    }

    fn run(&self) -> PathBuf {
        self.0.join("run")
    }

    fn write(&self, rel: &str, bytes: &[u8]) {
        let path = self.run().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
    }

    fn append(&self, rel: &str, bytes: &[u8]) {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(self.run().join(rel))
            .unwrap();
        f.write_all(bytes).unwrap();
    }

    fn db(&self, name: &str) -> PathBuf {
        self.0.join(format!("{name}.db"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

/// Raw space packets of the given APIDs in turn, `n` of each; a packet now
/// and then is lost, so that sequence counts jump.
fn raw(apids: &[u16], n: u16, salt: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for seq in 0..n {
        for &apid in apids {
            if (seq + apid) % 37 == 0 {
                continue;
            }
            out.extend(packet(apid, seq, &[salt, seq as u8, (apid & 0xFF) as u8]));
        }
    }
    out
}

/// A run of every kind of file: the demo run (three sources, COSMOS logs,
/// text logs, kept fields, findings across sources), raw packet files that
/// meet their APIDs in different orders and add new ones as they go, one
/// copy of another, an empty file, one of noise, compressed packets and
/// text, and compressed data that gives out partway.
fn mixed_run(s: &Scratch) -> Vec<String> {
    for f in demo_run(90) {
        s.write(f.rel, &f.bytes);
    }
    let mut extra: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..10u16 {
        let mut apids: Vec<u16> = (0..4).map(|k| 0x20 + (i * 3 + k * 5) % 11).collect();
        if i % 3 == 1 {
            apids.reverse();
        }
        extra.push((
            format!("extra/raw-{i:02}.bin"),
            raw(&apids, 50 + i * 7, i as u8),
        ));
    }
    extra.push(("extra/raw-copy.bin".into(), raw(&[0x21, 0x22], 40, 1)));
    extra.push(("ground/raw-copy.bin".into(), raw(&[0x21, 0x22], 40, 1)));
    extra.push(("extra/empty.bin".into(), Vec::new()));
    extra.push((
        "extra/noise.bin".into(),
        (0..4000u32).map(|i| (i * 7 % 251) as u8).collect(),
    ));
    extra.push((
        "extra/packed.bin.gz".into(),
        gzip(&raw(&[0x40, 0x41], 60, 9)),
    ));
    let cut = gzip(&raw(&[0x42], 300, 3));
    extra.push(("extra/cut.bin.gz".into(), cut[..cut.len() / 2].to_vec()));
    let text: String = (0..40)
        .map(|i| format!("2024-01-01T00:00:{:02}.000Z INFO line {i}\n", i % 60))
        .collect();
    extra.push(("extra/notes.log".into(), text.clone().into_bytes()));
    extra.push(("extra/notes-old.log.gz".into(), gzip(text.as_bytes())));
    for (rel, bytes) in &extra {
        s.write(rel, bytes);
    }
    let mut rels: Vec<String> = demo_run(90).iter().map(|f| f.rel.to_string()).collect();
    rels.extend(extra.into_iter().map(|(rel, _)| rel));
    rels.sort();
    rels
}

/// Ingests the scratch run into store `db` on `threads` threads (0: on
/// this one, a file at a time).
fn ingest(s: &Scratch, db: &Path, threads: usize, hook: Option<Hook>) -> IngestSummary {
    let mut store = Store::open(db).unwrap();
    store.read_with_threads(threads);
    if let Some(hook) = hook {
        store.on_reading(hook);
    }
    ingest_targets(&mut store, &[s.run()], None, None, None).unwrap()
}

/// A hook that holds threads back so that files finish out of order:
/// earlier files longer, by a pattern that changes with `round`.
fn shuffling(rels: &[String], round: usize) -> Hook {
    let order: BTreeMap<String, usize> = rels
        .iter()
        .enumerate()
        .map(|(i, r)| (r.clone(), i))
        .collect();
    let n = rels.len();
    Arc::new(move |rel: &str, stage: Stage| {
        let i = order.get(rel).copied().unwrap_or(0);
        let wait = match (round % 3, stage) {
            (0, Stage::Read) => n - i,
            (1, Stage::Finish) => n - i,
            (2, _) => (i * 7 + round) % 5,
            _ => 0,
        };
        std::thread::sleep(Duration::from_millis(wait as u64 * 2));
    })
}

/// Everything a store holds and answers: every small table row for row,
/// what `packets` and `field_values` hold, the density and item views, and
/// each segment file's name and bytes.
fn dump(db: &Path) -> Vec<String> {
    let store = Store::open_read_only(db, Duration::from_secs(60)).unwrap();
    let q = |sql: &str| -> Table { store.query_user(sql, usize::MAX).unwrap() };
    let mut out = Vec::new();
    for sql in [
        "SELECT id, root, config FROM runs ORDER BY id",
        "SELECT * FROM unfinished ORDER BY run_id",
        "SELECT * FROM files ORDER BY id",
        "SELECT * FROM lanes ORDER BY id",
        "SELECT * FROM logs ORDER BY id",
        "SELECT * FROM findings ORDER BY id",
        "SELECT * FROM coarse ORDER BY lane_id, clock, bucket",
        "SELECT * FROM coarse_meta ORDER BY run_id, clock",
        "SELECT * FROM file_series ORDER BY file_id, lane_id, packet, field",
        "SELECT * FROM segments ORDER BY file_id",
        "SELECT * FROM segment_lanes ORDER BY lane_id, file_id",
        "SELECT seq FROM sqlite_sequence WHERE name = 'segment_serial'",
        "SELECT * FROM packets",
        "SELECT * FROM field_values",
        "SELECT * FROM field_values WHERE field = 'CYCLE' ORDER BY num",
        "SELECT lane_id, count(*), sum(length), min(id), max(id) FROM packets GROUP BY lane_id",
    ] {
        out.push(format!("{sql}\n{:?}", q(sql)));
    }
    let runs = q("SELECT id FROM runs ORDER BY id");
    for row in &runs.rows {
        let run = row[0].int().unwrap();
        for clock in [Clock::Receive, Clock::Packet, Clock::Order] {
            let d = store
                .packet_density(run, clock, i64::MIN / 4, i64::MAX / 4, 50)
                .unwrap();
            let items = store
                .packet_items(run, clock, i64::MIN / 4, i64::MAX / 4, 100_000)
                .unwrap();
            out.push(format!("density {run} {clock:?}\n{d:?}\nitems\n{items:?}"));
        }
    }
    let folder = packetlane::shell::segment::folder_for(db);
    let mut names: Vec<String> = fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    for name in names {
        let bytes = fs::read(folder.join(&name)).unwrap();
        out.push(format!(
            "segment {name} {} bytes {:?}",
            bytes.len(),
            crc(&bytes)
        ));
    }
    out
}

/// A checksum of a file's bytes, so that two dumps compare them.
fn crc(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

fn same(a: &[String], b: &[String], what: &str) {
    assert_eq!(a.len(), b.len(), "{what}: dumps differ in length");
    for (x, y) in a.iter().zip(b) {
        assert!(
            x == y,
            "{what}:\n--- a file at a time\n{x}\n--- threads\n{y}"
        );
    }
}

/// Outcomes as text, in order.
fn outcomes(s: &IngestSummary) -> Vec<String> {
    s.files
        .iter()
        .map(|f| {
            format!(
                "{} {:?} {} {} {} {} {}",
                f.rel, f.status, f.format, f.packets, f.entries, f.note, f.removed
            )
        })
        .collect()
}

#[test]
fn files_read_on_several_threads_are_stored_as_a_file_at_a_time() {
    let s = Scratch::new();
    let rels = mixed_run(&s);
    let one = ingest(&s, &s.db("one"), 0, None);
    let want = dump(&s.db("one"));
    // The run has what the test is about.
    assert!(one.files.iter().any(|f| f.status == Status::NotReadable));
    assert!(
        one.files
            .iter()
            .filter(|f| f.status == Status::Ingested)
            .count()
            > 15
    );
    assert!(want.iter().any(|d| d.starts_with("segment ")));
    for (round, threads) in [1, 2, 3, 8, 4, 16, 5].into_iter().enumerate() {
        let name = format!("many{round}");
        let got = ingest(&s, &s.db(&name), threads, Some(shuffling(&rels, round)));
        assert_eq!(outcomes(&one), outcomes(&got), "round {round}");
        // Every file was given the ids foreseen for it.
        assert_eq!(got.read_again, 0, "round {round}");
        same(
            &want,
            &dump(&s.db(&name)),
            &format!("round {round}, {threads} threads"),
        );
    }
}

/// Files that fail after the files behind them were given their ids, and
/// one that fails as it is read: each is left out, and every other file
/// stored, as when files are read one at a time.
#[test]
fn a_file_that_fails_late_leaves_the_others_as_a_file_at_a_time() {
    let s = Scratch::new();
    let rels = mixed_run(&s);
    let failing = |slow: bool| -> Hook {
        let shuffle = shuffling(&rels, 1);
        Arc::new(move |rel: &str, stage: Stage| {
            if slow {
                shuffle(rel, stage);
            }
            match (rel, stage) {
                ("extra/raw-03.bin", Stage::Finish) => panic!("made to fail"),
                ("extra/raw-06.bin", Stage::Read) => panic!("made to fail early"),
                ("bench-a/tlm.bin", Stage::Finish) => panic!("made to fail"),
                _ => {}
            }
        })
    };
    let one = ingest(&s, &s.db("one"), 0, Some(failing(false)));
    let failed: Vec<&str> = one
        .files
        .iter()
        .filter(|f| f.note.contains("made to fail"))
        .map(|f| f.rel.as_str())
        .collect();
    assert_eq!(
        failed,
        ["bench-a/tlm.bin", "extra/raw-03.bin", "extra/raw-06.bin"]
    );
    let want = dump(&s.db("one"));
    for threads in [1, 3, 8] {
        let name = format!("many{threads}");
        let got = ingest(&s, &s.db(&name), threads, Some(failing(true)));
        assert_eq!(outcomes(&one), outcomes(&got), "{threads} threads");
        // What was foreseen for the files behind each of the two that
        // failed late no longer held.
        assert_eq!(got.read_again, 2, "{threads} threads");
        same(&want, &dump(&s.db(&name)), &format!("{threads} threads"));
    }
}

/// The ways a run is read again, each done to a store read a file at a time
/// and to one read on several threads: a file in the middle grows, another is
/// emptied, a text log changes, nothing changes, the configuration
/// changes.
#[test]
fn a_run_read_again_is_stored_as_a_file_at_a_time() {
    let s = Scratch::new();
    let rels = mixed_run(&s);
    let step = |round: usize| -> (Vec<String>, Vec<String>) {
        let a = ingest(&s, &s.db("one"), 0, None);
        let b = ingest(&s, &s.db("many"), 6, Some(shuffling(&rels, round)));
        assert_eq!(outcomes(&a), outcomes(&b), "step {round}");
        assert_eq!(b.read_again, 0, "step {round}");
        same(
            &dump(&s.db("one")),
            &dump(&s.db("many")),
            &format!("step {round}"),
        );
        (outcomes(&a), outcomes(&b))
    };
    step(0);
    s.append("extra/raw-04.bin", &raw(&[0x2A, 0x50], 30, 77));
    s.write("extra/raw-07.bin", &[]);
    s.append("extra/notes.log", b"2024-01-01T00:01:00.000Z INFO later\n");
    let (changed, _) = step(1);
    assert!(
        changed
            .iter()
            .any(|o| o.starts_with("extra/raw-04.bin Ingested"))
    );
    assert!(
        changed
            .iter()
            .any(|o| o.starts_with("extra/raw-07.bin NotReadable"))
    );
    let (again, _) = step(2);
    assert!(
        again
            .iter()
            .all(|o| o.contains("AlreadyIngested") || o.contains("NotReadable"))
    );
    s.append("packetlane.toml", b"\n# changed\n");
    let (reset, _) = step(3);
    assert!(
        reset
            .iter()
            .any(|o| o.starts_with("extra/raw-04.bin Ingested"))
    );
    s.write("extra/raw-07.bin", &raw(&[0x77], 20, 7));
    fs::remove_file(s.run().join("extra/raw-01.bin")).unwrap();
    step(4);
}

/// A store opened for writing while an ingest is reading files leaves the
/// files that ingest is writing alone: its sweep waits for another time.
#[test]
fn a_sweep_during_an_ingest_leaves_its_files_alone() {
    let s = Scratch::new();
    mixed_run(&s);
    let db = s.db("one");
    drop(Store::open(&db).unwrap());
    let opened = Arc::new(AtomicUsize::new(0));
    let hook: Hook = {
        let db = db.clone();
        let opened = opened.clone();
        Arc::new(move |rel: &str, stage: Stage| {
            if rel == "extra/raw-05.bin" && stage == Stage::Finish {
                drop(Store::open(&db).unwrap());
                opened.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let summary = ingest(&s, &db, 4, Some(hook));
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    for f in &summary.files {
        assert!(
            f.status != Status::NotReadable || f.rel.contains("empty") || f.rel.contains("noise"),
            "{} {}",
            f.rel,
            f.note
        );
    }
}

/// Another writer stores a run in the same store while files are being
/// read: the files read ahead were foreseen ids that are now taken, so
/// they are read again, and every packet ends up with its own file's ids
/// and lanes.
#[test]
fn files_read_while_another_writer_stores_are_given_the_ids_the_store_gives() {
    let s = Scratch::new();
    let rels = mixed_run(&s);
    let other = s.0.join("other");
    for i in 0..4u16 {
        let path = other.join(format!("o{i}.bin"));
        fs::create_dir_all(&other).unwrap();
        fs::write(&path, raw(&[0x300 + i, 0x310 + i], 30, 5)).unwrap();
    }
    let reference = ingest(&s, &s.db("one"), 0, None);
    let db = s.db("many");
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook: Hook = {
        let db = db.clone();
        let other = other.clone();
        let done = done.clone();
        let shuffle = shuffling(&rels, 0);
        Arc::new(move |rel: &str, stage: Stage| {
            shuffle(rel, stage);
            if rel == "extra/raw-02.bin"
                && stage == Stage::Read
                && !done.swap(true, Ordering::SeqCst)
            {
                let mut store = Store::open(&db).unwrap();
                store.read_with_threads(0);
                ingest_targets(&mut store, std::slice::from_ref(&other), None, None, None).unwrap();
            }
        })
    };
    let got = ingest(&s, &db, 6, Some(hook));
    assert!(done.load(Ordering::SeqCst));
    assert!(got.read_again > 0);
    assert_eq!(outcomes(&reference), outcomes(&got));
    let store = Store::open_read_only(&db, Duration::from_secs(60)).unwrap();
    let count = |sql: &str| -> i64 { store.query_user(sql, 10).unwrap().rows[0][0].int().unwrap() };
    // Each packet's lane is a lane of its file's source and of its APID.
    assert_eq!(
        count(
            "SELECT count(*) FROM packets p JOIN lanes l ON l.id = p.lane_id
             JOIN files f ON f.id = p.file_id
             WHERE l.source != f.source OR l.run_id != f.run_id
                OR (l.kind = 'packet' AND (p.apid IS NULL OR l.apid != p.apid))"
        ),
        0
    );
    // Each file's packets are where its row says.
    assert_eq!(
        count(
            "SELECT count(*) FROM files f LEFT JOIN segments s ON s.file_id = f.id
             WHERE f.packets != (SELECT count(*) FROM packets p WHERE p.file_id = f.id)
                OR (f.packets > 0 AND (s.first_packet != f.first_packet
                                       OR s.last_packet != f.last_packet))"
        ),
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM packets"),
        count("SELECT sum(packets) FROM files")
    );
}
