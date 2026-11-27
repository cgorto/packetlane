//! The comparison of sources is read from the checksum sections of the
//! segment files. These tests check its findings against the comparison it
//! replaced, which asked SQL over the `packets` rows of the same store: the
//! statements are kept here as the oracle while those rows are still
//! written. Findings must be the same rows in the same order, with the same
//! lane and packet ids.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use packetlane::pure::cross::{hop_finding, origin_finding};
use packetlane::pure::sql;
use packetlane::pure::synth::{Source, demo_run, packet};
use packetlane::shell::cross::{GROUP_MEMORY, group_sizes};
use packetlane::shell::ingest::ingest_targets;
use packetlane::shell::store::Store;
use rusqlite::{Connection, OpenFlags, params};

// ---- the oracle: the comparison as it was asked of SQL ----------------------------

/// Drops the temporary table of [`HOP_STAGE`], if one was left.
const HOP_UNSTAGE: &str = "DROP TABLE IF EXISTS temp.hop";

/// The packets of a run's lanes that have a counterpart from another
/// source, in order of checksum and lane. Takes the run id.
const HOP_STAGE: [&str; 2] = [
    "CREATE TEMP TABLE hop (
       sum INTEGER NOT NULL, lane_id INTEGER NOT NULL, id INTEGER NOT NULL,
       seq INTEGER, length INTEGER,
       PRIMARY KEY (sum, lane_id, id)
     ) WITHOUT ROWID",
    "INSERT INTO temp.hop (sum, lane_id, id, seq, length)
     SELECT p.sum, p.lane_id, p.id, p.seq, p.length
     FROM files f CROSS JOIN oracle_packets p NOT INDEXED
       ON p.id BETWEEN f.first_packet AND f.last_packet
     WHERE f.run_id = ?1 AND p.lane_id IN (
       SELECT a.id FROM lanes a JOIN lanes b
         ON b.run_id = a.run_id AND b.kind = 'packet' AND b.apid = a.apid
        AND b.ptype = a.ptype AND b.source != a.source
       WHERE a.run_id = ?1 AND a.kind = 'packet')
     ORDER BY p.sum, p.lane_id, p.id",
];

/// For every pair of lanes that has packets the second lacks between the
/// first and last packet they share: lane a, lane b, shared, missing, first
/// missing id. Reads `temp.hop`. Takes the run id.
const HOP_COMPARE_ALL: &str = "WITH pair AS MATERIALIZED (
       SELECT a.id AS a, b.id AS b
       FROM lanes a JOIN lanes b
         ON b.run_id = a.run_id AND b.kind = 'packet' AND b.apid = a.apid
        AND b.ptype = a.ptype AND b.source != a.source
       WHERE a.run_id = ?1 AND a.kind = 'packet'),
     shared AS MATERIALIZED (
       SELECT pair.a AS a, pair.b AS b, COUNT(*) AS n, MIN(p.id) AS lo, MAX(p.id) AS hi
       FROM temp.hop p CROSS JOIN pair ON pair.a = p.lane_id
       WHERE EXISTS (SELECT 1 FROM temp.hop q
                     WHERE q.sum = p.sum AND q.lane_id = pair.b)
       GROUP BY pair.a, pair.b)
     SELECT shared.a, shared.b, shared.n, COUNT(*), MIN(p.id)
     FROM temp.hop p CROSS JOIN shared ON shared.a = p.lane_id
     WHERE p.id BETWEEN shared.lo AND shared.hi
       AND NOT EXISTS (SELECT 1 FROM temp.hop q
                       WHERE q.sum = p.sum AND q.lane_id = shared.b)
     GROUP BY shared.a, shared.b";

/// Which other sources hold copies of a lane's packets, matched by
/// checksum, sequence count and length. Takes lane, run, apid, ptype.
const LANE_ORIGINS: &str = "SELECT l.source,
            SUM((SELECT COUNT(*) FROM oracle_packets p INDEXED BY oracle_packets_lane_receive
                 WHERE p.lane_id = ?1 AND EXISTS (
                   SELECT 1 FROM temp.hop q
                   WHERE q.sum = p.sum AND q.lane_id = l.id
                     AND q.seq = p.seq AND q.length = p.length))) AS n
     FROM lanes l
     WHERE l.run_id = ?2 AND l.kind = 'packet' AND l.apid = ?3 AND l.ptype = ?4
       AND l.id != ?1
     GROUP BY l.source HAVING n > 0 ORDER BY l.source";

/// One finding: kind, severity, message, lane id, packet id.
type Row = (String, String, String, Option<i64>, Option<i64>);

/// The cross-source findings of a run as the comparison over SQL made
/// them, in the order it stored them.
fn oracle(conn: &Connection, run: i64) -> Vec<Row> {
    let mut out = Vec::new();
    let pairs = sql::lane_pairs(run);
    let pairs: Vec<(i64, String, i64, String)> = conn
        .prepare(&pairs.sql)
        .unwrap()
        .query_map(params![run], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    if pairs.is_empty() {
        return out;
    }
    conn.execute_batch(HOP_UNSTAGE).unwrap();
    conn.execute_batch(HOP_STAGE[0]).unwrap();
    conn.execute(HOP_STAGE[1], params![run]).unwrap();
    let compared: HashMap<(i64, i64), (i64, i64, Option<i64>)> = conn
        .prepare(HOP_COMPARE_ALL)
        .unwrap()
        .query_map(params![run], |r| {
            Ok(((r.get(0)?, r.get(1)?), (r.get(2)?, r.get(3)?, r.get(4)?)))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut found = Vec::new();
    for (a, source_a, b, source_b) in &pairs {
        if let Some(&(shared, missing, first)) = compared.get(&(*a, *b)) {
            found.extend(hop_finding(*a, source_a, source_b, shared, missing, first));
        }
    }
    let mixed = sql::lanes_with_finding(run, "interleaved");
    let mixed: Vec<(i64, i64, i64, Option<i64>)> = conn
        .prepare(&mixed.sql)
        .unwrap()
        .query_map(params![run, "interleaved"], |r| {
            Ok((r.get(0)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for (lane, apid, ptype, packet) in mixed {
        let list: Vec<(String, i64)> = conn
            .prepare(LANE_ORIGINS)
            .unwrap()
            .query_map(params![lane, run, apid, ptype], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        found.extend(origin_finding(lane, packet, &list));
    }
    conn.execute_batch(HOP_UNSTAGE).unwrap();
    for f in found {
        out.push((
            f.kind.name().to_string(),
            f.severity.as_str().to_string(),
            f.message,
            Some(f.lane),
            f.packet,
        ));
    }
    out
}

/// The cross-source findings the store holds for a run, in order.
fn stored(conn: &Connection, run: i64) -> Vec<Row> {
    conn.prepare(
        "SELECT kind, severity, message, lane_id, packet_id FROM findings
         WHERE run_id = ? AND file_id IS NULL ORDER BY id",
    )
    .unwrap()
    .query_map(params![run], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

/// Checks every run of the store against the oracle. Returns the stored
/// findings of each run, by run id.
fn check(db: &Path) -> Vec<Vec<Row>> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let runs: Vec<i64> = conn
        .prepare("SELECT id FROM runs ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    runs.iter()
        .map(|&run| {
            let got = stored(&conn, run);
            assert_eq!(got, oracle(&conn, run), "run {run}");
            got
        })
        .collect()
}

fn count(rows: &[Row], kind: &str) -> usize {
    rows.iter().filter(|r| r.0 == kind).count()
}

// ---- stores --------------------------------------------------------------------

/// A folder removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "packetlane-cross-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn db(&self) -> PathBuf {
        self.0.join("store.db")
    }

    /// Writes the files, given as (path within the run, bytes), into the
    /// run folder `name`, and ingests that folder.
    fn ingest(&self, name: &str, files: &[(String, Vec<u8>)]) -> PathBuf {
        let run = self.0.join(name);
        for (rel, bytes) in files {
            let path = run.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        self.ingest_again(&run);
        run
    }

    fn ingest_again(&self, run: &Path) {
        let run = std::fs::canonicalize(run).unwrap();
        let mut store = Store::open_with_oracle(&self.db()).unwrap();
        ingest_targets(&mut store, &[run], None, None, None).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn demo_files(seconds: u32) -> Vec<(String, Vec<u8>)> {
    demo_run(seconds)
        .into_iter()
        .map(|f| (f.rel.to_string(), f.bytes))
        .collect()
}

/// Three sources logging the same streams, with everything that could make
/// a comparison go wrong.
fn awkward_run() -> Vec<(String, Vec<u8>)> {
    let p = |apid: u16, seq: u16, body: &[u8]| packet(apid, seq, body);
    let mut a = Vec::new();
    let mut b = Vec::new();
    let mut c = Vec::new();
    // APID 10: b lacks packets before the first shared one, in the middle,
    // and after the last; each side holds one packet twice; c logs the
    // stream with other bytes, so shares nothing.
    for seq in 0..40u16 {
        let one = p(10, seq, &[seq as u8, 1, 2]);
        a.extend(&one);
        if seq == 20 {
            a.extend(&one);
        }
        if !matches!(seq, 0..=2 | 10 | 11 | 30 | 37..=39) {
            b.extend(&one);
            if seq == 25 {
                b.extend(&one);
            }
        }
        c.extend(p(10, seq, &[seq as u8, 9, 9]));
    }
    // APID 11: a stream that sends the same bytes every time.
    for _ in 0..5 {
        a.extend(p(11, 0, &[7; 4]));
    }
    for _ in 0..3 {
        b.extend(p(11, 0, &[7; 4]));
    }
    // APID 12: one source only. APID 13: c has all of it, a the middle.
    for seq in 0..20u16 {
        a.extend(p(12, seq, &[seq as u8]));
        let one = p(13, seq, &[seq as u8, 5]);
        c.extend(&one);
        if (5..15).contains(&seq) && seq != 9 {
            a.extend(&one);
        }
    }
    vec![
        ("a/tlm.bin".to_string(), a),
        ("b/tlm.bin".to_string(), b),
        ("c/tlm.bin".to_string(), c),
    ]
}

/// Many streams from three sources, each source's log in several files cut
/// at different places, each source losing different packets.
fn wide_run(streams: u16, per_source: u32) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for (s, name) in ["gse-a", "gse-b", "gse-c"].iter().enumerate() {
        let cuts = [
            per_source / 5 + s as u32 * 97,
            per_source / 2,
            per_source * 4 / 5 - s as u32 * 31,
        ];
        let mut part = Vec::new();
        let mut n = 0;
        for i in 0..per_source {
            if cuts.contains(&i) {
                files.push((format!("{name}/part{n}.bin"), std::mem::take(&mut part)));
                n += 1;
            }
            // Each source loses a packet now and then, not the same ones;
            // runs of them now and then.
            let mix = (i as u64).wrapping_mul(2_654_435_761) ^ (s as u64 * 40_503);
            if mix.is_multiple_of(211) || (i / 1000 == 7 + s as u32 && i % 1000 < 20) {
                continue;
            }
            let apid = 0x100 + (i % u32::from(streams)) as u16;
            let seq = ((i / u32::from(streams)) % 16384) as u16;
            part.extend(packet(apid, seq, &i.to_be_bytes()));
        }
        files.push((format!("{name}/part{n}.bin"), part));
    }
    files
}

/// Two units send on one APID by mistake, each logging its own packets; a
/// collector logs both, so its copy has two counters running at once; a
/// relay logs part of the first unit's. Some packets are logged twice, by
/// the collector and by the units.
fn interleaved_run(packets: u32) -> Vec<(String, Vec<u8>)> {
    let mut first = Source::new(300, 9000, 8);
    let mut second = Source::new(300, 12, 8);
    let (mut a, mut b, mut c, mut r) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in 0..packets {
        let one = first.emit();
        a.extend(&one);
        c.extend(&one);
        if i % 97 == 3 {
            a.extend(&one);
        }
        if i % 89 == 5 {
            c.extend(&one);
        }
        if (packets / 4..packets / 2).contains(&i) {
            r.extend(&one);
        }
        if i >= 10 {
            let two = second.emit();
            if i % 7 != 0 {
                b.extend(&two);
            }
            if i % 13 != 0 {
                c.extend(&two);
            }
        }
    }
    vec![
        ("unit-a/a.bin".to_string(), a),
        ("unit-b/b.bin".to_string(), b),
        ("collector/c.bin".to_string(), c),
        ("relay/r.bin".to_string(), r),
    ]
}

// ---- tests ------------------------------------------------------------------------

#[test]
fn the_demo_run_compares_as_the_rows_say() {
    let scratch = Scratch::new();
    scratch.ingest("run", &demo_files(120));
    let runs = check(&scratch.db());
    assert!(count(&runs[0], "hop_missing") > 0, "{:?}", runs[0]);
}

#[test]
fn an_awkward_run_compares_as_the_rows_say() {
    let scratch = Scratch::new();
    scratch.ingest("run", &awkward_run());
    let runs = check(&scratch.db());
    let mut messages: Vec<&str> = runs[0].iter().map(|r| r.2.as_str()).collect();
    messages.sort();
    assert_eq!(
        messages,
        [
            "1 packet from c missing in a (9 shared)",
            "3 packets from a missing in b (32 shared)",
        ]
    );
}

#[test]
fn a_wide_run_with_losses_compares_as_the_rows_say() {
    let scratch = Scratch::new();
    scratch.ingest("run", &wide_run(60, 30_000));
    let runs = check(&scratch.db());
    // Every ordered pair of sources, on most streams.
    assert!(count(&runs[0], "hop_missing") > 200, "{}", runs[0].len());
}

#[test]
fn an_interleaved_stream_is_traced_as_the_rows_say() {
    let scratch = Scratch::new();
    scratch.ingest("run", &interleaved_run(20_000));
    let runs = check(&scratch.db());
    let origins: Vec<&Row> = runs[0].iter().filter(|r| r.0 == "origins").collect();
    assert_eq!(origins.len(), 1, "{:?}", runs[0]);
    assert!(origins[0].2.contains("unit-a") && origins[0].2.contains("unit-b"));
    assert!(origins[0].2.contains("relay"), "{}", origins[0].2);
}

#[test]
fn a_file_read_again_after_it_grows_compares_as_the_rows_say() {
    let scratch = Scratch::new();
    let run = scratch.ingest("run", &wide_run(12, 12_000));
    let before = check(&scratch.db());
    // One source's last file grows, with packets the others lack.
    let path = run.join("gse-b/part3.bin");
    let mut bytes = std::fs::read(&path).unwrap();
    for i in 0..500u32 {
        bytes.extend(packet(0x100 + (i % 12) as u16, 5000 + i as u16, &[1, 2, 3]));
    }
    // And a packet the others hold, so the new ones lie between shared
    // ones.
    bytes.extend(packet(0x100, 0, &0u32.to_be_bytes()));
    std::fs::write(&path, bytes).unwrap();
    scratch.ingest_again(&run);
    let after = check(&scratch.db());
    assert_ne!(before, after);
}

#[test]
fn runs_are_compared_each_with_its_own_packets() {
    let scratch = Scratch::new();
    let first = scratch.ingest("first", &awkward_run());
    // The second run holds the first one's packets too: they must not be
    // found in the other run.
    let mut files = awkward_run();
    files.truncate(1);
    files.extend(demo_files(60));
    scratch.ingest("second", &files);
    let runs = check(&scratch.db());
    assert_eq!(runs[0].len(), 2);
    assert!(!runs[1].is_empty());
    // A file of the first run read again leaves the second's alone.
    std::fs::write(first.join("b/tlm.bin"), &awkward_run()[1].1[..100]).unwrap();
    scratch.ingest_again(&first);
    let again = check(&scratch.db());
    assert_eq!(again[1], runs[1]);
}

#[test]
fn one_source_has_nothing_to_compare() {
    let scratch = Scratch::new();
    let mut files = interleaved_run(500);
    files.retain(|f| f.0.starts_with("collector"));
    let run = scratch.ingest("run", &files);
    let runs = check(&scratch.db());
    assert!(runs[0].is_empty());
    // No checksum section is read: with the first file's segment gone,
    // another file of the same source is still ingested.
    let folder = packetlane::shell::segment::folder_for(&scratch.db());
    for entry in std::fs::read_dir(&folder).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    std::fs::write(run.join("collector/more.bin"), packet(300, 1, &[1, 2])).unwrap();
    scratch.ingest_again(&run);
    assert!(check(&scratch.db())[0].is_empty());
}

/// A stream that sends the same packet hundreds of thousands of times, on
/// two sources, and a third that lacks those but shares what comes before
/// and after: one group of checksums far larger than what is held in
/// memory, and as many packets to give back as missing.
#[test]
fn one_packet_repeated_is_compared_in_bounded_memory() {
    let repeats = 200_000;
    let same = packet(50, 7, &[1, 2, 3]);
    let edge = |n: u16| packet(50, n, &[n as u8; 5]);
    let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
    for n in 100..110 {
        for log in [&mut a, &mut b, &mut c] {
            log.extend(edge(n));
        }
    }
    for _ in 0..repeats {
        a.extend(&same);
        b.extend(&same);
    }
    for n in 200..210 {
        for log in [&mut a, &mut b, &mut c] {
            log.extend(edge(n));
        }
    }
    let scratch = Scratch::new();
    scratch.ingest(
        "run",
        &[
            ("a/tlm.bin".to_string(), a),
            ("b/tlm.bin".to_string(), b),
            ("c/tlm.bin".to_string(), c),
        ],
    );
    let runs = check(&scratch.db());
    let (held, largest) = group_sizes();
    assert!(largest >= 2 * repeats, "largest group {largest}");
    assert!(held <= GROUP_MEMORY, "held {held}");
    let missing: Vec<&Row> = runs[0]
        .iter()
        .filter(|r| r.2.starts_with(&format!("{repeats} packets")))
        .collect();
    assert_eq!(missing.len(), 2, "{:?}", runs[0]);
}
