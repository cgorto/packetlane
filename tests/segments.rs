//! Segment files against the store's own rows: every answer read from the
//! segments is checked against the `packets` table of the same store, which
//! holds the same packets.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use packetlane::pure::segment::{level_for, plan};
use packetlane::pure::sql::{self, Clock, Query, bucket_width};
use packetlane::pure::synth::{Source, demo_run};
use packetlane::shell::ingest::ingest_targets;
use packetlane::shell::segment::{self, Segment};
use packetlane::shell::store::Store;

/// A scratch folder that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "packetlane-segments-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(fs::canonicalize(dir).unwrap())
    }

    fn db(&self) -> PathBuf {
        self.0.join("store.db")
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("run").join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    fn ingest(&self) {
        let run = fs::canonicalize(self.0.join("run")).unwrap();
        let mut store = Store::open(&self.db()).unwrap();
        ingest_targets(&mut store, &[run], None, None, None).unwrap();
    }

    fn reader(&self) -> Store {
        Store::open_read_only(&self.db(), Duration::from_secs(60)).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ints(store: &Store, q: &Query) -> Vec<Vec<i64>> {
    store
        .query(q, usize::MAX)
        .unwrap()
        .rows
        .iter()
        .map(|r| r.iter().map(|c| c.int().unwrap_or(i64::MIN)).collect())
        .collect()
}

fn ask(store: &Store, sql_text: &str, params: Vec<sql::Param>) -> Vec<Vec<i64>> {
    ints(store, &Query::new(sql_text, params))
}

/// The segment answer as (lane, bucket, count) rows.
fn from_segments(store: &Store, clock: Clock, from: i64, to: i64, buckets: i64) -> Vec<Vec<i64>> {
    store
        .packet_density(1, clock, from, to, buckets)
        .unwrap()
        .rows
        .iter()
        .map(|r| r.iter().map(|c| c.int().unwrap()).collect())
        .collect()
}

/// `sql::packet_density`, every packet counted directly, one row per lane
/// and bucket in that order.
fn counted(store: &Store, clock: Clock, from: i64, to: i64, buckets: i64) -> Vec<Vec<i64>> {
    let mut rows = ints(store, &sql::packet_density(1, clock, from, to, buckets));
    rows.sort();
    rows
}

/// The rule of `pure::segment::plan` worked out packet by packet from the
/// `packets` rows and the `segments` rows, in SQL: a packet in a stored
/// bucket that lies wholly inside the window, when view buckets are at
/// least as wide as stored ones, is counted in the view bucket where its
/// stored bucket starts; any other packet in its own.
fn rule_in_sql(store: &Store, clock: Clock, from: i64, to: i64, buckets: i64) -> Vec<Vec<i64>> {
    let c = clock.packet_column();
    let width = bucket_width(from, to, buckets);
    let (values, mut params) = level_table(store, clock, width);
    params.splice(0..0, [from.into(), to.into(), width.into()]);
    ask(
        store,
        &format!(
            "WITH lv(a, z, s) AS (VALUES {values}),
             p AS (
               SELECT p.lane_id AS lane, p.{c} AS t, lv.s AS s,
                      ((p.{c} >> lv.s) << lv.s) AS b0
               FROM packets p JOIN lv ON p.id BETWEEN lv.a AND lv.z
               WHERE p.{c} BETWEEN ?1 AND ?2)
             SELECT lane,
                    CASE WHEN s IS NOT NULL AND ?3 >= (1 << s) AND b0 >= ?1
                              AND b0 + (1 << s) - 1 <= ?2
                         THEN (b0 - ?1) / ?3 ELSE (t - ?1) / ?3 END AS bin,
                    COUNT(*)
             FROM p GROUP BY lane, bin ORDER BY lane, bin"
        ),
        params,
    )
}

/// The bucket level a view with buckets `width` wide reads in each segment,
/// as the text of SQL `VALUES` rows (first packet id, last packet id,
/// shift or null) and their parameters, numbered from 4.
fn level_table(store: &Store, clock: Clock, width: i64) -> (String, Vec<sql::Param>) {
    let mut rows = Vec::new();
    let mut params = Vec::new();
    for (first, last, levels) in segment_levels(store, clock) {
        let n = params.len() + 4;
        rows.push(format!("(?{n}, ?{}, ?{})", n + 1, n + 2));
        params.push(first.into());
        params.push(last.into());
        params.push(level_for(&levels, width).map(i64::from).into());
    }
    (rows.join(", "), params)
}

/// Each segment's first and last packet id and stored bucket levels on a
/// clock.
fn segment_levels(store: &Store, clock: Clock) -> Vec<(i64, i64, Vec<u32>)> {
    let names = store
        .query(
            &Query::new(
                "SELECT name, first_packet, last_packet FROM segments",
                vec![],
            ),
            usize::MAX,
        )
        .unwrap();
    names
        .rows
        .iter()
        .map(|r| {
            let seg = Segment::open(&store.segment_folder().join(r[0].text().unwrap())).unwrap();
            (r[1].int().unwrap(), r[2].int().unwrap(), seg.levels(clock))
        })
        .collect()
}

fn totals(rows: &[Vec<i64>]) -> Vec<(i64, i64)> {
    let mut out: Vec<(i64, i64)> = Vec::new();
    for r in rows {
        match out.last_mut() {
            Some((lane, n)) if *lane == r[0] => *n += r[2],
            _ => out.push((r[0], r[2])),
        }
    }
    out
}

/// The run's first and last value on a clock, from its packets.
fn extent(store: &Store, clock: Clock) -> Option<(i64, i64)> {
    let c = clock.packet_column();
    let r = ask(
        store,
        &format!("SELECT MIN({c}), MAX({c}) FROM packets WHERE {c} IS NOT NULL"),
        vec![],
    );
    (r[0][0] != i64::MIN).then(|| (r[0][0], r[0][1]))
}

fn clock_index(clock: Clock) -> usize {
    match clock {
        Clock::Receive => 0,
        Clock::Packet => 1,
        Clock::Order => 2,
    }
}

/// The `segments` columns of a clock: lowest value, highest, shift.
fn manifest_columns(clock: Clock) -> (&'static str, &'static str, &'static str) {
    match clock {
        Clock::Receive => ("receive_min", "receive_max", "receive_shift"),
        Clock::Packet => ("packet_min", "packet_max", "packet_shift"),
        Clock::Order => ("first_packet", "last_packet", "order_shift"),
    }
}

/// The narrowest stored bucket of the segments a window touches, if any.
fn finest_bucket(store: &Store, clock: Clock, from: i64, to: i64) -> Option<i64> {
    let (min, max, shift) = manifest_columns(clock);
    let r = ask(
        store,
        &format!("SELECT MIN({shift}) FROM segments WHERE {min} <= ? AND {max} >= ?"),
        vec![to.into(), from.into()],
    );
    (r[0][0] != i64::MIN).then(|| 1i64 << r[0][0])
}

/// The first and last value and the bucket width of the segment with the
/// widest buckets on a clock.
fn coarsest_segment(store: &Store, clock: Clock) -> (i64, i64, i64) {
    let (min, max, shift) = manifest_columns(clock);
    let r = ask(
        store,
        &format!(
            "SELECT {min}, {max}, {shift} FROM segments WHERE {shift} IS NOT NULL
             ORDER BY {shift} DESC LIMIT 1"
        ),
        vec![],
    );
    (r[0][0], r[0][1], 1i64 << r[0][2])
}

/// Checks every clock of the store: fine zoom row for row against counting
/// every packet, coarse zoom row for row against the rule worked out in
/// SQL, and per-lane totals against a count of the window, at zooms and
/// offsets that start and end inside stored buckets and wider than the run.
fn check_store(store: &Store) -> [bool; 3] {
    let mut checked = 0;
    let mut fine_seen = [false; 3];
    for clock in Clock::ALL {
        let Some((min, max)) = extent(store, clock) else {
            continue;
        };
        let span = max - min + 1;

        // Fine: view buckets narrower than the stored buckets of every
        // segment the window touches. Windows in the segment with the widest
        // buckets; those that touch a segment with buckets too narrow to be
        // fine are passed over.
        let (lo, hi, wide) = coarsest_segment(store, clock);
        let mid = lo + (hi - lo) / 3;
        for (from, to, buckets) in [
            (lo, lo + wide * 3 - 1, 4000),
            (mid, mid + wide * 7 + 13, 2_000),
            (hi - wide * 2, hi, 997),
        ] {
            let touched = finest_bucket(store, clock, from, to).unwrap();
            if bucket_width(from, to, buckets) >= touched {
                continue;
            }
            fine_seen[clock_index(clock)] = true;
            assert_eq!(
                from_segments(store, clock, from, to, buckets),
                counted(store, clock, from, to, buckets),
                "fine {clock:?} {from}..={to} in {buckets}"
            );
            checked += 1;
        }

        // Coarse and in between, at several offsets.
        let mut coarse_seen = false;
        for (from, to, buckets) in [
            (min, max, 1000),
            (min - span, max + span, 1000),
            (min - 1, max + 1, 7),
            (min + span / 7 + 3, max - span / 5 - 11, 333),
            (min + span / 3 + 1, min + span / 3 + span / 10, 1000),
            (min + span / 2 - 5, min + span / 2 + span / 100, 1000),
            (min + 17, min + span / 1000 + 19, 1000),
            (min + span / 4, min + span / 4, 5),
            (i64::MIN, i64::MAX, 1000),
            (min, max, 1),
        ] {
            let got = from_segments(store, clock, from, to, buckets);
            // SQLite turns a difference too large for 64 bits into a
            // float; for such a window only the totals are compared.
            if to.checked_sub(from).is_some() {
                assert_eq!(
                    got,
                    rule_in_sql(store, clock, from, to, buckets),
                    "rule {clock:?} {from}..={to} in {buckets}"
                );
            }
            let width = bucket_width(from, to, buckets);
            // Some segment is counted partly from whole buckets, partly
            // packet by packet.
            for (_, _, levels) in segment_levels(store, clock) {
                if let Some(shift) = level_for(&levels, width) {
                    let p = plan(from, to, width, shift);
                    coarse_seen |= p.whole.is_some() && !p.direct.is_empty();
                }
            }
            let c = clock.packet_column();
            let direct = ask(
                store,
                &format!(
                    "SELECT lane_id, COUNT(*) FROM packets WHERE {c} BETWEEN ? AND ?
                     GROUP BY lane_id ORDER BY lane_id"
                ),
                vec![from.into(), to.into()],
            );
            let direct: Vec<(i64, i64)> = direct.iter().map(|r| (r[0], r[1])).collect();
            assert_eq!(totals(&got), direct, "totals {clock:?} {from}..={to}");
            checked += 1;
        }
        assert!(coarse_seen, "no coarse window on {clock:?}");
    }
    assert!(checked > 0);
    fine_seen
}

/// Text log entries, as the density request now counts them (pre-counted
/// buckets of log lanes where they fit, the ends directly), give per lane
/// what counting every entry gives.
fn check_logs(store: &Store) {
    for clock in [Clock::Receive, Clock::Packet] {
        let r = ask(store, "SELECT MIN(log_ns), MAX(log_ns) FROM logs", vec![]);
        let (min, max) = (r[0][0], r[0][1]);
        let span = max - min + 1;
        let meta = store.query(&sql::coarse_meta(1, clock), 1).unwrap();
        let coarse = Some((
            meta.rows[0][0].int().unwrap(),
            meta.rows[0][1].int().unwrap(),
        ));
        for (from, to, buckets) in [
            (min, max, 1000),
            (min - 7, max + span, 3),
            (min + span / 3 + 1, max - span / 4, 7),
            (min + span / 2, min + span / 2 + span / 50, 1000),
        ] {
            let mut rows: Vec<Vec<i64>> =
                sql::log_density_stored(1, clock, from, to, buckets, coarse)
                    .iter()
                    .flat_map(|q| ints(store, q))
                    .collect();
            rows.sort();
            let direct = ask(
                store,
                "SELECT lane_id, 0, COUNT(*) FROM logs WHERE log_ns BETWEEN ? AND ?
                 GROUP BY lane_id ORDER BY lane_id",
                vec![from.into(), to.into()],
            );
            let direct: Vec<(i64, i64)> = direct.iter().map(|r| (r[0], r[2])).collect();
            assert_eq!(totals(&rows), direct, "logs {clock:?} {from}..={to}");
        }
    }
}

fn demo(scratch: &Scratch, seconds: u32) {
    for file in demo_run(seconds) {
        scratch.write(file.rel, &file.bytes);
    }
    // Enough packets in one file for its id buckets to be wider than one.
    let mut source = Source::new(300, 0, 6);
    let bytes: Vec<u8> = (0..10_000).flat_map(|_| source.emit()).collect();
    scratch.write("extra/big.bin", &bytes);
}

#[test]
fn density_from_segments_matches_the_rows_on_the_demo_run() {
    let scratch = Scratch::new();
    demo(&scratch, 120);
    scratch.ingest();
    let store = scratch.reader();
    // Every packet file has a segment, and only those.
    let files = ask(
        &store,
        "SELECT COUNT(*) FROM files WHERE packets > 0",
        vec![],
    );
    let segments = ask(&store, "SELECT COUNT(*) FROM segments", vec![]);
    assert_eq!(files, segments);
    assert!(segments[0][0] >= 3);
    assert_eq!(check_store(&store), [true; 3], "a clock had no fine window");
    check_logs(&store);
}

/// Several hosts, each with its own files of the same streams.
fn multi_source(scratch: &Scratch) {
    for (host, apid, offset) in [
        ("unit-a", 100u16, 0u16),
        ("unit-b", 100, 3),
        ("unit-c", 7, 11),
    ] {
        for pass in 0..3u64 {
            let mut source = Source::new(apid, offset + pass as u16 * 1_000, 4 + pass as usize);
            let bytes: Vec<u8> = (0..(200 + pass * 37)).flat_map(|_| source.emit()).collect();
            scratch.write(&format!("{host}/pass{pass}.bin"), &bytes);
        }
    }
}

#[test]
fn density_from_segments_matches_the_rows_on_a_run_of_several_sources() {
    let scratch = Scratch::new();
    multi_source(&scratch);
    demo(&scratch, 60);
    scratch.ingest();
    let store = scratch.reader();
    assert!(ask(&store, "SELECT COUNT(*) FROM segments", vec![])[0][0] >= 9);
    assert_eq!(check_store(&store), [true; 3], "a clock had no fine window");
}

#[test]
#[ignore = "times the density request; give it a store in SEG_TIMING_DB"]
fn density_timing() {
    let db = PathBuf::from(std::env::var("SEG_TIMING_DB").unwrap());
    let store = Store::open_read_only(&db, Duration::from_secs(600)).unwrap();
    let runs = ask(&store, "SELECT id FROM runs ORDER BY id", vec![]);
    let run = runs[0][0];
    let median = |mut f: Box<dyn FnMut() -> i64 + '_>| -> (f64, i64) {
        let mut times = Vec::new();
        let mut total = 0;
        for _ in 0..7 {
            let started = Instant::now();
            total = f();
            times.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(f64::total_cmp);
        (times[3], total)
    };
    for clock in Clock::ALL {
        let c = clock.packet_column();
        let r = ask(
            &store,
            &format!("SELECT MIN({c}), MAX({c}) FROM packets"),
            vec![],
        );
        let (min, max) = (r[0][0], r[0][1]);
        let span = max - min + 1;
        for (zoom, buckets) in [
            (1i64, 1000),
            (1, 500),
            (10, 1000),
            (100, 1000),
            (1000, 1000),
        ] {
            let width = span / zoom;
            let from = min + (span - width) / 2;
            let to = from + width - 1;
            let (seg, seg_total) = median(Box::new(|| {
                let mut n: i64 = store
                    .packet_density(run, clock, from, to, buckets)
                    .unwrap()
                    .rows
                    .iter()
                    .map(|r| r[2].int().unwrap())
                    .sum();
                let meta = store.query(&sql::coarse_meta(run, clock), 1).unwrap();
                let coarse = meta
                    .rows
                    .first()
                    .and_then(|r| Some((r[0].int()?, r[1].int()?)));
                for q in sql::log_density_stored(run, clock, from, to, buckets, coarse) {
                    n += store
                        .query(&q, usize::MAX)
                        .unwrap()
                        .rows
                        .iter()
                        .map(|r| r[2].int().unwrap())
                        .sum::<i64>();
                }
                n
            }));
            let (old, old_total) = median(Box::new(|| {
                let meta = store.query(&sql::coarse_meta(run, clock), 1).unwrap();
                let coarse = meta
                    .rows
                    .first()
                    .and_then(|r| Some((r[0].int()?, r[1].int()?)));
                sql::density(run, clock, from, to, buckets, coarse)
                    .iter()
                    .flat_map(|q| store.query(q, usize::MAX).unwrap().rows)
                    .map(|r| r[2].int().unwrap())
                    .sum()
            }));
            let (packets, _) = median(Box::new(|| {
                store
                    .packet_density(run, clock, from, to, buckets)
                    .unwrap()
                    .rows
                    .len() as i64
            }));
            assert_eq!(seg_total, old_total, "{clock:?} 1/{zoom}");
            println!(
                "{} 1/{zoom} in {buckets}: whole request {seg:.1} ms (packets from segments {packets:.1} ms), \
                 before {old:.1} ms; {seg_total} items",
                clock.name()
            );
        }
    }
}

/// The segment files in the folder, sorted.
fn files_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The segments the store lists, sorted.
fn listed(store: &Store) -> Vec<String> {
    let mut names: Vec<String> = store
        .query(&Query::new("SELECT name FROM segments", vec![]), usize::MAX)
        .unwrap()
        .rows
        .iter()
        .map(|r| r[0].text().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// Every packet record of every segment is its row in `packets`, and each
/// segment covers exactly its file's packets.
fn check_records(scratch: &Scratch, store: &Store) {
    let folder = segment::folder_for(&scratch.db());
    let segments = store
        .query(
            &Query::new(
                "SELECT s.name, s.first_packet, s.last_packet, f.first_packet, f.last_packet
                 FROM segments s JOIN files f ON f.id = s.file_id",
                vec![],
            ),
            usize::MAX,
        )
        .unwrap();
    assert!(!segments.rows.is_empty());
    for r in &segments.rows {
        let name = r[0].text().unwrap();
        let ids: Vec<i64> = r[1..].iter().map(|c| c.int().unwrap()).collect();
        assert_eq!((ids[0], ids[1]), (ids[2], ids[3]), "{name}");
        let seg = Segment::open(&folder.join(name)).unwrap();
        assert_eq!(seg.first_packet(), ids[0]);
        assert_eq!(seg.packets() as i64, ids[1] - ids[0] + 1);
        let labels = seg.labels().unwrap();
        let rows = store
            .query(
                &Query::new(
                    "SELECT receive_ns, packet_ns, offset, sum, length, lane_id, apid, seq, ptype,
                            label
                     FROM packets WHERE id BETWEEN ? AND ? ORDER BY id",
                    vec![ids[0].into(), ids[1].into()],
                ),
                usize::MAX,
            )
            .unwrap();
        for (i, row) in rows.rows.iter().enumerate() {
            let p = seg.packet(i as u64).unwrap();
            let header = p
                .header
                .map(|(apid, seq, ptype)| (i64::from(apid), i64::from(seq), i64::from(ptype)));
            let label = p.label.map(|l| labels[l as usize].clone());
            assert_eq!(
                (
                    p.receive_ns,
                    p.packet_ns,
                    p.offset,
                    p.sum,
                    p.length,
                    i64::from(p.lane),
                    header,
                    label.as_deref(),
                ),
                (
                    row[0].int(),
                    row[1].int(),
                    row[2].int().unwrap(),
                    row[3].int().unwrap(),
                    row[4].int().unwrap(),
                    row[5].int().unwrap(),
                    row[6]
                        .int()
                        .map(|apid| (apid, row[7].int().unwrap(), row[8].int().unwrap())),
                    row[9].text(),
                ),
                "{name} packet {i}"
            );
        }
        assert!(seg.packet(rows.rows.len() as u64).is_err());
    }
}

#[test]
fn segments_hold_the_rows_of_their_files() {
    let scratch = Scratch::new();
    demo(&scratch, 60);
    multi_source(&scratch);
    scratch.ingest();
    let store = scratch.reader();
    // Some packets have a receive time and no packet time.
    let partial = ask(
        &store,
        "SELECT COUNT(*) FROM packets WHERE receive_ns IS NOT NULL AND packet_ns IS NULL",
        vec![],
    );
    assert!(partial[0][0] > 0);
    check_records(&scratch, &store);
    // The folder holds the listed segments and nothing else.
    assert_eq!(
        files_in(&segment::folder_for(&scratch.db())),
        listed(&store)
    );
}

#[test]
fn a_file_read_again_after_it_grows_gets_a_new_segment() {
    let scratch = Scratch::new();
    demo(&scratch, 60);
    let mut early = Source::new(42, 0, 10);
    let early_bytes: Vec<u8> = (0..300).flat_map(|_| early.emit()).collect();
    scratch.write("aa/early.bin", &early_bytes);
    // Read last, so it has the highest file id and its packets the highest
    // packet ids, which SQLite hands out again once they are deleted.
    let mut late = Source::new(43, 0, 10);
    let late_bytes: Vec<u8> = (0..300).flat_map(|_| late.emit()).collect();
    scratch.write("zz/late.bin", &late_bytes);
    scratch.ingest();
    let folder = segment::folder_for(&scratch.db());
    let store = scratch.reader();
    let file_id = |rel: &str| {
        ask(
            &store,
            "SELECT id FROM files WHERE rel = ?",
            vec![rel.into()],
        )[0][0]
    };
    let segment_of = |rel: &str| {
        store
            .query(
                &Query::new(
                    "SELECT s.name FROM segments s JOIN files f ON f.id = s.file_id
                     WHERE f.rel = ?",
                    vec![rel.into()],
                ),
                1,
            )
            .unwrap()
            .rows[0][0]
            .text()
            .unwrap()
            .to_string()
    };
    let (late_id, early_seg, late_seg) = (
        file_id("zz/late.bin"),
        segment_of("aa/early.bin"),
        segment_of("zz/late.bin"),
    );
    assert_eq!(late_seg, format!("{late_id}.seg"));

    let grow = |rel: &str, source: &mut Source, n: usize| {
        let mut bytes = fs::read(scratch.0.join("run").join(rel)).unwrap();
        bytes.extend((0..n).flat_map(|_| source.emit()));
        scratch.write(rel, &bytes);
        scratch.ingest();
    };
    let count = |rel: &str| {
        ask(
            &store,
            "SELECT packets FROM files WHERE rel = ?",
            vec![rel.into()],
        )[0][0]
    };

    // The last file grows. It is given its old id again, so its new segment
    // cannot take the old one's name while that is still listed.
    grow("zz/late.bin", &mut late, 50);
    assert_eq!(file_id("zz/late.bin"), late_id);
    assert_eq!(segment_of("zz/late.bin"), format!("{late_id}.1.seg"));
    assert!(!folder.join(&late_seg).exists());
    assert_eq!(files_in(&folder), listed(&store));
    assert_eq!(count("zz/late.bin"), 350);
    check_records(&scratch, &store);

    // Again: now the plain name is free.
    grow("zz/late.bin", &mut late, 1);
    assert_eq!(segment_of("zz/late.bin"), format!("{late_id}.seg"));
    assert_eq!(files_in(&folder), listed(&store));

    // A file in the middle grows: a new id, a new segment, the old one gone.
    grow("aa/early.bin", &mut early, 50);
    assert_ne!(segment_of("aa/early.bin"), early_seg);
    assert!(!folder.join(&early_seg).exists());
    assert_eq!(files_in(&folder), listed(&store));
    assert_eq!((count("aa/early.bin"), count("zz/late.bin")), (350, 351));
    check_records(&scratch, &store);
    assert_eq!(check_store(&store), [true; 3], "a clock had no fine window");
}

#[test]
fn a_file_that_no_longer_holds_packets_loses_its_segment() {
    let scratch = Scratch::new();
    let mut source = Source::new(5, 0, 8);
    let bytes: Vec<u8> = (0..100).flat_map(|_| source.emit()).collect();
    scratch.write("a/one.bin", &bytes);
    scratch.write("a/two.bin", &bytes);
    scratch.ingest();
    let folder = segment::folder_for(&scratch.db());
    let store = scratch.reader();
    assert_eq!(listed(&store).len(), 2);

    // One is emptied (nothing to store), the other becomes a text log.
    scratch.write("a/one.bin", &[]);
    scratch.write("a/two.bin", b"2026-01-01T00:00:00Z started\n");
    scratch.ingest();
    assert!(listed(&store).is_empty());
    assert!(files_in(&folder).is_empty());
    assert_eq!(ask(&store, "SELECT COUNT(*) FROM packets", vec![])[0][0], 0);
}

#[test]
fn a_changed_configuration_replaces_every_segment() {
    let scratch = Scratch::new();
    demo(&scratch, 60);
    let config = scratch.0.join("run/packetlane.toml");
    let aside = scratch.0.join("packetlane.toml");
    fs::rename(&config, &aside).unwrap();
    scratch.ingest();
    let folder = segment::folder_for(&scratch.db());
    let store = scratch.reader();
    let before = listed(&store);
    let no_packet_time = ask(
        &store,
        "SELECT COUNT(*) FROM segments WHERE packet_min IS NOT NULL",
        vec![],
    );
    assert_eq!(no_packet_time[0][0], 0);

    // With the configuration the run is emptied and read again.
    fs::rename(&aside, &config).unwrap();
    scratch.ingest();
    let after = listed(&store);
    assert_eq!(after.len(), before.len());
    assert_eq!(files_in(&folder), after);
    // Packet time is read now, and the segments have it.
    let with_packet_time = ask(
        &store,
        "SELECT COUNT(*) FROM segments WHERE packet_min IS NOT NULL",
        vec![],
    );
    assert!(with_packet_time[0][0] > 0);
    check_records(&scratch, &store);
    assert_eq!(check_store(&store), [true; 3], "a clock had no fine window");
}

#[test]
fn files_in_the_segment_folder_that_the_store_does_not_list_are_removed() {
    let scratch = Scratch::new();
    let mut source = Source::new(5, 0, 8);
    let bytes: Vec<u8> = (0..100).flat_map(|_| source.emit()).collect();
    scratch.write("a/one.bin", &bytes);
    scratch.ingest();
    let folder = segment::folder_for(&scratch.db());
    let kept = files_in(&folder);
    assert_eq!(kept.len(), 1);
    for stray in ["99.seg", "7.seg.tmp", "7.receive.1.tmp", "notes.txt"] {
        fs::write(folder.join(stray), b"left behind").unwrap();
    }
    drop(Store::open(&scratch.db()).unwrap());
    let mut expected = kept.clone();
    expected.push("notes.txt".to_string());
    expected.sort();
    assert_eq!(files_in(&folder), expected);
    // A reader removes nothing.
    fs::write(folder.join("98.seg"), b"left behind").unwrap();
    drop(scratch.reader());
    assert!(folder.join("98.seg").exists());
}

#[test]
fn damaged_segments_are_refused() {
    let scratch = Scratch::new();
    let mut source = Source::new(5, 0, 8);
    let bytes: Vec<u8> = (0..100).flat_map(|_| source.emit()).collect();
    scratch.write("a/one.bin", &bytes);
    scratch.ingest();
    let folder = segment::folder_for(&scratch.db());
    let name = files_in(&folder).pop().unwrap();
    let path = folder.join(&name);
    let good = fs::read(&path).unwrap();
    assert!(Segment::open(&path).is_ok());

    let len = good.len();
    let mut damaged: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("magic only", good[..8].to_vec()),
        ("cut short by one byte", good[..len - 1].to_vec()),
        ("cut before the directory", good[..len - 40].to_vec()),
        ("cut in half", good[..len / 2].to_vec()),
    ];
    let mut flip = |what: &'static str, at: usize| {
        let mut b = good.clone();
        b[at] ^= 0x55;
        damaged.push((what, b));
    };
    flip("bad leading magic", 0);
    flip("bad trailing magic", len - 1);
    flip("wrong version", len - 12);
    flip("directory claims more entries", len - 16);
    let entries = u32::from_le_bytes(good[len - 16..len - 12].try_into().unwrap()) as usize;
    flip("first section moved", len - 32 - entries * 32 + 8);
    for (what, bytes) in &damaged {
        fs::write(&path, bytes).unwrap();
        assert!(Segment::open(&path).is_err(), "{what}");
        // Reading density from it fails with an error, not a panic.
        let store = scratch.reader();
        assert!(
            store
                .packet_density(1, Clock::Order, 0, i64::MAX, 100)
                .is_err(),
            "{what}"
        );
    }
    fs::remove_file(&path).unwrap();
    assert!(
        scratch
            .reader()
            .packet_density(1, Clock::Order, 0, i64::MAX, 100)
            .is_err()
    );
    fs::write(&path, &good).unwrap();
    assert!(
        scratch
            .reader()
            .packet_density(1, Clock::Order, 0, i64::MAX, 100)
            .is_ok()
    );
}
