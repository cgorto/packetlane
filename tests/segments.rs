//! Segment files against the oracle: every answer read from the segments is
//! checked against the `oracle_packets` and `oracle_field_values` tables of
//! the same store (see `pure::oracle`), which a store opened for tests
//! writes with the same packets.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use packetlane::pure::oracle;
use packetlane::pure::segment::{DELAY, level_for, plan};
use packetlane::pure::sql::{self, Clock, Query, bucket_width};
use packetlane::pure::synth::{Source, cosmos4_entry, cosmos4_header, demo_run, timed_packet};
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
        let mut store = Store::open_with_oracle(&self.db()).unwrap();
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
    let mut rows = ints(store, &oracle::packet_density(1, clock, from, to, buckets));
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
               FROM oracle_packets p JOIN lv ON p.id BETWEEN lv.a AND lv.z
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
        &format!("SELECT MIN({c}), MAX({c}) FROM oracle_packets WHERE {c} IS NOT NULL"),
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
                    "SELECT lane_id, COUNT(*) FROM oracle_packets WHERE {c} BETWEEN ? AND ?
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

/// One item row as (id, lane, time, seq, length); a missing seq is
/// `i64::MIN`.
fn item_rows(t: &sql::Table) -> Vec<[i64; 5]> {
    t.rows
        .iter()
        .map(|r| {
            let mut out = [0i64; 5];
            for (o, c) in out.iter_mut().zip(r) {
                *o = c.int().unwrap_or(i64::MIN);
            }
            out
        })
        .collect()
}

/// Item lists from the segments against the `packets` rows, on every clock,
/// for windows whole, wider than the run, unaligned, empty, inverted and
/// one instant wide, at limits that do and do not cut. Returns whether
/// some limit cut through packets of equal time.
fn check_items(store: &Store) -> bool {
    let mut cut_a_tie = false;
    for clock in Clock::ALL {
        let Some((min, max)) = extent(store, clock) else {
            continue;
        };
        let span = max - min + 1;
        let c = clock.packet_column();
        // Times held by more than one packet, for windows that start there.
        let tied = ask(
            store,
            &format!(
                "SELECT {c} FROM oracle_packets WHERE {c} IS NOT NULL
                 GROUP BY {c} HAVING COUNT(*) > 1 ORDER BY {c} LIMIT 3"
            ),
            vec![],
        );
        let mut windows = vec![
            (min, max),
            (min - span, max + span),
            (min + span / 7 + 3, max - span / 5 - 11),
            (max + 1, max + span),
            (max, min),
            (min + span / 2, min + span / 2),
            (i64::MIN, i64::MAX),
        ];
        windows.extend(tied.iter().map(|r| (r[0], max)));
        for (from, to) in windows {
            for limit in [1usize, 2, 37, 1_000_000] {
                let got = store.packet_items(1, clock, from, to, limit).unwrap();
                let lim = limit.min(i64::MAX as usize) as i64;
                let old = store
                    .query(
                        &oracle::packet_items(1, clock, from, to, lim.saturating_add(1)),
                        limit,
                    )
                    .unwrap();
                let what = format!("{clock:?} {from}..={to} limit {limit}");
                assert_eq!(got.columns, old.columns, "{what}");
                assert_eq!(got.truncated, old.truncated, "{what}");
                let (g, o) = (item_rows(&got), item_rows(&old));
                // The same times in the same order...
                let times = |rows: &[[i64; 5]]| rows.iter().map(|r| r[2]).collect::<Vec<_>>();
                assert_eq!(times(&g), times(&o), "{what}");
                // ...the same packets when nothing is cut...
                if !old.truncated {
                    let (mut gs, mut os) = (g.clone(), o.clone());
                    gs.sort_unstable();
                    os.sort_unstable();
                    assert_eq!(gs, os, "{what}");
                }
                // ...and exactly the first by time and then id.
                let exact = ints(
                    store,
                    &Query::new(
                        format!(
                            "SELECT id, lane_id, {c}, seq, length FROM oracle_packets
                             WHERE {c} BETWEEN ? AND ? ORDER BY {c}, id LIMIT ?"
                        ),
                        vec![from.into(), to.into(), lim.into()],
                    ),
                );
                assert_eq!(
                    g.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
                    exact,
                    "{what}"
                );
                cut_a_tie |= old.truncated
                    && g.last().is_some_and(|last| {
                        o.last().is_some_and(|l| l[0] != last[0])
                            || tied.iter().any(|t| t[0] == last[2])
                    });
            }
        }
    }
    cut_a_tie
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

/// A run with kept fields of every kind: a dense lane (100,000 packets in
/// three seconds, enough for its series buckets to pay), a sparse one
/// (whose buckets do not), and packets with no time on either clock.
const KEPT_CONFIG: &str = r#"
[packet_time]
code = "unix"
byte_offset = 6
coarse_bytes = 4
require_secondary_header = false

[[packet]]
apid = 16
name = "HK"
  [[packet.field]]
  name = "V"
  bit_offset = 112
  bit_length = 16
  keep = true
  [[packet.field]]
  name = "MODE"
  bit_offset = 128
  bit_length = 8
  labels = { "0" = "OFF", "1" = "ON" }
  keep = true
  [[packet.field]]
  name = "NAME"
  bit_offset = 136
  bit_length = 32
  kind = "ascii"
  keep = true
  [[packet.field]]
  name = "ARR"
  bit_offset = 168
  bit_length = 8
  count = 3
  keep = true
  [[packet.field]]
  name = "F"
  bit_offset = 192
  bit_length = 32
  kind = "float"
  keep = true

[[packet]]
apid = 18
name = "RARE"
  [[packet.field]]
  name = "V"
  bit_offset = 112
  bit_length = 16
  keep = true

[[packet]]
apid = 17
name = "TINY"
  [[packet.field]]
  name = "B"
  bit_offset = 48
  bit_length = 8
  keep = true
"#;

/// One kept-field packet: receive time, packet time (unix seconds and
/// microseconds), and a body whose values follow `i`.
fn kept_entry(apid: u16, i: u32, receive_ns: i64, packet_ns: i64) -> Vec<u8> {
    let mut time = ((packet_ns / 1_000_000_000) as u32).to_be_bytes().to_vec();
    time.extend_from_slice(&(((packet_ns % 1_000_000_000) / 1_000) as u32).to_be_bytes());
    let mut body = ((i * 7_919 % 65_536) as u16).to_be_bytes().to_vec();
    body.push((i % 2) as u8);
    body.extend_from_slice(if i.is_multiple_of(3) {
        b"UNIT"
    } else {
        b"spar"
    });
    body.extend_from_slice(&[(i % 5) as u8, 7, (i % 251) as u8]);
    let f = if i.is_multiple_of(97) {
        f32::NAN
    } else {
        i as f32 * 0.25 - 100.0
    };
    body.extend_from_slice(&f.to_be_bytes());
    let packet = timed_packet(apid, (i % 16_384) as u16, &time, &body);
    cosmos4_entry(receive_ns, "UNIT", "HK", &packet)
}

fn kept_run(scratch: &Scratch) {
    scratch.write("packetlane.toml", KEPT_CONFIG.as_bytes());
    let t0 = 1_767_225_600_000_000_000i64;
    let mut dense = cosmos4_header(true, "kept", "bench");
    for i in 0..100_000u32 {
        let r = t0 + i64::from(i) * 30_000;
        // One packet in a hundred is of a rarer stream, whose few values
        // lie among many packets.
        let apid = if i % 100 == 50 { 18 } else { 16 };
        dense.extend(kept_entry(
            apid,
            i,
            r,
            r - 40_000_000 - i64::from(i % 13) * 1_000,
        ));
    }
    scratch.write("bench/dense.bin", &dense);
    let mut sparse = cosmos4_header(true, "kept", "other");
    for i in 0..300u32 {
        let r = t0 + i64::from(i) * 10_000_000 + 3;
        sparse.extend(kept_entry(16, i, r, r - 1_000_000 * i64::from(i % 50)));
    }
    scratch.write("other/sparse.bin", &sparse);
    // Plain packets: no receive time, and too short to hold a packet time.
    let mut tiny = Source::new(17, 0, 2);
    let bytes: Vec<u8> = (0..50).flat_map(|_| tiny.emit()).collect();
    scratch.write("raw/tiny.bin", &bytes);
}

/// A number cell as `merge_series` reads it.
fn number(c: &sql::Cell) -> Option<f64> {
    match c {
        sql::Cell::Real(v) => Some(*v),
        sql::Cell::Int(v) => Some(*v as f64),
        _ => None,
    }
}

/// Series rows as (bucket, min, max, count).
fn series_rows(t: &sql::Table) -> Vec<(i64, f64, f64, i64)> {
    t.rows
        .iter()
        .map(|r| {
            (
                r[0].int().unwrap(),
                number(&r[1]).unwrap(),
                number(&r[2]).unwrap(),
                r[3].int().unwrap(),
            )
        })
        .collect()
}

/// For each segment holding the series on a clock: first and last packet
/// id, the series' bucket grid shift, whether its buckets were kept, and
/// whether the segment has the series at all.
fn series_levels(
    store: &Store,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
) -> Vec<(i64, i64, u32, bool, bool)> {
    let mut out = Vec::new();
    for (first, last, name) in listed_segments(store) {
        let seg = Segment::open(&store.segment_folder().join(name)).unwrap();
        if clock == Clock::Order {
            out.push((first, last, 0, false, false));
            continue;
        }
        let id = match field {
            None => Some(DELAY),
            Some((p, f)) => seg.series_id(p, f).unwrap(),
        };
        let group = id.and_then(|id| seg.group(clock, lane as u32, id).unwrap());
        let shift = seg.series_shift(clock).unwrap();
        out.push((
            first,
            last,
            shift,
            group.is_some_and(|g| g.buckets > 0),
            group.is_some(),
        ));
    }
    out
}

fn listed_segments(store: &Store) -> Vec<(i64, i64, String)> {
    store
        .query(
            &Query::new(
                "SELECT first_packet, last_packet, name FROM segments",
                vec![],
            ),
            usize::MAX,
        )
        .unwrap()
        .rows
        .iter()
        .map(|r| {
            (
                r[0].int().unwrap(),
                r[1].int().unwrap(),
                r[2].text().unwrap().to_string(),
            )
        })
        .collect()
}

/// The rule for plots worked out value by value from the `packets` and
/// `field_values` rows in SQL: a value in a stored bucket of its segment
/// that was kept and lies wholly inside the window, when view buckets are
/// at least as wide, goes to the view bucket where that stored bucket
/// starts; any other to its own.
#[allow(clippy::too_many_arguments)]
fn series_rule_in_sql(
    store: &Store,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    from: i64,
    to: i64,
    buckets: i64,
) -> Vec<(i64, f64, f64, i64)> {
    let c = clock.packet_column();
    let width = bucket_width(from, to, buckets);
    let (value, join, filter) = match field {
        None => (
            "(p.receive_ns - p.packet_ns) / 1000000.0",
            "",
            "p.receive_ns IS NOT NULL AND p.packet_ns IS NOT NULL",
        ),
        Some(_) => (
            "v.num",
            "CROSS JOIN oracle_field_values v INDEXED BY oracle_field_values_packet ON v.packet_id = p.id",
            "v.packet = ?8 AND v.field = ?9 AND v.num IS NOT NULL",
        ),
    };
    // Segment by segment, each read by its range of ids, then merged as
    // `merge_series` merges.
    let mut parts = Vec::new();
    for (a, z, s, kept, _) in series_levels(store, clock, lane, field) {
        let (packet, name) = field.unwrap_or(("", ""));
        let q = Query::new(
            format!(
                "SELECT CASE WHEN ?7 AND ?3 >= (1 << ?6) AND ((t >> ?6) << ?6) >= ?1
                              AND ((t >> ?6) << ?6) + (1 << ?6) - 1 <= ?2
                         THEN (((t >> ?6) << ?6) - ?1) / ?3 ELSE (t - ?1) / ?3 END AS bin,
                        MIN(num), MAX(num), COUNT(*)
                 FROM (SELECT p.{c} AS t, {value} AS num
                       FROM oracle_packets p {join}
                       WHERE p.id BETWEEN ?4 AND ?5 AND p.lane_id = ?10
                         AND p.{c} BETWEEN ?1 AND ?2 AND {filter})
                 GROUP BY bin"
            ),
            vec![
                from.into(),
                to.into(),
                width.into(),
                a.into(),
                z.into(),
                i64::from(s).into(),
                i64::from(kept).into(),
                packet.into(),
                name.into(),
                lane.into(),
            ],
        );
        parts.push(store.query(&q, usize::MAX).unwrap());
    }
    let parts: Vec<&sql::Table> = parts.iter().collect();
    series_rows(&sql::merge_series(&parts))
}

/// Plots from the segments against the rows, for every lane and kept field
/// with numbers and every lane's arrival delay, on every clock: fine zoom
/// row for row against `sql::value_series` and `sql::lag_series`; coarse
/// zoom row for row against the rule worked out in SQL, with the totals,
/// lowest and highest against the window's values. Returns how many
/// series were read partly from stored buckets and partly point by point,
/// how many had buckets that were not kept, and how many fine plots on a
/// time clock were compared.
fn check_series(db: &Path) -> (usize, usize, usize) {
    let store = &Store::open_read_only(db, Duration::from_secs(600)).unwrap();
    let mut mixed = 0;
    let mut fine = 0;
    let mut skipped = 0;
    let mut series: Vec<(i64, Option<(String, String)>)> = store
        .query(
            &Query::new(
                "SELECT DISTINCT p.lane_id, v.packet, v.field FROM oracle_field_values v
                 JOIN oracle_packets p ON p.id = v.packet_id WHERE v.num IS NOT NULL
                 ORDER BY 1, 2, 3",
                vec![],
            ),
            usize::MAX,
        )
        .unwrap()
        .rows
        .iter()
        .map(|r| {
            let name = (
                r[1].text().unwrap().to_string(),
                r[2].text().unwrap().to_string(),
            );
            (r[0].int().unwrap(), Some(name))
        })
        .collect();
    for r in ask(
        store,
        "SELECT DISTINCT lane_id FROM oracle_packets
         WHERE receive_ns IS NOT NULL AND packet_ns IS NOT NULL ORDER BY 1",
        vec![],
    ) {
        series.push((r[0], None));
    }
    assert!(!series.is_empty());
    for (lane, name) in &series {
        let store = &Store::open_read_only(db, Duration::from_secs(600)).unwrap();
        let field = name.as_ref().map(|(p, f)| (p.as_str(), f.as_str()));
        for clock in Clock::ALL {
            let c = clock.packet_column();
            let r = ask(
                store,
                &format!("SELECT MIN({c}), MAX({c}) FROM oracle_packets WHERE lane_id = ?"),
                vec![(*lane).into()],
            );
            if r[0][0] == i64::MIN {
                continue;
            }
            let (min, max) = (r[0][0], r[0][1]);
            let span = max - min + 1;
            let levels = series_levels(store, clock, *lane, field);
            let kept_min = levels.iter().filter(|l| l.3).map(|l| l.2).min();
            skipped += levels.iter().filter(|l| l.4 && !l.3).count();
            let what = |from: i64, to: i64, b: i64| {
                format!("{lane} {field:?} {clock:?} {from}..={to} in {b}")
            };
            // Fine: view buckets narrower than every stored bucket.
            let fine_width = kept_min.map_or((span / 50).max(1), |s| 1i64 << s);
            for (from, to, buckets) in [
                (min, min + fine_width * 3 - 1, 4000),
                (
                    min + span / 3 + 7,
                    min + span / 3 + 7 + fine_width * 2,
                    3_999,
                ),
                (max - fine_width * 5, max, 1_000),
            ] {
                if kept_min.is_some() && bucket_width(from, to, buckets) >= fine_width {
                    continue;
                }
                let got = series_rows(
                    &store
                        .series(1, clock, *lane, field, from, to, buckets)
                        .unwrap(),
                );
                let q = match field {
                    Some((p, f)) => oracle::value_series(1, clock, *lane, p, f, from, to, buckets),
                    None => oracle::lag_series(1, clock, *lane, from, to, buckets),
                };
                let want = series_rows(&store.query(&q, usize::MAX).unwrap());
                assert_eq!(got, want, "fine {}", what(from, to, buckets));
                fine += usize::from(clock != Clock::Order);
            }
            // Coarse and in between.
            for (from, to, buckets) in [
                (min, max, 1000),
                (min - span, max + span, 7),
                (min + span / 7 + 3, max - span / 5 - 11, 333),
                (min + span / 3 + 1, min + span / 3 + span / 10, 1000),
                (min + 17, min + span / 1000 + 19, 1000),
                (min, max, 1),
            ] {
                let got = series_rows(
                    &store
                        .series(1, clock, *lane, field, from, to, buckets)
                        .unwrap(),
                );
                let want = series_rule_in_sql(store, clock, *lane, field, from, to, buckets);
                assert_eq!(got, want, "rule {}", what(from, to, buckets));
                // Totals, lowest and highest are those of the window.
                let q = match field {
                    Some((p, f)) => oracle::value_series(1, clock, *lane, p, f, from, to, 1),
                    None => oracle::lag_series(1, clock, *lane, from, to, 1),
                };
                let all = series_rows(&store.query(&q, usize::MAX).unwrap());
                let sum = |rows: &[(i64, f64, f64, i64)]| rows.iter().map(|r| r.3).sum::<i64>();
                assert_eq!(sum(&got), sum(&all), "total {}", what(from, to, buckets));
                let lo = got.iter().map(|r| r.1).fold(f64::INFINITY, f64::min);
                let hi = got.iter().map(|r| r.2).fold(f64::NEG_INFINITY, f64::max);
                if let Some(a) = all.first() {
                    assert_eq!((lo, hi), (a.1, a.2), "extremes {}", what(from, to, buckets));
                }
                let width = bucket_width(from, to, buckets);
                mixed += usize::from(levels.iter().any(|&(_, _, s, kept, _)| {
                    let p = plan(from, to, width, s);
                    kept && p.whole.is_some() && !p.direct.is_empty()
                }));
            }
        }
    }
    (mixed, skipped, fine)
}

#[test]
fn plots_from_segments_match_the_rows() {
    let scratch = Scratch::new();
    kept_run(&scratch);
    multi_source(&scratch);
    scratch.ingest();
    let (mixed, skipped, fine) = check_series(&scratch.db());
    assert!(fine > 0, "no fine plot on a time clock");
    assert!(mixed > 0, "no plot read partly from stored buckets");
    assert!(skipped > 0, "no series with buckets not kept");
    // The demo's own kept fields.
    let scratch = Scratch::new();
    demo(&scratch, 60);
    scratch.ingest();
    check_series(&scratch.db());
}

/// Packet detail and kept values from the segments against the rows, for
/// the first, last and every 97th packet of each segment and for packets
/// picked out by what they hold. Returns how many were compared.
fn check_details(store: &Store) -> usize {
    let mut ids: Vec<i64> = Vec::new();
    for (first, last, _) in listed_segments(store) {
        ids.extend([first, last, first + (last - first) / 2]);
        ids.extend((first..=last).step_by(97));
    }
    for pick in [
        // No packet time; neither time; a text; a text and a number; an
        // array; a number that is not one.
        "SELECT id FROM oracle_packets WHERE packet_ns IS NULL LIMIT 5",
        "SELECT id FROM oracle_packets WHERE packet_ns IS NULL AND receive_ns IS NULL LIMIT 5",
        "SELECT packet_id FROM oracle_field_values WHERE text IS NOT NULL AND num IS NULL LIMIT 5",
        "SELECT packet_id FROM oracle_field_values WHERE text IS NOT NULL AND num IS NOT NULL LIMIT 5",
        "SELECT packet_id FROM oracle_field_values WHERE text LIKE '[%' LIMIT 5",
        "SELECT packet_id FROM oracle_field_values WHERE field = 'F' AND num IS NULL LIMIT 5",
    ] {
        ids.extend(ask(store, pick, vec![]).iter().map(|r| r[0]));
    }
    // And packets that are not there.
    ids.extend([0, -1, i64::MAX]);
    for &id in &ids {
        assert_eq!(
            store.packet_detail(id).unwrap(),
            store.query(&oracle::packet_detail(id), 1).unwrap(),
            "packet {id}"
        );
        let rows = store
            .query(
                &Query::new(
                    "SELECT packet, field, num, text FROM oracle_field_values
                     WHERE packet_id = ? ORDER BY rowid",
                    vec![id.into()],
                ),
                usize::MAX,
            )
            .unwrap();
        assert_eq!(store.packet_values(id).unwrap(), rows, "values of {id}");
    }
    ids.len()
}

/// A run's findings with their packets' times from the segments against
/// `sql::run_findings`, whole and cut short.
fn check_findings(store: &Store) -> usize {
    let all = store.query(&oracle::run_findings(1), usize::MAX).unwrap();
    for limit in [usize::MAX, all.rows.len(), 3, 1] {
        assert_eq!(
            store.run_findings(1, limit).unwrap(),
            store.query(&oracle::run_findings(1), limit).unwrap(),
            "limit {limit}"
        );
    }
    all.rows.len()
}

#[test]
fn packet_details_values_and_findings_from_segments_match_the_rows() {
    let scratch = Scratch::new();
    kept_run(&scratch);
    multi_source(&scratch);
    scratch.ingest();
    let store = scratch.reader();
    // Values on packets with neither time are kept.
    let timeless = ask(
        &store,
        "SELECT COUNT(*) FROM oracle_field_values v JOIN oracle_packets p ON p.id = v.packet_id
         WHERE p.receive_ns IS NULL AND p.packet_ns IS NULL",
        vec![],
    );
    assert!(timeless[0][0] > 0);
    assert!(check_details(&store) > 100);
    check_findings(&store);
    // The demo, whose findings point at packets of every file.
    let scratch = Scratch::new();
    demo(&scratch, 60);
    scratch.ingest();
    let store = scratch.reader();
    check_details(&store);
    assert!(check_findings(&store) > 3, "too few findings to compare");
}

/// The directory of a segment's bytes: (kind, clock, record size, offset,
/// length, where the entry starts).
fn directory(bytes: &[u8]) -> Vec<(u16, u8, u32, u64, u64, usize)> {
    let len = bytes.len();
    let n = u32::from_le_bytes(bytes[len - 16..len - 12].try_into().unwrap()) as usize;
    let at = len - 32 - n * 32;
    (0..n)
        .map(|i| {
            let e = &bytes[at + i * 32..at + i * 32 + 32];
            (
                u16::from_le_bytes([e[0], e[1]]),
                e[2],
                u32::from_le_bytes(e[4..8].try_into().unwrap()),
                u64::from_le_bytes(e[8..16].try_into().unwrap()),
                u64::from_le_bytes(e[16..24].try_into().unwrap()),
                at + i * 32,
            )
        })
        .collect()
}

#[test]
fn damaged_kept_value_sections_are_errors_not_panics() {
    let scratch = Scratch::new();
    kept_run(&scratch);
    scratch.ingest();
    let store = scratch.reader();
    let folder = segment::folder_for(&scratch.db());
    // The dense file's segment, its first packet and lane.
    let r = ask(
        &store,
        "SELECT s.first_packet, p.lane_id FROM segments s
         JOIN files f ON f.id = s.file_id JOIN oracle_packets p ON p.id = s.first_packet
         WHERE f.rel = 'bench/dense.bin'",
        vec![],
    );
    let (first, lane) = (r[0][0], r[0][1]);
    let name = store
        .query(
            &Query::new(
                "SELECT name FROM segments WHERE first_packet = ?",
                vec![first.into()],
            ),
            1,
        )
        .unwrap()
        .rows[0][0]
        .text()
        .unwrap()
        .to_string();
    let path = folder.join(&name);
    let good = fs::read(&path).unwrap();
    let reads = |store: &Store| -> [bool; 4] {
        [
            store
                .series(
                    1,
                    Clock::Receive,
                    lane,
                    Some(("HK", "V")),
                    i64::MIN,
                    i64::MAX,
                    100,
                )
                .is_ok(),
            store
                .series(1, Clock::Packet, lane, None, i64::MIN, i64::MAX, 100)
                .is_ok(),
            store.packet_values(first).is_ok(),
            store
                .packet_items(1, Clock::Receive, i64::MIN, i64::MAX, 10)
                .is_ok(),
        ]
    };
    assert_eq!(reads(&store), [true; 4]);
    let entry = |kind: u16, clock: u8| {
        *directory(&good)
            .iter()
            .find(|e| e.0 == kind && e.1 == clock)
            .unwrap()
    };
    let put_u64 =
        |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    // Each new section with a wrong record size, and cut short by a byte.
    for kind in 5..=10u16 {
        for e in directory(&good).into_iter().filter(|e| e.0 == kind) {
            let mut b = good.clone();
            b[e.5 + 4] ^= 1;
            cases.push((format!("kind {kind} record size"), b));
            if e.2 != 0 && e.4 > 0 {
                let mut b = good.clone();
                put_u64(&mut b, e.5 + 16, e.4 - 1);
                cases.push((format!("kind {kind} cut short"), b));
            }
        }
    }
    // Records that pass the directory but point outside their sections:
    // a group running past its points and its buckets, a value naming no
    // series, a text past the texts section, a series name cut short.
    let groups = entry(9, 0);
    let mut b = good.clone();
    put_u64(&mut b, groups.3 as usize + 16, u64::MAX - 3);
    cases.push(("group count".into(), b));
    let mut b = good.clone();
    put_u64(&mut b, groups.3 as usize + 24, u64::MAX);
    cases.push(("group buckets".into(), b));
    let values = entry(6, 0);
    let mut b = good.clone();
    b[values.3 as usize + 4..values.3 as usize + 7].copy_from_slice(&[0xFF, 0xFF, 0x7F]);
    cases.push(("value series".into(), b));
    let texts = entry(7, 0);
    let first_text = (0..values.4 / 24)
        .map(|i| values.3 as usize + i as usize * 24)
        .find(|&at| good[at + 7] & 2 != 0)
        .unwrap();
    let mut b = good.clone();
    put_u64(&mut b, first_text + 16, texts.4 - 2);
    cases.push(("text offset".into(), b));
    let names = entry(5, 0);
    let mut b = good.clone();
    put_u64(&mut b, names.5 + 16, names.4 - 1);
    cases.push(("series names cut".into(), b));
    for (what, bytes) in &cases {
        fs::write(&path, bytes).unwrap();
        let got = reads(&scratch.reader());
        assert!(got.iter().any(|ok| !ok), "{what}: {got:?}");
    }
    fs::write(&path, &good).unwrap();
    assert_eq!(reads(&scratch.reader()), [true; 4]);
}

#[test]
fn item_lists_from_segments_match_the_rows() {
    let scratch = Scratch::new();
    demo(&scratch, 60);
    multi_source(&scratch);
    // A copy of a file in another folder: the same times twice.
    let copy = fs::read(scratch.0.join("run/bench-b/gen.bin")).unwrap();
    scratch.write("copy/gen.bin", &copy);
    scratch.ingest();
    let store = scratch.reader();
    assert!(check_items(&store), "no limit cut through equal times");
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
            &format!("SELECT MIN({c}), MAX({c}) FROM oracle_packets"),
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
                // Every packet and entry counted from the rows.
                std::iter::once(oracle::packet_density(run, clock, from, to, buckets))
                    .chain(sql::log_density(run, clock, from, to, buckets))
                    .collect::<Vec<_>>()
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
                     FROM oracle_packets WHERE id BETWEEN ? AND ? ORDER BY id",
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
        "SELECT COUNT(*) FROM oracle_packets WHERE receive_ns IS NOT NULL AND packet_ns IS NULL",
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
    assert!(late_seg.starts_with(&format!("{late_id}.")) && late_seg.ends_with(".seg"));

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

    // The last file grows. It is given its old id again, and its new
    // segment a name of its own.
    grow("zz/late.bin", &mut late, 50);
    assert_eq!(file_id("zz/late.bin"), late_id);
    let second = segment_of("zz/late.bin");
    assert_ne!(second, late_seg);
    assert!(!folder.join(&late_seg).exists());
    assert_eq!(files_in(&folder), listed(&store));
    assert_eq!(count("zz/late.bin"), 350);
    check_records(&scratch, &store);

    // Again: the first name is free, and is not taken again, so that no
    // reader that listed it finds another segment under it.
    grow("zz/late.bin", &mut late, 1);
    assert_eq!(file_id("zz/late.bin"), late_id);
    let third = segment_of("zz/late.bin");
    assert!(third != late_seg && third != second, "{third}");
    assert_eq!(files_in(&folder), listed(&store));

    // A file in the middle grows: a new id, a new segment, the old one gone.
    grow("aa/early.bin", &mut early, 50);
    assert_ne!(segment_of("aa/early.bin"), early_seg);
    assert!(!folder.join(&early_seg).exists());
    assert_eq!(files_in(&folder), listed(&store));
    assert_eq!((count("aa/early.bin"), count("zz/late.bin")), (350, 351));
    check_items(&store);
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
    assert_eq!(
        ask(&store, "SELECT COUNT(*) FROM oracle_packets", vec![])[0][0],
        0
    );
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
    drop(Store::open_with_oracle(&scratch.db()).unwrap());
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

/// The old way of reading a plot: from the store's rows.
#[allow(clippy::too_many_arguments)]
fn series_from_sql(
    store: &Store,
    run: i64,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    from: i64,
    to: i64,
    buckets: i64,
) -> sql::Table {
    let q = match field {
        Some((packet, name)) => {
            oracle::value_series(run, clock, lane, packet, name, from, to, buckets)
        }
        None => oracle::lag_series(run, clock, lane, from, to, buckets),
    };
    store.query(&q, 4001).unwrap()
}

#[test]
#[ignore = "times item lists and plots; give it a store in SEG_TIMING_DB"]
fn reads_timing() {
    let db = PathBuf::from(std::env::var("SEG_TIMING_DB").unwrap());
    let store = Store::open_read_only(&db, Duration::from_secs(600)).unwrap();
    let run = ask(&store, "SELECT id FROM runs ORDER BY id", vec![])[0][0];
    let median = |f: &mut dyn FnMut() -> usize| -> (f64, usize) {
        let mut times = Vec::new();
        let mut n = 0;
        for _ in 0..7 {
            let started = Instant::now();
            n = f();
            times.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(f64::total_cmp);
        (times[3], n)
    };
    // The kept field with the most numbers on one lane, and the lane with
    // the most packets with both times.
    let r = store
        .query(
            &Query::new(
                "SELECT lane_id, packet, field, SUM(count) AS n FROM file_series
                 GROUP BY lane_id, packet, field ORDER BY n DESC LIMIT 1",
                vec![],
            ),
            1,
        )
        .unwrap();
    let (kept_lane, packet, field) = (
        r.rows[0][0].int().unwrap(),
        r.rows[0][1].text().unwrap().to_string(),
        r.rows[0][2].text().unwrap().to_string(),
    );
    let delay_lane = ask(
        &store,
        "SELECT id FROM lanes WHERE kind = 'packet' ORDER BY packet_count DESC LIMIT 1",
        vec![],
    )[0][0];
    for clock in Clock::ALL {
        let c = clock.packet_column();
        let r = ask(
            &store,
            &format!("SELECT MIN({c}), MAX({c}) FROM oracle_packets"),
            vec![],
        );
        let (min, max) = (r[0][0], r[0][1]);
        let span = max - min + 1;
        let window = |zoom: i64| {
            let width = span / zoom;
            let from = min + (span - width) / 2;
            (from, from + width - 1)
        };
        for zoom in [1i64, 100, 1000] {
            let (from, to) = window(zoom);
            let (seg, n) = median(&mut || {
                store
                    .packet_items(run, clock, from, to, 1000)
                    .unwrap()
                    .rows
                    .len()
            });
            let (old, m) = median(&mut || {
                store
                    .query(&oracle::packet_items(run, clock, from, to, 1001), 1000)
                    .unwrap()
                    .rows
                    .len()
            });
            assert_eq!(n, m);
            println!(
                "items {} 1/{zoom}: segments {seg:.2} ms, sql {old:.2} ms; {n} rows",
                clock.name()
            );
        }
        for (what, lane, key) in [
            ("kept", kept_lane, Some((packet.as_str(), field.as_str()))),
            ("delay", delay_lane, None),
        ] {
            for zoom in [1i64, 10, 100, 1000] {
                let (from, to) = window(zoom);
                let (seg, n) = median(&mut || {
                    let t = store.series(run, clock, lane, key, from, to, 1000).unwrap();
                    t.rows.iter().map(|r| r[3].int().unwrap() as usize).sum()
                });
                let (old, m) = median(&mut || {
                    let t = series_from_sql(&store, run, clock, lane, key, from, to, 1000);
                    t.rows.iter().map(|r| r[3].int().unwrap() as usize).sum()
                });
                println!(
                    "plot {what} {} 1/{zoom}: segments {seg:.2} ms, sql {old:.2} ms; {n} values (sql {m})",
                    clock.name()
                );
            }
        }
    }
}
