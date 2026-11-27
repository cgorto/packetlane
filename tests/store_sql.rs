//! Two things about the store's SQL that no answer on a small run shows:
//! which index SQLite uses for it, and that the statements which read all
//! packets in one pass give what asking lane by lane gave.
//!
//! A new index can make an existing query slow without changing a single
//! answer, because SQLite may prefer it. The load tests show that as
//! seconds lost. Here it shows at once, on a small store: the store never
//! runs ANALYZE, so SQLite chooses the same plan at any size.
//!
//! The plans are compared as SQLite words them. SQLite is built in with
//! rusqlite, so the wording changes only when that dependency does; if
//! these tests fail after such a change and the same indexes are still
//! named, it is the wording, and the expected text here is what to update.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use packetlane::pure::sql::{self, Clock, Param, Query};
use packetlane::pure::synth::{demo_run, packet};
use packetlane::shell::ingest::ingest_targets;
use packetlane::shell::store::Store;
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, params_from_iter};

/// A store holding one run, in a folder removed when the test ends.
struct Stored {
    dir: PathBuf,
    conn: Connection,
}

impl Drop for Stored {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Ingests the files, given as (path within the run, bytes).
fn stored(files: &[(String, Vec<u8>)]) -> Stored {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "packetlane-sql-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let run = dir.join("run");
    for (rel, bytes) in files {
        let path = run.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let db = dir.join("store.db");
    ingest(&db, &run);
    let conn = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    Stored { dir, conn }
}

fn ingest(db: &Path, run: &Path) {
    let run = std::fs::canonicalize(run).unwrap();
    let mut store = Store::open(db).unwrap();
    ingest_targets(&mut store, &[run], None, None, None).unwrap();
}

fn demo() -> Stored {
    let files: Vec<(String, Vec<u8>)> = demo_run(120)
        .into_iter()
        .map(|f| (f.rel.to_string(), f.bytes))
        .collect();
    stored(&files)
}

fn bound(q: &Query) -> impl Iterator<Item = Value> + '_ {
    q.params.iter().map(|p| match p {
        Param::Null => Value::Null,
        Param::Int(v) => Value::Integer(*v),
        Param::Text(v) => Value::Text(v.clone()),
    })
}

/// Every row of the answer, each cell as text.
fn rows(conn: &Connection, q: &Query) -> Vec<Vec<String>> {
    let mut stmt = conn.prepare(&q.sql).unwrap();
    let n = stmt.column_count();
    stmt.query_map(params_from_iter(bound(q)), |row| {
        (0..n)
            .map(|i| {
                row.get::<_, Value>(i).map(|v| match v {
                    Value::Null => "null".to_string(),
                    Value::Integer(i) => i.to_string(),
                    Value::Real(f) => f.to_string(),
                    Value::Text(t) => t,
                    Value::Blob(_) => "blob".to_string(),
                })
            })
            .collect()
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

/// The steps of SQLite's plan for the query.
fn plan(conn: &Connection, q: &Query) -> Vec<String> {
    let explain = Query {
        sql: format!("EXPLAIN QUERY PLAN {}", q.sql),
        params: q.params.clone(),
    };
    rows(conn, &explain)
        .into_iter()
        .map(|r| r[3].clone())
        .collect()
}

/// The one step of the plan that reads the table, by name or alias.
fn step<'a>(plan: &'a [String], table: &str) -> &'a str {
    let found: Vec<&String> = plan
        .iter()
        .filter(|s| s.split_whitespace().nth(1) == Some(table))
        .collect();
    assert_eq!(found.len(), 1, "steps reading {table} in {plan:#?}");
    found[0]
}

// ---- plans ------------------------------------------------------------------

/// A view of every lane must find its packets by time, so that what it
/// costs follows the width of the view and not the size of the run.
#[test]
fn views_of_every_lane_find_their_packets_by_time() {
    let store = demo();
    let (from, to) = (1_767_225_600_000_000_000, 1_767_225_700_000_000_000);
    for (clock, index) in [
        (
            Clock::Receive,
            "packets_receive (receive_ns>? AND receive_ns<?)",
        ),
        (
            Clock::Packet,
            "packets_packet (packet_ns>? AND packet_ns<?)",
        ),
        (Clock::Order, "INTEGER PRIMARY KEY (rowid>? AND rowid<?)"),
    ] {
        let mut queries = vec![
            ("items", sql::packet_items(1, clock, from, to, 2000)),
            ("density", sql::packet_density(1, clock, from, to, 400)),
        ];
        // With pre-counted buckets, the two ends of the window are still
        // counted from the packets.
        let before = queries.len();
        for q in sql::density(1, clock, from + 7, to + 7, 400, Some((from, 1_000_000_000))) {
            if q.sql.contains("FROM packets") {
                queries.push(("density, ends", q));
            }
        }
        assert!(queries.len() > before, "no end of the window was counted");
        for (name, q) in &queries {
            let plan = plan(&store.conn, q);
            let step = step(&plan, "packets");
            assert!(
                step.starts_with("SEARCH") && step.ends_with(index),
                "{name}: {step}"
            );
            // In time order as found: nothing is sorted afterwards.
            assert!(
                !plan.iter().any(|s| s.contains("ORDER BY")),
                "{name}: {plan:#?}"
            );
        }
    }
}

/// A plot of one lane must find that lane's packets by time, so that what
/// it costs follows that lane and not everything logged alongside it.
#[test]
fn plots_find_one_lanes_packets_by_time() {
    let store = demo();
    let (from, to) = (1_767_225_600_000_000_000, 1_767_225_700_000_000_000);
    for (clock, index) in [
        (
            Clock::Receive,
            "packets_lane_receive (lane_id=? AND receive_ns>? AND receive_ns<?)",
        ),
        (
            Clock::Packet,
            "packets_lane_packet (lane_id=? AND packet_ns>? AND packet_ns<?)",
        ),
    ] {
        // Arrival delay is answered from the index alone.
        let plan_of = plan(&store.conn, &sql::lag_series(1, clock, 2, from, to, 1200));
        assert_eq!(
            step(&plan_of, "packets"),
            format!("SEARCH packets USING COVERING INDEX {index}")
        );
        // A value plot finds the packets that way, then looks each one's
        // values up by packet, not by field.
        let q = sql::value_series(1, clock, 2, "SIM_HK", "BUS_VOLTS", from, to, 1200);
        let plan_of = plan(&store.conn, &q);
        assert_eq!(
            step(&plan_of, "p"),
            format!("SEARCH p USING COVERING INDEX {index}")
        );
        assert_eq!(
            step(&plan_of, "v"),
            "SEARCH v USING INDEX field_values_packet (packet_id=?)"
        );
    }
    // On the order clock a window is a range of ids, which is the table's
    // own order. The lane-first indexes do not hold ids in order, and
    // taking one would read the whole lane for any window.
    let by_id = "USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)";
    let plan_of = plan(
        &store.conn,
        &sql::lag_series(1, Clock::Order, 2, 10, 500, 100),
    );
    assert_eq!(step(&plan_of, "packets"), format!("SEARCH packets {by_id}"));
    let q = sql::value_series(1, Clock::Order, 2, "SIM_HK", "BUS_VOLTS", 10, 500, 100);
    assert_eq!(
        step(&plan(&store.conn, &q), "p"),
        format!("SEARCH p {by_id}")
    );
}

/// Makes the temporary table the comparison of sources reads, as an
/// ingest does, on this connection.
fn stage(conn: &Connection, run: i64) {
    conn.execute_batch(sql::HOP_UNSTAGE).unwrap();
    for q in sql::hop_stage(run) {
        conn.execute(&q.sql, params_from_iter(bound(&q))).unwrap();
    }
}

/// The comparison of sources reads the run's packets once to copy them, by
/// their files' id ranges, then the copy twice, whatever the number of
/// streams, and answers "is this packet in that lane" from an index.
#[test]
fn sources_are_compared_in_two_passes_over_the_packets() {
    let store = demo();
    // Copying: each file's packets by id, and no other index.
    let copy = &sql::hop_stage(1)[1];
    stage(&store.conn, 1);
    store.conn.execute_batch("DELETE FROM temp.hop").unwrap();
    let steps = plan(&store.conn, copy);
    assert_eq!(
        step(&steps, "p"),
        "SEARCH p USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)",
        "{steps:#?}"
    );
    // Comparing.
    let steps = plan(&store.conn, &sql::hop_compare_all(1));
    let scans: Vec<&String> = steps.iter().filter(|s| s.starts_with("SCAN")).collect();
    // The copy is kept in checksum order, so reading it from end to end
    // makes each lookup below land beside the last.
    assert_eq!(scans, ["SCAN p"; 2], "{steps:#?}");
    let lookups = steps
        .iter()
        .filter(|s| s.ends_with("USING PRIMARY KEY (sum=? AND lane_id=?)"))
        .count();
    assert_eq!(lookups, 2, "{steps:#?}");
    // Tracing an interleaved stream reads that lane's packets by lane, and
    // asks the same index about each.
    let steps = plan(&store.conn, &sql::lane_origins(1, 2, 100, 0));
    let reads: Vec<&String> = steps
        .iter()
        .filter(|s| s.split_whitespace().nth(1) == Some("p"))
        .collect();
    assert!(
        !reads.is_empty()
            && reads
                .iter()
                .all(|s| *s == "SEARCH p USING INDEX packets_lane_receive (lane_id=?)"),
        "{steps:#?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| s.ends_with("USING PRIMARY KEY (sum=? AND lane_id=?)")),
        "{steps:#?}"
    );
}

// ---- one pass against lane by lane --------------------------------------------

/// How lane `a` compares with lane `b`, asked for one pair: what
/// `hop_compare_all` replaced, kept here to check it against.
const ONE_PAIR: &str = "WITH m AS MATERIALIZED (
       SELECT p.id AS id,
              EXISTS (SELECT 1 FROM packets q
                      WHERE q.sum = p.sum AND q.lane_id = ?1) AS hit
       FROM packets p WHERE p.lane_id = ?2),
     w AS (SELECT MIN(id) AS lo, MAX(id) AS hi FROM m WHERE hit = 1)
     SELECT (SELECT COUNT(*) FROM m WHERE hit = 1),
            (SELECT COUNT(*) FROM m, w WHERE hit = 0 AND id BETWEEN w.lo AND w.hi),
            (SELECT MIN(id) FROM m, w WHERE hit = 0 AND id BETWEEN w.lo AND w.hi)";

/// One lane's count and ranges, asked for one lane: what the one-pass
/// refresh replaced.
const ONE_LANE: &str = "SELECT COUNT(*), MIN(receive_ns), MAX(receive_ns), COUNT(receive_ns),
            MIN(packet_ns), MAX(packet_ns), COUNT(packet_ns), MIN(id), MAX(id)
     FROM packets WHERE lane_id = ?1";

/// Checks every pair of the run against [`ONE_PAIR`]. Returns the pairs
/// that have something missing, as (source a, source b, apid, shared,
/// missing).
fn check_pairs(conn: &Connection) -> Vec<(String, String, i64, i64, i64)> {
    check_pairs_of(conn, 1)
}

/// The same for any run of the store.
fn check_pairs_of(conn: &Connection, run: i64) -> Vec<(String, String, i64, i64, i64)> {
    stage(conn, run);
    let all = rows(conn, &sql::hop_compare_all(run));
    let pairs = rows(conn, &sql::lane_pairs(run));
    assert!(!pairs.is_empty());
    let mut with_missing = Vec::new();
    for pair in &pairs {
        let (a, b) = (&pair[0], &pair[2]);
        let old = rows(
            conn,
            &Query {
                sql: ONE_PAIR.to_string(),
                params: vec![
                    b.parse::<i64>().unwrap().into(),
                    a.parse::<i64>().unwrap().into(),
                ],
            },
        );
        let old = &old[0];
        let new: Vec<&Vec<String>> = all.iter().filter(|r| &r[0] == a && &r[1] == b).collect();
        let (shared, missing): (i64, i64) = (old[0].parse().unwrap(), old[1].parse().unwrap());
        if shared > 0 && missing > 0 {
            assert_eq!(new.len(), 1, "pair {a} {b}");
            assert_eq!(&new[0][2..], &old[..], "pair {a} {b}");
            with_missing.push((
                pair[1].clone(),
                pair[3].clone(),
                pair[4].parse().unwrap(),
                shared,
                missing,
            ));
        } else {
            // Nothing to report for the pair, and the one pass says nothing.
            assert!(
                new.is_empty(),
                "pair {a} {b}: {new:?}, lane by lane {old:?}"
            );
        }
    }
    assert_eq!(all.len(), with_missing.len());
    with_missing
}

/// Checks the stored count and ranges of every packet lane against
/// [`ONE_LANE`]. Returns how many lanes there were.
fn check_lanes(conn: &Connection) -> usize {
    let stored = rows(
        conn,
        &Query {
            sql: "SELECT id, count, receive_min, receive_max, receive_count,
                         packet_min, packet_max, packet_count, order_min, order_max
                  FROM lanes WHERE kind != 'log' ORDER BY id"
                .to_string(),
            params: vec![],
        },
    );
    for lane in &stored {
        let direct = rows(
            conn,
            &Query {
                sql: ONE_LANE.to_string(),
                params: vec![lane[0].parse::<i64>().unwrap().into()],
            },
        );
        assert_eq!(&lane[1..], &direct[0][..], "lane {}", lane[0]);
    }
    stored.len()
}

/// Three sources logging the same streams, with everything that could make
/// one pass differ from lane by lane.
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

#[test]
fn one_pass_gives_what_lane_by_lane_gave() {
    let store = stored(&awkward_run());
    assert_eq!(check_lanes(&store.conn), 8);
    let mut missing = check_pairs(&store.conn);
    missing.sort();
    assert_eq!(
        missing,
        [
            // Of a's 41 packets on APID 10, b has 32 (the one a holds twice
            // counts twice); 10, 11 and 30 are missing within what they
            // share, and those before and after are not counted.
            ("a".to_string(), "b".to_string(), 10, 32, 3),
            // Of c's 20 on APID 13, a has 9; 9 is missing between them.
            ("c".to_string(), "a".to_string(), 13, 9, 1),
        ]
    );

    let demo = demo();
    assert!(check_lanes(&demo.conn) > 3);
    assert!(!check_pairs(&demo.conn).is_empty());
}

/// A lane keeps its row when its file is read again and no longer holds
/// the stream; its count must go to nothing.
#[test]
fn a_lane_left_without_packets_reads_as_empty() {
    let store = stored(&awkward_run());
    let run = store.dir.join("run");
    // The file from c again, now with one stream of its two.
    let only: Vec<u8> = (0..40u16)
        .flat_map(|seq| packet(10, seq, &[seq as u8, 9, 9]))
        .collect();
    std::fs::write(run.join("c/tlm.bin"), only).unwrap();
    ingest(&store.dir.join("store.db"), &run);
    assert_eq!(check_lanes(&store.conn), 8);
    let empty = rows(
        &store.conn,
        &Query {
            sql: "SELECT COUNT(*) FROM lanes WHERE source = 'c' AND apid = 13 AND count = 0
                  AND receive_count = 0 AND order_min IS NULL"
                .to_string(),
            params: vec![],
        },
    );
    assert_eq!(empty[0][0], "1");
}

// ---- the list of what a run has to plot ----------------------------------------

/// What a run has to plot, counted from every stored value: what the
/// per-file counts replaced.
const SERIES_FROM_VALUES: &str = "SELECT p.lane_id, v.packet, v.field, COUNT(*)
     FROM field_values v JOIN packets p ON p.id = v.packet_id
     WHERE v.num IS NOT NULL AND v.file_id IN (SELECT id FROM files WHERE run_id = 1)
     GROUP BY p.lane_id, v.packet, v.field
     ORDER BY p.lane_id, v.packet, v.field";

/// Checks the list against the stored values. Returns how long it is.
fn check_series(conn: &Connection) -> usize {
    let counted = rows(conn, &sql::run_series(1));
    let from_values = rows(
        conn,
        &Query {
            sql: SERIES_FROM_VALUES.to_string(),
            params: vec![],
        },
    );
    assert_eq!(counted, from_values);
    // And nothing is left behind from a file that was read again.
    let left = rows(
        conn,
        &Query {
            sql: "SELECT COUNT(*) FROM file_series WHERE file_id NOT IN (SELECT id FROM files)"
                .to_string(),
            params: vec![],
        },
    );
    assert_eq!(left[0][0], "0");
    counted.len()
}

/// The list is kept as files are read, so it has to follow every way a
/// file's values can change.
#[test]
fn the_list_of_kept_fields_follows_the_stored_values() {
    let files: Vec<(String, Vec<u8>)> = demo_run(120)
        .into_iter()
        .map(|f| (f.rel.to_string(), f.bytes))
        .collect();
    let store = stored(&files);
    let run = store.dir.join("run");
    let db = store.dir.join("store.db");
    let whole = check_series(&store.conn);
    assert!(whole >= 2, "the demo keeps two fields");

    // A file that holds kept values, read again with a third of it left.
    let one = |sql: &str| {
        rows(
            &store.conn,
            &Query {
                sql: sql.to_string(),
                params: vec![],
            },
        )[0][0]
            .clone()
    };
    let rel = one(
        "SELECT f.rel FROM file_series s JOIN files f ON f.id = s.file_id
         ORDER BY s.count DESC LIMIT 1",
    );
    let total = "SELECT SUM(count) FROM file_series";
    let before: i64 = one(total).parse().unwrap();
    let bytes = &files.iter().find(|(r, _)| *r == rel).unwrap().1;
    std::fs::write(run.join(&rel), &bytes[..bytes.len() / 3]).unwrap();
    ingest(&db, &run);
    assert!(check_series(&store.conn) > 0);
    let after: i64 = one(total).parse().unwrap();
    assert!(after > 0 && after < before, "{after} of {before}");

    // The configuration changed, so the whole run is read again: one field
    // is no longer kept.
    let config = run.join("packetlane.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let at = text.find("keep = true").expect("a kept field");
    let fewer = format!("{}keep = false{}", &text[..at], &text[at + 11..]);
    std::fs::write(&config, fewer).unwrap();
    ingest(&db, &run);
    let after = check_series(&store.conn);
    assert!(after > 0 && after < whole, "{after} of {whole}");
}

// ---- stored series buckets -------------------------------------------------------

use packetlane::pure::sql::{Cell, Table};

/// The answer to a statement, as the store gives it.
fn table(conn: &Connection, q: &Query) -> Table {
    let mut stmt = conn.prepare(&q.sql).unwrap();
    let n = stmt.column_count();
    let rows = stmt
        .query_map(params_from_iter(bound(q)), |row| {
            (0..n)
                .map(|i| {
                    row.get::<_, Value>(i).map(|v| match v {
                        Value::Integer(i) => Cell::Int(i),
                        Value::Real(f) => Cell::Real(f),
                        Value::Text(t) => Cell::Text(t),
                        _ => Cell::Null,
                    })
                })
                .collect()
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    Table {
        columns: Vec::new(),
        rows,
        truncated: false,
    }
}

/// A series over a window as the server works it out: bucket, min, max,
/// count. `stored` says whether to use the stored buckets.
#[allow(clippy::too_many_arguments)]
fn series_rows(
    conn: &Connection,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    from: i64,
    to: i64,
    buckets: i64,
    stored: Option<(i64, i64)>,
) -> (usize, Vec<(i64, f64, f64, i64)>) {
    let queries = sql::series(1, clock, lane, field, from, to, buckets, stored);
    let parts: Vec<Table> = queries.iter().map(|q| table(conn, q)).collect();
    let parts: Vec<&Table> = parts.iter().collect();
    let real = |c: &Cell| match c {
        Cell::Real(v) => *v,
        Cell::Int(v) => *v as f64,
        other => panic!("{other:?}"),
    };
    let rows = sql::merge_series(&parts)
        .rows
        .iter()
        .map(|r| {
            (
                r[0].int().unwrap(),
                real(&r[1]),
                real(&r[2]),
                r[3].int().unwrap(),
            )
        })
        .collect();
    (queries.len(), rows)
}

/// Count, lowest and highest over all buckets.
fn totals(rows: &[(i64, f64, f64, i64)]) -> (i64, f64, f64) {
    rows.iter()
        .fold((0, f64::INFINITY, f64::NEG_INFINITY), |(n, lo, hi), r| {
            (n + r.3, lo.min(r.1), hi.max(r.2))
        })
}

/// The demo's lanes are far too short to be given stored buckets, so this
/// builds them for every lane, as an ingest does for long ones, and checks
/// them against reading the packets.
#[test]
fn stored_buckets_give_what_reading_the_packets_gives() {
    let store = demo();
    // An ordinary ingest stored none.
    let none = rows(
        &store.conn,
        &Query {
            sql: "SELECT COUNT(*) FROM coarse_series".to_string(),
            params: vec![],
        },
    );
    assert_eq!(none[0][0], "0");

    let writer = Connection::open(store.dir.join("store.db")).unwrap();
    let lane: i64 = writer
        .query_row(
            "SELECT lane_id FROM file_series WHERE packet = 'SIM_HK' AND field = 'BUS_VOLTS'
             ORDER BY count DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for clock in [Clock::Receive, Clock::Packet] {
        let meta = table(&store.conn, &sql::coarse_meta(1, clock));
        let (origin, real_width) = (
            meta.rows[0][0].int().unwrap(),
            meta.rows[0][1].int().unwrap(),
        );
        // Two minutes of data would put one packet in a bucket. Buckets
        // 512 times as wide, 32 across the run, hold several each, as a
        // long run's do.
        let coarse_width = real_width * 512;
        for q in sql::build_coarse_series(1, clock, origin, coarse_width, 1) {
            writer.execute(&q.sql, params_from_iter(bound(&q))).unwrap();
        }
        let stored = Some((origin, coarse_width));
        let width = sql::series_width(coarse_width);
        let span = real_width * sql::COARSE_BUCKETS;

        for field in [Some(("SIM_HK", "BUS_VOLTS")), None] {
            let has = table(&store.conn, &sql::has_coarse_series(lane, clock, field));
            assert_eq!(has.rows.len(), 1, "{field:?}");
            let ask = |from: i64, to: i64, buckets: i64, stored| {
                series_rows(&store.conn, clock, lane, field, from, to, buckets, stored)
            };

            // Buckets that line up with the stored ones: the same answer,
            // bucket for bucket, from one statement.
            let (from, buckets) = (origin + 2 * width, 5);
            let to = from + 2 * width * buckets - 1;
            let (statements, from_stored) = ask(from, to, buckets, stored);
            let (_, direct) = ask(from, to, buckets, None);
            assert_eq!(statements, 1);
            assert_eq!(direct.len(), 5, "{direct:?}");
            assert!(direct.iter().all(|r| r.3 > 1), "{direct:?}");
            assert_eq!(from_stored, direct, "{clock:?} {field:?}");

            // Any other window wide enough: the ends are read directly, and
            // nothing is lost or counted twice. A stored bucket may land
            // one requested bucket early, never further.
            for (from, to, buckets) in [
                (origin - span / 7, origin + span + span / 5, 20),
                (origin + span / 3 + 12_345, origin + span - 999, 12),
                (origin + 1, origin + span / 2, 8),
            ] {
                let (statements, from_stored) = ask(from, to, buckets, stored);
                let (_, direct) = ask(from, to, buckets, None);
                assert!(statements > 1, "{from} {to}");
                assert_eq!(totals(&from_stored), totals(&direct), "{from} {to}");
                let last = direct.last().unwrap().0;
                assert!(from_stored.iter().all(|r| (0..=last).contains(&r.0)));
            }

            // A window whose buckets are narrower than the stored ones, even
            // by a nanosecond, is read directly.
            assert_eq!(ask(origin, origin + width * 10 - 11, 10, stored).0, 1);
            assert!(ask(origin, origin + width * 10 - 1, 10, stored).0 >= 1);
            let (statements, narrow) = ask(origin, origin + span / 20, 4000, stored);
            assert_eq!(statements, 1);
            assert_eq!(narrow, ask(origin, origin + span / 20, 4000, None).1);
        }

        // The stored part is found by its key.
        let q = &sql::series(1, clock, lane, None, origin, origin + span, 10, stored)[0];
        let steps = plan(&store.conn, q);
        assert!(
            step(&steps, "coarse_series").starts_with("SEARCH coarse_series USING PRIMARY KEY"),
            "{steps:#?}"
        );
    }
    // The order clock has no stored buckets.
    assert!(sql::build_coarse_series(1, Clock::Order, 0, 100, 1).is_empty());
}

// ---- what was read from a file is found by its packet ids -------------------------

/// Every file's row says which packets are its own, and nothing is left in
/// the store from a file that is gone or was read again.
fn check_files(conn: &Connection) {
    let one = |sql: &str| {
        rows(
            conn,
            &Query {
                sql: sql.to_string(),
                params: vec![],
            },
        )
    };
    let wrong = one(
        "SELECT f.rel, f.packets, f.first_packet, f.last_packet, s.n, s.lo, s.hi
         FROM files f
         LEFT JOIN (SELECT file_id, COUNT(*) AS n, MIN(id) AS lo, MAX(id) AS hi
                    FROM packets GROUP BY file_id) s ON s.file_id = f.id
         WHERE f.packets != COALESCE(s.n, 0)
            OR f.first_packet IS NOT s.lo OR f.last_packet IS NOT s.hi",
    );
    assert!(wrong.is_empty(), "{wrong:?}");
    for (what, sql) in [
        (
            "packets of no file",
            "SELECT COUNT(*) FROM packets WHERE file_id NOT IN (SELECT id FROM files)",
        ),
        (
            "values of no packet",
            "SELECT COUNT(*) FROM field_values WHERE packet_id NOT IN (SELECT id FROM packets)",
        ),
        (
            "values of another file's packet",
            "SELECT COUNT(*) FROM field_values v JOIN packets p ON p.id = v.packet_id
             WHERE p.file_id != v.file_id",
        ),
    ] {
        assert_eq!(one(sql)[0][0], "0", "{what}");
    }
}

/// Writes a second run beside the first and ingests it into the same store.
fn add_run(store: &Stored, name: &str, files: &[(String, Vec<u8>)]) -> PathBuf {
    let run = store.dir.join(name);
    for (rel, bytes) in files {
        let path = run.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    ingest(&store.dir.join("store.db"), &run);
    run
}

/// Two runs in one store: reading a file of one again, and reading the
/// whole of it again, must take away exactly that run's rows.
#[test]
fn a_file_read_again_takes_only_its_own_rows_with_it() {
    let demo_files: Vec<(String, Vec<u8>)> = demo_run(120)
        .into_iter()
        .map(|f| (f.rel.to_string(), f.bytes))
        .collect();
    let store = stored(&demo_files);
    let first = store.dir.join("run");
    let db = store.dir.join("store.db");
    add_run(&store, "second", &awkward_run());
    check_files(&store.conn);
    let count = |run: i64| -> i64 {
        rows(
            &store.conn,
            &Query {
                sql: "SELECT COUNT(*) FROM packets WHERE file_id IN
                      (SELECT id FROM files WHERE run_id = ?)"
                    .to_string(),
                params: vec![run.into()],
            },
        )[0][0]
            .parse()
            .unwrap()
    };
    let (one, two) = (count(1), count(2));
    assert!(one > 0 && two > 0);

    // The first run's largest packet file, cut to a third: not the last
    // file read, so its ids lie in the middle of the table.
    let (rel, bytes) = demo_files
        .iter()
        .filter(|(rel, _)| rel.ends_with(".bin"))
        .max_by_key(|(_, bytes)| bytes.len())
        .unwrap();
    std::fs::write(first.join(rel), &bytes[..bytes.len() / 3]).unwrap();
    ingest(&db, &first);
    check_files(&store.conn);
    let fewer = count(1);
    assert!(fewer > 0 && fewer < one, "{fewer} of {one}");
    assert_eq!(count(2), two);
    // Both runs still compare and count as lane by lane would, each from
    // its own packets only.
    check_lanes(&store.conn);
    check_pairs_of(&store.conn, 1);
    assert_eq!(check_pairs_of(&store.conn, 2).len(), 2);

    // The first run's configuration changes, so all of it is read again.
    let config = first.join("packetlane.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("{text}\n# changed\n")).unwrap();
    ingest(&db, &first);
    check_files(&store.conn);
    assert_eq!(count(1), fewer);
    assert_eq!(count(2), two);
    check_lanes(&store.conn);

    // And the rows are found by id, not by reading every packet.
    for statement in sql::delete_file_packets() {
        let steps = plan(
            &store.conn,
            &Query {
                sql: statement.clone(),
                params: vec![1i64.into()],
            },
        );
        let table = if statement.contains("field_values") {
            "field_values"
        } else {
            "packets"
        };
        let step = step(&steps, table);
        assert!(
            step.starts_with("SEARCH") && (step.contains("rowid>") || step.contains("packet_id>")),
            "{statement}: {steps:#?}"
        );
    }
}

// ---- which sources hold copies of an interleaved stream -----------------------------

/// Which other sources hold copies of a lane's packets, asked of the
/// packets themselves: what the lookup in the temporary table replaced.
const ORIGINS_FROM_PACKETS: &str = "SELECT l.source,
            SUM((SELECT COUNT(*) FROM packets p
                 WHERE p.lane_id = ?1 AND EXISTS (
                   SELECT 1 FROM packets q
                   WHERE q.sum = p.sum AND q.lane_id = l.id
                     AND q.seq = p.seq AND q.length = p.length))) AS n
     FROM lanes l
     WHERE l.run_id = ?2 AND l.kind = 'packet' AND l.apid = ?3 AND l.ptype = ?4
       AND l.id != ?1
     GROUP BY l.source HAVING n > 0 ORDER BY l.source";

/// Checks the lookup for every interleaved stream of a run. Returns how
/// many sources were named in all.
fn check_origins(conn: &Connection, run: i64) -> usize {
    stage(conn, run);
    let mixed = rows(conn, &sql::lanes_with_finding(run, "interleaved"));
    assert!(!mixed.is_empty(), "no interleaved stream to trace");
    let mut named = 0;
    for row in &mixed {
        let n = |i: usize| row[i].parse::<i64>().unwrap();
        let (lane, apid, ptype) = (n(0), n(2), n(3));
        let staged = rows(conn, &sql::lane_origins(run, lane, apid, ptype));
        let direct = rows(
            conn,
            &Query {
                sql: ORIGINS_FROM_PACKETS.to_string(),
                params: vec![lane.into(), run.into(), apid.into(), ptype.into()],
            },
        );
        assert_eq!(staged, direct, "lane {lane}");
        named += staged.len();
    }
    named
}

#[test]
fn an_interleaved_stream_is_traced_as_the_packets_say() {
    // Two units send on one APID by mistake, each logging its own packets;
    // a collector logs both, so its copy has two counters running at once.
    let mut first = packetlane::pure::synth::Source::new(300, 9000, 8);
    let mut second = packetlane::pure::synth::Source::new(300, 12, 8);
    let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..40 {
        let packet = first.emit();
        a.extend(&packet);
        c.extend(&packet);
        if i >= 10 {
            let packet = second.emit();
            b.extend(&packet);
            c.extend(&packet);
        }
    }
    let store = stored(&[
        ("unit-a/a.bin".to_string(), a),
        ("unit-b/b.bin".to_string(), b),
        ("collector/c.bin".to_string(), c),
    ]);
    // Both units are named for the collector's stream.
    assert_eq!(check_origins(&store.conn, 1), 2);
    // With another run in the store, the answer is the same.
    add_run(&store, "second", &awkward_run());
    assert_eq!(check_origins(&store.conn, 1), 2);
}

// ---- lane totals from what each segment holds ---------------------------------------

/// How a run's packet lanes were counted from the `packets` rows before the
/// counts were kept per segment: the statements the store ran, kept here
/// to check the counts against.
const OLD_REFRESH_PACKET_LANES: [&str; 2] = [
    "UPDATE lanes SET
       (count, receive_min, receive_max, receive_count,
        packet_min, packet_max, packet_count, order_min, order_max) =
       (0, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL)
     WHERE run_id = ? AND kind != 'log'",
    "UPDATE lanes SET
       (count, receive_min, receive_max, receive_count,
        packet_min, packet_max, packet_count, order_min, order_max) =
       (s.n, s.r_min, s.r_max, s.r_n, s.p_min, s.p_max, s.p_n, s.o_min, s.o_max)
     FROM (SELECT lane_id, COUNT(*) AS n,
                  MIN(receive_ns) AS r_min, MAX(receive_ns) AS r_max, COUNT(receive_ns) AS r_n,
                  MIN(packet_ns) AS p_min, MAX(packet_ns) AS p_max, COUNT(packet_ns) AS p_n,
                  MIN(id) AS o_min, MAX(id) AS o_max
           FROM packets INDEXED BY packets_lane_receive
           WHERE lane_id IN (SELECT id FROM lanes WHERE run_id = ?1)
           GROUP BY lane_id) AS s
     WHERE lanes.id = s.lane_id AND lanes.run_id = ?1 AND lanes.kind != 'log'",
];

/// Every lane row of the store as the old statements would leave it, for
/// every run, against what is stored: the old statements run inside a
/// transaction that is rolled back. Returns how many packet lanes hold
/// packets.
fn lanes_match_the_old_counts(db: &Path) -> usize {
    let conn = Connection::open(db).unwrap();
    let all = || {
        rows(
            &conn,
            &Query::new(
                "SELECT id, run_id, source, kind, apid, ptype, file_id, count,
                        receive_min, receive_max, receive_count,
                        packet_min, packet_max, packet_count, order_min, order_max
                 FROM lanes ORDER BY id",
                vec![],
            ),
        )
    };
    let stored = all();
    conn.execute_batch("BEGIN").unwrap();
    let runs: Vec<i64> = conn
        .prepare("SELECT id FROM runs")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for run in runs {
        for statement in OLD_REFRESH_PACKET_LANES {
            conn.execute(statement, [run]).unwrap();
        }
    }
    let old = all();
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(stored, old);
    // And the next file's packets are numbered as when the next id was
    // asked of the packets, and every file's packets are where its row
    // says.
    let next = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(
        next(sql::NEXT_PACKET_ID),
        next("SELECT COALESCE(MAX(id), 0) + 1 FROM packets")
    );
    check_files(&conn);
    stored
        .iter()
        .filter(|r| r[3] != "log" && r[7] != "0")
        .count()
}

/// The lane counts follow every way a file's packets can change: read,
/// read again after growing, emptied, losing a stream, a changed
/// configuration, with another run in the store.
#[test]
fn lane_counts_are_what_the_packets_say() {
    let mut demo_files: Vec<(String, Vec<u8>)> = demo_run(120)
        .into_iter()
        .map(|f| (f.rel.to_string(), f.bytes))
        .collect();
    let (rel, bytes) = demo_files
        .iter()
        .filter(|(rel, _)| rel.ends_with(".bin"))
        .max_by_key(|(_, bytes)| bytes.len())
        .cloned()
        .unwrap();
    // Beside it, from the same source, its first third: its lanes are
    // then held by two segments each, over different spans.
    let early = rel.replace(".bin", "-early.bin");
    demo_files.push((early, bytes[..bytes.len() / 3].to_vec()));
    let store = stored(&awkward_run());
    let first = store.dir.join("run");
    let db = store.dir.join("store.db");
    assert_eq!(lanes_match_the_old_counts(&db), 8);
    let second = add_run(&store, "second", &demo_files);
    let both = lanes_match_the_old_counts(&db);
    assert!(both > 8);

    // A file of the first run grows: more of a stream, and a new one.
    let path = first.join("b/tlm.bin");
    let mut grown = std::fs::read(&path).unwrap();
    for seq in 40..60u16 {
        grown.extend(packet(10, seq, &[seq as u8, 1, 2]));
        grown.extend(packet(14, seq, &[seq as u8]));
    }
    std::fs::write(&path, grown).unwrap();
    ingest(&db, &first);
    assert_eq!(lanes_match_the_old_counts(&db), both + 1);

    // A file of the second run, cut short; then one emptied.
    std::fs::write(second.join(&rel), &bytes[..bytes.len() / 2]).unwrap();
    ingest(&db, &second);
    assert_eq!(lanes_match_the_old_counts(&db), both + 1);
    std::fs::write(first.join("c/tlm.bin"), b"").unwrap();
    ingest(&db, &first);
    // c held APIDs 10 and 13 alone.
    assert_eq!(lanes_match_the_old_counts(&db), both - 1);

    // c again, with one of its streams; then the configuration changes,
    // and the whole run is read again.
    let only: Vec<u8> = (0..40u16)
        .flat_map(|seq| packet(10, seq, &[seq as u8, 9, 9]))
        .collect();
    std::fs::write(first.join("c/tlm.bin"), only).unwrap();
    ingest(&db, &first);
    assert_eq!(lanes_match_the_old_counts(&db), both);
    std::fs::write(first.join("packetlane.toml"), "# changed\n").unwrap();
    ingest(&db, &first);
    assert_eq!(lanes_match_the_old_counts(&db), both);
}
