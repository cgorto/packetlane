//! Two things about the store's SQL that no answer on a small run shows:
//! which index SQLite uses for it, and that the statements which read all
//! packets in one pass give what asking lane by lane gave.
//!
//! A new index can make an existing query slow without changing a single
//! answer, because SQLite may prefer it. The load tests show that as
//! seconds lost. Here it shows at once, on a small store: the store never
//! runs ANALYZE, so SQLite chooses the same plan at any size.

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

/// Each view of the timeline must find its packets by time, so that what it
/// costs follows the width of the view and not the size of the run.
#[test]
fn views_of_the_timeline_find_their_packets_by_time() {
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
    ] {
        let mut queries = vec![
            (
                "items",
                "packets",
                sql::packet_items(1, clock, from, to, 2000),
            ),
            (
                "value plot",
                "p",
                sql::value_series(1, clock, 2, "SIM_HK", "BUS_VOLTS", from, to, 1200),
            ),
            (
                "delay plot",
                "packets",
                sql::lag_series(1, clock, 2, from, to, 1200),
            ),
            (
                "density",
                "packets",
                sql::packet_density(1, clock, from, to, 400),
            ),
        ];
        // With pre-counted buckets, the two ends of the window are still
        // counted from the packets.
        for q in sql::density(1, clock, from + 7, to + 7, 400, Some((from, 1_000_000_000))) {
            if q.sql.contains("FROM packets") {
                queries.push(("density, ends", "packets", q));
            }
        }
        for (name, table, q) in &queries {
            let plan = plan(&store.conn, q);
            let step = step(&plan, table);
            assert!(
                step.starts_with("SEARCH") && step.ends_with(index),
                "{name}: {step}"
            );
        }
    }
    // And a plot looks its values up by packet, not by field.
    let q = sql::value_series(1, Clock::Receive, 2, "SIM_HK", "BUS_VOLTS", from, to, 1200);
    let plan = plan(&store.conn, &q);
    assert_eq!(
        step(&plan, "v"),
        "SEARCH v USING INDEX field_values_packet (packet_id=?)"
    );
}

/// The comparison of sources reads the packets twice, whatever the number
/// of streams, and answers "is this packet in that lane" from an index.
#[test]
fn sources_are_compared_in_two_passes_over_the_packets() {
    let store = demo();
    let plan = plan(&store.conn, &sql::hop_compare_all(1));
    let scans: Vec<&String> = plan.iter().filter(|s| s.starts_with("SCAN")).collect();
    assert_eq!(
        scans, ["SCAN p USING COVERING INDEX packets_sum"; 2],
        "{plan:#?}"
    );
    let lookups = plan
        .iter()
        .filter(|s| s.ends_with("USING COVERING INDEX packets_sum (sum=? AND lane_id=?)"))
        .count();
    assert_eq!(lookups, 2, "{plan:#?}");
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
    let all = rows(conn, &sql::hop_compare_all(1));
    let pairs = rows(conn, &sql::lane_pairs(1));
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
