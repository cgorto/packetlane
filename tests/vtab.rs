//! The tables `packets` and `field_values`, which are served from the
//! segment files, against the oracle tables a store opened for tests also
//! writes (`pure::oracle`): the same SQL over either gives the same rows.
//! Also what the tables must refuse or stop: writes, a statement past its
//! time, a segment that is gone.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetlane::pure::sql::{Cell, Query, Table};
use packetlane::pure::synth::{Source, cosmos4_entry, cosmos4_header, demo_run, timed_packet};
use packetlane::shell::ingest::ingest_targets;
use packetlane::shell::store::Store;

/// A scratch folder that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "packetlane-vtab-{}-{}",
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

    fn write(&self, rel: &str, bytes: &[u8]) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
    }

    fn ingest(&self, run: &str) {
        let run = fs::canonicalize(self.0.join(run)).unwrap();
        let mut store = Store::open_with_oracle(&self.db()).unwrap();
        ingest_targets(&mut store, &[run], None, None, None).unwrap();
    }

    fn reader(&self) -> Store {
        Store::open_read_only(&self.db(), Duration::from_secs(60)).unwrap()
    }

    fn root(&self, run: &str) -> String {
        self.0.join(run).to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Kept fields of every kind: numbers, text only, a number with a label
/// as text, arrays, floats that are sometimes not a number.
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

const T0: i64 = 1_767_225_600_000_000_000;

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

/// Run `a`: a dense file, a sparse one from another source, and plain
/// packets with no time and no label; run `b`: the demo run. Then a file
/// of run `a` is read again, shorter.
fn stored() -> Scratch {
    let s = Scratch::new();
    s.write("a/packetlane.toml", KEPT_CONFIG.as_bytes());
    let mut dense = cosmos4_header(true, "kept", "bench");
    for i in 0..6_000u32 {
        let r = T0 + i64::from(i) * 300_000;
        let apid = if i % 100 == 50 { 18 } else { 16 };
        // Some packets share a receive time, so that ties are ordered by id.
        let r = if i % 10 == 3 { r - 300_000 } else { r };
        dense.extend(kept_entry(
            apid,
            i,
            r,
            r - 40_000_000 - i64::from(i % 13) * 1_000,
        ));
    }
    s.write("a/bench/dense.bin", &dense);
    let sparse = |n: u32| {
        let mut out = cosmos4_header(true, "kept", "other");
        for i in 0..n {
            let r = T0 + i64::from(i) * 10_000_000 + 3;
            out.extend(kept_entry(16, i, r, r - 1_000_000 * i64::from(i % 50)));
        }
        out
    };
    s.write("a/other/sparse.bin", &sparse(300));
    let mut tiny = Source::new(17, 0, 2);
    let bytes: Vec<u8> = (0..50).flat_map(|_| tiny.emit()).collect();
    s.write("a/raw/tiny.bin", &bytes);
    for file in demo_run(30) {
        s.write(&format!("b/{}", file.rel), &file.bytes);
    }
    s.ingest("a");
    s.ingest("b");
    // Read again, shorter: its rows go, and its new ones take new ids.
    s.write("a/other/sparse.bin", &sparse(200));
    s.ingest("a");
    s
}

/// The statement for the segment-backed tables and for the oracle ones.
fn both(sql: &str) -> (String, String) {
    let mut ours = sql.to_string();
    let mut oracle = sql.to_string();
    for (key, table) in [
        ("{PV}", "packet_view"),
        ("{VV}", "value_view"),
        ("{P}", "packets"),
        ("{V}", "field_values"),
    ] {
        ours = ours.replace(key, table);
        oracle = oracle.replace(key, &format!("oracle_{table}"));
    }
    (ours, oracle)
}

fn same_cell(a: &Cell, b: &Cell) -> bool {
    match (a, b) {
        (Cell::Real(x), Cell::Real(y)) => {
            x == y || (x - y).abs() <= 1e-9 * x.abs().max(y.abs()) || (x.is_nan() && y.is_nan())
        }
        _ => a == b,
    }
}

fn same_rows(a: &[Vec<Cell>], b: &[Vec<Cell>]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_cell(p, q)))
}

fn sorted(t: &Table) -> Vec<Vec<Cell>> {
    let mut rows = t.rows.clone();
    rows.sort_by_key(|r| format!("{r:?}"));
    rows
}

/// Runs the statement over both, and fails unless the rows agree: in
/// order if it orders them, as a set otherwise. Returns how many rows.
fn compare(reader: &Store, sql: &str) -> usize {
    let (ours, oracle) = both(sql);
    let want = reader
        .query_user(&oracle, 1_000_000)
        .unwrap_or_else(|e| panic!("oracle: {e}\n{oracle}"));
    let got = reader
        .query_user(&ours, 1_000_000)
        .unwrap_or_else(|e| panic!("{e}\n{ours}"));
    let ordered = sql.to_ascii_lowercase().contains("order by");
    let agree = if ordered {
        same_rows(&got.rows, &want.rows)
    } else {
        same_rows(&sorted(&got), &sorted(&want))
    };
    if !agree {
        let n = got.rows.len().max(want.rows.len());
        let at = (0..n)
            .find(|&i| match (got.rows.get(i), want.rows.get(i)) {
                (Some(a), Some(b)) => !same_rows(std::slice::from_ref(a), std::slice::from_ref(b)),
                _ => true,
            })
            .unwrap_or(0);
        panic!(
            "{ours}\n{} rows, oracle {}; first difference at {at}:\n  {:?}\n  oracle {:?}",
            got.rows.len(),
            want.rows.len(),
            got.rows.get(at),
            want.rows.get(at)
        );
    }
    want.rows.len()
}

/// The statement the page's query builder writes (see `buildSql` in
/// `web/app.js`).
fn builder(view: &str, cols: &[&str], filters: &[String], sort: Option<(&str, bool)>) -> String {
    let sort_as = |c: &str| match c {
        "receive_time" => "receive_ns".to_string(),
        "packet_time" => "packet_ns".to_string(),
        other => other.to_string(),
    };
    let mut sql = format!("select {}\nfrom {view}", cols.join(", "));
    if !filters.is_empty() {
        sql += &format!("\nwhere {}", filters.join("\n  and "));
    }
    sql += "\norder by ";
    if let Some((c, desc)) = sort {
        sql += &format!("{}{}, ", sort_as(c), if desc { " desc" } else { "" });
    }
    sql + "id\nlimit 100"
}

/// A `like` filter as the builder writes it.
fn like(col: &str, value: &str) -> String {
    format!("{col} like '%{value}%' escape '\\'")
}

const PACKET_COLS: [&str; 11] = [
    "source",
    "file",
    "apid",
    "type",
    "seq",
    "length",
    "receive_time",
    "packet_time",
    "label",
    "idx",
    "offset",
];
const VALUE_COLS: [&str; 10] = [
    "source",
    "file",
    "apid",
    "packet",
    "field",
    "value",
    "text",
    "receive_time",
    "packet_time",
    "idx",
];

/// A view the builder reads: its name, columns, filters and sort columns.
type Shape = (
    &'static str,
    &'static [&'static str],
    Vec<String>,
    Vec<&'static str>,
);

#[test]
fn every_query_builder_shape_gives_what_the_tables_gave() {
    let s = stored();
    let reader = s.reader();
    let run = format!("run = '{}'", s.root("a"));
    let time = "receive_time > '2026-01-01T00:00:00.900'".to_string();
    let shapes: [Shape; 2] = [
        (
            "{PV}",
            &PACKET_COLS,
            vec![
                time.clone(),
                "apid = 16".into(),
                like("file", "dense"),
                "seq >= 1000".into(),
                "label = 'UNIT HK'".into(),
                "type = 'tm'".into(),
            ],
            vec!["receive_time", "packet_time", "seq", "idx", "label"],
        ),
        (
            "{VV}",
            &VALUE_COLS,
            vec![
                time,
                "apid = 18".into(),
                "field = 'V'".into(),
                "value > 30000".into(),
                "value <= -50".into(),
                "packet = 'RARE'".into(),
                like("text", "UN"),
            ],
            vec!["receive_time", "packet_time", "value", "field", "idx"],
        ),
    ];
    let mut statements = 0;
    let mut rows = 0;
    for (view, cols, filters, sorts) in &shapes {
        // No filter at all, the run alone, each filter with the run, and
        // all of them.
        let mut sets: Vec<Vec<String>> = vec![vec![], vec![run.clone()]];
        for f in filters {
            sets.push(vec![run.clone(), f.clone()]);
            sets.push(vec![f.clone()]);
        }
        sets.push(
            std::iter::once(run.clone())
                .chain(filters.iter().take(3).cloned())
                .collect(),
        );
        for set in &sets {
            let mut orders: Vec<Option<(&str, bool)>> = vec![None];
            for s in sorts {
                orders.push(Some((s, false)));
                orders.push(Some((s, true)));
            }
            for order in orders {
                rows += compare(&reader, &builder(view, cols, set, order));
                statements += 1;
            }
        }
    }
    assert!(
        statements > 150 && rows > 5_000,
        "{statements} statements, {rows} rows"
    );
}

#[test]
fn statements_over_the_tables_give_what_the_tables_gave() {
    let s = stored();
    let reader = s.reader();
    let t = |ms: i64| T0 + ms * 1_000_000;
    let exact: i64 = reader
        .query_user("SELECT receive_ns FROM packets WHERE id = 2000", 1)
        .unwrap()
        .rows[0][0]
        .int()
        .unwrap();
    let last: i64 = reader
        .query_user("SELECT MAX(id) FROM packets", 1)
        .unwrap()
        .rows[0][0]
        .int()
        .unwrap();
    let statements = vec![
        // Point lookups and ranges of ids.
        "SELECT * FROM {P} WHERE id = 5".to_string(),
        "SELECT * FROM {P} WHERE rowid = 77".into(),
        format!("SELECT * FROM {{P}} WHERE id = {last}"),
        format!("SELECT * FROM {{P}} WHERE id = {}", last + 1),
        "SELECT * FROM {P} WHERE id BETWEEN 100 AND 250 ORDER BY id".into(),
        "SELECT id, lane_id FROM {P} WHERE id > 5990 ORDER BY id".into(),
        "SELECT id FROM {P} WHERE id >= 5990 AND id < 6010 ORDER BY id DESC".into(),
        "SELECT id FROM {P} WHERE id < 10 OR id > 6300 ORDER BY id".into(),
        "SELECT * FROM {P} WHERE id IN (1, 77, 6001, 6100, 99999) ORDER BY id".into(),
        "SELECT * FROM {P} WHERE id = -5".into(),
        "SELECT * FROM {P} ORDER BY id DESC LIMIT 7".into(),
        "SELECT * FROM {P} ORDER BY rowid LIMIT 7".into(),
        // Values of another type than the column's.
        "SELECT id FROM {P} WHERE id = '12'".into(),
        "SELECT id FROM {P} WHERE id = 12.0".into(),
        "SELECT id FROM {P} WHERE id = 12.5".into(),
        "SELECT id FROM {P} WHERE id > 12.5 AND id < 15.5 ORDER BY id".into(),
        "SELECT id FROM {P} WHERE id > 'x' LIMIT 3".into(),
        "SELECT id FROM {P} WHERE id > NULL".into(),
        "SELECT COUNT(*) FROM {P} WHERE lane_id = '2'".into(),
        "SELECT COUNT(*) FROM {P} WHERE file_id = 2.0".into(),
        "SELECT COUNT(*) FROM {P} WHERE file_id = 1.0".into(),
        "SELECT COUNT(*) FROM {P} WHERE lane_id = 2.0".into(),
        "SELECT COUNT(*) FROM {V} WHERE file_id = 1.0".into(),
        format!(
            "SELECT COUNT(*) FROM {{P}} WHERE receive_ns > '{}'",
            t(1000)
        ),
        // By file and by lane.
        "SELECT id, file_id, idx FROM {P} WHERE file_id = 2 ORDER BY id LIMIT 50".into(),
        "SELECT COUNT(*), MIN(id), MAX(id), MIN(idx), MAX(idx) FROM {P} WHERE file_id = 3".into(),
        "SELECT * FROM {P} WHERE file_id = 999".into(),
        "SELECT COUNT(*), SUM(length) FROM {P} WHERE lane_id = 2".into(),
        "SELECT lane_id, COUNT(*) FROM {P} WHERE lane_id IN (1, 3, 5) GROUP BY 1 ORDER BY 1".into(),
        format!(
            "SELECT id FROM {{P}} WHERE lane_id = 2 AND receive_ns > {} ORDER BY id LIMIT 20",
            t(600)
        ),
        // By time.
        format!(
            "SELECT id, receive_ns FROM {{P}} WHERE receive_ns BETWEEN {} AND {} ORDER BY receive_ns, id",
            t(300),
            t(400)
        ),
        format!(
            "SELECT id FROM {{P}} WHERE packet_ns >= {} AND packet_ns < {} ORDER BY packet_ns, id",
            t(100),
            t(130)
        ),
        format!(
            "SELECT id, lane_id FROM {{P}} WHERE receive_ns > {} ORDER BY receive_ns DESC, id LIMIT 40",
            t(900)
        ),
        format!(
            "SELECT id FROM {{P}} WHERE receive_ns < {} ORDER BY receive_ns DESC, id DESC LIMIT 40",
            t(900)
        ),
        format!("SELECT id FROM {{P}} WHERE receive_ns = {exact}"),
        format!(
            "SELECT COUNT(*) FROM {{P}} WHERE receive_ns > {} AND receive_ns < {}",
            t(9),
            t(5)
        ),
        format!("SELECT * FROM {{P}} WHERE receive_ns > {}", i64::MAX - 1),
        // Ordered by time with no range: packets without the time first
        // when ascending, last when descending.
        "SELECT id, receive_ns FROM {P} ORDER BY receive_ns, id LIMIT 80".into(),
        "SELECT id, receive_ns FROM {P} ORDER BY receive_ns DESC, id LIMIT 80".into(),
        "SELECT id, packet_ns FROM {P} ORDER BY packet_ns, id DESC LIMIT 80".into(),
        "SELECT id, packet_ns FROM {P} ORDER BY packet_ns DESC, id DESC LIMIT 80".into(),
        "SELECT id FROM {P} ORDER BY receive_ns, id".into(),
        "SELECT id FROM {P} ORDER BY packet_ns DESC, id".into(),
        // Nulls.
        "SELECT * FROM {P} WHERE receive_ns IS NULL ORDER BY id".into(),
        "SELECT COUNT(*) FROM {P} WHERE packet_ns IS NULL".into(),
        "SELECT COUNT(*), COUNT(label), COUNT(apid) FROM {P}".into(),
        "SELECT typeof(receive_ns), typeof(label), typeof(apid), typeof(seq), COUNT(*)
         FROM {P} GROUP BY 1, 2, 3, 4 ORDER BY 1, 2, 3, 4"
            .into(),
        // Aggregates and full scans.
        "SELECT COUNT(*) FROM {P}".into(),
        "SELECT apid, ptype, COUNT(*), SUM(length), MIN(offset), MAX(seq), SUM(sum % 1000)
         FROM {P} GROUP BY 1, 2 ORDER BY 1, 2"
            .into(),
        "SELECT label, COUNT(*) FROM {P} GROUP BY 1 ORDER BY 1".into(),
        "SELECT DISTINCT lane_id FROM {P} ORDER BY 1".into(),
        // Nothing narrows these.
        "SELECT id FROM {P} WHERE (sum % 7) = 3 ORDER BY id".into(),
        "SELECT id FROM {P} WHERE length + idx = 40".into(),
        // Joins.
        "SELECT p.id, f.rel, l.source FROM {P} p JOIN files f ON f.id = p.file_id
         JOIN lanes l ON l.id = p.lane_id WHERE l.apid = 18 ORDER BY p.id"
            .into(),
        "SELECT l.id, COUNT(p.id) FROM lanes l LEFT JOIN {P} p ON p.lane_id = l.id
         GROUP BY l.id ORDER BY l.id"
            .into(),
        "SELECT f.rel, COUNT(*) FROM files f JOIN {P} p ON p.file_id = f.id GROUP BY 1 ORDER BY 1"
            .into(),
        "SELECT x.id, p.receive_ns, p.packet_ns FROM findings x LEFT JOIN {P} p
         ON p.id = x.packet_id ORDER BY x.id"
            .into(),
        "SELECT a.id, b.id FROM {P} a JOIN {P} b ON b.id = a.id + 1
         WHERE a.id BETWEEN 10 AND 20 ORDER BY a.id"
            .into(),
        // Kept values.
        "SELECT * FROM {V} WHERE packet_id = 1234".into(),
        "SELECT * FROM {V} WHERE packet_id BETWEEN 10 AND 40".into(),
        "SELECT * FROM {V} WHERE packet_id > 6250".into(),
        "SELECT packet_id, field, num FROM {V} WHERE packet_id < 30 ORDER BY packet_id".into(),
        "SELECT packet, field, COUNT(*), COUNT(num), COUNT(text), round(SUM(num), 3), MIN(num)
         FROM {V} GROUP BY 1, 2 ORDER BY 1, 2"
            .into(),
        "SELECT * FROM {V} WHERE field = 'V' AND num > 30000 ORDER BY packet_id LIMIT 50".into(),
        "SELECT * FROM {V} WHERE field = 'NAME' AND text = 'UNIT'".into(),
        "SELECT packet_id FROM {V} WHERE field = 'F' AND num IS NULL".into(),
        "SELECT * FROM {V} WHERE packet = 'RARE' AND field = 'V' ORDER BY packet_id".into(),
        "SELECT COUNT(*) FROM {V} WHERE field = 'v' COLLATE NOCASE".into(),
        "SELECT COUNT(*) FROM {V} WHERE field = 5".into(),
        "SELECT COUNT(*) FROM {V} WHERE field = 'ARR[1]'".into(),
        "SELECT COUNT(*) FROM {V} WHERE field = 'NOPE'".into(),
        "SELECT COUNT(*) FROM {V} WHERE num = 7".into(),
        "SELECT COUNT(*) FROM {V} WHERE num = '7'".into(),
        "SELECT COUNT(*) FROM {V} WHERE num BETWEEN -50.5 AND 10".into(),
        "SELECT COUNT(*) FROM {V} WHERE num > 9007199254740993".into(),
        "SELECT COUNT(*) FROM {V} WHERE num IS NOT NULL AND text IS NOT NULL".into(),
        "SELECT * FROM {V} WHERE file_id = 3".into(),
        "SELECT COUNT(*) FROM {V} WHERE file_id = 1 AND field = 'MODE' AND num = 1".into(),
        "SELECT typeof(num), typeof(text), COUNT(*) FROM {V} GROUP BY 1, 2 ORDER BY 1, 2".into(),
        "SELECT v.field, p.apid, COUNT(*) FROM {V} v JOIN {P} p ON p.id = v.packet_id
         WHERE p.lane_id = 3 GROUP BY 1, 2 ORDER BY 1, 2"
            .into(),
        "SELECT p.id, COUNT(v.packet_id) FROM {P} p LEFT JOIN {V} v ON v.packet_id = p.id
         WHERE p.id BETWEEN 1 AND 300 GROUP BY p.id ORDER BY p.id"
            .into(),
        "SELECT COUNT(*) FROM {P} WHERE id IN
         (SELECT packet_id FROM {V} WHERE field = 'MODE' AND num = 1)"
            .into(),
        // Either of two, which SQLite may answer from two plans joined by
        // rowid.
        "SELECT COUNT(*) FROM {V} WHERE field = 'MODE' OR packet_id < 100".into(),
        "SELECT COUNT(*) FROM {P} WHERE lane_id = 2 OR file_id = 3".into(),
        "SELECT COUNT(*) FROM {P} WHERE id = 3 OR receive_ns IS NULL".into(),
        // The views.
        "SELECT * FROM {PV} ORDER BY id LIMIT 20".into(),
        "SELECT * FROM {PV} WHERE id = 4000".into(),
        "SELECT * FROM {VV} WHERE field = 'MODE' ORDER BY id LIMIT 20".into(),
        "SELECT * FROM {VV} WHERE value > 1000 AND field = 'V' ORDER BY id".into(),
        "SELECT run, source, COUNT(*) FROM {PV} GROUP BY 1, 2 ORDER BY 1, 2".into(),
        "SELECT run, field, COUNT(*), round(SUM(value), 3) FROM {VV} GROUP BY 1, 2 ORDER BY 1, 2"
            .into(),
    ];
    for sql in &statements {
        compare(&reader, sql);
    }
}

/// The plan SQLite takes, one step a line.
fn plan(reader: &Store, sql: &str) -> String {
    reader
        .query_user(&format!("EXPLAIN QUERY PLAN {sql}"), 100)
        .unwrap()
        .rows
        .iter()
        .map(|r| r[3].text().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The query builder's statements read the tables in the order asked for,
/// and look packets up by id, so a limit stops them early: nothing is
/// sorted afterwards, and nothing is read whole for each row.
#[test]
fn the_query_builder_is_answered_without_sorting_or_scanning_per_row() {
    let s = stored();
    let reader = s.reader();
    let run = format!("run = '{}'", s.root("a"));
    let cases = [
        builder(
            "packet_view",
            &PACKET_COLS,
            std::slice::from_ref(&run),
            None,
        ),
        builder("value_view", &VALUE_COLS, std::slice::from_ref(&run), None),
        builder(
            "value_view",
            &VALUE_COLS,
            &[run.clone(), "field = 'V'".into(), "value > 3".into()],
            None,
        ),
        builder(
            "packet_view",
            &PACKET_COLS,
            std::slice::from_ref(&run),
            Some(("receive_time", false)),
        ),
        builder(
            "packet_view",
            &PACKET_COLS,
            std::slice::from_ref(&run),
            Some(("packet_time", true)),
        ),
    ];
    for sql in &cases {
        let steps = plan(&reader, sql);
        assert!(!steps.contains("TEMP B-TREE"), "{sql}\n{steps}");
        // The virtual table is the one thing read whole, in order; every
        // other step is a lookup, packets by id ("i=", as the plan
        // describes the constraint it takes).
        let scans: Vec<&str> = steps
            .lines()
            .filter(|l| !l.starts_with("SEARCH") && !l.ends_with(":i="))
            .collect();
        assert_eq!(scans.len(), 1, "{sql}\n{steps}");
        assert!(
            scans[0].starts_with("SCAN p VIRTUAL TABLE")
                || scans[0].starts_with("SCAN v VIRTUAL TABLE"),
            "{sql}\n{steps}"
        );
    }
    // A value search by field and by value reads only the values, and
    // finds each one's packet by id.
    for sql in [
        "SELECT * FROM value_view WHERE field = 'V' AND value > 3",
        "SELECT * FROM value_view WHERE value BETWEEN 3 AND 4",
    ] {
        let steps = plan(&reader, sql);
        let lines: Vec<&str> = steps.lines().collect();
        assert!(lines[0].starts_with("SCAN v VIRTUAL TABLE"), "{steps}");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("SCAN p VIRTUAL TABLE") && l.ends_with(":i=")),
            "{steps}"
        );
        assert!(
            lines[0].contains("n>") || lines[0].contains("ng"),
            "{steps}"
        );
    }
}

#[test]
fn the_tables_cannot_be_written() {
    let s = stored();
    let store = Store::open(&s.db()).unwrap();
    for sql in [
        "DELETE FROM packets WHERE id = 1",
        "UPDATE packets SET apid = 1",
        "INSERT INTO field_values (packet_id, file_id, packet, field) VALUES (1, 1, 'a', 'b')",
        "DROP TABLE packets",
    ] {
        let err = store.query(&Query::new(sql, vec![]), 10).unwrap_err();
        assert!(!err.to_string().is_empty(), "{sql}");
        assert!(s.reader().query_user(sql, 10).is_err(), "{sql}");
    }
    assert_eq!(
        store
            .query(&Query::new("SELECT COUNT(*) FROM packets", vec![]), 1)
            .unwrap()
            .rows[0][0],
        Cell::Int(6000 + 200 + 50 + count_demo(&store))
    );
}

fn count_demo(store: &Store) -> i64 {
    store
        .query(
            &Query::new(
                "SELECT COUNT(*) FROM oracle_packets p JOIN files f ON f.id = p.file_id
                 JOIN runs r ON r.id = f.run_id WHERE r.root LIKE '%/b'",
                vec![],
            ),
            1,
        )
        .unwrap()
        .rows[0][0]
        .int()
        .unwrap()
}

/// The progress handler that limits a statement's time does not run
/// inside a long read of a table; the tables look at the clock themselves.
#[test]
fn a_long_read_of_the_tables_is_stopped_at_the_time_limit() {
    let s = stored();
    let reader = Store::open_read_only(&s.db(), Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    // Nothing matches, so no row comes back to SQLite while it reads.
    let err = reader
        .query_user("SELECT COUNT(*) FROM field_values WHERE num > 1e300", 10)
        .unwrap_err();
    assert!(err.to_string().contains("time limit"), "{err}");
    // The same statement with time to spare.
    assert_eq!(
        s.reader()
            .query_user("SELECT COUNT(*) FROM field_values WHERE num > 1e300", 10)
            .unwrap()
            .rows[0][0],
        Cell::Int(0)
    );
}

#[test]
fn a_missing_segment_is_an_error() {
    let s = stored();
    let folder = s.db().with_file_name("store.db.seg");
    let reader = s.reader();
    let name = reader
        .query_user("SELECT name FROM segments ORDER BY first_packet LIMIT 1", 1)
        .unwrap()
        .rows[0][0]
        .text()
        .unwrap()
        .to_string();
    fs::write(folder.join(&name), b"not a segment").unwrap();
    for sql in [
        "SELECT COUNT(*) FROM packets",
        "SELECT * FROM packets WHERE id = 1",
        "SELECT COUNT(*) FROM field_values",
        "SELECT COUNT(*) FROM packet_view",
    ] {
        let err = reader.query_user(sql, 10).unwrap_err().to_string();
        assert!(err.contains(&name), "{sql}: {err}");
    }
    fs::remove_file(folder.join(&name)).unwrap();
    let err = reader
        .query_user("SELECT COUNT(*) FROM packets", 10)
        .unwrap_err()
        .to_string();
    assert!(err.contains(&name), "{err}");
}

/// Nothing about the tables is in the file: a connection that does not
/// know them (as a stock `sqlite3` does not) opens it and reads the rest.
#[test]
fn the_file_holds_no_trace_of_the_tables() {
    let s = stored();
    let conn =
        rusqlite::Connection::open_with_flags(s.db(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE name IN ('packets', 'field_values')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(names.is_empty(), "{names:?}");
    let files: i64 = conn
        .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
        .unwrap();
    assert!(files > 3);
    let err = conn
        .query_row("SELECT COUNT(*) FROM packets", [], |r| r.get::<_, i64>(0))
        .unwrap_err();
    assert!(err.to_string().contains("no such table"), "{err}");
    assert!(Path::new(&s.db()).exists());
}

/// A file read again after a reader listed the segments and before it
/// opened them: the reader finds the listed segment gone, reads the list
/// again and answers from the new one, for SQL and for the page's reads
/// alike.
#[test]
fn a_segment_replaced_after_it_was_listed_is_read_from_a_new_list() {
    use packetlane::pure::sql::Clock;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let s = stored();
    let db = s.db();
    let run = fs::canonicalize(s.0.join("a")).unwrap();
    let dense = run.join("bench/dense.bin");
    let original = fs::read(&dense).unwrap();
    // Each time the hook is armed, the dense file is read again twice:
    // shorter, then whole with its last byte changed, so that it ends as
    // long as before but not the same. A name a reader listed must not
    // come to mean the last of these.
    let armed = Arc::new(AtomicBool::new(false));
    let shorter = Arc::new(AtomicUsize::new(0));
    let mut reader = s.reader();
    // The connection learns the tables before the hook is set.
    reader
        .query_user("SELECT COUNT(*) FROM packets", 1)
        .unwrap();
    {
        let (armed, shorter) = (Arc::clone(&armed), Arc::clone(&shorter));
        let (db, run, dense) = (db.clone(), run.clone(), dense.clone());
        reader.after_listing(Box::new(move || {
            if !armed.swap(false, Ordering::SeqCst) {
                return;
            }
            let k = shorter.fetch_add(1, Ordering::SeqCst);
            let mut changed = original.clone();
            if let Some(last) = changed.last_mut() {
                *last = last.wrapping_add(k as u8 + 1);
            }
            for bytes in [&original[..original.len() * 2 / 3], &changed[..]] {
                fs::write(&dense, bytes).unwrap();
                let mut store = Store::open_with_oracle(&db).unwrap();
                ingest_targets(&mut store, std::slice::from_ref(&run), None, None, None).unwrap();
            }
        }));
    }
    let fresh = || s.reader();
    let sql = "SELECT COUNT(*), SUM(p.length), MAX(p.id), SUM(p.sum % 1000) FROM packets p JOIN files f ON f.id = p.file_id
               WHERE f.rel = 'bench/dense.bin'";
    armed.store(true, Ordering::SeqCst);
    let got = reader.query_user(sql, 10).unwrap();
    assert!(!armed.load(Ordering::SeqCst), "the file was not read again");
    assert_eq!(
        got.rows,
        fresh()
            .query_user(&sql.replace("packets", "oracle_packets"), 10)
            .unwrap()
            .rows
    );

    let (from, to) = (T0, T0 + 2_000_000_000);
    type Read<'a> = Box<dyn Fn(&Store) -> Table + 'a>;
    let reads: Vec<(&str, Read)> = vec![
        (
            "density",
            Box::new(|r| r.packet_density(1, Clock::Receive, from, to, 50).unwrap()),
        ),
        (
            "items",
            Box::new(|r| r.packet_items(1, Clock::Packet, from, to, 100).unwrap()),
        ),
        (
            "series",
            Box::new(|r| {
                r.series(1, Clock::Receive, 1, Some(("HK", "V")), from, to, 20)
                    .unwrap()
            }),
        ),
        ("detail", Box::new(|r| r.packet_detail(6_400).unwrap())),
        ("values", Box::new(|r| r.packet_values(6_400).unwrap())),
        ("findings", Box::new(|r| r.run_findings(1, 1000).unwrap())),
    ];
    for (name, read) in &reads {
        armed.store(true, Ordering::SeqCst);
        let got = read(&reader);
        assert!(
            !armed.load(Ordering::SeqCst),
            "{name}: the file was not read again"
        );
        assert_eq!(got, read(&fresh()), "{name}");
    }
}

/// The page's reads of the segment files keep to a request's time as its
/// SQL does.
#[test]
fn the_pages_reads_of_the_segment_files_stop_at_the_time_limit() {
    use packetlane::pure::sql::Clock;
    let s = stored();
    let (from, to) = (T0 - 1_000_000_000, T0 + 4_000_000_000);
    let late = Store::open_read_only(&s.db(), Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let in_time = s.reader();
    type Read = fn(&Store, i64, i64) -> packetlane::shell::store::Result<Table>;
    let reads: [(&str, Read); 3] = [
        ("density", |r, from, to| {
            r.packet_density(1, Clock::Receive, from, to, 7)
        }),
        ("items", |r, from, to| {
            r.packet_items(1, Clock::Packet, from, to, 100_000)
        }),
        ("series", |r, from, to| {
            r.series(1, Clock::Receive, 1, Some(("HK", "V")), from, to, 3)
        }),
    ];
    for (name, read) in reads {
        let err = read(&late, from, to).unwrap_err().to_string();
        assert!(err.contains("time limit"), "{name}: {err}");
        assert!(!read(&in_time, from, to).unwrap().rows.is_empty(), "{name}");
    }
}
