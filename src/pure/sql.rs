//! The store's schema and every statement run against it, as text plus
//! parameters. Nothing here touches a database; `shell::store` executes what
//! these functions describe.

use serde::Serialize;
use serde::ser::Serializer;

pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY,
  root TEXT NOT NULL UNIQUE,
  config TEXT NOT NULL DEFAULT '',
  ingested_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  path TEXT NOT NULL,
  rel TEXT NOT NULL,
  source TEXT NOT NULL,
  format TEXT NOT NULL,
  size INTEGER NOT NULL,
  checksum INTEGER NOT NULL,
  packets INTEGER NOT NULL DEFAULT 0,
  entries INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT '',
  UNIQUE (run_id, rel)
);
CREATE TABLE IF NOT EXISTS lanes (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  apid INTEGER NOT NULL DEFAULT -1,
  ptype INTEGER NOT NULL DEFAULT -1,
  file_id INTEGER NOT NULL DEFAULT 0,
  count INTEGER NOT NULL DEFAULT 0,
  receive_min INTEGER,
  receive_max INTEGER,
  receive_count INTEGER NOT NULL DEFAULT 0,
  packet_min INTEGER,
  packet_max INTEGER,
  packet_count INTEGER NOT NULL DEFAULT 0,
  order_min INTEGER,
  order_max INTEGER,
  UNIQUE (run_id, source, kind, apid, ptype, file_id)
);
CREATE TABLE IF NOT EXISTS packets (
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL REFERENCES files(id),
  lane_id INTEGER NOT NULL REFERENCES lanes(id),
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  length INTEGER NOT NULL,
  receive_ns INTEGER,
  packet_ns INTEGER,
  apid INTEGER,
  ptype INTEGER,
  seq INTEGER,
  sum INTEGER NOT NULL,
  label TEXT
);
CREATE INDEX IF NOT EXISTS packets_receive ON packets (receive_ns, lane_id);
CREATE INDEX IF NOT EXISTS packets_packet ON packets (packet_ns, lane_id);
CREATE INDEX IF NOT EXISTS packets_sum ON packets (sum, lane_id);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL REFERENCES files(id),
  lane_id INTEGER NOT NULL REFERENCES lanes(id),
  offset INTEGER NOT NULL,
  log_ns INTEGER,
  text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_time ON logs (log_ns, lane_id);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  file_id INTEGER,
  lane_id INTEGER,
  packet_id INTEGER,
  severity TEXT NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coarse (
  lane_id INTEGER NOT NULL,
  clock INTEGER NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (lane_id, clock, bucket)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS coarse_meta (
  run_id INTEGER NOT NULL,
  clock INTEGER NOT NULL,
  origin INTEGER NOT NULL,
  width INTEGER NOT NULL,
  PRIMARY KEY (run_id, clock)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS field_values (
  packet_id INTEGER NOT NULL REFERENCES packets(id),
  file_id INTEGER NOT NULL REFERENCES files(id),
  packet TEXT NOT NULL,
  field TEXT NOT NULL,
  num REAL,
  text TEXT
);
CREATE INDEX IF NOT EXISTS field_values_field ON field_values (field, num);
CREATE INDEX IF NOT EXISTS field_values_file ON field_values (file_id);
CREATE INDEX IF NOT EXISTS field_values_packet ON field_values (packet_id);
DROP VIEW IF EXISTS value_view;
CREATE VIEW value_view AS
  SELECT v.packet_id AS id, r.root AS run, l.source, f.rel AS file, p.apid, v.packet, v.field,
         v.num AS value, v.text,
         strftime('%Y-%m-%dT%H:%M:%f', p.receive_ns / 1000000000.0, 'unixepoch') AS receive_time,
         strftime('%Y-%m-%dT%H:%M:%f', p.packet_ns / 1000000000.0, 'unixepoch') AS packet_time,
         p.idx, p.receive_ns, p.packet_ns
  FROM field_values v
  JOIN packets p ON p.id = v.packet_id
  JOIN files f ON f.id = v.file_id
  JOIN lanes l ON l.id = p.lane_id
  JOIN runs r ON r.id = f.run_id;
DROP VIEW IF EXISTS packet_view;
CREATE VIEW packet_view AS
  SELECT p.id, r.root AS run, l.source, f.rel AS file, p.apid,
         CASE p.ptype WHEN 0 THEN 'tm' WHEN 1 THEN 'tc' END AS type,
         p.seq, p.length,
         strftime('%Y-%m-%dT%H:%M:%f', p.receive_ns / 1000000000.0, 'unixepoch') AS receive_time,
         strftime('%Y-%m-%dT%H:%M:%f', p.packet_ns / 1000000000.0, 'unixepoch') AS packet_time,
         p.label, p.idx, p.offset, p.ptype, p.receive_ns, p.packet_ns
  FROM packets p
  JOIN files f ON f.id = p.file_id
  JOIN lanes l ON l.id = p.lane_id
  JOIN runs r ON r.id = f.run_id;
DROP VIEW IF EXISTS log_view;
CREATE VIEW log_view AS
  SELECT g.id, r.root AS run, l.source, f.rel AS file,
         strftime('%Y-%m-%dT%H:%M:%f', g.log_ns / 1000000000.0, 'unixepoch') AS log_time,
         g.text, g.offset, g.log_ns
  FROM logs g
  JOIN files f ON f.id = g.file_id
  JOIN lanes l ON l.id = g.lane_id
  JOIN runs r ON r.id = f.run_id;
DROP VIEW IF EXISTS finding_view;
CREATE VIEW finding_view AS
  SELECT x.id, r.root AS run, x.severity, x.kind, l.source, NULLIF(l.apid, -1) AS apid,
         f.rel AS file, x.message
  FROM findings x
  JOIN runs r ON r.id = x.run_id
  LEFT JOIN lanes l ON l.id = x.lane_id
  LEFT JOIN files f ON f.id = x.file_id;
DROP VIEW IF EXISTS file_view;
CREATE VIEW file_view AS
  SELECT f.id, r.root AS run, f.source, f.rel AS file, f.format, f.size, f.packets,
         f.entries, f.note
  FROM files f
  JOIN runs r ON r.id = f.run_id;
";

#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Null,
    Int(i64),
    Text(String),
}

impl From<i64> for Param {
    fn from(v: i64) -> Self {
        Param::Int(v)
    }
}

impl From<&str> for Param {
    fn from(v: &str) -> Self {
        Param::Text(v.to_string())
    }
}

impl From<String> for Param {
    fn from(v: String) -> Self {
        Param::Text(v)
    }
}

impl From<Option<i64>> for Param {
    fn from(v: Option<i64>) -> Self {
        v.map_or(Param::Null, Param::Int)
    }
}

/// One statement and the values for its `?` placeholders, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub sql: String,
    pub params: Vec<Param>,
}

impl Query {
    pub fn new(sql: impl Into<String>, params: Vec<Param>) -> Self {
        Self {
            sql: sql.into(),
            params,
        }
    }
}

/// One value read back from the store.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
}

/// The largest integer a browser's number type holds exactly.
pub const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

impl Serialize for Cell {
    /// Integers too large for a browser to hold exactly (nanosecond
    /// timestamps are) are written as strings so no digits are lost.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Cell::Null => s.serialize_unit(),
            Cell::Int(v) if (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(v) => s.serialize_i64(*v),
            Cell::Int(v) => s.serialize_str(&v.to_string()),
            Cell::Real(v) if v.is_finite() => s.serialize_f64(*v),
            Cell::Real(v) => s.serialize_str(&v.to_string()),
            Cell::Text(v) => s.serialize_str(v),
        }
    }
}

impl Cell {
    pub fn int(&self) -> Option<i64> {
        match self {
            Cell::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn text(&self) -> Option<&str> {
        match self {
            Cell::Text(v) => Some(v),
            _ => None,
        }
    }
}

/// The rows a query returned.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
    /// True if there were more rows than the limit the caller set.
    pub truncated: bool,
}

/// Which clock the timeline's horizontal axis shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clock {
    /// When each logging host received the packet; log time for text logs.
    Receive,
    /// The packet's own timestamp; log time for text logs.
    Packet,
    /// Order of ingest, for packets with no usable time. No text logs.
    Order,
}

impl Clock {
    pub fn parse(s: &str) -> Option<Clock> {
        match s {
            "receive" => Some(Clock::Receive),
            "packet" => Some(Clock::Packet),
            "order" => Some(Clock::Order),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Clock::Receive => "receive",
            Clock::Packet => "packet",
            Clock::Order => "order",
        }
    }

    /// The `packets` column this clock reads.
    pub fn packet_column(self) -> &'static str {
        match self {
            Clock::Receive => "receive_ns",
            Clock::Packet => "packet_ns",
            Clock::Order => "id",
        }
    }

    /// The `logs` column this clock reads, if text logs have a place on it.
    pub fn log_column(self) -> Option<&'static str> {
        match self {
            Clock::Receive | Clock::Packet => Some("log_ns"),
            Clock::Order => None,
        }
    }
}

const RUN_LANES: &str = "(SELECT id FROM lanes WHERE run_id = ?)";

// ---- reading ---------------------------------------------------------------

pub fn runs() -> Query {
    Query::new(
        "SELECT r.id, r.root, r.ingested_ns,
                (SELECT COUNT(*) FROM files f WHERE f.run_id = r.id),
                (SELECT COALESCE(SUM(f.packets), 0) FROM files f WHERE f.run_id = r.id),
                (SELECT COALESCE(SUM(f.entries), 0) FROM files f WHERE f.run_id = r.id),
                (SELECT COUNT(*) FROM findings x WHERE x.run_id = r.id AND x.severity = 'problem')
         FROM runs r ORDER BY r.ingested_ns DESC, r.id DESC",
        vec![],
    )
}

pub fn run_row(run: i64) -> Query {
    Query::new(
        "SELECT id, root, config, ingested_ns FROM runs WHERE id = ?",
        vec![run.into()],
    )
}

pub fn run_lanes(run: i64) -> Query {
    Query::new(
        "SELECT l.id, l.source, l.kind, l.apid, l.ptype, l.file_id, l.count,
                l.receive_min, l.receive_max, l.receive_count,
                l.packet_min, l.packet_max, l.packet_count,
                l.order_min, l.order_max,
                COALESCE((SELECT f.rel FROM files f WHERE f.id = l.file_id), '')
         FROM lanes l WHERE l.run_id = ?
         ORDER BY l.source, l.kind = 'log', l.kind = 'other', l.ptype, l.apid, l.id",
        vec![run.into()],
    )
}

pub fn run_files(run: i64) -> Query {
    Query::new(
        "SELECT id, rel, source, format, size, packets, entries, note
         FROM files WHERE run_id = ? ORDER BY rel",
        vec![run.into()],
    )
}

pub fn run_findings(run: i64) -> Query {
    Query::new(
        "SELECT x.id, x.severity, x.kind, x.message, x.lane_id, x.file_id, x.packet_id,
                p.receive_ns, p.packet_ns,
                COALESCE((SELECT f.rel FROM files f WHERE f.id = x.file_id), '')
         FROM findings x LEFT JOIN packets p ON p.id = x.packet_id
         WHERE x.run_id = ?
         ORDER BY x.severity = 'info', COALESCE(p.receive_ns, p.packet_ns, x.packet_id, 0), x.id",
        vec![run.into()],
    )
}

/// Bucket width that divides `from..=to` into at most `buckets` buckets.
pub fn bucket_width(from: i64, to: i64, buckets: i64) -> i64 {
    let span = to.saturating_sub(from).saturating_add(1).max(1);
    let buckets = buckets.max(1);
    (span / buckets + i64::from(span % buckets != 0)).max(1)
}

/// Packet counts per lane and bucket. Columns: lane, bucket, count.
pub fn packet_density(run: i64, clock: Clock, from: i64, to: i64, buckets: i64) -> Query {
    let c = clock.packet_column();
    Query::new(
        format!(
            "SELECT lane_id, ({c} - ?) / ? AS b, COUNT(*) FROM packets
             WHERE {c} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             GROUP BY lane_id, b"
        ),
        vec![
            from.into(),
            bucket_width(from, to, buckets).into(),
            from.into(),
            to.into(),
            run.into(),
        ],
    )
}

/// Text log entry counts per lane and bucket, or `None` on a clock with no
/// place for text logs.
pub fn log_density(run: i64, clock: Clock, from: i64, to: i64, buckets: i64) -> Option<Query> {
    let c = clock.log_column()?;
    Some(Query::new(
        format!(
            "SELECT lane_id, ({c} - ?) / ? AS b, COUNT(*) FROM logs
             WHERE {c} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             GROUP BY lane_id, b"
        ),
        vec![
            from.into(),
            bucket_width(from, to, buckets).into(),
            from.into(),
            to.into(),
            run.into(),
        ],
    ))
}

/// What a run has to plot from kept fields: every lane, packet name and
/// field with numbers stored. Columns: lane, packet, field, count.
pub fn run_series(run: i64) -> Query {
    Query::new(
        "SELECT p.lane_id, v.packet, v.field, COUNT(*)
         FROM field_values v JOIN packets p ON p.id = v.packet_id
         WHERE v.num IS NOT NULL AND v.file_id IN (SELECT id FROM files WHERE run_id = ?)
         GROUP BY p.lane_id, v.packet, v.field
         ORDER BY p.lane_id, v.packet, v.field",
        vec![run.into()],
    )
}

/// One kept field of one lane over a window, reduced to the lowest and
/// highest value in each bucket. Columns: bucket, min, max, count.
#[allow(clippy::too_many_arguments)]
pub fn value_series(
    run: i64,
    clock: Clock,
    lane: i64,
    packet: &str,
    field: &str,
    from: i64,
    to: i64,
    buckets: i64,
) -> Query {
    let c = clock.packet_column();
    Query::new(
        format!(
            "SELECT (p.{c} - ?) / ? AS b, MIN(v.num), MAX(v.num), COUNT(*)
             FROM packets p JOIN field_values v ON v.packet_id = p.id
             WHERE p.lane_id = ? AND p.lane_id IN {RUN_LANES} AND p.{c} BETWEEN ? AND ?
               AND v.packet = ? AND v.field = ? AND v.num IS NOT NULL
             GROUP BY b ORDER BY b"
        ),
        vec![
            from.into(),
            bucket_width(from, to, buckets).into(),
            lane.into(),
            run.into(),
            from.into(),
            to.into(),
            packet.into(),
            field.into(),
        ],
    )
}

/// How long after its own time each packet of a lane was received, in
/// milliseconds, by bucket. Columns: bucket, min, max, count.
pub fn lag_series(run: i64, clock: Clock, lane: i64, from: i64, to: i64, buckets: i64) -> Query {
    let c = clock.packet_column();
    Query::new(
        format!(
            "SELECT ({c} - ?) / ? AS b, MIN(receive_ns - packet_ns) / 1000000.0,
                    MAX(receive_ns - packet_ns) / 1000000.0, COUNT(*)
             FROM packets
             WHERE lane_id = ? AND lane_id IN {RUN_LANES} AND {c} BETWEEN ? AND ?
               AND receive_ns IS NOT NULL AND packet_ns IS NOT NULL
             GROUP BY b ORDER BY b"
        ),
        vec![
            from.into(),
            bucket_width(from, to, buckets).into(),
            lane.into(),
            run.into(),
            from.into(),
            to.into(),
        ],
    )
}

/// Individual packets in a window. Columns: id, lane, time, seq, length.
pub fn packet_items(run: i64, clock: Clock, from: i64, to: i64, limit: i64) -> Query {
    let c = clock.packet_column();
    Query::new(
        format!(
            "SELECT id, lane_id, {c}, seq, length FROM packets
             WHERE {c} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             ORDER BY {c} LIMIT ?"
        ),
        vec![from.into(), to.into(), run.into(), limit.into()],
    )
}

/// Individual log entries in a window. Columns: id, lane, time, text.
pub fn log_items(run: i64, clock: Clock, from: i64, to: i64, limit: i64) -> Option<Query> {
    let c = clock.log_column()?;
    Some(Query::new(
        format!(
            "SELECT id, lane_id, {c}, substr(text, 1, 240) FROM logs
             WHERE {c} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             ORDER BY {c} LIMIT ?"
        ),
        vec![from.into(), to.into(), run.into(), limit.into()],
    ))
}

pub fn packet_detail(id: i64) -> Query {
    Query::new(
        "SELECT p.id, p.idx, p.offset, p.length, p.receive_ns, p.packet_ns, p.apid, p.ptype,
                p.seq, p.label, p.lane_id, f.path, f.rel, l.source, f.run_id, f.format, p.sum
         FROM packets p JOIN files f ON f.id = p.file_id JOIN lanes l ON l.id = p.lane_id
         WHERE p.id = ?",
        vec![id.into()],
    )
}

pub fn log_detail(id: i64) -> Query {
    Query::new(
        "SELECT g.id, g.offset, g.log_ns, g.text, g.lane_id, f.rel, l.source, f.run_id
         FROM logs g JOIN files f ON f.id = g.file_id JOIN lanes l ON l.id = g.lane_id
         WHERE g.id = ?",
        vec![id.into()],
    )
}

/// Text log entries containing `needle`, ignoring ASCII case.
/// Columns: id, lane, time, text.
pub fn search_logs(run: i64, needle: &str, limit: i64) -> Query {
    Query::new(
        format!(
            "SELECT id, lane_id, log_ns, substr(text, 1, 240) FROM logs
             WHERE lane_id IN {RUN_LANES} AND instr(lower(text), lower(?)) > 0
             ORDER BY log_ns LIMIT ?"
        ),
        vec![run.into(), needle.into(), limit.into()],
    )
}

pub fn run_config(run: i64) -> Query {
    Query::new("SELECT config FROM runs WHERE id = ?", vec![run.into()])
}

/// Paths already ingested under a folder, for the file browser.
/// Columns: path, packets, entries, note.
pub fn files_under(prefix: &str) -> Query {
    Query::new(
        "SELECT path, packets, entries, note FROM files
         WHERE substr(path, 1, length(?)) = ?",
        vec![prefix.into(), prefix.into()],
    )
}

// ---- writing ---------------------------------------------------------------

/// The id and stored configuration text of the run for a folder.
pub const RUN_BY_ROOT: &str = "SELECT id, config FROM runs WHERE root = ?";
/// Files a run holds. Columns: path, rel.
pub const RUN_FILE_PATHS: &str = "SELECT path, rel FROM files WHERE run_id = ? ORDER BY rel";
/// Statements that empty a run, each taking the run id. Used when its
/// configuration changes, because names, clocks and time formats are
/// applied as files are read.
pub const RESET_RUN: [&str; 8] = [
    "DELETE FROM field_values WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM packets WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM logs WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM findings WHERE run_id = ?",
    "DELETE FROM coarse WHERE lane_id IN (SELECT id FROM lanes WHERE run_id = ?)",
    "DELETE FROM coarse_meta WHERE run_id = ?",
    "DELETE FROM lanes WHERE run_id = ?",
    "DELETE FROM files WHERE run_id = ?",
];
pub const UPSERT_RUN: &str = "INSERT INTO runs (root, config, ingested_ns) VALUES (?, ?, ?)
     ON CONFLICT (root) DO UPDATE SET config = excluded.config, ingested_ns = excluded.ingested_ns";
pub const RUN_ID: &str = "SELECT id FROM runs WHERE root = ?";
/// A file of a run by its path within the run. Columns: id, size, checksum.
pub const FILE_BY_REL: &str = "SELECT id, size, checksum FROM files WHERE run_id = ? AND rel = ?";
/// Statements that remove one file and what was read from it, each taking
/// the file id.
pub const DELETE_FILE: [&str; 6] = [
    "DELETE FROM field_values WHERE file_id = ?",
    "DELETE FROM packets WHERE file_id = ?",
    "DELETE FROM logs WHERE file_id = ?",
    "DELETE FROM findings WHERE file_id = ?",
    "DELETE FROM lanes WHERE kind = 'log' AND file_id = ?",
    "DELETE FROM files WHERE id = ?",
];
pub const INSERT_FILE: &str =
    "INSERT INTO files (run_id, path, rel, source, format, size, checksum)
     VALUES (?, ?, ?, ?, ?, ?, ?)";
pub const FINISH_FILE: &str = "UPDATE files SET packets = ?, entries = ?, note = ? WHERE id = ?";
pub const INSERT_LANE: &str =
    "INSERT OR IGNORE INTO lanes (run_id, source, kind, apid, ptype, file_id)
     VALUES (?, ?, ?, ?, ?, ?)";
pub const LANE_ID: &str = "SELECT id FROM lanes
     WHERE run_id = ? AND source = ? AND kind = ? AND apid = ? AND ptype = ? AND file_id = ?";
pub const NEXT_PACKET_ID: &str = "SELECT COALESCE(MAX(id), 0) + 1 FROM packets";
pub const INSERT_PACKET: &str = "INSERT INTO packets
     (id, file_id, lane_id, idx, offset, length, receive_ns, packet_ns, apid, ptype, seq, sum, label)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
pub const INSERT_LOG: &str =
    "INSERT INTO logs (file_id, lane_id, offset, log_ns, text) VALUES (?, ?, ?, ?, ?)";
/// One kept field value of one packet: the number, the text, or both.
pub const INSERT_VALUE: &str = "INSERT INTO field_values (packet_id, file_id, packet, field, num, text) VALUES (?, ?, ?, ?, ?, ?)";
pub const INSERT_FINDING: &str = "INSERT INTO findings
     (run_id, file_id, lane_id, packet_id, severity, kind, message) VALUES (?, ?, ?, ?, ?, ?, ?)";
pub const DELETE_CROSS_FINDINGS: &str = "DELETE FROM findings WHERE run_id = ? AND file_id IS NULL";

/// Recomputes the per-lane totals and time ranges for a run.
pub const REFRESH_PACKET_LANES: &str = "UPDATE lanes SET
       (count, receive_min, receive_max, receive_count,
        packet_min, packet_max, packet_count, order_min, order_max) =
       (SELECT COUNT(*), MIN(receive_ns), MAX(receive_ns), COUNT(receive_ns),
               MIN(packet_ns), MAX(packet_ns), COUNT(packet_ns), MIN(id), MAX(id)
        FROM packets WHERE lane_id = lanes.id)
     WHERE run_id = ? AND kind != 'log'";
pub const REFRESH_LOG_LANES: &str = "UPDATE lanes SET
       (count, receive_min, receive_max, receive_count, packet_min, packet_max, packet_count) =
       (SELECT COUNT(*), MIN(log_ns), MAX(log_ns), COUNT(log_ns),
               MIN(log_ns), MAX(log_ns), COUNT(log_ns)
        FROM logs WHERE lane_id = lanes.id)
     WHERE run_id = ? AND kind = 'log'";

// ---- cross-source checks ---------------------------------------------------

/// Pairs of packet lanes in a run that carry the same stream from different
/// sources. Columns: lane a, source a, lane b, source b, apid, ptype.
pub fn lane_pairs(run: i64) -> Query {
    Query::new(
        "SELECT a.id, a.source, b.id, b.source, a.apid, a.ptype
         FROM lanes a JOIN lanes b
           ON b.run_id = a.run_id AND b.kind = 'packet' AND b.apid = a.apid
          AND b.ptype = a.ptype AND b.source != a.source
         WHERE a.run_id = ? AND a.kind = 'packet'
         ORDER BY a.apid, a.ptype, a.source, b.source",
        vec![run.into()],
    )
}

/// How lane `a` compares with lane `b`, matching packets by the checksum of
/// their bytes, which the `(sum, lane_id)` index answers without a row read.
/// One row: packets of `a` also in `b`; packets of `a` not in `b` that sit
/// between the first and last shared packet; the id of the first such packet.
pub fn hop_compare(lane_a: i64, lane_b: i64) -> Query {
    Query::new(
        "WITH m AS MATERIALIZED (
           SELECT p.id AS id,
                  EXISTS (SELECT 1 FROM packets q
                          WHERE q.sum = p.sum AND q.lane_id = ?1) AS hit
           FROM packets p WHERE p.lane_id = ?2),
         w AS (SELECT MIN(id) AS lo, MAX(id) AS hi FROM m WHERE hit = 1)
         SELECT (SELECT COUNT(*) FROM m WHERE hit = 1),
                (SELECT COUNT(*) FROM m, w WHERE hit = 0 AND id BETWEEN w.lo AND w.hi),
                (SELECT MIN(id) FROM m, w WHERE hit = 0 AND id BETWEEN w.lo AND w.hi)",
        vec![lane_b.into(), lane_a.into()],
    )
}

/// Streams with a per-file finding of the given kind.
/// Columns: lane, source, apid, ptype, packet id of the finding.
pub fn lanes_with_finding(run: i64, kind: &str) -> Query {
    Query::new(
        "SELECT x.lane_id, l.source, l.apid, l.ptype, MIN(x.packet_id)
         FROM findings x JOIN lanes l ON l.id = x.lane_id
         WHERE x.run_id = ? AND x.kind = ? AND x.file_id IS NOT NULL
         GROUP BY x.lane_id",
        vec![run.into(), kind.into()],
    )
}

/// Which other sources hold copies of a lane's packets.
/// Columns: source, number of the lane's packets found there.
pub fn lane_origins(run: i64, lane: i64, apid: i64, ptype: i64) -> Query {
    Query::new(
        "SELECT l.source,
                SUM((SELECT COUNT(*) FROM packets p
                     WHERE p.lane_id = ?1 AND EXISTS (
                       SELECT 1 FROM packets q
                       WHERE q.sum = p.sum AND q.lane_id = l.id
                         AND q.seq = p.seq AND q.length = p.length))) AS n
         FROM lanes l
         WHERE l.run_id = ?2 AND l.kind = 'packet' AND l.apid = ?3 AND l.ptype = ?4
           AND l.id != ?1
         GROUP BY l.source HAVING n > 0 ORDER BY l.source",
        vec![lane.into(), run.into(), apid.into(), ptype.into()],
    )
}

// ---- pre-counted density ---------------------------------------------------
//
// Counting every packet of a long run for each redraw is too slow, so after
// an ingest the store keeps counts per lane in `COARSE_BUCKETS` fixed buckets
// per clock. A view whose own buckets are at least that wide is drawn from
// those counts; a narrower view covers little enough to count directly.

/// Buckets kept per run and clock.
pub const COARSE_BUCKETS: i64 = 4096;

impl Clock {
    pub const ALL: [Clock; 3] = [Clock::Receive, Clock::Packet, Clock::Order];

    fn code(self) -> i64 {
        match self {
            Clock::Receive => 0,
            Clock::Packet => 1,
            Clock::Order => 2,
        }
    }
}

pub const CLEAR_COARSE: &str =
    "DELETE FROM coarse WHERE lane_id IN (SELECT id FROM lanes WHERE run_id = ?)";
pub const CLEAR_COARSE_META: &str = "DELETE FROM coarse_meta WHERE run_id = ?";

/// First and last value a run holds on each clock, read from its lanes.
/// One row: receive min, max; packet min, max; order min, max.
pub fn run_extents(run: i64) -> Query {
    Query::new(
        "SELECT MIN(receive_min), MAX(receive_max), MIN(packet_min), MAX(packet_max),
                MIN(order_min), MAX(order_max)
         FROM lanes WHERE run_id = ?",
        vec![run.into()],
    )
}

/// The statements that fill the pre-counted buckets for one clock of a run
/// whose values on that clock span `min..=max`.
pub fn build_coarse(run: i64, clock: Clock, min: i64, max: i64) -> Vec<Query> {
    let width = bucket_width(min, max, COARSE_BUCKETS);
    let mut out = vec![Query::new(
        "INSERT INTO coarse_meta (run_id, clock, origin, width) VALUES (?, ?, ?, ?)",
        vec![run.into(), clock.code().into(), min.into(), width.into()],
    )];
    let mut fill = |table: &str, column: &str| {
        out.push(Query::new(
            format!(
                "INSERT INTO coarse (lane_id, clock, bucket, count)
                 SELECT lane_id, ?1, ({column} - ?2) / ?3 AS b, COUNT(*) FROM {table}
                 WHERE {column} IS NOT NULL AND lane_id IN (SELECT id FROM lanes WHERE run_id = ?4)
                 GROUP BY lane_id, b"
            ),
            vec![clock.code().into(), min.into(), width.into(), run.into()],
        ));
    };
    fill("packets", clock.packet_column());
    if let Some(column) = clock.log_column() {
        fill("logs", column);
    }
    out
}

/// Origin and bucket width of a run's pre-counted buckets on one clock.
pub fn coarse_meta(run: i64, clock: Clock) -> Query {
    Query::new(
        "SELECT origin, width FROM coarse_meta WHERE run_id = ? AND clock = ?",
        vec![run.into(), clock.code().into()],
    )
}

/// Counts rows of one table whose time lies in `lo..=hi`, into buckets of
/// `width` measured from `from`.
fn range_density(
    table: &str,
    column: &str,
    run: i64,
    lo: i64,
    hi: i64,
    from: i64,
    width: i64,
) -> Query {
    Query::new(
        format!(
            "SELECT lane_id, ({column} - ?) / ? AS b, COUNT(*) FROM {table}
             WHERE {column} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             GROUP BY lane_id, b"
        ),
        vec![from.into(), width.into(), lo.into(), hi.into(), run.into()],
    )
}

/// The pre-counted part of a window: the stored buckets that lie wholly
/// inside it, as (first bucket, last bucket, first value, last value).
fn whole_coarse_buckets(
    from: i64,
    to: i64,
    origin: i64,
    coarse_width: i64,
) -> Option<(i64, i64, i64, i64)> {
    let first = from
        .checked_sub(origin)?
        .checked_add(coarse_width - 1)?
        .div_euclid(coarse_width);
    let last = to
        .checked_sub(origin)?
        .checked_add(1)?
        .div_euclid(coarse_width)
        .checked_sub(1)?;
    if first > last {
        return None;
    }
    let lo = origin.checked_add(first.checked_mul(coarse_width)?)?;
    let hi = origin
        .checked_add(last.checked_add(1)?.checked_mul(coarse_width)?)?
        .checked_sub(1)?;
    Some((first, last, lo, hi))
}

/// The statements that count a window into `buckets` buckets. Each returns
/// lane, bucket, count, and together they count every row in the window
/// exactly once. `coarse` is the origin and width from [`coarse_meta`], if
/// the run has pre-counted buckets: those are used for the part of the
/// window they cover whole, and the two ends are counted directly.
pub fn density(
    run: i64,
    clock: Clock,
    from: i64,
    to: i64,
    buckets: i64,
    coarse: Option<(i64, i64)>,
) -> Vec<Query> {
    let width = bucket_width(from, to, buckets);
    let direct = |lo: i64, hi: i64| -> Vec<Query> {
        let mut out = vec![range_density(
            "packets",
            clock.packet_column(),
            run,
            lo,
            hi,
            from,
            width,
        )];
        if let Some(column) = clock.log_column() {
            out.push(range_density("logs", column, run, lo, hi, from, width));
        }
        out
    };
    let whole = match coarse {
        Some((origin, coarse_width)) if coarse_width > 0 && width >= coarse_width => {
            whole_coarse_buckets(from, to, origin, coarse_width)
                .map(|found| (found, origin, coarse_width))
        }
        _ => None,
    };
    let Some(((first, last, lo, hi), origin, coarse_width)) = whole else {
        return direct(from, to);
    };
    let mut out = vec![Query::new(
        "SELECT lane_id, (?1 + bucket * ?2 - ?3) / ?4 AS b, SUM(count) FROM coarse
         WHERE clock = ?5 AND bucket BETWEEN ?6 AND ?7
           AND lane_id IN (SELECT id FROM lanes WHERE run_id = ?8)
         GROUP BY lane_id, b",
        vec![
            origin.into(),
            coarse_width.into(),
            from.into(),
            width.into(),
            clock.code().into(),
            first.into(),
            last.into(),
            run.into(),
        ],
    )];
    if from < lo {
        out.extend(direct(from, lo - 1));
    }
    if hi < to {
        out.extend(direct(hi + 1, to));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_width_covers_the_span() {
        assert_eq!(bucket_width(0, 99, 10), 10);
        assert_eq!(bucket_width(0, 100, 10), 11);
        assert_eq!(bucket_width(5, 5, 10), 1);
        assert_eq!(bucket_width(0, 9, 0), 10);
        assert_eq!(bucket_width(10, 0, 4), 1);
        assert_eq!(bucket_width(i64::MIN, i64::MAX, 1000), i64::MAX / 1000 + 1);
        // Every value in the span lands in a bucket below the count asked for.
        for (from, to, n) in [(0i64, 999, 7), (-50, 50, 3), (17, 1_000_003, 1920)] {
            let w = bucket_width(from, to, n);
            assert!((to - from) / w < n, "{from}..{to} in {n}");
        }
    }

    #[test]
    fn large_integers_are_serialised_as_strings() {
        let row = vec![
            Cell::Int(42),
            Cell::Int(1_767_225_600_000_000_000),
            Cell::Null,
            Cell::Real(1.5),
            Cell::Text("x".into()),
            Cell::Int(MAX_SAFE_INT),
            Cell::Int(-MAX_SAFE_INT - 1),
        ];
        assert_eq!(
            serde_json::to_string(&row).unwrap(),
            r#"[42,"1767225600000000000",null,1.5,"x",9007199254740991,"-9007199254740992"]"#
        );
    }

    #[test]
    fn clocks_map_to_columns() {
        assert_eq!(Clock::parse("receive"), Some(Clock::Receive));
        assert_eq!(Clock::parse("wall"), None);
        assert_eq!(Clock::Order.packet_column(), "id");
        assert!(log_density(1, Clock::Order, 0, 1, 10).is_none());
        let q = packet_density(3, Clock::Packet, 100, 199, 10);
        assert!(q.sql.contains("packet_ns BETWEEN"));
        assert_eq!(
            q.params,
            vec![100.into(), 10.into(), 100.into(), 199.into(), 3.into()]
        );
    }

    #[test]
    fn density_uses_pre_counted_buckets_only_when_they_are_fine_enough() {
        // Whole run: view buckets (250) are wider than the stored ones (100).
        let wide = density(1, Clock::Receive, 1_000, 100_999, 400, Some((1_000, 100)));
        assert_eq!(wide.len(), 1);
        assert!(wide[0].sql.contains("FROM coarse"));
        assert_eq!(wide[0].params[5], Param::Int(0));
        assert_eq!(wide[0].params[6], Param::Int(999));
        // Zoomed in: view buckets (5) are narrower, so count the rows.
        let narrow = density(1, Clock::Receive, 50_000, 51_999, 400, Some((1_000, 100)));
        assert_eq!(narrow.len(), 2);
        assert!(narrow.iter().all(|q| !q.sql.contains("FROM coarse")));
        assert!(narrow[0].sql.contains("FROM packets"));
        assert!(narrow[1].sql.contains("FROM logs"));
        // No stored buckets, and a clock with no text logs.
        assert_eq!(density(1, Clock::Order, 0, 99_999, 400, None).len(), 1);
        // A window that starts before the stored origin.
        let early = density(1, Clock::Receive, -5_000, 100_999, 400, Some((1_000, 100)));
        assert_eq!(early[0].params[5], Param::Int(-60));
    }

    #[test]
    fn coarse_build_statements() {
        let q = build_coarse(7, Clock::Packet, 1_000, 410_599);
        assert_eq!(q.len(), 3);
        assert_eq!(
            q[0].params,
            vec![7.into(), 1.into(), 1_000.into(), 100.into()]
        );
        assert!(q[1].sql.contains("FROM packets") && q[1].sql.contains("packet_ns"));
        assert!(q[2].sql.contains("FROM logs") && q[2].sql.contains("log_ns"));
        assert_eq!(build_coarse(7, Clock::Order, 1, 50).len(), 2);
    }

    #[test]
    fn pre_counted_buckets_are_only_used_where_they_fit_whole() {
        let coarse = Some((1_000, 100));
        // Neither stored bucket lies wholly inside 1050..=1149: count directly.
        let q = density(1, Clock::Receive, 1_050, 1_149, 1, coarse);
        assert!(q.iter().all(|q| !q.sql.contains("FROM coarse")));
        // 1050..=1449 holds buckets 1..=3 whole (1100..=1399), plus two ends.
        let q = density(1, Clock::Order, 1_050, 1_449, 2, coarse);
        assert_eq!(q.len(), 3);
        assert_eq!(
            (&q[0].params[5], &q[0].params[6]),
            (&Param::Int(1), &Param::Int(3))
        );
        assert_eq!(
            (&q[1].params[2], &q[1].params[3]),
            (&Param::Int(1_050), &Param::Int(1_099))
        );
        assert_eq!(
            (&q[2].params[2], &q[2].params[3]),
            (&Param::Int(1_400), &Param::Int(1_449))
        );
        // Extremes fall back to counting directly instead of overflowing.
        let q = density(1, Clock::Order, i64::MIN, i64::MAX, 400, Some((0, 1)));
        assert!(!q.is_empty());
    }
}
