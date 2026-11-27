//! The store's schema and every statement run against it, as text plus
//! parameters. Nothing here touches a database; `shell::store` executes what
//! these functions describe.

use serde::Serialize;
use serde::ser::Serializer;

pub const SCHEMA_VERSION: i64 = 5;

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
  first_packet INTEGER,
  last_packet INTEGER,
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
CREATE INDEX IF NOT EXISTS packets_lane_receive ON packets (lane_id, receive_ns, packet_ns);
CREATE INDEX IF NOT EXISTS packets_lane_packet ON packets (lane_id, packet_ns, receive_ns);
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
CREATE TABLE IF NOT EXISTS coarse_series (
  lane_id INTEGER NOT NULL,
  clock INTEGER NOT NULL,
  packet TEXT NOT NULL,
  field TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  lo REAL NOT NULL,
  hi REAL NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (lane_id, clock, packet, field, bucket)
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
CREATE INDEX IF NOT EXISTS field_values_packet ON field_values (packet_id);
CREATE TABLE IF NOT EXISTS file_series (
  file_id INTEGER NOT NULL REFERENCES files(id),
  lane_id INTEGER NOT NULL REFERENCES lanes(id),
  packet TEXT NOT NULL,
  field TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (file_id, lane_id, packet, field)
) WITHOUT ROWID;
-- One row per segment file of packets; see pure::segment.
CREATE TABLE IF NOT EXISTS segments (
  file_id INTEGER PRIMARY KEY REFERENCES files(id),
  name TEXT NOT NULL UNIQUE,
  first_packet INTEGER NOT NULL,
  last_packet INTEGER NOT NULL,
  receive_min INTEGER,
  receive_max INTEGER,
  receive_shift INTEGER,
  packet_min INTEGER,
  packet_max INTEGER,
  packet_shift INTEGER,
  order_shift INTEGER NOT NULL
);
-- What each segment holds of each lane; a packet lane's count and time
-- ranges in `lanes` are worked out from these rows.
CREATE TABLE IF NOT EXISTS segment_lanes (
  file_id INTEGER NOT NULL REFERENCES files(id),
  lane_id INTEGER NOT NULL REFERENCES lanes(id),
  count INTEGER NOT NULL,
  receive_min INTEGER,
  receive_max INTEGER,
  receive_count INTEGER NOT NULL,
  packet_min INTEGER,
  packet_max INTEGER,
  packet_count INTEGER NOT NULL,
  order_min INTEGER NOT NULL,
  order_max INTEGER NOT NULL,
  PRIMARY KEY (lane_id, file_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS segment_lanes_file ON segment_lanes (file_id);
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

    /// What to write after `packets` and any alias in a query that reads a
    /// window of every lane of a run: the index that finds packets by this clock, so
    /// that the cost follows the width of the window.
    ///
    /// The index is named because SQLite, left to choose, takes a lane-first
    /// index and visits the lanes one at a time, sorting afterwards.
    fn all_lanes(self) -> &'static str {
        match self {
            Clock::Receive => "INDEXED BY packets_receive",
            Clock::Packet => "INDEXED BY packets_packet",
            // By id, which is the table's own order and needs no index.
            Clock::Order => "NOT INDEXED",
        }
    }

    /// What to write after `packets` and any alias in a query that reads a
    /// window of one lane: the index that finds a lane's packets by this clock, so that
    /// the cost follows that lane's packets and not everything else logged
    /// at the same time.
    fn one_lane(self) -> &'static str {
        match self {
            Clock::Receive => "INDEXED BY packets_lane_receive",
            Clock::Packet => "INDEXED BY packets_lane_packet",
            // By id, as for every lane: no index holds a lane's ids in
            // order, and SQLite would otherwise read the whole lane.
            Clock::Order => "NOT INDEXED",
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

/// What a run's findings are ordered by, without their packets' times,
/// which come from the segment files: id, whether it is only information,
/// packet id. See [`run_findings`] for the order.
pub fn run_finding_keys(run: i64) -> Query {
    Query::new(
        "SELECT id, severity = 'info', packet_id FROM findings WHERE run_id = ?",
        vec![run.into()],
    )
}

/// Some of a run's findings, by id (a JSON array of them), without their
/// packets' times. Columns: id, severity, kind, message, lane, file,
/// packet, file's rel.
pub fn findings_by_id(run: i64, ids_json: &str) -> Query {
    Query::new(
        "SELECT x.id, x.severity, x.kind, x.message, x.lane_id, x.file_id, x.packet_id,
                COALESCE((SELECT f.rel FROM files f WHERE f.id = x.file_id), '')
         FROM findings x
         WHERE x.run_id = ? AND x.id IN (SELECT value FROM json_each(?))",
        vec![run.into(), ids_json.into()],
    )
}

/// The segments of a run, in id order. Columns: name, first packet id,
/// last packet id.
pub fn run_segment_ranges(run: i64) -> Query {
    Query::new(
        "SELECT name, first_packet, last_packet FROM segments
         WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)
         ORDER BY first_packet",
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
    let index = clock.all_lanes();
    Query::new(
        format!(
            "SELECT lane_id, ({c} - ?) / ? AS b, COUNT(*) FROM packets {index}
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
///
/// Read from the counts kept per file at ingest (`file_series`), so that
/// opening a run does not read every stored value.
pub fn run_series(run: i64) -> Query {
    Query::new(
        "SELECT lane_id, packet, field, SUM(count)
         FROM file_series
         WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)
         GROUP BY lane_id, packet, field
         ORDER BY lane_id, packet, field",
        vec![run.into()],
    )
}

/// One kept field of one lane over a window, reduced to the lowest and
/// highest value in each bucket. Columns: bucket, min, max, count.
///
/// `CROSS JOIN` makes SQLite start from the lane's packets in the window
/// and look their values up, so the cost follows the window. Left to
/// itself it starts from every stored value of the field, however narrow
/// the view.
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
    let grid = (from, bucket_width(from, to, buckets));
    series_range(run, clock, lane, Some((packet, field)), grid, from, to)
}

/// How long after its own time each packet of a lane was received, in
/// milliseconds, by bucket. Columns: bucket, min, max, count.
pub fn lag_series(run: i64, clock: Clock, lane: i64, from: i64, to: i64, buckets: i64) -> Query {
    let grid = (from, bucket_width(from, to, buckets));
    series_range(run, clock, lane, None, grid, from, to)
}

/// A series (a kept field, or arrival delay if `field` is `None`) read from
/// the packets whose time lies in `lo..=hi`, into buckets counted from
/// `grid.0` and `grid.1` wide.
fn series_range(
    run: i64,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    grid: (i64, i64),
    lo: i64,
    hi: i64,
) -> Query {
    let c = clock.packet_column();
    let index = clock.one_lane();
    let mut params: Vec<Param> = vec![
        grid.0.into(),
        grid.1.into(),
        lane.into(),
        run.into(),
        lo.into(),
        hi.into(),
    ];
    let sql = match field {
        Some((packet, field)) => {
            params.push(packet.into());
            params.push(field.into());
            format!(
                "SELECT (p.{c} - ?) / ? AS b, MIN(v.num), MAX(v.num), COUNT(*)
                 FROM packets p {index} CROSS JOIN field_values v ON v.packet_id = p.id
                 WHERE p.lane_id = ? AND p.lane_id IN {RUN_LANES} AND p.{c} BETWEEN ? AND ?
                   AND v.packet = ? AND v.field = ? AND v.num IS NOT NULL
                 GROUP BY b ORDER BY b"
            )
        }
        None => format!(
            "SELECT ({c} - ?) / ? AS b, MIN(receive_ns - packet_ns) / 1000000.0,
                    MAX(receive_ns - packet_ns) / 1000000.0, COUNT(*)
             FROM packets {index}
             WHERE lane_id = ? AND lane_id IN {RUN_LANES} AND {c} BETWEEN ? AND ?
               AND receive_ns IS NOT NULL AND packet_ns IS NOT NULL
             GROUP BY b ORDER BY b"
        ),
    };
    Query::new(sql, params)
}

/// Individual packets in a window. Columns: id, lane, time, seq, length.
pub fn packet_items(run: i64, clock: Clock, from: i64, to: i64, limit: i64) -> Query {
    let c = clock.packet_column();
    let index = clock.all_lanes();
    Query::new(
        format!(
            "SELECT id, lane_id, {c}, seq, length FROM packets {index}
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
/// The ids of a file's packets, as `BETWEEN` wants them. A file's packets
/// are numbered in one unbroken run as it is read, and the file's row keeps
/// the first and last (`first_packet`, `last_packet`; null if it held
/// none). What was read from a file is found by that range, which the
/// tables are already in order of, and so needs no index by file.
const FILE_PACKETS: &str = "(SELECT first_packet FROM files WHERE id = ?1)
                                AND (SELECT last_packet FROM files WHERE id = ?1)";

/// Removes the packets of one file and their kept values. Takes the file
/// id; the file's row must still be there.
pub fn delete_file_packets() -> [String; 2] {
    [
        format!("DELETE FROM field_values WHERE packet_id BETWEEN {FILE_PACKETS}"),
        format!("DELETE FROM packets WHERE id BETWEEN {FILE_PACKETS}"),
    ]
}

/// The files of a run. Columns: id.
pub const RUN_FILE_IDS: &str = "SELECT id FROM files WHERE run_id = ?";

/// Removes everything read for a run but the run itself, each taking the
/// run id. The packets and kept values go first, file by file, with
/// [`delete_file_packets`].
pub const RESET_RUN: [&str; 10] = [
    "DELETE FROM segments WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM segment_lanes WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM file_series WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM logs WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)",
    "DELETE FROM findings WHERE run_id = ?",
    "DELETE FROM coarse_series WHERE lane_id IN (SELECT id FROM lanes WHERE run_id = ?)",
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
/// the file id. Its packets and kept values go first, with
/// [`delete_file_packets`].
pub const DELETE_FILE: [&str; 7] = [
    "DELETE FROM segments WHERE file_id = ?",
    "DELETE FROM segment_lanes WHERE file_id = ?",
    "DELETE FROM file_series WHERE file_id = ?",
    "DELETE FROM logs WHERE file_id = ?",
    "DELETE FROM findings WHERE file_id = ?",
    "DELETE FROM lanes WHERE kind = 'log' AND file_id = ?",
    "DELETE FROM files WHERE id = ?",
];
pub const INSERT_FILE: &str =
    "INSERT INTO files (run_id, path, rel, source, format, size, checksum)
     VALUES (?, ?, ?, ?, ?, ?, ?)";
/// Takes packets, entries, note, first packet id, last packet id, file id.
pub const FINISH_FILE: &str = "UPDATE files
     SET packets = ?, entries = ?, note = ?, first_packet = ?, last_packet = ?
     WHERE id = ?";
pub const INSERT_LANE: &str =
    "INSERT OR IGNORE INTO lanes (run_id, source, kind, apid, ptype, file_id)
     VALUES (?, ?, ?, ?, ?, ?)";
pub const LANE_ID: &str = "SELECT id FROM lanes
     WHERE run_id = ? AND source = ? AND kind = ? AND apid = ? AND ptype = ? AND file_id = ?";
/// The id the next file's first packet gets: one more than the highest any
/// segment holds. A file's packets are numbered from there with no gaps.
pub const NEXT_PACKET_ID: &str = "SELECT COALESCE(MAX(last_packet), 0) + 1 FROM segments";
pub const INSERT_PACKET: &str = "INSERT INTO packets
     (id, file_id, lane_id, idx, offset, length, receive_ns, packet_ns, apid, ptype, seq, sum, label)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
pub const INSERT_LOG: &str =
    "INSERT INTO logs (file_id, lane_id, offset, log_ns, text) VALUES (?, ?, ?, ?, ?)";
/// One kept field value of one packet: the number, the text, or both.
pub const INSERT_VALUE: &str = "INSERT INTO field_values (packet_id, file_id, packet, field, num, text) VALUES (?, ?, ?, ?, ?, ?)";
/// How many numbers one file holds of one kept field of one lane.
pub const INSERT_FILE_SERIES: &str =
    "INSERT INTO file_series (file_id, lane_id, packet, field, count) VALUES (?, ?, ?, ?, ?)";
pub const INSERT_FINDING: &str = "INSERT INTO findings
     (run_id, file_id, lane_id, packet_id, severity, kind, message) VALUES (?, ?, ?, ?, ?, ?, ?)";
pub const DELETE_CROSS_FINDINGS: &str = "DELETE FROM findings WHERE run_id = ? AND file_id IS NULL";

// ---- segments ------------------------------------------------------------------
//
// Each packet file's packets are also written to a segment file beside the
// store (see `pure::segment`); the `segments` table lists them.

/// Takes file id, name, first and last packet id, receive min, max and
/// shift, packet min, max and shift, order shift.
pub const INSERT_SEGMENT: &str = "INSERT INTO segments
     (file_id, name, first_packet, last_packet, receive_min, receive_max, receive_shift,
      packet_min, packet_max, packet_shift, order_shift)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
/// The segment of one file, if it has one. Columns: name.
pub const FILE_SEGMENT: &str = "SELECT name FROM segments WHERE file_id = ?";
/// The segments of a run's files. Columns: name.
pub const RUN_SEGMENTS: &str =
    "SELECT name FROM segments WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)";
/// Every segment the store lists. Columns: name.
pub const ALL_SEGMENTS: &str = "SELECT name FROM segments";

/// The segments of a run holding packets whose time on `clock` may lie in
/// `from..=to`, in id order. Columns: name, first packet id, lowest and
/// highest value on the clock.
pub fn segments_in_window(run: i64, clock: Clock, from: i64, to: i64) -> Query {
    let (min, max) = match clock {
        Clock::Receive => ("receive_min", "receive_max"),
        Clock::Packet => ("packet_min", "packet_max"),
        Clock::Order => ("first_packet", "last_packet"),
    };
    Query::new(
        format!(
            "SELECT name, first_packet, {min}, {max} FROM segments
             WHERE file_id IN (SELECT id FROM files WHERE run_id = ?)
               AND {min} <= ? AND {max} >= ?
             ORDER BY first_packet"
        ),
        vec![run.into(), to.into(), from.into()],
    )
}

/// The segment holding a packet, and its file. Columns: name, first packet
/// id, path, rel, run id, format.
pub fn packet_segment(id: i64) -> Query {
    Query::new(
        "SELECT s.name, s.first_packet, f.path, f.rel, f.run_id, f.format
         FROM segments s JOIN files f ON f.id = s.file_id
         WHERE ?1 BETWEEN s.first_packet AND s.last_packet",
        vec![id.into()],
    )
}

/// A lane's source. Columns: source.
pub fn lane_source(lane: i64) -> Query {
    Query::new("SELECT source FROM lanes WHERE id = ?", vec![lane.into()])
}

/// Takes file id, lane id, count, receive min, max and count, packet min,
/// max and count, first and last packet id: what one segment holds of one
/// lane.
pub const INSERT_SEGMENT_LANE: &str = "INSERT INTO segment_lanes
     (file_id, lane_id, count, receive_min, receive_max, receive_count,
      packet_min, packet_max, packet_count, order_min, order_max)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/// Sets each packet lane's count and time ranges for a run from what its
/// segments hold of it (`segment_lanes`), which is kept as each file is
/// read and removed with the file. A lane none of whose packets are left
/// reads as empty. No packet is read.
pub const LANES_FROM_SEGMENTS: &str = "UPDATE lanes SET
       (count, receive_min, receive_max, receive_count,
        packet_min, packet_max, packet_count, order_min, order_max) =
       (SELECT COALESCE(SUM(count), 0), MIN(receive_min), MAX(receive_max),
               COALESCE(SUM(receive_count), 0), MIN(packet_min), MAX(packet_max),
               COALESCE(SUM(packet_count), 0), MIN(order_min), MAX(order_max)
        FROM segment_lanes WHERE lane_id = lanes.id)
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

// Whether a packet of one lane is also in another is asked by the checksum
// of its bytes. An index of every packet by checksum would answer that, but
// checksums come in no order, so keeping one up to date touches a different
// page for every packet read: it was most of the time an ingest took, and
// what made ingest need a large page cache. Instead, once the files are
// read, the packets of the streams that more than one source logged are
// copied to a temporary table, sorted by checksum as they are written. The
// comparisons below read that table, and it is dropped when they are done.

/// Drops the temporary table of [`hop_stage`], if a failed ingest left one.
pub const HOP_UNSTAGE: &str = "DROP TABLE IF EXISTS temp.hop";

/// The statements that make `temp.hop`: the packets of a run's lanes that
/// have a counterpart from another source, kept in order of checksum and
/// lane. The run's packets are found by its files' id ranges, so no other
/// run is read.
///
/// The table is its own index (`WITHOUT ROWID`) and is filled in its own
/// order, from one sort: nothing is written twice, and reading it from end
/// to end asks about each checksum beside the last. The sequence count and
/// length are there for the tracing of interleaved streams, which matches
/// on them too.
pub fn hop_stage(run: i64) -> Vec<Query> {
    vec![
        Query::new(
            "CREATE TEMP TABLE hop (
               sum INTEGER NOT NULL, lane_id INTEGER NOT NULL, id INTEGER NOT NULL,
               seq INTEGER, length INTEGER,
               PRIMARY KEY (sum, lane_id, id)
             ) WITHOUT ROWID",
            vec![],
        ),
        Query::new(
            "INSERT INTO temp.hop (sum, lane_id, id, seq, length)
             SELECT p.sum, p.lane_id, p.id, p.seq, p.length
             FROM files f CROSS JOIN packets p NOT INDEXED
               ON p.id BETWEEN f.first_packet AND f.last_packet
             WHERE f.run_id = ?1 AND p.lane_id IN (
               SELECT a.id FROM lanes a JOIN lanes b
                 ON b.run_id = a.run_id AND b.kind = 'packet' AND b.apid = a.apid
                AND b.ptype = a.ptype AND b.source != a.source
               WHERE a.run_id = ?1 AND a.kind = 'packet')
             ORDER BY p.sum, p.lane_id, p.id",
            vec![run.into()],
        ),
    ]
}

/// How every lane of a run compares with each lane that carries the same
/// stream from another source, matching packets by the checksum of their
/// bytes. Reads `temp.hop`, which [`hop_stage`] must have made.
///
/// One row for each pair (`a`, `b`) where `a` has packets that `b` lacks
/// between the first and last packet they share. Columns: lane `a`, lane
/// `b`, packets of `a` also in `b`, packets of `a` missing from `b` within
/// that span, the id of the first such packet.
///
/// The packets are read twice in all, however many pairs there are: once
/// to find what each pair shares and once to count what is missing.
/// `CROSS JOIN` keeps SQLite to that order. Asking pair by pair instead
/// reads every packet once per pair.
pub fn hop_compare_all(run: i64) -> Query {
    Query::new(
        "WITH pair AS MATERIALIZED (
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
         GROUP BY shared.a, shared.b",
        vec![run.into()],
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

/// Which other sources hold copies of a lane's packets. The lane's own
/// packets are read from the store, by lane, and each is looked for in
/// `temp.hop`, which [`hop_stage`] must have made.
/// Columns: source, number of the lane's packets found there.
pub fn lane_origins(run: i64, lane: i64, apid: i64, ptype: i64) -> Query {
    Query::new(
        "SELECT l.source,
                SUM((SELECT COUNT(*) FROM packets p INDEXED BY packets_lane_receive
                     WHERE p.lane_id = ?1 AND EXISTS (
                       SELECT 1 FROM temp.hop q
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
    density_of(run, clock, from, to, buckets, coarse, false)
}

/// As [`density`], for text log entries only: the statements that count a
/// window's log entries, from the pre-counted buckets of log lanes where
/// they cover it whole. None on a clock with no place for text logs.
pub fn log_density_stored(
    run: i64,
    clock: Clock,
    from: i64,
    to: i64,
    buckets: i64,
    coarse: Option<(i64, i64)>,
) -> Vec<Query> {
    if clock.log_column().is_none() {
        return Vec::new();
    }
    density_of(run, clock, from, to, buckets, coarse, true)
}

fn density_of(
    run: i64,
    clock: Clock,
    from: i64,
    to: i64,
    buckets: i64,
    coarse: Option<(i64, i64)>,
    logs_only: bool,
) -> Vec<Query> {
    let width = bucket_width(from, to, buckets);
    let lanes = if logs_only { " AND kind = 'log'" } else { "" };
    let direct = |lo: i64, hi: i64| -> Vec<Query> {
        let mut out = Vec::new();
        if !logs_only {
            out.push(range_density(
                &format!("packets {}", clock.all_lanes()),
                clock.packet_column(),
                run,
                lo,
                hi,
                from,
                width,
            ));
        }
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
        format!(
            "SELECT lane_id, (?1 + bucket * ?2 - ?3) / ?4 AS b, SUM(count) FROM coarse
             WHERE clock = ?5 AND bucket BETWEEN ?6 AND ?7
               AND lane_id IN (SELECT id FROM lanes WHERE run_id = ?8{lanes})
             GROUP BY lane_id, b"
        ),
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

// ---- stored series buckets ---------------------------------------------------
//
// A plot of a whole long run reads every packet of its lane. For lanes with
// enough packets to make that slow, the store keeps, after an ingest, the
// lowest and highest value in each of a fixed set of buckets, for every
// kept field and for arrival delay. A view whose own buckets are at least
// that wide is drawn from those; a narrower view covers little enough of
// the lane to read directly.

/// Stored series buckets per pre-counted density bucket: 16,384 a run.
pub const SERIES_PER_COARSE: i64 = 4;

/// Lanes with fewer packets than this on a clock get no stored buckets:
/// reading them whole is quick, and buckets for every small lane would
/// cost more room than the lane's values.
pub const SERIES_MIN_PACKETS: i64 = 8 * SERIES_PER_COARSE * COARSE_BUCKETS;

/// The width of a stored series bucket, from the width of the run's
/// pre-counted density buckets on the same clock. They share an origin.
pub fn series_width(coarse_width: i64) -> i64 {
    (coarse_width / SERIES_PER_COARSE).max(1)
}

pub const CLEAR_COARSE_SERIES: &str =
    "DELETE FROM coarse_series WHERE lane_id IN (SELECT id FROM lanes WHERE run_id = ?)";

/// The statements that fill the stored series buckets for one clock of a
/// run, for lanes with at least `min_packets` on that clock. `origin` and
/// `coarse_width` are the run's, as in `coarse_meta`. None for the order
/// clock, which has no lane-first index to read a lane by.
pub fn build_coarse_series(
    run: i64,
    clock: Clock,
    origin: i64,
    coarse_width: i64,
    min_packets: i64,
) -> Vec<Query> {
    let (c, counted) = match clock {
        Clock::Receive => ("receive_ns", "receive_count"),
        Clock::Packet => ("packet_ns", "packet_count"),
        Clock::Order => return Vec::new(),
    };
    let index = clock.one_lane();
    let lanes =
        format!("(SELECT id FROM lanes WHERE run_id = ?4 AND kind = 'packet' AND {counted} >= ?5)");
    let params: Vec<Param> = vec![
        clock.code().into(),
        origin.into(),
        series_width(coarse_width).into(),
        run.into(),
        min_packets.into(),
    ];
    vec![
        Query::new(
            format!(
                "INSERT INTO coarse_series (lane_id, clock, packet, field, bucket, lo, hi, count)
                 SELECT lane_id, ?1, '', '', ({c} - ?2) / ?3 AS b,
                        MIN(receive_ns - packet_ns) / 1000000.0,
                        MAX(receive_ns - packet_ns) / 1000000.0, COUNT(*)
                 FROM packets {index}
                 WHERE lane_id IN {lanes} AND receive_ns IS NOT NULL AND packet_ns IS NOT NULL
                 GROUP BY lane_id, b"
            ),
            params.clone(),
        ),
        Query::new(
            format!(
                "INSERT INTO coarse_series (lane_id, clock, packet, field, bucket, lo, hi, count)
                 SELECT p.lane_id, ?1, v.packet, v.field, (p.{c} - ?2) / ?3 AS b,
                        MIN(v.num), MAX(v.num), COUNT(*)
                 FROM packets p {index} CROSS JOIN field_values v ON v.packet_id = p.id
                 WHERE p.lane_id IN {lanes} AND p.{c} IS NOT NULL AND v.num IS NOT NULL
                 GROUP BY p.lane_id, v.packet, v.field, b"
            ),
            params,
        ),
    ]
}

/// The name a series is stored under: a kept field's packet and field, or
/// two empty names for arrival delay.
fn series_key<'a>(field: Option<(&'a str, &'a str)>) -> (&'a str, &'a str) {
    field.unwrap_or(("", ""))
}

/// Whether a series has stored buckets on a clock: one row if so.
pub fn has_coarse_series(lane: i64, clock: Clock, field: Option<(&str, &str)>) -> Query {
    let (packet, field) = series_key(field);
    Query::new(
        "SELECT 1 FROM coarse_series
         WHERE lane_id = ? AND clock = ? AND packet = ? AND field = ? LIMIT 1",
        vec![
            lane.into(),
            clock.code().into(),
            packet.into(),
            field.into(),
        ],
    )
}

/// The statements that reduce a series over a window to `buckets` buckets.
/// Each returns bucket, min, max, count; a bucket may come from more than
/// one, and [`merge_series`] joins them. Together they take in every packet
/// in the window exactly once.
///
/// `stored` is the origin and width from [`coarse_meta`] if the series has
/// stored buckets ([`has_coarse_series`]): those are used for the part of
/// the window they cover whole, and the two ends are read directly. A
/// stored bucket goes to the requested bucket its start falls in.
#[allow(clippy::too_many_arguments)]
pub fn series(
    run: i64,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    from: i64,
    to: i64,
    buckets: i64,
    stored: Option<(i64, i64)>,
) -> Vec<Query> {
    let width = bucket_width(from, to, buckets);
    let direct = |lo: i64, hi: i64| series_range(run, clock, lane, field, (from, width), lo, hi);
    let whole = match stored {
        Some((origin, coarse_width)) if coarse_width > 0 => {
            let stored_width = series_width(coarse_width);
            (width >= stored_width)
                .then(|| whole_coarse_buckets(from, to, origin, stored_width))
                .flatten()
                .map(|found| (found, origin, stored_width))
        }
        _ => None,
    };
    let Some(((first, last, lo, hi), origin, stored_width)) = whole else {
        return vec![direct(from, to)];
    };
    let (packet, name) = series_key(field);
    let mut out = vec![Query::new(
        "SELECT (?1 + bucket * ?2 - ?3) / ?4 AS b, MIN(lo), MAX(hi), SUM(count)
         FROM coarse_series
         WHERE lane_id = ?5 AND lane_id IN (SELECT id FROM lanes WHERE run_id = ?6)
           AND clock = ?7 AND packet = ?8 AND field = ?9 AND bucket BETWEEN ?10 AND ?11
         GROUP BY b ORDER BY b",
        vec![
            origin.into(),
            stored_width.into(),
            from.into(),
            width.into(),
            lane.into(),
            run.into(),
            clock.code().into(),
            packet.into(),
            name.into(),
            first.into(),
            last.into(),
        ],
    )];
    if from < lo {
        out.push(direct(from, lo - 1));
    }
    if hi < to {
        out.push(direct(hi + 1, to));
    }
    out
}

/// Joins the answers to the statements from [`series`] into one row a
/// bucket, in bucket order: the lowest min, the highest max, the counts
/// added.
pub fn merge_series(parts: &[&Table]) -> Table {
    let number = |c: &Cell| match c {
        Cell::Real(v) => Some(*v),
        Cell::Int(v) => Some(*v as f64),
        _ => None,
    };
    let mut merged: std::collections::BTreeMap<i64, (f64, f64, i64)> =
        std::collections::BTreeMap::new();
    for row in parts.iter().flat_map(|t| &t.rows) {
        let (Some(bucket), Some(lo), Some(hi), Some(count)) = (
            row.first().and_then(Cell::int),
            row.get(1).and_then(number),
            row.get(2).and_then(number),
            row.get(3).and_then(Cell::int),
        ) else {
            continue;
        };
        merged
            .entry(bucket)
            .and_modify(|m| *m = (m.0.min(lo), m.1.max(hi), m.2 + count))
            .or_insert((lo, hi, count));
    }
    Table {
        columns: ["bucket", "min", "max", "count"]
            .map(str::to_string)
            .to_vec(),
        rows: merged
            .into_iter()
            .map(|(b, (lo, hi, n))| {
                vec![Cell::Int(b), Cell::Real(lo), Cell::Real(hi), Cell::Int(n)]
            })
            .collect(),
        truncated: parts.iter().any(|t| t.truncated),
    }
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
    fn log_density_from_stored_buckets_reads_no_packets() {
        let coarse = Some((1_000, 100));
        let q = log_density_stored(1, Clock::Receive, 1_050, 1_449, 2, coarse);
        assert_eq!(q.len(), 3);
        assert!(q[0].sql.contains("FROM coarse") && q[0].sql.contains("kind = 'log'"));
        assert!(q[1..].iter().all(|q| q.sql.contains("FROM logs")));
        let narrow = log_density_stored(1, Clock::Packet, 1_050, 1_149, 1, coarse);
        assert_eq!(narrow.len(), 1);
        assert!(narrow[0].sql.contains("FROM logs"));
        assert!(log_density_stored(1, Clock::Order, 0, 99, 2, coarse).is_empty());
        // The full statements still count packets and every lane.
        let all = density(1, Clock::Receive, 1_050, 1_449, 2, coarse);
        assert!(!all[0].sql.contains("kind = 'log'"));
        assert!(all.iter().any(|q| q.sql.contains("FROM packets")));
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
