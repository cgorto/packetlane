//! The SQLite store. This module owns the connection and runs statements;
//! what the statements are, and what their results mean, is decided in
//! `pure::sql`, `pure::ingest` and `pure::cross`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rusqlite::limits::Limit;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter};
use serde::Serialize;

use crate::pure::config::{Config, SourceInfo};
use crate::pure::cross::{Comparison, CrossFinding, hop_finding, origin_finding};
use crate::pure::decode::{Format, decoder_for};
use crate::pure::finding::{Kind, Severity};
use crate::pure::ingest::{LaneKey, ptype_code};
use crate::pure::oracle;
use crate::pure::pipeline::{FileCheck, Seen};
use crate::pure::segment as segment_layout;
use crate::pure::sql::{self, Cell, Param, Query, Table};
use crate::pure::textlog::{Assembler, Entry};
use crate::shell::cross;
use crate::shell::files::{ReadError, Records, Source, open_sniffed};
use crate::shell::segment::{self, CHUNK_BYTES, Ids, Writer};
use crate::shell::vtab;
use crate::shell::workers;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Longest line of a text log kept in memory; the rest of the line is skipped.
const MAX_LINE: usize = 64 * 1024;
/// Largest single value a read-only connection will produce.
const MAX_VALUE_BYTES: i32 = 1024 * 1024;
/// Most text one result may hold in total.
const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;

pub struct Store {
    conn: Connection,
    /// The folder of segment files beside the store.
    segments: PathBuf,
    /// Whether every packet and kept value is also written to the oracle
    /// tables of `pure::oracle`; only tests ask for it.
    oracle: bool,
    /// What the tables `packets` and `field_values` on this connection read.
    shared: Arc<vtab::Shared>,
    /// See [`Store::after_listing`].
    after_listing: Option<Box<dyn Fn() + Send>>,
    /// When a read-only store's requests must stop.
    deadline: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ingested,
    AlreadyIngested,
    NotReadable,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileOutcome {
    pub rel: String,
    pub status: Status,
    pub format: &'static str,
    pub packets: u64,
    pub entries: u64,
    pub note: String,
    /// True if rows from an earlier version of this file were removed.
    #[serde(skip)]
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngestSummary {
    pub run: i64,
    pub root: String,
    /// True if a changed configuration made the run's other files be read again.
    pub reread: bool,
    pub files: Vec<FileOutcome>,
    pub problems: i64,
}

fn bind(p: &Param) -> SqlValue {
    match p {
        Param::Null => SqlValue::Null,
        Param::Int(v) => SqlValue::Integer(*v),
        Param::Text(v) => SqlValue::Text(v.clone()),
    }
}

fn collect(stmt: &mut rusqlite::Statement<'_>, params: &[Param], limit: usize) -> Result<Table> {
    let columns: Vec<String> = stmt.column_names().map(str::to_string).collect();
    let n = columns.len();
    let mut rows = stmt.query(params_from_iter(params.iter().map(bind)))?;
    let mut out = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    while let Some(row) = rows.next()? {
        if out.len() >= limit {
            truncated = true;
            break;
        }
        let mut cells = Vec::with_capacity(n);
        for i in 0..n {
            cells.push(match row.get_ref(i)? {
                ValueRef::Null => Cell::Null,
                ValueRef::Integer(v) => Cell::Int(v),
                ValueRef::Real(v) => Cell::Real(v),
                ValueRef::Text(t) => {
                    bytes = bytes.saturating_add(t.len());
                    if bytes > MAX_RESULT_BYTES {
                        return Err("Result too large; select fewer rows or columns".into());
                    }
                    Cell::Text(String::from_utf8_lossy(t).into_owned())
                }
                ValueRef::Blob(b) => Cell::Text(format!("<{} bytes>", b.len())),
            });
        }
        out.push(cells);
    }
    Ok(Table {
        columns,
        rows: out,
        truncated,
    })
}

/// Says how long each part of an ingest took, on standard error, when the
/// environment variable `PACKETLANE_TIMING` is set. For measuring; the
/// load tests set it.
struct Phases {
    on: bool,
    last: Instant,
}

impl Phases {
    fn start() -> Phases {
        Phases {
            on: std::env::var_os("PACKETLANE_TIMING").is_some(),
            last: Instant::now(),
        }
    }

    /// The part that has just ended.
    fn mark(&mut self, name: &str) {
        self.say(name, self.last.elapsed());
        self.last = Instant::now();
    }

    fn say(&self, name: &str, took: Duration) {
        if self.on {
            eprintln!("  phase {name}: {:.2} s", took.as_secs_f64());
        }
    }
}

/// The page cache to write with, in KiB: the most SQLite may hold, not what
/// it takes, since it fills the cache only as it touches pages. SQLite holds
/// no packet rows: while ingesting it writes a file's lanes, findings and
/// counts, and the lines of text logs with their time index. Measured on
/// ten million packets in 12 lanes and three million in 900, 2 MB ingests
/// as fast as the 8 MB it was sized at for the packet indexes of earlier
/// layouts, and peaks about 5 MB lower on the first.
const WRITE_CACHE_KIB: i64 = 2 * 1024;

/// The page cache to write with: [`WRITE_CACHE_KIB`], or as many megabytes
/// as the environment variable `PACKETLANE_CACHE_MB` says (1 to 4096).
fn write_cache_kib() -> i64 {
    std::env::var("PACKETLANE_CACHE_MB")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|mb| (1..=4096).contains(mb))
        .map_or(WRITE_CACHE_KIB, |mb| mb * 1024)
}

fn run_query(conn: &Connection, q: &Query, limit: usize) -> Result<Table> {
    let mut stmt = conn.prepare_cached(&q.sql)?;
    collect(&mut stmt, &q.params, limit)
}

/// Refuses a store made by a build with another schema: its tables, or its
/// segments, are not the ones this build reads. A file with no schema yet
/// (version 0) is a new store.
fn check_schema(conn: &Connection, path: &Path) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 0 && version != sql::SCHEMA_VERSION {
        return Err(format!(
            "{} uses schema {version}, expected {}; delete it or pass a different --db",
            path.display(),
            sql::SCHEMA_VERSION
        )
        .into());
    }
    Ok(())
}

impl Store {
    /// Opens the store for reading and writing, creating it if needed.
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Sorting and temporary tables go to a file, not to memory.
        conn.pragma_update(None, "temp_store", "FILE")?;
        // Negative means a size in KiB, not a count of pages.
        conn.pragma_update(None, "cache_size", -write_cache_kib())?;
        check_schema(&conn, path)?;
        let segments = segment::folder_for(path);
        let shared = vtab::Shared::new(segments.clone());
        vtab::register(&conn, &shared)?;
        conn.execute_batch(sql::SCHEMA)?;
        conn.pragma_update(None, "user_version", sql::SCHEMA_VERSION)?;
        fs::create_dir_all(&segments)?;
        remove_orphans(&conn, &segments)?;
        Ok(Store {
            conn,
            segments,
            oracle: false,
            shared,
            after_listing: None,
            deadline: None,
        })
    }

    /// Opens the store for reading and writing as [`Store::open`] does, and
    /// also writes every packet and kept value to the oracle tables of
    /// `pure::oracle`, with the ids they would have had in SQLite. For
    /// tests only: they compare what the segment files give with those
    /// rows. Nothing the program runs opens a store this way.
    #[doc(hidden)]
    pub fn open_with_oracle(path: &Path) -> Result<Store> {
        let mut store = Store::open(path)?;
        store.conn.execute_batch(oracle::SCHEMA)?;
        store.oracle = true;
        Ok(store)
    }

    /// Opens the store so that nothing run on this connection can change it
    /// or reach another database file, and so that no statement runs for
    /// longer than `budget`.
    pub fn open_read_only(path: &Path, budget: Duration) -> Result<Store> {
        // No URI flag: a `file:` name could ask for another mode.
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "query_only", true)?;
        conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
        // No single value larger than this can be made or read here.
        conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)?;
        check_schema(&conn, path)?;
        let deadline = Instant::now() + budget;
        conn.progress_handler(10_000, Some(move || Instant::now() > deadline))?;
        let segments = segment::folder_for(path);
        // The progress handler does not run inside a long read of the
        // segment files; the tables look at the clock themselves.
        let shared = vtab::Shared::new(segments.clone());
        shared.set_deadline(deadline);
        vtab::register(&conn, &shared)?;
        Ok(Store {
            conn,
            segments,
            oracle: false,
            shared,
            after_listing: None,
            deadline: Some(deadline),
        })
    }

    /// Runs one of the tool's own statements.
    pub fn query(&self, q: &Query, limit: usize) -> Result<Table> {
        // A statement on a connection that has never named `packets` or
        // `field_values` needs no list of segments, nor a transaction.
        {
            let mut stmt = self.conn.prepare_cached(&q.sql)?;
            if !self.shared.used() {
                return collect(&mut stmt, &q.params, limit);
            }
        }
        self.with_segments(|| {
            let mut stmt = self.conn.prepare_cached(&q.sql)?;
            if self.shared.used() && !self.shared.loaded() {
                self.shared.load(&self.conn)?;
            }
            collect(&mut stmt, &q.params, limit)
        })
    }

    /// Runs a statement that may read `packets` or `field_values`: in a
    /// read transaction of its own (unless one is open), with the list of
    /// segments read in that transaction first. If a listed segment turns
    /// out to have been replaced meanwhile, which only a statement that
    /// started before the replacement was committed can see, the statement
    /// is run once more on a fresh transaction and list. `run` must prepare
    /// its statement, and read the list if it is not read yet and the
    /// statement names a table that needs it, before stepping it.
    fn with_segments<T>(&self, run: impl Fn() -> Result<T>) -> Result<T> {
        let mut retried = false;
        loop {
            self.shared.forget();
            let result = self.in_read_transaction(|| {
                if self.shared.used() {
                    self.shared.load(&self.conn)?;
                }
                self.listed_now();
                run()
            });
            let stale = self.shared.take_stale();
            self.shared.forget();
            match result {
                Err(_) if stale && !retried => retried = true,
                other => return other,
            }
        }
    }

    /// Runs a read of the segment files, all its statements in one read
    /// transaction, and once more if a segment it listed turned out to have
    /// been replaced meanwhile ([`segment::Stale`]): the list is read again,
    /// and finds the new one.
    fn again_if_stale<T>(&self, read: impl Fn() -> Result<T>) -> Result<T> {
        segment::with_deadline(self.deadline, || match self.in_read_transaction(&read) {
            Err(e) if e.is::<segment::Stale>() => self.in_read_transaction(read),
            other => other,
        })
    }

    /// Runs `f` in a read transaction of its own, unless one is open, so
    /// that every statement in it sees the store as it was when the first
    /// one started.
    fn in_read_transaction<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let own = self.conn.is_autocommit();
        if own {
            self.conn.execute_batch("BEGIN")?;
        }
        let result = f();
        if own && !self.conn.is_autocommit() {
            let end = if result.is_ok() { "COMMIT" } else { "ROLLBACK" };
            if let Err(e) = self.conn.execute_batch(end)
                && result.is_ok()
            {
                return Err(e.into());
            }
        }
        result
    }

    /// Calls the hook a test set with [`Store::after_listing`], if any.
    fn listed_now(&self) {
        if let Some(hook) = &self.after_listing {
            hook();
        }
    }

    /// For tests: something to do each time segments have been listed and
    /// before they are opened, such as replacing one, to show what a
    /// reader does when that happens between the two.
    #[doc(hidden)]
    pub fn after_listing(&mut self, hook: Box<dyn Fn() + Send>) {
        self.after_listing = Some(hook);
    }

    /// Packet counts per lane and bucket over a window, from the segment
    /// files, by the rule in `pure::segment::plan`. Columns: lane, bucket,
    /// count; one row per lane and bucket.
    pub fn packet_density(
        &self,
        run: i64,
        clock: sql::Clock,
        from: i64,
        to: i64,
        buckets: i64,
    ) -> Result<Table> {
        self.again_if_stale(|| self.packet_density_once(run, clock, from, to, buckets))
    }

    /// Individual packets in a window, as `oracle::packet_items` had them
    /// (columns: id, lane, time, seq, length), from the segment files: at
    /// most `limit`, in order of time and then id, `truncated` if there
    /// were more.
    pub fn packet_items(
        &self,
        run: i64,
        clock: sql::Clock,
        from: i64,
        to: i64,
        limit: usize,
    ) -> Result<Table> {
        self.again_if_stale(|| self.packet_items_once(run, clock, from, to, limit))
    }

    /// One lane's kept field (packet name and field name), or its arrival
    /// delay in milliseconds if `field` is `None`, over a window in
    /// `buckets` buckets (columns: bucket, min, max, count), from the
    /// segment files.
    #[allow(clippy::too_many_arguments)]
    pub fn series(
        &self,
        run: i64,
        clock: sql::Clock,
        lane: i64,
        field: Option<(&str, &str)>,
        from: i64,
        to: i64,
        buckets: i64,
    ) -> Result<Table> {
        self.again_if_stale(|| self.series_once(run, clock, lane, field, from, to, buckets))
    }

    /// One packet, as `oracle::packet_detail` had it: its record from its
    /// segment file, its file and source from the store. No rows if there
    /// is no such packet.
    pub fn packet_detail(&self, id: i64) -> Result<Table> {
        self.again_if_stale(|| self.packet_detail_once(id))
    }

    /// A packet's kept values, as its `field_values` rows have them
    /// (columns: packet, field, num, text), in the order they were kept,
    /// from its segment file.
    pub fn packet_values(&self, id: i64) -> Result<Table> {
        self.again_if_stale(|| self.packet_values_once(id))
    }

    /// A run's findings, as `oracle::run_findings` had them (columns: id,
    /// severity, kind, message, lane, file, packet, the packet's receive
    /// and packet time, the file's rel), in its order: problems first, then
    /// by the packet's time (receive, else packet, else its id), then by
    /// id. The times come from the segment files. At most `limit`,
    /// `truncated` if there were more.
    pub fn run_findings(&self, run: i64, limit: usize) -> Result<Table> {
        self.again_if_stale(|| self.run_findings_once(run, limit))
    }

    /// Packet counts per lane and bucket over a window, from the segment
    /// files, by the rule in `pure::segment::plan`. Columns: lane, bucket,
    /// count; one row per lane and bucket.
    fn packet_density_once(
        &self,
        run: i64,
        clock: sql::Clock,
        from: i64,
        to: i64,
        buckets: i64,
    ) -> Result<Table> {
        let listed = self.listed(run, clock, from, to)?;
        let width = sql::bucket_width(from, to, buckets);
        let rows = segment::density(&self.segments, &listed, clock, from, to, width)?;
        Ok(Table {
            columns: ["lane", "bucket", "count"].map(str::to_string).to_vec(),
            rows: rows
                .into_iter()
                .map(|(lane, bucket, count)| {
                    vec![Cell::Int(lane), Cell::Int(bucket), Cell::Int(count)]
                })
                .collect(),
            truncated: false,
        })
    }

    /// The segments of a run that may hold packets whose time on `clock`
    /// lies in `from..=to`.
    fn listed(
        &self,
        run: i64,
        clock: sql::Clock,
        from: i64,
        to: i64,
    ) -> Result<Vec<segment::Listed>> {
        let listed = self.query(&sql::segments_in_window(run, clock, from, to), usize::MAX)?;
        self.listed_now();
        Ok(listed
            .rows
            .iter()
            .filter_map(|r| {
                Some(segment::Listed {
                    name: r[0].text()?.to_string(),
                    first_packet: r[1].int()?,
                    min: r[2].int()?,
                    max: r[3].int()?,
                })
            })
            .collect())
    }

    /// Individual packets in a window, as `oracle::packet_items` had them
    /// (columns: id, lane, time, seq, length), from the segment files: at
    /// most `limit`, in order of time and then id, `truncated` if there
    /// were more.
    fn packet_items_once(
        &self,
        run: i64,
        clock: sql::Clock,
        from: i64,
        to: i64,
        limit: usize,
    ) -> Result<Table> {
        let listed = self.listed(run, clock, from, to)?;
        let mut items = segment::items(
            &self.segments,
            &listed,
            clock,
            from,
            to,
            limit.saturating_add(1),
        )?;
        let truncated = items.len() > limit;
        items.truncate(limit);
        Ok(Table {
            columns: ["id", "lane_id", clock.packet_column(), "seq", "length"]
                .map(str::to_string)
                .to_vec(),
            rows: items
                .into_iter()
                .map(|i| {
                    vec![
                        Cell::Int(i.id),
                        Cell::Int(i64::from(i.lane)),
                        Cell::Int(i.time),
                        i.seq.map_or(Cell::Null, |s| Cell::Int(i64::from(s))),
                        Cell::Int(i.length),
                    ]
                })
                .collect(),
            truncated,
        })
    }

    /// One lane's kept field (packet name and field name), or its arrival
    /// delay in milliseconds if `field` is `None`, over a window in
    /// `buckets` buckets, as `sql::series` and `sql::merge_series` have it
    /// (columns: bucket, min, max, count), from the segment files.
    #[allow(clippy::too_many_arguments)]
    fn series_once(
        &self,
        run: i64,
        clock: sql::Clock,
        lane: i64,
        field: Option<(&str, &str)>,
        from: i64,
        to: i64,
        buckets: i64,
    ) -> Result<Table> {
        let listed = self.listed(run, clock, from, to)?;
        let width = sql::bucket_width(from, to, buckets);
        let rows = segment::series(&self.segments, &listed, clock, lane, field, from, to, width)?;
        Ok(Table {
            columns: ["bucket", "min", "max", "count"]
                .map(str::to_string)
                .to_vec(),
            rows: rows
                .into_iter()
                .map(|(b, lo, hi, n)| {
                    vec![
                        Cell::Int(b),
                        Cell::Real(lo),
                        Cell::Real(hi),
                        Cell::Int(i64::try_from(n).unwrap_or(i64::MAX)),
                    ]
                })
                .collect(),
            truncated: false,
        })
    }

    /// The segment holding a packet, opened, with the packet's index in it
    /// and its file's row (path, rel, run id, format); `None` if no
    /// segment holds it.
    fn packet_segment(&self, id: i64) -> Result<Option<(segment::Segment, u64, Vec<Cell>)>> {
        let found = self.query(&sql::packet_segment(id), 1)?;
        self.listed_now();
        let Some(row) = found.rows.into_iter().next() else {
            return Ok(None);
        };
        let (Some(name), Some(first)) = (row[0].text(), row[1].int()) else {
            return Err("segment row without a name or first packet".into());
        };
        let listed = segment::Listed {
            name: name.to_string(),
            first_packet: first,
            min: first,
            max: first,
        };
        let seg = segment::open_listed(&self.segments, &listed)?;
        let index = u64::try_from(id - first).map_err(|_| "packet before its segment")?;
        Ok(Some((seg, index, row[2..].to_vec())))
    }

    /// One packet, as `oracle::packet_detail` had it: its record from its
    /// segment file, its file and source from the store. No rows if there
    /// is no such packet.
    fn packet_detail_once(&self, id: i64) -> Result<Table> {
        let columns = [
            "id",
            "idx",
            "offset",
            "length",
            "receive_ns",
            "packet_ns",
            "apid",
            "ptype",
            "seq",
            "label",
            "lane_id",
            "path",
            "rel",
            "source",
            "run_id",
            "format",
            "sum",
        ];
        let mut table = Table {
            columns: columns.map(str::to_string).to_vec(),
            rows: Vec::new(),
            truncated: false,
        };
        let Some((seg, index, file)) = self.packet_segment(id)? else {
            return Ok(table);
        };
        let p = seg.packet(index)?;
        let label = match p.label {
            Some(n) => Some(
                seg.labels()?
                    .get(n as usize)
                    .cloned()
                    .ok_or("packet label out of range")?,
            ),
            None => None,
        };
        let lane = i64::from(p.lane);
        let source = self.query(&sql::lane_source(lane), 1)?;
        let source = source
            .rows
            .first()
            .and_then(|r| r.first())
            .cloned()
            .unwrap_or(Cell::Null);
        let int = |v: Option<i64>| v.map_or(Cell::Null, Cell::Int);
        let header = p.header;
        table.rows.push(vec![
            Cell::Int(id),
            Cell::Int(index as i64),
            Cell::Int(p.offset),
            Cell::Int(p.length),
            int(p.receive_ns),
            int(p.packet_ns),
            int(header.map(|h| i64::from(h.0))),
            int(header.map(|h| i64::from(h.2))),
            int(header.map(|h| i64::from(h.1))),
            label.map_or(Cell::Null, Cell::Text),
            Cell::Int(lane),
            file[0].clone(),
            file[1].clone(),
            source,
            file[2].clone(),
            file[3].clone(),
            Cell::Int(p.sum),
        ]);
        Ok(table)
    }

    /// A packet's kept values, as its `field_values` rows have them
    /// (columns: packet, field, num, text), in the order they were kept,
    /// from its segment file.
    fn packet_values_once(&self, id: i64) -> Result<Table> {
        let mut table = Table {
            columns: ["packet", "field", "num", "text"]
                .map(str::to_string)
                .to_vec(),
            rows: Vec::new(),
            truncated: false,
        };
        let Some((seg, index, _)) = self.packet_segment(id)? else {
            return Ok(table);
        };
        for v in seg.values_of(index)? {
            table.rows.push(vec![
                Cell::Text(v.packet),
                Cell::Text(v.field),
                v.num.map_or(Cell::Null, Cell::Real),
                v.text.map_or(Cell::Null, Cell::Text),
            ]);
        }
        Ok(table)
    }

    /// A run's findings, as `oracle::run_findings` had them (columns: id,
    /// severity, kind, message, lane, file, packet, the packet's receive
    /// and packet time, the file's rel), in its order: problems first, then
    /// by the packet's time (receive, else packet, else its id), then by
    /// id. The times come from the segment files. At most `limit`,
    /// `truncated` if there were more.
    fn run_findings_once(&self, run: i64, limit: usize) -> Result<Table> {
        // First what they are ordered by, which is small whatever their
        // messages; then the text of the ones shown.
        let keys = self.query(&sql::run_finding_keys(run), usize::MAX)?;
        let ranges = self.query(&sql::run_segment_ranges(run), usize::MAX)?;
        self.listed_now();
        let ranges: Vec<segment::Listed> = ranges
            .rows
            .iter()
            .filter_map(|r| {
                Some(segment::Listed {
                    name: r[0].text()?.to_string(),
                    first_packet: r[1].int()?,
                    min: r[1].int()?,
                    max: r[2].int()?,
                })
            })
            .collect();
        // The packets asked about, segment by segment.
        let mut wanted: Vec<(usize, i64)> = keys
            .rows
            .iter()
            .filter_map(|r| r[2].int())
            .filter_map(|id| {
                let at = ranges.partition_point(|s| s.max < id);
                ranges
                    .get(at)
                    .filter(|s| s.first_packet <= id)
                    .map(|_| (at, id))
            })
            .collect();
        wanted.sort_unstable();
        wanted.dedup();
        let mut times: HashMap<i64, (Option<i64>, Option<i64>)> = HashMap::new();
        let mut open: Option<(usize, segment::Segment)> = None;
        for (at, id) in wanted {
            if open.as_ref().is_none_or(|(i, _)| *i != at) {
                open = Some((at, segment::open_listed(&self.segments, &ranges[at])?));
            }
            if let Some((_, seg)) = &open {
                let p = seg.packet((id - seg.first_packet()) as u64)?;
                times.insert(id, (p.receive_ns, p.packet_ns));
            }
        }
        let mut order: Vec<(bool, i64, i64)> = keys
            .rows
            .iter()
            .map(|r| {
                let packet = r[2].int();
                let (receive, time) = packet
                    .and_then(|id| times.get(&id).copied())
                    .unwrap_or((None, None));
                let at = receive.or(time).or(packet).unwrap_or(0);
                (r[1].int() == Some(1), at, r[0].int().unwrap_or(0))
            })
            .collect();
        order.sort_unstable();
        let truncated = order.len() > limit;
        order.truncate(limit);
        let rank: HashMap<i64, usize> = order.iter().enumerate().map(|(i, k)| (k.2, i)).collect();
        let ids = format!(
            "[{}]",
            order
                .iter()
                .map(|k| k.2.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut found = self.query(&sql::findings_by_id(run, &ids), usize::MAX)?;
        let mut rows: Vec<(usize, Vec<Cell>)> = std::mem::take(&mut found.rows)
            .into_iter()
            .map(|mut r| {
                let (receive, time) = r[6]
                    .int()
                    .and_then(|id| times.get(&id).copied())
                    .unwrap_or((None, None));
                let at = r[0].int().and_then(|id| rank.get(&id).copied());
                let rel = r.pop().unwrap_or(Cell::Null);
                r.push(receive.map_or(Cell::Null, Cell::Int));
                r.push(time.map_or(Cell::Null, Cell::Int));
                r.push(rel);
                (at.unwrap_or(usize::MAX), r)
            })
            .collect();
        rows.sort_by_key(|r| r.0);
        let mut columns = found.columns;
        let rel = columns.pop().unwrap_or_default();
        columns.extend(["receive_ns".to_string(), "packet_ns".to_string(), rel]);
        Ok(Table {
            columns,
            rows: rows.into_iter().map(|r| r.1).collect(),
            truncated,
        })
    }

    /// The folder of segment files beside the store.
    pub fn segment_folder(&self) -> &Path {
        &self.segments
    }

    /// Runs a statement typed by the user. It is refused unless SQLite
    /// itself reports that it cannot write.
    pub fn query_user(&self, sql_text: &str, limit: usize) -> Result<Table> {
        self.with_segments(|| {
            let mut stmt = self.conn.prepare(sql_text)?;
            if !stmt.readonly() {
                return Err("Only read-only statements are allowed".into());
            }
            if self.shared.used() && !self.shared.loaded() {
                // The first statement on this connection to name the
                // tables: planned again now that their sizes are known.
                self.shared.load(&self.conn)?;
                stmt = self.conn.prepare(sql_text)?;
            }
            collect(&mut stmt, &[], limit)
        })
    }

    /// Ingests files that all lie under `root` into the run for that root.
    /// `root` and every path in `files` must already be canonical.
    pub fn ingest(
        &mut self,
        root: &Path,
        files: &[(std::path::PathBuf, String)],
        config_text: &str,
        now_ns: i64,
    ) -> Result<IngestSummary> {
        let config = Config::parse(config_text).map_err(|e| format!("Config error: {e}"))?;
        let root_text = root.to_string_lossy().into_owned();

        // Names, clock corrections and time formats are applied while files
        // are read. If the configuration has changed since this run was
        // stored, what is stored is stale: empty the run and read its
        // files again along with the ones asked for now.
        let mut files = files.to_vec();
        let stored: Option<(i64, String)> = self
            .conn
            .query_row(sql::RUN_BY_ROOT, params![root_text], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let mut reread = false;
        if let Some((run_id, old_config)) = stored
            && old_config != config_text
        {
            let tx = self.conn.transaction()?;
            {
                let mut stmt = tx.prepare(sql::RUN_FILE_PATHS)?;
                let mut rows = stmt.query(params![run_id])?;
                while let Some(row) = rows.next()? {
                    reread = true;
                    let path: String = row.get(0)?;
                    let path = std::path::PathBuf::from(path);
                    if !files.iter().any(|(p, _)| *p == path) && path.is_file() {
                        files.push((path, row.get(1)?));
                    }
                }
            }
            if self.oracle {
                let file_ids: Vec<i64> = tx
                    .prepare(sql::RUN_FILE_IDS)?
                    .query_map(params![run_id], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                for file_id in file_ids {
                    for statement in oracle::delete_file_packets() {
                        tx.execute(&statement, params![file_id])?;
                    }
                }
            }
            let old_segments: Vec<String> = tx
                .prepare(sql::RUN_SEGMENTS)?
                .query_map(params![run_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for statement in sql::RESET_RUN {
                tx.execute(statement, params![run_id])?;
            }
            tx.execute(sql::MARK_UNFINISHED, params![run_id])?;
            tx.commit()?;
            for name in old_segments {
                discard_segment(&self.segments, &name);
            }
            files.sort();
        }
        let files = &files;

        self.conn
            .execute(sql::UPSERT_RUN, params![root_text, config_text, now_ns])?;
        let run_id: i64 = self
            .conn
            .query_row(sql::RUN_ID, params![root_text], |r| r.get(0))?;

        let mut phases = Phases::start();
        let mut outcomes = Vec::with_capacity(files.len());
        let mut changed = false;
        for (path, rel) in files {
            let outcome = match self.ingest_here(run_id, path, rel, &config) {
                Ok(outcome) => outcome,
                Err(e) => FileOutcome {
                    rel: rel.clone(),
                    status: Status::NotReadable,
                    format: "",
                    packets: 0,
                    entries: 0,
                    note: e.to_string(),
                    removed: false,
                },
            };
            changed |= outcome.status == Status::Ingested || outcome.removed;
            outcomes.push(outcome);
        }

        phases.mark("reading files");
        // Also when no file changed now but the step did not finish after
        // an earlier ingest that changed one.
        let owed = self
            .conn
            .query_row(sql::IS_UNFINISHED, params![run_id], |_| Ok(()))
            .optional()?
            .is_some();
        if changed || owed {
            let tx = self.conn.transaction()?;
            tx.execute(sql::LANES_FROM_SEGMENTS, params![run_id])?;
            tx.execute(sql::REFRESH_LOG_LANES, params![run_id])?;
            phases.mark("lane totals from the files' counts");
            // Text log entries are counted into buckets for the density
            // view; packets are counted from their segments when asked.
            tx.execute(sql::CLEAR_COARSE, params![run_id])?;
            tx.execute(sql::CLEAR_COARSE_META, params![run_id])?;
            let extents = run_query(&tx, &sql::run_extents(run_id), 1)?;
            if let Some(row) = extents.rows.first() {
                for (i, clock) in sql::Clock::ALL.into_iter().enumerate() {
                    // A span too wide for 64 bits gets no pre-counted buckets;
                    // views of it are counted directly.
                    if let (Some(min), Some(max)) = (row[i * 2].int(), row[i * 2 + 1].int())
                        && max.checked_sub(min).is_some()
                    {
                        for q in sql::build_log_coarse(run_id, clock, min, max) {
                            tx.execute(&q.sql, params_from_iter(q.params.iter().map(bind)))?;
                        }
                    }
                }
            }
            phases.mark("text log buckets");
            tx.execute(sql::DELETE_CROSS_FINDINGS, params![run_id])?;
            for finding in cross_findings(&tx, &self.segments, run_id, &mut phases)? {
                tx.execute(
                    sql::INSERT_FINDING,
                    params![
                        run_id,
                        Option::<i64>::None,
                        finding.lane,
                        finding.packet,
                        finding.severity.as_str(),
                        finding.kind.name(),
                        finding.message
                    ],
                )?;
            }
            tx.execute(sql::CLEAR_UNFINISHED, params![run_id])?;
            tx.commit()?;
            phases.mark("storing the findings");
        }

        let problems: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE run_id = ? AND severity = 'problem'",
            params![run_id],
            |r| r.get(0),
        )?;
        Ok(IngestSummary {
            run: run_id,
            root: root_text,
            reread,
            files: outcomes,
            problems,
        })
    }

    /// The file of a run at `rel`, as the store holds it now: id, size,
    /// checksum.
    fn known_file(&self, run_id: i64, rel: &str) -> Result<Option<(i64, i64, i64)>> {
        Ok(self
            .conn
            .query_row(sql::FILE_BY_REL, params![run_id, rel], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?)
    }

    /// Reads and stores one file on this thread, the store giving ids as
    /// it goes: what every file got before files were read in parallel,
    /// and what a file whose ids were not the ones foreseen gets again.
    fn ingest_here(
        &mut self,
        run_id: i64,
        path: &Path,
        rel: &str,
        config: &Config,
    ) -> Result<FileOutcome> {
        let job = workers::Job {
            path: path.to_path_buf(),
            rel: rel.to_string(),
            known: self.known_file(run_id, rel)?,
        };
        let stem = workers::stem(0);
        let stop = AtomicBool::new(false);
        let (read, writer) =
            workers::read_file(&job, config, &self.segments, &stem, CHUNK_BYTES, &stop)?;
        let finish = match writer {
            Some(writer) => Finish::Here(Box::new(writer)),
            None => Finish::Nothing,
        };
        match self.store_read(run_id, &job, read, finish, config)? {
            Committed::Stored(outcome) => Ok(outcome),
            Committed::Mismatch => Err("the store changed while the file was read".into()),
        }
    }

    /// Stores what reading a file came to, in one transaction: the same
    /// statements, in the same order, whichever thread read it. A file
    /// read elsewhere comes with its segment finished with the ids
    /// foreseen for it ([`Finish::Done`]); if the store gives other ids, or
    /// no longer holds what the reading was told it held, nothing is
    /// stored, the segment is removed and the answer is
    /// [`Committed::Mismatch`].
    fn store_read(
        &mut self,
        run_id: i64,
        job: &workers::Job,
        read: workers::Read<'_>,
        finish: Finish,
        config: &Config,
    ) -> Result<Committed> {
        let outcome = |status, format, packets, entries, note: String| FileOutcome {
            rel: job.rel.clone(),
            status,
            format,
            packets,
            entries,
            note,
            removed: false,
        };
        let (size, checksum) = match read {
            workers::Read::Failed(e) => return Err(e.into()),
            workers::Read::Unchanged => {
                if self.known_file(run_id, &job.rel)? != job.known {
                    return Ok(Committed::Mismatch);
                }
                let skipped = outcome(Status::AlreadyIngested, "", 0, 0, String::new());
                return Ok(Committed::Stored(skipped));
            }
            workers::Read::Packets(p) => {
                return self.store_packets(run_id, job, *p, finish, config);
            }
            workers::Read::Nothing { size, checksum, .. }
            | workers::Read::Text { size, checksum } => (size, checksum),
        };

        // A file is known by its place in the run. The same content there is
        // already ingested; different content (a log that has grown, say)
        // replaces what was read before.
        let tx = self.conn.transaction()?;
        let known: Option<(i64, i64, i64)> = tx
            .query_row(sql::FILE_BY_REL, params![run_id, job.rel], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        // The earlier version's segment, removed once its row is gone for good.
        let mut old_segment: Option<String> = None;
        if let Some((file_id, old_size, old_checksum)) = known {
            if (old_size, old_checksum) == (size, checksum) {
                let skipped = outcome(Status::AlreadyIngested, "", 0, 0, String::new());
                return Ok(Committed::Stored(skipped));
            }
            old_segment = tx
                .query_row(sql::FILE_SEGMENT, params![file_id], |r| r.get(0))
                .optional()?;
            if self.oracle {
                for statement in oracle::delete_file_packets() {
                    tx.execute(&statement, params![file_id])?;
                }
            }
            for statement in sql::DELETE_FILE {
                tx.execute(statement, params![file_id])?;
            }
        }

        let (format, mut file) = open_sniffed(&job.path)?;
        if format != Format::Text {
            let note = match format {
                Format::Gzip => "Compressed file that cannot be read, or holds another one",
                Format::Empty => "Empty file",
                _ if decoder_for(format, config).is_some() => {
                    return Err("the file changed while it was read".into());
                }
                _ => "Unrecognised format",
            };
            // Nothing to store. Keep the removal of an earlier version, if any.
            if known.is_some() {
                tx.execute(sql::MARK_UNFINISHED, params![run_id])?;
            }
            tx.commit()?;
            if let Some(name) = &old_segment {
                discard_segment(&self.segments, name);
            }
            let mut result = outcome(Status::NotReadable, format.name(), 0, 0, note.to_string());
            result.removed = known.is_some();
            return Ok(Committed::Stored(result));
        }

        let source = config.source_for(&job.rel);
        tx.execute(
            sql::INSERT_FILE,
            params![
                run_id,
                job.path.to_string_lossy(),
                job.rel,
                source.name,
                format.name(),
                size,
                checksum
            ],
        )?;
        let file_id = tx.last_insert_rowid();
        let mut lanes = Lanes::new(run_id, &source.name);
        let assembler = Assembler::new(config.log_format_for(&job.rel, source.utc_offset_s));
        let entries = ingest_text(&tx, &mut file, file_id, &source, assembler, &mut lanes)?;
        // How the content was reached, then why the compressed data gave
        // out, if it did.
        let fault = file
            .fault()
            .map(|why| format!("Compressed data unreadable past this point: {why}"));
        let note: Vec<String> = file
            .is_gzip()
            .then(|| "gzip".to_string())
            .into_iter()
            .chain(fault.clone())
            .collect();
        let note = note.join("; ");
        if let Some(message) = fault {
            tx.execute(
                sql::INSERT_FINDING,
                params![
                    run_id,
                    file_id,
                    None::<i64>,
                    None::<i64>,
                    Severity::Problem.as_str(),
                    Kind::Truncated.name(),
                    message
                ],
            )?;
        }
        tx.execute(
            sql::FINISH_FILE,
            params![
                0i64,
                entries as i64,
                note,
                None::<i64>,
                None::<i64>,
                file_id
            ],
        )?;
        // The run's end-of-ingest step is owed until it commits.
        tx.execute(sql::MARK_UNFINISHED, params![run_id])?;
        tx.commit()?;
        if let Some(name) = &old_segment {
            discard_segment(&self.segments, name);
        }
        Ok(Committed::Stored(outcome(
            Status::Ingested,
            format.name(),
            0,
            entries,
            note,
        )))
    }

    /// [`Store::store_read`] for a packet file.
    fn store_packets(
        &mut self,
        run_id: i64,
        job: &workers::Job,
        p: workers::Packets<'_>,
        finish: Finish,
        config: &Config,
    ) -> Result<Committed> {
        let folder = self.segments.clone();
        // A finished segment not listed by the end is removed.
        let mut unlisted: Option<String> = None;
        let result = self.store_packets_in(run_id, job, p, finish, config, &mut unlisted);
        if let Some(name) = unlisted {
            discard_segment(&folder, &name);
        }
        result
    }

    fn store_packets_in(
        &mut self,
        run_id: i64,
        job: &workers::Job,
        p: workers::Packets<'_>,
        finish: Finish,
        config: &Config,
        unlisted: &mut Option<String>,
    ) -> Result<Committed> {
        let oracle_on = self.oracle;
        let folder = self.segments.clone();
        let tx = self.conn.transaction()?;
        let known: Option<(i64, i64, i64)> = tx
            .query_row(sql::FILE_BY_REL, params![run_id, job.rel], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        if known != job.known {
            return Ok(Committed::Mismatch);
        }
        // The earlier version's segment, removed once its row is gone for good.
        let mut old_segment: Option<String> = None;
        if let Some((file_id, _, _)) = known {
            old_segment = tx
                .query_row(sql::FILE_SEGMENT, params![file_id], |r| r.get(0))
                .optional()?;
            if oracle_on {
                for statement in oracle::delete_file_packets() {
                    tx.execute(&statement, params![file_id])?;
                }
            }
            for statement in sql::DELETE_FILE {
                tx.execute(statement, params![file_id])?;
            }
        }
        tx.execute(
            sql::INSERT_FILE,
            params![
                run_id,
                job.path.to_string_lossy(),
                job.rel,
                p.source,
                p.format.name(),
                p.size,
                p.checksum
            ],
        )?;
        let file_id = tx.last_insert_rowid();
        // The file's packets are numbered from here, with no gaps.
        let first_packet: i64 = tx.query_row(sql::NEXT_PACKET_ID, [], |r| r.get(0))?;
        tx.execute(sql::NEXT_SEGMENT_SERIAL, [])?;
        let serial = tx.last_insert_rowid();
        tx.execute(sql::DROP_SEGMENT_SERIAL, [])?;
        let mut lane_ids = Vec::with_capacity(p.keys.len());
        {
            let mut insert = tx.prepare_cached(sql::INSERT_LANE)?;
            let mut select = tx.prepare_cached(sql::LANE_ID)?;
            for key in &p.keys {
                let row = params![run_id, p.source, key.kind, key.apid, key.ptype, key.file_id];
                insert.execute(row)?;
                lane_ids.push(select.query_row(row, |r| r.get::<_, i64>(0))?);
            }
        }
        let ids = Ids {
            file_id,
            serial: Some(serial),
            first_packet,
            // A lane whose id a segment cannot hold is refused when the
            // segment is finished.
            lanes: lane_ids
                .iter()
                .map(|&id| u32::try_from(id).unwrap_or(u32::MAX))
                .collect(),
        };
        let written = match finish {
            Finish::Here(writer) => {
                let written = writer.finish_with(&ids)?;
                *unlisted = written.as_ref().map(|w| w.name.clone());
                written
            }
            Finish::Nothing => return Err("a packet file without its segment".into()),
        };
        let lane_of = |key: &LaneKey| -> Result<i64> {
            p.keys
                .iter()
                .position(|k| k == key)
                .map(|i| lane_ids[i])
                .ok_or_else(|| "a lane the file did not number".into())
        };
        if oracle_on {
            let mut by_key = HashMap::new();
            for (key, &id) in p.keys.iter().zip(&lane_ids) {
                by_key.insert(*key, id);
            }
            fill_oracle(&tx, job, config, file_id, first_packet, &by_key)?;
        }
        {
            let mut insert_series = tx.prepare_cached(sql::INSERT_FILE_SERIES)?;
            for &((own, packet, field), count) in &p.series {
                let lane_id = lane_ids[own as usize];
                insert_series.execute(params![file_id, lane_id, packet, field, count])?;
            }
            let mut insert_finding = tx.prepare_cached(sql::INSERT_FINDING)?;
            for finding in &p.findings {
                let lane_id = match &finding.lane {
                    Some(key) => Some(lane_of(key)?),
                    None => None,
                };
                let packet_id = finding
                    .packet
                    .and_then(|i| i64::try_from(i).ok())
                    .map(|i| first_packet + i);
                insert_finding.execute(params![
                    run_id,
                    file_id,
                    lane_id,
                    packet_id,
                    finding.severity.as_str(),
                    finding.kind.name(),
                    finding.message
                ])?;
            }
        }
        // How the content was reached, what it says about itself and how
        // reading ended, then why the compressed data gave out, if it did.
        let fault = p
            .fault
            .as_ref()
            .map(|why| format!("Compressed data unreadable past this point: {why}"));
        let note: Vec<String> = p
            .gzip
            .then(|| "gzip".to_string())
            .into_iter()
            .chain((!p.note.is_empty()).then(|| p.note.clone()))
            .chain(fault.clone())
            .collect();
        let note = note.join("; ");
        if let Some(message) = fault {
            tx.execute(
                sql::INSERT_FINDING,
                params![
                    run_id,
                    file_id,
                    None::<i64>,
                    None::<i64>,
                    Severity::Problem.as_str(),
                    Kind::Truncated.name(),
                    message
                ],
            )?;
        }
        let packets = p.packets;
        tx.execute(
            sql::FINISH_FILE,
            params![
                packets as i64,
                0i64,
                note,
                (packets > 0).then_some(first_packet),
                (packets > 0).then(|| first_packet + packets as i64 - 1),
                file_id
            ],
        )?;
        if let Some(w) = &written {
            if w.last_packet - w.first_packet + 1 != packets as i64 {
                return Err("the segment and the stored rows disagree".into());
            }
            let time = |c: usize| w.times[c].map(|(lo, hi, shift)| (lo, hi, i64::from(shift)));
            let (r, t) = (time(0), time(1));
            tx.execute(
                sql::INSERT_SEGMENT,
                params![
                    file_id,
                    w.name,
                    w.first_packet,
                    w.last_packet,
                    r.map(|t| t.0),
                    r.map(|t| t.1),
                    r.map(|t| t.2),
                    t.map(|t| t.0),
                    t.map(|t| t.1),
                    t.map(|t| t.2),
                    i64::from(w.order_shift)
                ],
            )?;
            let mut insert_lane = tx.prepare_cached(sql::INSERT_SEGMENT_LANE)?;
            for (lane, s) in &w.lanes {
                let [(r, r_n), (t, t_n)] = s.times;
                insert_lane.execute(params![
                    file_id,
                    lane,
                    s.count as i64,
                    r.map(|t| t.0),
                    r.map(|t| t.1),
                    r_n as i64,
                    t.map(|t| t.0),
                    t.map(|t| t.1),
                    t_n as i64,
                    s.first_id,
                    s.last_id
                ])?;
            }
        }
        // The run's end-of-ingest step is owed until it commits.
        tx.execute(sql::MARK_UNFINISHED, params![run_id])?;
        tx.commit()?;
        // Listed now.
        *unlisted = None;
        if let Some(name) = &old_segment {
            discard_segment(&folder, name);
        }
        Ok(Committed::Stored(FileOutcome {
            rel: job.rel.clone(),
            status: Status::Ingested,
            format: p.format.name(),
            packets,
            entries: 0,
            note,
            removed: false,
        }))
    }
}

/// How a packet file's segment is to be finished when the file is stored.
enum Finish {
    /// Not a packet file.
    Nothing,
    /// Here, with the ids the store gives.
    Here(Box<Writer>),
}

/// What storing a file came to.
enum Committed {
    Stored(FileOutcome),
    /// Not stored: the store does not give the ids foreseen, or no longer
    /// holds what the reading was told it held.
    Mismatch,
}

/// Fills the oracle's tables with a file's packets and kept values, read
/// again from the file: the tables a test compares the segments with.
fn fill_oracle(
    conn: &Connection,
    job: &workers::Job,
    config: &Config,
    file_id: i64,
    base_id: i64,
    lanes: &HashMap<LaneKey, i64>,
) -> Result<()> {
    let (format, mut file) = open_sniffed(&job.path)?;
    let decoder = decoder_for(format, config).ok_or("the file changed while it was read")?;
    let source = config.source_for(&job.rel);
    let mut check = FileCheck::new(config, &source);
    let mut insert = conn.prepare_cached(oracle::INSERT_PACKET)?;
    let mut insert_value = conn.prepare_cached(oracle::INSERT_VALUE)?;
    for item in Records::new(BufReader::new(&mut file), decoder) {
        let record = match item {
            Ok(record) => record,
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(ReadError::Decode(_)) => break,
        };
        let Seen { row, values } = check.observe(&record);
        let packet_id = base_id + row.idx;
        let lane_id = *lanes
            .get(&row.lane())
            .ok_or("the file changed while it was read")?;
        insert.execute(params![
            packet_id,
            file_id,
            lane_id,
            row.idx,
            row.offset,
            row.length,
            row.receive_ns,
            row.packet_ns,
            row.header.map(|h| i64::from(h.apid)),
            row.header.map(|h| ptype_code(h.packet_type)),
            row.header.map(|h| i64::from(h.seq_count)),
            row.sum,
            record.label,
        ])?;
        for v in values {
            insert_value.execute(params![
                packet_id, file_id, v.packet, v.field, v.num, v.text
            ])?;
        }
    }
    Ok(())
}

/// Removes a segment the store does not list. If that fails nothing is
/// wrong with what was committed, so the ingest goes on; the sweep the next
/// time the store is opened for writing removes what is left.
fn discard_segment(folder: &Path, name: &str) {
    let _ = segment::remove(folder, name);
}

/// Removes the segment and temporary files the store does not list: left by
/// a crash, or by an ingest that did not commit. Every writer creates such
/// files only while it holds the store's write lock, so this takes that lock
/// first; if another writer holds it, the sweep waits for another time.
fn remove_orphans(conn: &Connection, folder: &Path) -> Result<()> {
    conn.busy_timeout(Duration::ZERO)?;
    let locked = conn.execute_batch("BEGIN IMMEDIATE");
    conn.busy_timeout(Duration::from_secs(5))?;
    match locked {
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::DatabaseBusy =>
        {
            return Ok(());
        }
        other => other?,
    }
    let swept = (|| -> Result<()> {
        let listed: HashSet<String> = conn
            .prepare(sql::ALL_SEGMENTS)?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for entry in fs::read_dir(folder)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if segment::is_ours(name) && !listed.contains(name) && entry.file_type()?.is_file() {
                segment::remove(folder, name)?;
            }
        }
        Ok(())
    })();
    conn.execute_batch("COMMIT")?;
    swept
}

/// Looks up or creates lane ids for one file's source.
struct Lanes<'a> {
    run_id: i64,
    source: &'a str,
    known: segment_layout::Map<LaneKey, i64>,
}

impl<'a> Lanes<'a> {
    fn new(run_id: i64, source: &'a str) -> Self {
        Self {
            run_id,
            source,
            known: segment_layout::Map::default(),
        }
    }

    fn id(&mut self, conn: &Connection, key: LaneKey) -> Result<i64> {
        if let Some(&id) = self.known.get(&key) {
            return Ok(id);
        }
        let p = params![
            self.run_id,
            self.source,
            key.kind,
            key.apid,
            key.ptype,
            key.file_id
        ];
        conn.prepare_cached(sql::INSERT_LANE)?.execute(p)?;
        let id: i64 = conn
            .prepare_cached(sql::LANE_ID)?
            .query_row(p, |r| r.get(0))?;
        self.known.insert(key, id);
        Ok(id)
    }
}

/// Reads one line, newline included, keeping at most `max` bytes of it.
/// Returns how many bytes of the file the line occupied; zero at the end.
fn read_line_bounded<R: BufRead>(r: &mut R, out: &mut Vec<u8>, max: usize) -> io::Result<u64> {
    let mut consumed = 0u64;
    loop {
        let buf = match r.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(consumed);
        }
        let (take, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        let room = max.saturating_sub(out.len());
        out.extend_from_slice(&buf[..take.min(room)]);
        r.consume(take);
        consumed += take as u64;
        if done {
            return Ok(consumed);
        }
    }
}

fn ingest_text(
    conn: &Connection,
    file: &mut Source,
    file_id: i64,
    source: &SourceInfo,
    mut assembler: Assembler,
    lanes: &mut Lanes<'_>,
) -> Result<u64> {
    let lane_id = lanes.id(conn, LaneKey::log(file_id))?;
    let mut insert = conn.prepare_cached(sql::INSERT_LOG)?;
    let mut count = 0u64;
    let mut store = |entry: Entry| -> Result<()> {
        let time = entry
            .time_ns
            .and_then(|t| t.checked_add(source.clock_offset_ns));
        insert.execute(params![
            file_id,
            lane_id,
            i64::try_from(entry.offset).unwrap_or(i64::MAX),
            time,
            entry.text
        ])?;
        count += 1;
        Ok(())
    };

    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut offset = 0u64;
    loop {
        line.clear();
        let used = read_line_bounded(&mut reader, &mut line, MAX_LINE)?;
        if used == 0 {
            break;
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if let Some(entry) = assembler.push_line(offset, &String::from_utf8_lossy(&line)) {
            store(entry)?;
        }
        offset += used;
    }
    if let Some(entry) = assembler.finish() {
        store(entry)?;
    }
    Ok(count)
}

/// The findings that compare one source's log with another's, from the
/// checksum sections of the run's segments: for each pair of lanes that
/// carry the same stream from two sources (`sql::lane_pairs`, in its
/// order), what one holds that the other lacks; then, for each stream with
/// interleaved counters (`sql::lanes_with_finding`, in its order), which
/// other sources hold copies of its packets. A run from one source has no
/// pairs, and no section is read.
fn cross_findings(
    conn: &Connection,
    folder: &Path,
    run_id: i64,
    phases: &mut Phases,
) -> Result<Vec<CrossFinding>> {
    let mut out = Vec::new();
    let pairs = run_query(conn, &sql::lane_pairs(run_id), usize::MAX)?;
    let lane = |c: &Cell| -> Result<u32> {
        c.int()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| "lane id out of range".into())
    };
    let mut listed: Vec<(i64, &str, i64, &str)> = Vec::with_capacity(pairs.rows.len());
    let mut lane_pairs: Vec<(u32, u32)> = Vec::with_capacity(pairs.rows.len());
    for row in &pairs.rows {
        let (Some(a), Some(source_a), Some(b), Some(source_b)) =
            (row[0].int(), row[1].text(), row[2].int(), row[3].text())
        else {
            continue;
        };
        listed.push((a, source_a, b, source_b));
        lane_pairs.push((lane(&row[0])?, lane(&row[2])?));
    }
    if lane_pairs.is_empty() {
        return Ok(out);
    }
    let mixed = run_query(
        conn,
        &sql::lanes_with_finding(run_id, Kind::Interleaved.name()),
        usize::MAX,
    )?;
    let mut traced = Vec::new();
    for row in &mixed.rows {
        if let Ok(x) = lane(&row[0]) {
            traced.push(x);
        }
    }
    let segments: Vec<(String, i64)> =
        run_query(conn, &sql::run_segment_ranges(run_id), usize::MAX)?
            .rows
            .iter()
            .filter_map(|r| Some((r[0].text()?.to_string(), r[1].int()?)))
            .collect();

    let mut cmp = Comparison::new(&lane_pairs, &traced);
    let replay = cross::compare(folder, &segments, &mut cmp, cross::FAN_IN)?;
    phases.mark("merging the checksum sections");
    replay.run(&mut cmp)?;
    phases.mark("counting packets a partner lacks");

    for (&(a, source_a, _, source_b), c) in listed.iter().zip(cmp.counts()) {
        out.extend(hop_finding(
            a,
            source_a,
            source_b,
            c.shared,
            c.missing,
            c.first_missing,
        ));
    }
    for row in &mixed.rows {
        let (Some(x), Ok(traced)) = (row[0].int(), lane(&row[0])) else {
            continue;
        };
        // Per source, the packets of the stream that source's lanes hold.
        let mut found: Vec<(String, i64)> = Vec::new();
        for (&(a, _, _, source_b), &(_, other)) in listed.iter().zip(&lane_pairs) {
            if a != x {
                continue;
            }
            let n = cmp.copies(traced, other);
            match found.iter_mut().find(|f| f.0 == source_b) {
                Some(f) => f.1 += n,
                None => found.push((source_b.to_string(), n)),
            }
        }
        found.retain(|f| f.1 > 0);
        found.sort();
        out.extend(origin_finding(x, row[4].int(), &found));
    }
    Ok(out)
}
