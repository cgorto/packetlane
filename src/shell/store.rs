//! The SQLite store. This module owns the connection and runs statements;
//! what the statements are, and what their results mean, is decided in
//! `pure::sql`, `pure::ingest` and `pure::cross`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::limits::Limit;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter};
use serde::Serialize;

use crate::pure::config::{Config, SourceInfo};
use crate::pure::cross::{CrossFinding, hop_finding, origin_finding};
use crate::pure::decode::{Decoder, Format, decoder_for};
use crate::pure::finding::{Kind, Severity};
use crate::pure::ingest::{LaneKey, ptype_code};
use crate::pure::pipeline::{FileCheck, Seen};
use crate::pure::sql::{self, Cell, Param, Query, Table};
use crate::pure::textlog::{Assembler, Entry};
use crate::shell::files::{Hashing, ReadError, Records, Source, open_sniffed};

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

/// The page cache to write with, in KiB. A file's packets are written to
/// the end of each lane's part of the two lane-first indexes, so what must
/// stay in memory is a couple of pages for every lane the file holds: 4 MB
/// was enough for a file of 300 lanes, measured, and this leaves room for
/// about twice that. With less, each packet pushes out a page another lane
/// is about to need. With more, nothing is gained. Peak memory while
/// writing was 16, 22, 35, 61 and 81 MB at 2, 4, 8, 16 and 32 MB of cache.
const WRITE_CACHE_KIB: i64 = 8 * 1024;

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
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 0 && version != sql::SCHEMA_VERSION {
            return Err(format!(
                "{} uses schema {version}, expected {}; delete it or pass a different --db",
                path.display(),
                sql::SCHEMA_VERSION
            )
            .into());
        }
        conn.execute_batch(sql::SCHEMA)?;
        conn.pragma_update(None, "user_version", sql::SCHEMA_VERSION)?;
        Ok(Store { conn })
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
        let deadline = Instant::now() + budget;
        conn.progress_handler(10_000, Some(move || Instant::now() > deadline))?;
        Ok(Store { conn })
    }

    /// Runs one of the tool's own statements.
    pub fn query(&self, q: &Query, limit: usize) -> Result<Table> {
        run_query(&self.conn, q, limit)
    }

    /// Runs a statement typed by the user. It is refused unless SQLite
    /// itself reports that it cannot write.
    pub fn query_user(&self, sql_text: &str, limit: usize) -> Result<Table> {
        let mut stmt = self.conn.prepare(sql_text)?;
        if !stmt.readonly() {
            return Err("Only read-only statements are allowed".into());
        }
        collect(&mut stmt, &[], limit)
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
            let file_ids: Vec<i64> = tx
                .prepare(sql::RUN_FILE_IDS)?
                .query_map(params![run_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for file_id in file_ids {
                for statement in sql::delete_file_packets() {
                    tx.execute(&statement, params![file_id])?;
                }
            }
            for statement in sql::RESET_RUN {
                tx.execute(statement, params![run_id])?;
            }
            tx.commit()?;
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
            let outcome = match self.ingest_file(run_id, path, rel, &config) {
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
        if changed {
            let tx = self.conn.transaction()?;
            for statement in sql::REFRESH_PACKET_LANES {
                tx.execute(statement, params![run_id])?;
            }
            tx.execute(sql::REFRESH_LOG_LANES, params![run_id])?;
            phases.mark("lane counts");
            let mut series_took = Duration::ZERO;
            tx.execute(sql::CLEAR_COARSE, params![run_id])?;
            tx.execute(sql::CLEAR_COARSE_META, params![run_id])?;
            tx.execute(sql::CLEAR_COARSE_SERIES, params![run_id])?;
            let extents = run_query(&tx, &sql::run_extents(run_id), 1)?;
            if let Some(row) = extents.rows.first() {
                for (i, clock) in sql::Clock::ALL.into_iter().enumerate() {
                    // A span too wide for 64 bits gets no pre-counted buckets;
                    // views of it are counted directly.
                    if let (Some(min), Some(max)) = (row[i * 2].int(), row[i * 2 + 1].int())
                        && max.checked_sub(min).is_some()
                    {
                        let width = sql::bucket_width(min, max, sql::COARSE_BUCKETS);
                        let series = sql::build_coarse_series(
                            run_id,
                            clock,
                            min,
                            width,
                            sql::SERIES_MIN_PACKETS,
                        );
                        for q in sql::build_coarse(run_id, clock, min, max) {
                            tx.execute(&q.sql, params_from_iter(q.params.iter().map(bind)))?;
                        }
                        let started = Instant::now();
                        for q in series {
                            tx.execute(&q.sql, params_from_iter(q.params.iter().map(bind)))?;
                        }
                        series_took += started.elapsed();
                    }
                }
            }
            phases.say("series buckets", series_took);
            phases.say(
                "density buckets",
                phases.last.elapsed().saturating_sub(series_took),
            );
            phases.last = Instant::now();
            tx.execute(sql::DELETE_CROSS_FINDINGS, params![run_id])?;
            for finding in cross_findings(&tx, run_id, &mut phases)? {
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
            tx.commit()?;
            phases.mark("writing it down");
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

    fn ingest_file(
        &mut self,
        run_id: i64,
        path: &Path,
        rel: &str,
        config: &Config,
    ) -> Result<FileOutcome> {
        // Opened read-only, twice: once to identify the content, once to parse it.
        let (checksum, size) = Hashing::new(File::open(path)?).finish()?;
        let (checksum, size) = (checksum as i64, i64::try_from(size)?);
        let outcome = |status, format, packets, entries, note: String| FileOutcome {
            rel: rel.to_string(),
            status,
            format,
            packets,
            entries,
            note,
            removed: false,
        };

        // A file is known by its place in the run. The same content there is
        // already ingested; different content (a log that has grown, say)
        // replaces what was read before.
        let tx = self.conn.transaction()?;
        let known: Option<(i64, i64, i64)> = tx
            .query_row(sql::FILE_BY_REL, params![run_id, rel], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        if let Some((file_id, old_size, old_checksum)) = known {
            if (old_size, old_checksum) == (size, checksum) {
                return Ok(outcome(Status::AlreadyIngested, "", 0, 0, String::new()));
            }
            for statement in sql::delete_file_packets() {
                tx.execute(&statement, params![file_id])?;
            }
            for statement in sql::DELETE_FILE {
                tx.execute(statement, params![file_id])?;
            }
        }

        let (format, mut file) = open_sniffed(path)?;
        let decoder = decoder_for(format, config);
        if format != Format::Text && decoder.is_none() {
            // Nothing to store. Keep the removal of an earlier version, if any.
            tx.commit()?;
            let note = match format {
                Format::Gzip => "Compressed file that cannot be read, or holds another one",
                Format::Empty => "Empty file",
                _ => "Unrecognised format",
            };
            let mut result = outcome(Status::NotReadable, format.name(), 0, 0, note.to_string());
            result.removed = known.is_some();
            return Ok(result);
        }

        let source = config.source_for(rel);
        tx.execute(
            sql::INSERT_FILE,
            params![
                run_id,
                path.to_string_lossy(),
                rel,
                source.name,
                format.name(),
                size,
                checksum
            ],
        )?;
        let file_id = tx.last_insert_rowid();
        let mut lanes = Lanes::new(run_id, &source.name);
        // The file's packets are numbered from here, with no gaps.
        let first_packet: i64 = tx.query_row(sql::NEXT_PACKET_ID, [], |r| r.get(0))?;

        let (packets, entries, note) = match decoder {
            Some(decoder) => {
                let (packets, note) = ingest_packets(
                    &tx, &mut file, decoder, config, file_id, run_id, &source, &mut lanes,
                )?;
                (packets, 0, note)
            }
            None => {
                let assembler = Assembler::new(config.log_format_for(rel, source.utc_offset_s));
                let entries = ingest_text(&tx, &mut file, file_id, &source, assembler, &mut lanes)?;
                (0, entries, String::new())
            }
        };
        // How the content was reached, what it says about itself and how
        // reading ended, then why the compressed data gave out, if it did.
        let fault = file
            .fault()
            .map(|why| format!("Compressed data unreadable past this point: {why}"));
        let note: Vec<String> = file
            .is_gzip()
            .then(|| "gzip".to_string())
            .into_iter()
            .chain((!note.is_empty()).then_some(note))
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
                packets as i64,
                entries as i64,
                note,
                (packets > 0).then_some(first_packet),
                (packets > 0).then(|| first_packet + packets as i64 - 1),
                file_id
            ],
        )?;
        tx.commit()?;
        Ok(outcome(
            Status::Ingested,
            format.name(),
            packets,
            entries,
            note,
        ))
    }
}

/// Looks up or creates lane ids for one file's source.
struct Lanes<'a> {
    run_id: i64,
    source: &'a str,
    known: HashMap<LaneKey, i64>,
}

impl<'a> Lanes<'a> {
    fn new(run_id: i64, source: &'a str) -> Self {
        Self {
            run_id,
            source,
            known: HashMap::new(),
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

#[allow(clippy::too_many_arguments)]
fn ingest_packets(
    conn: &Connection,
    file: &mut Source,
    decoder: Box<dyn Decoder>,
    config: &Config,
    file_id: i64,
    run_id: i64,
    source: &SourceInfo,
    lanes: &mut Lanes<'_>,
) -> Result<(u64, String)> {
    let base_id: i64 = conn.query_row(sql::NEXT_PACKET_ID, [], |r| r.get(0))?;
    let mut insert = conn.prepare_cached(sql::INSERT_PACKET)?;
    let mut insert_value = conn.prepare_cached(sql::INSERT_VALUE)?;
    let mut check = FileCheck::new(config, source);
    let mut end = None;
    // How many numbers were kept of each field of each lane, for the list
    // of what the run has to plot.
    let mut series: HashMap<(i64, &str, &str), i64> = HashMap::new();

    let mut records = Records::new(BufReader::new(file), decoder);
    for item in &mut records {
        let record = match item {
            Ok(record) => record,
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(ReadError::Decode(e)) => {
                end = Some(e);
                break;
            }
        };
        let Seen { row, values } = check.observe(&record);
        let packet_id = base_id + row.idx;
        let lane_id = lanes.id(conn, row.lane())?;
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
            row.label,
        ])?;
        // After the packet's own row, which these rows point at.
        for v in values {
            insert_value.execute(params![
                packet_id, file_id, v.packet, v.field, v.num, v.text
            ])?;
            if v.num.is_some() {
                *series.entry((lane_id, v.packet, v.field)).or_default() += 1;
            }
        }
    }
    let mut insert_series = conn.prepare_cached(sql::INSERT_FILE_SERIES)?;
    for ((lane_id, packet, field), count) in series {
        insert_series.execute(params![file_id, lane_id, packet, field, count])?;
    }

    let report = check.finish();
    let findings = report.findings(&records.notices(), end.as_ref());
    let mut insert_finding = conn.prepare_cached(sql::INSERT_FINDING)?;
    for finding in &findings {
        let lane_id = match finding.lane {
            Some(key) => Some(lanes.id(conn, key)?),
            None => None,
        };
        let packet_id = finding
            .packet
            .and_then(|i| i64::try_from(i).ok())
            .map(|i| base_id + i);
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
    // What the file says about itself, then why reading stopped early.
    let note: Vec<String> = records
        .describe()
        .into_iter()
        .chain(end.map(|e| e.to_string()))
        .collect();
    Ok((report.records, note.join("; ")))
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

fn cross_findings(
    conn: &Connection,
    run_id: i64,
    phases: &mut Phases,
) -> Result<Vec<CrossFinding>> {
    let mut out = Vec::new();

    // Every pair is compared in one query; the findings are then made in
    // the order the pairs are listed, which is the order they are stored in.
    // A run from one source has no pairs, and its packets are not read.
    let pairs = run_query(conn, &sql::lane_pairs(run_id), usize::MAX)?;
    if pairs.rows.is_empty() {
        return Ok(out);
    }
    conn.execute_batch(sql::HOP_UNSTAGE)?;
    for q in sql::hop_stage(run_id) {
        conn.execute(&q.sql, params_from_iter(q.params.iter().map(bind)))?;
    }
    phases.mark("indexing packets by content");
    let compared = run_query(conn, &sql::hop_compare_all(run_id), usize::MAX)?.rows;
    let compared: HashMap<(i64, i64), &Vec<Cell>> = compared
        .iter()
        .filter_map(|r| Some(((r[0].int()?, r[1].int()?), r)))
        .collect();
    for row in &pairs.rows {
        let (Some(a), Some(source_a), Some(b), Some(source_b)) =
            (row[0].int(), row[1].text(), row[2].int(), row[3].text())
        else {
            continue;
        };
        if let Some(r) = compared.get(&(a, b)) {
            let shared = r[2].int().unwrap_or(0);
            let missing = r[3].int().unwrap_or(0);
            out.extend(hop_finding(
                a,
                source_a,
                source_b,
                shared,
                missing,
                r[4].int(),
            ));
        }
    }

    phases.mark("comparing sources");
    let mixed = run_query(
        conn,
        &sql::lanes_with_finding(run_id, Kind::Interleaved.name()),
        usize::MAX,
    )?;
    for row in &mixed.rows {
        let (Some(lane), Some(apid), Some(ptype)) = (row[0].int(), row[2].int(), row[3].int())
        else {
            continue;
        };
        let origins = run_query(
            conn,
            &sql::lane_origins(run_id, lane, apid, ptype),
            usize::MAX,
        )?;
        let list: Vec<(String, i64)> = origins
            .rows
            .iter()
            .filter_map(|r| Some((r[0].text()?.to_string(), r[1].int()?)))
            .collect();
        out.extend(origin_finding(lane, row[4].int(), &list));
    }
    phases.mark("tracing interleaved streams");
    conn.execute_batch(sql::HOP_UNSTAGE)?;
    Ok(out)
}
