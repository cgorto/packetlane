//! The tables `packets` and `field_values`, served from the segment files.
//!
//! Both are eponymous-only virtual tables: the store registers them on every
//! connection it opens, and nothing about them is written into the database
//! file, so a stock `sqlite3` opens the file and sees every other table.
//! They have the columns, types and meaning the SQLite tables of the same
//! names had (see `pure::segment` for where each column comes from), and
//! the views that name them are unchanged.
//!
//! # Which segments
//!
//! The store reads the list of segments (the `segments` and `segment_lanes`
//! rows) inside the read transaction a statement runs in, before it runs,
//! and hands it to the tables through [`Shared`]; every cursor of the
//! statement takes that list. A segment the list names that is gone, or
//! whose first packet is not the one listed, was replaced since: the cursor
//! fails, says so through [`Shared::take_stale`], and the store runs the
//! whole statement once more on a fresh list. No row is ever made up from a
//! segment other than the one listed.
//!
//! # Plans
//!
//! Constraints are only ever used to skip what cannot match: SQLite is
//! never told it may omit its own check, so it tests every row it gets. A
//! constraint whose value has a type the plan does not expect (`id = '7'`,
//! `field = 5`, a text compared under another collation) is not used.
//!
//! `packets` is read in id order, either way, segment after segment,
//! skipping segments by their listed id range, file, lanes and time ranges;
//! a single id is a binary search on the listed ranges and one read, and
//! the block of records it read is kept for the next lookup, so a join that
//! looks packets up in id order reads each block once. Or it is read from
//! the segments' time-order sections, merged by time and then id, either
//! way up: for a range of receive or packet time, or for an order by one.
//! Packets without that time are not in those sections; with no range to
//! rule them out they are read from the packet records, first when the
//! order is ascending and last when it is descending, as SQLite orders
//! nulls. Rows read in time order fetch their packet record only for a
//! column that needs it. An order is claimed only when it is the one
//! produced across all segments: id ascending or descending, or a time
//! clock either way followed by id either way.
//!
//! `field_values` is read in packet order from the segments' values
//! sections: a range of packets found by binary search, segments without
//! a series of the packet and field asked for skipped, the others read
//! whole and their values tested by series and number. With a field and a
//! range of numbers asked for, the values between those numbers are first
//! counted in the series' value order (two binary searches a series); if
//! there are at most 64 K of them they are gathered from there, put in
//! packet order and handed out, so that a narrow range costs what it holds.
//! Or, with a field asked for and an order by number (either way, then
//! packet id either way), it is read from the value order of every series
//! the field (and packet) names in every segment, between the bounds on the
//! number, merged: values without a number first when ascending and last
//! when descending, as SQLite orders nulls; runs of one number turned round
//! where packet ids go the other way. Its rowid is the segment's place in
//! the list and the value's place in the segment, unique within a
//! statement; the rowids the SQLite table had are kept nowhere.
//!
//! Each read checks the time limit of the connection now and then, since
//! SQLite's progress handler does not run while a table reads without
//! returning a row.
//!
//! # Safety
//!
//! rusqlite's traits for a virtual table and its cursor are `unsafe` to
//! implement: SQLite hands back pointers to the structs, which it treats as
//! its own `sqlite3_vtab` and `sqlite3_vtab_cursor`. That is the only
//! `unsafe` here: four `unsafe impl`s, one for each table and each cursor,
//! each saying why it holds.
//! Nothing in a callback may panic, since a panic cannot cross into C: each
//! body is run under `catch_unwind` and a panic becomes an error.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::ffi::{CStr, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use rusqlite::types::ValueRef;
use rusqlite::vtab::{
    Context, Filters, IndexConstraintOp, IndexFlags, IndexInfo, Module, VTab, VTabConfig,
    VTabConnection, VTabCursor, sqlite3_vtab, sqlite3_vtab_cursor,
};
use rusqlite::{Connection, Error as SqlError};

use crate::pure::segment::{
    KIND_PACKETS, KIND_TIME, KIND_VALUE_ORDER, KIND_VALUES, PACKET_BYTES, PacketRecord, TIME_BYTES,
    TimeRecord, VALUE_BYTES, VALUE_ORDER_BYTES, ValueGroup, ValueOrderRecord, ValueRecord,
    number_key,
};
use crate::pure::sql::{self, Clock};
use crate::shell::segment::Segment;

type VResult<T> = rusqlite::Result<T>;

/// Buffer each reader of a section reads through, at most.
const SCAN_BUFFER: usize = 64 << 10;
/// What all the readers of one merge may hold together, about.
const MERGE_BUFFERS: usize = 4 << 20;
/// Records read between two looks at the clock.
const TICK: u32 = 4096;

fn fail(message: impl Into<String>) -> SqlError {
    SqlError::ModuleError(message.into())
}

/// Runs a callback body, turning a panic into an error.
fn guard<T>(f: impl FnOnce() -> VResult<T>) -> VResult<T> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(fail("internal error reading the segment files")))
}

// ---- what a statement reads -----------------------------------------------------

/// What the tables of one connection share with the store that opened it.
pub struct Shared {
    folder: PathBuf,
    /// Set once a statement on the connection has named either table.
    used: AtomicBool,
    /// Set when a listed segment was found replaced.
    stale: AtomicBool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    manifest: Option<Arc<Manifest>>,
    deadline: Option<Instant>,
}

impl Shared {
    pub fn new(folder: PathBuf) -> Arc<Shared> {
        Arc::new(Shared {
            folder,
            used: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            state: Mutex::new(State::default()),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// No statement may read past this time.
    pub fn set_deadline(&self, deadline: Instant) {
        self.state().deadline = Some(deadline);
    }

    /// Whether a statement on this connection has named either table, so
    /// that statements need the list of segments.
    pub fn used(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    /// Whether the list of segments has been read for this statement.
    pub fn loaded(&self) -> bool {
        self.state().manifest.is_some()
    }

    /// Drops the list of segments read for the statement before.
    pub fn forget(&self) {
        self.state().manifest = None;
        self.stale.store(false, Ordering::Relaxed);
    }

    /// Reads the list of segments, on the connection and in the
    /// transaction the statement runs in.
    pub fn load(&self, conn: &Connection) -> crate::shell::store::Result<()> {
        let manifest = Manifest::load(conn)?;
        self.state().manifest = Some(Arc::new(manifest));
        Ok(())
    }

    /// Whether a listed segment was found replaced since the last call.
    pub fn take_stale(&self) -> bool {
        self.stale.swap(false, Ordering::Relaxed)
    }

    fn snapshot(&self) -> (Option<Arc<Manifest>>, Option<Instant>) {
        let state = self.state();
        (state.manifest.clone(), state.deadline)
    }

    fn stats(&self) -> Stats {
        self.state()
            .manifest
            .as_ref()
            .map_or_else(Stats::guess, |m| m.stats)
    }
}

/// Registers both tables on a connection.
pub fn register(conn: &Connection, shared: &Arc<Shared>) -> rusqlite::Result<()> {
    const PACKETS: Module<PacketsTab> = Module::eponymous_only_module();
    const VALUES: Module<ValuesTab> = Module::eponymous_only_module();
    conn.create_module(c"packets", &PACKETS, Some(Arc::clone(shared)))?;
    conn.create_module(c"field_values", &VALUES, Some(Arc::clone(shared)))
}

/// What the planner is told about sizes.
#[derive(Debug, Clone, Copy)]
struct Stats {
    packets: f64,
    values: f64,
    segments: f64,
    lanes: f64,
    /// Segments a lane is found in, on average.
    lane_segments: f64,
    /// Packets with a time on each time clock.
    timed: [f64; 2],
}

impl Stats {
    /// Sizes when no list has been read yet.
    fn guess() -> Stats {
        Stats {
            packets: 1e6,
            values: 2e6,
            segments: 1.0,
            lanes: 10.0,
            lane_segments: 1.0,
            timed: [1e6, 1e6],
        }
    }
}

/// The segments a statement reads, as listed when it started.
struct Manifest {
    segs: Vec<Seg>,
    stats: Stats,
}

struct Seg {
    file_id: i64,
    name: String,
    first: i64,
    last: i64,
    /// Lowest and highest receive and packet time.
    times: [Option<(i64, i64)>; 2],
    /// Packets with a receive and a packet time.
    timed: [u64; 2],
    /// Lanes it holds packets of, in order.
    lanes: Vec<i64>,
    opened: OnceLock<Arc<Opened>>,
}

impl Seg {
    fn packets(&self) -> u64 {
        u64::try_from(self.last - self.first + 1).unwrap_or(0)
    }

    fn has_lane(&self, lane: i64) -> bool {
        self.lanes.binary_search(&lane).is_ok()
    }
}

impl Manifest {
    fn load(conn: &Connection) -> crate::shell::store::Result<Manifest> {
        let mut segs: Vec<Seg> = Vec::new();
        let mut at: HashMap<i64, usize> = HashMap::new();
        {
            let mut stmt = conn.prepare_cached(sql::MANIFEST_SEGMENTS)?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let time = |lo: usize| -> rusqlite::Result<Option<(i64, i64)>> {
                    Ok(match (r.get(lo)?, r.get(lo + 1)?) {
                        (Some(a), Some(b)) => Some((a, b)),
                        _ => None,
                    })
                };
                let seg = Seg {
                    file_id: r.get(0)?,
                    name: r.get(1)?,
                    first: r.get(2)?,
                    last: r.get(3)?,
                    times: [time(4)?, time(6)?],
                    timed: [0, 0],
                    lanes: Vec::new(),
                    opened: OnceLock::new(),
                };
                if seg.last < seg.first || seg.last.checked_sub(seg.first).is_none() {
                    return Err(format!("segment {} lists no packets", seg.name).into());
                }
                at.insert(seg.file_id, segs.len());
                segs.push(seg);
            }
        }
        let mut lanes = HashSet::new();
        let mut entries = 0f64;
        {
            let mut stmt = conn.prepare_cached(sql::MANIFEST_LANES)?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let file: i64 = r.get(0)?;
                let lane: i64 = r.get(1)?;
                let (receive, packet): (i64, i64) = (r.get(2)?, r.get(3)?);
                if let Some(seg) = at.get(&file).and_then(|&i| segs.get_mut(i)) {
                    seg.lanes.push(lane);
                    seg.timed[0] += u64::try_from(receive).unwrap_or(0);
                    seg.timed[1] += u64::try_from(packet).unwrap_or(0);
                    lanes.insert(lane);
                    entries += 1.0;
                }
            }
        }
        for seg in &mut segs {
            seg.lanes.sort_unstable();
        }
        let values: i64 = conn
            .prepare_cached(sql::MANIFEST_VALUES)?
            .query_row([], |r| r.get(0))?;
        let packets: f64 = segs.iter().map(|s| s.packets() as f64).sum();
        let timed = |c: usize| segs.iter().map(|s| s.timed[c] as f64).sum::<f64>();
        let lanes = lanes.len().max(1) as f64;
        let stats = Stats {
            packets,
            values: values.max(0) as f64,
            segments: segs.len() as f64,
            lanes,
            lane_segments: (entries / lanes).max(1.0),
            timed: [timed(0), timed(1)],
        };
        Ok(Manifest { segs, stats })
    }

    /// The segment holding a packet id.
    fn holding(&self, id: i64) -> Option<usize> {
        let at = self.segs.partition_point(|s| s.last < id);
        self.segs.get(at).filter(|s| s.first <= id).map(|_| at)
    }
}

/// A segment opened for a statement, with what is read from it once.
struct Opened {
    seg: Segment,
    labels: OnceLock<Vec<String>>,
    names: OnceLock<Vec<(String, String)>>,
    groups: OnceLock<Vec<ValueGroup>>,
}

impl Opened {
    fn labels(&self) -> VResult<&[String]> {
        if let Some(l) = self.labels.get() {
            return Ok(l);
        }
        let read = self.seg.labels().map_err(|e| fail(e.to_string()))?;
        Ok(self.labels.get_or_init(|| read))
    }

    fn names(&self) -> VResult<&[(String, String)]> {
        if let Some(n) = self.names.get() {
            return Ok(n);
        }
        let read = self.seg.series_names().map_err(|e| fail(e.to_string()))?;
        Ok(self.names.get_or_init(|| read))
    }

    fn groups(&self) -> VResult<&[ValueGroup]> {
        if let Some(g) = self.groups.get() {
            return Ok(g);
        }
        let read = self.seg.value_groups().map_err(|e| fail(e.to_string()))?;
        Ok(self.groups.get_or_init(|| read))
    }

    /// Which series match a packet name and a field name asked for, by
    /// number; all if neither is asked for.
    fn matching(&self, packet: Option<&str>, field: Option<&str>) -> VResult<Vec<bool>> {
        Ok(self
            .names()?
            .iter()
            .map(|(p, f)| packet.is_none_or(|w| w == p) && field.is_none_or(|w| w == f))
            .collect())
    }
}

/// What every cursor holds: the list it reads, and its limits.
struct Reading {
    shared: Arc<Shared>,
    manifest: Arc<Manifest>,
    deadline: Option<Instant>,
    ticks: u32,
}

impl Reading {
    fn start(shared: &Arc<Shared>) -> VResult<Reading> {
        let (manifest, deadline) = shared.snapshot();
        let manifest = manifest.ok_or_else(|| fail("the list of segments was not read"))?;
        Ok(Reading {
            shared: Arc::clone(shared),
            manifest,
            deadline,
            ticks: 0,
        })
    }

    /// Fails once the statement's time is up; looks at the clock only now
    /// and then.
    fn tick(&mut self) -> VResult<()> {
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks.is_multiple_of(TICK)
            && let Some(deadline) = self.deadline
            && Instant::now() > deadline
        {
            return Err(fail(
                "Statement took longer than the time limit; narrow it down",
            ));
        }
        Ok(())
    }

    /// Opens a listed segment, once per statement, checking it is the one
    /// listed.
    fn open(&self, at: usize) -> VResult<Arc<Opened>> {
        let seg = self
            .manifest
            .segs
            .get(at)
            .ok_or_else(|| fail("no such segment"))?;
        if let Some(o) = seg.opened.get() {
            return Ok(Arc::clone(o));
        }
        let path = self.shared.folder.join(&seg.name);
        let segment = match Segment::open(&path) {
            Ok(s) => s,
            Err(e) => {
                if !path.exists() {
                    self.shared.stale.store(true, Ordering::Relaxed);
                    return Err(fail(format!("{}: gone since it was listed", seg.name)));
                }
                return Err(fail(e.to_string()));
            }
        };
        if segment.first_packet() != seg.first || segment.packets() != seg.packets() {
            self.shared.stale.store(true, Ordering::Relaxed);
            return Err(fail(format!("{}: replaced since it was listed", seg.name)));
        }
        let opened = Arc::new(Opened {
            seg: segment,
            labels: OnceLock::new(),
            names: OnceLock::new(),
            groups: OnceLock::new(),
        });
        Ok(Arc::clone(seg.opened.get_or_init(|| opened)))
    }
}

/// Fixed-width records from one range of a segment, through a buffer,
/// first to last or last to first.
struct Records<const N: usize> {
    opened: Arc<Opened>,
    /// The range, in bytes: `start..end`, a whole number of records.
    start: u64,
    end: u64,
    back: bool,
    cap: usize,
    buf: Vec<u8>,
    at: usize,
}

impl<const N: usize> Records<N> {
    /// Records from `start` up to `end`.
    fn new(opened: Arc<Opened>, start: u64, end: u64, buffer: usize) -> Self {
        Self::make(opened, start, end, buffer, false)
    }

    /// Records from the one before `end` down to `start`.
    fn back(opened: Arc<Opened>, start: u64, end: u64, buffer: usize) -> Self {
        Self::make(opened, start, end, buffer, true)
    }

    fn make(opened: Arc<Opened>, start: u64, end: u64, buffer: usize, back: bool) -> Self {
        let span = end.saturating_sub(start) / N as u64;
        let records = ((buffer / N).max(1) as u64).min(span.max(1));
        let cap = usize::try_from(records).unwrap_or(1).saturating_mul(N);
        Records {
            opened,
            start,
            end: start.saturating_add(span.saturating_mul(N as u64)),
            back,
            cap,
            buf: Vec::new(),
            at: 0,
        }
    }

    /// Where the reader stands, in bytes: the start of the next record
    /// when reading first to last, the end of it when reading last to
    /// first.
    fn boundary(&self) -> u64 {
        if self.back {
            self.end.saturating_add(self.at as u64)
        } else {
            self.start
                .saturating_sub(self.buf.len().saturating_sub(self.at) as u64)
        }
    }

    fn fill(&mut self, from: u64, want: usize) -> VResult<()> {
        self.buf.resize(want, 0);
        self.opened
            .seg
            .read_at(&mut self.buf, from)
            .map_err(|e| fail(format!("reading a segment: {e}")))
    }

    fn read(&mut self) -> VResult<Option<[u8; N]>> {
        let mut record = [0u8; N];
        if self.back {
            if self.at == 0 {
                let left = self.end.saturating_sub(self.start);
                if left == 0 {
                    return Ok(None);
                }
                let want = usize::try_from(left).unwrap_or(usize::MAX).min(self.cap);
                let from = self.end.saturating_sub(want as u64);
                self.fill(from, want)?;
                self.end = from;
                self.at = want;
            }
            let Some(at) = self.at.checked_sub(N) else {
                return Ok(None);
            };
            let Some(src) = self.buf.get(at..at + N) else {
                return Ok(None);
            };
            record.copy_from_slice(src);
            self.at = at;
            return Ok(Some(record));
        }
        if self.at >= self.buf.len() {
            let left = self.end.saturating_sub(self.start);
            if left == 0 {
                return Ok(None);
            }
            let want = usize::try_from(left).unwrap_or(usize::MAX).min(self.cap);
            self.fill(self.start, want)?;
            self.start = self.start.saturating_add(want as u64);
            self.at = 0;
        }
        let Some(src) = self.buf.get(self.at..self.at.saturating_add(N)) else {
            return Ok(None);
        };
        record.copy_from_slice(src);
        self.at += N;
        Ok(Some(record))
    }
}

/// Records of a sorted section read through [`Records`], with each run of
/// records of equal key handed out in the other order than the reader
/// reads them, if asked: last to first within the run when reading first
/// to last, and the other way. A run of up to `cap` records is held; a
/// longer one is read again, the other way, by a second reader over just
/// its range, so memory stays the same however long a run is.
struct TieReader<const N: usize> {
    reader: Records<N>,
    reverse: bool,
    key: fn(&[u8; N]) -> u64,
    cap: usize,
    /// The run being handed out, last record first.
    run: Vec<[u8; N]>,
    /// The first record of the next run, and where the reader stood before
    /// it.
    peeked: Option<([u8; N], u64)>,
    /// A run too long to hold, read the other way.
    long: Option<Records<N>>,
}

impl<const N: usize> TieReader<N> {
    fn new(reader: Records<N>, reverse: bool, key: fn(&[u8; N]) -> u64, cap: usize) -> Self {
        TieReader {
            reader,
            reverse,
            key,
            cap: cap.max(1),
            run: Vec::new(),
            peeked: None,
            long: None,
        }
    }

    fn read(&mut self) -> VResult<Option<[u8; N]>> {
        if !self.reverse {
            return self.reader.read();
        }
        if let Some(long) = &mut self.long {
            match long.read()? {
                Some(r) => return Ok(Some(r)),
                None => self.long = None,
            }
        }
        if let Some(r) = self.run.pop() {
            return Ok(Some(r));
        }
        let (first, from) = match self.peeked.take() {
            Some(p) => p,
            None => {
                let at = self.reader.boundary();
                match self.reader.read()? {
                    Some(r) => (r, at),
                    None => return Ok(None),
                }
            }
        };
        let key = (self.key)(&first);
        self.run.push(first);
        let mut held = true;
        let to = loop {
            let at = self.reader.boundary();
            match self.reader.read()? {
                None => break at,
                Some(r) if (self.key)(&r) != key => {
                    self.peeked = Some((r, at));
                    break at;
                }
                Some(r) if self.run.len() < self.cap => self.run.push(r),
                Some(_) => held = false,
            }
        };
        if held {
            return Ok(self.run.pop());
        }
        self.run.clear();
        let opened = Arc::clone(&self.reader.opened);
        let buffer = self.reader.cap;
        let mut long = if self.reader.back {
            Records::new(opened, to, from, buffer)
        } else {
            Records::back(opened, from, to, buffer)
        };
        let first = long.read()?;
        self.long = Some(long);
        Ok(first)
    }
}

// ---- constraints ------------------------------------------------------------------

/// How a constraint compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    fn of(op: IndexConstraintOp) -> Option<Op> {
        match op {
            IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_EQ => Some(Op::Eq),
            IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_GT => Some(Op::Gt),
            IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_GE => Some(Op::Ge),
            IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_LT => Some(Op::Lt),
            IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_LE => Some(Op::Le),
            _ => None,
        }
    }

    fn code(self) -> char {
        match self {
            Op::Eq => '=',
            Op::Gt => '>',
            Op::Ge => 'g',
            Op::Lt => '<',
            Op::Le => 'l',
        }
    }

    fn from_code(c: char) -> Option<Op> {
        match c {
            '=' => Some(Op::Eq),
            '>' => Some(Op::Gt),
            'g' => Some(Op::Ge),
            '<' => Some(Op::Lt),
            'l' => Some(Op::Le),
            _ => None,
        }
    }
}

/// The constraints a plan passes to `filter`: for each argument, a column
/// letter and an operator code, in argument order.
fn decode_plan(idx_str: Option<&str>) -> Vec<(char, Op)> {
    let chars: Vec<char> = idx_str.unwrap_or("").chars().collect();
    chars
        .chunks_exact(2)
        .filter_map(|p| Some((*p.first()?, Op::from_code(*p.get(1)?)?)))
        .collect()
}

/// An inclusive range of integers, narrowed by constraints; values of an
/// unexpected type leave it as it is, so it only ever holds more than
/// matches, never less.
#[derive(Debug, Clone, Copy)]
struct Range {
    lo: i64,
    hi: i64,
    /// Whether any constraint applied, which rules out nulls.
    bounded: bool,
    empty: bool,
}

impl Range {
    fn all() -> Range {
        Range {
            lo: i64::MIN,
            hi: i64::MAX,
            bounded: false,
            empty: false,
        }
    }

    fn narrow(&mut self, op: Op, v: ValueRef<'_>) {
        let (lo, hi) = match v {
            ValueRef::Null => {
                // A comparison with null is never true.
                self.empty = true;
                return;
            }
            ValueRef::Integer(v) => (v, v),
            // Beyond what an i64 holds, a real bounds nothing here; SQLite
            // still compares it.
            ValueRef::Real(f) if f.abs() < 9.2e18 => (f.floor() as i64, f.ceil() as i64),
            _ => return,
        };
        self.bounded = true;
        match op {
            Op::Eq => {
                self.lo = self.lo.max(lo);
                self.hi = self.hi.min(hi);
            }
            Op::Gt => match lo.checked_add(i64::from(lo == hi)) {
                Some(v) => self.lo = self.lo.max(v),
                None => self.empty = true,
            },
            Op::Ge => self.lo = self.lo.max(lo),
            Op::Lt => match hi.checked_sub(i64::from(lo == hi)) {
                Some(v) => self.hi = self.hi.min(v),
                None => self.empty = true,
            },
            Op::Le => self.hi = self.hi.min(hi),
        }
        if self.lo > self.hi {
            self.empty = true;
        }
    }

    fn holds(&self, v: i64) -> bool {
        (self.lo..=self.hi).contains(&v)
    }

    fn holds_opt(&self, v: Option<i64>) -> bool {
        match v {
            Some(v) => self.holds(v),
            None => !self.bounded,
        }
    }

    fn meets(&self, lo: i64, hi: i64) -> bool {
        lo <= self.hi && hi >= self.lo
    }
}

/// One integer an equality asks for; `None` if none or not usable.
#[derive(Debug, Clone, Copy, Default)]
struct Equal {
    value: Option<i64>,
    empty: bool,
}

impl Equal {
    fn narrow(&mut self, v: ValueRef<'_>) {
        let v = match v {
            ValueRef::Null => {
                self.empty = true;
                return;
            }
            ValueRef::Integer(v) => v,
            ValueRef::Real(f) if f.fract() == 0.0 && f.abs() < 9.0e15 => f as i64,
            ValueRef::Real(f) if !f.is_nan() => {
                // No integer equals it.
                self.empty = true;
                return;
            }
            _ => return,
        };
        match self.value {
            Some(old) if old != v => self.empty = true,
            _ => self.value = Some(v),
        }
    }

    fn holds(&self, v: i64) -> bool {
        self.value.is_none_or(|w| w == v)
    }
}

/// A usable constraint a plan takes: its index in SQLite's list, the
/// column letter and the operator.
type Taken = (usize, char, Op);

/// Passes the constraints to `filter`, in order, and returns the plan's
/// description of them.
fn take(info: &mut IndexInfo, taken: &[Taken]) -> VResult<()> {
    let mut code = String::with_capacity(taken.len() * 2);
    for (n, &(i, column, op)) in taken.iter().enumerate() {
        let mut usage = info.constraint_usage(i);
        usage.set_argv_index(c_int::try_from(n + 1).map_err(|_| fail("too many constraints"))?);
        usage.set_omit(false);
        code.push(column);
        code.push(op.code());
    }
    info.set_idx_str(&code);
    Ok(())
}

/// One side of a range costs a quarter of what it narrows, as SQLite
/// reckons for an index.
fn sides(taken: &[Taken], column: char) -> (bool, i32) {
    let mut eq = false;
    let (mut lo, mut hi) = (false, false);
    for &(_, c, op) in taken {
        if c != column {
            continue;
        }
        match op {
            Op::Eq => eq = true,
            Op::Gt | Op::Ge => lo = true,
            Op::Lt | Op::Le => hi = true,
        }
    }
    (eq, i32::from(lo) + i32::from(hi))
}

fn quarter(n: i32) -> f64 {
    0.25f64.powi(n)
}

// ---- packets --------------------------------------------------------------------

const P_ID: c_int = 0;
const P_FILE: c_int = 1;
const P_LANE: c_int = 2;
const P_IDX: c_int = 3;
const P_OFFSET: c_int = 4;
const P_LENGTH: c_int = 5;
const P_RECEIVE: c_int = 6;
const P_PACKET: c_int = 7;
const P_APID: c_int = 8;
const P_PTYPE: c_int = 9;
const P_SEQ: c_int = 10;
const P_SUM: c_int = 11;
const P_LABEL: c_int = 12;

/// How a `packets` plan reads, kept in its plan number: in id order or in
/// order of a time clock (and then id), which way, and whether rows need
/// their packet records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Access {
    /// `None` for id order, else the time clock (0 receive, 1 packet).
    clock: Option<usize>,
    desc: bool,
    /// For a time order, whether packets of equal time come by id
    /// descending.
    ties_desc: bool,
    records: bool,
}

impl Access {
    fn encode(self) -> c_int {
        let by = match self.clock {
            None => 0,
            Some(0) => 1,
            Some(_) => 2,
        };
        by | c_int::from(self.desc) << 2
            | c_int::from(self.ties_desc) << 3
            | c_int::from(self.records) << 4
    }

    fn decode(n: c_int) -> Access {
        Access {
            clock: match n & 3 {
                1 => Some(0),
                2 => Some(1),
                _ => None,
            },
            desc: n & 4 != 0,
            ties_desc: n & 8 != 0,
            records: n & 16 != 0,
        }
    }
}

fn is_id(column: c_int) -> bool {
    column == -1 || column == P_ID
}

#[repr(C)]
struct PacketsTab {
    /// SQLite's part; must come first.
    base: sqlite3_vtab,
    shared: Arc<Shared>,
}

// SAFETY: `PacketsTab` is `#[repr(C)]` with `sqlite3_vtab` as its first
// field, which is what the trait requires: rusqlite boxes the value and
// hands SQLite a pointer to it as a `sqlite3_vtab`, and casts it back.
unsafe impl<'vtab> VTab<'vtab> for PacketsTab {
    type Aux = Arc<Shared>;
    type Cursor = PacketsCursor;

    fn connect(
        db: &mut VTabConnection,
        aux: Option<&Arc<Shared>>,
        _module: &[u8],
        _database: &[u8],
        _table: &[u8],
        _args: &[&[u8]],
    ) -> VResult<(Cow<'static, CStr>, Self)> {
        guard(|| {
            let shared = aux.ok_or_else(|| fail("packets: no store"))?;
            db.config(VTabConfig::Innocuous)?;
            Ok((
                Cow::Borrowed(
                    c"CREATE TABLE x(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL,
                      lane_id INTEGER NOT NULL, idx INTEGER NOT NULL, offset INTEGER NOT NULL,
                      length INTEGER NOT NULL, receive_ns INTEGER, packet_ns INTEGER,
                      apid INTEGER, ptype INTEGER, seq INTEGER, sum INTEGER NOT NULL, label TEXT)",
                ),
                PacketsTab {
                    base: sqlite3_vtab::default(),
                    shared: Arc::clone(shared),
                },
            ))
        })
    }

    fn best_index(&self, info: &mut IndexInfo) -> VResult<bool> {
        guard(|| {
            self.shared.used.store(true, Ordering::Relaxed);
            let stats = self.shared.stats();
            let mut taken: Vec<Taken> = Vec::new();
            for (i, c) in info.constraints().enumerate() {
                if !c.is_usable() {
                    continue;
                }
                let Some(op) = Op::of(c.operator()) else {
                    continue;
                };
                let column = match c.column() {
                    -1 | P_ID => 'i',
                    P_FILE if op == Op::Eq => 'f',
                    P_LANE if op == Op::Eq => 'l',
                    P_RECEIVE => 'r',
                    P_PACKET => 'p',
                    _ => continue,
                };
                taken.push((i, column, op));
            }
            let n = stats.packets.max(1.0);
            let segments = stats.segments.max(1.0);
            let (id_eq, id_sides) = sides(&taken, 'i');
            let file_eq = sides(&taken, 'f').0;
            let lane_eq = sides(&taken, 'l').0;
            let file_part = if file_eq { 1.0 / segments } else { 1.0 };
            let lane_part = if lane_eq {
                (stats.lane_segments / segments).min(1.0)
            } else {
                1.0
            };
            let time_part = |column: char| {
                let (eq, s) = sides(&taken, column);
                if eq { 1e-6 } else { quarter(s) }
            };
            let out = (n
                * if id_eq { 1.0 / n } else { quarter(id_sides) }
                * file_part
                * if lane_eq {
                    1.0 / stats.lanes.max(1.0)
                } else {
                    1.0
                }
                * time_part('r')
                * time_part('p'))
            .max(1.0);
            // What a row needs beyond its id, file and index: its packet
            // record, or for a time order beyond its time and lane too.
            let used = info.col_used();
            let mask = |columns: &[c_int]| columns.iter().fold(0u64, |m, &c| m | (1u64 << c));
            let needs = |free: &[c_int]| used & !mask(free) != 0;
            let filtered =
                lane_eq || sides(&taken, 'r') != (false, 0) || sides(&taken, 'p') != (false, 0);
            let asked: Vec<(c_int, bool)> = info
                .order_bys()
                .map(|o| (o.column(), o.is_order_by_desc()))
                .collect();

            // In id order.
            let id_scan = if id_eq {
                1.0
            } else {
                n * quarter(id_sides) * file_part * lane_part
            };
            let by_id_order = asked.first().filter(|(c, _)| is_id(*c));
            let mut access = Access {
                clock: None,
                desc: by_id_order.is_some_and(|o| o.1),
                ties_desc: false,
                records: filtered || needs(&[P_ID, P_FILE, P_IDX]),
            };
            let mut cost = id_scan + if id_eq { segments.log2() + 1.0 } else { 0.0 };
            let mut ordered = by_id_order.is_some();
            // In time order, when a range asks for it or the order does.
            for (column, code, c) in [(P_RECEIVE, 'r', 0usize), (P_PACKET, 'p', 1usize)] {
                let (eq, s) = sides(&taken, code);
                let bounded = eq || s > 0;
                let order = match asked.as_slice() {
                    [(t, desc)] if *t == column => Some((*desc, *desc)),
                    [(t, desc), (id, ties), ..] if *t == column && is_id(*id) => {
                        Some((*desc, *ties))
                    }
                    _ => None,
                };
                if !bounded && order.is_none() {
                    continue;
                }
                let timed = stats.timed.get(c).copied().unwrap_or(n);
                let mut scan = timed * time_part(code) * file_part * lane_part;
                if !bounded {
                    // Packets without the time are read too, in id order.
                    scan += (n - timed).max(0.0);
                }
                let records = needs(&[P_ID, P_FILE, P_LANE, P_IDX, column]);
                let here = scan * 1.2 + if records { out } else { 0.0 } + 1.0;
                if here < cost || (order.is_some() && !ordered && here < cost * 4.0) {
                    let (desc, ties_desc) = order.unwrap_or((false, false));
                    access = Access {
                        clock: Some(c),
                        desc,
                        ties_desc,
                        records,
                    };
                    cost = here;
                    ordered = order.is_some();
                }
            }
            take(info, &taken)?;
            info.set_idx_num(access.encode());
            info.set_estimated_cost(cost);
            info.set_estimated_rows(out as i64);
            if access.clock.is_none() && id_eq {
                info.set_idx_flags(IndexFlags::SQLITE_INDEX_SCAN_UNIQUE);
                info.set_estimated_rows(1);
            }
            info.set_order_by_consumed(ordered);
            Ok(true)
        })
    }

    fn open(&'vtab mut self) -> VResult<PacketsCursor> {
        guard(|| {
            Ok(PacketsCursor {
                base: sqlite3_vtab_cursor::default(),
                reading: Reading::start(&self.shared)?,
                source: PacketSource::Done,
                bounds: None,
                row: None,
                block: None,
                plan: None,
            })
        })
    }
}

/// What a `packets` plan is narrowed by.
#[derive(Debug, Clone, Copy)]
struct PacketBounds {
    id: Range,
    file: Equal,
    lane: Equal,
    times: [Range; 2],
}

impl PacketBounds {
    fn read(plan: &[(char, Op)], args: &Filters<'_>) -> PacketBounds {
        let mut b = PacketBounds {
            id: Range::all(),
            file: Equal::default(),
            lane: Equal::default(),
            times: [Range::all(), Range::all()],
        };
        for (&(column, op), v) in plan.iter().zip(args.iter()) {
            match column {
                'i' => b.id.narrow(op, v),
                'f' => b.file.narrow(v),
                'l' => b.lane.narrow(v),
                'r' => b.times[0].narrow(op, v),
                'p' => b.times[1].narrow(op, v),
                _ => {}
            }
        }
        b
    }

    fn empty(&self) -> bool {
        self.id.empty || self.file.empty || self.lane.empty || self.times.iter().any(|t| t.empty)
    }

    /// Whether rows must be read to apply the bounds.
    fn on_records(&self) -> bool {
        self.lane.value.is_some() || self.times.iter().any(|t| t.bounded)
    }

    /// Whether a segment may hold a packet that matches.
    fn may_hold(&self, s: &Seg) -> bool {
        if !self.id.meets(s.first, s.last) || !self.file.holds(s.file_id) {
            return false;
        }
        if let Some(lane) = self.lane.value
            && !s.has_lane(lane)
        {
            return false;
        }
        for (range, times) in self.times.iter().zip(&s.times) {
            if range.bounded {
                match times {
                    Some((lo, hi)) if range.meets(*lo, *hi) => {}
                    _ => return false,
                }
            }
        }
        true
    }

    fn holds(&self, p: &PacketRecord) -> bool {
        self.lane.holds(i64::from(p.lane))
            && self.times[0].holds_opt(p.receive_ns)
            && self.times[1].holds_opt(p.packet_ns)
    }
}

/// The current row of a `packets` cursor.
struct PacketRow {
    id: i64,
    seg: usize,
    lane: Option<u32>,
    /// A time clock's time, when the row came from a time order.
    time: Option<(usize, i64)>,
    record: OnceCell<PacketRecord>,
}

impl PacketRow {
    fn with_record(id: i64, seg: usize, p: PacketRecord) -> PacketRow {
        let lane = Some(p.lane);
        let record = OnceCell::new();
        let _ = record.set(p);
        PacketRow {
            id,
            seg,
            lane,
            time: None,
            record,
        }
    }
}

/// Packets in id order, ascending or descending, from the segments in
/// `segs` (in the order they are visited), within `lo..=hi`.
struct IdScan {
    segs: Vec<usize>,
    next: usize,
    lo: i64,
    hi: i64,
    desc: bool,
    /// Whether packet records are read; if not, rows are only ids.
    records: bool,
    /// Only packets without a time on this clock (the part of a time
    /// order that has none).
    untimed: Option<usize>,
    open: Option<IdOpen>,
}

/// The segment an id scan is in.
struct IdOpen {
    seg: usize,
    /// The next id, and the last one, in the scan's direction.
    id: i64,
    last: i64,
    reader: Option<Records<PACKET_BYTES>>,
}

impl IdScan {
    fn new(segs: Vec<usize>, b: &PacketBounds, desc: bool, records: bool) -> IdScan {
        let mut segs = segs;
        if desc {
            segs.reverse();
        }
        IdScan {
            segs,
            next: 0,
            lo: b.id.lo,
            hi: b.id.hi,
            desc,
            records: records || b.on_records(),
            untimed: None,
            open: None,
        }
    }

    fn enter(&mut self, r: &Reading, at: usize) -> VResult<Option<IdOpen>> {
        let Some(seg) = r.manifest.segs.get(at) else {
            return Ok(None);
        };
        let (lo, hi) = (self.lo.max(seg.first), self.hi.min(seg.last));
        if lo > hi {
            return Ok(None);
        }
        // Opened even when no record is read: it must be the one listed.
        let opened = r.open(at)?;
        let reader = if self.records || self.untimed.is_some() {
            let (offset, _) = opened
                .seg
                .section_bytes(KIND_PACKETS, Clock::Receive)
                .map_err(|e| fail(e.to_string()))?;
            let bytes = |id: i64| {
                u64::try_from(id - seg.first)
                    .ok()
                    .and_then(|i| i.checked_mul(PACKET_BYTES as u64))
                    .and_then(|b| b.checked_add(offset))
            };
            let (Some(start), Some(end)) = (bytes(lo), hi.checked_add(1).and_then(bytes)) else {
                return Err(fail("packet range out of bounds"));
            };
            Some(if self.desc {
                Records::back(opened, start, end, SCAN_BUFFER)
            } else {
                Records::new(opened, start, end, SCAN_BUFFER)
            })
        } else {
            None
        };
        let (id, last) = if self.desc { (hi, lo) } else { (lo, hi) };
        Ok(Some(IdOpen {
            seg: at,
            id,
            last,
            reader,
        }))
    }

    /// Moves a row that is only an id to the next id of the segment it is
    /// in, if this scan reads no records and that id is in range; false
    /// if the row must be made anew.
    fn step_in_place(&mut self, row: &mut PacketRow) -> bool {
        let Some(open) = &mut self.open else {
            return false;
        };
        if open.reader.is_some()
            || row.seg != open.seg
            || row.lane.is_some()
            || row.time.is_some()
            || row.record.get().is_some()
        {
            return false;
        }
        let id = open.id;
        let inside = if self.desc {
            id >= open.last && id > i64::MIN
        } else {
            id <= open.last && id < i64::MAX
        };
        if !inside {
            return false;
        }
        open.id = if self.desc { id - 1 } else { id + 1 };
        row.id = id;
        true
    }

    fn next(&mut self, r: &mut Reading, b: &PacketBounds) -> VResult<Option<PacketRow>> {
        loop {
            r.tick()?;
            let Some(open) = &mut self.open else {
                let Some(&at) = self.segs.get(self.next) else {
                    return Ok(None);
                };
                self.next += 1;
                self.open = self.enter(r, at)?;
                continue;
            };
            let done = if self.desc {
                open.id < open.last
            } else {
                open.id > open.last
            };
            if done {
                self.open = None;
                continue;
            }
            let id = open.id;
            open.id = if self.desc {
                id.saturating_sub(1)
            } else {
                id.saturating_add(1)
            };
            if id == i64::MIN || id == i64::MAX {
                // Never a packet id; and the step above would not move.
                open.last = id;
                open.id = if self.desc { i64::MIN } else { i64::MAX };
            }
            let Some(reader) = &mut open.reader else {
                return Ok(Some(PacketRow {
                    id,
                    seg: open.seg,
                    lane: None,
                    time: None,
                    record: OnceCell::new(),
                }));
            };
            let Some(raw) = reader.read()? else {
                return Err(fail("a segment's packets ended early"));
            };
            let p = PacketRecord::decode(&raw);
            let missing = match self.untimed {
                Some(0) => p.receive_ns.is_some(),
                Some(_) => p.packet_ns.is_some(),
                None => false,
            };
            if missing || !b.holds(&p) {
                continue;
            }
            return Ok(Some(PacketRow::with_record(id, open.seg, p)));
        }
    }
}

/// One segment's time order, read from one end of a window. Packets of
/// equal time come by index ascending when it is read first to last and
/// descending when read last to first; turned round if the order wants the
/// other way.
struct TimeSlot {
    seg: usize,
    first: i64,
    packets: u64,
    reader: TieReader<TIME_BYTES>,
}

/// The time of a time-order record, as the key its ties share.
fn time_key(b: &[u8; TIME_BYTES]) -> u64 {
    TimeRecord::decode(b).ns as u64
}

impl TimeSlot {
    /// The next record in the slot's order.
    fn take(&mut self) -> VResult<Option<TimeRecord>> {
        let Some(raw) = self.reader.read()? else {
            return Ok(None);
        };
        let t = TimeRecord::decode(&raw);
        if u64::from(t.index) >= self.packets {
            return Err(fail("a time record names no packet"));
        }
        Ok(Some(t))
    }
}

/// The next packet of a slot of a time order: its key in the order, time,
/// id, slot and lane.
type Next = ((i64, i64), i64, i64, usize, u32);

/// Packets in order of a time clock and then id, merged across segments.
struct TimeScan {
    clock: usize,
    desc: bool,
    ties_desc: bool,
    /// Packets without the time: first in an ascending order, last in a
    /// descending one; when nothing rules them out.
    untimed: Option<IdScan>,
    slots: Vec<TimeSlot>,
    /// The next packet of each slot: its key in the order, time, id, slot
    /// and lane.
    heap: BinaryHeap<Reverse<Next>>,
    started: bool,
}

impl TimeScan {
    fn key(&self, ns: i64, id: i64) -> (i64, i64) {
        // `!` reverses the order of an i64 without overflow.
        match (self.desc, self.ties_desc) {
            (false, false) => (ns, id),
            (false, true) => (ns, !id),
            (true, false) => (!ns, id),
            (true, true) => (!ns, !id),
        }
    }

    fn advance(&mut self, slot: usize, b: &PacketBounds) -> VResult<()> {
        let range = b.times.get(self.clock).copied().unwrap_or_else(Range::all);
        let Some(s) = self.slots.get_mut(slot) else {
            return Ok(());
        };
        let Some(t) = s.take()? else {
            return Ok(());
        };
        let past = if self.desc {
            t.ns < range.lo
        } else {
            t.ns > range.hi
        };
        if past {
            return Ok(());
        }
        let id = s.first.saturating_add(i64::from(t.index));
        let key = self.key(t.ns, id);
        self.heap.push(Reverse((key, t.ns, id, slot, t.lane)));
        Ok(())
    }

    fn next(&mut self, r: &mut Reading, b: &PacketBounds) -> VResult<Option<PacketRow>> {
        if !self.desc
            && let Some(scan) = &mut self.untimed
        {
            if let Some(row) = scan.next(r, b)? {
                return Ok(Some(row));
            }
            self.untimed = None;
        }
        if !self.started {
            self.started = true;
            for slot in 0..self.slots.len() {
                self.advance(slot, b)?;
            }
        }
        loop {
            r.tick()?;
            let Some(Reverse((_, ns, id, slot, lane))) = self.heap.pop() else {
                break;
            };
            self.advance(slot, b)?;
            // The rest of the bounds need the packet record, and are left
            // to SQLite's own check.
            if !b.id.holds(id) || !b.lane.holds(i64::from(lane)) {
                continue;
            }
            let Some(s) = self.slots.get(slot) else {
                continue;
            };
            return Ok(Some(PacketRow {
                id,
                seg: s.seg,
                lane: Some(lane),
                time: Some((self.clock, ns)),
                record: OnceCell::new(),
            }));
        }
        if let Some(scan) = &mut self.untimed {
            return scan.next(r, b);
        }
        Ok(None)
    }
}

enum PacketSource {
    Done,
    Ids(IdScan),
    Times(Box<TimeScan>),
}

/// Packet records read for lookups by id, kept for the next lookup: a
/// join that looks packets up in id order reads each block once.
struct Block {
    seg: usize,
    first: i64,
    records: usize,
    bytes: Vec<u8>,
}

/// Records a lookup reads at first, and at most when lookups go forward.
const BLOCK_FIRST: usize = 8;
const BLOCK_MOST: usize = 1024;

#[repr(C)]
struct PacketsCursor {
    /// SQLite's part; must come first.
    base: sqlite3_vtab_cursor,
    reading: Reading,
    source: PacketSource,
    bounds: Option<PacketBounds>,
    row: Option<PacketRow>,
    block: Option<Block>,
    /// The plan's constraints as last decoded, and the text they came from:
    /// a join looks packets up with the same plan once a row.
    plan: Option<(String, Vec<(char, Op)>)>,
}

impl PacketsCursor {
    fn step(&mut self) -> VResult<()> {
        let Some(b) = self.bounds else {
            self.row = None;
            return Ok(());
        };
        // Rows that are only ids move on in place: a count of every packet
        // costs a step of SQLite's and an addition here.
        if let (PacketSource::Ids(scan), Some(row)) = (&mut self.source, &mut self.row)
            && scan.step_in_place(row)
        {
            return self.reading.tick();
        }
        self.row = match &mut self.source {
            PacketSource::Done => None,
            PacketSource::Ids(scan) => scan.next(&mut self.reading, &b)?,
            PacketSource::Times(scan) => scan.next(&mut self.reading, &b)?,
        };
        if self.row.is_none() {
            self.source = PacketSource::Done;
        }
        Ok(())
    }

    fn record(&self) -> VResult<&PacketRecord> {
        let row = self.row.as_ref().ok_or_else(|| fail("no current row"))?;
        if let Some(p) = row.record.get() {
            return Ok(p);
        }
        let opened = self.reading.open(row.seg)?;
        let index = u64::try_from(row.id - opened.seg.first_packet())
            .map_err(|_| fail("packet before its segment"))?;
        let p = opened.seg.packet(index).map_err(|e| fail(e.to_string()))?;
        Ok(row.record.get_or_init(|| p))
    }

    /// One packet by id, through the block kept from the lookup before.
    fn lookup(&mut self, at: usize, id: i64) -> VResult<PacketRecord> {
        let seg = self
            .reading
            .manifest
            .segs
            .get(at)
            .ok_or_else(|| fail("no such segment"))?;
        let (first, last) = (seg.first, seg.last);
        let offset_in = |b: &Block| -> Option<usize> {
            let i = usize::try_from(id.checked_sub(b.first)?).ok()?;
            (b.seg == at && i < b.records).then_some(i)
        };
        if let Some(i) = self.block.as_ref().and_then(offset_in) {
            return self.decode_block(i);
        }
        // A lookup just past the block read before reads a larger one.
        let records = match &self.block {
            Some(b) if b.seg == at && id >= b.first && id - b.first < (b.records as i64) * 2 => {
                (b.records * 2).min(BLOCK_MOST)
            }
            _ => BLOCK_FIRST,
        };
        let records = records
            .min(usize::try_from(last - id + 1).unwrap_or(1))
            .max(1);
        let opened = self.reading.open(at)?;
        let (offset, _) = opened
            .seg
            .section_bytes(KIND_PACKETS, Clock::Receive)
            .map_err(|e| fail(e.to_string()))?;
        let start = u64::try_from(id - first)
            .ok()
            .and_then(|i| i.checked_mul(PACKET_BYTES as u64))
            .and_then(|b| b.checked_add(offset))
            .ok_or_else(|| fail("packet out of bounds"))?;
        let mut bytes = self.block.take().map(|b| b.bytes).unwrap_or_default();
        bytes.resize(records * PACKET_BYTES, 0);
        opened
            .seg
            .read_at(&mut bytes, start)
            .map_err(|e| fail(format!("reading a segment: {e}")))?;
        self.block = Some(Block {
            seg: at,
            first: id,
            records,
            bytes,
        });
        self.decode_block(0)
    }

    fn decode_block(&self, i: usize) -> VResult<PacketRecord> {
        let b = self.block.as_ref().ok_or_else(|| fail("no block"))?;
        let at = i * PACKET_BYTES;
        let raw: &[u8; PACKET_BYTES] = b
            .bytes
            .get(at..at + PACKET_BYTES)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| fail("packet out of the block"))?;
        Ok(PacketRecord::decode(raw))
    }

    fn start(&mut self, access: Access, b: PacketBounds) -> VResult<()> {
        let m = Arc::clone(&self.reading.manifest);
        self.bounds = Some(b);
        self.source = PacketSource::Done;
        self.row = None;
        if b.empty() {
            return Ok(());
        }
        if b.id.lo == b.id.hi {
            // One packet: found by binary search on the listed ranges.
            let id = b.id.lo;
            let Some(at) = m
                .holding(id)
                .filter(|&at| m.segs.get(at).is_some_and(|s| b.may_hold(s)))
            else {
                return Ok(());
            };
            let p = self.lookup(at, id)?;
            if b.holds(&p) {
                self.row = Some(PacketRow::with_record(id, at, p));
            }
            return Ok(());
        }
        let segs: Vec<usize> = (0..m.segs.len())
            .filter(|&at| m.segs.get(at).is_some_and(|s| b.may_hold(s)))
            .collect();
        let Some(c) = access.clock else {
            self.source = PacketSource::Ids(IdScan::new(segs, &b, access.desc, access.records));
            return self.step();
        };
        let which = if c == 0 {
            Clock::Receive
        } else {
            Clock::Packet
        };
        let range = b.times.get(c).copied().unwrap_or_else(Range::all);
        let mut untimed = Vec::new();
        let mut slots = Vec::new();
        let buffer = (MERGE_BUFFERS / segs.len().max(1)).clamp(4 << 10, SCAN_BUFFER);
        for &at in &segs {
            let Some(seg) = m.segs.get(at) else {
                continue;
            };
            let opened = self.reading.open(at)?;
            let timed = opened.seg.timed(which).map_err(|e| fail(e.to_string()))?;
            if !range.bounded && timed < opened.seg.packets() {
                untimed.push(at);
            }
            if timed == 0 {
                continue;
            }
            let (offset, length) = opened
                .seg
                .section_bytes(KIND_TIME, which)
                .map_err(|e| fail(e.to_string()))?;
            let position = |t: i64| -> VResult<u64> {
                opened
                    .seg
                    .time_position(which, t)
                    .map_err(|e| fail(e.to_string()))
            };
            let bytes = |p: u64| {
                p.checked_mul(TIME_BYTES as u64)
                    .and_then(|b| b.checked_add(offset))
                    .ok_or_else(|| fail("time order out of bounds"))
            };
            let end = offset.saturating_add(length);
            let reader = if access.desc {
                let upto = match range.hi.checked_add(1) {
                    Some(t) => bytes(position(t)?)?,
                    None => end,
                };
                Records::back(Arc::clone(&opened), offset, upto, buffer)
            } else {
                Records::new(
                    Arc::clone(&opened),
                    bytes(position(range.lo)?)?,
                    end,
                    buffer,
                )
            };
            // Runs of one time are held up to the reader's buffer, and read
            // again the other way past it.
            let reverse = access.desc != access.ties_desc;
            slots.push(TimeSlot {
                seg: at,
                first: seg.first,
                packets: seg.packets(),
                reader: TieReader::new(reader, reverse, time_key, buffer / TIME_BYTES),
            });
        }
        let untimed = (!untimed.is_empty()).then(|| {
            let mut scan = IdScan::new(untimed, &b, access.ties_desc, true);
            scan.untimed = Some(c);
            scan
        });
        self.source = PacketSource::Times(Box::new(TimeScan {
            clock: c,
            desc: access.desc,
            ties_desc: access.ties_desc,
            untimed,
            slots,
            heap: BinaryHeap::new(),
            started: false,
        }));
        self.step()
    }
}

// SAFETY: `PacketsCursor` is `#[repr(C)]` with `sqlite3_vtab_cursor` as its
// first field, which is what the trait requires: rusqlite boxes the value
// and hands SQLite a pointer to it as a `sqlite3_vtab_cursor`, and casts it
// back.
unsafe impl VTabCursor for PacketsCursor {
    fn filter(&mut self, plan: c_int, idx_str: Option<&str>, args: &Filters<'_>) -> VResult<()> {
        guard(|| {
            let text = idx_str.unwrap_or("");
            if self.plan.as_ref().is_none_or(|(t, _)| t != text) {
                self.plan = Some((text.to_string(), decode_plan(idx_str)));
            }
            let constraints = self.plan.as_ref().map_or(&[][..], |(_, p)| p.as_slice());
            let b = PacketBounds::read(constraints, args);
            self.start(Access::decode(plan), b)
        })
    }

    fn next(&mut self) -> VResult<()> {
        guard(|| self.step())
    }

    fn eof(&self) -> bool {
        self.row.is_none()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> VResult<()> {
        guard(|| {
            let row = self.row.as_ref().ok_or_else(|| fail("no current row"))?;
            let seg = self
                .reading
                .manifest
                .segs
                .get(row.seg)
                .ok_or_else(|| fail("no such segment"))?;
            match i {
                P_ID => ctx.set_result(row.id),
                P_FILE => ctx.set_result(seg.file_id),
                P_LANE => match row.lane {
                    Some(lane) => ctx.set_result(i64::from(lane)),
                    None => ctx.set_result(i64::from(self.record()?.lane)),
                },
                P_IDX => ctx.set_result(row.id - seg.first),
                P_RECEIVE | P_PACKET => {
                    let c = usize::from(i == P_PACKET);
                    match row.time {
                        Some((clock, t)) if clock == c => ctx.set_result(t),
                        _ => {
                            let p = self.record()?;
                            ctx.set_result(if c == 0 { p.receive_ns } else { p.packet_ns })
                        }
                    }
                }
                P_OFFSET => ctx.set_result(self.record()?.offset),
                P_LENGTH => ctx.set_result(self.record()?.length),
                P_SUM => ctx.set_result(self.record()?.sum),
                P_APID => ctx.set_result(self.record()?.header.map(|h| i64::from(h.0))),
                P_SEQ => ctx.set_result(self.record()?.header.map(|h| i64::from(h.1))),
                P_PTYPE => ctx.set_result(self.record()?.header.map(|h| i64::from(h.2))),
                P_LABEL => match self.record()?.label {
                    None => ctx.set_result(None::<&str>),
                    Some(n) => {
                        let opened = self.reading.open(row.seg)?;
                        let labels = opened.labels()?;
                        let label = usize::try_from(n)
                            .ok()
                            .and_then(|n| labels.get(n))
                            .ok_or_else(|| fail("a packet's label is out of range"))?;
                        ctx.set_result(label.as_str())
                    }
                },
                _ => Err(fail("no such column")),
            }
        })
    }

    fn rowid(&self) -> VResult<i64> {
        guard(|| {
            self.row
                .as_ref()
                .map(|r| r.id)
                .ok_or_else(|| fail("no current row"))
        })
    }
}

// ---- field_values -------------------------------------------------------------------

const V_PACKET_ID: c_int = 0;
const V_FILE: c_int = 1;
const V_PACKET: c_int = 2;
const V_FIELD: c_int = 3;
const V_NUM: c_int = 4;
const V_TEXT: c_int = 5;

#[repr(C)]
struct ValuesTab {
    /// SQLite's part; must come first.
    base: sqlite3_vtab,
    shared: Arc<Shared>,
}

// SAFETY: `ValuesTab` is `#[repr(C)]` with `sqlite3_vtab` as its first
// field, which is what the trait requires: rusqlite boxes the value and
// hands SQLite a pointer to it as a `sqlite3_vtab`, and casts it back.
unsafe impl<'vtab> VTab<'vtab> for ValuesTab {
    type Aux = Arc<Shared>;
    type Cursor = ValuesCursor;

    fn connect(
        db: &mut VTabConnection,
        aux: Option<&Arc<Shared>>,
        _module: &[u8],
        _database: &[u8],
        _table: &[u8],
        _args: &[&[u8]],
    ) -> VResult<(Cow<'static, CStr>, Self)> {
        guard(|| {
            let shared = aux.ok_or_else(|| fail("field_values: no store"))?;
            db.config(VTabConfig::Innocuous)?;
            Ok((
                Cow::Borrowed(
                    c"CREATE TABLE x(packet_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
                      packet TEXT NOT NULL, field TEXT NOT NULL, num REAL, text TEXT)",
                ),
                ValuesTab {
                    base: sqlite3_vtab::default(),
                    shared: Arc::clone(shared),
                },
            ))
        })
    }

    fn best_index(&self, info: &mut IndexInfo) -> VResult<bool> {
        guard(|| {
            self.shared.used.store(true, Ordering::Relaxed);
            let stats = self.shared.stats();
            let mut taken: Vec<Taken> = Vec::new();
            let constraints: Vec<(usize, c_int, Option<Op>, bool)> = info
                .constraints()
                .enumerate()
                .map(|(i, c)| (i, c.column(), Op::of(c.operator()), c.is_usable()))
                .collect();
            for (i, column, op, usable) in constraints {
                let Some(op) = op.filter(|_| usable) else {
                    continue;
                };
                let binary = || {
                    info.collation(i)
                        .is_ok_and(|c| c.eq_ignore_ascii_case("BINARY"))
                };
                let column = match column {
                    V_PACKET_ID => 'i',
                    V_FILE if op == Op::Eq => 'f',
                    V_PACKET if op == Op::Eq && binary() => 'k',
                    V_FIELD if op == Op::Eq && binary() => 'd',
                    V_NUM => 'n',
                    _ => continue,
                };
                taken.push((i, column, op));
            }
            let packets = stats.packets.max(1.0);
            let values = stats.values.max(1.0);
            let segments = stats.segments.max(1.0);
            let (id_eq, id_sides) = sides(&taken, 'i');
            let file_part = if sides(&taken, 'f').0 {
                1.0 / segments
            } else {
                1.0
            };
            let (num_eq, num_sides) = sides(&taken, 'n');
            let scan = if id_eq {
                // A binary search in a segment's values, then its few.
                (values / segments).max(2.0).log2() + values / packets
            } else {
                values * quarter(id_sides) * file_part
            };
            let out = (if id_eq {
                values / packets
            } else {
                values * quarter(id_sides) * file_part
            } * if sides(&taken, 'd').0 { 0.1 } else { 1.0 }
                * if sides(&taken, 'k').0 { 0.01 } else { 1.0 }
                * if num_eq { 0.01 } else { quarter(num_sides) })
            .max(1.0);
            take(info, &taken)?;
            info.set_estimated_rows(out as i64);
            let asked: Vec<(c_int, bool)> = info
                .order_bys()
                .map(|o| (o.column(), o.is_order_by_desc()))
                .collect();
            // No column and nothing to test, as for a count of every value:
            // places alone, nothing read.
            if info.col_used() == 0 && info.constraints().count() == 0 && asked.is_empty() {
                info.set_idx_num(PLAN_COUNT);
                info.set_estimated_cost(values * 0.1 + 1.0);
                info.set_order_by_consumed(false);
                return Ok(true);
            }
            // In order of number, either way, then of packet id, either way:
            // from the value order of the series a field (and packet) names,
            // merged across them, reading what they hold between the bounds
            // on the number. With no order of packet id asked for, values
            // of equal number come by packet id the way the number goes.
            let by_value = match asked.as_slice() {
                [(V_NUM, num_desc)] => Some((*num_desc, *num_desc)),
                [(V_NUM, num_desc), (V_PACKET_ID, id_desc)] => Some((*num_desc, *id_desc)),
                _ => None,
            }
            // Not for one file at a time: as the inner loop of a join over
            // files it would only be sorted again, by file.
            .filter(|_| sides(&taken, 'd').0 && !sides(&taken, 'f').0);
            if let Some((num_desc, id_desc)) = by_value {
                let mut plan = PLAN_BY_VALUE;
                if num_desc {
                    plan |= PLAN_NUM_DESC;
                }
                if id_desc {
                    plan |= PLAN_ID_DESC;
                }
                info.set_idx_num(plan);
                info.set_estimated_cost(out + segments.log2().max(1.0) + 1.0);
                info.set_order_by_consumed(true);
                return Ok(true);
            }
            // In packet order, and within a packet in the order kept; only
            // the packet id can be claimed.
            info.set_idx_num(0);
            info.set_estimated_cost(scan + 1.0);
            info.set_order_by_consumed(asked == [(V_PACKET_ID, false)]);
            Ok(true)
        })
    }

    fn open(&'vtab mut self) -> VResult<ValuesCursor> {
        guard(|| {
            Ok(ValuesCursor {
                base: sqlite3_vtab_cursor::default(),
                reading: Reading::start(&self.shared)?,
                scan: None,
                row: None,
            })
        })
    }
}

/// A range of numbers a constraint on `num` allows; a number outside it
/// cannot match, and neither can a null.
#[derive(Debug, Clone, Copy)]
struct NumRange {
    lo: Option<(f64, bool)>,
    hi: Option<(f64, bool)>,
    bounded: bool,
    empty: bool,
}

impl NumRange {
    fn narrow(&mut self, op: Op, v: ValueRef<'_>) {
        // An integer beyond what a double holds exactly is compared exactly
        // by SQLite; it is not used here.
        let v = match v {
            ValueRef::Null => {
                self.empty = true;
                return;
            }
            ValueRef::Integer(v) if v.unsigned_abs() <= 1 << 53 => v as f64,
            ValueRef::Real(f) if !f.is_nan() => f,
            _ => return,
        };
        self.bounded = true;
        let tighter_lo = |old: Option<(f64, bool)>, new: (f64, bool)| match old {
            Some(o) if o.0 > new.0 || (o.0 == new.0 && o.1) => Some(o),
            _ => Some(new),
        };
        let tighter_hi = |old: Option<(f64, bool)>, new: (f64, bool)| match old {
            Some(o) if o.0 < new.0 || (o.0 == new.0 && o.1) => Some(o),
            _ => Some(new),
        };
        match op {
            Op::Eq => {
                self.lo = tighter_lo(self.lo, (v, false));
                self.hi = tighter_hi(self.hi, (v, false));
            }
            Op::Gt => self.lo = tighter_lo(self.lo, (v, true)),
            Op::Ge => self.lo = tighter_lo(self.lo, (v, false)),
            Op::Lt => self.hi = tighter_hi(self.hi, (v, true)),
            Op::Le => self.hi = tighter_hi(self.hi, (v, false)),
        }
    }

    fn holds(&self, num: Option<f64>) -> bool {
        let Some(n) = num else {
            return !self.bounded;
        };
        let above = self
            .lo
            .is_none_or(|(lo, strict)| if strict { n > lo } else { n >= lo });
        let below = self
            .hi
            .is_none_or(|(hi, strict)| if strict { n < hi } else { n <= hi });
        above && below
    }
}

/// What a `field_values` plan is narrowed by.
#[derive(Debug, Clone)]
struct ValueBounds {
    packet_id: Range,
    file: Equal,
    packet: Option<String>,
    field: Option<String>,
    num: NumRange,
    empty: bool,
}

impl ValueBounds {
    fn read(plan: &[(char, Op)], args: &Filters<'_>) -> ValueBounds {
        let mut b = ValueBounds {
            packet_id: Range::all(),
            file: Equal::default(),
            packet: None,
            field: None,
            num: NumRange {
                lo: None,
                hi: None,
                bounded: false,
                empty: false,
            },
            empty: false,
        };
        let text = |slot: &mut Option<String>, empty: &mut bool, v: ValueRef<'_>| match v {
            ValueRef::Null => *empty = true,
            ValueRef::Text(t) => match std::str::from_utf8(t) {
                Ok(t) => match slot {
                    Some(old) if old != t => *empty = true,
                    _ => *slot = Some(t.to_string()),
                },
                Err(_) => *empty = true,
            },
            _ => {}
        };
        for (&(column, op), v) in plan.iter().zip(args.iter()) {
            match column {
                'i' => b.packet_id.narrow(op, v),
                'f' => b.file.narrow(v),
                'k' => text(&mut b.packet, &mut b.empty, v),
                'd' => text(&mut b.field, &mut b.empty, v),
                'n' => b.num.narrow(op, v),
                _ => {}
            }
        }
        b
    }

    fn empty(&self) -> bool {
        self.empty || self.packet_id.empty || self.file.empty || self.num.empty
    }
}

/// One segment's kept values being read.
struct ValueSlot {
    seg: usize,
    first: i64,
    packets: u64,
    /// Position of the next record in the section.
    position: u64,
    /// The last packet index wanted.
    last: u64,
    /// Which series match, by number; all if `None`.
    series: Option<Vec<bool>>,
    reader: Records<VALUE_BYTES>,
}

/// Kept values in packet order, segment after segment.
struct ValueScan {
    segs: Vec<usize>,
    next: usize,
    open: Option<ValueSlot>,
    bounds: ValueBounds,
}

/// The current row of a `field_values` cursor.
struct ValueRow {
    seg: usize,
    packet_id: i64,
    position: u64,
    value: ValueRecord,
    /// The value has a text, but where it starts must be read from its
    /// record in the values section.
    text_unread: bool,
    /// Only the place is known: everything else must be read from the
    /// record in the values section.
    unread: bool,
}

/// A `field_values` plan for a count of every value: no column used and
/// nothing to test, so each value's place is all a row needs.
const PLAN_COUNT: c_int = 8;

/// Every value's place, segment after segment, nothing read.
struct Places {
    segs: Vec<usize>,
    next: usize,
    /// The segment being counted, the next place and the end.
    open: Option<(usize, u64, u64)>,
}

impl Places {
    fn next(&mut self, r: &mut Reading) -> VResult<Option<ValueRow>> {
        loop {
            r.tick()?;
            if let Some((seg, at, end)) = &mut self.open
                && *at < *end
            {
                let position = *at;
                *at += 1;
                return Ok(Some(ValueRow {
                    seg: *seg,
                    packet_id: 0,
                    position,
                    value: ValueRecord {
                        index: 0,
                        series: 0,
                        num: None,
                        text_at: None,
                    },
                    text_unread: false,
                    unread: true,
                }));
            }
            let Some(&at) = self.segs.get(self.next) else {
                return Ok(None);
            };
            self.next += 1;
            let opened = r.open(at)?;
            let (_, length) = opened
                .seg
                .section_bytes(KIND_VALUES, Clock::Receive)
                .map_err(|e| fail(e.to_string()))?;
            self.open = Some((at, 0, length / VALUE_BYTES as u64));
        }
    }

    /// Moves a row to the next place of its segment, if there is one.
    fn step_in_place(&mut self, row: &mut ValueRow) -> bool {
        match &mut self.open {
            Some((seg, at, end)) if *seg == row.seg && *at < *end => {
                row.position = *at;
                *at += 1;
                true
            }
            _ => false,
        }
    }
}

/// A `field_values` plan in order of number; with the order each way.
const PLAN_BY_VALUE: c_int = 1;
const PLAN_NUM_DESC: c_int = 2;
const PLAN_ID_DESC: c_int = 4;

/// Most values [`Picked`] gathers to hand out in packet order: 64 K, of 32
/// bytes each, 2 MB.
const PICK_MOST: u64 = 1 << 16;

/// Values of a field between two numbers, few enough to gather from the
/// value order and hand out in packet order, as the scan in packet order
/// would: by segment, then place in it.
struct Picked {
    rows: std::vec::IntoIter<PickedRow>,
}

struct PickedRow {
    seg: usize,
    position: u64,
    packet_id: i64,
    index: u32,
    series: u32,
    num: f64,
    text: bool,
}

impl Picked {
    /// The values a field (and packet) and bounds on the number allow, if
    /// there are at most [`PICK_MOST`]; `None` if more, or if the bounds
    /// do not name a field and a range of numbers.
    fn gather(r: &mut Reading, segs: &[usize], b: &ValueBounds) -> VResult<Option<Picked>> {
        // A range of packets (a join looking packets' values up, one
        // packet at a time) is quicker found in packet order.
        if b.field.is_none() || !b.num.bounded || b.empty() || b.packet_id.bounded {
            return Ok(None);
        }
        let mut ranges = Vec::new();
        let mut total = 0u64;
        for &at in segs {
            let opened = r.open(at)?;
            let ok = opened.matching(b.packet.as_deref(), b.field.as_deref())?;
            if !ok.contains(&true) {
                continue;
            }
            for g in opened.groups()? {
                if !ok.get(g.series as usize).copied().unwrap_or(false) {
                    continue;
                }
                let (from, to) = opened
                    .seg
                    .value_order_range(g, b.num.lo, b.num.hi)
                    .map_err(|e| fail(e.to_string()))?;
                total = total.saturating_add(to - from);
                if total > PICK_MOST {
                    return Ok(None);
                }
                if from < to {
                    ranges.push((at, g.series, from, to));
                }
            }
        }
        let mut rows = Vec::with_capacity(total as usize);
        for (at, series, from, to) in ranges {
            let Some(seg) = r.manifest.segs.get(at) else {
                continue;
            };
            let (first, packets) = (seg.first, seg.packets());
            let opened = r.open(at)?;
            let (offset, _) = opened
                .seg
                .section_bytes(KIND_VALUE_ORDER, Clock::Receive)
                .map_err(|e| fail(e.to_string()))?;
            let bytes = |n: u64| {
                n.saturating_mul(VALUE_ORDER_BYTES as u64)
                    .saturating_add(offset)
            };
            let mut reader =
                Records::<VALUE_ORDER_BYTES>::new(opened, bytes(from), bytes(to), SCAN_BUFFER);
            while let Some(raw) = reader.read()? {
                r.tick()?;
                let v = ValueOrderRecord::decode(&raw);
                if u64::from(v.index) >= packets {
                    return Err(fail("a kept value names no packet"));
                }
                let packet_id = first.saturating_add(i64::from(v.index));
                if b.packet_id.holds(packet_id) && b.num.holds(Some(v.num)) {
                    rows.push(PickedRow {
                        seg: at,
                        position: v.position,
                        packet_id,
                        index: v.index,
                        series,
                        num: v.num,
                        text: v.text,
                    });
                }
            }
        }
        rows.sort_unstable_by_key(|p| (p.seg, p.position));
        Ok(Some(Picked {
            rows: rows.into_iter(),
        }))
    }

    fn next(&mut self) -> Option<ValueRow> {
        self.rows.next().map(|p| ValueRow {
            seg: p.seg,
            packet_id: p.packet_id,
            position: p.position,
            value: ValueRecord {
                index: p.index,
                series: p.series,
                num: Some(p.num),
                text_at: None,
            },
            text_unread: p.text,
            unread: false,
        })
    }
}

/// One series of one segment in value order: its values with a number,
/// between the bounds, or those without one.
struct ByValueSlot {
    seg: usize,
    first: i64,
    packets: u64,
    series: u32,
    numbers: bool,
    reader: TieReader<VALUE_ORDER_BYTES>,
    head: Option<ValueOrderRecord>,
}

/// Values in order of number and then packet id, merged across the series
/// and segments a field names. Values without a number come first when
/// the number ascends and last when it descends, as SQLite orders nulls,
/// by packet id.
struct ByValue {
    num_desc: bool,
    id_desc: bool,
    bounds: ValueBounds,
    slots: Vec<ByValueSlot>,
    /// Each slot's next value: whether it is in the later of the two parts
    /// (numbers, values without one), its number and packet id as keys of
    /// the order, and the slot.
    heap: BinaryHeap<Reverse<(bool, u64, i64, usize)>>,
}

fn value_order_key(b: &[u8; VALUE_ORDER_BYTES]) -> u64 {
    ValueOrderRecord::key_of(b)
}

impl ByValue {
    fn new(
        r: &mut Reading,
        segs: &[usize],
        b: ValueBounds,
        num_desc: bool,
        id_desc: bool,
    ) -> VResult<ByValue> {
        // (segment, series, first record, end, numbers)
        let mut parts = Vec::new();
        if !b.empty() {
            for &at in segs {
                let opened = r.open(at)?;
                let ok = opened.matching(b.packet.as_deref(), b.field.as_deref())?;
                if !ok.contains(&true) {
                    continue;
                }
                for g in opened.groups()? {
                    if !ok.get(g.series as usize).copied().unwrap_or(false) {
                        continue;
                    }
                    let (from, to) = if b.num.bounded {
                        opened
                            .seg
                            .value_order_range(g, b.num.lo, b.num.hi)
                            .map_err(|e| fail(e.to_string()))?
                    } else {
                        (g.first + g.nulls, g.first + g.count)
                    };
                    if from < to {
                        parts.push((at, g.series, from, to, true));
                    }
                    if !b.num.bounded && g.nulls > 0 {
                        parts.push((at, g.series, g.first, g.first + g.nulls, false));
                    }
                }
            }
        }
        // The readers share the merge's buffers; each holds a run of equal
        // numbers as large as its buffer.
        let buffer = (MERGE_BUFFERS / parts.len().max(1)).clamp(VALUE_ORDER_BYTES, SCAN_BUFFER);
        let mut slots = Vec::with_capacity(parts.len());
        for (at, series, from, to, numbers) in parts {
            let Some(seg) = r.manifest.segs.get(at) else {
                continue;
            };
            let opened = r.open(at)?;
            let (offset, _) = opened
                .seg
                .section_bytes(KIND_VALUE_ORDER, Clock::Receive)
                .map_err(|e| fail(e.to_string()))?;
            let bytes = |n: u64| {
                n.saturating_mul(VALUE_ORDER_BYTES as u64)
                    .saturating_add(offset)
            };
            // Values with a number are read the way the number goes, runs
            // of one number turned round if packet ids go the other way;
            // those without one the way packet ids go.
            let back = if numbers { num_desc } else { id_desc };
            let reader = if back {
                Records::back(opened, bytes(from), bytes(to), buffer)
            } else {
                Records::new(opened, bytes(from), bytes(to), buffer)
            };
            let reverse = numbers && num_desc != id_desc;
            slots.push(ByValueSlot {
                seg: at,
                first: seg.first,
                packets: seg.packets(),
                series,
                numbers,
                reader: TieReader::new(
                    reader,
                    reverse,
                    value_order_key,
                    buffer / VALUE_ORDER_BYTES,
                ),
                head: None,
            });
        }
        let mut scan = ByValue {
            num_desc,
            id_desc,
            bounds: b,
            slots,
            heap: BinaryHeap::new(),
        };
        for slot in 0..scan.slots.len() {
            scan.advance(r, slot)?;
        }
        Ok(scan)
    }

    /// Reads a slot's next value within the bounds on packet id onto the
    /// heap.
    fn advance(&mut self, r: &mut Reading, slot: usize) -> VResult<()> {
        let Some(s) = self.slots.get_mut(slot) else {
            return Ok(());
        };
        s.head = None;
        while let Some(raw) = s.reader.read()? {
            r.tick()?;
            let v = ValueOrderRecord::decode(&raw);
            if u64::from(v.index) >= s.packets {
                return Err(fail("a kept value names no packet"));
            }
            let id = s.first.saturating_add(i64::from(v.index));
            if !self.bounds.packet_id.holds(id) {
                continue;
            }
            let later = s.numbers == self.num_desc;
            let num = if s.numbers {
                let k = number_key(v.num);
                if self.num_desc { !k } else { k }
            } else {
                0
            };
            let id = if self.id_desc { !id } else { id };
            s.head = Some(v);
            self.heap.push(Reverse((!later, num, id, slot)));
            break;
        }
        Ok(())
    }

    fn next(&mut self, r: &mut Reading) -> VResult<Option<ValueRow>> {
        let Some(Reverse((_, _, _, slot))) = self.heap.pop() else {
            return Ok(None);
        };
        let Some(s) = self.slots.get(slot) else {
            return Ok(None);
        };
        let Some(v) = s.head else {
            return Err(fail("a value-order slot lost its value"));
        };
        let row = ValueRow {
            seg: s.seg,
            packet_id: s.first.saturating_add(i64::from(v.index)),
            position: v.position,
            value: ValueRecord {
                index: v.index,
                series: s.series,
                num: s.numbers.then_some(v.num),
                text_at: None,
            },
            text_unread: v.text,
            unread: false,
        };
        self.advance(r, slot)?;
        Ok(Some(row))
    }
}

/// How a `field_values` cursor reads.
enum ValueSource {
    Places(Places),
    Packets(ValueScan),
    Picked(Picked),
    ByValue(ByValue),
}

impl ValueScan {
    fn next(&mut self, r: &mut Reading) -> VResult<Option<ValueRow>> {
        loop {
            r.tick()?;
            if self.open.is_none() {
                let Some(&at) = self.segs.get(self.next) else {
                    return Ok(None);
                };
                self.next += 1;
                self.open = self.slot(r, at)?;
                continue;
            }
            let Some(slot) = &mut self.open else {
                continue;
            };
            let Some(raw) = slot.reader.read()? else {
                self.open = None;
                continue;
            };
            let position = slot.position;
            slot.position = slot.position.saturating_add(1);
            let v = ValueRecord::decode(&raw);
            let index = u64::from(v.index);
            if index >= slot.packets {
                return Err(fail("a kept value names no packet"));
            }
            if index > slot.last {
                self.open = None;
                continue;
            }
            let wanted = match &slot.series {
                None => true,
                Some(ok) => usize::try_from(v.series)
                    .ok()
                    .and_then(|s| ok.get(s))
                    .copied()
                    .unwrap_or(false),
            };
            if !wanted || !self.bounds.num.holds(v.num) {
                continue;
            }
            return Ok(Some(ValueRow {
                seg: slot.seg,
                packet_id: slot.first.saturating_add(i64::from(v.index)),
                position,
                value: v,
                text_unread: false,
                unread: false,
            }));
        }
    }

    /// Starts reading a segment's values, or `None` if none can match.
    fn slot(&self, r: &Reading, at: usize) -> VResult<Option<ValueSlot>> {
        let b = &self.bounds;
        let Some(seg) = r.manifest.segs.get(at) else {
            return Ok(None);
        };
        let (lo, hi) = (b.packet_id.lo.max(seg.first), b.packet_id.hi.min(seg.last));
        if lo > hi {
            return Ok(None);
        }
        let opened = r.open(at)?;
        let series = if b.packet.is_some() || b.field.is_some() {
            let names = opened.names()?;
            let ok: Vec<bool> = names
                .iter()
                .map(|(p, f)| {
                    b.packet.as_ref().is_none_or(|w| w == p)
                        && b.field.as_ref().is_none_or(|w| w == f)
                })
                .collect();
            if !ok.contains(&true) {
                return Ok(None);
            }
            Some(ok)
        } else {
            None
        };
        let index = |id: i64| u64::try_from(id - seg.first).map_err(|_| fail("bad packet range"));
        let (first, last) = (index(lo)?, index(hi)?);
        let position = if first == 0 {
            0
        } else {
            opened
                .seg
                .value_position(first)
                .map_err(|e| fail(e.to_string()))?
        };
        let (offset, length) = opened
            .seg
            .section_bytes(KIND_VALUES, Clock::Receive)
            .map_err(|e| fail(e.to_string()))?;
        let start = position
            .checked_mul(VALUE_BYTES as u64)
            .and_then(|b| b.checked_add(offset))
            .ok_or_else(|| fail("kept values out of bounds"))?;
        // A few values of one packet need no large buffer.
        let buffer = if first == last { 1024 } else { SCAN_BUFFER };
        Ok(Some(ValueSlot {
            seg: at,
            first: seg.first,
            packets: seg.packets(),
            position,
            last,
            series,
            reader: Records::new(opened, start, offset.saturating_add(length), buffer),
        }))
    }
}

#[repr(C)]
struct ValuesCursor {
    /// SQLite's part; must come first.
    base: sqlite3_vtab_cursor,
    reading: Reading,
    scan: Option<ValueSource>,
    row: Option<ValueRow>,
}

impl ValuesCursor {
    fn step(&mut self) -> VResult<()> {
        if let (Some(ValueSource::Places(places)), Some(row)) = (&mut self.scan, &mut self.row)
            && places.step_in_place(row)
        {
            return self.reading.tick();
        }
        self.row = match &mut self.scan {
            Some(ValueSource::Places(places)) => places.next(&mut self.reading)?,
            Some(ValueSource::Packets(scan)) => scan.next(&mut self.reading)?,
            Some(ValueSource::Picked(picked)) => picked.next(),
            Some(ValueSource::ByValue(scan)) => scan.next(&mut self.reading)?,
            None => None,
        };
        if self.row.is_none() {
            self.scan = None;
        }
        Ok(())
    }
}

// SAFETY: `ValuesCursor` is `#[repr(C)]` with `sqlite3_vtab_cursor` as its
// first field, which is what the trait requires: rusqlite boxes the value
// and hands SQLite a pointer to it as a `sqlite3_vtab_cursor`, and casts it
// back.
unsafe impl VTabCursor for ValuesCursor {
    fn filter(&mut self, plan: c_int, idx_str: Option<&str>, args: &Filters<'_>) -> VResult<()> {
        guard(|| {
            let b = ValueBounds::read(&decode_plan(idx_str), args);
            let m = Arc::clone(&self.reading.manifest);
            let segs: Vec<usize> = if b.empty() {
                Vec::new()
            } else if b.packet_id.lo == b.packet_id.hi {
                m.holding(b.packet_id.lo).into_iter().collect()
            } else {
                (0..m.segs.len())
                    .filter(|&at| {
                        m.segs.get(at).is_some_and(|s| {
                            b.packet_id.meets(s.first, s.last) && b.file.holds(s.file_id)
                        })
                    })
                    .collect()
            };
            let r = &mut self.reading;
            self.scan = Some(if plan & PLAN_COUNT != 0 {
                ValueSource::Places(Places {
                    segs,
                    next: 0,
                    open: None,
                })
            } else if plan & PLAN_BY_VALUE != 0 {
                let (num_desc, id_desc) = (plan & PLAN_NUM_DESC != 0, plan & PLAN_ID_DESC != 0);
                ValueSource::ByValue(ByValue::new(r, &segs, b, num_desc, id_desc)?)
            } else if let Some(picked) = Picked::gather(r, &segs, &b)? {
                ValueSource::Picked(picked)
            } else {
                ValueSource::Packets(ValueScan {
                    segs,
                    next: 0,
                    open: None,
                    bounds: b,
                })
            });
            self.step()
        })
    }

    fn next(&mut self) -> VResult<()> {
        guard(|| self.step())
    }

    fn eof(&self) -> bool {
        self.row.is_none()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> VResult<()> {
        guard(|| {
            let read;
            let row = match self.row.as_ref().ok_or_else(|| fail("no current row"))? {
                // A count's row is only a place: its value is read if a
                // column is asked for after all.
                row if row.unread => {
                    let opened = self.reading.open(row.seg)?;
                    let value = opened
                        .seg
                        .value_at(row.position)
                        .map_err(|e| fail(e.to_string()))?;
                    let first = self
                        .reading
                        .manifest
                        .segs
                        .get(row.seg)
                        .map_or(0, |s| s.first);
                    read = ValueRow {
                        seg: row.seg,
                        packet_id: first.saturating_add(i64::from(value.index)),
                        position: row.position,
                        value,
                        text_unread: false,
                        unread: false,
                    };
                    &read
                }
                row => row,
            };
            let name = |which: usize| -> VResult<String> {
                let opened = self.reading.open(row.seg)?;
                let names = opened.names()?;
                let (p, f) = usize::try_from(row.value.series)
                    .ok()
                    .and_then(|s| names.get(s))
                    .ok_or_else(|| fail("a kept value names no series"))?;
                Ok(if which == 0 { p.clone() } else { f.clone() })
            };
            match i {
                V_PACKET_ID => ctx.set_result(row.packet_id),
                V_FILE => {
                    let seg = self
                        .reading
                        .manifest
                        .segs
                        .get(row.seg)
                        .ok_or_else(|| fail("no such segment"))?;
                    ctx.set_result(seg.file_id)
                }
                V_PACKET => ctx.set_result(name(0)?),
                V_FIELD => ctx.set_result(name(1)?),
                V_NUM => ctx.set_result(row.value.num),
                V_TEXT => {
                    let at = if row.text_unread {
                        let opened = self.reading.open(row.seg)?;
                        let v = opened
                            .seg
                            .value_at(row.position)
                            .map_err(|e| fail(e.to_string()))?;
                        if v.series != row.value.series {
                            return Err(fail("a value in value order names another value"));
                        }
                        v.text_at
                    } else {
                        row.value.text_at
                    };
                    match at {
                        None => ctx.set_result(None::<&str>),
                        Some(at) => {
                            let opened = self.reading.open(row.seg)?;
                            ctx.set_result(opened.seg.text(at).map_err(|e| fail(e.to_string()))?)
                        }
                    }
                }
                _ => Err(fail("no such column")),
            }
        })
    }

    /// Unique within a statement: the segment's place in the list and the
    /// value's place in the segment. The rowids the SQLite table gave, in
    /// order of insertion, are not kept anywhere.
    fn rowid(&self) -> VResult<i64> {
        guard(|| {
            let row = self.row.as_ref().ok_or_else(|| fail("no current row"))?;
            let seg = i64::try_from(row.seg).map_err(|_| fail("too many segments"))?;
            let position = i64::try_from(row.position).map_err(|_| fail("too many values"))?;
            if position >= 1 << 40 || seg >= 1 << 22 {
                return Err(fail("too many values for a rowid"));
            }
            Ok((seg << 40) | position)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::ingest::PacketRow as Row;
    use crate::shell::segment::Writer;

    /// A segment whose receive times come in runs of one time, some far
    /// longer than a reader holds, opened as a statement opens it.
    fn tied_segment(dir: &std::path::Path) -> (Arc<Opened>, Vec<TimeRecord>) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let mut writer = Writer::create(dir, 1, 1).unwrap();
        let runs = [(5i64, 50u32), (7, 3), (9, 1), (10, 20), (-4, 9), (12, 2)];
        let mut want = Vec::new();
        let mut index = 0u32;
        for (t, n) in runs {
            for _ in 0..n {
                let row = Row {
                    idx: i64::from(index),
                    offset: 0,
                    length: 1,
                    receive_ns: Some(t),
                    packet_ns: None,
                    header: None,
                    length_ok: true,
                    sum: 0,
                };
                let lane = i64::from(index % 3) + 1;
                writer.push(lane, &row, None).unwrap();
                want.push(TimeRecord {
                    ns: t,
                    index,
                    lane: index % 3 + 1,
                });
                index += 1;
            }
        }
        let written = writer.finish().unwrap().unwrap();
        let seg = Segment::open(&dir.join(&written.name)).unwrap();
        let opened = Arc::new(Opened {
            seg,
            labels: OnceLock::new(),
            names: OnceLock::new(),
            groups: OnceLock::new(),
        });
        (opened, want)
    }

    #[test]
    fn runs_of_one_time_turn_round_whatever_their_length() {
        let dir = std::env::temp_dir().join(format!("packetlane-ties-{}", std::process::id()));
        let (opened, records) = tied_segment(&dir);
        let (offset, length) = opened.seg.section_bytes(KIND_TIME, Clock::Receive).unwrap();
        // (read last to first, ties by index descending)
        for (back, ties_desc) in [(false, true), (true, false), (false, false), (true, true)] {
            let mut want = records.clone();
            want.sort_by_key(|r| {
                (
                    if back { -r.ns } else { r.ns },
                    if ties_desc {
                        -i64::from(r.index)
                    } else {
                        i64::from(r.index)
                    },
                )
            });
            // A run longer than the reader holds is read again the other
            // way; buffers of one record, of four, and of all of them.
            for (buffer, cap) in [(TIME_BYTES, 1), (4 * TIME_BYTES, 4), (1 << 16, 1 << 12)] {
                let reader = if back {
                    Records::back(Arc::clone(&opened), offset, offset + length, buffer)
                } else {
                    Records::new(Arc::clone(&opened), offset, offset + length, buffer)
                };
                let mut ties = TieReader::new(reader, back != ties_desc, time_key, cap);
                let mut got = Vec::new();
                while let Some(raw) = ties.read().unwrap() {
                    got.push(TimeRecord::decode(&raw));
                }
                assert_eq!(got, want, "back {back} ties_desc {ties_desc} cap {cap}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
