//! Writing and reading segment files. What is in them, and how a density
//! view is put together from them, is in `pure::segment`; this module only
//! moves the bytes. Reads are positioned reads into small buffers, so a
//! reader holds no more than a few pages whatever the size of the file.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::pure::ingest::{PacketRow, ptype_code};
use crate::pure::segment::{
    self as layout, BUCKET_BYTES, BucketRecord, CHECKSUM_BYTES, CHECKSUM_KEY_BYTES, ChecksumRecord,
    DELAY, ENTRY_BYTES, Entry, FormatError, GROUP_BYTES, GroupRecord, KIND_BUCKETS, KIND_CHECKSUMS,
    KIND_GROUPS, KIND_LABELS, KIND_PACKETS, KIND_SERIES, KIND_SERIES_BUCKETS, KIND_SERIES_NAMES,
    KIND_TEXTS, KIND_TIME, KIND_VALUE_GROUPS, KIND_VALUE_ORDER, KIND_VALUES, LaneStats, LaneTable,
    LevelCounter, MAGIC, PACKET_BYTES, POINT_BYTES, POINT_KEY_BYTES, PacketRecord, PointRecord,
    SERIES_BUCKET_BYTES, SeriesBucket, TAIL_BYTES, TIME_BYTES, Tail, TimeRecord, VALUE_BYTES,
    VALUE_GROUP_BYTES, VALUE_KEY_BYTES, VALUE_ORDER_BYTES, ValueGroup, ValueRecord,
};
use crate::pure::sql::Clock;
use crate::shell::store::Result;

/// What each of a segment writer's six sorters holds before it writes a
/// sorted run, unless the writer is given another figure: 1 MB (two sorters
/// of times, two of kept numbers and arrival delays, one of checksums and
/// one of kept values in value order). Putting a chunk in order by group or
/// by radix takes a scratch copy of it for as long as that runs, one at a
/// time, and merging what they spilled [`MERGE_MEMORY`].
pub const CHUNK_BYTES: usize = 1 << 20;
/// Records a time-order sorter of [`CHUNK_BYTES`] holds; given to
/// [`Writer::with_chunk`], every sorter holds [`CHUNK_BYTES`].
const SORT_CHUNK: usize = CHUNK_BYTES / TIME_BYTES;
/// Buffer for each of the temporary files kept values and their texts are
/// written to.
const SPOOL_BUFFER: usize = 64 << 10;
/// Most sorted runs merged at once. More are merged in passes, the
/// smallest first, so buffers stay the same however long the input.
const FAN_IN: usize = 128;
/// What the buffers of the runs being merged hold in all: each run gets
/// an equal share, at least [`MIN_RUN_BUFFER`] and at most [`IO_BUFFER`],
/// so at most 2 MB however many runs (128 of 16 KB).
const MERGE_MEMORY: usize = 2 << 20;
const MIN_RUN_BUFFER: usize = 16 << 10;
/// Buffer for writing, and for reading a section from end to end.
const IO_BUFFER: usize = 256 << 10;
/// Buffer for scanning a range of a section.
const SCAN_BUFFER: usize = 64 << 10;

/// The folder a store's segments are kept in: beside the store, named
/// after it.
pub fn folder_for(db: &Path) -> PathBuf {
    let mut name = db
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("store"));
    name.push(".seg");
    db.with_file_name(name)
}

/// Whether a file in the segment folder is one this program writes: a
/// segment or a temporary file. Nothing else there is ever removed.
pub fn is_ours(name: &str) -> bool {
    name.ends_with(".seg") || name.ends_with(".tmp")
}

// Writers lock the segment folder itself (an advisory lock on the open
// folder): shared while an ingest writes segments and temporary files
// outside the store's transactions, alone while the folder is swept.

/// Holds the folder against a sweep until the handle returned is dropped;
/// other ingests may hold it at the same time.
pub fn hold_folder(folder: &Path) -> Result<File> {
    let file = File::open(folder)?;
    file.lock_shared()?;
    Ok(file)
}

/// The folder to oneself for a sweep, until the handle returned is
/// dropped; `None` if an ingest holds it now.
pub fn sweep_folder(folder: &Path) -> Result<Option<File>> {
    let file = File::open(folder)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

fn remove_quietly(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Removes a segment that is no longer listed. Already gone is fine.
pub fn remove(folder: &Path, name: &str) -> Result<()> {
    match fs::remove_file(folder.join(name)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

// ---- bounded sorting -----------------------------------------------------------

/// A file that is removed when this is dropped.
pub(crate) struct TempFile {
    path: PathBuf,
    pub(crate) file: File,
}

impl TempFile {
    pub(crate) fn create(path: PathBuf) -> Result<TempFile> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok(TempFile { path, file })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        remove_quietly(&self.path);
    }
}

thread_local! {
    /// When reads of segment files on this thread must stop; see
    /// [`with_deadline`].
    static DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// Runs `read` with every buffered read of a segment file on this thread
/// failing once `deadline` has passed, so that a request's reads of the
/// segment files keep to its time as its SQL does.
pub fn with_deadline<T>(deadline: Option<Instant>, read: impl FnOnce() -> T) -> T {
    struct Restore(Option<Instant>);
    impl Drop for Restore {
        fn drop(&mut self) {
            DEADLINE.with(|d| d.set(self.0));
        }
    }
    let _restore = Restore(DEADLINE.with(|d| d.replace(deadline)));
    read()
}

/// Fails if this thread's reads are past their deadline.
fn in_time() -> Result<()> {
    match DEADLINE.with(std::cell::Cell::get) {
        Some(deadline) if Instant::now() > deadline => {
            Err("Request took longer than the time limit while reading the segment files".into())
        }
        _ => Ok(()),
    }
}

/// Reads fixed-width records from one range of a file, through a buffer.
struct RangeReader<'a, const N: usize> {
    file: &'a File,
    next: u64,
    end: u64,
    buf: Vec<u8>,
    at: usize,
}

impl<'a, const N: usize> RangeReader<'a, N> {
    fn new(file: &'a File, start: u64, end: u64, buffer: usize) -> Self {
        RangeReader {
            file,
            next: start,
            end,
            buf: Vec::with_capacity((buffer / N).max(1) * N),
            at: 0,
        }
    }

    fn read(&mut self) -> Result<Option<[u8; N]>> {
        if self.at >= self.buf.len() {
            in_time()?;
            let left = self.end.saturating_sub(self.next);
            if left < N as u64 {
                return Ok(None);
            }
            let want = (self.buf.capacity() as u64).min(left / N as u64 * N as u64) as usize;
            self.buf.resize(want, 0);
            self.file.read_exact_at(&mut self.buf, self.next)?;
            self.next += want as u64;
            self.at = 0;
        }
        let mut record = [0u8; N];
        record.copy_from_slice(&self.buf[self.at..self.at + N]);
        self.at += N;
        Ok(Some(record))
    }
}

/// Reads one sorted run of a sorter's temporary files through a buffer of
/// records, for merging: the records ready are handed out as a slice.
struct RunReader<'a, const N: usize> {
    file: &'a File,
    next: u64,
    end: u64,
    /// Records per read.
    cap: usize,
    buf: Vec<[u8; N]>,
    at: usize,
}

impl<'a, const N: usize> RunReader<'a, N> {
    fn new(file: &'a File, start: u64, end: u64, buffer: usize) -> Self {
        RunReader {
            file,
            next: start,
            end,
            cap: (buffer / N).max(1),
            buf: Vec::new(),
            at: 0,
        }
    }

    /// The records read and not yet taken; empty once the run is done.
    fn ready(&mut self) -> Result<&[[u8; N]]> {
        if self.at >= self.buf.len() {
            let left = self.end.saturating_sub(self.next) / N as u64;
            let want = left.min(self.cap as u64) as usize;
            self.buf.resize(want, [0; N]);
            self.at = 0;
            if want > 0 {
                self.file
                    .read_exact_at(self.buf.as_flattened_mut(), self.next)?;
                self.next += (want * N) as u64;
            }
        }
        Ok(&self.buf[self.at..])
    }
}

/// Hands the records of sorted `runs` to `out` in order, slice by slice.
/// The run with the lowest next record gives every record up to the next
/// record of any other run in one slice, so that runs which do not
/// overlap, or groups of records that lie together in every run, cost a
/// comparison of a few bytes each and no work on the heap.
fn merge_runs<const N: usize>(
    files: &[Option<TempFile>],
    runs: &[Run<N>],
    mut out: impl FnMut(&[[u8; N]]) -> Result<()>,
) -> Result<()> {
    let buffer = (MERGE_MEMORY / runs.len().max(1)).clamp(MIN_RUN_BUFFER, IO_BUFFER);
    let mut readers = Vec::with_capacity(runs.len());
    for r in runs {
        let file = files
            .get(r.file)
            .and_then(Option::as_ref)
            .ok_or("sorter has no file")?;
        readers.push(RunReader::<N>::new(
            &file.file,
            r.start,
            r.start + r.len,
            buffer,
        ));
    }
    let mut heap = BinaryHeap::with_capacity(runs.len());
    for (i, reader) in readers.iter_mut().enumerate() {
        if let Some(&head) = reader.ready()?.first() {
            heap.push(Reverse((head, i)));
        }
    }
    while let Some(Reverse((_, i))) = heap.pop() {
        let bound = heap.peek().map(|Reverse((head, _))| *head);
        let reader = &mut readers[i];
        loop {
            let ready = reader.ready()?;
            if ready.is_empty() {
                break;
            }
            let n = match &bound {
                None => ready.len(),
                Some(b) => gallop(ready, b),
            };
            out(&ready[..n])?;
            let next = ready.get(n).copied();
            reader.at += n;
            if let Some(next) = next {
                heap.push(Reverse((next, i)));
                break;
            }
        }
    }
    Ok(())
}

/// How many of the sorted `records` are at most `bound`: an exponential
/// search from the start, so that one record costs a comparison or two,
/// as it does when runs interleave record by record.
fn gallop<const N: usize>(records: &[[u8; N]], bound: &[u8; N]) -> usize {
    let mut hi = 1;
    while hi <= records.len() && records[hi - 1] <= *bound {
        hi *= 2;
    }
    let lo = hi / 2;
    let end = hi.min(records.len() + 1) - 1;
    lo + records[lo..end].partition_point(|r| r <= bound)
}

/// How a sorter puts one chunk in order before writing it as a run. All
/// give the order of the records' bytes; they differ in what input they
/// are quick for. A chunk already in order is left as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkOrder {
    /// A comparison sort.
    Compare,
    /// Records interleaved from groups named by their first eight bytes,
    /// each group arriving in order or nearly: a stable sort by group, then
    /// a sort of each group that is not in order.
    Grouped,
    /// Records whose first two bytes are spread evenly: a radix sort on
    /// those two bytes, then a sort of each set of records sharing them.
    Radix,
}

/// The group of a record sorted [`ChunkOrder::Grouped`].
fn group_of<const N: usize>(r: &[u8; N]) -> u64 {
    r.first_chunk::<8>().map_or(0, |b| u64::from_be_bytes(*b))
}

/// Puts `buf` in the order of its records' bytes. [`ChunkOrder::Grouped`]
/// and [`ChunkOrder::Radix`] take a scratch buffer as large as `buf` for
/// the time they run.
fn order_chunk<const N: usize>(how: ChunkOrder, buf: &mut Vec<[u8; N]>) {
    if buf.is_sorted() {
        return;
    }
    match how {
        ChunkOrder::Grouped if N >= 8 => {
            buf.sort_by_key(group_of);
            let mut rest = &mut buf[..];
            while let Some(first) = rest.first() {
                let g = group_of(first);
                let n = rest.partition_point(|r| group_of(r) == g);
                let (part, after) = rest.split_at_mut(n);
                if !part.is_sorted() {
                    part.sort_unstable();
                }
                rest = after;
            }
        }
        ChunkOrder::Radix if N >= 2 => {
            let mut scratch = vec![[0u8; N]; buf.len()];
            for byte in [1, 0] {
                let mut starts = [0usize; 257];
                for r in buf.iter() {
                    starts[usize::from(r[byte]) + 1] += 1;
                }
                for i in 0..256 {
                    starts[i + 1] += starts[i];
                }
                for r in buf.iter() {
                    let slot = &mut starts[usize::from(r[byte])];
                    scratch[*slot] = *r;
                    *slot += 1;
                }
                std::mem::swap(buf, &mut scratch);
            }
            drop(scratch);
            let mut rest = &mut buf[..];
            while let Some(first) = rest.first() {
                let lead = [first[0], first[1]];
                let n = rest.partition_point(|r| r[..2] == lead);
                let (part, after) = rest.split_at_mut(n);
                if n > 1 {
                    part.sort_unstable();
                }
                rest = after;
            }
        }
        _ => buf.sort_unstable(),
    }
}

/// One sorted run: where it lies in which temporary file, and its last
/// record.
#[derive(Debug, Clone, Copy)]
struct Run<const N: usize> {
    file: usize,
    start: u64,
    len: u64,
    last: [u8; N],
}

/// Sorts fixed-width records whose byte order is their sort order, holding
/// at most `chunk` of them in memory. Each full chunk is put in order and
/// written out. What sorting costs follows how far the input is from
/// order: the part of a chunk that comes after everything written so far
/// extends one long run, in a file of its own; the rest extends the last
/// of the other runs if it comes after it, or starts a new one. Input in
/// order is one run, read back as it was written; a few late records make
/// a few short runs. The runs are merged at the end, at most `fan_in` at a
/// time, the smallest first. Temporary files are removed when it is
/// dropped, whether or not it finished.
pub struct Sorter<const N: usize> {
    stem: PathBuf,
    chunk: usize,
    fan_in: usize,
    how: ChunkOrder,
    buf: Vec<[u8; N]>,
    /// Temporary files by number, and how long each is: 0 holds the long
    /// run, 1 the others, later ones what merging passes write. A file is
    /// closed and removed once no run lies in it.
    files: Vec<Option<TempFile>>,
    ends: Vec<u64>,
    runs: Vec<Run<N>>,
    /// The long run, and the last run of file 1.
    main: Option<usize>,
    tail: Option<usize>,
    names: u32,
}

impl<const N: usize> Sorter<N> {
    /// Temporary files are named from `stem` (a path) plus a number and
    /// `.tmp`. Chunks are put in order by comparison; see
    /// [`Sorter::ordered`].
    pub fn new(stem: PathBuf, chunk: usize, fan_in: usize) -> Self {
        Sorter {
            stem,
            chunk: chunk.max(1),
            fan_in: fan_in.max(2),
            how: ChunkOrder::Compare,
            buf: Vec::new(),
            files: Vec::new(),
            ends: Vec::new(),
            runs: Vec::new(),
            main: None,
            tail: None,
            names: 0,
        }
    }

    /// Puts chunks in order the way `how` says.
    pub fn ordered(mut self, how: ChunkOrder) -> Self {
        self.how = how;
        self
    }

    /// Takes its chunk's memory now, on this thread, rather than on the
    /// thread that first pushes: memory a thread takes stays with that
    /// thread's allocator, so a writer filled on one thread and finished
    /// on another would otherwise hold both threads' share at once. The
    /// pages are not touched until records fill them.
    pub fn reserved(mut self) -> Self {
        self.buf.reserve_exact(self.chunk);
        self
    }

    fn temp(&mut self) -> Result<TempFile> {
        self.names += 1;
        let mut name = self.stem.clone().into_os_string();
        name.push(format!(".{}.tmp", self.names));
        TempFile::create(PathBuf::from(name))
    }

    /// Writes `records` at the end of file `slot`, creating the files up
    /// to it if need be; returns where they start.
    fn append(&mut self, slot: usize, records: &[[u8; N]]) -> Result<u64> {
        while self.files.len() <= slot {
            let temp = self.temp()?;
            self.files.push(Some(temp));
            self.ends.push(0);
        }
        let Some(temp) = &self.files[slot] else {
            return Err("sorter has no file".into());
        };
        let start = self.ends[slot];
        let bytes = records.as_flattened();
        temp.file.write_all_at(bytes, start)?;
        self.ends[slot] += bytes.len() as u64;
        Ok(start)
    }

    pub fn push(&mut self, record: [u8; N]) -> Result<()> {
        if self.buf.capacity() == 0 {
            self.buf.reserve_exact(self.chunk);
        }
        self.buf.push(record);
        if self.buf.len() >= self.chunk {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.buf);
        order_chunk(self.how, &mut buf);
        let result = self.write_chunk(&buf);
        buf.clear();
        self.buf = buf;
        result
    }

    /// Writes a chunk in order: what comes after the long run extends it,
    /// the rest extends or follows the last other run.
    fn write_chunk(&mut self, buf: &[[u8; N]]) -> Result<()> {
        let split = match self.main {
            Some(m) => buf.partition_point(|r| *r < self.runs[m].last),
            None => 0,
        };
        let (before, after) = buf.split_at(split);
        if let Some(&last) = after.last() {
            let start = self.append(0, after)?;
            let len = after.as_flattened().len() as u64;
            match self.main {
                Some(m) => {
                    self.runs[m].len += len;
                    self.runs[m].last = last;
                }
                None => {
                    self.main = Some(self.runs.len());
                    self.runs.push(Run {
                        file: 0,
                        start,
                        len,
                        last,
                    });
                }
            }
        }
        if let (Some(first), Some(&last)) = (before.first(), before.last()) {
            let start = self.append(1, before)?;
            let len = before.as_flattened().len() as u64;
            match self.tail {
                Some(t) if self.runs[t].last <= *first => {
                    self.runs[t].len += len;
                    self.runs[t].last = last;
                }
                _ => {
                    self.tail = Some(self.runs.len());
                    self.runs.push(Run {
                        file: 1,
                        start,
                        len,
                        last,
                    });
                }
            }
        }
        Ok(())
    }

    /// Hands every record to `out`, in order, a slice at a time. Returns
    /// the most sorted runs that were merged at once.
    pub fn finish(mut self, mut out: impl FnMut(&[[u8; N]]) -> Result<()>) -> Result<usize> {
        if self.runs.is_empty() {
            let mut buf = std::mem::take(&mut self.buf);
            order_chunk(self.how, &mut buf);
            if !buf.is_empty() {
                out(&buf)?;
            }
            return Ok(0);
        }
        self.spill()?;
        self.buf = Vec::new();
        let mut widest = 0;
        // Merge the smallest runs into one until few enough are left:
        // just enough of them that `fan_in` remain, at most `fan_in` at once.
        while self.runs.len() > self.fan_in {
            let k = (self.runs.len() - self.fan_in + 1).min(self.fan_in);
            widest = widest.max(k);
            self.runs.sort_by_key(|r| r.len);
            let group: Vec<Run<N>> = self.runs.drain(..k).collect();
            let to = self.temp()?;
            let mut writer = BufWriter::with_capacity(IO_BUFFER, &to.file);
            let mut len = 0u64;
            let mut last = [0u8; N];
            merge_runs(&self.files, &group, |records| {
                writer.write_all(records.as_flattened())?;
                len += records.as_flattened().len() as u64;
                if let Some(&r) = records.last() {
                    last = r;
                }
                Ok(())
            })?;
            writer.flush()?;
            drop(writer);
            self.files.push(Some(to));
            self.ends.push(len);
            self.runs.push(Run {
                file: self.files.len() - 1,
                start: 0,
                len,
                last,
            });
            for (i, file) in self.files.iter_mut().enumerate() {
                if !self.runs.iter().any(|r| r.file == i) {
                    *file = None;
                }
            }
        }
        widest = widest.max(self.runs.len());
        merge_runs(&self.files, &self.runs, out)?;
        Ok(widest)
    }
}

/// Parts a [`Spread`] sorter divides its records into, by first byte.
const PARTS: usize = 256;

/// Sorts fixed-width records whose byte order is their sort order and
/// whose first byte is spread evenly (checksums): what a [`Sorter`] does,
/// at less cost for input in no order. Each record goes to one of
/// [`PARTS`] parts by its first byte, buffered in memory a block at a time;
/// a full block is appended to one temporary file, pointing back at the
/// part's block before it. At the end each part is read back and sorted in
/// memory, the parts in order: every record is written once and read once,
/// and no runs are merged. A part larger than [`MERGE_MEMORY`] (records
/// that share a first byte far more than their share, or a file of
/// hundreds of millions of packets) is sorted by a [`Sorter`] of its own.
pub struct Spread<const N: usize> {
    stem: PathBuf,
    chunk: usize,
    /// Records a block holds.
    block: usize,
    /// Each part's records not yet in a block of the file.
    held: Vec<Vec<[u8; N]>>,
    /// Each part's last block in the file (its start), and how many
    /// records the part has in all.
    last: Vec<Option<u64>>,
    counts: Vec<u64>,
    file: Option<TempFile>,
    end: u64,
    /// The most bytes of one part sorted in memory.
    part_memory: usize,
}

impl<const N: usize> Spread<N> {
    /// Temporary files are named from `stem` (a path) plus `.tmp`; the
    /// blocks held in memory together take about `chunk` records.
    pub fn new(stem: PathBuf, chunk: usize) -> Self {
        Spread {
            stem,
            chunk: chunk.max(1),
            block: (chunk / PARTS).max(16),
            // Taken now, on this thread: see [`Sorter::reserved`].
            held: (0..PARTS)
                .map(|_| Vec::with_capacity((chunk / PARTS).max(16)))
                .collect(),
            last: vec![None; PARTS],
            counts: vec![0; PARTS],
            file: None,
            end: 0,
            part_memory: MERGE_MEMORY,
        }
    }

    /// Sorts a part in memory only if it takes at most `bytes`.
    pub fn sorting_in_memory(mut self, bytes: usize) -> Self {
        self.part_memory = bytes;
        self
    }

    fn block_bytes(&self) -> usize {
        8 + self.block * N
    }

    pub fn push(&mut self, record: [u8; N]) -> Result<()> {
        let part = usize::from(record.first().copied().unwrap_or(0));
        let block = self.block;
        let held = &mut self.held[part];
        if held.capacity() == 0 {
            held.reserve_exact(block);
        }
        held.push(record);
        self.counts[part] += 1;
        if held.len() >= block {
            self.spill(part)?;
        }
        Ok(())
    }

    /// Appends a part's held records to the file as a block: the start of
    /// the part's block before it (`u64::MAX` for none), then the records.
    fn spill(&mut self, part: usize) -> Result<()> {
        if self.file.is_none() {
            let mut name = self.stem.clone().into_os_string();
            name.push(".tmp");
            self.file = Some(TempFile::create(PathBuf::from(name))?);
        }
        let Some(file) = &self.file else {
            return Err("spread sorter has no file".into());
        };
        let mut bytes = Vec::with_capacity(self.block_bytes());
        bytes.extend_from_slice(&self.last[part].unwrap_or(u64::MAX).to_le_bytes());
        bytes.extend_from_slice(self.held[part].as_flattened());
        bytes.resize(self.block_bytes(), 0);
        file.file.write_all_at(&bytes, self.end)?;
        self.last[part] = Some(self.end);
        self.end += bytes.len() as u64;
        self.held[part].clear();
        Ok(())
    }

    /// Hands every record of a part to `f`, its blocks from the last back,
    /// then what is held of it.
    fn each_of(&self, part: usize, mut f: impl FnMut(&[[u8; N]]) -> Result<()>) -> Result<()> {
        let mut at = self.last[part];
        let mut buf = vec![0u8; self.block_bytes()];
        while let (Some(start), Some(file)) = (at, &self.file) {
            file.file.read_exact_at(&mut buf, start)?;
            let mut prev = [0u8; 8];
            prev.copy_from_slice(&buf[..8]);
            let prev = u64::from_le_bytes(prev);
            let records: Vec<[u8; N]> = buf[8..]
                .chunks_exact(N)
                .map(|r| {
                    let mut a = [0u8; N];
                    a.copy_from_slice(r);
                    a
                })
                .collect();
            f(&records)?;
            at = (prev != u64::MAX).then_some(prev);
        }
        f(&self.held[part])
    }

    /// Hands every record to `out`, in order, a slice at a time.
    pub fn finish(mut self, mut out: impl FnMut(&[[u8; N]]) -> Result<()>) -> Result<()> {
        let fits = (self.part_memory / N) as u64;
        let mut part_buf: Vec<[u8; N]> = Vec::new();
        for part in 0..PARTS {
            let count = self.counts[part];
            if count == 0 {
                continue;
            }
            if count <= fits {
                part_buf.clear();
                part_buf.reserve_exact(count as usize);
                self.each_of(part, |records| {
                    part_buf.extend_from_slice(records);
                    Ok(())
                })?;
                part_buf.sort_unstable();
                out(&part_buf)?;
            } else {
                let mut stem = self.stem.clone().into_os_string();
                stem.push(format!(".part{part}"));
                let mut sorter = Sorter::<N>::new(PathBuf::from(stem), self.chunk, FAN_IN)
                    .ordered(ChunkOrder::Radix);
                self.each_of(part, |records| {
                    for &r in records {
                        sorter.push(r)?;
                    }
                    Ok(())
                })?;
                sorter.finish(&mut out)?;
            }
            // Done with: its memory goes now.
            self.held[part] = Vec::new();
        }
        Ok(())
    }
}

// ---- writing ------------------------------------------------------------------

/// The ids a segment is finished with. A file's segment is written as the
/// file is read, before the store has given the file, its packets or its
/// lanes their ids: until then lanes are numbered from 0 in the order the
/// file first meets them (its own numbers), and packets by index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ids {
    pub file_id: i64,
    /// Part of the name, if given: `<file id>.<serial>.seg`.
    pub serial: Option<i64>,
    pub first_packet: i64,
    /// The store's id of each of the file's own lane numbers.
    pub lanes: Vec<u32>,
}

/// What the store keeps about a written segment, in its `segments` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub name: String,
    pub first_packet: i64,
    pub last_packet: i64,
    /// Lowest and highest value and grid shift on the receive clock and on
    /// the packet clock, if any packet has that time.
    pub times: [Option<(i64, i64, u32)>; 2],
    pub order_shift: u32,
    /// What the segment holds of each lane, in lane order.
    pub lanes: Vec<(u32, LaneStats)>,
}

/// Writes one segment as a file's packets are read, with the file's own
/// lane numbers; [`Writer::finish_with`] writes the rest with the store's
/// ids. Nothing is visible under the segment's own name until then; dropped
/// before that, it leaves nothing behind.
pub struct Writer {
    folder: PathBuf,
    /// Names the temporary files.
    stem: String,
    /// The ids [`Writer::finish`] uses, for a writer made by
    /// [`Writer::create`] or [`Writer::with_chunk`]: file id, serial, first
    /// packet id.
    given: (i64, Option<i64>, i64),
    temp: TempFile,
    out: BufWriter<File>,
    at: u64,
    /// Has the segment written back to disk as it grows.
    flusher: Flusher,
    count: u64,
    labels: layout::Map<String, u32>,
    label_list: Vec<String>,
    sorters: Vec<Sorter<TIME_BYTES>>,
    ranges: [Option<(i64, i64)>; 2],
    /// Kept series numbered by packet name, then field name.
    series: layout::Map<String, layout::Map<String, u32>>,
    series_list: Vec<(String, String)>,
    /// Kept values in packet order and their texts, until they are copied
    /// into the segment at the end.
    values: Option<Spool>,
    texts: Option<Spool>,
    /// Kept numbers and arrival delays per time clock, to be sorted by
    /// lane, series and time.
    points: Vec<Sorter<POINT_KEY_BYTES>>,
    /// The last packet added: its index, lane and times.
    current: Option<(u32, u32, [Option<i64>; 2])>,
    /// What has been added of each lane, with indexes for ids.
    lanes: LaneTable<LaneStats>,
    /// One more than the highest lane number added.
    lane_bound: u32,
    /// The records each bucket grid would hold, per clock (receive,
    /// packet, order), counted as the values come in order: the order
    /// clock's from the packets once their ids are known, the time clocks'
    /// as their sections are written.
    levels: [LevelCounter; 3],
    /// Every space packet, to be sorted by checksum, sequence count,
    /// length and index.
    sums: Option<Spread<CHECKSUM_KEY_BYTES>>,
    /// Every kept value, to be sorted by series, number, index and place.
    by_value: Option<Sorter<VALUE_KEY_BYTES>>,
}

/// How much of a segment is written between asking for it to be written
/// back to disk.
const FLUSH_EVERY: u64 = 64 << 20;

/// Asks, on a thread of its own, for a segment to be written back to disk
/// every [`FLUSH_EVERY`] bytes while it is finished, so that the sync that
/// ends it has little left to wait for. Asking again while it is still
/// writing back asks for nothing more. (Asked while the file is read as
/// well, it held up the reading more than it saved: measured on btrfs.)
struct Flusher {
    wake: Option<std::sync::mpsc::SyncSender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    next: u64,
}

impl Flusher {
    fn start(file: &File) -> Result<Flusher> {
        let file = file.try_clone()?;
        let (wake, woken) = std::sync::mpsc::sync_channel::<()>(1);
        let thread = std::thread::Builder::new()
            .name("segment-flush".into())
            .stack_size(64 << 10)
            .spawn(move || {
                while woken.recv().is_ok() {
                    // The sync that ends the segment reports any failure.
                    let _ = file.sync_data();
                }
            })?;
        Ok(Flusher {
            wake: Some(wake),
            thread: Some(thread),
            next: FLUSH_EVERY,
        })
    }

    /// The file is `at` bytes long now.
    fn at(&mut self, at: u64) {
        if at >= self.next {
            self.next = at + FLUSH_EVERY;
            if let Some(wake) = &self.wake {
                let _ = wake.try_send(());
            }
        }
    }

    fn stop(&mut self) {
        self.wake = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Bytes written one after another to a temporary file, to be copied into
/// a segment when it is finished.
struct Spool {
    temp: TempFile,
    out: BufWriter<File>,
    len: u64,
}

impl Spool {
    fn create(path: PathBuf) -> Result<Spool> {
        let temp = TempFile::create(path)?;
        let out = BufWriter::with_capacity(SPOOL_BUFFER, temp.file.try_clone()?);
        Ok(Spool { temp, out, len: 0 })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes)?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Copies everything written to `out`; returns how many bytes.
    fn copy_into(mut self, out: &mut impl Write) -> Result<u64> {
        self.out.flush()?;
        let mut buf = vec![0u8; IO_BUFFER];
        let mut at = 0u64;
        while at < self.len {
            let n = (self.len - at).min(buf.len() as u64) as usize;
            self.temp.file.read_exact_at(&mut buf[..n], at)?;
            out.write_all(&buf[..n])?;
            at += n as u64;
        }
        Ok(self.len)
    }
}

/// One lane's one series as its points come out of the sorter, with its
/// buckets so far.
struct OpenGroup {
    lane: u32,
    series: u32,
    first: u64,
    count: u64,
    buckets: Vec<SeriesBucket>,
}

impl OpenGroup {
    fn add(&mut self, shift: u32, p: &PointRecord) {
        self.count += 1;
        let bucket = layout::bucket_of(p.ns, shift);
        match self.buckets.last_mut() {
            Some(b) if b.bucket == bucket => {
                b.lo = b.lo.min(p.num);
                b.hi = b.hi.max(p.num);
                b.count += 1;
            }
            _ => self.buckets.push(SeriesBucket {
                bucket,
                lo: p.num,
                hi: p.num,
                count: 1,
            }),
        }
    }

    /// Its group record, its buckets written to `spool` if they pay.
    fn close(self, spool: &mut Spool) -> Result<GroupRecord> {
        let bucket_first = spool.len / SERIES_BUCKET_BYTES as u64;
        let n = self.buckets.len() as u64;
        let keep = layout::series_buckets_pay(n, self.count);
        if keep {
            for b in &self.buckets {
                spool.write(&b.encode())?;
            }
        }
        Ok(GroupRecord {
            lane: self.lane,
            series: self.series,
            first: self.first,
            count: self.count,
            bucket_first,
            buckets: if keep { n } else { 0 },
        })
    }
}

impl Writer {
    /// Starts the segment of file `file_id`, whose first packet has id
    /// `first_packet`, with lanes numbered as the store numbers them:
    /// [`Writer::finish`] keeps every number as it is.
    pub fn create(folder: &Path, file_id: i64, first_packet: i64) -> Result<Writer> {
        Writer::with_chunk(folder, file_id, first_packet, SORT_CHUNK)
    }

    /// Names the segment `<file id>.<serial>.seg` instead of
    /// `<file id>.seg`. The store gives each segment a serial it never gives
    /// again, so that a name a reader has listed never comes to mean
    /// another segment.
    pub fn with_serial(mut self, serial: i64) -> Writer {
        self.given.1 = Some(serial);
        self
    }

    /// As [`Writer::create`], with sorters that hold `chunk` records.
    pub fn with_chunk(
        folder: &Path,
        file_id: i64,
        first_packet: i64,
        chunk: usize,
    ) -> Result<Writer> {
        let mut w = if chunk == SORT_CHUNK {
            Writer::start(folder, &file_id.to_string(), CHUNK_BYTES)?
        } else {
            Writer::build(folder, &file_id.to_string(), |_| chunk)?
        };
        w.given = (file_id, None, first_packet);
        Ok(w)
    }

    /// Starts a segment whose ids are given when it is finished
    /// ([`Writer::finish_with`]). Its temporary files are named from
    /// `stem`, which no other writer in the folder may be using; each of
    /// its six sorters holds about `chunk_bytes` of records at once.
    pub fn start(folder: &Path, stem: &str, chunk_bytes: usize) -> Result<Writer> {
        Writer::build(folder, stem, |record| (chunk_bytes / record).max(1))
    }

    /// A writer whose sorters of records `n` bytes long hold `chunk(n)`.
    fn build(folder: &Path, stem: &str, chunk: impl Fn(usize) -> usize) -> Result<Writer> {
        let temp = TempFile::create(folder.join(format!("{stem}.seg.tmp")))?;
        let flusher = Flusher::start(&temp.file)?;
        let mut out = BufWriter::with_capacity(IO_BUFFER, temp.file.try_clone()?);
        out.write_all(&MAGIC)?;
        let path = |what: &str| folder.join(format!("{stem}.{what}"));
        let sorter = |clock: &str| Sorter::new(path(clock), chunk(TIME_BYTES), FAN_IN).reserved();
        let points = |clock: &str| {
            Sorter::new(path(clock), chunk(POINT_KEY_BYTES), FAN_IN)
                .ordered(ChunkOrder::Grouped)
                .reserved()
        };
        let spool = |what: &str| Spool::create(folder.join(format!("{stem}.{what}.tmp")));
        Ok(Writer {
            folder: folder.to_path_buf(),
            stem: stem.to_string(),
            given: (0, None, 1),
            temp,
            out,
            at: MAGIC.len() as u64,
            flusher,
            count: 0,
            labels: layout::Map::default(),
            label_list: Vec::new(),
            sorters: vec![sorter("receive"), sorter("packet")],
            ranges: [None, None],
            series: layout::Map::default(),
            series_list: Vec::new(),
            values: Some(spool("values")?),
            texts: Some(spool("texts")?),
            points: vec![points("receive-kept"), points("packet-kept")],
            current: None,
            lanes: LaneTable::default(),
            lane_bound: 0,
            levels: Default::default(),
            sums: Some(Spread::new(path("sums"), chunk(CHECKSUM_KEY_BYTES))),
            by_value: Some(
                Sorter::new(path("by-value"), chunk(VALUE_KEY_BYTES), FAN_IN).reserved(),
            ),
        })
    }

    /// The number of a kept series in this segment.
    fn series_id(&mut self, packet: &str, field: &str) -> Result<u32> {
        if let Some(&n) = self.series.get(packet).and_then(|f| f.get(field)) {
            return Ok(n);
        }
        let n = u32::try_from(self.series_list.len())
            .ok()
            .filter(|&n| n < layout::MAX_SERIES)
            .ok_or("too many kept fields for a segment")?;
        self.series
            .entry(packet.to_string())
            .or_default()
            .insert(field.to_string(), n);
        self.series_list
            .push((packet.to_string(), field.to_string()));
        Ok(n)
    }

    /// Adds a kept value of the packet added last, as the `field_values`
    /// table gets it. A number that is not a number is kept as none, as
    /// SQLite stores it.
    pub fn push_value(
        &mut self,
        packet: &str,
        field: &str,
        num: Option<f64>,
        text: Option<&str>,
    ) -> Result<()> {
        let (index, lane, times) = self.current.ok_or("a kept value before any packet")?;
        let series = self.series_id(packet, field)?;
        let num = num.filter(|n| !n.is_nan());
        let (Some(values), Some(texts)) = (&mut self.values, &mut self.texts) else {
            return Err("a kept value after the segment was finished".into());
        };
        let text_at = match text {
            Some(text) => {
                let at = texts.len;
                texts.write(&layout::encode_label(text)?)?;
                Some(at)
            }
            None => None,
        };
        let record = ValueRecord {
            index,
            series,
            num,
            text_at,
        };
        let position = values.len / VALUE_BYTES as u64;
        values.write(&record.encode())?;
        if let Some(by_value) = &mut self.by_value {
            by_value.push(layout::value_key(
                series,
                num,
                index,
                position,
                text_at.is_some(),
            ))?;
        }
        if let Some(num) = num {
            for (c, t) in times.into_iter().enumerate() {
                if let Some(ns) = t {
                    let p = PointRecord { ns, index, num };
                    self.points[c].push(layout::point_key(lane, series, &p))?;
                }
            }
        }
        Ok(())
    }

    /// Adds the next packet, of lane `lane` (the file's own number for it,
    /// see [`Ids`]). Its id is the first packet's plus the number added
    /// before it.
    pub fn push(&mut self, lane: i64, row: &PacketRow, label: Option<&str>) -> Result<()> {
        let label = match label {
            None => None,
            Some(text) => Some(match self.labels.get(text) {
                Some(&n) => n,
                None => {
                    let n = self.add_label(text.to_string())?;
                    self.labels.insert(text.to_string(), n);
                    n
                }
            }),
        };
        self.push_numbered(lane, row, label)
    }

    /// Adds a label to the segment's list, numbered on from the one added
    /// before it, for packets added with [`Writer::push_numbered`].
    pub fn add_label(&mut self, text: String) -> Result<u32> {
        let n =
            u32::try_from(self.label_list.len()).map_err(|_| "too many labels for a segment")?;
        self.label_list.push(text);
        Ok(n)
    }

    /// As [`Writer::push`], with the label given by its number: labels
    /// numbered by whoever adds the packets, in the order they first come,
    /// and each added ([`Writer::add_label`]) before the first packet with
    /// it. Either way the segment numbers them so.
    pub fn push_numbered(&mut self, lane: i64, row: &PacketRow, label: Option<u32>) -> Result<()> {
        let index = u32::try_from(self.count)
            .map_err(|_| "more packets in one file than a segment holds")?;
        let lane = u32::try_from(lane)
            .ok()
            .filter(|&l| l < u32::MAX)
            .ok_or("lane id out of range for a segment")?;
        if label.is_some_and(|n| n as usize >= self.label_list.len()) {
            return Err("a packet's label was not added".into());
        }
        self.lane_bound = self.lane_bound.max(lane + 1);
        let record = PacketRecord {
            receive_ns: row.receive_ns,
            packet_ns: row.packet_ns,
            offset: row.offset,
            sum: row.sum,
            length: row.length,
            lane,
            label,
            header: row
                .header
                .map(|h| (h.apid, h.seq_count, ptype_code(h.packet_type) as u8)),
            length_ok: row.length_ok,
        };
        self.out.write_all(&record.encode())?;
        self.at += PACKET_BYTES as u64;
        for (c, t) in [row.receive_ns, row.packet_ns].into_iter().enumerate() {
            if let Some(ns) = t {
                self.sorters[c].push(TimeRecord { ns, index, lane }.sort_key())?;
                self.ranges[c] = Some(match self.ranges[c] {
                    Some((lo, hi)) => (lo.min(ns), hi.max(ns)),
                    None => (ns, ns),
                });
            }
        }
        // Arrival delay, on both clocks, for a packet with both times.
        if let (Some(r), Some(p)) = (row.receive_ns, row.packet_ns) {
            let num = layout::delay_ms(r, p);
            for (c, ns) in [r, p].into_iter().enumerate() {
                let point = PointRecord { ns, index, num };
                self.points[c].push(layout::point_key(lane, DELAY, &point))?;
            }
        }
        if let (Some(h), Some(sums)) = (row.header, &mut self.sums) {
            let record = ChecksumRecord {
                sum: row.sum,
                seq: h.seq_count,
                length: row.length,
                lane,
                index,
            };
            sums.push(record.sort_key())?;
        }
        let at = i64::from(index);
        self.lanes
            .get_or_insert_with(lane, || LaneStats::new(at))
            .add(at, [row.receive_ns, row.packet_ns]);
        self.current = Some((index, lane, [row.receive_ns, row.packet_ns]));
        self.count += 1;
        Ok(())
    }

    /// Puts the store's lane ids (`lanes`, by the file's own number) in the
    /// packets section in place of the file's own numbers, and counts the
    /// order clock's bucket levels, which need the packets' ids. One pass
    /// over the section, already flushed, a buffer at a time.
    fn seal_packets(&mut self, lanes: &[u32], first_packet: i64) -> Result<()> {
        let mut buf = vec![0u8; IO_BUFFER / PACKET_BYTES * PACKET_BYTES];
        let mut at = MAGIC.len() as u64;
        let end = at + self.count * PACKET_BYTES as u64;
        let mut id = first_packet;
        while at < end {
            let n = ((end - at) as usize).min(buf.len());
            let part = &mut buf[..n];
            self.temp.file.read_exact_at(part, at)?;
            for record in part.chunks_exact_mut(PACKET_BYTES) {
                let own = PacketRecord::lane_of(record);
                let lane = *lanes
                    .get(own as usize)
                    .ok_or("a lane of the segment has no id")?;
                if lane == u32::MAX {
                    return Err("lane id out of range for a segment".into());
                }
                self.levels[2].add(own, id);
                PacketRecord::set_lane(record, lane);
                id += 1;
            }
            self.temp.file.write_all_at(part, at)?;
            at += n as u64;
        }
        Ok(())
    }

    /// Writes bytes at the end, returning where they started.
    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let start = self.at;
        self.out.write_all(bytes)?;
        self.at += bytes.len() as u64;
        self.flusher.at(self.at);
        Ok(start)
    }

    /// [`Writer::finish_with`] the ids the writer was made with, every lane
    /// keeping its number.
    pub fn finish(self) -> Result<Option<Written>> {
        let (file_id, serial, first_packet) = self.given;
        let lanes = (0..self.lane_bound).collect();
        self.finish_with(&Ids {
            file_id,
            serial,
            first_packet,
            lanes,
        })
    }

    /// Writes the rest of the segment with the store's ids, syncs it and
    /// gives it its own name. Returns `None`, leaving nothing behind, if no
    /// packet was added. The caller adds the `segments` row in the
    /// transaction that commits the file's rows, and checks there that the
    /// ids are the ones the store gives.
    pub fn finish_with(mut self, ids: &Ids) -> Result<Option<Written>> {
        if self.count == 0 {
            return Ok(None);
        }
        if ids.lanes.len() < self.lane_bound as usize {
            return Err("a lane of the segment has no id".into());
        }
        let lanes = ids.lanes.as_slice();
        let first_packet = ids.first_packet;
        self.out.flush()?;
        self.seal_packets(lanes, first_packet)?;
        let mut entries = vec![Entry {
            kind: KIND_PACKETS,
            clock: 0,
            record: PACKET_BYTES as u32,
            offset: MAGIC.len() as u64,
            length: self.count * PACKET_BYTES as u64,
            param: 0,
        }];

        let start = self.at;
        for text in std::mem::take(&mut self.label_list) {
            self.append(&layout::encode_label(&text)?)?;
        }
        entries.push(Entry {
            kind: KIND_LABELS,
            clock: 0,
            record: 0,
            offset: start,
            length: self.at - start,
            param: 0,
        });

        for (c, sorter) in std::mem::take(&mut self.sorters).into_iter().enumerate() {
            let start = self.at;
            let out = &mut self.out;
            let levels = &mut self.levels[c];
            let mut length = 0u64;
            let flusher = &mut self.flusher;
            sorter.finish(|keys| {
                flusher.at(start + length);
                for key in keys {
                    let mut record = TimeRecord::from_sort_key(key);
                    levels.add(record.lane, record.ns);
                    record.lane = lanes[record.lane as usize];
                    out.write_all(&record.encode())?;
                }
                length += (keys.len() * TIME_BYTES) as u64;
                Ok(())
            })?;
            self.at += length;
            entries.push(Entry {
                kind: KIND_TIME,
                clock: c as u8,
                record: TIME_BYTES as u32,
                offset: start,
                length,
                param: 0,
            });
        }
        // How many records each level would hold was counted as the values
        // came in order; the levels worth keeping are written finest first,
        // the finest counted from the section just written read back in its
        // order (time order for the time clocks, id order for the order
        // clock), each coarser one from the level before it.
        self.out.flush()?;
        let last_packet = first_packet + self.count as i64 - 1;
        let order_shift = layout::grid_shift(first_packet, last_packet);
        let mut times = [None, None];
        let mut grids = Vec::new();
        for c in 0..2 {
            if let Some((lo, hi)) = self.ranges[c] {
                let shift = layout::grid_shift(lo, hi);
                times[c] = Some((lo, hi, shift));
                grids.push((c as u8, shift, entries[2 + c]));
            }
        }
        grids.push((2, order_shift, entries[0]));
        for (clock, base, source) in grids {
            let (records, values) = self.levels[usize::from(clock)].records(base);
            let mut finer: Option<(Entry, u32)> = None;
            for shift in layout::choose_levels(base, &records, values) {
                let entry = match finer {
                    None => self.bucket_section(clock, shift, source, first_packet)?,
                    Some((finer, from)) => self.coarser_section(clock, shift, finer, from)?,
                };
                entries.push(entry);
                finer = Some((entry, shift));
            }
        }

        // Kept values: the series' names, the values in packet order and
        // their texts, then for each time clock the numbers and delays by
        // lane, series and time, their buckets and where each group lies.
        let start = self.at;
        for (packet, field) in std::mem::take(&mut self.series_list) {
            self.append(&layout::encode_label(&packet)?)?;
            self.append(&layout::encode_label(&field)?)?;
        }
        entries.push(Entry {
            kind: KIND_SERIES_NAMES,
            clock: 0,
            record: 0,
            offset: start,
            length: self.at - start,
            param: 0,
        });
        let spools = [
            (KIND_VALUES, VALUE_BYTES as u32, self.values.take()),
            (KIND_TEXTS, 0, self.texts.take()),
        ];
        for (kind, record, spool) in spools {
            let spool = spool.ok_or("segment finished twice")?;
            let start = self.at;
            self.at += spool.copy_into(&mut self.out)?;
            entries.push(Entry {
                kind,
                clock: 0,
                record,
                offset: start,
                length: self.at - start,
                param: 0,
            });
        }
        for (c, sorter) in std::mem::take(&mut self.points).into_iter().enumerate() {
            let shift = times[c].map_or(0, |t| layout::series_shift(t.2));
            entries.extend(self.series_sections(c as u8, shift, sorter, lanes)?);
        }
        // Every space packet by checksum, for the comparison of sources.
        let sums = self.sums.take().ok_or("segment finished twice")?;
        let start = self.at;
        let out = &mut self.out;
        let mut length = 0u64;
        let flusher = &mut self.flusher;
        sums.finish(|keys| {
            flusher.at(start + length);
            for key in keys {
                let mut record = ChecksumRecord::from_sort_key(key);
                record.lane = lanes[record.lane as usize];
                out.write_all(&record.encode())?;
            }
            length += (keys.len() * CHECKSUM_BYTES) as u64;
            Ok(())
        })?;
        self.at += length;
        entries.push(Entry {
            kind: KIND_CHECKSUMS,
            clock: 0,
            record: CHECKSUM_BYTES as u32,
            offset: start,
            length,
            param: 0,
        });

        // Every kept value by series and number, for `field_values` in
        // order of value, and where each series lies.
        let by_value = self.by_value.take().ok_or("segment finished twice")?;
        let start = self.at;
        let out = &mut self.out;
        let mut groups: Vec<ValueGroup> = Vec::new();
        let mut written = 0u64;
        by_value.finish(|keys| {
            for key in keys {
                let (series, has, record) = layout::from_value_key(key);
                match groups.last_mut() {
                    Some(g) if g.series == series => g.count += 1,
                    _ => groups.push(ValueGroup {
                        series,
                        first: written,
                        nulls: 0,
                        count: 1,
                    }),
                }
                if !has && let Some(g) = groups.last_mut() {
                    g.nulls += 1;
                }
                out.write_all(&record.encode())?;
                written += 1;
            }
            Ok(())
        })?;
        self.at += written * VALUE_ORDER_BYTES as u64;
        entries.push(Entry {
            kind: KIND_VALUE_ORDER,
            clock: 0,
            record: VALUE_ORDER_BYTES as u32,
            offset: start,
            length: self.at - start,
            param: 0,
        });
        let start = self.at;
        for g in &groups {
            self.append(&g.encode())?;
        }
        entries.push(Entry {
            kind: KIND_VALUE_GROUPS,
            clock: 0,
            record: VALUE_GROUP_BYTES as u32,
            offset: start,
            length: self.at - start,
            param: 0,
        });

        let tail = Tail {
            first_packet,
            packets: self.count,
            entries: entries.len() as u32,
        };
        for e in &entries {
            self.out.write_all(&e.encode())?;
        }
        self.out.write_all(&tail.encode())?;
        self.out.flush()?;
        self.flusher.stop();
        self.temp.file.sync_all()?;

        // The name is free if no earlier segment holds it, including the
        // one this file had before, which stays until the commit.
        let stem = match ids.serial {
            Some(serial) => format!("{}.{serial}", ids.file_id),
            None => ids.file_id.to_string(),
        };
        let name = (0..)
            .map(|n| match n {
                0 => format!("{stem}.seg"),
                n => format!("{stem}.{n}.seg"),
            })
            .find(|name| !self.folder.join(name).exists())
            .ok_or("no free segment name")?;
        fs::rename(&self.temp.path, self.folder.join(&name))?;
        // Renamed: the temporary file is gone, nothing to remove on drop.
        self.temp.path = PathBuf::new();
        File::open(&self.folder)?.sync_all()?;
        let mut held: Vec<(u32, LaneStats)> = std::mem::take(&mut self.lanes)
            .into_sorted()
            .into_iter()
            .map(|(own, mut s)| {
                s.first_id += first_packet;
                s.last_id += first_packet;
                (lanes[own as usize], s)
            })
            .collect();
        held.sort_unstable_by_key(|l| l.0);
        Ok(Some(Written {
            name,
            first_packet,
            last_packet,
            times,
            order_shift,
            lanes: held,
        }))
    }

    /// Writes one time clock's kept numbers and delays from their sorter,
    /// grouped by lane and series, with each group's buckets on the grid of
    /// `shift` where they pay, and the groups. The points come grouped by
    /// the file's own lane numbers; the groups are written with the store's
    /// (`lanes`), in order of those. Returns the three entries.
    fn series_sections(
        &mut self,
        clock: u8,
        shift: u32,
        sorter: Sorter<POINT_KEY_BYTES>,
        lanes: &[u32],
    ) -> Result<[Entry; 3]> {
        let mut buckets = Spool::create(
            self.folder
                .join(format!("{}.buckets{clock}.tmp", self.stem)),
        )?;
        let mut groups: Vec<GroupRecord> = Vec::new();
        let mut open: Option<OpenGroup> = None;
        let start = self.at;
        let mut written = 0u64;
        let out = &mut self.out;
        let flusher = &mut self.flusher;
        sorter.finish(|keys| {
            flusher.at(start + written * POINT_BYTES as u64);
            for key in keys {
                let (lane, series, point) = layout::from_point_key(key);
                if open
                    .as_ref()
                    .is_some_and(|g| (g.lane, g.series) != (lane, series))
                    && let Some(g) = open.take()
                {
                    groups.push(g.close(&mut buckets)?);
                }
                let group = open.get_or_insert_with(|| OpenGroup {
                    lane,
                    series,
                    first: written,
                    count: 0,
                    buckets: Vec::new(),
                });
                group.add(shift, &point);
                out.write_all(&point.encode())?;
                written += 1;
            }
            Ok(())
        })?;
        if let Some(g) = open.take() {
            groups.push(g.close(&mut buckets)?);
        }
        for g in &mut groups {
            g.lane = lanes[g.lane as usize];
        }
        groups.sort_unstable_by_key(|g| (g.lane, g.series));
        self.at += written * POINT_BYTES as u64;
        let series = Entry {
            kind: KIND_SERIES,
            clock,
            record: POINT_BYTES as u32,
            offset: start,
            length: self.at - start,
            param: 0,
        };
        let start = self.at;
        self.at += buckets.copy_into(&mut self.out)?;
        let bucket_entry = Entry {
            kind: KIND_SERIES_BUCKETS,
            clock,
            record: SERIES_BUCKET_BYTES as u32,
            offset: start,
            length: self.at - start,
            param: i64::from(shift),
        };
        let start = self.at;
        for g in &groups {
            self.append(&g.encode())?;
        }
        let group_entry = Entry {
            kind: KIND_GROUPS,
            clock,
            record: GROUP_BYTES as u32,
            offset: start,
            length: self.at - start,
            param: 0,
        };
        Ok([series, bucket_entry, group_entry])
    }

    /// Counts one clock's buckets on the grid of `shift` by reading
    /// `source` from end to end, and appends them.
    fn bucket_section(
        &mut self,
        clock: u8,
        shift: u32,
        source: Entry,
        first_packet: i64,
    ) -> Result<Entry> {
        let start = self.at;
        let mut tally = Tally::new(shift);
        let file = self.temp.file.try_clone()?;
        let out = &mut self.out;
        each_value(&file, first_packet, clock, source, |t, lane| {
            tally.add(t, lane, 1, out)
        })?;
        tally.flush(out)?;
        self.at += tally.written;
        Ok(Entry {
            kind: KIND_BUCKETS,
            clock,
            record: BUCKET_BYTES as u32,
            offset: start,
            length: tally.written,
            param: i64::from(shift),
        })
    }

    /// Counts one clock's buckets on the grid of `shift` from those of the
    /// finer grid of shift `from`, in section `finer` just written, and
    /// appends them: a bucket of the coarser grid is a run of whole buckets
    /// of the finer one.
    fn coarser_section(&mut self, clock: u8, shift: u32, finer: Entry, from: u32) -> Result<Entry> {
        self.out.flush()?;
        let start = self.at;
        let step = shift.saturating_sub(from);
        let mut tally = Tally::new(0);
        let file = self.temp.file.try_clone()?;
        let out = &mut self.out;
        let end = finer.offset + finer.length;
        let mut r = RangeReader::<BUCKET_BYTES>::new(&file, finer.offset, end, IO_BUFFER);
        while let Some(rec) = r.read()? {
            let b = BucketRecord::decode(&rec);
            tally.add(layout::bucket_of(b.bucket, step), b.lane, b.count, out)?;
        }
        tally.flush(out)?;
        self.at += tally.written;
        Ok(Entry {
            kind: KIND_BUCKETS,
            clock,
            record: BUCKET_BYTES as u32,
            offset: start,
            length: tally.written,
            param: i64::from(shift),
        })
    }
}

/// Hands each (value, lane) of a clock to `f`, in ascending order of value,
/// by reading `source` from end to end: a time-order section, or for the
/// order clock (2) the packets section, whose first packet has id `first`.
fn each_value(
    file: &File,
    first: i64,
    clock: u8,
    source: Entry,
    mut f: impl FnMut(i64, u32) -> Result<()>,
) -> Result<()> {
    let end = source.offset + source.length;
    if clock == 2 {
        let mut r = RangeReader::<PACKET_BYTES>::new(file, source.offset, end, IO_BUFFER);
        let mut id = first;
        while let Some(rec) = r.read()? {
            f(id, PacketRecord::lane_of(&rec))?;
            id += 1;
        }
    } else {
        let mut r = RangeReader::<TIME_BYTES>::new(file, source.offset, end, IO_BUFFER);
        while let Some(rec) = r.read()? {
            let rec = TimeRecord::decode(&rec);
            f(rec.ns, rec.lane)?;
        }
    }
    Ok(())
}

/// Counts packets per lane in one bucket at a time, from values that come
/// in ascending order, writing each bucket's records when the next begins.
struct Tally {
    shift: u32,
    current: Option<i64>,
    /// Each lane's count in the current bucket, and the lanes counted.
    counts: LaneTable<u32>,
    touched: Vec<u32>,
    written: u64,
}

impl Tally {
    fn new(shift: u32) -> Tally {
        Tally {
            shift,
            current: None,
            counts: LaneTable::default(),
            touched: Vec::new(),
            written: 0,
        }
    }

    /// Adds `n` packets of `lane` at `t`.
    fn add(&mut self, t: i64, lane: u32, n: u32, out: &mut impl Write) -> Result<()> {
        let bucket = layout::bucket_of(t, self.shift);
        if self.current != Some(bucket) {
            self.flush(out)?;
            self.current = Some(bucket);
        }
        let count = self.counts.get_or_insert_with(lane, || 0);
        if *count == 0 {
            self.touched.push(lane);
        }
        *count += n;
        Ok(())
    }

    fn flush(&mut self, out: &mut impl Write) -> Result<()> {
        let Some(bucket) = self.current else {
            return Ok(());
        };
        self.touched.sort_unstable();
        for lane in std::mem::take(&mut self.touched) {
            let count = self
                .counts
                .get_mut(lane)
                .map(std::mem::take)
                .unwrap_or_default();
            out.write_all(
                &BucketRecord {
                    bucket,
                    lane,
                    count,
                }
                .encode(),
            )?;
            self.written += BUCKET_BYTES as u64;
        }
        Ok(())
    }
}

type Error = crate::shell::store::Error;

// ---- reading ------------------------------------------------------------------

/// An open segment, its directory checked.
pub struct Segment {
    file: File,
    first_packet: i64,
    packets: u64,
    entries: Vec<Entry>,
}

impl Segment {
    pub fn open(path: &Path) -> Result<Segment> {
        let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let len = file.metadata()?.len();
        let fail = |e: FormatError| -> Error { format!("{}: {e}", path.display()).into() };
        if len < (MAGIC.len() + TAIL_BYTES) as u64 {
            return Err(fail(FormatError("too short to be a segment".into())));
        }
        let mut magic = [0u8; 8];
        file.read_exact_at(&mut magic, 0)?;
        if magic != MAGIC {
            return Err(fail(FormatError("not a segment file (bad magic)".into())));
        }
        let mut tail = [0u8; TAIL_BYTES];
        file.read_exact_at(&mut tail, len - TAIL_BYTES as u64)?;
        let tail = Tail::decode(&tail).map_err(fail)?;
        let dir_at = tail.directory_at(len).map_err(fail)?;
        let mut dir = vec![0u8; tail.entries as usize * ENTRY_BYTES];
        file.read_exact_at(&mut dir, dir_at)?;
        let entries: Vec<Entry> = dir.chunks_exact(ENTRY_BYTES).map(Entry::decode).collect();
        layout::check_directory(&entries, &tail, dir_at).map_err(fail)?;
        Ok(Segment {
            file,
            first_packet: tail.first_packet,
            packets: tail.packets,
            entries,
        })
    }

    pub fn first_packet(&self) -> i64 {
        self.first_packet
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Where a section lies in the file: its offset and length in bytes.
    pub fn section_bytes(&self, kind: u16, clock: Clock) -> Result<(u64, u64)> {
        let e = self.section(kind, layout::clock_code(clock))?;
        Ok((e.offset, e.length))
    }

    /// Reads bytes at an offset, for a reader that keeps its own buffer.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }

    /// The position of the first record of a time clock's time order whose
    /// time is at least `at_least`.
    pub fn time_position(&self, clock: Clock, at_least: i64) -> Result<u64> {
        let e = self.section(KIND_TIME, layout::clock_code(clock))?;
        self.lower_bound(&e, at_least)
    }

    /// The position of the first kept value of the packet at `index` or of
    /// a later one.
    pub fn value_position(&self, index: u64) -> Result<u64> {
        let e = self.section(KIND_VALUES, 0)?;
        self.search(&e, (0, e.records()), 4, |b| u64::from(u32_le(b)) < index)
    }

    fn section(&self, kind: u16, clock: u8) -> Result<Entry> {
        self.entries
            .iter()
            .find(|e| e.kind == kind && e.clock == clock)
            .copied()
            .ok_or_else(|| format!("segment has no section of kind {kind}, clock {clock}").into())
    }

    /// The first record of a sorted section whose leading i64 is at least
    /// `key`, by binary search with one small read a step.
    fn lower_bound(&self, e: &Entry, key: i64) -> Result<u64> {
        let (mut lo, mut hi) = (0u64, e.records());
        let mut b = [0u8; 8];
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            self.file
                .read_exact_at(&mut b, e.offset + mid * u64::from(e.record))?;
            if i64::from_le_bytes(b) < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Hands each record of a sorted section whose leading i64 lies in
    /// `lo..=hi` to `f`.
    fn scan<const N: usize>(
        &self,
        e: &Entry,
        lo: i64,
        hi: i64,
        mut f: impl FnMut(&[u8; N]),
    ) -> Result<()> {
        let first = self.lower_bound(e, lo)?;
        let mut r = RangeReader::<N>::new(
            &self.file,
            e.offset + first * N as u64,
            e.offset + e.length,
            SCAN_BUFFER,
        );
        while let Some(rec) = r.read()? {
            let mut b = [0u8; 8];
            b.copy_from_slice(&rec[..8]);
            if i64::from_le_bytes(b) > hi {
                break;
            }
            f(&rec);
        }
        Ok(())
    }

    /// Each packet whose time on `clock` lies in `lo..=hi`, as (lane,
    /// time); on the order clock the time is the packet id.
    pub fn points(
        &self,
        clock: Clock,
        lo: i64,
        hi: i64,
        mut f: impl FnMut(u32, i64),
    ) -> Result<()> {
        if lo > hi {
            return Ok(());
        }
        match clock {
            Clock::Order => {
                let last = self.first_packet + self.packets as i64 - 1;
                let (lo, hi) = (lo.max(self.first_packet), hi.min(last));
                if lo > hi {
                    return Ok(());
                }
                let e = self.section(KIND_PACKETS, 0)?;
                let start = e.offset + (lo - self.first_packet) as u64 * PACKET_BYTES as u64;
                let end = e.offset + (hi - self.first_packet + 1) as u64 * PACKET_BYTES as u64;
                let mut r = RangeReader::<PACKET_BYTES>::new(&self.file, start, end, SCAN_BUFFER);
                let mut id = lo;
                while let Some(rec) = r.read()? {
                    f(PacketRecord::lane_of(&rec), id);
                    id += 1;
                }
                Ok(())
            }
            _ => {
                let e = self.section(KIND_TIME, layout::clock_code(clock))?;
                self.scan::<TIME_BYTES>(&e, lo, hi, |rec| {
                    let rec = TimeRecord::decode(rec);
                    f(rec.lane, rec.ns);
                })
            }
        }
    }

    /// The shifts of the bucket levels stored for a clock, finest first;
    /// empty if no level was worth storing.
    pub fn levels(&self, clock: Clock) -> Vec<u32> {
        let code = layout::clock_code(clock);
        let mut out: Vec<u32> = self
            .entries
            .iter()
            .filter(|e| e.kind == KIND_BUCKETS && e.clock == code)
            .map(|e| e.param as u32)
            .collect();
        out.sort_unstable();
        out
    }

    /// Each stored bucket from `first` to `last` of the level of `shift`
    /// on `clock`.
    pub fn buckets(
        &self,
        clock: Clock,
        shift: u32,
        first: i64,
        last: i64,
        mut f: impl FnMut(BucketRecord),
    ) -> Result<()> {
        let code = layout::clock_code(clock);
        let e = self
            .entries
            .iter()
            .find(|e| e.kind == KIND_BUCKETS && e.clock == code && e.param == i64::from(shift))
            .copied()
            .ok_or_else(|| format!("segment has no bucket level of shift {shift}"))?;
        self.scan::<BUCKET_BYTES>(&e, first, last, |rec| f(BucketRecord::decode(rec)))
    }

    /// The packet at `index` within the segment.
    pub fn packet(&self, index: u64) -> Result<PacketRecord> {
        if index >= self.packets {
            return Err("no such packet in the segment".into());
        }
        let e = self.section(KIND_PACKETS, 0)?;
        let mut b = [0u8; PACKET_BYTES];
        self.file
            .read_exact_at(&mut b, e.offset + index * PACKET_BYTES as u64)?;
        Ok(PacketRecord::decode(&b))
    }

    /// The first record in `lo..hi` of a fixed-width section for which
    /// `before`, given the record's first `key` bytes, is false, by binary
    /// search with one small read a step. `before` must be true for a
    /// leading run of records and false after.
    fn search(
        &self,
        e: &Entry,
        (mut lo, mut hi): (u64, u64),
        key: usize,
        before: impl Fn(&[u8]) -> bool,
    ) -> Result<u64> {
        let mut b = [0u8; 16];
        let key = key.min(16).min(e.record as usize);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            self.file
                .read_exact_at(&mut b[..key], e.offset + mid * u64::from(e.record))?;
            if before(&b[..key]) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Hands records `from..to` of a fixed-width section to `f`, in order,
    /// until `f` returns false.
    fn each<const N: usize>(
        &self,
        e: &Entry,
        from: u64,
        to: u64,
        mut f: impl FnMut(&[u8; N]) -> Result<bool>,
    ) -> Result<()> {
        let to = to.min(e.records());
        if from >= to {
            return Ok(());
        }
        let mut r = RangeReader::<N>::new(
            &self.file,
            e.offset + from * N as u64,
            e.offset + to * N as u64,
            SCAN_BUFFER,
        );
        while let Some(rec) = r.read()? {
            if !f(&rec)? {
                break;
            }
        }
        Ok(())
    }

    /// Packets `from..=to` by index within the segment, with their index.
    pub fn packets_in(
        &self,
        from: u64,
        to: u64,
        mut f: impl FnMut(u64, PacketRecord) -> Result<bool>,
    ) -> Result<()> {
        let e = self.section(KIND_PACKETS, 0)?;
        let mut index = from;
        self.each::<PACKET_BYTES>(&e, from, to.saturating_add(1), |rec| {
            let go = f(index, PacketRecord::decode(rec))?;
            index += 1;
            Ok(go)
        })
    }

    /// A cursor over the packets from index `from` on, in index order.
    pub fn packet_cursor(&self, from: u64) -> Result<PacketCursor<'_>> {
        let e = self.section(KIND_PACKETS, 0)?;
        let from = from.min(self.packets);
        Ok(PacketCursor {
            index: from,
            reader: RangeReader::new(
                &self.file,
                e.offset + from * PACKET_BYTES as u64,
                e.offset + e.length,
                SCAN_BUFFER,
            ),
        })
    }

    /// A cursor over the packets whose time on a time clock is at least
    /// `from`, in order of time and index.
    pub fn times_from(&self, clock: Clock, from: i64) -> Result<TimeCursor<'_>> {
        let e = self.section(KIND_TIME, layout::clock_code(clock))?;
        let first = self.lower_bound(&e, from)?;
        Ok(TimeCursor {
            reader: RangeReader::new(
                &self.file,
                e.offset + first * TIME_BYTES as u64,
                e.offset + e.length,
                SCAN_BUFFER,
            ),
        })
    }

    /// The kept series this segment names, by number: packet name and
    /// field name.
    pub fn series_names(&self) -> Result<Vec<(String, String)>> {
        let e = self.section(KIND_SERIES_NAMES, 0)?;
        let len = usize::try_from(e.length).map_err(|_| "series names section too large")?;
        let mut b = vec![0u8; len];
        self.file.read_exact_at(&mut b, e.offset)?;
        let names = layout::decode_labels(&b)?;
        if names.len() % 2 != 0 {
            return Err(FormatError("series names section is not in pairs".into()).into());
        }
        Ok(names
            .chunks_exact(2)
            .map(|p| (p[0].clone(), p[1].clone()))
            .collect())
    }

    /// The number of a kept series in this segment, if it has the series.
    pub fn series_id(&self, packet: &str, field: &str) -> Result<Option<u32>> {
        Ok(self
            .series_names()?
            .iter()
            .position(|(p, f)| p == packet && f == field)
            .map(|n| n as u32))
    }

    /// Every group (lane and series) of kept numbers and delays on a time
    /// clock, in order of lane and series, each checked to lie within its
    /// sections.
    pub fn groups(&self, clock: Clock) -> Result<Vec<GroupRecord>> {
        let code = layout::clock_code(clock);
        let e = self.section(KIND_GROUPS, code)?;
        let points = self.section(KIND_SERIES, code)?.records();
        let buckets = self.section(KIND_SERIES_BUCKETS, code)?.records();
        let series = self.series_names()?.len() as u64;
        let mut out = Vec::with_capacity(e.records() as usize);
        let mut bad = false;
        self.each::<GROUP_BYTES>(&e, 0, e.records(), |rec| {
            let g = GroupRecord::decode(rec);
            let ends =
                |first: u64, n: u64, of: u64| first.checked_add(n).is_some_and(|end| end <= of);
            bad = !ends(g.first, g.count, points)
                || !ends(g.bucket_first, g.buckets, buckets)
                || (g.series != DELAY && u64::from(g.series) >= series)
                || out.last().is_some_and(|last: &GroupRecord| {
                    (last.lane, last.series) >= (g.lane, g.series)
                });
            out.push(g);
            Ok(!bad)
        })?;
        if bad {
            return Err(FormatError("a group of kept numbers is out of range".into()).into());
        }
        Ok(out)
    }

    /// The group of one lane's one series on a time clock, if there is one.
    /// Found by binary search, and checked to lie within its sections.
    pub fn group(&self, clock: Clock, lane: u32, series: u32) -> Result<Option<GroupRecord>> {
        let code = layout::clock_code(clock);
        let e = self.section(KIND_GROUPS, code)?;
        let key = |b: &[u8]| (u32_le(b), u32_le(&b[4..]));
        let at = self.search(&e, (0, e.records()), 8, |b| key(b) < (lane, series))?;
        let mut found = None;
        self.each::<GROUP_BYTES>(&e, at, at + 1, |rec| {
            let g = GroupRecord::decode(rec);
            found = Some(g).filter(|g| (g.lane, g.series) == (lane, series));
            Ok(false)
        })?;
        let Some(g) = found else {
            return Ok(None);
        };
        let points = self.section(KIND_SERIES, code)?.records();
        let buckets = self.section(KIND_SERIES_BUCKETS, code)?.records();
        let ends = |first: u64, n: u64, of: u64| first.checked_add(n).is_some_and(|end| end <= of);
        if !ends(g.first, g.count, points) || !ends(g.bucket_first, g.buckets, buckets) {
            return Err(FormatError("a group of kept numbers is out of range".into()).into());
        }
        Ok(Some(g))
    }

    /// How many packets have a time on a time clock.
    pub fn timed(&self, clock: Clock) -> Result<u64> {
        Ok(self
            .section(KIND_TIME, layout::clock_code(clock))?
            .records())
    }

    /// The grid shift of a time clock's series buckets.
    pub fn series_shift(&self, clock: Clock) -> Result<u32> {
        let e = self.section(KIND_SERIES_BUCKETS, layout::clock_code(clock))?;
        Ok(e.param as u32)
    }

    /// The points of a group whose time lies in `lo..=hi`, in order.
    pub fn group_points(
        &self,
        clock: Clock,
        g: &GroupRecord,
        lo: i64,
        hi: i64,
        mut f: impl FnMut(PointRecord),
    ) -> Result<()> {
        if lo > hi {
            return Ok(());
        }
        let e = self.section(KIND_SERIES, layout::clock_code(clock))?;
        let end = g.first + g.count;
        let first = self.search(&e, (g.first, end), 8, |b| i64_le(b) < lo)?;
        self.each::<POINT_BYTES>(&e, first, end, |rec| {
            let p = PointRecord::decode(rec);
            if p.ns > hi {
                return Ok(false);
            }
            f(p);
            Ok(true)
        })
    }

    /// The stored buckets of a group from `first` to `last`, in order.
    pub fn group_buckets(
        &self,
        clock: Clock,
        g: &GroupRecord,
        first: i64,
        last: i64,
        mut f: impl FnMut(SeriesBucket),
    ) -> Result<()> {
        let e = self.section(KIND_SERIES_BUCKETS, layout::clock_code(clock))?;
        let end = g.bucket_first + g.buckets;
        let from = self.search(&e, (g.bucket_first, end), 8, |b| i64_le(b) < first)?;
        self.each::<SERIES_BUCKET_BYTES>(&e, from, end, |rec| {
            let b = SeriesBucket::decode(rec);
            if b.bucket > last {
                return Ok(false);
            }
            f(b);
            Ok(true)
        })
    }

    /// The kept values of packets `from..=to` (indexes within the segment),
    /// in packet order and, within a packet, in the order they were kept.
    pub fn values_in(
        &self,
        from: u64,
        to: u64,
        mut f: impl FnMut(ValueRecord) -> Result<bool>,
    ) -> Result<()> {
        let e = self.section(KIND_VALUES, 0)?;
        let first = self.search(&e, (0, e.records()), 4, |b| u64::from(u32_le(b)) < from)?;
        self.each::<VALUE_BYTES>(&e, first, e.records(), |rec| {
            let v = ValueRecord::decode(rec);
            if u64::from(v.index) > to {
                return Ok(false);
            }
            f(v)
        })
    }

    /// The kept value at `position` in the values section.
    pub fn value_at(&self, position: u64) -> Result<ValueRecord> {
        let e = self.section(KIND_VALUES, 0)?;
        if position >= e.records() {
            return Err(FormatError("a kept value is out of range".into()).into());
        }
        let mut b = [0u8; VALUE_BYTES];
        self.file
            .read_exact_at(&mut b, e.offset + position * VALUE_BYTES as u64)?;
        Ok(ValueRecord::decode(&b))
    }

    /// Every series' place in the value-order section, in series order,
    /// checked to lie within it.
    pub fn value_groups(&self) -> Result<Vec<ValueGroup>> {
        let e = self.section(KIND_VALUE_GROUPS, 0)?;
        let records = self.section(KIND_VALUE_ORDER, 0)?.records();
        let series = self.series_names()?.len() as u64;
        let mut out = Vec::with_capacity(e.records().min(series) as usize);
        let mut bad = false;
        self.each::<VALUE_GROUP_BYTES>(&e, 0, e.records(), |rec| {
            let g = ValueGroup::decode(rec);
            bad = g.first.checked_add(g.count).is_none_or(|end| end > records)
                || g.nulls > g.count
                || u64::from(g.series) >= series
                || out
                    .last()
                    .is_some_and(|l: &ValueGroup| l.series >= g.series);
            out.push(g);
            Ok(!bad)
        })?;
        if bad {
            return Err(
                FormatError("a group of values in value order is out of range".into()).into(),
            );
        }
        Ok(out)
    }

    /// The records of group `g` in the value-order section, as a range
    /// `from..to`, whose number lies above `lo` and below `hi` (each a
    /// number and whether it is excluded), by two binary searches.
    pub fn value_order_range(
        &self,
        g: &ValueGroup,
        lo: Option<(f64, bool)>,
        hi: Option<(f64, bool)>,
    ) -> Result<(u64, u64)> {
        let e = self.section(KIND_VALUE_ORDER, 0)?;
        let (start, end) = (g.first + g.nulls, g.first + g.count);
        let key = layout::ValueOrderRecord::key_of;
        let from = match lo {
            None => start,
            Some((x, strict)) => {
                let k = layout::number_key(x);
                self.search(&e, (start, end), 8, |b| {
                    if strict { key(b) <= k } else { key(b) < k }
                })?
            }
        };
        let to = match hi {
            None => end,
            Some((x, strict)) => {
                let k = layout::number_key(x);
                self.search(&e, (from, end), 8, |b| {
                    if strict { key(b) < k } else { key(b) <= k }
                })?
            }
        };
        Ok((from, to.max(from)))
    }

    /// The text of a value, from the texts section.
    pub fn text(&self, at: u64) -> Result<String> {
        let e = self.section(KIND_TEXTS, 0)?;
        let fail = || -> Error { FormatError("a kept text is out of range".into()).into() };
        if at.checked_add(4).is_none_or(|end| end > e.length) {
            return Err(fail());
        }
        let mut len = [0u8; 4];
        self.file.read_exact_at(&mut len, e.offset + at)?;
        let len = u64::from(u32::from_le_bytes(len));
        if at + 4 + len > e.length {
            return Err(fail());
        }
        let mut b = vec![0u8; len as usize];
        self.file.read_exact_at(&mut b, e.offset + at + 4)?;
        String::from_utf8(b).map_err(|_| FormatError("a kept text is not UTF-8".into()).into())
    }

    /// The kept values of the packet at `index`: packet name, field name,
    /// number and text, in the order they were kept.
    pub fn values_of(&self, index: u64) -> Result<Vec<KeptRow>> {
        let names = self.series_names()?;
        let mut found = Vec::new();
        self.values_in(index, index, |v| {
            found.push(v);
            Ok(true)
        })?;
        let mut out = Vec::with_capacity(found.len());
        for v in found {
            let (packet, field) = names
                .get(v.series as usize)
                .ok_or_else(|| FormatError("a kept value names no series".into()))?;
            let text = match v.text_at {
                Some(at) => Some(self.text(at)?),
                None => None,
            };
            out.push(KeptRow {
                packet: packet.clone(),
                field: field.clone(),
                num: v.num,
                text,
            });
        }
        Ok(out)
    }

    /// The segment's labels, numbered as packet records refer to them.
    pub fn labels(&self) -> Result<Vec<String>> {
        let e = self.section(KIND_LABELS, 0)?;
        let len = usize::try_from(e.length).map_err(|_| "labels section too large")?;
        let mut b = vec![0u8; len];
        self.file.read_exact_at(&mut b, e.offset)?;
        Ok(layout::decode_labels(&b)?)
    }

    /// The segment's space packets in checksum order, read through a
    /// buffer of about `buffer` bytes on a handle of their own.
    pub fn checksums(&self, buffer: usize) -> Result<Checksums> {
        let e = self.section(KIND_CHECKSUMS, 0)?;
        Ok(Checksums {
            records: RecordFile::new(
                self.file.try_clone()?,
                e.offset,
                e.offset + e.length,
                buffer,
            ),
            packets: self.packets,
        })
    }
}

/// Fixed-width records from one range of a file it owns, through a buffer.
pub(crate) struct RecordFile<const N: usize> {
    file: File,
    next: u64,
    end: u64,
    buf: Vec<u8>,
    at: usize,
}

impl<const N: usize> RecordFile<N> {
    pub(crate) fn new(file: File, start: u64, end: u64, buffer: usize) -> Self {
        RecordFile {
            file,
            next: start,
            end,
            buf: Vec::with_capacity((buffer / N).max(1) * N),
            at: 0,
        }
    }

    pub(crate) fn read(&mut self) -> Result<Option<[u8; N]>> {
        if self.at >= self.buf.len() {
            in_time()?;
            let left = self.end.saturating_sub(self.next);
            if left < N as u64 {
                return Ok(None);
            }
            let want = (self.buf.capacity() as u64).min(left / N as u64 * N as u64) as usize;
            self.buf.resize(want, 0);
            self.file.read_exact_at(&mut self.buf, self.next)?;
            self.next += want as u64;
            self.at = 0;
        }
        let mut record = [0u8; N];
        record.copy_from_slice(&self.buf[self.at..self.at + N]);
        self.at += N;
        Ok(Some(record))
    }
}

/// A segment's space packets in checksum order.
pub struct Checksums {
    records: RecordFile<CHECKSUM_BYTES>,
    packets: u64,
}

impl Checksums {
    /// The next record, checked to name a packet of the segment.
    pub fn next_record(&mut self) -> Result<Option<ChecksumRecord>> {
        let Some(b) = self.records.read()? else {
            return Ok(None);
        };
        let r = ChecksumRecord::decode(&b);
        if u64::from(r.index) >= self.packets {
            return Err(FormatError("a checksum record names no packet".into()).into());
        }
        Ok(Some(r))
    }
}

/// One kept value read back: as a `field_values` row has it.
#[derive(Debug, Clone, PartialEq)]
pub struct KeptRow {
    pub packet: String,
    pub field: String,
    pub num: Option<f64>,
    pub text: Option<String>,
}

/// Packets in order of time and index on one time clock, from a segment.
pub struct TimeCursor<'a> {
    reader: RangeReader<'a, TIME_BYTES>,
}

impl TimeCursor<'_> {
    pub fn next_time(&mut self) -> Result<Option<TimeRecord>> {
        Ok(self.reader.read()?.map(|b| TimeRecord::decode(&b)))
    }
}

/// Packets in index order, with their index, from a segment.
pub struct PacketCursor<'a> {
    index: u64,
    reader: RangeReader<'a, PACKET_BYTES>,
}

impl PacketCursor<'_> {
    pub fn next_packet(&mut self) -> Result<Option<(u64, PacketRecord)>> {
        let Some(b) = self.reader.read()? else {
            return Ok(None);
        };
        self.index += 1;
        Ok(Some((self.index - 1, PacketRecord::decode(&b))))
    }
}

fn i64_le(b: &[u8]) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    i64::from_le_bytes(a)
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One segment as the store lists it: enough to decide, without opening
/// it, whether a window touches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub first_packet: i64,
    /// Lowest and highest value on the clock asked about.
    pub min: i64,
    pub max: i64,
}

/// Packet counts per lane and view bucket over `from..=to` in buckets
/// `width` wide, from the listed segments, by the rule in
/// `pure::segment::plan`. Rows are (lane, bucket, count), one per lane and
/// bucket, in that order.
pub fn density(
    folder: &Path,
    listed: &[Listed],
    clock: Clock,
    from: i64,
    to: i64,
    width: i64,
) -> Result<Vec<(i64, i64, i64)>> {
    let mut counts = layout::Counts::new(from, to, width);
    for s in listed {
        if s.max < from || s.min > to {
            continue;
        }
        let segment = open_listed(folder, s)?;
        // The coarsest level the view's buckets are wide enough for; with
        // none, every packet in the window is counted.
        let shift = layout::level_for(&segment.levels(clock), width);
        let plan = match shift {
            Some(shift) => layout::plan(from, to, width, shift),
            None => layout::Plan {
                whole: None,
                direct: vec![(from, to)],
            },
        };
        if let (Some((first, last)), Some(shift)) = (plan.whole, shift) {
            segment.buckets(clock, shift, first, last, |b| {
                counts.bucket(b.lane, b.bucket, shift, b.count);
            })?;
        }
        for (lo, hi) in plan.direct {
            segment.points(clock, lo, hi, |lane, t| counts.point(lane, t))?;
        }
    }
    Ok(counts.rows())
}

/// A listed segment that is gone, or is not the one listed: its file was
/// read again, and the segment replaced, after the list was read. Reading
/// the list again finds the new one.
#[derive(Debug)]
pub struct Stale(pub String);

impl std::fmt::Display for Stale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Stale {}

/// Opens a listed segment, checking it is still the one listed; [`Stale`]
/// if it is not.
pub fn open_listed(folder: &Path, s: &Listed) -> Result<Segment> {
    let path = folder.join(&s.name);
    let segment = match Segment::open(&path) {
        Ok(segment) => segment,
        Err(_) if !path.exists() => {
            return Err(Stale(format!("{}: gone since it was listed", s.name)).into());
        }
        Err(e) => return Err(e),
    };
    if segment.first_packet() != s.first_packet {
        return Err(Stale(format!("{}: replaced since it was listed", s.name)).into());
    }
    Ok(segment)
}

/// One packet of an item list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub id: i64,
    pub lane: u32,
    /// Its time on the clock asked about; its id on the order clock.
    pub time: i64,
    pub seq: Option<u16>,
    pub length: i64,
}

/// The first `limit` packets whose time on `clock` lies in `from..=to`,
/// from the listed segments, in order of time and then id. Each segment's
/// time order is read from the start of the window and the segments are
/// merged, so the cost follows `limit`, not the window.
pub fn items(
    folder: &Path,
    listed: &[Listed],
    clock: Clock,
    from: i64,
    to: i64,
    limit: usize,
) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    if from > to || limit == 0 {
        return Ok(out);
    }
    let mut segments = Vec::new();
    for s in listed {
        if s.max >= from && s.min <= to {
            segments.push(open_listed(folder, s)?);
        }
    }
    if clock == Clock::Order {
        segments.sort_by_key(Segment::first_packet);
        for seg in &segments {
            let first = seg.first_packet();
            let last = first + seg.packets() as i64 - 1;
            let (lo, hi) = (from.max(first), to.min(last));
            if lo > hi {
                continue;
            }
            seg.packets_in((lo - first) as u64, (hi - first) as u64, |index, p| {
                let id = first + index as i64;
                out.push(item(id, id, &p));
                Ok(out.len() < limit)
            })?;
            if out.len() >= limit {
                break;
            }
        }
        return Ok(out);
    }
    let mut cursors = Vec::with_capacity(segments.len());
    let mut heap = BinaryHeap::new();
    for (i, seg) in segments.iter().enumerate() {
        let mut cursor = seg.times_from(clock, from)?;
        if let Some(t) = cursor.next_time()? {
            heap.push(Reverse((t.ns, seg.first_packet() + i64::from(t.index), i)));
        }
        cursors.push(cursor);
    }
    let mut chosen = Vec::new();
    while let Some(Reverse((ns, id, i))) = heap.pop() {
        if ns > to || chosen.len() >= limit {
            break;
        }
        chosen.push((ns, id, i));
        if let Some(t) = cursors[i].next_time()? {
            heap.push(Reverse((
                t.ns,
                segments[i].first_packet() + i64::from(t.index),
                i,
            )));
        }
    }
    drop(cursors);
    for (ns, id, i) in chosen {
        let seg = &segments[i];
        let p = seg.packet((id - seg.first_packet()) as u64)?;
        out.push(item(id, ns, &p));
    }
    Ok(out)
}

/// One lane's kept field (`field` as packet name and field name), or its
/// arrival delay if `field` is `None`, over `from..=to` in buckets `width`
/// wide, from the listed segments: (bucket, lowest, highest, count) for
/// each bucket with values, in bucket order.
///
/// On a time clock a segment's stored buckets of the series are taken
/// whole where the rule of `pure::segment::plan` allows and they were kept,
/// and the rest is read point by point from the series' group. On the
/// order clock the packets in the window are read with their values.
#[allow(clippy::too_many_arguments)]
pub fn series(
    folder: &Path,
    listed: &[Listed],
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    from: i64,
    to: i64,
    width: i64,
) -> Result<Vec<(i64, f64, f64, u64)>> {
    let mut bins = layout::SeriesBins::new(from, to, width);
    let Ok(lane) = u32::try_from(lane) else {
        return Ok(Vec::new());
    };
    if from > to {
        return Ok(Vec::new());
    }
    for s in listed {
        if s.max < from || s.min > to {
            continue;
        }
        let seg = open_listed(folder, s)?;
        let series = match field {
            None => DELAY,
            Some((packet, name)) => match seg.series_id(packet, name)? {
                Some(id) => id,
                None => continue,
            },
        };
        if clock == Clock::Order {
            order_series(&seg, lane, series, from, to, &mut bins)?;
            continue;
        }
        let Some(group) = seg.group(clock, lane, series)? else {
            continue;
        };
        let shift = seg.series_shift(clock)?;
        let plan = if group.buckets > 0 {
            layout::plan(from, to, width, shift)
        } else {
            layout::Plan {
                whole: None,
                direct: vec![(from, to)],
            }
        };
        if let Some((first, last)) = plan.whole {
            seg.group_buckets(clock, &group, first, last, |b| bins.bucket(&b, shift))?;
        }
        for (lo, hi) in plan.direct {
            seg.group_points(clock, &group, lo, hi, |p| bins.point(p.ns, p.num))?;
        }
    }
    Ok(bins.rows())
}

/// A series on the order clock, from one segment: the lane's packets with
/// ids in `from..=to` and, for a kept field, their values, read side by
/// side in packet order.
fn order_series(
    seg: &Segment,
    lane: u32,
    series: u32,
    from: i64,
    to: i64,
    bins: &mut layout::SeriesBins,
) -> Result<()> {
    let first = seg.first_packet();
    let last = first + seg.packets() as i64 - 1;
    let (lo, hi) = (from.max(first), to.min(last));
    if lo > hi {
        return Ok(());
    }
    let (lo, hi) = ((lo - first) as u64, (hi - first) as u64);
    // The lane's group on a time clock holds all of the series if every
    // packet has that time (and every delay, which needs both); if it
    // holds fewer points than the window has packets, it is read instead.
    for clock in [Clock::Receive, Clock::Packet] {
        let whole = series == DELAY || seg.timed(clock)? == seg.packets();
        if !whole {
            continue;
        }
        let Some(g) = seg.group(clock, lane, series)? else {
            // None of the lane's packets here has a value of the series.
            return Ok(());
        };
        if g.count <= hi - lo + 1 {
            return seg.group_points(clock, &g, i64::MIN, i64::MAX, |p| {
                let index = u64::from(p.index);
                if (lo..=hi).contains(&index) {
                    bins.point(first + index as i64, p.num);
                }
            });
        }
        break;
    }
    if series == DELAY {
        return seg.packets_in(lo, hi, |index, p| {
            if p.lane == lane
                && let (Some(r), Some(t)) = (p.receive_ns, p.packet_ns)
            {
                bins.point(first + index as i64, layout::delay_ms(r, t));
            }
            Ok(true)
        });
    }
    let mut packets = seg.packet_cursor(lo)?;
    let mut at: Option<(u64, u32)> = None;
    seg.values_in(lo, hi, |v| {
        let Some(num) = v.num.filter(|_| v.series == series) else {
            return Ok(true);
        };
        let index = u64::from(v.index);
        // The packet's lane, reading forward to it.
        while at.is_none_or(|(i, _)| i < index) {
            let Some((i, p)) = packets.next_packet()? else {
                return Ok(false);
            };
            at = Some((i, p.lane));
        }
        if at == Some((index, lane)) {
            bins.point(first + index as i64, num);
        }
        Ok(true)
    })
}

fn item(id: i64, time: i64, p: &PacketRecord) -> Item {
    Item {
        id,
        lane: p.lane,
        time,
        seq: p.header.map(|h| h.1),
        length: p.length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Scratch {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "packetlane-seg-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The sorted output, the most runs merged at once, and how many bytes
    /// the files in the folder held while the last merge ran.
    fn sort_all(
        scratch: &Scratch,
        input: &[u64],
        chunk: usize,
        fan_in: usize,
    ) -> (Vec<u64>, usize, usize) {
        let mut sorter = Sorter::<8>::new(scratch.0.join("t"), chunk, fan_in);
        for v in input {
            sorter.push(v.to_be_bytes()).unwrap();
        }
        let mut out = Vec::new();
        let mut files = 0;
        let widest = sorter
            .finish(|records| {
                if out.is_empty() {
                    files = fs::read_dir(&scratch.0)
                        .unwrap()
                        .map(|e| e.unwrap().metadata().unwrap().len() as usize)
                        .sum();
                }
                out.extend(records.iter().map(|b| u64::from_be_bytes(*b)));
                Ok(())
            })
            .unwrap();
        (out, widest, files)
    }

    #[test]
    fn the_spread_sorter_gives_the_order_of_a_plain_sort_whatever_the_input() {
        let scratch = Scratch::new();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let n = 3_000u64;
        let shapes: Vec<(&str, Vec<[u8; 10]>)> = vec![
            ("random", (0..n).map(|_| key(random(), 0)).collect()),
            (
                "random with ties",
                (0..n)
                    .map(|_| key((random() % 40) << 56, random() as u16 % 3))
                    .collect(),
            ),
            (
                "one first byte",
                (0..n)
                    .map(|i| key((0x42 << 56) | (random() % 100), i as u16))
                    .collect(),
            ),
            ("all equal", (0..n).map(|_| key(7, 7)).collect()),
            ("sorted", (0..n).map(|i| key(i << 48, 0)).collect()),
            ("reversed", (0..n).map(|i| key((n - i) << 48, 0)).collect()),
            ("few", (0..5).map(|_| key(random(), 1)).collect()),
            ("none", Vec::new()),
        ];
        fn key(a: u64, b: u16) -> [u8; 10] {
            let mut k = [0u8; 10];
            k[..8].copy_from_slice(&a.to_be_bytes());
            k[8..].copy_from_slice(&b.to_be_bytes());
            k
        }
        for (name, input) in &shapes {
            let mut expected = input.clone();
            expected.sort_unstable();
            for chunk in [1, 300, 5_000, 100_000] {
                // In memory always, never, or as a part's size has it.
                for memory in [usize::MAX, 0, 400] {
                    let mut sorter =
                        Spread::<10>::new(scratch.0.join("p"), chunk).sorting_in_memory(memory);
                    for r in input {
                        sorter.push(*r).unwrap();
                    }
                    let mut out = Vec::new();
                    sorter
                        .finish(|records| {
                            out.extend_from_slice(records);
                            Ok(())
                        })
                        .unwrap();
                    let what = format!("{name} chunk {chunk} memory {memory}");
                    assert!(out == expected, "{what}");
                    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0, "{what}");
                }
            }
        }
    }

    #[test]
    fn the_sorter_merges_more_runs_than_it_opens_at_once() {
        let scratch = Scratch::new();
        // A scrambled sequence with repeats: 5,000 records in chunks of 7
        // is hundreds of runs, merged 4 at a time in many passes.
        let input: Vec<u64> = (0..5_000u64).map(|i| (i * 7_919) % 1_009).collect();
        let mut expected = input.clone();
        expected.sort_unstable();
        // Never more runs at once than allowed, and by the time the output
        // is handed out the temporary files hold at most twice the input.
        for fan_in in [4, 32] {
            let (out, widest, files) = sort_all(&scratch, &input, 7, fan_in);
            assert_eq!((out == expected, widest), (true, fan_in));
            assert!(files <= 2 * 8 * input.len(), "{files}");
        }
        // Few enough runs to merge in one go; one chunk, sorted in memory.
        assert_eq!(
            sort_all(&scratch, &input, 1_000, 32),
            (expected.clone(), 5, 8 * input.len())
        );
        assert_eq!(sort_all(&scratch, &input, 100_000, 4), (expected, 0, 0));
        assert_eq!(sort_all(&scratch, &[], 7, 4), (Vec::new(), 0, 0));
        // Input in order is one run, whatever the chunk.
        let sorted: Vec<u64> = (0..5_000).collect();
        assert_eq!(sort_all(&scratch, &sorted, 7, 4), (sorted, 1, 8 * 5_000));
        // Its temporary files are gone.
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn the_sorter_gives_the_order_of_a_plain_sort_whatever_the_input() {
        let scratch = Scratch::new();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Records of a group (eight bytes) and a value (four), as the
        // sorter of kept numbers has them.
        let record = |group: u64, value: u32| {
            let mut b = [0u8; 12];
            b[..8].copy_from_slice(&group.to_be_bytes());
            b[8..].copy_from_slice(&value.to_be_bytes());
            b
        };
        let n = 600u32;
        let shapes: Vec<(&str, Vec<[u8; 12]>)> = vec![
            ("sorted", (0..n).map(|i| record(0, i)).collect()),
            ("ties", (0..n).map(|i| record(0, i / 40)).collect()),
            (
                "late",
                (0..n)
                    .map(|i| {
                        record(
                            0,
                            if i % 97 == 0 {
                                i.saturating_sub(150)
                            } else {
                                i
                            },
                        )
                    })
                    .collect(),
            ),
            (
                "blocks swapped",
                (0..n).map(|i| record(0, (i + 250) % n)).collect(),
            ),
            ("reversed", (0..n).map(|i| record(0, n - i)).collect()),
            (
                "random",
                (0..n)
                    .map(|_| record(random() % 50, random() as u32 % 100))
                    .collect(),
            ),
            ("all equal", (0..n).map(|_| record(7, 7)).collect()),
            (
                "streams apart",
                (0..n)
                    .map(|i| record(0, i * 10 + (i % 3) * 2_000))
                    .collect(),
            ),
            (
                "groups",
                (0..n)
                    .map(|i| record(u64::from(i % 9) << 40, i - i % 9 + (i % 4)))
                    .collect(),
            ),
            (
                "first bytes spread",
                (0..n)
                    .map(|_| record(random(), random() as u32 % 3))
                    .collect(),
            ),
        ];
        for (name, input) in &shapes {
            let mut expected = input.clone();
            expected.sort_unstable();
            for how in [ChunkOrder::Compare, ChunkOrder::Grouped, ChunkOrder::Radix] {
                for chunk in [1, 3, 64, 1_000] {
                    for fan_in in [2, 3, 8, 128] {
                        let mut sorter =
                            Sorter::<12>::new(scratch.0.join("s"), chunk, fan_in).ordered(how);
                        for r in input {
                            sorter.push(*r).unwrap();
                        }
                        let mut out = Vec::new();
                        let widest = sorter
                            .finish(|records| {
                                out.extend_from_slice(records);
                                Ok(())
                            })
                            .unwrap();
                        let what = format!("{name} {how:?} chunk {chunk} fan-in {fan_in}");
                        assert!(out == expected, "{what}");
                        assert!(widest <= fan_in, "{what}");
                        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0, "{what}");
                    }
                }
            }
        }
    }

    #[test]
    fn galloping_finds_what_a_binary_search_finds() {
        for len in 0..40u8 {
            let records: Vec<[u8; 1]> = (0..len).map(|i| [i / 3 * 2]).collect();
            for bound in 0..90u8 {
                let want = records.partition_point(|r| r[0] <= bound);
                assert_eq!(gallop(&records, &[bound]), want, "{len} {bound}");
            }
        }
    }

    #[test]
    fn a_sorter_dropped_unfinished_leaves_nothing() {
        let scratch = Scratch::new();
        let mut sorter = Sorter::<8>::new(scratch.0.join("t"), 3, 4);
        for v in 0..10u64 {
            sorter.push(v.to_be_bytes()).unwrap();
        }
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 1);
        drop(sorter);
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    fn row(i: i64, receive_ns: Option<i64>, packet_ns: Option<i64>) -> PacketRow {
        PacketRow {
            idx: i,
            offset: i * 10,
            length: 10,
            receive_ns,
            packet_ns,
            header: None,
            length_ok: true,
            sum: i ^ 0x5555,
        }
    }

    #[test]
    fn a_segment_written_through_spilled_runs_is_in_order_and_complete() {
        let scratch = Scratch::new();
        // Sorters of three records: 2,000 packets spill hundreds of runs.
        let mut writer = Writer::with_chunk(&scratch.0, 7, 1_000, 3).unwrap();
        let mut expected: [Vec<(i64, u32, u32)>; 2] = [Vec::new(), Vec::new()];
        for i in 0..2_000i64 {
            let lane = (i % 5) as u32 + 1;
            // Scrambled times with ties; some packets lack one time or both.
            let r = (i % 7 != 0).then_some((i * 7_919) % 1_009 - 500);
            let p = (i % 3 != 0).then_some(-(i * 31) % 97);
            writer
                .push(i64::from(lane), &row(i, r, p), (i % 4 == 0).then_some("A"))
                .unwrap();
            for (c, t) in [r, p].into_iter().enumerate() {
                if let Some(t) = t {
                    expected[c].push((t, i as u32, lane));
                }
            }
        }
        let written = writer.finish().unwrap().unwrap();
        assert_eq!((written.first_packet, written.last_packet), (1_000, 2_999));
        // Only the segment is left: no temporary files.
        let names: Vec<_> = fs::read_dir(&scratch.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("7.seg")]);

        let seg = Segment::open(&scratch.0.join(&written.name)).unwrap();
        for (c, clock) in [Clock::Receive, Clock::Packet].into_iter().enumerate() {
            expected[c].sort_by_key(|&(t, index, _)| (t, index));
            let mut got = Vec::new();
            seg.points(clock, i64::MIN, i64::MAX, |lane, t| got.push((t, lane)))
                .unwrap();
            let want: Vec<(i64, u32)> = expected[c].iter().map(|&(t, _, lane)| (t, lane)).collect();
            assert_eq!(got, want, "{clock:?}");
            let (lo, hi, base) = written.times[c].unwrap();
            assert_eq!((lo, hi), (want[0].0, want[want.len() - 1].0));
            // Levels on the base grid or coarser, each with at most half the
            // records of the one before.
            let levels = seg.levels(clock);
            assert!(!levels.is_empty() && levels[0] >= base, "{levels:?}");
            let mut before = want.len();
            for &shift in &levels {
                // Each level holds every packet once, in order.
                let mut buckets = Vec::new();
                seg.buckets(clock, shift, i64::MIN, i64::MAX, |b| buckets.push(b))
                    .unwrap();
                assert!(
                    buckets
                        .windows(2)
                        .all(|w| (w[0].bucket, w[0].lane) < (w[1].bucket, w[1].lane))
                );
                assert!(buckets.len() * 2 <= before, "{shift}");
                before = buckets.len();
                let mut per_lane = std::collections::BTreeMap::new();
                for b in &buckets {
                    *per_lane.entry(b.lane).or_insert(0u32) += b.count;
                }
                let mut want_lane = std::collections::BTreeMap::new();
                for &(_, lane) in &want {
                    *want_lane.entry(lane).or_insert(0u32) += 1;
                }
                assert_eq!(per_lane, want_lane);
            }
            // A level that is not stored is refused.
            assert!(seg.buckets(clock, 63, 0, 0, |_| ()).is_err());
        }
        let mut ids = Vec::new();
        seg.points(Clock::Order, 1_500, 1_502, |lane, id| ids.push((id, lane)))
            .unwrap();
        assert_eq!(ids, vec![(1_500, 1), (1_501, 2), (1_502, 3)]);
        let p = seg.packet(4).unwrap();
        assert_eq!(
            (p.offset, p.sum, p.label, p.lane),
            (40, 4 ^ 0x5555, Some(0), 5)
        );
        assert_eq!(seg.labels().unwrap(), ["A"]);
    }

    #[test]
    fn kept_values_and_delays_are_written_by_packet_and_by_series() {
        let scratch = Scratch::new();
        // Sorters of three records: everything below spills.
        let mut writer = Writer::with_chunk(&scratch.0, 3, 100, 3).unwrap();
        // (index, lane, receive, packet) and what each packet keeps.
        let mut want_values: Vec<Vec<KeptRow>> = Vec::new();
        type Points = Vec<(i64, u32, f64)>;
        let mut want_points: BTreeMap<(u32, &str, usize), Points> = BTreeMap::new();
        let kept = |packet: &str, field: &str, num: Option<f64>, text: Option<&str>| KeptRow {
            packet: packet.into(),
            field: field.into(),
            num,
            text: text.map(str::to_string),
        };
        for i in 0..600u32 {
            let lane = 1 + i % 2;
            let r = (i % 5 != 0).then_some(i64::from(i) * 1_000 + 7);
            let p = (i % 3 != 0).then_some(i64::from(i) * 1_000 - (i64::from(i) % 4) * 250_000);
            writer
                .push(i64::from(lane), &row(i64::from(i), r, p), None)
                .unwrap();
            let mut values = Vec::new();
            // A number on every packet; on lane 2 a label with it; now and
            // then a text alone, a number that is not one, and an array.
            values.push(kept("HK", "VOLTS", Some(f64::from(i) * 0.5 - 7.0), None));
            if lane == 2 {
                values.push(kept("HK", "MODE", Some(f64::from(i % 3)), Some("RUN")));
            }
            if i % 7 == 0 {
                values.push(kept("TXT", "NAME", None, Some("unit ünï")));
                values.push(kept("HK", "NAN", Some(f64::NAN), None));
                values.push(kept("ARR", "SAMPLES", None, Some("[1, 2, 3]")));
            }
            for v in &values {
                writer
                    .push_value(&v.packet, &v.field, v.num, v.text.as_deref())
                    .unwrap();
            }
            let series_of = |v: &KeptRow| match (v.packet.as_str(), v.field.as_str()) {
                ("HK", "VOLTS") => "VOLTS",
                ("HK", "MODE") => "MODE",
                _ => "-",
            };
            for (c, t) in [r, p].into_iter().enumerate() {
                let Some(ns) = t else { continue };
                for v in &values {
                    if let (Some(num), "VOLTS" | "MODE") =
                        (v.num.filter(|n| !n.is_nan()), series_of(v))
                    {
                        let entry = want_points.entry((lane, series_of(v), c)).or_default();
                        entry.push((ns, i, num));
                    }
                }
                if let (Some(r), Some(p)) = (r, p) {
                    let entry = want_points.entry((lane, "", c)).or_default();
                    entry.push((ns, i, (r - p) as f64 / 1e6));
                }
            }
            // As SQLite stores it: a number that is not one is none.
            for v in &mut values {
                v.num = v.num.filter(|n| !n.is_nan());
            }
            want_values.push(values);
        }
        let written = writer.finish().unwrap().unwrap();
        let names: Vec<_> = fs::read_dir(&scratch.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("3.seg")]);
        let seg = Segment::open(&scratch.0.join(&written.name)).unwrap();

        // By packet: every value, in order, numbers and texts as kept.
        for (i, want) in want_values.iter().enumerate() {
            let got = seg.values_of(i as u64).unwrap();
            assert_eq!(got.len(), want.len(), "{i}");
            for (g, w) in got.iter().zip(want) {
                assert_eq!(
                    (&g.packet, &g.field, g.num.map(f64::to_bits), &g.text),
                    (&w.packet, &w.field, w.num.map(f64::to_bits), &w.text),
                    "{i}"
                );
            }
        }
        assert!(seg.values_of(600).unwrap().is_empty());
        assert_eq!(
            seg.series_id("HK", "MODE").unwrap(),
            Some(4),
            "{:?}",
            seg.series_names()
        );
        assert_eq!(seg.series_id("HK", "NOPE").unwrap(), None);

        // By series: each lane's numbers and delays in order of time.
        for (c, clock) in [Clock::Receive, Clock::Packet].into_iter().enumerate() {
            let groups = seg.groups(clock).unwrap();
            let keys: Vec<_> = groups.iter().map(|g| (g.lane, g.series)).collect();
            let id = |name: &str| match name {
                "" => DELAY,
                name => seg.series_id("HK", name).unwrap().unwrap(),
            };
            let mut by_id = BTreeMap::new();
            for ((lane, name, clock), points) in &want_points {
                if *clock == c {
                    by_id.insert((*lane, id(name)), points.clone());
                }
            }
            let want_keys: Vec<_> = by_id.keys().copied().collect();
            assert_eq!(keys, want_keys, "{clock:?}");
            let shift = seg.series_shift(clock).unwrap();
            assert_eq!(shift, layout::series_shift(written.times[c].unwrap().2));
            for g in &groups {
                let mut want = by_id[&(g.lane, g.series)].clone();
                want.sort_by_key(|a| (a.0, a.1));
                let mut got = Vec::new();
                seg.group_points(clock, g, i64::MIN, i64::MAX, |p| {
                    got.push((p.ns, p.index, p.num));
                })
                .unwrap();
                assert_eq!(got, want, "{clock:?} {g:?}");
                // A window is a binary search and a scan.
                let (lo, hi) = (want[10].0, want[20].0);
                let mut part = Vec::new();
                seg.group_points(clock, g, lo, hi, |p| part.push(p.ns))
                    .unwrap();
                let expect: Vec<i64> = want
                    .iter()
                    .map(|w| w.0)
                    .filter(|t| (lo..=hi).contains(t))
                    .collect();
                assert_eq!(part, expect);
                // Few points a bucket here: no buckets are kept.
                assert_eq!(g.buckets, 0, "{g:?}");
            }
        }
    }

    #[test]
    fn series_buckets_are_kept_where_they_pay() {
        let scratch = Scratch::new();
        let mut writer = Writer::with_chunk(&scratch.0, 4, 1, 50).unwrap();
        // Lane 1 has 5,000 numbers over a span of 1,000 ns: many a bucket.
        // Lane 2 has 20 numbers spread over it: about one a bucket.
        for i in 0..5_020i64 {
            let lane = if i % 251 == 0 { 2 } else { 1 };
            writer
                .push(lane, &row(i, Some(i * 1_000 / 5_020), None), None)
                .unwrap();
            writer
                .push_value("HK", "V", Some((i % 13) as f64), None)
                .unwrap();
        }
        let written = writer.finish().unwrap().unwrap();
        let seg = Segment::open(&scratch.0.join(&written.name)).unwrap();
        let shift = seg.series_shift(Clock::Receive).unwrap();
        assert_eq!(shift, 0);
        let dense = seg.group(Clock::Receive, 1, 0).unwrap().unwrap();
        let sparse = seg.group(Clock::Receive, 2, 0).unwrap().unwrap();
        assert_eq!(sparse.buckets, 0);
        assert!(dense.buckets > 0 && dense.buckets * 4 <= dense.count);
        let mut points = Vec::new();
        seg.group_points(Clock::Receive, &dense, i64::MIN, i64::MAX, |p| {
            points.push(p)
        })
        .unwrap();
        let mut buckets = Vec::new();
        seg.group_buckets(Clock::Receive, &dense, i64::MIN, i64::MAX, |b| {
            buckets.push(b)
        })
        .unwrap();
        // Each bucket is the lowest, highest and number of its points.
        let mut want: Vec<SeriesBucket> = Vec::new();
        for p in &points {
            let bucket = layout::bucket_of(p.ns, shift);
            match want.last_mut() {
                Some(b) if b.bucket == bucket => {
                    b.lo = b.lo.min(p.num);
                    b.hi = b.hi.max(p.num);
                    b.count += 1;
                }
                _ => want.push(SeriesBucket {
                    bucket,
                    lo: p.num,
                    hi: p.num,
                    count: 1,
                }),
            }
        }
        assert_eq!(buckets, want);
        assert_eq!(seg.group(Clock::Receive, 3, 0).unwrap(), None);
        assert!(seg.group(Clock::Packet, 1, 0).unwrap().is_none());
    }

    /// The bytes of a segment of 6,000 packets on seven lanes whose times
    /// are in order in some stretches and not in others: late packets, a
    /// clock that jumps back, ties, lanes running apart, and kept values
    /// with ties, negative numbers and two values of one field in one
    /// packet, written with sorters of `chunk` records (`None`: the
    /// default).
    fn disordered_segment(scratch: &Scratch, chunk: Option<usize>) -> Vec<u8> {
        let mut writer = match chunk {
            Some(chunk) => Writer::with_chunk(&scratch.0, 9, 50, chunk).unwrap(),
            None => Writer::create(&scratch.0, 9, 50).unwrap(),
        };
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..6_000i64 {
            let lane = i % 7 + 1;
            // In order, then late packets, then a jump back, then ties.
            let base = match i {
                0..1_500 => i * 1_000,
                1_500..3_000 if i % 50 == 0 => i * 1_000 - 400_000,
                1_500..3_000 => i * 1_000,
                3_000..4_500 => i * 1_000 - 2_000_000,
                _ => (i / 100) * 1_000,
            };
            let receive = (i % 11 != 0).then_some(base);
            // Each lane's packet time runs behind by its own amount.
            let packet = (i % 13 != 0).then_some(base - lane * 300_000);
            let mut r = row(i, receive, packet);
            r.sum = (random() % 400) as i64 - 200;
            r.header = (i % 17 != 0).then_some(crate::pure::ccsds::PrimaryHeader {
                version: 0,
                packet_type: crate::pure::ccsds::PacketType::Telemetry,
                has_secondary_header: false,
                apid: lane as u16,
                seq_flags: crate::pure::ccsds::SeqFlags::Unsegmented,
                seq_count: (random() % 3) as u16,
                data_length: 3,
            });
            writer.push(lane, &r, None).unwrap();
            let n = (random() % 5) as f64 - 2.5;
            writer.push_value("HK", "A", Some(n), None).unwrap();
            if i % 3 == 0 {
                writer.push_value("HK", "A", Some(-n), None).unwrap();
                writer.push_value("HK", "B", Some(0.0), Some("x")).unwrap();
            }
        }
        let written = writer.finish().unwrap().unwrap();
        let path = scratch.0.join(&written.name);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();
        bytes
    }

    #[test]
    fn a_segment_is_the_same_whatever_its_sorters_hold() {
        let scratch = Scratch::new();
        let whole = disordered_segment(&scratch, None);
        for chunk in [3, 97, 1_000] {
            assert!(
                disordered_segment(&scratch, Some(chunk)) == whole,
                "chunk {chunk}"
            );
        }
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn a_writer_dropped_unfinished_leaves_nothing() {
        let scratch = Scratch::new();
        let mut writer = Writer::with_chunk(&scratch.0, 7, 1, 3).unwrap();
        for i in 0..100 {
            writer.push(1, &row(i, Some(100 - i), None), None).unwrap();
        }
        assert!(fs::read_dir(&scratch.0).unwrap().count() > 1);
        drop(writer);
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
        // No packets: nothing written.
        let writer = Writer::create(&scratch.0, 8, 1).unwrap();
        assert_eq!(writer.finish().unwrap(), None);
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn a_sorter_that_cannot_write_says_so() {
        let scratch = Scratch::new();
        let mut sorter = Sorter::<8>::new(scratch.0.join("missing/t"), 2, 4);
        sorter.push([0; 8]).unwrap();
        assert!(sorter.push([1; 8]).is_err());
    }
}
