//! Writing and reading segment files. What is in them, and how a density
//! view is put together from them, is in `pure::segment`; this module only
//! moves the bytes. Reads are positioned reads into small buffers, so a
//! reader holds no more than a few pages whatever the size of the file.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::hash::BuildHasherDefault;
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::pure::ingest::{PacketRow, ptype_code};
use crate::pure::segment::{
    self as layout, BUCKET_BYTES, BucketRecord, ENTRY_BYTES, Entry, FormatError, KIND_BUCKETS,
    KIND_LABELS, KIND_PACKETS, KIND_TIME, MAGIC, MixHasher, PACKET_BYTES, PacketRecord, TAIL_BYTES,
    TIME_BYTES, Tail, TimeRecord,
};
use crate::pure::sql::Clock;
use crate::shell::store::Result;

/// Records a time-order sorter holds before it writes a sorted run: about
/// 1 MB each. Two of them run beside SQLite's page cache during ingest.
const SORT_CHUNK: usize = (1 << 20) / TIME_BYTES;
/// Most sorted runs merged at once. More are merged in passes, so open
/// files and buffers stay the same however long the input.
const FAN_IN: usize = 32;
/// Buffer each sorted run is read through while merging.
const RUN_BUFFER: usize = 32 << 10;
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
struct TempFile {
    path: PathBuf,
    file: File,
}

impl TempFile {
    fn create(path: PathBuf) -> Result<TempFile> {
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

/// Merges sorted runs of one file into one sorted stream.
struct Merger<'a, const N: usize> {
    readers: Vec<RangeReader<'a, N>>,
    heap: BinaryHeap<Reverse<([u8; N], usize)>>,
}

impl<'a, const N: usize> Merger<'a, N> {
    fn new(file: &'a File, runs: &[(u64, u64)]) -> Result<Self> {
        let mut readers = Vec::with_capacity(runs.len());
        let mut heap = BinaryHeap::with_capacity(runs.len());
        for (i, &(start, len)) in runs.iter().enumerate() {
            let mut r = RangeReader::new(file, start, start + len, RUN_BUFFER);
            if let Some(first) = r.read()? {
                heap.push(Reverse((first, i)));
            }
            readers.push(r);
        }
        Ok(Merger { readers, heap })
    }

    fn next(&mut self) -> Result<Option<[u8; N]>> {
        let Some(Reverse((record, i))) = self.heap.pop() else {
            return Ok(None);
        };
        if let Some(next) = self.readers[i].read()? {
            self.heap.push(Reverse((next, i)));
        }
        Ok(Some(record))
    }
}

/// Sorts fixed-width records whose byte order is their sort order, holding
/// at most `chunk` of them in memory. Each full chunk is sorted and written
/// to a temporary file as a run; the runs are merged at the end, at most
/// `fan_in` at a time. Temporary files are removed when it is dropped,
/// whether or not it finished.
pub struct Sorter<const N: usize> {
    stem: PathBuf,
    chunk: usize,
    fan_in: usize,
    buf: Vec<[u8; N]>,
    spill: Option<TempFile>,
    runs: Vec<(u64, u64)>,
    written: u64,
    passes: u32,
}

impl<const N: usize> Sorter<N> {
    /// Temporary files are named from `stem` (a path) plus a number and
    /// `.tmp`.
    pub fn new(stem: PathBuf, chunk: usize, fan_in: usize) -> Self {
        Sorter {
            stem,
            chunk: chunk.max(1),
            fan_in: fan_in.max(2),
            buf: Vec::new(),
            spill: None,
            runs: Vec::new(),
            written: 0,
            passes: 0,
        }
    }

    fn temp(&mut self) -> Result<TempFile> {
        self.passes += 1;
        let mut name = self.stem.clone().into_os_string();
        name.push(format!(".{}.tmp", self.passes));
        TempFile::create(PathBuf::from(name))
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
        self.buf.sort_unstable();
        if self.spill.is_none() {
            let temp = self.temp()?;
            self.spill = Some(temp);
        }
        let Some(temp) = &self.spill else {
            return Err("sorter has no file".into());
        };
        let bytes = self.buf.as_flattened();
        temp.file.write_all_at(bytes, self.written)?;
        self.runs.push((self.written, bytes.len() as u64));
        self.written += bytes.len() as u64;
        self.buf.clear();
        Ok(())
    }

    /// Hands every record to `out`, in order. Returns the most sorted runs
    /// that were merged at once.
    pub fn finish(mut self, mut out: impl FnMut([u8; N]) -> Result<()>) -> Result<usize> {
        if self.runs.is_empty() {
            self.buf.sort_unstable();
            for record in std::mem::take(&mut self.buf) {
                out(record)?;
            }
            return Ok(0);
        }
        self.spill()?;
        self.buf = Vec::new();
        let mut widest = 0;
        // Merge groups of runs into longer runs until few enough are left.
        while self.runs.len() > self.fan_in {
            let Some(from) = self.spill.take() else {
                return Err("sorter has no file".into());
            };
            let to = self.temp()?;
            let mut runs = Vec::new();
            let mut writer = BufWriter::with_capacity(IO_BUFFER, &to.file);
            let mut at = 0u64;
            for group in self.runs.chunks(self.fan_in) {
                widest = widest.max(group.len());
                let mut merge = Merger::<N>::new(&from.file, group)?;
                let start = at;
                while let Some(record) = merge.next()? {
                    writer.write_all(&record)?;
                    at += N as u64;
                }
                runs.push((start, at - start));
            }
            writer.flush()?;
            drop(writer);
            drop(from);
            self.runs = runs;
            self.spill = Some(to);
        }
        let Some(file) = &self.spill else {
            return Err("sorter has no file".into());
        };
        widest = widest.max(self.runs.len());
        let mut merge = Merger::<N>::new(&file.file, &self.runs)?;
        while let Some(record) = merge.next()? {
            out(record)?;
        }
        Ok(widest)
    }
}

// ---- writing ------------------------------------------------------------------

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
}

/// Writes one segment as a file's packets are read. Nothing is visible
/// under the segment's own name until [`Writer::finish`]; dropped before
/// that, it leaves nothing behind.
pub struct Writer {
    folder: PathBuf,
    file_id: i64,
    first_packet: i64,
    temp: TempFile,
    out: BufWriter<File>,
    at: u64,
    count: u64,
    labels: HashMap<String, u32>,
    label_list: Vec<String>,
    sorters: Vec<Sorter<TIME_BYTES>>,
    ranges: [Option<(i64, i64)>; 2],
}

impl Writer {
    /// Starts the segment of file `file_id`, whose first packet has id
    /// `first_packet`.
    pub fn create(folder: &Path, file_id: i64, first_packet: i64) -> Result<Writer> {
        Writer::with_chunk(folder, file_id, first_packet, SORT_CHUNK)
    }

    /// As [`Writer::create`], with sorters that hold `chunk` records.
    pub fn with_chunk(
        folder: &Path,
        file_id: i64,
        first_packet: i64,
        chunk: usize,
    ) -> Result<Writer> {
        let temp = TempFile::create(folder.join(format!("{file_id}.seg.tmp")))?;
        let mut out = BufWriter::with_capacity(IO_BUFFER, temp.file.try_clone()?);
        out.write_all(&MAGIC)?;
        let sorter =
            |clock: &str| Sorter::new(folder.join(format!("{file_id}.{clock}")), chunk, FAN_IN);
        Ok(Writer {
            folder: folder.to_path_buf(),
            file_id,
            first_packet,
            temp,
            out,
            at: MAGIC.len() as u64,
            count: 0,
            labels: HashMap::new(),
            label_list: Vec::new(),
            sorters: vec![sorter("receive"), sorter("packet")],
            ranges: [None, None],
        })
    }

    /// Adds the next packet. Its id is the first packet's plus the number
    /// added before it.
    pub fn push(&mut self, lane_id: i64, row: &PacketRow, label: Option<&str>) -> Result<()> {
        let index = u32::try_from(self.count)
            .map_err(|_| "more packets in one file than a segment holds")?;
        let lane = u32::try_from(lane_id).map_err(|_| "lane id out of range for a segment")?;
        let label = match label {
            None => None,
            Some(text) => Some(match self.labels.get(text) {
                Some(&n) => n,
                None => {
                    let n = u32::try_from(self.label_list.len())
                        .map_err(|_| "too many labels for a segment")?;
                    self.labels.insert(text.to_string(), n);
                    self.label_list.push(text.to_string());
                    n
                }
            }),
        };
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
        self.count += 1;
        Ok(())
    }

    /// Writes bytes at the end, returning where they started.
    fn append(&mut self, bytes: &[u8]) -> Result<u64> {
        let start = self.at;
        self.out.write_all(bytes)?;
        self.at += bytes.len() as u64;
        Ok(start)
    }

    /// Writes the rest of the segment, syncs it and gives it its own name.
    /// Returns `None`, leaving nothing behind, if no packet was added. The
    /// caller adds the `segments` row in the transaction that commits the
    /// file's rows.
    pub fn finish(mut self) -> Result<Option<Written>> {
        if self.count == 0 {
            return Ok(None);
        }
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
            let mut length = 0u64;
            sorter.finish(|key| {
                out.write_all(&TimeRecord::from_sort_key(&key).encode())?;
                length += TIME_BYTES as u64;
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
        // The buckets are counted from the sections just written, read back
        // in their order: time order for the time clocks, id order for the
        // order clock.
        self.out.flush()?;
        let last_packet = self.first_packet + self.count as i64 - 1;
        let order_shift = layout::grid_shift(self.first_packet, last_packet);
        let mut times = [None, None];
        for c in 0..2 {
            let Some((lo, hi)) = self.ranges[c] else {
                entries.push(self.bucket_section(c as u8, 0, None)?);
                continue;
            };
            let shift = layout::grid_shift(lo, hi);
            times[c] = Some((lo, hi, shift));
            let source = entries[2 + c];
            entries.push(self.bucket_section(c as u8, shift, Some(source))?);
        }
        entries.push(self.bucket_section(2, order_shift, Some(entries[0]))?);

        let tail = Tail {
            first_packet: self.first_packet,
            packets: self.count,
            entries: entries.len() as u32,
        };
        for e in &entries {
            self.out.write_all(&e.encode())?;
        }
        self.out.write_all(&tail.encode())?;
        self.out.flush()?;
        self.temp.file.sync_all()?;

        // The name is free if no earlier segment holds it, including the
        // one this file had before, which stays until the commit.
        let name = (0..)
            .map(|n| match n {
                0 => format!("{}.seg", self.file_id),
                n => format!("{}.{n}.seg", self.file_id),
            })
            .find(|name| !self.folder.join(name).exists())
            .ok_or("no free segment name")?;
        fs::rename(&self.temp.path, self.folder.join(&name))?;
        // Renamed: the temporary file is gone, nothing to remove on drop.
        self.temp.path = PathBuf::new();
        File::open(&self.folder)?.sync_all()?;
        Ok(Some(Written {
            name,
            first_packet: self.first_packet,
            last_packet,
            times,
            order_shift,
        }))
    }

    /// Counts one clock's buckets by reading `source` (a time-order
    /// section, or the packets section for the order clock) from end to end
    /// and appends them. No source, no packets with that time: an empty
    /// section.
    fn bucket_section(&mut self, clock: u8, shift: u32, source: Option<Entry>) -> Result<Entry> {
        let start = self.at;
        let mut tally = Tally {
            shift,
            current: None,
            lanes: HashMap::default(),
            written: 0,
        };
        if let Some(source) = source {
            let file = self.temp.file.try_clone()?;
            let end = source.offset + source.length;
            if clock == 2 {
                let mut r = RangeReader::<PACKET_BYTES>::new(&file, source.offset, end, IO_BUFFER);
                let mut id = self.first_packet;
                while let Some(rec) = r.read()? {
                    tally.add(id, PacketRecord::lane_of(&rec), &mut self.out)?;
                    id += 1;
                }
            } else {
                let mut r = RangeReader::<TIME_BYTES>::new(&file, source.offset, end, IO_BUFFER);
                while let Some(rec) = r.read()? {
                    let rec = TimeRecord::decode(&rec);
                    tally.add(rec.ns, rec.lane, &mut self.out)?;
                }
            }
            tally.flush(&mut self.out)?;
        }
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

/// Counts packets per lane in one bucket at a time, from values that come
/// in ascending order, writing each bucket's records when the next begins.
struct Tally {
    shift: u32,
    current: Option<i64>,
    lanes: HashMap<u32, u32, BuildHasherDefault<MixHasher>>,
    written: u64,
}

impl Tally {
    fn add(&mut self, t: i64, lane: u32, out: &mut impl Write) -> Result<()> {
        let bucket = layout::bucket_of(t, self.shift);
        if self.current != Some(bucket) {
            self.flush(out)?;
            self.current = Some(bucket);
        }
        *self.lanes.entry(lane).or_default() += 1;
        Ok(())
    }

    fn flush(&mut self, out: &mut impl Write) -> Result<()> {
        let Some(bucket) = self.current else {
            return Ok(());
        };
        let mut lanes: Vec<(u32, u32)> = self.lanes.drain().collect();
        lanes.sort_unstable();
        for (lane, count) in lanes {
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

    /// The grid shift of a clock's buckets.
    pub fn shift(&self, clock: Clock) -> Result<u32> {
        let e = self.section(KIND_BUCKETS, layout::clock_code(clock))?;
        Ok(e.param as u32)
    }

    /// Each stored bucket from `first` to `last` on `clock`.
    pub fn buckets(
        &self,
        clock: Clock,
        first: i64,
        last: i64,
        mut f: impl FnMut(BucketRecord),
    ) -> Result<()> {
        let e = self.section(KIND_BUCKETS, layout::clock_code(clock))?;
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

    /// The segment's labels, numbered as packet records refer to them.
    pub fn labels(&self) -> Result<Vec<String>> {
        let e = self.section(KIND_LABELS, 0)?;
        let len = usize::try_from(e.length).map_err(|_| "labels section too large")?;
        let mut b = vec![0u8; len];
        self.file.read_exact_at(&mut b, e.offset)?;
        Ok(layout::decode_labels(&b)?)
    }
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
        let segment = Segment::open(&folder.join(&s.name))?;
        if segment.first_packet() != s.first_packet {
            return Err(format!("{}: replaced since it was listed", s.name).into());
        }
        let shift = segment.shift(clock)?;
        let plan = layout::plan(from, to, width, shift);
        if let Some((first, last)) = plan.whole {
            segment.buckets(clock, first, last, |b| {
                counts.bucket(b.lane, b.bucket, shift, b.count);
            })?;
        }
        for (lo, hi) in plan.direct {
            segment.points(clock, lo, hi, |lane, t| counts.point(lane, t))?;
        }
    }
    Ok(counts.rows())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// The sorted output, the most runs merged at once, and how many files
    /// were in the folder while the last merge ran.
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
            .finish(|b| {
                if out.is_empty() {
                    files = fs::read_dir(&scratch.0).unwrap().count();
                }
                out.push(u64::from_be_bytes(b));
                Ok(())
            })
            .unwrap();
        (out, widest, files)
    }

    #[test]
    fn the_sorter_merges_more_runs_than_it_opens_at_once() {
        let scratch = Scratch::new();
        // A scrambled sequence with repeats: 5,000 records in runs of 7 is
        // 715 runs, merged 4 at a time in five passes.
        let input: Vec<u64> = (0..5_000u64).map(|i| (i * 7_919) % 1_009).collect();
        let mut expected = input.clone();
        expected.sort_unstable();
        // Never more runs at once than allowed, and only the last pass's
        // file is left by the time the output is handed out.
        assert_eq!(sort_all(&scratch, &input, 7, 4), (expected.clone(), 4, 1));
        assert_eq!(sort_all(&scratch, &input, 7, 32), (expected.clone(), 32, 1));
        // Few enough runs to merge in one go; one chunk, sorted in memory.
        assert_eq!(
            sort_all(&scratch, &input, 1_000, 32),
            (expected.clone(), 5, 1)
        );
        assert_eq!(sort_all(&scratch, &input, 100_000, 4), (expected, 0, 0));
        assert_eq!(sort_all(&scratch, &[], 7, 4), (Vec::new(), 0, 0));
        // Its temporary files are gone.
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
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
            let (lo, hi, shift) = written.times[c].unwrap();
            assert_eq!((lo, hi), (want[0].0, want[want.len() - 1].0));
            assert_eq!(seg.shift(clock).unwrap(), shift);
            // The buckets hold every packet once, in order.
            let mut buckets = Vec::new();
            seg.buckets(clock, i64::MIN, i64::MAX, |b| buckets.push(b))
                .unwrap();
            assert!(
                buckets
                    .windows(2)
                    .all(|w| (w[0].bucket, w[0].lane) < (w[1].bucket, w[1].lane))
            );
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
