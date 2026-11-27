//! The comparison of sources, read from the checksum sections of a run's
//! segments. What a group of packets with one checksum comes to is decided
//! in `pure::cross`; this module merges the sections into one stream in
//! checksum order, keeps what must be given back later in temporary files,
//! and gives it back.
//!
//! Memory stays the same whatever the run holds. At most [`FAN_IN`]
//! sections are read at once, through buffers that share
//! [`MERGE_BUDGET`]; a run of more segments is merged in passes through
//! temporary files. Of the packets of one checksum at most
//! [`GROUP_MEMORY`] are held; the rest of a larger group goes to a
//! temporary file. The ids of packets a partner lacks go to another, read
//! back once when every group has been seen. Temporary files lie in the
//! segment folder, named `cross.<n>.tmp`, and are removed when done with,
//! or by the sweep when the store is next opened for writing.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{BufWriter, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::pure::cross::{Comparison, Logged};
use crate::shell::segment::{self, Checksums, RecordFile, TempFile};
use crate::shell::store::Result;

/// Most sections, or merged runs, read at once.
pub const FAN_IN: usize = 64;
/// Read buffers of one merge, all together.
pub const MERGE_BUDGET: usize = 4 << 20;
const MIN_BUFFER: usize = 4 << 10;
const MAX_BUFFER: usize = 64 << 10;
/// Most packets of one checksum held in memory.
pub const GROUP_MEMORY: usize = 1 << 16;
/// Buffer for writing a temporary file, and for reading one back.
const IO_BUFFER: usize = 64 << 10;

/// A packet in a merged run: checksum, sequence count, length, lane, id.
const LOGGED_BYTES: usize = 30;
/// A packet of one group: lane, id.
const HELD_BYTES: usize = 12;
/// A packet a partner lacks: pair, id.
const CANDIDATE_BYTES: usize = 12;

static MOST_HELD: AtomicUsize = AtomicUsize::new(0);
static LARGEST_GROUP: AtomicUsize = AtomicUsize::new(0);

/// The most packets of one checksum this process has held in memory at
/// once while comparing sources, and the most it has seen in one group.
/// For tests of the bound.
pub fn group_sizes() -> (usize, usize) {
    (
        MOST_HELD.load(Ordering::Relaxed),
        LARGEST_GROUP.load(Ordering::Relaxed),
    )
}

fn encode(l: &Logged) -> [u8; LOGGED_BYTES] {
    let mut b = [0u8; LOGGED_BYTES];
    b[0..8].copy_from_slice(&l.sum.to_le_bytes());
    b[8..16].copy_from_slice(&l.length.to_le_bytes());
    b[16..24].copy_from_slice(&l.id.to_le_bytes());
    b[24..28].copy_from_slice(&l.lane.to_le_bytes());
    b[28..30].copy_from_slice(&l.seq.to_le_bytes());
    b
}

fn i64_le(b: &[u8]) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    i64::from_le_bytes(a)
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn decode(b: &[u8; LOGGED_BYTES]) -> Logged {
    Logged {
        sum: i64_le(&b[0..]),
        length: i64_le(&b[8..]),
        id: i64_le(&b[16..]),
        lane: u32_le(&b[24..]),
        seq: u16::from_le_bytes([b[28], b[29]]),
    }
}

/// Names temporary files in the segment folder.
struct Temps {
    folder: PathBuf,
    next: u32,
}

impl Temps {
    fn create(&mut self) -> Result<TempFile> {
        self.next += 1;
        TempFile::create(self.folder.join(format!("cross.{}.tmp", self.next)))
    }
}

/// Where packets come from in a merge.
enum Input {
    Segment { records: Checksums, first: i64 },
    Run(RecordFile<LOGGED_BYTES>),
}

impl Input {
    fn next(&mut self) -> Result<Option<Logged>> {
        Ok(match self {
            Input::Segment { records, first } => records.next_record()?.map(|r| Logged {
                sum: r.sum,
                seq: r.seq,
                length: r.length,
                lane: r.lane,
                id: *first + i64::from(r.index),
            }),
            Input::Run(records) => records.read()?.map(|b| decode(&b)),
        })
    }
}

/// The read buffer of each of `n` inputs merged at once.
fn buffer_for(n: usize) -> usize {
    (MERGE_BUDGET / n.max(1)).clamp(MIN_BUFFER, MAX_BUFFER)
}

/// Hands every wanted packet of the inputs to `out`, in order. Fails if an
/// input is not in order.
fn merge(
    mut inputs: Vec<Input>,
    wants: &dyn Fn(u32) -> bool,
    mut out: impl FnMut(Logged) -> Result<()>,
) -> Result<()> {
    let mut heap = BinaryHeap::with_capacity(inputs.len());
    let next = |input: &mut Input| -> Result<Option<Logged>> {
        while let Some(l) = input.next()? {
            if wants(l.lane) {
                return Ok(Some(l));
            }
        }
        Ok(None)
    };
    for (i, input) in inputs.iter_mut().enumerate() {
        if let Some(l) = next(input)? {
            heap.push(Reverse((l, i)));
        }
    }
    let mut last: Option<Logged> = None;
    while let Some(Reverse((l, i))) = heap.pop() {
        if last.is_some_and(|last| l < last) {
            return Err("a checksum section is out of order".into());
        }
        last = Some(l);
        out(l)?;
        if let Some(n) = next(&mut inputs[i])? {
            heap.push(Reverse((n, i)));
        }
    }
    Ok(())
}

/// Opens the checksum sections of some segments, each listed as its name
/// and first packet id.
fn open_segments(folder: &Path, list: &[(String, i64)], buffer: usize) -> Result<Vec<Input>> {
    let mut out = Vec::with_capacity(list.len());
    for (name, first) in list {
        let listed = segment::Listed {
            name: name.clone(),
            first_packet: *first,
            min: *first,
            max: *first,
        };
        let seg = segment::open_listed(folder, &listed)?;
        out.push(Input::Segment {
            records: seg.checksums(buffer)?,
            first: *first,
        });
    }
    Ok(out)
}

/// Merged runs: ranges of one temporary file.
struct Runs {
    temp: TempFile,
    ranges: Vec<(u64, u64)>,
}

impl Runs {
    fn inputs(&self, ranges: &[(u64, u64)]) -> Result<Vec<Input>> {
        let buffer = buffer_for(ranges.len());
        ranges
            .iter()
            .map(|&(start, end)| {
                Ok(Input::Run(RecordFile::new(
                    self.temp.file.try_clone()?,
                    start,
                    end,
                    buffer,
                )))
            })
            .collect()
    }
}

/// Merges groups of `fan_in` inputs, each group into one run of a new
/// temporary file.
fn merge_level(
    temps: &mut Temps,
    groups: usize,
    mut open: impl FnMut(usize) -> Result<Vec<Input>>,
    wants: &dyn Fn(u32) -> bool,
) -> Result<Runs> {
    let temp = temps.create()?;
    let mut ranges = Vec::with_capacity(groups);
    let mut writer = BufWriter::with_capacity(IO_BUFFER, temp.file.try_clone()?);
    let mut at = 0u64;
    for g in 0..groups {
        let start = at;
        merge(open(g)?, wants, |l| {
            writer.write_all(&encode(&l))?;
            at += LOGGED_BYTES as u64;
            Ok(())
        })?;
        ranges.push((start, at));
    }
    writer.flush()?;
    drop(writer);
    Ok(Runs { temp, ranges })
}

/// The packets of the current group, in memory up to [`GROUP_MEMORY`] and
/// then in a temporary file as well.
struct Group {
    held: Vec<(u32, i64)>,
    over: Option<TempFile>,
    over_len: u64,
    size: usize,
}

impl Group {
    fn push(&mut self, temps: &mut Temps, lane: u32, id: i64) -> Result<()> {
        if self.held.len() >= GROUP_MEMORY {
            if self.over.is_none() {
                self.over = Some(temps.create()?);
            }
            let Some(over) = &self.over else {
                return Err("no file for a large group".into());
            };
            let mut bytes = Vec::with_capacity(self.held.len() * HELD_BYTES);
            for (lane, id) in self.held.drain(..) {
                bytes.extend_from_slice(&lane.to_le_bytes());
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            over.file.write_all_at(&bytes, self.over_len)?;
            self.over_len += bytes.len() as u64;
        }
        if self.held.capacity() == 0 {
            self.held.reserve(16);
        }
        self.held.push((lane, id));
        self.size += 1;
        MOST_HELD.fetch_max(self.held.len(), Ordering::Relaxed);
        Ok(())
    }

    /// Empties the group.
    fn clear(&mut self) {
        LARGEST_GROUP.fetch_max(self.size, Ordering::Relaxed);
        self.held.clear();
        self.over_len = 0;
        self.size = 0;
    }

    /// Hands every packet of the group to `f`, and empties it.
    fn drain(&mut self, mut f: impl FnMut(u32, i64) -> Result<()>) -> Result<()> {
        if let Some(over) = &self.over
            && self.over_len > 0
        {
            let mut r =
                RecordFile::<HELD_BYTES>::new(over.file.try_clone()?, 0, self.over_len, IO_BUFFER);
            while let Some(b) = r.read()? {
                f(u32_le(&b), i64_le(&b[4..]))?;
            }
        }
        for &(lane, id) in &self.held {
            f(lane, id)?;
        }
        self.clear();
        Ok(())
    }
}

/// What the merge left to be given back: every (pair, id) of a packet a
/// partner lacks.
pub struct Replay {
    candidates: Option<(TempFile, u64)>,
}

impl Replay {
    /// Gives every kept (pair, id) back to the comparison.
    pub fn run(self, cmp: &mut Comparison) -> Result<()> {
        let Some((temp, len)) = self.candidates else {
            return Ok(());
        };
        let mut r = RecordFile::<CANDIDATE_BYTES>::new(temp.file.try_clone()?, 0, len, IO_BUFFER);
        while let Some(b) = r.read()? {
            cmp.replay(u32_le(&b) as usize, i64_le(&b[4..]));
        }
        Ok(())
    }
}

/// Feeds every space packet of the listed segments (name, first packet id)
/// to the comparison, in checksum order, reading at most `fan_in` sections
/// at once. What it returns gives the comparison what it could not decide
/// until every packet had been seen.
pub fn compare(
    folder: &Path,
    segments: &[(String, i64)],
    cmp: &mut Comparison,
    fan_in: usize,
) -> Result<Replay> {
    let fan_in = fan_in.max(2);
    let mut temps = Temps {
        folder: folder.to_path_buf(),
        next: 0,
    };
    let lanes = cmp.lanes();
    let wants = |lane: u32| lanes.binary_search(&lane).is_ok();
    // First the segments, in groups, then the runs that makes, until few
    // enough are left to merge at once.
    let mut runs: Option<Runs> = None;
    if segments.len() > fan_in {
        let chunks: Vec<&[(String, i64)]> = segments.chunks(fan_in).collect();
        let buffer = buffer_for(fan_in);
        runs = Some(merge_level(
            &mut temps,
            chunks.len(),
            |g| open_segments(folder, chunks[g], buffer),
            &wants,
        )?);
        while let Some(level) = runs.as_ref().filter(|r| r.ranges.len() > fan_in) {
            let chunks: Vec<&[(u64, u64)]> = level.ranges.chunks(fan_in).collect();
            let next = merge_level(
                &mut temps,
                chunks.len(),
                |g| level.inputs(chunks[g]),
                &wants,
            )?;
            runs = Some(next);
        }
    }
    let inputs = match &runs {
        Some(r) => r.inputs(&r.ranges)?,
        None => open_segments(folder, segments, buffer_for(segments.len()))?,
    };

    let mut group = Group {
        held: Vec::new(),
        over: None,
        over_len: 0,
        size: 0,
    };
    let mut kept = Kept { file: None, len: 0 };
    merge(inputs, &wants, |l| {
        if cmp.ends_group(&l) {
            kept.end_group(cmp, &mut group, &mut temps)?;
        }
        cmp.add(&l);
        group.push(&mut temps, l.lane, l.id)
    })?;
    kept.end_group(cmp, &mut group, &mut temps)?;
    let candidates = match kept.file {
        Some((mut writer, temp)) => {
            writer.flush()?;
            drop(writer);
            Some((temp, kept.len))
        }
        None => None,
    };
    Ok(Replay { candidates })
}

/// The (pair, id) of every packet a partner lacks, in a temporary file.
struct Kept {
    file: Option<(BufWriter<std::fs::File>, TempFile)>,
    len: u64,
}

impl Kept {
    /// Ends the current group, keeping its packets that a partner lacks.
    fn end_group(
        &mut self,
        cmp: &mut Comparison,
        group: &mut Group,
        temps: &mut Temps,
    ) -> Result<()> {
        cmp.end_group();
        if !cmp.any_absent() {
            group.clear();
            return Ok(());
        }
        if self.file.is_none() {
            let temp = temps.create()?;
            let writer = BufWriter::with_capacity(IO_BUFFER, temp.file.try_clone()?);
            self.file = Some((writer, temp));
        }
        let Some((writer, _)) = &mut self.file else {
            return Err("no file for packets a partner lacks".into());
        };
        let len = &mut self.len;
        group.drain(|lane, id| {
            for pair in cmp.candidates(lane) {
                let pair = u32::try_from(pair).map_err(|_| "too many pairs of lanes")?;
                writer.write_all(&pair.to_le_bytes())?;
                writer.write_all(&id.to_le_bytes())?;
                *len += CANDIDATE_BYTES as u64;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::ccsds::{PacketType, PrimaryHeader, SeqFlags};
    use crate::pure::cross::compare_all;
    use crate::pure::ingest::PacketRow;
    use crate::shell::segment::Writer;
    use std::fs;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Packets with few distinct checksums, in id order. Lanes 1 to 3 are
    /// one stream from three sources, 4 and 5 another; lane 6 has no
    /// partner.
    fn packets(n: usize) -> Vec<Logged> {
        let mut x = 7u64;
        let mut next = move |m: u64| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 33) % m
        };
        (0..n)
            .map(|i| Logged {
                sum: next(300) as i64 - 150,
                seq: next(2) as u16,
                length: 10 + next(2) as i64,
                lane: 1 + next(6) as u32,
                id: i as i64 + 1,
            })
            .collect()
    }

    const PAIRS: [(u32, u32); 8] = [
        (1, 2),
        (1, 3),
        (2, 1),
        (2, 3),
        (3, 1),
        (3, 2),
        (4, 5),
        (5, 4),
    ];

    /// Many segments merged two at a time, through spilled sorts, give
    /// what the comparison gives over every packet at once, and leave no
    /// temporary file behind.
    #[test]
    fn segments_merged_in_passes_compare_as_all_packets_at_once() {
        let dir = std::env::temp_dir().join(format!("packetlane-cross-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let scratch = Scratch(dir);
        let all = packets(9_000);
        let mut listed = Vec::new();
        for (file, chunk) in all.chunks(1_000).enumerate() {
            let first = chunk[0].id;
            let mut w = Writer::with_chunk(&scratch.0, file as i64 + 1, first, 97).unwrap();
            for p in chunk {
                let header = PrimaryHeader {
                    version: 0,
                    packet_type: PacketType::Telemetry,
                    has_secondary_header: false,
                    apid: 5,
                    seq_flags: SeqFlags::Unsegmented,
                    seq_count: p.seq,
                    data_length: 3,
                };
                let row = PacketRow {
                    idx: p.id - first,
                    offset: 0,
                    length: p.length,
                    receive_ns: None,
                    packet_ns: None,
                    header: Some(header),
                    length_ok: true,
                    sum: p.sum,
                };
                w.push(i64::from(p.lane), &row, None).unwrap();
            }
            listed.push((w.finish().unwrap().unwrap().name, first));
        }
        let mut sorted = all.clone();
        sorted.sort_unstable();
        let want = compare_all(&PAIRS, &[1, 4], sorted);
        for fan_in in [2, 3, 64] {
            let mut cmp = Comparison::new(&PAIRS, &[1, 4]);
            compare(&scratch.0, &listed, &mut cmp, fan_in)
                .unwrap()
                .run(&mut cmp)
                .unwrap();
            assert_eq!(cmp.counts(), want.counts(), "fan in {fan_in}");
            for (x, l) in [(1, 2), (1, 3), (4, 5)] {
                assert_eq!(cmp.copies(x, l), want.copies(x, l));
            }
            let left: Vec<String> = fs::read_dir(&scratch.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| !n.ends_with(".seg"))
                .collect();
            assert!(left.is_empty(), "{left:?}");
        }
        assert!(want.counts().iter().all(|c| c.shared > 0));
        assert!(want.counts().iter().any(|c| c.missing > 0));
        assert!(want.copies(1, 2) > 0);
    }
}
