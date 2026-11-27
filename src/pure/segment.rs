//! Segment files: what one input file's packets look like on disk, and how a
//! density view is put together from them. This module only encodes and
//! decodes bytes and does arithmetic; `shell::segment` reads and writes the
//! files.
//!
//! # Where they are
//!
//! Every packet file ingested gets one segment, written alongside its rows in
//! SQLite, in a folder beside the store named after it: the store
//! `packetlane.db` keeps its segments in `packetlane.db.seg/`. A segment is
//! never changed once written. A file that is read again gets a new segment
//! and the old one is removed. Text logs get none.
//!
//! The `segments` table in the store (see `sql::SCHEMA`) has one row per
//! segment: the file it was read from, its file name in the folder, its first
//! and last packet id, and for each clock its lowest and highest value and the
//! shift of its bucket grid. Readers prune with that row and open only the
//! segments a window touches. The file name is usually `<file id>.seg`; it is
//! `<file id>.<n>.seg` when a file that is read again is given the id its
//! earlier version had (SQLite hands out the highest id plus one), because
//! the earlier segment must stay in place until the new one is committed.
//!
//! # Writing order
//!
//! A segment is written to a temporary name in the folder, flushed, synced,
//! renamed to its own name and the folder synced, all before the transaction
//! that adds its `files` and `segments` rows commits. When a file is read
//! again or its run is emptied, its `segments` row goes in that transaction
//! and the file after the commit. A segment with no row (left by a crash) is
//! removed the next time the store is opened for writing.
//!
//! Known limitation, for a later milestone: a reader that loaded the
//! `segments` rows before a segment was replaced finds the file missing, or
//! finds a file whose first packet differs from its row, and fails. The fix
//! is to read the rows again and retry.
//!
//! # Layout
//!
//! All numbers are little-endian. A segment is:
//!
//! ```text
//! magic "PLSEGMNT"          8 bytes
//! section ...               in the order they were written
//! directory                 one 32-byte entry per section
//! tail                      32 bytes
//! ```
//!
//! The tail is: first packet id (i64), number of packets (u64), number of
//! directory entries (u32), format version (u32), magic "PLSEGEND". The
//! directory lies just before it. Each entry is: kind (u16), clock (u8), one
//! zero byte, record size (u32, 0 for a section of variable-length
//! records), offset from the start of the file (u64), length in bytes (u64),
//! and a parameter (i64: the grid shift for buckets, else 0). A reader skips
//! kinds it does not know, so later versions can add sections; it rejects a
//! file whose magic, version or directory is wrong.
//!
//! Clocks are numbered 0 receive, 1 packet, 2 order.
//!
//! Sections in version 1:
//!
//! - kind 1, packets: one 56-byte record per logged item, in id order;
//!   packet id = first packet id + index. Record: receive time (i64), packet
//!   time (i64), offset in the file (i64), checksum (i64), length (i64), lane
//!   id (u32, the `lanes` table's id), label (u32, index into the labels),
//!   APID (u16), sequence count (u16), packet type (u8, 0 telemetry, 1
//!   command), flags (u8), two zero bytes. Flags say which values are there:
//!   [`HAS_RECEIVE`], [`HAS_PACKET`], [`HAS_HEADER`] (APID, sequence count
//!   and type), [`HAS_LABEL`], and [`LENGTH_OK`].
//! - kind 2, labels: the segment's distinct labels, each a u32 length and
//!   that many bytes of UTF-8, numbered from 0 in order.
//! - kind 3, time order, one per time clock (receive, packet): a 16-byte
//!   record (time i64, lane u32, index u32) for every packet that has that
//!   time, sorted by time and then index. It is time-first across all lanes
//!   so that reading a window costs what the window holds, not lanes times
//!   segments.
//! - kind 4, density buckets, one per clock (receive, packet, order): a
//!   16-byte record (bucket i64, lane u32, count u32) per lane and bucket that
//!   holds packets, sorted by bucket and then lane. Buckets lie on a fixed
//!   grid, bucket = `t >> shift` (an arithmetic shift, so negative and
//!   enormous times are fine), with `t` the packet id on the order clock.
//!   `shift` is the entry's parameter: the smallest for which the segment's
//!   values span at most [`GRID_BUCKETS`] buckets.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};

use crate::pure::sql::Clock;

pub const MAGIC: [u8; 8] = *b"PLSEGMNT";
pub const TAIL_MAGIC: [u8; 8] = *b"PLSEGEND";
pub const VERSION: u32 = 1;

pub const PACKET_BYTES: usize = 56;
pub const TIME_BYTES: usize = 16;
pub const BUCKET_BYTES: usize = 16;
pub const ENTRY_BYTES: usize = 32;
pub const TAIL_BYTES: usize = 32;
/// More sections than any version will have; a directory claiming more is
/// damaged.
pub const MAX_ENTRIES: u32 = 256;

/// The most buckets a segment's values span on one clock.
pub const GRID_BUCKETS: i128 = 4096;

pub const KIND_PACKETS: u16 = 1;
pub const KIND_LABELS: u16 = 2;
pub const KIND_TIME: u16 = 3;
pub const KIND_BUCKETS: u16 = 4;

pub const HAS_RECEIVE: u8 = 1;
pub const HAS_PACKET: u8 = 2;
pub const HAS_HEADER: u8 = 4;
pub const HAS_LABEL: u8 = 8;
pub const LENGTH_OK: u8 = 16;

/// Why a segment could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError(pub String);

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "segment: {}", self.0)
    }
}

impl std::error::Error for FormatError {}

fn bad<T>(why: impl Into<String>) -> Result<T, FormatError> {
    Err(FormatError(why.into()))
}

pub fn clock_code(clock: Clock) -> u8 {
    match clock {
        Clock::Receive => 0,
        Clock::Packet => 1,
        Clock::Order => 2,
    }
}

fn i64_at(b: &[u8], at: usize) -> i64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    i64::from_le_bytes(a)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

// ---- records ----------------------------------------------------------------

/// One logged item. A value whose flag is clear reads as zero.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacketRecord {
    pub receive_ns: Option<i64>,
    pub packet_ns: Option<i64>,
    pub offset: i64,
    pub sum: i64,
    pub length: i64,
    pub lane: u32,
    pub label: Option<u32>,
    /// APID, sequence count and packet type code, if the item is a packet.
    pub header: Option<(u16, u16, u8)>,
    pub length_ok: bool,
}

impl PacketRecord {
    pub fn encode(&self) -> [u8; PACKET_BYTES] {
        let mut b = [0u8; PACKET_BYTES];
        let mut flags = 0u8;
        if let Some(t) = self.receive_ns {
            b[0..8].copy_from_slice(&t.to_le_bytes());
            flags |= HAS_RECEIVE;
        }
        if let Some(t) = self.packet_ns {
            b[8..16].copy_from_slice(&t.to_le_bytes());
            flags |= HAS_PACKET;
        }
        b[16..24].copy_from_slice(&self.offset.to_le_bytes());
        b[24..32].copy_from_slice(&self.sum.to_le_bytes());
        b[32..40].copy_from_slice(&self.length.to_le_bytes());
        b[40..44].copy_from_slice(&self.lane.to_le_bytes());
        if let Some(l) = self.label {
            b[44..48].copy_from_slice(&l.to_le_bytes());
            flags |= HAS_LABEL;
        }
        if let Some((apid, seq, ptype)) = self.header {
            b[48..50].copy_from_slice(&apid.to_le_bytes());
            b[50..52].copy_from_slice(&seq.to_le_bytes());
            b[52] = ptype;
            flags |= HAS_HEADER;
        }
        if self.length_ok {
            flags |= LENGTH_OK;
        }
        b[53] = flags;
        b
    }

    pub fn decode(b: &[u8; PACKET_BYTES]) -> PacketRecord {
        let flags = b[53];
        let has = |f: u8| flags & f != 0;
        PacketRecord {
            receive_ns: has(HAS_RECEIVE).then(|| i64_at(b, 0)),
            packet_ns: has(HAS_PACKET).then(|| i64_at(b, 8)),
            offset: i64_at(b, 16),
            sum: i64_at(b, 24),
            length: i64_at(b, 32),
            lane: u32_at(b, 40),
            label: has(HAS_LABEL).then(|| u32_at(b, 44)),
            header: has(HAS_HEADER).then(|| (u16_at(b, 48), u16_at(b, 50), b[52])),
            length_ok: has(LENGTH_OK),
        }
    }

    /// The lane of an encoded record, without decoding the rest.
    pub fn lane_of(b: &[u8]) -> u32 {
        u32_at(b, 40)
    }
}

/// One packet's place in a time-order section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeRecord {
    pub ns: i64,
    pub index: u32,
    pub lane: u32,
}

impl TimeRecord {
    pub fn encode(&self) -> [u8; TIME_BYTES] {
        let mut b = [0u8; TIME_BYTES];
        b[0..8].copy_from_slice(&self.ns.to_le_bytes());
        b[8..12].copy_from_slice(&self.lane.to_le_bytes());
        b[12..16].copy_from_slice(&self.index.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> TimeRecord {
        TimeRecord {
            ns: i64_at(b, 0),
            lane: u32_at(b, 8),
            index: u32_at(b, 12),
        }
    }

    /// Bytes whose order is the section's order, time then index, for
    /// sorting without decoding. The lane comes last and never decides.
    pub fn sort_key(&self) -> [u8; TIME_BYTES] {
        let mut b = [0u8; TIME_BYTES];
        b[0..8].copy_from_slice(&(((self.ns as u64) ^ (1 << 63)).to_be_bytes()));
        b[8..12].copy_from_slice(&self.index.to_be_bytes());
        b[12..16].copy_from_slice(&self.lane.to_be_bytes());
        b
    }

    pub fn from_sort_key(b: &[u8; TIME_BYTES]) -> TimeRecord {
        let mut ns = [0u8; 8];
        ns.copy_from_slice(&b[0..8]);
        TimeRecord {
            ns: (u64::from_be_bytes(ns) ^ (1 << 63)) as i64,
            index: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            lane: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        }
    }
}

/// How many packets of one lane fall in one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BucketRecord {
    pub bucket: i64,
    pub lane: u32,
    pub count: u32,
}

impl BucketRecord {
    pub fn encode(&self) -> [u8; BUCKET_BYTES] {
        let mut b = [0u8; BUCKET_BYTES];
        b[0..8].copy_from_slice(&self.bucket.to_le_bytes());
        b[8..12].copy_from_slice(&self.lane.to_le_bytes());
        b[12..16].copy_from_slice(&self.count.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> BucketRecord {
        BucketRecord {
            bucket: i64_at(b, 0),
            lane: u32_at(b, 8),
            count: u32_at(b, 12),
        }
    }
}

/// One label as stored in the labels section.
pub fn encode_label(text: &str) -> Result<Vec<u8>, FormatError> {
    let len = u32::try_from(text.len()).or_else(|_| bad("label too long"))?;
    let mut out = Vec::with_capacity(4 + text.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(out)
}

/// Every label in a labels section, in order.
pub fn decode_labels(mut b: &[u8]) -> Result<Vec<String>, FormatError> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return bad("labels section cut short");
        }
        let len = u32_at(b, 0) as usize;
        let rest = &b[4..];
        if rest.len() < len {
            return bad("labels section cut short");
        }
        let text = std::str::from_utf8(&rest[..len]).or_else(|_| bad("label is not UTF-8"))?;
        out.push(text.to_string());
        b = &rest[len..];
    }
    Ok(out)
}

// ---- directory and tail -------------------------------------------------------

/// Where one section lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub kind: u16,
    pub clock: u8,
    /// Bytes per record; 0 if records vary in length.
    pub record: u32,
    pub offset: u64,
    pub length: u64,
    /// The grid shift for buckets; 0 otherwise.
    pub param: i64,
}

impl Entry {
    pub fn encode(&self) -> [u8; ENTRY_BYTES] {
        let mut b = [0u8; ENTRY_BYTES];
        b[0..2].copy_from_slice(&self.kind.to_le_bytes());
        b[2] = self.clock;
        b[4..8].copy_from_slice(&self.record.to_le_bytes());
        b[8..16].copy_from_slice(&self.offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.length.to_le_bytes());
        b[24..32].copy_from_slice(&self.param.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Entry {
        Entry {
            kind: u16_at(b, 0),
            clock: b[2],
            record: u32_at(b, 4),
            offset: u64_at(b, 8),
            length: u64_at(b, 16),
            param: i64_at(b, 24),
        }
    }

    /// How many records the section holds, for fixed-width records.
    pub fn records(&self) -> u64 {
        match self.record {
            0 => 0,
            n => self.length / u64::from(n),
        }
    }
}

/// The end of a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    pub first_packet: i64,
    pub packets: u64,
    pub entries: u32,
}

impl Tail {
    pub fn encode(&self) -> [u8; TAIL_BYTES] {
        let mut b = [0u8; TAIL_BYTES];
        b[0..8].copy_from_slice(&self.first_packet.to_le_bytes());
        b[8..16].copy_from_slice(&self.packets.to_le_bytes());
        b[16..20].copy_from_slice(&self.entries.to_le_bytes());
        b[20..24].copy_from_slice(&VERSION.to_le_bytes());
        b[24..32].copy_from_slice(&TAIL_MAGIC);
        b
    }

    /// The tail, if `b` is the last bytes of a segment of this version.
    pub fn decode(b: &[u8]) -> Result<Tail, FormatError> {
        if b.len() != TAIL_BYTES {
            return bad("too short to be a segment");
        }
        if b[24..32] != TAIL_MAGIC {
            return bad("not a segment file (bad magic)");
        }
        let version = u32_at(b, 20);
        if version != VERSION {
            return bad(format!(
                "format version {version}, this build reads {VERSION}"
            ));
        }
        let tail = Tail {
            first_packet: i64_at(b, 0),
            packets: u64_at(b, 8),
            entries: u32_at(b, 16),
        };
        if tail.entries > MAX_ENTRIES {
            return bad("directory too large");
        }
        Ok(tail)
    }

    /// Where the directory starts in a file of `file_len` bytes.
    pub fn directory_at(&self, file_len: u64) -> Result<u64, FormatError> {
        let need = (MAGIC.len() + TAIL_BYTES) as u64 + u64::from(self.entries) * ENTRY_BYTES as u64;
        if file_len < need {
            return bad("directory cut short");
        }
        Ok(file_len - TAIL_BYTES as u64 - u64::from(self.entries) * ENTRY_BYTES as u64)
    }
}

/// Checks a directory read from a file whose directory starts at `dir_at`:
/// every known section lies between the magic and the directory, has the
/// record size its kind needs and a whole number of records, and the
/// packets section holds as many records as the tail says.
/// Known sections appear once each and do not overlap.
pub fn check_directory(entries: &[Entry], tail: &Tail, dir_at: u64) -> Result<(), FormatError> {
    let mut packets = None;
    let mut known: Vec<(u64, u64, u16, u8)> = Vec::new();
    for e in entries {
        let end = e.offset.checked_add(e.length);
        if e.offset < MAGIC.len() as u64 || end.is_none_or(|end| end > dir_at) {
            return bad("section lies outside the file");
        }
        let (record, clocks): (u32, &[u8]) = match e.kind {
            KIND_PACKETS => (PACKET_BYTES as u32, &[0]),
            KIND_LABELS => (0, &[0]),
            KIND_TIME => (TIME_BYTES as u32, &[0, 1]),
            KIND_BUCKETS => (BUCKET_BYTES as u32, &[0, 1, 2]),
            // A section of a later version.
            _ => continue,
        };
        if e.record != record || !clocks.contains(&e.clock) {
            return bad(format!("section of kind {} is malformed", e.kind));
        }
        if record != 0 && e.length % u64::from(record) != 0 {
            return bad(format!("section of kind {} is cut short", e.kind));
        }
        if e.kind == KIND_BUCKETS && !(0..=63).contains(&e.param) {
            return bad("bucket grid shift out of range");
        }
        if e.kind == KIND_PACKETS {
            packets = Some(e.records());
        }
        known.push((e.offset, e.offset + e.length, e.kind, e.clock));
    }
    if packets != Some(tail.packets) {
        return bad("packet count does not match the packets section");
    }
    let mut kinds: Vec<(u16, u8)> = known.iter().map(|k| (k.2, k.3)).collect();
    kinds.sort_unstable();
    kinds.dedup();
    known.sort_unstable();
    if kinds.len() != known.len() || known.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return bad("sections overlap or repeat");
    }
    Ok(())
}

// ---- the bucket grid ------------------------------------------------------------

/// The bucket `t` falls in on a grid of `2^shift`-wide buckets.
pub fn bucket_of(t: i64, shift: u32) -> i64 {
    t >> shift.min(63)
}

/// First and last value of a bucket. Wider than `i64` for shift 63.
pub fn bucket_span(bucket: i64, shift: u32) -> (i128, i128) {
    let shift = shift.min(63);
    let start = i128::from(bucket) << shift;
    (start, start + (1i128 << shift) - 1)
}

/// The smallest shift for which `min..=max` spans at most
/// [`GRID_BUCKETS`] buckets. Any span fits at shift 63.
pub fn grid_shift(min: i64, max: i64) -> u32 {
    let (lo, hi) = (min.min(max), min.max(max));
    (0..63u32)
        .find(|&s| i128::from(hi >> s) - i128::from(lo >> s) < GRID_BUCKETS)
        .unwrap_or(63)
}

/// How a window `from..=to` with view buckets `width` wide is counted from
/// one segment whose grid has the given shift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Stored buckets lying wholly inside the window, first and last, to be
    /// added to the view bucket their start falls in. `None` if view
    /// buckets are narrower than stored ones or none lies wholly inside.
    pub whole: Option<(i64, i64)>,
    /// Ranges, at most two, to count packet by packet.
    pub direct: Vec<(i64, i64)>,
}

/// The rule, exactly: if `width >= 2^shift`, the stored buckets lying
/// wholly inside the window are taken whole and the parts of the window
/// before the first and after the last are counted directly; otherwise the
/// whole window is counted directly. Every value in the window is in
/// exactly one stored bucket taken whole or one direct range.
pub fn plan(from: i64, to: i64, width: i64, shift: u32) -> Plan {
    let shift = shift.min(63);
    let direct_all = Plan {
        whole: None,
        direct: vec![(from, to)],
    };
    let size = 1i128 << shift;
    if from > to || i128::from(width) < size {
        return direct_all;
    }
    let (from_w, to_w) = (i128::from(from), i128::from(to));
    let first = (from_w + size - 1).div_euclid(size);
    let last = (to_w + 1).div_euclid(size) - 1;
    if first > last {
        return direct_all;
    }
    let (Ok(first_b), Ok(last_b)) = (i64::try_from(first), i64::try_from(last)) else {
        return direct_all;
    };
    let lo = first * size;
    let hi = (last + 1) * size - 1;
    let mut direct = Vec::new();
    if from_w < lo {
        // `lo - 1` is below `lo <= to`, so it fits.
        direct.push((from, (lo - 1) as i64));
    }
    if hi < to_w {
        direct.push(((hi + 1) as i64, to));
    }
    Plan {
        whole: Some((first_b, last_b)),
        direct,
    }
}

/// The view bucket of a value in `from..=to`.
pub fn view_bucket(t: i64, from: i64, width: i64) -> i64 {
    // `t >= from`, so the difference fits in 64 unsigned bits.
    let offset = t.wrapping_sub(from) as u64;
    (offset / width.max(1) as u64) as i64
}

/// A hasher for keys that are already well spread small integers.
#[derive(Default)]
pub struct MixHasher(u64);

impl Hasher for MixHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }

    fn write_u64(&mut self, v: u64) {
        self.0 = (self.0 ^ v)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(29);
    }
}

/// Packet counts per lane and view bucket over a window, gathered from
/// stored buckets and single packets. Its cost follows what is added, not
/// lanes times buckets.
pub struct Counts {
    from: i64,
    to: i64,
    width: i64,
    counts: HashMap<u64, i64, BuildHasherDefault<MixHasher>>,
}

impl Counts {
    pub fn new(from: i64, to: i64, width: i64) -> Counts {
        Counts {
            from,
            to,
            width: width.max(1),
            counts: HashMap::default(),
        }
    }

    fn add(&mut self, lane: u32, bin: i64, n: i64) {
        // Bins are below the 4000 a view may ask for, plus one.
        let key = (u64::from(lane) << 32) | (bin as u64 & 0xFFFF_FFFF);
        *self.counts.entry(key).or_default() += n;
    }

    /// One packet at `t`. Ignored outside the window.
    pub fn point(&mut self, lane: u32, t: i64) {
        if (self.from..=self.to).contains(&t) {
            self.add(lane, view_bucket(t, self.from, self.width), 1);
        }
    }

    /// A stored bucket taken whole: its packets go to the view bucket its
    /// start falls in. Ignored unless it lies wholly inside the window.
    pub fn bucket(&mut self, lane: u32, bucket: i64, shift: u32, count: u32) {
        let (start, end) = bucket_span(bucket, shift);
        if start >= i128::from(self.from) && end <= i128::from(self.to) {
            let bin = view_bucket(start as i64, self.from, self.width);
            self.add(lane, bin, i64::from(count));
        }
    }

    /// One row per lane and view bucket: (lane, bucket, count), in that
    /// order.
    pub fn rows(&self) -> Vec<(i64, i64, i64)> {
        let mut out: Vec<(i64, i64, i64)> = self
            .counts
            .iter()
            .map(|(&k, &n)| ((k >> 32) as i64, (k & 0xFFFF_FFFF) as i64, n))
            .collect();
        out.sort_unstable();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_records_keep_what_is_there_and_nothing_else() {
        let full = PacketRecord {
            receive_ns: Some(i64::MIN),
            packet_ns: Some(-1),
            offset: 1 << 40,
            sum: -7,
            length: 65_542,
            lane: u32::MAX,
            label: Some(0),
            header: Some((2047, 16_383, 1)),
            length_ok: true,
        };
        assert_eq!(PacketRecord::decode(&full.encode()), full);
        let empty = PacketRecord::default();
        let bytes = empty.encode();
        assert_eq!(PacketRecord::decode(&bytes), empty);
        // A missing time is a cleared flag, not a value that could be real.
        assert_eq!(bytes[53], 0);
        let zero = PacketRecord {
            receive_ns: Some(0),
            header: Some((0, 0, 0)),
            ..PacketRecord::default()
        };
        assert_eq!(PacketRecord::decode(&zero.encode()), zero);
        assert_ne!(zero.encode(), bytes);
        assert_eq!(PacketRecord::lane_of(&full.encode()), u32::MAX);
    }

    #[test]
    fn time_keys_sort_by_time_then_index_never_lane() {
        let records = [
            TimeRecord {
                ns: 5,
                index: 9,
                lane: 1,
            },
            TimeRecord {
                ns: 5,
                index: 2,
                lane: 7,
            },
            TimeRecord {
                ns: -3,
                index: 4,
                lane: 0,
            },
            TimeRecord {
                ns: i64::MIN,
                index: 0,
                lane: 3,
            },
            TimeRecord {
                ns: i64::MAX,
                index: 1,
                lane: 2,
            },
            TimeRecord {
                ns: 0,
                index: 3,
                lane: 9,
            },
        ];
        let mut keys: Vec<[u8; TIME_BYTES]> = records.iter().map(TimeRecord::sort_key).collect();
        keys.sort_unstable();
        let sorted: Vec<TimeRecord> = keys.iter().map(TimeRecord::from_sort_key).collect();
        let mut expected = records.to_vec();
        expected.sort_by_key(|r| (r.ns, r.index));
        assert_eq!(sorted, expected);
        for r in records {
            assert_eq!(TimeRecord::decode(&r.encode()), r);
        }
    }

    #[test]
    fn labels_and_buckets_round_trip() {
        let mut bytes = Vec::new();
        for l in ["", "INST HEALTH", "ünï"] {
            bytes.extend(encode_label(l).unwrap());
        }
        assert_eq!(decode_labels(&bytes).unwrap(), ["", "INST HEALTH", "ünï"]);
        assert!(decode_labels(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_labels(&[1, 0]).is_err());
        let b = BucketRecord {
            bucket: -5,
            lane: 3,
            count: u32::MAX,
        };
        assert_eq!(BucketRecord::decode(&b.encode()), b);
    }

    fn sample() -> (Tail, Vec<Entry>, u64) {
        let entries = vec![
            Entry {
                kind: KIND_PACKETS,
                clock: 0,
                record: PACKET_BYTES as u32,
                offset: 8,
                length: 3 * PACKET_BYTES as u64,
                param: 0,
            },
            Entry {
                kind: KIND_BUCKETS,
                clock: 2,
                record: BUCKET_BYTES as u32,
                offset: 8 + 3 * PACKET_BYTES as u64,
                length: BUCKET_BYTES as u64,
                param: 12,
            },
        ];
        let tail = Tail {
            first_packet: 41,
            packets: 3,
            entries: 2,
        };
        let dir_at = 8 + 3 * PACKET_BYTES as u64 + BUCKET_BYTES as u64;
        (tail, entries, dir_at)
    }

    #[test]
    fn the_tail_and_directory_are_checked() {
        let (tail, entries, dir_at) = sample();
        let bytes = tail.encode();
        assert_eq!(Tail::decode(&bytes).unwrap(), tail);
        let file_len = dir_at + 2 * ENTRY_BYTES as u64 + TAIL_BYTES as u64;
        assert_eq!(tail.directory_at(file_len).unwrap(), dir_at);
        assert!(tail.directory_at(40).is_err());
        assert!(check_directory(&entries, &tail, dir_at).is_ok());
        for e in &entries {
            assert_eq!(Entry::decode(&e.encode()), *e);
        }

        let mut magic = bytes;
        magic[31] ^= 1;
        assert!(Tail::decode(&magic).unwrap_err().0.contains("magic"));
        let mut version = bytes;
        version[20] = 2;
        assert!(Tail::decode(&version).unwrap_err().0.contains("version"));
        let mut huge = bytes;
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Tail::decode(&huge).is_err());
        assert!(Tail::decode(&bytes[1..]).is_err());

        // A section running into the directory, a ragged one, a wrong
        // record size, an absurd shift, a miscounted packets section, two
        // sections overlapping, one repeated.
        let broken: [fn(&mut Vec<Entry>, &mut Tail); 8] = [
            |e, _| e[1].offset -= 16,
            |e, _| {
                e[1].length = 0;
                e.push(e[1]);
            },
            |e, _| e[1].length += 16,
            |e, _| e[1].length -= 1,
            |e, _| e[0].record = 48,
            |e, _| e[1].param = 64,
            |e, _| e[0].offset = u64::MAX,
            |_, t| t.packets = 4,
        ];
        for (i, f) in broken.iter().enumerate() {
            let (mut tail, mut entries, dir_at) = sample();
            f(&mut entries, &mut tail);
            assert!(
                check_directory(&entries, &tail, dir_at).is_err(),
                "case {i}"
            );
        }
        // A section of a kind not known yet is passed over.
        let (tail, mut entries, dir_at) = sample();
        entries.push(Entry {
            kind: 99,
            clock: 7,
            record: 3,
            offset: 8,
            length: 1,
            param: -1,
        });
        assert!(check_directory(&entries, &tail, dir_at).is_ok());
    }

    #[test]
    fn grid_shift_is_the_smallest_that_fits() {
        assert_eq!(grid_shift(0, 0), 0);
        assert_eq!(grid_shift(0, 4095), 0);
        assert_eq!(grid_shift(0, 4096), 1);
        assert_eq!(grid_shift(1, 4096), 0);
        assert_eq!(grid_shift(-4096, -1), 0);
        assert_eq!(grid_shift(-4097, -1), 1);
        assert_eq!(grid_shift(i64::MIN, i64::MAX), 52);
        assert_eq!(grid_shift(i64::MAX, i64::MIN), 52);
        for (min, max) in [
            (17i64, 1_000_003),
            (-5, 5),
            (i64::MIN, 0),
            (1 << 60, i64::MAX),
        ] {
            let s = grid_shift(min, max);
            let span = |s: u32| i128::from(bucket_of(max, s)) - i128::from(bucket_of(min, s)) + 1;
            assert!(span(s) <= GRID_BUCKETS);
            assert!(s == 0 || span(s - 1) > GRID_BUCKETS);
        }
        assert_eq!(bucket_of(-1, 3), -1);
        assert_eq!(bucket_of(i64::MIN, 63), -1);
        assert_eq!(bucket_of(i64::MAX, 63), 0);
        assert_eq!(bucket_span(-1, 63), (-(1i128 << 63), -1));
        assert_eq!(bucket_span(0, 63), (0, (1i128 << 63) - 1));
    }

    /// Every value of the window is counted once, by a stored bucket lying
    /// wholly inside or by a direct range, and nothing outside it is.
    fn covers_exactly(from: i64, to: i64, width: i64, shift: u32) {
        let p = plan(from, to, width, shift);
        let mut pieces: Vec<(i128, i128)> = p
            .direct
            .iter()
            .map(|&(a, b)| (i128::from(a), i128::from(b)))
            .collect();
        if let Some((first, last)) = p.whole {
            assert!(i128::from(width) >= 1i128 << shift);
            let (lo, _) = bucket_span(first, shift);
            let (_, hi) = bucket_span(last, shift);
            assert!(lo >= i128::from(from) && hi <= i128::from(to));
            pieces.push((lo, hi));
        }
        pieces.sort();
        assert_eq!(
            pieces[0].0,
            i128::from(from),
            "{from}..{to} {width} {shift}"
        );
        assert_eq!(pieces.last().unwrap().1, i128::from(to));
        for pair in pieces.windows(2) {
            assert_eq!(pair[0].1 + 1, pair[1].0, "{from}..{to} {width} {shift}");
        }
    }

    #[test]
    fn plans_count_every_value_once() {
        for (from, to, width, shift) in [
            (0i64, 99, 10, 2),
            (1, 98, 10, 2),
            (3, 5, 10, 2),
            (4, 7, 10, 2),
            (-17, 1000, 300, 6),
            (1_050, 1_449, 200, 5),
            (0, 99, 3, 2),
            (i64::MIN, i64::MAX, i64::MAX, 62),
            (i64::MIN, i64::MAX, i64::MAX, 63),
            (i64::MAX - 10, i64::MAX, 100, 3),
            (i64::MIN, i64::MIN + 10, 100, 3),
            (-1, 0, 5, 63),
        ] {
            covers_exactly(from, to, width, shift);
        }
        // View buckets narrower than stored ones: all direct.
        assert_eq!(plan(0, 99, 3, 2).whole, None);
        // Buckets of 4: 4..=7 .. 92..=95 lie inside 1..=98.
        assert_eq!(
            plan(1, 98, 10, 2),
            Plan {
                whole: Some((1, 23)),
                direct: vec![(1, 3), (96, 98)]
            }
        );
        // Aligned on both ends: nothing direct.
        assert_eq!(plan(0, 99, 4, 2).direct, vec![]);
        // Too narrow to hold one stored bucket whole.
        assert_eq!(plan(5, 7, 4, 2).whole, None);
        assert_eq!(plan(i64::MIN, i64::MAX, i64::MAX, 63).whole, None);
    }

    #[test]
    fn counts_follow_the_rule() {
        let mut c = Counts::new(10, 49, 10);
        c.point(1, 10);
        c.point(1, 19);
        c.point(1, 20);
        c.point(2, 49);
        c.point(2, 50);
        c.point(2, 9);
        // 12..=15 (shift 2, bucket 3) starts in view bucket 0; 48..=51 is
        // not wholly inside and is dropped.
        c.bucket(1, 3, 2, 5);
        c.bucket(1, 12, 2, 7);
        assert_eq!(c.rows(), vec![(1, 0, 7), (1, 1, 1), (2, 3, 1)]);
        let mut wide = Counts::new(i64::MIN, i64::MAX, i64::MAX);
        wide.point(0, i64::MAX);
        wide.point(0, i64::MIN);
        wide.bucket(0, -1, 63, 3);
        assert_eq!(wide.rows(), vec![(0, 0, 4), (0, 2, 1)]);
    }
}
