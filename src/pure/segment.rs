//! Segment files: what one input file's packets look like on disk, and how a
//! density view is put together from them. This module only encodes and
//! decodes bytes and does arithmetic; `shell::segment` reads and writes the
//! files.
//!
//! # Where they are
//!
//! Every packet file ingested gets one segment, in a folder beside the store
//! named after it: the store `packetlane.db` keeps its segments in
//! `packetlane.db.seg/`. A segment is never changed once written. A file
//! that is read again gets a new segment and the old one is removed. Text
//! logs get none. The tables `packets` and `field_values` that SQL sees are
//! read from them (see `shell::vtab`).
//!
//! The `segments` table in the store (see `sql::SCHEMA`) has one row per
//! segment: the file it was read from, its file name in the folder, its first
//! and last packet id, and for each clock its lowest and highest value and the
//! shift of its bucket grid. Readers prune with that row and open only the
//! segments a window touches. The file name is `<file id>.<serial>.seg`, with
//! a serial the store hands out once (`segment_serial`), so that a name never
//! comes to mean another segment, even when a file read again is given the
//! id its earlier version had (SQLite hands out the highest id plus one).
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
//! A reader reads the `segments` rows and everything else it needs from
//! SQLite in one read transaction. If a segment it listed was replaced after
//! that transaction started, it finds the file gone, or a file that is not
//! the one listed (its first packet or count differs): it ends the transaction,
//! reads the rows again in a new one and tries once more; a second failure
//! is an error. That holds for the page's reads and for SQL over `packets`
//! and `field_values` alike (see `shell::vtab`).
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
//! Sections in version 4 (version 3 had all but kind 11):
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
//! - kind 4, density buckets, none or more per clock (receive, packet,
//!   order), one per level: a 16-byte record (bucket i64, lane u32, count
//!   u32) per lane and bucket that holds packets, sorted by bucket and then
//!   lane. Buckets lie on a grid, bucket = `t >> shift` (an arithmetic
//!   shift, so negative and enormous times are fine), with `t` the packet id
//!   on the order clock; `shift` is the entry's parameter, and tells the
//!   levels of a clock apart. The finest possible level is the clock's base
//!   grid, the smallest shift for which the segment's values span at most
//!   [`GRID_BUCKETS`] buckets (the shift the store's `segments` row keeps);
//!   the others are each twice as wide as the one before, up to
//!   [`MAX_LEVELS`] in all. A level is stored only if it pays, by
//!   [`choose_levels`]: with at most half the records of the finer level
//!   stored before it, or of the clock's packets. A segment of many lanes
//!   has about a record a packet at its base grid and keeps only coarser
//!   levels; one of a few lanes keeps them all. A view reads the coarsest
//!   level no wider than its own buckets ([`level_for`]), or with none
//!   counts every packet.
//!
//! Kept values (fields marked `keep`) hold everything the `field_values`
//! table holds, one record for each of its rows:
//!
//! - kind 5, series names: the segment's kept series, each a packet name
//!   and a field name encoded as labels are, numbered from 0 in order.
//! - kind 6, values: a 24-byte record per kept value, in packet order and,
//!   within a packet, in the order the values were kept: index (u32),
//!   series (u32: the number in its low 24 bits, flags in the high 8),
//!   number (f64), and where its text starts in the texts section (u64).
//!   Flags: [`VALUE_NUM`] and [`VALUE_TEXT`]; a value may have both, either
//!   or neither (a number that is not a number, which SQLite stores as
//!   null, is kept as none). Every value is here whatever the packet's
//!   times; a packet's values are found by a binary search on the index.
//! - kind 7, texts: the values' texts, each a u32 length and that many
//!   bytes of UTF-8.
//! - kind 8, kept numbers in time order, one per time clock (receive,
//!   packet): a 20-byte record (time i64, index u32, number f64) for every
//!   value with a number on a packet with that time, and one for the
//!   arrival delay of every packet with both times, in groups of one lane
//!   and one series, each sorted by time and then index. A delay is the
//!   series [`DELAY`]; its number is milliseconds, worked out once as
//!   SQLite does ([`delay_ms`]), so plotting it is the same as plotting a
//!   kept field.
//! - kind 9, groups, one per time clock: a 40-byte record per group, sorted
//!   by lane and series: lane (u32), series (u32), first record in kind 8
//!   and how many (u64 each), first record in kind 10 and how many (u64
//!   each; none if the group's buckets were not worth keeping). One lane's
//!   one series over a window is a binary search in its group and a scan.
//! - kind 10, series buckets, one per time clock, whose parameter is their
//!   grid shift, two less than the clock's base grid ([`series_shift`]): a 32-byte record (bucket i64, lowest f64,
//!   highest f64, count u64) per bucket of a group that holds numbers, in
//!   bucket order, for the groups whose buckets pay
//!   ([`series_buckets_pay`]: at most a quarter as many as the group's
//!   numbers). A plot takes them as density takes its buckets: whole only
//!   when the plot's buckets are at least as wide and the stored bucket
//!   lies wholly inside the window, the two ends read point by point.
//!
//! For the comparison of sources:
//!
//! - kind 11, checksum order: a 28-byte record for every logged item that
//!   is a space packet (has a header): checksum (i64), length (i64), lane
//!   (u32), index (u32), sequence count (u16), two zero bytes. Sorted by
//!   checksum, sequence count, length, lane and index. The checksum comes
//!   first because packets are matched across sources by it; the sequence
//!   count and length come before the lane because the tracing of
//!   interleaved streams matches on all three, so that the packets that
//!   match lie together whatever their lanes and tracing needs no more than
//!   a count per lane (see `pure::cross`). A run's
//!   sections are merged in that order, with ids in place of indexes.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};

use crate::pure::sql::Clock;

pub const MAGIC: [u8; 8] = *b"PLSEGMNT";
pub const TAIL_MAGIC: [u8; 8] = *b"PLSEGEND";
pub const VERSION: u32 = 4;

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
pub const KIND_SERIES_NAMES: u16 = 5;
pub const KIND_VALUES: u16 = 6;
pub const KIND_TEXTS: u16 = 7;
pub const KIND_SERIES: u16 = 8;
pub const KIND_GROUPS: u16 = 9;
pub const KIND_SERIES_BUCKETS: u16 = 10;
pub const KIND_CHECKSUMS: u16 = 11;

pub const VALUE_BYTES: usize = 24;
pub const POINT_BYTES: usize = 20;
pub const GROUP_BYTES: usize = 40;
pub const SERIES_BUCKET_BYTES: usize = 32;
/// The sort key of a point while a segment is written: lane, series, time,
/// index, value.
pub const POINT_KEY_BYTES: usize = 28;
pub const CHECKSUM_BYTES: usize = 28;
/// The sort key of a checksum record while a segment is written: checksum,
/// sequence count, length, lane, index.
pub const CHECKSUM_KEY_BYTES: usize = 26;

/// The series number of arrival delay in the time-order sections.
pub const DELAY: u32 = u32::MAX;
/// Kept series a segment may name: series numbers take 24 bits of a value
/// record.
pub const MAX_SERIES: u32 = 1 << 24;

/// Flags of a value record.
pub const VALUE_NUM: u8 = 1;
pub const VALUE_TEXT: u8 = 2;

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

/// One kept value of a packet, as the `field_values` table has it: a
/// number, a text, both or (a number that is not one, which SQLite stores
/// as null) neither.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValueRecord {
    /// The packet's index in the segment.
    pub index: u32,
    /// Its number in the series names section.
    pub series: u32,
    pub num: Option<f64>,
    /// Where its text starts in the texts section.
    pub text_at: Option<u64>,
}

impl ValueRecord {
    pub fn encode(&self) -> [u8; VALUE_BYTES] {
        let mut b = [0u8; VALUE_BYTES];
        let mut flags = 0u8;
        b[0..4].copy_from_slice(&self.index.to_le_bytes());
        if let Some(n) = self.num {
            b[8..16].copy_from_slice(&n.to_bits().to_le_bytes());
            flags |= VALUE_NUM;
        }
        if let Some(at) = self.text_at {
            b[16..24].copy_from_slice(&at.to_le_bytes());
            flags |= VALUE_TEXT;
        }
        let series = (self.series & (MAX_SERIES - 1)) | (u32::from(flags) << 24);
        b[4..8].copy_from_slice(&series.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> ValueRecord {
        let series = u32_at(b, 4);
        let flags = (series >> 24) as u8;
        ValueRecord {
            index: u32_at(b, 0),
            series: series & (MAX_SERIES - 1),
            num: (flags & VALUE_NUM != 0).then(|| f64::from_bits(u64_at(b, 8))),
            text_at: (flags & VALUE_TEXT != 0).then(|| u64_at(b, 16)),
        }
    }

    /// The index of an encoded record, without decoding the rest.
    pub fn index_of(b: &[u8]) -> u32 {
        u32_at(b, 0)
    }
}

/// One number of a series at one time, in a time-order section of kept
/// numbers. Its lane and series are its group's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PointRecord {
    pub ns: i64,
    pub index: u32,
    pub num: f64,
}

impl PointRecord {
    pub fn encode(&self) -> [u8; POINT_BYTES] {
        let mut b = [0u8; POINT_BYTES];
        b[0..8].copy_from_slice(&self.ns.to_le_bytes());
        b[8..12].copy_from_slice(&self.index.to_le_bytes());
        b[12..20].copy_from_slice(&self.num.to_bits().to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> PointRecord {
        PointRecord {
            ns: i64_at(b, 0),
            index: u32_at(b, 8),
            num: f64::from_bits(u64_at(b, 12)),
        }
    }
}

/// A point while a segment is written, with its lane and series, as bytes
/// whose order is the section's: lane, series, time, index (and the value,
/// which only orders two values of one field of one packet).
pub fn point_key(lane: u32, series: u32, p: &PointRecord) -> [u8; POINT_KEY_BYTES] {
    let mut b = [0u8; POINT_KEY_BYTES];
    b[0..4].copy_from_slice(&lane.to_be_bytes());
    b[4..8].copy_from_slice(&series.to_be_bytes());
    b[8..16].copy_from_slice(&(((p.ns as u64) ^ (1 << 63)).to_be_bytes()));
    b[16..20].copy_from_slice(&p.index.to_be_bytes());
    b[20..28].copy_from_slice(&p.num.to_bits().to_be_bytes());
    b
}

/// The lane, series and point of a [`point_key`].
pub fn from_point_key(b: &[u8; POINT_KEY_BYTES]) -> (u32, u32, PointRecord) {
    let be32 = |at: usize| u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let be64 = |at: usize| {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[at..at + 8]);
        u64::from_be_bytes(a)
    };
    let point = PointRecord {
        ns: (be64(8) ^ (1 << 63)) as i64,
        index: be32(16),
        num: f64::from_bits(be64(20)),
    };
    (be32(0), be32(4), point)
}

/// Where one lane's one series lies in a time-order section of kept numbers
/// and in its buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupRecord {
    pub lane: u32,
    /// A number in the series names section, or [`DELAY`].
    pub series: u32,
    /// First record and number of records in the section.
    pub first: u64,
    pub count: u64,
    /// The same in the series buckets section; no buckets if none were
    /// worth keeping.
    pub bucket_first: u64,
    pub buckets: u64,
}

impl GroupRecord {
    pub fn encode(&self) -> [u8; GROUP_BYTES] {
        let mut b = [0u8; GROUP_BYTES];
        b[0..4].copy_from_slice(&self.lane.to_le_bytes());
        b[4..8].copy_from_slice(&self.series.to_le_bytes());
        b[8..16].copy_from_slice(&self.first.to_le_bytes());
        b[16..24].copy_from_slice(&self.count.to_le_bytes());
        b[24..32].copy_from_slice(&self.bucket_first.to_le_bytes());
        b[32..40].copy_from_slice(&self.buckets.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> GroupRecord {
        GroupRecord {
            lane: u32_at(b, 0),
            series: u32_at(b, 4),
            first: u64_at(b, 8),
            count: u64_at(b, 16),
            bucket_first: u64_at(b, 24),
            buckets: u64_at(b, 32),
        }
    }
}

/// The lowest and highest number of a series in one bucket, and how many.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeriesBucket {
    pub bucket: i64,
    pub lo: f64,
    pub hi: f64,
    pub count: u64,
}

impl SeriesBucket {
    pub fn encode(&self) -> [u8; SERIES_BUCKET_BYTES] {
        let mut b = [0u8; SERIES_BUCKET_BYTES];
        b[0..8].copy_from_slice(&self.bucket.to_le_bytes());
        b[8..16].copy_from_slice(&self.lo.to_bits().to_le_bytes());
        b[16..24].copy_from_slice(&self.hi.to_bits().to_le_bytes());
        b[24..32].copy_from_slice(&self.count.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> SeriesBucket {
        SeriesBucket {
            bucket: i64_at(b, 0),
            lo: f64::from_bits(u64_at(b, 8)),
            hi: f64::from_bits(u64_at(b, 16)),
            count: u64_at(b, 24),
        }
    }
}

/// Whether a series' buckets are worth keeping: at most a quarter as many
/// as its numbers, so that reading them costs at most a quarter of reading
/// the numbers.
pub fn series_buckets_pay(buckets: u64, numbers: u64) -> bool {
    buckets > 0 && buckets.saturating_mul(4) <= numbers
}

/// The grid of a clock's series buckets: four times finer than its base
/// grid, so up to 16,384 buckets across the segment's span. A plot reads a
/// lane's values alone, so finer buckets than density's still pay where
/// a lane has many values; where it has few they are not kept.
pub fn series_shift(base: u32) -> u32 {
    base.saturating_sub(2)
}

/// Arrival delay in milliseconds, as SQLite works it out from
/// `(receive_ns - packet_ns) / 1000000.0`: the difference in whole
/// nanoseconds, or in floating point if that does not fit in 64 bits.
pub fn delay_ms(receive_ns: i64, packet_ns: i64) -> f64 {
    match receive_ns.checked_sub(packet_ns) {
        Some(d) => d as f64 / 1_000_000.0,
        None => (receive_ns as f64 - packet_ns as f64) / 1_000_000.0,
    }
}

/// One space packet's place in the checksum-order section: the checksum of
/// its bytes, its sequence count and length, its lane and its index in the
/// segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChecksumRecord {
    pub sum: i64,
    pub seq: u16,
    pub length: i64,
    pub lane: u32,
    pub index: u32,
}

impl ChecksumRecord {
    pub fn encode(&self) -> [u8; CHECKSUM_BYTES] {
        let mut b = [0u8; CHECKSUM_BYTES];
        b[0..8].copy_from_slice(&self.sum.to_le_bytes());
        b[8..16].copy_from_slice(&self.length.to_le_bytes());
        b[16..20].copy_from_slice(&self.lane.to_le_bytes());
        b[20..24].copy_from_slice(&self.index.to_le_bytes());
        b[24..26].copy_from_slice(&self.seq.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> ChecksumRecord {
        ChecksumRecord {
            sum: i64_at(b, 0),
            length: i64_at(b, 8),
            lane: u32_at(b, 16),
            index: u32_at(b, 20),
            seq: u16_at(b, 24),
        }
    }

    /// Bytes whose order is the section's order: checksum, sequence count,
    /// length, lane, index.
    pub fn sort_key(&self) -> [u8; CHECKSUM_KEY_BYTES] {
        let mut b = [0u8; CHECKSUM_KEY_BYTES];
        b[0..8].copy_from_slice(&(((self.sum as u64) ^ (1 << 63)).to_be_bytes()));
        b[8..10].copy_from_slice(&self.seq.to_be_bytes());
        b[10..18].copy_from_slice(&(((self.length as u64) ^ (1 << 63)).to_be_bytes()));
        b[18..22].copy_from_slice(&self.lane.to_be_bytes());
        b[22..26].copy_from_slice(&self.index.to_be_bytes());
        b
    }

    pub fn from_sort_key(b: &[u8; CHECKSUM_KEY_BYTES]) -> ChecksumRecord {
        let flipped = |at: usize| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[at..at + 8]);
            (u64::from_be_bytes(v) ^ (1 << 63)) as i64
        };
        ChecksumRecord {
            sum: flipped(0),
            seq: u16::from_be_bytes([b[8], b[9]]),
            length: flipped(10),
            lane: u32::from_be_bytes([b[18], b[19], b[20], b[21]]),
            index: u32::from_be_bytes([b[22], b[23], b[24], b[25]]),
        }
    }
}

/// What one segment holds of one lane: how many packets, the lowest and
/// highest time and how many have one on each time clock, and the first
/// and last packet id. Kept while the segment is written and stored in the
/// `segment_lanes` table; a lane's totals are worked out from its rows
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneStats {
    pub count: u64,
    /// Receive time, then packet time: lowest and highest, and how many.
    pub times: [(Option<(i64, i64)>, u64); 2],
    pub first_id: i64,
    pub last_id: i64,
}

impl LaneStats {
    /// A lane whose first packet has id `id`, before that packet is added.
    pub fn new(id: i64) -> LaneStats {
        LaneStats {
            count: 0,
            times: [(None, 0); 2],
            first_id: id,
            last_id: id,
        }
    }

    /// Adds a packet with id `id` and its receive and packet time.
    pub fn add(&mut self, id: i64, times: [Option<i64>; 2]) {
        self.count += 1;
        self.first_id = self.first_id.min(id);
        self.last_id = self.last_id.max(id);
        for (slot, t) in self.times.iter_mut().zip(times) {
            if let Some(t) = t {
                slot.0 = Some(match slot.0 {
                    Some((lo, hi)) => (lo.min(t), hi.max(t)),
                    None => (t, t),
                });
                slot.1 += 1;
            }
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
    let mut known: Vec<(u64, u64, u16, u8, i64)> = Vec::new();
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
            KIND_SERIES_NAMES => (0, &[0]),
            KIND_VALUES => (VALUE_BYTES as u32, &[0]),
            KIND_TEXTS => (0, &[0]),
            KIND_SERIES => (POINT_BYTES as u32, &[0, 1]),
            KIND_GROUPS => (GROUP_BYTES as u32, &[0, 1]),
            KIND_SERIES_BUCKETS => (SERIES_BUCKET_BYTES as u32, &[0, 1]),
            KIND_CHECKSUMS => (CHECKSUM_BYTES as u32, &[0]),
            // A section of a later version.
            _ => continue,
        };
        if e.record != record || !clocks.contains(&e.clock) {
            return bad(format!("section of kind {} is malformed", e.kind));
        }
        if record != 0 && e.length % u64::from(record) != 0 {
            return bad(format!("section of kind {} is cut short", e.kind));
        }
        if matches!(e.kind, KIND_BUCKETS | KIND_SERIES_BUCKETS) && !(0..=63).contains(&e.param) {
            return bad("bucket grid shift out of range");
        }
        if e.kind == KIND_PACKETS {
            packets = Some(e.records());
        }
        // Bucket levels of one clock are told apart by their shift.
        let level = if e.kind == KIND_BUCKETS { e.param } else { 0 };
        known.push((e.offset, e.offset + e.length, e.kind, e.clock, level));
    }
    if packets != Some(tail.packets) {
        return bad("packet count does not match the packets section");
    }
    let mut kinds: Vec<(u16, u8, i64)> = known.iter().map(|k| (k.2, k.3, k.4)).collect();
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

/// The most bucket levels a clock may have: the base grid and twelve
/// coarser ones, each twice as wide as the one before; the twelfth holds
/// the whole span in one or two buckets.
pub const MAX_LEVELS: u32 = 13;

/// Which levels of bucket counts are worth storing. `records[i]` is how
/// many (bucket, lane) records the grid of shift `base + i` would hold and
/// `packets` how many packets have the clock's value. Going from the base
/// grid to coarser ones, a level is kept if it holds at most half as many
/// records as the finer level kept before it, or, for the first kept, half
/// as many as there are packets: reading it must cost at most half of what
/// a view would read without it. Returns the kept shifts, finest first.
pub fn choose_levels(base: u32, records: &[u64], packets: u64) -> Vec<u32> {
    let mut kept = Vec::new();
    let mut reference = packets;
    for (i, &n) in records.iter().enumerate() {
        let shift = base + i as u32;
        if shift > 63 {
            break;
        }
        if n > 0 && n.saturating_mul(2) <= reference {
            kept.push(shift);
            reference = n;
        }
    }
    kept
}

/// Lane ids below this are looked up by index in a [`LaneTable`]; the
/// others in a map.
const DENSE_LANES: u32 = 1 << 16;

/// Something per lane: by index for lanes below [`DENSE_LANES`], else in
/// a map. Holds at most a slot per lane id up to the highest seen below
/// that, 64 K of them.
#[derive(Debug)]
pub struct LaneTable<T> {
    dense: Vec<Option<T>>,
    sparse: Map<u32, T>,
}

impl<T> Default for LaneTable<T> {
    fn default() -> Self {
        LaneTable {
            dense: Vec::new(),
            sparse: Map::default(),
        }
    }
}

impl<T> LaneTable<T> {
    pub fn get_mut(&mut self, lane: u32) -> Option<&mut T> {
        if lane < DENSE_LANES {
            self.dense.get_mut(lane as usize).and_then(Option::as_mut)
        } else {
            self.sparse.get_mut(&lane)
        }
    }

    pub fn insert(&mut self, lane: u32, value: T) {
        if lane < DENSE_LANES {
            if self.dense.len() <= lane as usize {
                self.dense.resize_with(lane as usize + 1, || None);
            }
            self.dense[lane as usize] = Some(value);
        } else {
            self.sparse.insert(lane, value);
        }
    }

    /// The value of `lane`, inserted with `make` if it has none.
    pub fn get_or_insert_with(&mut self, lane: u32, make: impl FnOnce() -> T) -> &mut T {
        if self.get_mut(lane).is_none() {
            self.insert(lane, make());
        }
        match self.get_mut(lane) {
            Some(v) => v,
            None => unreachable!("inserted just above"),
        }
    }

    /// Every lane and its value, in lane order.
    pub fn into_sorted(self) -> Vec<(u32, T)> {
        let mut out: Vec<(u32, T)> = self
            .dense
            .into_iter()
            .enumerate()
            .filter_map(|(lane, v)| v.map(|v| (lane as u32, v)))
            .collect();
        let mut sparse: Vec<(u32, T)> = self.sparse.into_iter().collect();
        sparse.sort_unstable_by_key(|s| s.0);
        out.extend(sparse);
        out
    }
}

/// How many records each bucket grid of a clock would hold, counted from
/// the clock's values as they come, in ascending order within each lane.
/// A lane's value starts a record on every grid whose bucket differs from
/// that of the lane's value before it; for `t` after `last` those are the
/// grids of a shift below the bit length of `t ^ last` (buckets are an
/// arithmetic shift, so this holds for negative values too). So it keeps
/// one count per bit length rather than per grid, and a value costs a
/// lookup and an addition however many grids there are.
#[derive(Debug)]
pub struct LevelCounter {
    last: LaneTable<i64>,
    lanes: u64,
    values: u64,
    /// Values by the bit length of their difference from the lane's last.
    changes: [u64; 65],
}

impl Default for LevelCounter {
    fn default() -> Self {
        LevelCounter {
            last: LaneTable::default(),
            lanes: 0,
            values: 0,
            changes: [0; 65],
        }
    }
}

impl LevelCounter {
    pub fn add(&mut self, lane: u32, t: i64) {
        self.values += 1;
        match self.last.get_mut(lane) {
            Some(last) => {
                let bits = 64 - ((*last ^ t) as u64).leading_zeros();
                self.changes[bits as usize] += 1;
                *last = t;
            }
            None => {
                self.last.insert(lane, t);
                self.lanes += 1;
            }
        }
    }

    /// How many records each grid from shift `base` up (at most
    /// [`MAX_LEVELS`], never past 63) holds, and how many values were
    /// counted: what [`choose_levels`] takes.
    pub fn records(&self, base: u32) -> (Vec<u64>, u64) {
        let base = base.min(63);
        let levels = (64 - base).min(MAX_LEVELS);
        let records = (base..base + levels)
            .map(|shift| self.lanes + self.changes[shift as usize + 1..].iter().sum::<u64>())
            .collect();
        (records, self.values)
    }
}

/// The level a view with buckets `width` wide reads: the coarsest stored
/// level whose buckets are no wider than the view's, if any.
pub fn level_for(levels: &[u32], width: i64) -> Option<u32> {
    levels
        .iter()
        .copied()
        .filter(|&s| (1i128 << s.min(63)) <= i128::from(width))
        .max()
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

    fn write_u32(&mut self, v: u32) {
        self.write_u64(u64::from(v));
    }

    fn write_u64(&mut self, v: u64) {
        self.0 = (self.0 ^ v)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(29);
    }
}

/// Most cells, lanes times view buckets, that [`Counts`] keeps in a table;
/// a window needing more is counted in a map. 32 MB.
const TABLE_CELLS: u64 = 1 << 22;

/// Lane ids below this find their row in a table by index.
const SMALL_LANES: u32 = 1 << 16;

type Map<K, V> = HashMap<K, V, BuildHasherDefault<MixHasher>>;

/// Packet counts per lane and view bucket over a window, gathered from
/// stored buckets and single packets. Counts go to a map, whose cost
/// follows what is added; once the map holds at least a sixteenth of the
/// cells a table of every view bucket of the lanes seen would have, and
/// that table is small enough, to that table, which is quicker to add to.
pub struct Counts {
    from: i64,
    to: i64,
    width: i64,
    /// View buckets in the window.
    bins: u64,
    map: Map<u64, i64>,
    /// The map's size at which a table is next considered; `None` once a
    /// table is out of the question.
    look_at: Option<usize>,
    /// Each lane's row in `table`; for lanes below [`SMALL_LANES`], also
    /// the row plus one by lane, 0 for none.
    slots: Map<u32, usize>,
    small: Vec<u32>,
    /// `bins` counts per lane, row after row, while counting in a table.
    table: Vec<i64>,
    in_table: bool,
    /// [`TABLE_CELLS`], but for tests.
    table_cells: u64,
}

/// The map's key for a lane and view bucket. View buckets are below the
/// 4000 a view may ask for, plus one.
fn cell_key(lane: u32, bin: i64) -> u64 {
    (u64::from(lane) << 32) | (bin as u64 & 0xFFFF_FFFF)
}

impl Counts {
    pub fn new(from: i64, to: i64, width: i64) -> Counts {
        Counts::sized(from, to, width, TABLE_CELLS, 1024)
    }

    fn sized(from: i64, to: i64, width: i64, table_cells: u64, first_look: usize) -> Counts {
        let width = width.max(1);
        let bins = if from <= to {
            view_bucket(to, from, width) as u64 + 1
        } else {
            0
        };
        Counts {
            from,
            to,
            width,
            bins,
            map: Map::default(),
            look_at: (bins <= table_cells).then_some(first_look),
            slots: Map::default(),
            small: Vec::new(),
            table: Vec::new(),
            in_table: false,
            table_cells,
        }
    }

    fn add(&mut self, lane: u32, bin: i64, n: i64) {
        if self.in_table {
            let known = match self.small.get(lane as usize) {
                Some(&s) if s > 0 => Some(s as usize - 1),
                Some(_) => None,
                None => self.slots.get(&lane).copied(),
            };
            let slot = match known {
                Some(slot) => Some(slot),
                None if (self.slots.len() as u64 + 1) * self.bins <= self.table_cells => {
                    let slot = self.slots.len();
                    self.new_slot(lane, slot);
                    self.table.resize(self.table.len() + self.bins as usize, 0);
                    Some(slot)
                }
                None => None,
            };
            if let Some(slot) = slot {
                self.table[slot * self.bins as usize + bin as usize] += n;
                return;
            }
            // Too many lanes for a table: back to the map, for good.
            self.leave_table();
        }
        *self.map.entry(cell_key(lane, bin)).or_default() += n;
        if self.look_at.is_some_and(|at| self.map.len() >= at) {
            self.look_at = self.look_at.map(|at| at * 2);
            self.consider_table();
        }
    }

    /// Moves to a table if the map holds at least a sixteenth of its cells
    /// and it is small enough.
    fn consider_table(&mut self) {
        // The most lanes a table may have: stop counting them past that.
        let most = (self.map.len() as u64 * 16).min(self.table_cells) / self.bins.max(1);
        let mut seen: Map<u32, ()> = Map::default();
        for &k in self.map.keys() {
            seen.insert((k >> 32) as u32, ());
            if seen.len() as u64 > most {
                return;
            }
        }
        let mut lanes: Vec<u32> = seen.into_keys().collect();
        lanes.sort_unstable();
        let cells = lanes.len() as u64 * self.bins;
        if cells > self.table_cells || (self.map.len() as u64) * 16 < cells {
            return;
        }
        self.table = vec![0; cells as usize];
        for (slot, &lane) in lanes.iter().enumerate() {
            self.new_slot(lane, slot);
        }
        for (&k, &n) in &self.map {
            let slot = self.slots[&((k >> 32) as u32)];
            self.table[slot * self.bins as usize + (k & 0xFFFF_FFFF) as usize] = n;
        }
        self.map = Map::default();
        self.in_table = true;
    }

    fn new_slot(&mut self, lane: u32, slot: usize) {
        self.slots.insert(lane, slot);
        if lane < SMALL_LANES {
            if self.small.len() <= lane as usize {
                self.small.resize(lane as usize + 1, 0);
            }
            self.small[lane as usize] = slot as u32 + 1;
        }
    }

    /// Moves what the table holds to the map, which counts from now on.
    fn leave_table(&mut self) {
        for (&lane, &slot) in &self.slots {
            let row = &self.table[slot * self.bins as usize..(slot + 1) * self.bins as usize];
            for (bin, &n) in row.iter().enumerate() {
                if n != 0 {
                    self.map.insert(cell_key(lane, bin as i64), n);
                }
            }
        }
        self.table = Vec::new();
        self.slots = Map::default();
        self.small = Vec::new();
        self.in_table = false;
        self.look_at = None;
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
        if !self.in_table {
            let mut out: Vec<(i64, i64, i64)> = self
                .map
                .iter()
                .filter(|&(_, &n)| n != 0)
                .map(|(&k, &n)| ((k >> 32) as i64, (k & 0xFFFF_FFFF) as i64, n))
                .collect();
            out.sort_unstable();
            return out;
        }
        let mut order: Vec<(u32, usize)> = self.slots.iter().map(|(&l, &s)| (l, s)).collect();
        order.sort_unstable();
        let mut out = Vec::new();
        for (lane, slot) in order {
            let row = &self.table[slot * self.bins as usize..(slot + 1) * self.bins as usize];
            for (bin, &n) in row.iter().enumerate() {
                if n != 0 {
                    out.push((i64::from(lane), bin as i64, n));
                }
            }
        }
        out
    }
}

/// Most view buckets [`SeriesBins`] keeps in a table; more go to a map.
const SERIES_TABLE: u64 = 1 << 16;

/// A series over a window, reduced to the lowest and highest value and the
/// count in each view bucket, from stored buckets and single points, by
/// the rule of [`plan`].
pub struct SeriesBins {
    from: i64,
    to: i64,
    width: i64,
    /// (lowest, highest, count) by view bucket; count 0 for none.
    table: Vec<(f64, f64, u64)>,
    map: Option<std::collections::BTreeMap<i64, (f64, f64, u64)>>,
}

impl SeriesBins {
    pub fn new(from: i64, to: i64, width: i64) -> SeriesBins {
        let width = width.max(1);
        let bins = if from <= to {
            view_bucket(to, from, width) as u64 + 1
        } else {
            0
        };
        let small = bins <= SERIES_TABLE;
        SeriesBins {
            from,
            to,
            width,
            table: if small {
                vec![(0.0, 0.0, 0); bins as usize]
            } else {
                Vec::new()
            },
            map: (!small).then(std::collections::BTreeMap::new),
        }
    }

    fn add(&mut self, bin: i64, lo: f64, hi: f64, count: u64) {
        let cell = match &mut self.map {
            Some(map) => map.entry(bin).or_insert((lo, hi, 0)),
            None => &mut self.table[bin as usize],
        };
        if cell.2 == 0 {
            *cell = (lo, hi, count);
        } else {
            *cell = (cell.0.min(lo), cell.1.max(hi), cell.2 + count);
        }
    }

    /// One value at `t`. Ignored outside the window.
    pub fn point(&mut self, t: i64, value: f64) {
        if (self.from..=self.to).contains(&t) {
            self.add(view_bucket(t, self.from, self.width), value, value, 1);
        }
    }

    /// A stored bucket taken whole: it goes to the view bucket its start
    /// falls in. Ignored unless it lies wholly inside the window.
    pub fn bucket(&mut self, b: &SeriesBucket, shift: u32) {
        let (start, end) = bucket_span(b.bucket, shift);
        if b.count > 0 && start >= i128::from(self.from) && end <= i128::from(self.to) {
            let bin = view_bucket(start as i64, self.from, self.width);
            self.add(bin, b.lo, b.hi, b.count);
        }
    }

    /// One row per view bucket with values: (bucket, lowest, highest,
    /// count), in bucket order.
    pub fn rows(&self) -> Vec<(i64, f64, f64, u64)> {
        match &self.map {
            Some(map) => map
                .iter()
                .map(|(&bin, &(lo, hi, n))| (bin, lo, hi, n))
                .collect(),
            None => self
                .table
                .iter()
                .enumerate()
                .filter(|(_, c)| c.2 > 0)
                .map(|(bin, &(lo, hi, n))| (bin as i64, lo, hi, n))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_records_sort_by_their_keys_and_survive_encoding() {
        let mut records = Vec::new();
        for sum in [i64::MIN, -5, 0, 7, i64::MAX] {
            for seq in [0u16, 1, u16::MAX] {
                for length in [i64::MIN, -1, 0, 9, i64::MAX] {
                    for (lane, index) in [(0u32, 0u32), (0, u32::MAX), (3, 1), (u32::MAX, 2)] {
                        records.push(ChecksumRecord {
                            sum,
                            seq,
                            length,
                            lane,
                            index,
                        });
                    }
                }
            }
        }
        let mut by_key = records.clone();
        by_key.reverse();
        by_key.sort_by_key(|r| r.sort_key());
        records.sort();
        assert_eq!(by_key, records);
        for r in &records {
            assert_eq!(ChecksumRecord::from_sort_key(&r.sort_key()), *r);
            assert_eq!(ChecksumRecord::decode(&r.encode()), *r);
        }
    }

    #[test]
    fn series_bins_follow_the_rule() {
        let mut s = SeriesBins::new(10, 49, 10);
        s.point(10, 3.0);
        s.point(19, -1.0);
        s.point(20, 7.5);
        s.point(50, 100.0);
        s.point(9, 100.0);
        let bucket = |bucket, lo, hi, count| SeriesBucket {
            bucket,
            lo,
            hi,
            count,
        };
        // 12..=15 (shift 2, bucket 3) starts in view bucket 0; 48..=51 is
        // not wholly inside and is dropped.
        s.bucket(&bucket(3, -4.0, 2.0, 6), 2);
        s.bucket(&bucket(12, -9.0, 9.0, 2), 2);
        assert_eq!(s.rows(), vec![(0, -4.0, 3.0, 8), (1, 7.5, 7.5, 1)]);
        // A window of more view buckets than a table holds.
        let mut wide = SeriesBins::new(0, 1 << 40, 1);
        wide.point(1 << 39, 2.0);
        wide.point(1 << 39, 1.0);
        assert_eq!(wide.rows(), vec![(1 << 39, 1.0, 2.0, 2)]);
        assert!(SeriesBins::new(5, 4, 1).rows().is_empty());
    }

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
        version[20] = 1;
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
        // Bucket levels of one clock differ in shift; the same shift twice
        // is a repeat.
        let (tail, mut entries, mut dir_at) = sample();
        let mut level = entries[1];
        level.offset = dir_at;
        level.param = 14;
        entries.push(level);
        dir_at += BUCKET_BYTES as u64;
        assert!(check_directory(&entries, &tail, dir_at).is_ok());
        entries[2].param = 12;
        assert!(check_directory(&entries, &tail, dir_at).is_err());
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
    fn level_counts_are_the_records_each_grid_would_hold() {
        // Lanes, some past the dense ids, with values ascending in each:
        // negative, tied, small steps and enormous jumps.
        let mut state = 0x853c_49e6_748f_ea9bu64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let lanes = [0u32, 3, 9, 70_000, u32::MAX];
        let mut last = [i64::MIN; 5];
        let mut values = Vec::new();
        for _ in 0..3_000 {
            let i = (random() % 5) as usize;
            let step = match random() % 4 {
                0 => 0,
                1 => random() % 8,
                2 => random() % 100_000,
                _ => random() >> (random() % 64),
            };
            last[i] = if last[i] == i64::MIN {
                (random() as i64) >> (random() % 64)
            } else {
                last[i].saturating_add((step >> 1) as i64)
            };
            values.push((lanes[i], last[i]));
        }
        let mut counter = LevelCounter::default();
        for &(lane, t) in &values {
            counter.add(lane, t);
        }
        for base in [0, 1, 7, 20, 40, 51, 62, 63, 70] {
            let (records, n) = counter.records(base);
            assert_eq!(n, values.len() as u64);
            let levels = (64 - base.min(63)).min(MAX_LEVELS);
            assert_eq!(records.len(), levels as usize);
            for (i, &got) in records.iter().enumerate() {
                let shift = base.min(63) + i as u32;
                let mut seen = std::collections::BTreeSet::new();
                for &(lane, t) in &values {
                    seen.insert((lane, bucket_of(t, shift)));
                }
                assert_eq!(got, seen.len() as u64, "base {base} shift {shift}");
            }
        }
    }

    #[test]
    fn levels_are_kept_only_where_they_halve_what_is_read() {
        // A sparse grid (about a record a packet) is not kept; from there
        // each kept level holds at most half the last kept.
        assert_eq!(
            choose_levels(35, &[873, 437, 219, 109, 55, 28, 14], 1000),
            vec![36, 38, 40, 41]
        );
        // Dense lanes halve at every level.
        assert_eq!(
            choose_levels(10, &[16, 8, 4, 2], 3000),
            vec![10, 11, 12, 13]
        );
        // Nothing worth keeping, no packets, and never past shift 63.
        assert_eq!(choose_levels(0, &[900, 800, 700], 1000), Vec::<u32>::new());
        assert_eq!(choose_levels(0, &[0, 0], 0), Vec::<u32>::new());
        assert_eq!(choose_levels(62, &[4, 2, 1], 100), vec![62, 63]);

        // The coarsest level no wider than the view's buckets.
        let levels = [36, 38, 40];
        assert_eq!(level_for(&levels, (1 << 38) - 1), Some(36));
        assert_eq!(level_for(&levels, 1 << 38), Some(38));
        assert_eq!(level_for(&levels, i64::MAX), Some(40));
        assert_eq!(level_for(&levels, (1 << 36) - 1), None);
        assert_eq!(level_for(&[], i64::MAX), None);
        assert_eq!(level_for(&[63], i64::MAX), None);
    }

    #[test]
    fn counts_kept_in_a_table_or_a_map_agree() {
        // Ten view buckets, a table of at most 30 cells (three lanes),
        // looked at when the map holds four.
        let mut c = Counts::sized(0, 9, 1, 30, 4);
        let mut want = std::collections::BTreeMap::new();
        let mut add = |c: &mut Counts, lane: u32, t: i64| {
            c.point(lane, t);
            *want.entry((i64::from(lane), t)).or_insert(0) += 1;
            let rows: Vec<(i64, i64, i64)> = want.iter().map(|(&(l, t), &n)| (l, t, n)).collect();
            assert_eq!(c.rows(), rows);
        };
        for t in [3, 0, 3, 5] {
            add(&mut c, 7, t);
        }
        assert!(!c.in_table);
        // Four cells of one lane's ten: a table.
        add(&mut c, 7, 9);
        assert!(c.in_table);
        for (lane, t) in [(2, 5), (7, 3), (5, 0), (2, 5)] {
            add(&mut c, lane, t);
            assert!(c.in_table);
        }
        // A fourth lane does not fit: back to the map, for good.
        add(&mut c, 1, 1);
        assert!(!c.in_table);
        for t in 0..10 {
            add(&mut c, 3, t);
        }
        assert!(!c.in_table);
        // Few cells of many: a map, never a table.
        let mut sparse = Counts::sized(0, 999, 1, 1 << 20, 4);
        for lane in 0..10 {
            sparse.point(lane, i64::from(lane) * 7);
        }
        assert!(!sparse.in_table);
        // More view buckets than a table holds.
        let mut m = Counts::new(0, 1 << 23, 1);
        assert!(m.look_at.is_none());
        m.point(1, 1 << 22);
        assert_eq!(m.rows(), vec![(1, 1 << 22, 1)]);
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
