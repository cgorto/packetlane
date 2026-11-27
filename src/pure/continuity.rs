//! Sequence-count continuity, per APID and packet type, for one source.
//!
//! Each stream should be one counter that goes up by one and wraps at 16384.
//! This module follows every counter it can see ("runs") and classifies what
//! breaks the pattern:
//!
//! - `Gap`: a small jump forward. Packets were lost.
//! - `Duplicate`: the previous packet again.
//! - `Reset`: one run ends and another starts. A restart or a replay.
//! - `Interleaved`: two or more runs alive at once. More than one emitter is
//!   using the APID.
//! - `Stray`: a packet or two that fit no run.
//! - `Suppressed`: a stream produced more of one kind than is worth listing.
//! - `Constant`: every packet has the same count. The emitter does not count
//!   its packets (COSMOS, for one, sends every command with count 0), so
//!   there is nothing to check and the repeats are not problems.
//!
//! Known limits, from working with counters alone:
//!
//! - A restart that lands a little ahead of the old counter looks like a gap.
//! - Two emitters whose counters are identical look like duplicates.
//! - Packets that arrive out of order are reported as strays, not as loss.
//!
//! Timestamps settle these once the store exists.
//!
//! Feed one `Checker` per source file. Spotting one APID arriving from two
//! different files is a query over the store, not this module's job.

use std::fmt;

use crate::pure::ccsds::{IDLE_APID, PacketType, PrimaryHeader, SEQ_MODULUS};
use crate::pure::finding::{Finding, Kind, Severity};

/// Largest forward jump still treated as lost packets, not a new counter.
const MAX_GAP: u16 = 1024;
/// A run needs this many packets before it counts as a real counter.
const MIN_RUN: u32 = 3;
/// Runs compared against each new packet; older ones are retired.
const MAX_ACTIVE: usize = 8;
/// Retired runs kept per stream for the final verdict.
const MAX_RETIRED: usize = 64;
/// A run that has not advanced for this many packets of its stream is taken
/// to have ended. It can still be continued exactly, but a gap or duplicate
/// is no longer attributed to it.
const STALE_AFTER: u64 = 64;
/// A stream needs this many packets, all with one count, before it is taken
/// to be uncounted. Fewer could be one packet and its repeat.
const MIN_CONSTANT: u64 = 3;
/// Findings of one kind listed individually per stream; the rest are counted.
const MAX_LISTED: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamKey {
    pub apid: u16,
    pub packet_type: PacketType,
}

/// Something kept per stream: found without a search for every packet,
/// and handed back at the end in stream order, as a `BTreeMap` would.
#[derive(Debug)]
pub struct StreamTable<V> {
    /// By APID and type, the place in `entries` plus one; 0 for none.
    /// Made on first use.
    slots: Vec<u32>,
    entries: Vec<(StreamKey, V)>,
}

impl<V> Default for StreamTable<V> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            entries: Vec::new(),
        }
    }
}

impl<V> StreamTable<V> {
    /// Room for every 11-bit APID of both types.
    const SLOTS: usize = 2 << 11;

    pub fn get_or_insert_with(&mut self, key: StreamKey, new: impl FnOnce() -> V) -> &mut V {
        let slot = (key.apid <= 0x7FF).then(|| {
            let ptype = match key.packet_type {
                PacketType::Telemetry => 0,
                PacketType::Command => 1,
            };
            usize::from(key.apid) * 2 + ptype
        });
        let found = match slot {
            Some(slot) => self.slots.get(slot).and_then(|&n| n.checked_sub(1)),
            // Not from a header; a search will do.
            None => self
                .entries
                .iter()
                .position(|(k, _)| *k == key)
                .map(|i| i as u32),
        };
        let i = match found {
            Some(i) => i as usize,
            None => {
                self.entries.push((key, new()));
                if let Some(slot) = slot {
                    if self.slots.is_empty() {
                        self.slots = vec![0; Self::SLOTS];
                    }
                    self.slots[slot] = self.entries.len() as u32;
                }
                self.entries.len() - 1
            }
        };
        &mut self.entries[i].1
    }

    /// Every stream's value, in stream order.
    pub fn into_sorted(mut self) -> Vec<(StreamKey, V)> {
        self.entries.sort_unstable_by_key(|(k, _)| *k);
        self.entries
    }
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.packet_type {
            PacketType::Telemetry => "TM",
            PacketType::Command => "TC",
        };
        write!(f, "APID {} {kind}", self.apid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqKind {
    Gap {
        expected: u16,
        got: u16,
        missing: u16,
    },
    Duplicate {
        seq: u16,
    },
    Reset {
        got: u16,
    },
    Interleaved {
        counters: usize,
    },
    Stray {
        seq: u16,
    },
    Suppressed {
        what: &'static str,
        more: u64,
    },
    /// Not a problem: the stream does not count its packets.
    Constant {
        seq: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqFinding {
    pub key: StreamKey,
    pub kind: SeqKind,
    /// Zero-based position of the packet in the source.
    pub packet_index: u64,
    /// Byte offset of that packet in the source file.
    pub offset: u64,
}

impl SeqFinding {
    /// False for what is only worth knowing: a stream that does not count,
    /// or how many findings were left out of the list.
    pub fn is_problem(&self) -> bool {
        !matches!(
            self.kind,
            SeqKind::Suppressed { .. } | SeqKind::Constant { .. }
        )
    }

    /// The kind this is stored and listed as.
    pub fn kind(&self) -> Kind {
        match self.kind {
            SeqKind::Gap { .. } => Kind::Gap,
            SeqKind::Duplicate { .. } => Kind::Duplicate,
            SeqKind::Reset { .. } => Kind::Reset,
            SeqKind::Interleaved { .. } => Kind::Interleaved,
            SeqKind::Stray { .. } => Kind::Stray,
            SeqKind::Suppressed { .. } => Kind::Suppressed,
            SeqKind::Constant { .. } => Kind::ConstantCount,
        }
    }

    /// As every check reports: the same finding without its numbers.
    pub fn finding(&self) -> Finding<StreamKey> {
        Finding {
            lane: self.key,
            packet: Some(self.packet_index),
            severity: Severity::problem_if(self.is_problem()),
            kind: self.kind(),
            message: self.summary(),
        }
    }

    /// What was found, without the stream name or the position.
    pub fn summary(&self) -> String {
        match &self.kind {
            SeqKind::Gap {
                expected,
                got,
                missing,
            } => {
                let unit = if *missing == 1 { "packet" } else { "packets" };
                format!("{missing} {unit} missing (expected sequence count {expected}, got {got})")
            }
            SeqKind::Duplicate { seq } => format!("Sequence count {seq} repeated"),
            SeqKind::Reset { got } => format!("Sequence count restarted at {got}"),
            SeqKind::Interleaved { counters } => {
                format!("{counters} sequence counts running at once")
            }
            SeqKind::Stray { seq } => format!("Out-of-order packet (sequence count {seq})"),
            SeqKind::Suppressed { what, more } => {
                let label = if *more == 1 {
                    what.strip_suffix('s').unwrap_or(what)
                } else {
                    what
                };
                format!("{more} more {label} not listed")
            }
            SeqKind::Constant { seq } => {
                format!("Sequence count is always {seq}: this stream does not count its packets")
            }
        }
    }
}

impl fmt::Display for SeqFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let place = match self.kind {
            SeqKind::Suppressed { .. } => ", last at",
            SeqKind::Constant { .. } => ", from",
            _ => " at",
        };
        write!(
            f,
            "{}: {}{place} packet #{}, byte {:#x}",
            self.key,
            self.summary(),
            self.packet_index,
            self.offset
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct Tentative {
    expected: u16,
    pos: u64,
    /// Where the gap sits in the findings list, if it was listed.
    finding: Option<usize>,
    /// The packet that jumped ahead.
    jump_seq: u16,
    jump_index: u64,
    jump_offset: u64,
    /// Packets the run has taken since the jump, the jump included.
    since: u32,
}

#[derive(Debug)]
struct Run {
    next: u16,
    hits: u32,
    first_seq: u16,
    first_index: u64,
    first_offset: u64,
    last_index: u64,
    /// Position within its own stream when it last advanced.
    last_pos: u64,
    /// A gap just attributed to this run, which is withdrawn if the count
    /// that was skipped turns up after all: then it was a second counter.
    tentative: Option<Tentative>,
    /// The first packet that carried this run on after another counter had
    /// jumped ahead of it: index, offset, count.
    late: Option<(u64, u64, u16)>,
}

/// Counts findings of one kind so a noisy stream cannot flood the report.
#[derive(Debug, Default)]
struct Tally {
    count: u64,
    /// How many of them are in the findings list.
    listed: u64,
    last_index: u64,
    last_offset: u64,
}

impl Tally {
    /// Records one occurrence. True if it should be listed individually.
    fn add(&mut self, index: u64, offset: u64) -> bool {
        self.count += 1;
        self.last_index = index;
        self.last_offset = offset;
        let list = self.listed < MAX_LISTED;
        self.listed += u64::from(list);
        list
    }
}

#[derive(Debug, Default)]
struct Stream {
    active: Vec<Run>,
    retired: Vec<Run>,
    packets: u64,
    gaps: Tally,
    duplicates: Tally,
    strays: Tally,
    /// The first packet: count, index, offset.
    first: Option<(u16, u64, u64)>,
    /// Whether any packet's count differed from the first's.
    varied: bool,
    /// Where this stream's listed duplicates sit in the findings list, in
    /// case the stream turns out not to count at all.
    duplicate_findings: Vec<usize>,
}

#[derive(Debug, Default)]
pub struct Checker {
    streams: StreamTable<Stream>,
    findings: Vec<SeqFinding>,
    /// Findings withdrawn after the fact, by position.
    retracted: Vec<usize>,
    index: u64,
}

#[derive(Debug)]
pub struct Report {
    /// Packet count per stream, idle packets excluded.
    pub streams: Vec<(StreamKey, u64)>,
    /// In packet order.
    pub findings: Vec<SeqFinding>,
}

fn succ(seq: u16) -> u16 {
    (seq + 1) % SEQ_MODULUS
}

fn pred(seq: u16) -> u16 {
    (seq + SEQ_MODULUS - 1) % SEQ_MODULUS
}

/// How far `to` is ahead of `from`, going round the wrap.
fn forward(from: u16, to: u16) -> u16 {
    (to + SEQ_MODULUS - from) % SEQ_MODULUS
}

impl Checker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes the next packet, numbering packets in the order given.
    pub fn observe(&mut self, header: &PrimaryHeader, offset: u64) {
        let index = self.index;
        self.observe_at(index, header, offset);
    }

    /// Observes a packet whose position in the source the caller knows,
    /// for sources where not every logged item is a packet.
    pub fn observe_at(&mut self, index: u64, header: &PrimaryHeader, offset: u64) {
        self.index = index + 1;
        if header.apid == IDLE_APID {
            return;
        }
        let key = StreamKey {
            apid: header.apid,
            packet_type: header.packet_type,
        };
        let seq = header.seq_count % SEQ_MODULUS;
        let stream = self.streams.get_or_insert_with(key, Stream::default);
        stream.packets += 1;
        let pos = stream.packets;
        match stream.first {
            None => stream.first = Some((seq, index, offset)),
            Some((first, ..)) => stream.varied |= first != seq,
        }
        let live = |r: &Run| pos - r.last_pos <= STALE_AFTER;

        // 1. The next packet of a run we are already following.
        if let Some(run) = stream
            .active
            .iter_mut()
            .filter(|r| r.next == seq)
            .max_by_key(|r| r.last_index)
        {
            run.next = succ(seq);
            run.hits += 1;
            run.last_index = index;
            run.last_pos = pos;
            if let Some(t) = run.tentative.as_mut() {
                t.since += 1;
            }
            return;
        }

        // 2. The last packet of a live run, again.
        if let Some(run) = stream
            .active
            .iter_mut()
            .find(|r| live(r) && pred(r.next) == seq)
        {
            // A repeat still shows the emitter is alive.
            run.last_index = index;
            run.last_pos = pos;
            if stream.duplicates.add(index, offset) {
                stream.duplicate_findings.push(self.findings.len());
                self.findings.push(SeqFinding {
                    key,
                    kind: SeqKind::Duplicate { seq },
                    packet_index: index,
                    offset,
                });
            }
            return;
        }

        // 3. A little ahead of a live run: packets went missing.
        if let Some((run, missing)) = stream
            .active
            .iter_mut()
            .filter(|r| live(r))
            .map(|r| {
                let d = forward(r.next, seq);
                (r, d)
            })
            .filter(|(_, d)| *d <= MAX_GAP)
            .min_by_key(|(_, d)| *d)
        {
            let expected = run.next;
            let listed = stream.gaps.add(index, offset).then(|| {
                self.findings.push(SeqFinding {
                    key,
                    kind: SeqKind::Gap {
                        expected,
                        got: seq,
                        missing,
                    },
                    packet_index: index,
                    offset,
                });
                self.findings.len() - 1
            });
            run.tentative = Some(Tentative {
                expected,
                pos,
                finding: listed,
                jump_seq: seq,
                jump_index: index,
                jump_offset: offset,
                since: 1,
            });
            run.next = succ(seq);
            run.hits += 1;
            run.last_index = index;
            run.last_pos = pos;
            return;
        }

        // 4. Nothing fits: a new counter. `finish` decides what it means.
        // If this is the very count a recent "gap" skipped over, there was no
        // gap: two counters are running, and the jump was the other one.
        if let Some(i) = stream.active.iter().position(|r| {
            r.tentative
                .is_some_and(|t| t.expected == seq && pos - t.pos <= STALE_AFTER)
        }) && let Some(t) = stream.active[i].tentative.take()
        {
            self.retracted.extend(t.finding);
            stream.gaps.count = stream.gaps.count.saturating_sub(1);
            if t.finding.is_some() {
                stream.gaps.listed = stream.gaps.listed.saturating_sub(1);
            }
            let run = &mut stream.active[i];
            // The packets since the jump belong to the other counter: give
            // them a run of their own, and let this run carry on.
            let other = Run {
                next: run.next,
                hits: t.since,
                first_seq: t.jump_seq,
                first_index: t.jump_index,
                first_offset: t.jump_offset,
                last_index: run.last_index,
                last_pos: run.last_pos,
                tentative: None,
                late: None,
            };
            run.next = succ(seq);
            run.hits = run.hits.saturating_sub(t.since) + 1;
            run.last_index = index;
            run.last_pos = pos;
            run.late.get_or_insert((index, offset, seq));
            stream.active.push(other);
            return;
        }
        while stream.active.len() >= MAX_ACTIVE
            && let Some(oldest) =
                (0..stream.active.len()).min_by_key(|&i| stream.active[i].last_index)
        {
            let run = stream.active.swap_remove(oldest);
            if run.hits < MIN_RUN {
                if stream.strays.add(run.first_index, run.first_offset) {
                    self.findings.push(SeqFinding {
                        key,
                        kind: SeqKind::Stray { seq: run.first_seq },
                        packet_index: run.first_index,
                        offset: run.first_offset,
                    });
                }
            } else if stream.retired.len() < MAX_RETIRED {
                stream.retired.push(run);
            }
        }
        stream.active.push(Run {
            next: succ(seq),
            hits: 1,
            first_seq: seq,
            first_index: index,
            first_offset: offset,
            last_index: index,
            last_pos: pos,
            tentative: None,
            late: None,
        });
    }

    pub fn finish(mut self) -> Report {
        let mut streams = Vec::new();
        for (key, stream) in self.streams.into_sorted() {
            let Stream {
                active,
                retired,
                packets,
                gaps,
                mut duplicates,
                mut strays,
                first,
                varied,
                duplicate_findings,
            } = stream;
            streams.push((key, packets));

            // One count on every packet is a stream that does not count,
            // not a packet repeated over and over.
            if let Some((seq, packet_index, offset)) = first
                && !varied
                && packets >= MIN_CONSTANT
            {
                self.retracted.extend(duplicate_findings);
                duplicates = Tally::default();
                self.findings.push(SeqFinding {
                    key,
                    kind: SeqKind::Constant { seq },
                    packet_index,
                    offset,
                });
            }

            let mut runs: Vec<Run> = retired.into_iter().chain(active).collect();
            runs.sort_by_key(|r| r.first_index);
            // A packet that arrives late splits one counter in two: the late
            // packets carry on the old run while the rest continue as a run
            // that starts exactly where the old one ends. Join such pairs
            // and report the late part once.
            let mut i = 0;
            while i < runs.len() {
                let joined = runs[i].late.and_then(|late| {
                    let j = (0..runs.len()).find(|&j| {
                        j != i
                            && runs[j].first_seq == runs[i].next
                            && runs[j].first_index > runs[i].first_index
                            && runs[j].first_index < late.0
                    })?;
                    Some((j, late))
                });
                let Some((j, (late_index, late_offset, late_seq))) = joined else {
                    i += 1;
                    continue;
                };
                let old = runs.remove(i);
                let new = &mut runs[if j > i { j - 1 } else { j }];
                new.hits += old.hits;
                new.first_seq = old.first_seq;
                new.first_index = old.first_index;
                new.first_offset = old.first_offset;
                new.last_index = new.last_index.max(old.last_index);
                if strays.add(late_index, late_offset) {
                    self.findings.push(SeqFinding {
                        key,
                        kind: SeqKind::Stray { seq: late_seq },
                        packet_index: late_index,
                        offset: late_offset,
                    });
                }
                runs.sort_by_key(|r| r.first_index);
                i = 0;
            }
            // A stream with a single short run is just a short stream.
            let judge_strays = runs.len() > 1 || strays.count > 0;

            let mut latest_end: Option<u64> = None;
            let mut overlapping = 0usize;
            let mut first_overlap: Option<(u64, u64)> = None;
            for run in &runs {
                if run.hits < MIN_RUN {
                    if judge_strays && strays.add(run.first_index, run.first_offset) {
                        self.findings.push(SeqFinding {
                            key,
                            kind: SeqKind::Stray { seq: run.first_seq },
                            packet_index: run.first_index,
                            offset: run.first_offset,
                        });
                    }
                    continue;
                }
                match latest_end {
                    None => {}
                    Some(end) if run.first_index < end => {
                        overlapping += 1;
                        first_overlap.get_or_insert((run.first_index, run.first_offset));
                    }
                    Some(_) => self.findings.push(SeqFinding {
                        key,
                        kind: SeqKind::Reset { got: run.first_seq },
                        packet_index: run.first_index,
                        offset: run.first_offset,
                    }),
                }
                latest_end = Some(latest_end.map_or(run.last_index, |e| e.max(run.last_index)));
            }
            if let Some((packet_index, offset)) = first_overlap {
                self.findings.push(SeqFinding {
                    key,
                    kind: SeqKind::Interleaved {
                        counters: overlapping + 1,
                    },
                    packet_index,
                    offset,
                });
            }
            for (tally, what) in [
                (&gaps, "gaps"),
                (&duplicates, "repeated sequence counts"),
                (&strays, "out-of-order packets"),
            ] {
                if tally.count > tally.listed {
                    self.findings.push(SeqFinding {
                        key,
                        kind: SeqKind::Suppressed {
                            what,
                            more: tally.count - tally.listed,
                        },
                        packet_index: tally.last_index,
                        offset: tally.last_offset,
                    });
                }
            }
        }
        self.retracted.sort_unstable();
        for &i in self.retracted.iter().rev() {
            if i < self.findings.len() {
                self.findings.remove(i);
            }
        }
        self.findings.sort_by_key(|f| f.packet_index);
        Report {
            streams,
            findings: self.findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::decode_all;
    use crate::pure::decode::raw::RawDecoder;
    use crate::pure::synth::{Source, interleaved, packet};

    fn counts(seqs: &[u16]) -> Report {
        let data: Vec<u8> = seqs.iter().flat_map(|&s| packet(7, s, &[0])).collect();
        check(&data)
    }

    #[test]
    fn a_stream_that_never_counts_is_noted_once() {
        for n in [3usize, 12, 500] {
            let report = counts(&vec![0; n]);
            assert_eq!(kinds(&report), [&SeqKind::Constant { seq: 0 }], "{n}");
            assert!(!report.findings[0].is_problem());
            assert_eq!(report.findings[0].packet_index, 0);
        }
        // Any one count will do, not only 0.
        assert_eq!(kinds(&counts(&[9; 40])), [&SeqKind::Constant { seq: 9 }]);
    }

    #[test]
    fn repeats_in_a_stream_that_counts_stay_problems() {
        // Two packets could be one and its repeat.
        assert_eq!(kinds(&counts(&[0, 0])), [&SeqKind::Duplicate { seq: 0 }]);
        // One other count anywhere, and the stream counts.
        let mut seqs = vec![0u16; 30];
        seqs.push(1);
        let report = counts(&seqs);
        assert_eq!(report.findings.len(), 21, "{:?}", report.findings);
        assert!(
            report
                .findings
                .iter()
                .all(|f| !matches!(f.kind, SeqKind::Constant { .. }))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| matches!(f.kind, SeqKind::Suppressed { more: 9, .. }))
        );
        let report = counts(&[5, 6, 7, 7, 7, 8]);
        assert_eq!(
            kinds(&report),
            [
                &SeqKind::Duplicate { seq: 7 },
                &SeqKind::Duplicate { seq: 7 }
            ]
        );
    }

    #[test]
    fn an_uncounted_stream_does_not_hide_its_neighbours() {
        // APID 7 never counts; APID 8 counts and loses a packet.
        let mut data = Vec::new();
        for i in 0..10u16 {
            data.extend(packet(7, 0, &[0]));
            if i != 4 {
                data.extend(packet(8, i, &[0]));
            }
        }
        let report = check(&data);
        assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
        assert!(matches!(
            report.findings[0].kind,
            SeqKind::Constant { seq: 0 }
        ));
        assert!(matches!(
            report.findings[1].kind,
            SeqKind::Gap { missing: 1, .. }
        ));
    }

    fn check(data: &[u8]) -> Report {
        let mut checker = Checker::new();
        let (records, end) = decode_all(&mut RawDecoder::new(), data);
        assert_eq!(end, None);
        for record in records {
            let header = PrimaryHeader::parse(&record.payload).unwrap();
            checker.observe(&header, record.offset);
        }
        checker.finish()
    }

    fn kinds(report: &Report) -> Vec<&SeqKind> {
        report.findings.iter().map(|f| &f.kind).collect()
    }

    #[test]
    fn clean_stream_across_the_wrap() {
        let mut src = Source::new(0x1A3, 16380, 4);
        let data: Vec<u8> = (0..20).flat_map(|_| src.emit()).collect();
        let report = check(&data);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.streams.len(), 1);
        assert_eq!(report.streams[0].1, 20);
    }

    #[test]
    fn two_sources_on_one_apid() {
        let mut old = Source::new(0x1A3, 9000, 4);
        let mut new = Source::new(0x1A3, 12, 4);
        let report = check(&interleaved(&mut old, &mut new, 10));
        assert_eq!(kinds(&report), [&SeqKind::Interleaved { counters: 2 }]);
        // The second source's first packet: index 1, right after one 10-byte packet.
        assert_eq!(report.findings[0].packet_index, 1);
        assert_eq!(report.findings[0].offset, 10);
    }

    #[test]
    fn two_sources_with_nearby_counters() {
        let mut a = Source::new(0x1A3, 100, 4);
        let mut b = Source::new(0x1A3, 105, 4);
        let report = check(&interleaved(&mut a, &mut b, 10));
        assert_eq!(kinds(&report), [&SeqKind::Interleaved { counters: 2 }]);
    }

    #[test]
    fn second_source_just_ahead_across_the_wrap() {
        // The old counter is near the top; the new one starts just past the wrap.
        let mut old = Source::new(0x1A3, 15780, 4);
        let mut new = Source::new(0x1A3, 12, 4);
        let mut data: Vec<u8> = (0..5).flat_map(|_| old.emit()).collect();
        data.extend(interleaved(&mut new, &mut old, 20));
        let report = check(&data);
        assert_eq!(kinds(&report), [&SeqKind::Interleaved { counters: 2 }]);
    }

    #[test]
    fn a_late_packet_is_a_stray_not_a_gap() {
        let seqs = [1u16, 2, 3, 4, 5, 7, 6, 8, 9, 10];
        let data: Vec<u8> = seqs
            .iter()
            .flat_map(|&s| packet(0x1A3, s, &[0; 4]))
            .collect();
        let report = check(&data);
        assert_eq!(kinds(&report), [&SeqKind::Stray { seq: 6 }]);
    }

    #[test]
    fn different_apids_do_not_interfere() {
        let mut a = Source::new(0x100, 0, 4);
        let mut b = Source::new(0x101, 7000, 4);
        let report = check(&interleaved(&mut a, &mut b, 10));
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.streams.len(), 2);
    }

    #[test]
    fn lost_packets_are_a_gap() {
        let mut src = Source::new(0x1A3, 50, 4);
        let mut data: Vec<u8> = (0..5).flat_map(|_| src.emit()).collect();
        src.skip(3);
        data.extend((0..5).flat_map(|_| src.emit()));
        let report = check(&data);
        assert_eq!(
            kinds(&report),
            [&SeqKind::Gap {
                expected: 55,
                got: 58,
                missing: 3
            }]
        );
    }

    #[test]
    fn restart_is_a_reset_not_an_interleave() {
        let mut first = Source::new(0x1A3, 500, 4);
        let mut second = Source::new(0x1A3, 0, 4);
        let mut data: Vec<u8> = (0..20).flat_map(|_| first.emit()).collect();
        data.extend((0..20).flat_map(|_| second.emit()));
        let report = check(&data);
        assert_eq!(kinds(&report), [&SeqKind::Reset { got: 0 }]);
        assert_eq!(report.findings[0].packet_index, 20);
    }

    #[test]
    fn repeated_packet_is_a_duplicate() {
        let mut src = Source::new(0x1A3, 7, 4);
        let mut data: Vec<u8> = (0..3).flat_map(|_| src.emit()).collect();
        data.extend(packet(0x1A3, 9, &[0; 4]));
        data.extend((0..3).flat_map(|_| src.emit()));
        let report = check(&data);
        assert_eq!(kinds(&report), [&SeqKind::Duplicate { seq: 9 }]);
    }

    #[test]
    fn idle_packets_are_ignored() {
        let mut src = Source::new(0x1A3, 0, 4);
        let mut data = Vec::new();
        for i in 0..10u16 {
            data.extend(src.emit());
            data.extend(packet(IDLE_APID, i * 37, &[0; 4]));
        }
        let report = check(&data);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.streams.len(), 1);
    }

    #[test]
    fn restart_then_loss_is_reset_and_gap() {
        let mut first = Source::new(0x1A3, 500, 4);
        let mut second = Source::new(0x1A3, 0, 4);
        let mut data: Vec<u8> = (0..20).flat_map(|_| first.emit()).collect();
        data.extend((0..518).flat_map(|_| second.emit()));
        second.skip(5);
        data.extend((0..10).flat_map(|_| second.emit()));
        let report = check(&data);
        assert_eq!(
            kinds(&report),
            [
                &SeqKind::Reset { got: 0 },
                &SeqKind::Gap {
                    expected: 518,
                    got: 523,
                    missing: 5
                }
            ]
        );
    }

    #[test]
    fn slow_second_emitter_is_still_followed() {
        let mut fast = Source::new(0x1A3, 3000, 4);
        let mut slow = Source::new(0x1A3, 40, 4);
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend((0..200).flat_map(|_| fast.emit()));
            data.extend(slow.emit());
        }
        let report = check(&data);
        assert_eq!(kinds(&report), [&SeqKind::Interleaved { counters: 2 }]);
    }

    #[test]
    fn a_stuck_counter_does_not_flood() {
        // It counted once, so it is a counter, and then it stuck.
        let data: Vec<u8> = (0..1001u16)
            .flat_map(|i| packet(0x1A3, i.min(1), &[0; 4]))
            .collect();
        let report = check(&data);
        assert_eq!(report.findings.len(), 21, "{:?}", report.findings.len());
        assert_eq!(
            report.findings.last().map(|f| &f.kind),
            Some(&SeqKind::Suppressed {
                what: "repeated sequence counts",
                more: 979
            })
        );
    }

    fn check_seqs(seqs: &[u16]) -> Report {
        let data: Vec<u8> = seqs
            .iter()
            .flat_map(|&s| packet(0x1A3, s, &[0; 4]))
            .collect();
        check(&data)
    }

    #[test]
    fn one_packet_ahead_of_the_counter_is_a_stray_not_a_reset() {
        let report = check_seqs(&[100, 101, 102, 110, 103, 104, 105]);
        assert_eq!(kinds(&report), [&SeqKind::Stray { seq: 110 }]);
        assert_eq!(report.findings[0].packet_index, 3);
    }

    #[test]
    fn two_packets_ahead_of_the_counter_are_not_a_second_emitter() {
        let report = check_seqs(&[100, 101, 102, 110, 103, 111, 104, 105]);
        assert_eq!(kinds(&report), [&SeqKind::Stray { seq: 110 }]);
    }

    #[test]
    fn several_late_packets_are_reported_once() {
        let report = check_seqs(&[1, 2, 3, 4, 5, 8, 6, 7, 9, 10, 11]);
        assert_eq!(kinds(&report), [&SeqKind::Stray { seq: 6 }]);
    }

    #[test]
    fn listed_and_suppressed_gaps_add_up_after_a_retraction() {
        let mut seqs: Vec<u16> = vec![0, 1, 2, 5000, 5001, 5002];
        let mut b = 5002;
        for _ in 0..19 {
            b += 3;
            seqs.push(b); // 19 gaps on the second counter
        }
        seqs.push(10); // a 20th, on the first counter, listed
        b += 3;
        seqs.push(b); // a 21st, real, over the cap
        seqs.push(3); // the count the 20th skipped: that one was no gap
        let report = check_seqs(&seqs);
        let listed = report
            .findings
            .iter()
            .filter(|f| matches!(f.kind, SeqKind::Gap { .. }))
            .count() as u64;
        let suppressed: u64 = report
            .findings
            .iter()
            .map(|f| match f.kind {
                SeqKind::Suppressed { what: "gaps", more } => more,
                _ => 0,
            })
            .sum();
        assert_eq!((listed, suppressed), (19, 1));
    }
}
