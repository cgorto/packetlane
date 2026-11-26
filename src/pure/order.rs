//! Two checks on the order of one stream's packets that the sequence count
//! alone does not make: that segmented packets come as first, continuation,
//! last; and that packet time does not go backwards.
//!
//! Both only speak when the packet before is known to be the one before:
//! after a jump in the sequence count there is nothing to compare with, and
//! the jump is already reported by `continuity`.

use std::collections::BTreeMap;

use crate::pure::ccsds::{IDLE_APID, PrimaryHeader, SEQ_MODULUS, SeqFlags};
use crate::pure::continuity::StreamKey;
use crate::pure::finding::{Finding, Kind, Severity};

/// Findings of one kind listed per stream; the rest are counted.
const MAX_LISTED: u32 = 20;

/// What this check reports: kind [`Kind::Segment`] or [`Kind::TimeBack`],
/// with no packet for a closing count. Time going back is normal for
/// replayed data, so it is only a note.
pub type OrderFinding = Finding<StreamKey>;

#[derive(Clone, Copy, PartialEq)]
enum Segments {
    /// Nothing to go on: the start of the file, or just after a jump.
    Unknown,
    Between,
    Inside,
}

struct Stream {
    last_seq: Option<u16>,
    segments: Segments,
    last_time: Option<i64>,
    listed: [u32; 2],
    unlisted: [u64; 2],
}

#[derive(Default)]
pub struct OrderChecker {
    streams: BTreeMap<StreamKey, Stream>,
    findings: Vec<OrderFinding>,
}

impl OrderChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// `packet_ns` is the packet's own time, where the configuration says
    /// how to read one.
    pub fn observe(&mut self, index: u64, header: &PrimaryHeader, packet_ns: Option<i64>) {
        if header.apid == IDLE_APID {
            return;
        }
        let key = StreamKey {
            apid: header.apid,
            packet_type: header.packet_type,
        };
        let stream = self.streams.entry(key).or_insert(Stream {
            last_seq: None,
            segments: Segments::Unknown,
            last_time: None,
            listed: [0; 2],
            unlisted: [0; 2],
        });
        let follows = stream.last_seq.map(|s| (s + 1) % SEQ_MODULUS) == Some(header.seq_count);
        stream.last_seq = Some(header.seq_count);
        if !follows {
            stream.segments = Segments::Unknown;
            stream.last_time = None;
        }

        let before = stream.segments;
        let wrong = match (before, header.seq_flags) {
            (Segments::Inside, SeqFlags::First) => {
                Some("First segment while another packet's segments were still open")
            }
            (Segments::Inside, SeqFlags::Unsegmented) => {
                Some("Whole packet while another packet's segments were still open")
            }
            (Segments::Between, SeqFlags::Continuation) => {
                Some("Continuation segment with no first segment")
            }
            (Segments::Between, SeqFlags::Last) => Some("Last segment with no first segment"),
            _ => None,
        };
        stream.segments = match header.seq_flags {
            SeqFlags::First | SeqFlags::Continuation => Segments::Inside,
            SeqFlags::Last | SeqFlags::Unsegmented => Segments::Between,
        };
        let mut found = Vec::new();
        if let Some(what) = wrong {
            found.push((0, Kind::Segment, Severity::Problem, what.to_string()));
        }
        if let (Some(last), Some(now)) = (stream.last_time, packet_ns)
            && now < last
        {
            let back = (last - now) as f64 / 1e9;
            found.push((
                1,
                Kind::TimeBack,
                Severity::Info,
                format!("Packet time went back {back:.3} s"),
            ));
        }
        if packet_ns.is_some() {
            stream.last_time = packet_ns;
        }
        for (slot, kind, severity, message) in found {
            if stream.listed[slot] < MAX_LISTED {
                stream.listed[slot] += 1;
                self.findings.push(Finding {
                    lane: key,
                    packet: Some(index),
                    severity,
                    kind,
                    message,
                });
            } else {
                stream.unlisted[slot] += 1;
            }
        }
    }

    pub fn finish(mut self) -> Vec<OrderFinding> {
        for (key, stream) in &self.streams {
            for (slot, kind, what) in [
                (0, Kind::Segment, "segment order faults"),
                (1, Kind::TimeBack, "steps back in packet time"),
            ] {
                if stream.unlisted[slot] > 0 {
                    self.findings.push(Finding {
                        lane: *key,
                        packet: None,
                        severity: Severity::Info,
                        kind,
                        message: format!("{} more {what} not listed", stream.unlisted[slot]),
                    });
                }
            }
        }
        self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::ccsds::PacketType;

    fn header(seq: u16, flags: SeqFlags) -> PrimaryHeader {
        PrimaryHeader {
            version: 0,
            packet_type: PacketType::Telemetry,
            has_secondary_header: true,
            apid: 5,
            seq_flags: flags,
            seq_count: seq,
            data_length: 0,
        }
    }

    fn segments(start: u16, flags: &[SeqFlags]) -> Vec<(Option<u64>, String)> {
        let mut checker = OrderChecker::new();
        for (i, f) in flags.iter().enumerate() {
            checker.observe(
                i as u64,
                &header((start + i as u16) % SEQ_MODULUS, *f),
                None,
            );
        }
        checker
            .finish()
            .into_iter()
            .map(|f| (f.packet, f.message))
            .collect()
    }

    use SeqFlags::{Continuation as C, First as F, Last as L, Unsegmented as U};

    #[test]
    fn well_formed_segments_say_nothing() {
        assert_eq!(segments(0, &[U, F, C, C, L, U, F, L, F, L, U]), []);
        // Across the wrap of the sequence count too.
        assert_eq!(segments(SEQ_MODULUS - 2, &[F, C, C, L]), []);
        // A file may begin partway through a segmented packet.
        assert_eq!(segments(0, &[C, C, L, U]), []);
        assert_eq!(segments(0, &[L, F, L]), []);
    }

    #[test]
    fn segments_out_of_order_are_found() {
        let got = segments(0, &[U, C, L, U, L, F, F, C, U, U]);
        let want = [
            (1, "Continuation segment with no first segment"),
            (4, "Last segment with no first segment"),
            (
                6,
                "First segment while another packet's segments were still open",
            ),
            (
                8,
                "Whole packet while another packet's segments were still open",
            ),
        ];
        let want: Vec<(Option<u64>, String)> = want
            .iter()
            .map(|(i, m)| (Some(*i), m.to_string()))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn nothing_is_said_about_the_packet_after_a_jump() {
        let mut checker = OrderChecker::new();
        checker.observe(0, &header(0, U), Some(10_000_000_000));
        // Sequence count jumps: a continuation here may be the tail of a
        // packet whose start was lost, and an earlier time may be a replay.
        checker.observe(1, &header(7, C), Some(1_000_000_000));
        checker.observe(2, &header(8, L), Some(2_000_000_000));
        assert_eq!(checker.finish(), []);
    }

    #[test]
    fn time_going_back_is_a_note_not_a_problem() {
        let mut checker = OrderChecker::new();
        for (i, t) in [10.0, 11.0, 10.5, 10.6, 10.6, 3.0].iter().enumerate() {
            checker.observe(i as u64, &header(i as u16, U), Some((t * 1e9) as i64));
        }
        // No time at all on a packet neither resets nor trips the check.
        checker.observe(6, &header(6, U), None);
        checker.observe(7, &header(7, U), Some(4_000_000_000));
        let got = checker.finish();
        let lines: Vec<(Option<u64>, &str, bool)> = got
            .iter()
            .map(|f| (f.packet, f.message.as_str(), f.is_problem()))
            .collect();
        assert_eq!(
            lines,
            [
                (Some(2), "Packet time went back 0.500 s", false),
                (Some(5), "Packet time went back 7.600 s", false),
            ]
        );
        assert!(got.iter().all(|f| f.kind == Kind::TimeBack));
    }

    #[test]
    fn a_flood_is_capped_and_counted() {
        let mut checker = OrderChecker::new();
        for i in 0..100u16 {
            // Every packet a continuation after a whole packet, and earlier.
            let flags = if i % 2 == 0 { U } else { C };
            checker.observe(
                u64::from(i),
                &header(i, flags),
                Some(1_000_000 - i64::from(i)),
            );
        }
        let got = checker.finish();
        let count = |kind: &str, listed: bool| {
            got.iter()
                .filter(|f| f.kind.name() == kind && f.packet.is_some() == listed)
                .count()
        };
        assert_eq!(count("segment", true), 20);
        assert_eq!(count("time_back", true), 20);
        assert_eq!(count("segment", false), 1);
        assert_eq!(count("time_back", false), 1);
        assert!(
            got.iter()
                .any(|f| f.message == "79 more steps back in packet time not listed")
        );
    }

    #[test]
    fn idle_packets_and_other_streams_do_not_interfere() {
        let mut checker = OrderChecker::new();
        checker.observe(0, &header(0, F), None);
        let mut idle = header(9, U);
        idle.apid = IDLE_APID;
        checker.observe(1, &idle, None);
        let mut other = header(3, U);
        other.apid = 6;
        checker.observe(2, &other, None);
        checker.observe(3, &header(1, L), None);
        assert_eq!(checker.finish(), []);
    }
}
