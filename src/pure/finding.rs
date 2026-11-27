//! The one shape every check reports in: what was found, how much it
//! matters, and where.
//!
//! Sequence counts and decoders keep their own typed records
//! (`continuity::SeqFinding`, `decode::Notice`) because code matches on
//! their numbers; each turns itself into a [`Finding`] in one place, beside
//! its definition. Every other check builds a [`Finding`] directly.

use crate::pure::ingest::LaneKey;

/// How much a finding matters. Set by the check that made the finding: the
/// same kind can be either, as a limit is for red and yellow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Data was lost, damaged or out of bounds.
    Problem,
    /// Worth knowing, nothing wrong.
    Info,
}

impl Severity {
    /// As stored and as the page reads it.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Problem => "problem",
            Severity::Info => "info",
        }
    }

    pub fn problem_if(problem: bool) -> Severity {
        if problem {
            Severity::Problem
        } else {
            Severity::Info
        }
    }
}

/// Every kind of finding there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    // Sequence counts of one stream.
    Gap,
    Duplicate,
    Reset,
    Interleaved,
    Stray,
    ConstantCount,
    /// Findings or losses counted instead of listed.
    Suppressed,
    // What a decoder could not use, or had to repair.
    Junk,
    BadFrame,
    FrameGap,
    Corrected,
    ControlFrame,
    // How the read of a file ended.
    Truncated,
    Unreadable,
    // What a file's items are.
    LengthField,
    NonPacket,
    // Order within one stream.
    Segment,
    TimeBack,
    Limit,
    // One source's log against another's.
    HopMissing,
    Origins,
}

impl Kind {
    /// Every kind, for tests. A new kind must be added here by hand.
    pub const ALL: [Kind; 21] = [
        Kind::Gap,
        Kind::Duplicate,
        Kind::Reset,
        Kind::Interleaved,
        Kind::Stray,
        Kind::ConstantCount,
        Kind::Suppressed,
        Kind::Junk,
        Kind::BadFrame,
        Kind::FrameGap,
        Kind::Corrected,
        Kind::ControlFrame,
        Kind::Truncated,
        Kind::Unreadable,
        Kind::LengthField,
        Kind::NonPacket,
        Kind::Segment,
        Kind::TimeBack,
        Kind::Limit,
        Kind::HopMissing,
        Kind::Origins,
    ];

    /// As stored. Queries and saved links use these names, so they do not
    /// change.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Gap => "gap",
            Kind::Duplicate => "duplicate",
            Kind::Reset => "reset",
            Kind::Interleaved => "interleaved",
            Kind::Stray => "stray",
            Kind::ConstantCount => "constant_count",
            Kind::Suppressed => "suppressed",
            Kind::Junk => "junk",
            Kind::BadFrame => "bad_frame",
            Kind::FrameGap => "frame_gap",
            Kind::Corrected => "corrected",
            Kind::ControlFrame => "control_frame",
            Kind::Truncated => "truncated",
            Kind::Unreadable => "unreadable",
            Kind::LengthField => "length_field",
            Kind::NonPacket => "non_packet",
            Kind::Segment => "segment",
            Kind::TimeBack => "time_back",
            Kind::Limit => "limit",
            Kind::HopMissing => "hop_missing",
            Kind::Origins => "origins",
        }
    }
}

/// One finding. `L` says which lane it belongs to and `P` which packet, in
/// whatever terms the check has: a stream and a position in the file while
/// a file is read, database ids when stored lanes are compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding<L, P = u64> {
    pub lane: L,
    /// The packet the finding points at, if it points at one.
    pub packet: Option<P>,
    pub severity: Severity,
    pub kind: Kind,
    pub message: String,
}

/// A finding from reading one file: about a lane, or about the file as a
/// whole (`lane` is `None`). `packet` is the packet's position in the file.
pub type FileFinding = Finding<Option<LaneKey>>;

impl<L, P> Finding<L, P> {
    pub fn is_problem(&self) -> bool {
        self.severity == Severity::Problem
    }

    /// The same finding with its lane named another way.
    pub fn map_lane<M>(self, f: impl FnOnce(L) -> M) -> Finding<M, P> {
        Finding {
            lane: f(self.lane),
            packet: self.packet,
            severity: self.severity,
            kind: self.kind,
            message: self.message,
        }
    }
}

impl FileFinding {
    /// A finding about the file as a whole.
    pub fn file(severity: Severity, kind: Kind, message: String) -> FileFinding {
        Finding {
            lane: None,
            packet: None,
            severity,
            kind,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn kind_names_are_distinct_and_plain() {
        let names: BTreeSet<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), Kind::ALL.len());
        for name in names {
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{name}"
            );
        }
    }

    #[test]
    fn a_finding_keeps_everything_but_its_lane_when_renamed() {
        let f: Finding<u8> = Finding {
            lane: 7,
            packet: Some(3),
            severity: Severity::Problem,
            kind: Kind::Gap,
            message: "x".to_string(),
        };
        let g = f.clone().map_lane(|n| Some(u16::from(n) * 2));
        assert_eq!(g.lane, Some(14));
        assert_eq!(
            (g.packet, g.kind, g.is_problem()),
            (Some(3), Kind::Gap, true)
        );
        assert_eq!(g.message, f.message);
    }
}
