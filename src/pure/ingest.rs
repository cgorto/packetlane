//! Turning decoded records and check results into rows for the store.

use crate::pure::ccsds::{PacketType, PrimaryHeader};
use crate::pure::checksum::fnv1a;
use crate::pure::config::ResolvedTime;
use crate::pure::continuity::{Finding, FindingKind, Report, StreamKey};
use crate::pure::decode::{DecodeEnd, Record};
use crate::pure::format::packet_time_ns;

/// What kind of thing a timeline lane holds.
pub const LANE_PACKET: &str = "packet";
pub const LANE_OTHER: &str = "other";
pub const LANE_LOG: &str = "log";

pub const SEVERITY_PROBLEM: &str = "problem";
pub const SEVERITY_INFO: &str = "info";

/// Identifies a lane within one run and source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LaneKey {
    pub kind: &'static str,
    /// -1 when the lane is not one packet stream.
    pub apid: i64,
    /// 0 telemetry, 1 command, -1 when not a packet stream.
    pub ptype: i64,
    /// The file, for text log lanes; 0 otherwise.
    pub file_id: i64,
}

impl LaneKey {
    pub fn stream(key: StreamKey) -> LaneKey {
        LaneKey {
            kind: LANE_PACKET,
            apid: i64::from(key.apid),
            ptype: ptype_code(key.packet_type),
            file_id: 0,
        }
    }

    pub fn other() -> LaneKey {
        LaneKey {
            kind: LANE_OTHER,
            apid: -1,
            ptype: -1,
            file_id: 0,
        }
    }

    pub fn log(file_id: i64) -> LaneKey {
        LaneKey {
            kind: LANE_LOG,
            apid: -1,
            ptype: -1,
            file_id,
        }
    }
}

pub fn ptype_code(t: PacketType) -> i64 {
    match t {
        PacketType::Telemetry => 0,
        PacketType::Command => 1,
    }
}

pub fn ptype_from_code(code: i64) -> Option<PacketType> {
    match code {
        0 => Some(PacketType::Telemetry),
        1 => Some(PacketType::Command),
        _ => None,
    }
}

/// One row of the `packets` table, minus the ids the store assigns.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketRow {
    pub idx: i64,
    pub offset: i64,
    pub length: i64,
    pub receive_ns: Option<i64>,
    pub packet_ns: Option<i64>,
    /// The parsed header, if the logged item is one whole space packet.
    pub header: Option<PrimaryHeader>,
    pub sum: i64,
    pub label: Option<String>,
}

impl PacketRow {
    pub fn lane(&self) -> LaneKey {
        match &self.header {
            Some(h) => LaneKey::stream(StreamKey {
                apid: h.apid,
                packet_type: h.packet_type,
            }),
            None => LaneKey::other(),
        }
    }
}

/// The header of a logged item, if the item is exactly one space packet:
/// version 0 and a length field that matches the bytes present.
pub fn whole_packet_header(payload: &[u8]) -> Option<PrimaryHeader> {
    PrimaryHeader::parse(payload).filter(|h| h.version == 0 && h.total_len() == payload.len())
}

/// Builds the row for one record. `clock_offset_ns` is the correction for
/// the logging host's clock and applies to the receive time only.
pub fn packet_row(
    idx: u64,
    record: &Record,
    time: Option<&ResolvedTime>,
    clock_offset_ns: i64,
) -> PacketRow {
    let header = whole_packet_header(&record.payload);
    let packet_ns = match (&header, time) {
        (Some(h), Some(rule)) if h.has_secondary_header => packet_time_ns(rule, &record.payload),
        _ => None,
    };
    PacketRow {
        idx: i64::try_from(idx).unwrap_or(i64::MAX),
        offset: i64::try_from(record.offset).unwrap_or(i64::MAX),
        length: i64::try_from(record.payload.len()).unwrap_or(i64::MAX),
        receive_ns: record
            .receive_time_ns
            .and_then(|t| t.checked_add(clock_offset_ns)),
        packet_ns,
        header,
        // Stored as the same 64 bits, reinterpreted as signed.
        sum: fnv1a(&record.payload) as i64,
        label: record.label.clone(),
    }
}

/// One row of the `findings` table, minus ids.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingRow {
    pub lane: Option<LaneKey>,
    /// Position in the file of the packet the finding points at.
    pub packet_index: Option<u64>,
    pub severity: &'static str,
    pub kind: &'static str,
    pub message: String,
}

fn kind_name(kind: &FindingKind) -> &'static str {
    match kind {
        FindingKind::Gap { .. } => "gap",
        FindingKind::Duplicate { .. } => "duplicate",
        FindingKind::Reset { .. } => "reset",
        FindingKind::Interleaved { .. } => "interleaved",
        FindingKind::Stray { .. } => "stray",
        FindingKind::Suppressed { .. } => "suppressed",
    }
}

fn finding_row(finding: &Finding) -> FindingRow {
    FindingRow {
        lane: Some(LaneKey::stream(finding.key)),
        packet_index: Some(finding.packet_index),
        severity: match finding.kind {
            FindingKind::Suppressed { .. } => SEVERITY_INFO,
            _ => SEVERITY_PROBLEM,
        },
        kind: kind_name(&finding.kind),
        message: finding.summary(),
    }
}

/// Message for records in a packet file that are not CCSDS space packets.
pub fn non_packet_message(count: u64) -> String {
    if count == 1 {
        "1 record is not a space packet".to_string()
    } else {
        format!("{count} records are not space packets")
    }
}

/// The findings for one packet file: the continuity report, how the read
/// ended, and how many logged items were not space packets.
pub fn file_findings(
    report: &Report,
    end: Option<&DecodeEnd>,
    non_packets: u64,
) -> Vec<FindingRow> {
    let mut rows: Vec<FindingRow> = report.findings.iter().map(finding_row).collect();
    if let Some(end) = end {
        rows.push(FindingRow {
            lane: None,
            packet_index: None,
            severity: SEVERITY_PROBLEM,
            kind: match end {
                DecodeEnd::Truncated { .. } => "truncated",
                DecodeEnd::Error(_) => "unreadable",
            },
            message: end.to_string(),
        });
    }
    if non_packets > 0 {
        rows.push(FindingRow {
            lane: Some(LaneKey::other()),
            packet_index: None,
            severity: SEVERITY_INFO,
            kind: "non_packet",
            message: non_packet_message(non_packets),
        });
    }
    rows
}

/// A file's path within its run, with forward slashes, from the two
/// canonical paths split into components. `None` if the file is not under
/// the root.
pub fn relative_path(root: &[String], file: &[String]) -> Option<String> {
    let rest = file.strip_prefix(root)?;
    (!rest.is_empty()).then(|| rest.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::config::Config;
    use crate::pure::continuity::Checker;
    use crate::pure::decode::DecodeError;
    use crate::pure::synth::packet;

    fn record(payload: Vec<u8>) -> Record {
        Record {
            offset: 128,
            receive_time_ns: Some(1_000),
            label: Some("SIM HK".to_string()),
            payload,
        }
    }

    #[test]
    fn a_whole_packet_becomes_a_stream_row() {
        let row = packet_row(7, &record(packet(0x1A3, 5, &[1, 2, 3])), None, 250);
        assert_eq!(row.idx, 7);
        assert_eq!(row.offset, 128);
        assert_eq!(row.length, 9);
        assert_eq!(row.receive_ns, Some(1_250));
        assert_eq!(row.packet_ns, None);
        assert_eq!(row.header.unwrap().seq_count, 5);
        assert_eq!(row.lane().kind, LANE_PACKET);
        assert_eq!(row.lane().apid, 0x1A3);
        assert_eq!(row.lane().ptype, 0);
    }

    #[test]
    fn anything_else_goes_to_the_other_lane() {
        // Too short, wrong version, and a length that disagrees with the bytes.
        let mut long = packet(0x1A3, 5, &[1, 2, 3]);
        long.push(0);
        for payload in [vec![1, 2, 3], vec![0xFF; 12], long] {
            let row = packet_row(0, &record(payload), None, 0);
            assert!(row.header.is_none());
            assert_eq!(row.lane(), LaneKey::other());
        }
    }

    #[test]
    fn packet_time_needs_a_rule_and_a_secondary_header() {
        let rule = Config::parse("[packet_time]\ncode = \"cuc\"\nepoch = \"1970-01-01T00:00:00Z\"")
            .unwrap()
            .resolved_time()
            .unwrap();
        // No secondary header flag: the bytes are data, not a time.
        let plain = packet(0x1A3, 0, &[0, 0, 0, 9, 0, 0]);
        assert_eq!(
            packet_row(0, &record(plain.clone()), Some(&rule), 0).packet_ns,
            None
        );
        let mut flagged = plain;
        flagged[0] |= 0x08;
        let row = packet_row(0, &record(flagged), Some(&rule), 5);
        assert_eq!(row.packet_ns, Some(9_000_000_000));
        // The host clock correction does not touch the packet's own time.
        assert_eq!(row.receive_ns, Some(1_005));
    }

    #[test]
    fn findings_carry_lane_and_position() {
        let mut checker = Checker::new();
        for (i, seq) in [0u16, 1, 2, 6, 7].into_iter().enumerate() {
            let p = packet(0x064, seq, &[0]);
            checker.observe_at(i as u64 * 2, &PrimaryHeader::parse(&p).unwrap(), 0);
        }
        let end = DecodeEnd::Error(DecodeError::Implausible {
            offset: 99,
            reason: "test",
        });
        let rows = file_findings(&checker.finish(), Some(&end), 3);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind, "gap");
        assert_eq!(rows[0].packet_index, Some(6));
        assert_eq!(rows[0].lane.unwrap().apid, 0x064);
        assert_eq!(
            rows[0].message,
            "3 packets missing (expected sequence count 3, got 6)"
        );
        assert_eq!(rows[1].kind, "unreadable");
        assert!(rows[1].lane.is_none());
        assert_eq!(rows[2].kind, "non_packet");
        assert_eq!(rows[2].severity, SEVERITY_INFO);
    }

    #[test]
    fn relative_paths() {
        let v = |s: &str| s.split('/').map(str::to_string).collect::<Vec<_>>();
        assert_eq!(
            relative_path(&v("runs/a"), &v("runs/a/host/x.bin")).as_deref(),
            Some("host/x.bin")
        );
        assert_eq!(relative_path(&v("runs/a"), &v("runs/a")), None);
        assert_eq!(relative_path(&v("runs/a"), &v("runs/ab/x.bin")), None);
        assert_eq!(relative_path(&v("runs/a"), &v("other/x.bin")), None);
    }
}
