//! Turning decoded records and check results into rows for the store.

use crate::pure::ccsds::{PacketType, PrimaryHeader, SeqFlags};
use crate::pure::checksum::fnv1a;
use crate::pure::config::ResolvedTime;
use crate::pure::continuity::{Report, StreamKey};
use crate::pure::decode::{DecodeEnd, Notices, Record};
use crate::pure::finding::{FileFinding, Finding, Kind, Severity};
use crate::pure::format::packet_time_ns;

/// What kind of thing a timeline lane holds.
pub const LANE_PACKET: &str = "packet";
pub const LANE_OTHER: &str = "other";
pub const LANE_LOG: &str = "log";

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
    /// The parsed header, if the logged item is one space packet.
    pub header: Option<PrimaryHeader>,
    /// False for a command taken as a packet although its length field
    /// does not give its size: see [`logged_header`].
    pub length_ok: bool,
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

/// The header of an item a log keeps under a name, and whether the header's
/// length field gives the item's size.
///
/// Such a log records each item's size itself, so the packet's own length
/// field is not needed to find where it ends, and ground systems send
/// commands whose length field is wrong: COSMOS writes whatever default the
/// command's definition gives it, which has been 0. So a command is still
/// taken as a packet when its length field claims fewer bytes than are
/// there. That is all that is let through: telemetry, a segmented packet,
/// a field that claims too much, or an item with no name must match exactly,
/// since one logged item in eight starts with the three zero bits of a
/// version 0 header by chance.
pub fn logged_header(payload: &[u8], named: bool) -> Option<(PrimaryHeader, bool)> {
    let h = PrimaryHeader::parse(payload).filter(|h| h.version == 0)?;
    if h.total_len() == payload.len() {
        return Some((h, true));
    }
    let loose = named
        && h.packet_type == PacketType::Command
        && h.seq_flags == SeqFlags::Unsegmented
        && h.total_len() < payload.len();
    loose.then_some((h, false))
}

/// Message for commands taken as packets despite their length field.
pub fn wrong_length_message(count: u64) -> String {
    let (commands, have, their) = if count == 1 {
        ("command", "has", "its")
    } else {
        ("commands", "have", "their")
    };
    format!(
        "{count} {commands} {have} a length field that does not match {their} size; \
         the size the log recorded is used"
    )
}

/// Builds the row for one record. `clock_offset_ns` is the correction for
/// the logging host's clock and applies to the receive time only.
pub fn packet_row(
    idx: u64,
    record: &Record,
    time: Option<&ResolvedTime>,
    clock_offset_ns: i64,
) -> PacketRow {
    let found = logged_header(&record.payload, record.label.is_some());
    let header = found.map(|(h, _)| h);
    let packet_ns = match (&header, time) {
        (Some(h), Some(rule)) if rule.applies(h) => packet_time_ns(rule, &record.payload),
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
        length_ok: found.is_none_or(|(_, ok)| ok),
        // Stored as the same 64 bits, reinterpreted as signed.
        sum: fnv1a(&record.payload) as i64,
        label: record.label.clone(),
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

/// The findings for one packet file that no check of packets in order
/// makes: the continuity report, what the decoder gave up on, how the read
/// ended, how many commands per stream had a wrong length field, and how
/// many logged items were not space packets. In that order, which is the
/// order they are stored in.
pub fn file_findings(
    report: &Report,
    notices: &Notices,
    end: Option<&DecodeEnd>,
    wrong_length: &[(StreamKey, u64)],
    non_packets: u64,
) -> Vec<FileFinding> {
    let in_stream = |key: StreamKey| Some(LaneKey::stream(key));
    let mut found: Vec<FileFinding> = report
        .findings
        .iter()
        .map(|f| f.finding().map_lane(in_stream))
        .collect();
    found.extend(notices.list.iter().map(|notice| notice.finding()));
    if notices.more > 0 {
        found.push(Finding::file(
            Severity::Info,
            Kind::Suppressed,
            format!("{} more losses in this file are not listed", notices.more),
        ));
    }
    if let Some(end) = end {
        let kind = match end {
            DecodeEnd::Truncated { .. } => Kind::Truncated,
            DecodeEnd::Error(_) => Kind::Unreadable,
        };
        found.push(Finding::file(Severity::Problem, kind, end.to_string()));
    }
    found.extend(wrong_length.iter().map(|&(key, count)| Finding {
        lane: in_stream(key),
        packet: None,
        severity: Severity::Info,
        kind: Kind::LengthField,
        message: wrong_length_message(count),
    }));
    if non_packets > 0 {
        found.push(Finding {
            lane: Some(LaneKey::other()),
            packet: None,
            severity: Severity::Info,
            kind: Kind::NonPacket,
            message: non_packet_message(non_packets),
        });
    }
    found
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
    fn a_named_command_may_have_a_short_length_field() {
        use crate::pure::synth::cosmos_cmd;
        // As a real COSMOS command log has them: length field 0.
        let command = cosmos_cmd(999, 0, 1, &[0, 7, 0x3F, 0x80, 0, 0, 0xAB, 0, 0, 0, 0]);
        let row = packet_row(0, &record(command.clone()), None, 0);
        assert_eq!(row.header.unwrap().apid, 999);
        assert!(!row.length_ok);
        assert_eq!(row.lane().ptype, 1);
        assert_eq!(row.length, 19);

        let not_packets = [
            // The same bytes from a log that does not name its items.
            (command.clone(), false),
            // Telemetry.
            (
                command
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| if i == 0 { b & !0x10 } else { b })
                    .collect(),
                true,
            ),
            // A length field that claims more than is there.
            (cosmos_cmd(999, 40, 1, &[0; 11]), true),
            // Not unsegmented.
            (
                command
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| if i == 2 { b & 0x3F } else { b })
                    .collect(),
                true,
            ),
            // What COSMOS logs when it cannot identify a packet, and the
            // start of its metadata packet.
            (vec![0; 10], true),
            (vec![1, b'0', b'a', b'1', b'b', b'2', b'c', b'3'], true),
            (vec![0x10, 0x01, 0xC0], true),
        ];
        for (payload, named) in not_packets {
            assert!(logged_header(&payload, named).is_none(), "{payload:02x?}");
        }
        // A right length field is right whoever logged it.
        let exact = cosmos_cmd(999, 12, 1, &[0; 11]);
        assert_eq!(logged_header(&exact, false).map(|(_, ok)| ok), Some(true));
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

        // Unless the rule says the flag is not to be trusted, which then
        // holds for telemetry only.
        let rule =
            Config::parse("[packet_time]\ncode = \"unix\"\nrequire_secondary_header = false")
                .unwrap()
                .resolved_time()
                .unwrap();
        let mut plain = packet(0x1A3, 0, &[0, 0, 0, 9, 0, 0, 0, 5]);
        assert_eq!(
            packet_row(0, &record(plain.clone()), Some(&rule), 0).packet_ns,
            Some(9_000_005_000)
        );
        plain[0] |= 0x10;
        assert_eq!(
            packet_row(0, &record(plain), Some(&rule), 0).packet_ns,
            None
        );
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
        let key = StreamKey {
            apid: 999,
            packet_type: PacketType::Command,
        };
        let rows = file_findings(
            &checker.finish(),
            &Notices::default(),
            Some(&end),
            &[(key, 2)],
            3,
        );
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[2].kind, Kind::LengthField);
        assert_eq!(rows[2].severity, Severity::Info);
        assert_eq!(rows[2].lane.unwrap().apid, 999);
        assert_eq!(
            rows[2].message,
            "2 commands have a length field that does not match their size; \
             the size the log recorded is used"
        );
        let rows = [&rows[0], &rows[1], &rows[3]];
        assert_eq!(rows[0].kind, Kind::Gap);
        assert_eq!(rows[0].packet, Some(6));
        assert_eq!(rows[0].lane.unwrap().apid, 0x064);
        assert_eq!(
            rows[0].message,
            "3 packets missing (expected sequence count 3, got 6)"
        );
        assert_eq!(rows[1].kind, Kind::Unreadable);
        assert!(rows[1].lane.is_none());
        assert_eq!(rows[2].kind, Kind::NonPacket);
        assert_eq!(rows[2].severity, Severity::Info);
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
