//! Everything that is worked out about one packet file as its records go
//! by: each record's row, the values kept from it, and every check that
//! looks at packets one after another.
//!
//! The shell reads the file and decides what to do with the answers (store
//! them, print them). It makes none of them itself, so `packetlane check`
//! and the store cannot come to disagree about a file.
//!
//! Feed one [`FileCheck`] per file: [`FileCheck::observe`] for each record
//! in order, then [`FileCheck::finish`].

use std::collections::BTreeMap;

use crate::pure::config::{Config, PacketDef, ResolvedTime, SourceInfo};
use crate::pure::continuity::{Checker, Report, StreamKey};
use crate::pure::decode::{DecodeEnd, Notices, Record};
use crate::pure::finding::FileFinding;
use crate::pure::format::kept_values;
use crate::pure::ingest::{LaneKey, PacketRow, file_findings, packet_row};
use crate::pure::limits::{LimitChecker, LimitFinding};
use crate::pure::order::{OrderChecker, OrderFinding};

/// One value kept from a packet, for the `field_values` table.
#[derive(Debug, Clone, PartialEq)]
pub struct KeptValue<'a> {
    /// The name of the packet's definition.
    pub packet: &'a str,
    pub field: &'a str,
    /// The engineering value, where the field is a number.
    pub num: Option<f64>,
    /// The value's label, a text field's content, or an array's elements.
    pub text: Option<String>,
}

/// What one record came to.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen<'a> {
    pub row: PacketRow,
    /// Empty unless the record's definition marks fields `keep`.
    pub values: Vec<KeptValue<'a>>,
}

/// The checks on one file, in progress.
pub struct FileCheck<'a> {
    config: &'a Config,
    time: Option<ResolvedTime>,
    clock_offset_ns: i64,
    /// False if no definition has limits or kept fields. Most runs have
    /// none; then there is no need to look one up for every packet.
    watched: bool,
    continuity: Checker,
    order: OrderChecker,
    limits: LimitChecker<LaneKey>,
    records: u64,
    packets: u64,
    wrong_length: BTreeMap<StreamKey, u64>,
}

/// What was found in one file, once all of it has been seen.
#[derive(Debug)]
pub struct FileReport {
    /// Every logged item, space packet or not.
    pub records: u64,
    /// Those that are space packets.
    pub packets: u64,
    /// Commands taken as packets although their length field does not give
    /// their size, per stream. See `ingest::logged_header`.
    pub wrong_length: Vec<(StreamKey, u64)>,
    pub continuity: Report,
    pub order: Vec<OrderFinding>,
    pub limits: Vec<LimitFinding<LaneKey>>,
}

impl<'a> FileCheck<'a> {
    /// `source` is what the configuration says about the host that logged
    /// the file: its clock correction applies to receive times.
    pub fn new(config: &'a Config, source: &SourceInfo) -> Self {
        Self {
            config,
            time: config.resolved_time(),
            clock_offset_ns: source.clock_offset_ns,
            watched: config
                .packets
                .iter()
                .any(|d| d.fields.iter().any(|f| f.limits.is_some() || f.keep)),
            continuity: Checker::new(),
            order: OrderChecker::new(),
            limits: LimitChecker::default(),
            records: 0,
            packets: 0,
            wrong_length: BTreeMap::new(),
        }
    }

    /// Takes the next record of the file. The row's `idx` is the record's
    /// place in the file, counting from 0 and counting every record.
    pub fn observe(&mut self, record: &Record) -> Seen<'a> {
        let index = self.records;
        self.records += 1;
        let row = packet_row(index, record, self.time.as_ref(), self.clock_offset_ns);
        let def: Option<&'a PacketDef> = match self.watched {
            true => self
                .config
                .packet_for(record.label.as_deref(), row.header.as_ref()),
            false => None,
        };
        if let Some(def) = def.filter(|d| d.fields.iter().any(|f| f.limits.is_some())) {
            // The definition's address tells it apart from the others.
            let id = std::ptr::from_ref(def) as usize;
            self.limits
                .observe(index, id, def, &record.payload, &row.lane());
        }
        if let Some(header) = &row.header {
            self.packets += 1;
            self.continuity.observe_at(index, header, record.offset);
            self.order.observe(index, header, row.packet_ns);
            if !row.length_ok {
                let key = StreamKey {
                    apid: header.apid,
                    packet_type: header.packet_type,
                };
                *self.wrong_length.entry(key).or_default() += 1;
            }
        }
        let values = match def.filter(|d| d.fields.iter().any(|f| f.keep)) {
            Some(def) => kept_values(def, &record.payload)
                .into_iter()
                .map(|(field, num, text)| KeptValue {
                    packet: &def.name,
                    field,
                    num,
                    text,
                })
                .collect(),
            None => Vec::new(),
        };
        Seen { row, values }
    }

    pub fn finish(self) -> FileReport {
        FileReport {
            records: self.records,
            packets: self.packets,
            wrong_length: self.wrong_length.into_iter().collect(),
            continuity: self.continuity.finish(),
            order: self.order.finish(),
            limits: self.limits.finish(),
        }
    }
}

impl FileReport {
    /// Logged items that are not space packets.
    pub fn non_packets(&self) -> u64 {
        self.records - self.packets
    }

    /// Every finding for the file, in the order they are stored: sequence
    /// counts, what the decoder gave up on (`notices`) and how the read
    /// ended (`end`), length fields, items that are not packets, then
    /// segment and time order, then limits.
    pub fn findings(&self, notices: &Notices, end: Option<&DecodeEnd>) -> Vec<FileFinding> {
        let mut found = file_findings(
            &self.continuity,
            notices,
            end,
            &self.wrong_length,
            self.non_packets(),
        );
        let in_stream = |key| Some(LaneKey::stream(key));
        found.extend(self.order.iter().map(|f| f.clone().map_lane(in_stream)));
        found.extend(self.limits.iter().map(|f| f.clone().map_lane(Some)));
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::{DecodeError, Loss, Notice};
    use crate::pure::ingest::{LANE_OTHER, LANE_PACKET};
    use crate::pure::synth::{cosmos_cmd, cosmos_tlm, packet};

    const CONFIG: &str = r#"
[[source]]
path = "gse/"
name = "gse"
clock_offset_ms = 250

[packet_time]
code = "unix"
require_secondary_header = false

[[packet]]
apid = 2
label = "INST ADCS"
name = "ADCS"
  [[packet.field]]
  name = "TEMP"
  bit_offset = 128
  bit_length = 8
  unit = "C"
  keep = true
  limits = { red_low = -1, yellow_low = 5, yellow_high = 100, red_high = 130 }
  [[packet.field]]
  name = "SPARE"
  bit_offset = 136
  bit_length = 8
"#;

    fn record(offset: u64, label: Option<&str>, payload: Vec<u8>) -> Record {
        Record {
            offset,
            receive_time_ns: Some(5_000_000_000),
            label: label.map(str::to_string),
            payload,
        }
    }

    /// One reading, as COSMOS's example target would send it.
    fn adcs(seq: u16, time_ns: i64, temp: u8) -> Record {
        let payload = cosmos_tlm(2, seq, time_ns, 1, &[temp, 0]);
        record(100 * u64::from(seq), Some("INST ADCS"), payload)
    }

    #[test]
    fn a_record_becomes_a_row_and_its_kept_values() {
        let config = Config::parse(CONFIG).unwrap();
        let mut check = FileCheck::new(&config, &config.source_for("gse/tlm.bin"));

        let seen = check.observe(&record(64, Some("SYSTEM META"), vec![1, 2, 3]));
        assert_eq!(seen.row.idx, 0);
        assert!(seen.row.header.is_none());
        assert_eq!(seen.row.lane().kind, LANE_OTHER);
        assert!(seen.values.is_empty());

        let seen = check.observe(&adcs(1, 4_000_000_000, 20));
        assert_eq!(seen.row.idx, 1);
        assert_eq!(seen.row.lane().kind, LANE_PACKET);
        assert_eq!(seen.row.lane().apid, 2);
        // The time in the packet as the configuration says to read it; the
        // host's clock correction on the receive time only.
        assert_eq!(seen.row.packet_ns, Some(4_000_000_000));
        assert_eq!(seen.row.receive_ns, Some(5_250_000_000));
        // The kept field and not the other.
        assert_eq!(
            seen.values,
            [KeptValue {
                packet: "ADCS",
                field: "TEMP",
                num: Some(20.0),
                text: None,
            }]
        );

        // A packet no definition names is still a row, with nothing kept.
        let seen = check.observe(&record(900, None, packet(7, 0, &[0])));
        assert_eq!(seen.row.lane().apid, 7);
        assert!(seen.values.is_empty());

        let report = check.finish();
        assert_eq!((report.records, report.packets), (3, 2));
        assert_eq!(report.non_packets(), 1);
        assert!(report.findings(&Notices::default(), None).len() == 1);
    }

    #[test]
    fn with_nothing_configured_every_check_that_needs_no_names_still_runs() {
        let config = Config::default();
        let mut check = FileCheck::new(&config, &config.source_for(""));
        for seq in [0u16, 1, 2, 6, 7] {
            let seen = check.observe(&record(0, None, packet(100, seq, &[0])));
            assert_eq!(seen.row.packet_ns, None);
            assert!(seen.values.is_empty());
        }
        // COSMOS-style commands: one count on all, a length field of 0.
        for _ in 0..4 {
            check.observe(&record(0, Some("INST ABORT"), cosmos_cmd(999, 0, 2, &[])));
        }
        let report = check.finish();
        assert_eq!(report.packets, 9);
        assert_eq!(report.wrong_length.len(), 1);
        assert_eq!(report.wrong_length[0].0.apid, 999);
        assert_eq!(report.wrong_length[0].1, 4);
        let kinds: Vec<&str> = report
            .findings(&Notices::default(), None)
            .iter()
            .map(|r| r.kind.name())
            .collect();
        assert_eq!(kinds, ["gap", "constant_count", "length_field"]);
    }

    #[test]
    fn findings_come_out_in_the_order_they_are_stored() {
        let config = Config::parse(CONFIG).unwrap();
        let mut check = FileCheck::new(&config, &config.source_for("gse/tlm.bin"));
        let second = 1_000_000_000i64;
        check.observe(&record(64, Some("SYSTEM META"), vec![1, 2, 3]));
        check.observe(&adcs(1, 10 * second, 20));
        check.observe(&adcs(2, 11 * second, 20));
        // Time steps back, and the temperature goes past its red limit.
        check.observe(&adcs(3, 9 * second, 140));
        // Two packets lost.
        check.observe(&adcs(6, 12 * second, 140));
        check.observe(&record(0, Some("INST ABORT"), cosmos_cmd(999, 0, 2, &[])));
        let report = check.finish();

        let mut notices = Notices::default();
        notices.push(Notice {
            offset: 40,
            loss: Loss::Junk { bytes: 3 },
        });
        let end = DecodeEnd::Error(DecodeError::Implausible {
            offset: 99,
            reason: "test",
        });
        let rows = report.findings(&notices, Some(&end));
        let got: Vec<(&str, &str, Option<u64>)> = rows
            .iter()
            .map(|r| (r.kind.name(), r.severity.as_str(), r.packet))
            .collect();
        assert_eq!(
            got,
            [
                ("gap", "problem", Some(4)),
                ("junk", "problem", None),
                ("unreadable", "problem", None),
                ("length_field", "info", None),
                ("non_packet", "info", None),
                ("time_back", "info", Some(3)),
                ("limit", "problem", Some(3)),
            ],
            "{rows:#?}"
        );
        // Each on the lane of its own stream; the file's on none.
        assert_eq!(rows[0].lane.unwrap().apid, 2);
        assert!(rows[1].lane.is_none());
        assert_eq!(rows[3].lane.unwrap().apid, 999);
        assert_eq!(rows[4].lane.unwrap().kind, LANE_OTHER);
        assert_eq!(rows[6].lane.unwrap().apid, 2);
    }
}
