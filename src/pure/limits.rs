//! Watches fields that have limits as a file's packets go by, and reports
//! when one leaves its yellow or red range.
//!
//! A field's state changes as COSMOS changes it: only after `persistence`
//! packets in a row disagree with the current state. Each change to a
//! state other than green is one finding, so a value that stays out of
//! limits for a thousand packets is reported once.

use std::collections::HashMap;

use crate::pure::config::{LimitState, PacketDef};
use crate::pure::finding::{Finding, Kind, Severity};
use crate::pure::format::engineering;

/// Changes reported per field before the rest are only counted.
const MAX_PER_FIELD: u32 = 20;

/// What this check reports, all of kind [`Kind::Limit`]. `lane` is whatever
/// the caller uses to say where the packet belongs. `packet` is the packet
/// that settled the new state, or `None` for the closing count of changes
/// not listed. Red is a problem; yellow is a note.
pub type LimitFinding<L> = Finding<L>;

struct Watch<L> {
    state: LimitState,
    /// Packets in a row that disagreed with `state`.
    disagreeing: u32,
    reported: u32,
    unlisted: u64,
    name: String,
    lane: L,
}

pub struct LimitChecker<L> {
    /// Keyed by which definition and which of its fields.
    watches: HashMap<(usize, usize), Watch<L>>,
    findings: Vec<LimitFinding<L>>,
}

impl<L: Clone> Default for LimitChecker<L> {
    fn default() -> Self {
        Self {
            watches: HashMap::new(),
            findings: Vec::new(),
        }
    }
}

impl<L: Clone> LimitChecker<L> {
    /// `def_id` tells definitions apart; any number unique to `def` will do.
    pub fn observe(
        &mut self,
        packet_index: u64,
        def_id: usize,
        def: &PacketDef,
        packet: &[u8],
        lane: &L,
    ) {
        for (i, field) in def.fields.iter().enumerate() {
            if field.limits.is_none() {
                continue;
            }
            if let Some(value) = engineering(field, packet) {
                self.observe_value(packet_index, def_id, def, i, value, lane);
            }
        }
    }

    /// Takes the engineering value of field `i` of `def`, already read
    /// from the packet. A field with no limits is passed over.
    pub fn observe_value(
        &mut self,
        packet_index: u64,
        def_id: usize,
        def: &PacketDef,
        i: usize,
        value: f64,
        lane: &L,
    ) {
        let field = &def.fields[i];
        let Some(limits) = field.limits else { return };
        let watch = self.watches.entry((def_id, i)).or_insert_with(|| Watch {
            state: LimitState::Green,
            disagreeing: 0,
            reported: 0,
            unlisted: 0,
            name: format!("{} {}", def.name, field.name),
            lane: lane.clone(),
        });
        let now = limits.state(value);
        if now == watch.state {
            watch.disagreeing = 0;
            return;
        }
        watch.disagreeing += 1;
        if watch.disagreeing < limits.persistence {
            return;
        }
        watch.state = now;
        watch.disagreeing = 0;
        if now == LimitState::Green {
            return;
        }
        if watch.reported >= MAX_PER_FIELD {
            watch.unlisted += 1;
            return;
        }
        watch.reported += 1;
        let limit = match now {
            LimitState::RedLow => limits.red_low,
            LimitState::YellowLow => limits.yellow_low,
            LimitState::YellowHigh => limits.yellow_high,
            _ => limits.red_high,
        };
        let unit = if field.unit.is_empty() {
            String::new()
        } else {
            format!(" {}", field.unit)
        };
        self.findings.push(Finding {
            lane: lane.clone(),
            packet: Some(packet_index),
            severity: Severity::problem_if(now.is_red()),
            kind: Kind::Limit,
            message: format!(
                "{} went {}: {value}{unit} (limit {limit})",
                watch.name,
                now.name()
            ),
        });
    }

    /// The findings in the order they arose, then one line per field for
    /// changes that were not listed.
    pub fn finish(mut self) -> Vec<LimitFinding<L>> {
        let mut rest: Vec<&Watch<L>> = self.watches.values().filter(|w| w.unlisted > 0).collect();
        rest.sort_by(|a, b| a.name.cmp(&b.name));
        for watch in rest {
            self.findings.push(Finding {
                lane: watch.lane.clone(),
                packet: None,
                severity: Severity::Info,
                kind: Kind::Limit,
                message: format!(
                    "{}: {} more limit changes are not listed",
                    watch.name, watch.unlisted
                ),
            });
        }
        self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::config::Config;

    fn def(persistence: u32) -> PacketDef {
        let text = format!(
            "[[packet]]\napid = 1\nname = \"HK\"\n[[packet.field]]\nname = \"TEMP\"\nbit_offset = 0\nbit_length = 16\nunit = \"C\"\npoly = [-100.0, 0.5]\nlimits = {{ red_low = -80, yellow_low = -70, yellow_high = 60, red_high = 80, persistence = {persistence} }}\n[[packet.field]]\nname = \"FREE\"\nbit_offset = 16\nbit_length = 8\n"
        );
        Config::parse(&text).unwrap().packets.remove(0)
    }

    /// Feeds engineering temperatures; the raw value is (t + 100) * 2.
    fn run(def: &PacketDef, temps: &[f64]) -> Vec<LimitFinding<u8>> {
        let mut checker = LimitChecker::default();
        for (i, t) in temps.iter().enumerate() {
            let raw = ((t + 100.0) * 2.0) as u16;
            let mut packet = raw.to_be_bytes().to_vec();
            packet.push(0);
            checker.observe(i as u64, 0, def, &packet, &7u8);
        }
        checker.finish()
    }

    #[test]
    fn one_finding_per_excursion() {
        let got = run(
            &def(1),
            &[20.0, 61.0, 62.0, 63.0, 85.0, 86.0, 20.0, -75.0, -90.0, 0.0],
        );
        let lines: Vec<(Option<u64>, bool, &str)> = got
            .iter()
            .map(|f| (f.packet, f.is_problem(), f.message.as_str()))
            .collect();
        assert_eq!(
            lines,
            [
                (Some(1), false, "HK TEMP went yellow high: 61 C (limit 60)"),
                (Some(4), true, "HK TEMP went red high: 85 C (limit 80)"),
                (Some(7), false, "HK TEMP went yellow low: -75 C (limit -70)"),
                (Some(8), true, "HK TEMP went red low: -90 C (limit -80)"),
            ]
        );
        assert!(got.iter().all(|f| f.lane == 7));
    }

    #[test]
    fn the_edges_are_out_of_limits_as_cosmos_has_them() {
        let got = run(&def(1), &[60.0, 20.0, 80.0, 20.0, -70.0, 20.0, -80.0]);
        let states: Vec<&str> = got
            .iter()
            .map(|f| {
                f.message
                    .split(" went ")
                    .nth(1)
                    .unwrap()
                    .split(':')
                    .next()
                    .unwrap()
            })
            .collect();
        assert_eq!(states, ["yellow high", "red high", "yellow low", "red low"]);
    }

    #[test]
    fn persistence_ignores_a_sample_that_does_not_last() {
        let def = def(3);
        // One and two odd samples are not enough; the third in a row is.
        assert_eq!(run(&def, &[20.0, 90.0, 20.0, 90.0, 90.0, 20.0]).len(), 0);
        let got = run(&def, &[20.0, 90.0, 90.0, 90.0, 90.0]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].packet, Some(3));
        // And going back to green takes as long, so a dip does not re-arm it.
        assert_eq!(
            run(&def, &[90.0, 90.0, 90.0, 20.0, 90.0, 90.0, 90.0]).len(),
            1
        );
    }

    #[test]
    fn a_field_that_flaps_is_capped_and_counted() {
        let temps: Vec<f64> = (0..100)
            .map(|i| if i % 2 == 0 { 90.0 } else { 20.0 })
            .collect();
        let got = run(&def(1), &temps);
        assert_eq!(got.len(), MAX_PER_FIELD as usize + 1);
        let last = got.last().unwrap();
        assert_eq!(last.packet, None);
        assert_eq!(
            last.message,
            "HK TEMP: 30 more limit changes are not listed"
        );
    }

    #[test]
    fn a_packet_too_short_for_the_field_is_not_a_limit_change() {
        let def = def(1);
        let mut checker = LimitChecker::default();
        checker.observe(0, 0, &def, &[0x01], &0u8);
        assert!(checker.finish().is_empty());
    }
}
