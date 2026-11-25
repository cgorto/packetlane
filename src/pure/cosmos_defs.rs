//! Turns COSMOS 4 packet definition files (`cmd_tlm/*.txt`) into this
//! tool's `[[packet]]` configuration.
//!
//! COSMOS describes far more than this tool shows, so the import is partial
//! on purpose and says what it left out:
//!
//! - Every packet is labelled `TARGET PACKET`, the name COSMOS logs it
//!   under, so a definition finds its packets in a COSMOS log whatever
//!   COSMOS identified them by. The APID is added when the packet has one:
//!   an identifier item at bit 5, 11 bits, unsigned. Outside COSMOS logs
//!   there is no name to go by, and a packet is only decoded if its APID
//!   and type belong to one definition.
//! - Items become fields when they are fixed-size and at a known position.
//!   Little-endian numbers must be 16, 32 or 64 bits on a byte boundary;
//!   arrays must be of numbers. Derived items, sizes of zero or less,
//!   offsets from the end and little-endian bit fields are skipped.
//! - `STATE` becomes a label, `UNITS` the unit, `POLY_READ_CONVERSION` the
//!   field's polynomial and the default, enabled `LIMITS` its limits. Other
//!   conversions, other limits sets, green limits and format strings are
//!   dropped.
//! - ERB (`<% ... %>`) is not run. After one, the position of appended items
//!   is unknown, so they are skipped.

use std::collections::BTreeMap;

use crate::pure::config::{ByteOrder, FieldDef, FieldKind, Kind, Limits, MAX_COUNT, PacketDef};

#[derive(Debug, Default, PartialEq)]
pub struct Import {
    pub packets: Vec<PacketDef>,
    /// What was skipped and why, each starting `file:line:`.
    pub warnings: Vec<String>,
}

/// Splits a line the way COSMOS does: on spaces, keeping quoted text whole,
/// stopping at a `#` comment. Quotes are removed.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut token = String::new();
        if c == '"' || c == '\'' {
            chars.next();
            while let Some(d) = chars.next() {
                match d {
                    '\\' => token.extend(chars.next()),
                    d if d == c => break,
                    d => token.push(d),
                }
            }
        } else {
            while let Some(&d) = chars.peek().filter(|d| !d.is_whitespace()) {
                token.push(d);
                chars.next();
            }
            if token.starts_with('#') && !token.starts_with("#{") {
                break;
            }
        }
        out.push(token);
    }
    out
}

/// A whole number as COSMOS writes them: decimal or `0x` hex, `_` allowed.
fn integer(text: &str) -> Option<i64> {
    let text = text.replace('_', "");
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.as_str()),
    };
    let value = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => i64::from_str_radix(hex, 16).ok()?,
        None => digits.parse().ok()?,
    };
    Some(if negative { -value } else { value })
}

struct Building {
    def: PacketDef,
    line: usize,
    little_endian: bool,
    apid: Option<u16>,
    /// Where an appended item goes, in bits. `None` once it cannot be known.
    end: Option<u64>,
    /// The field that `STATE` and `UNITS` lines apply to, if it was kept.
    current: Option<usize>,
    conversions: usize,
}

struct Importer<'a> {
    file: &'a str,
    out: Import,
    building: Option<Building>,
    /// Inside GENERIC_..._CONVERSION_START/END: lines of Ruby, not keywords.
    in_ruby: bool,
}

impl Importer<'_> {
    fn warn(&mut self, line: usize, text: impl AsRef<str>) {
        self.out
            .warnings
            .push(format!("{}:{line}: {}", self.file, text.as_ref()));
    }

    fn finish(&mut self) {
        let Some(b) = self.building.take() else {
            return;
        };
        let name = b.def.name.clone();
        if b.conversions > 0 {
            self.warn(
                b.line,
                format!(
                    "{name}: {} conversions dropped; values are shown raw",
                    b.conversions
                ),
            );
        }
        let same = |p: &PacketDef| p.label == b.def.label && p.kind == b.def.kind;
        if self.out.packets.iter().any(same) {
            self.warn(b.line, format!("{name}: skipped, it is defined twice"));
            return;
        }
        self.out.packets.push(PacketDef {
            apid: b.apid,
            ..b.def
        });
    }

    fn line(&mut self, number: usize, raw: &str) {
        if self.in_ruby {
            self.in_ruby = !raw.to_ascii_uppercase().contains("_CONVERSION_END");
            return;
        }
        if raw.contains("<%") {
            self.warn(
                number,
                "ERB is not run; appended items after it are skipped",
            );
            if let Some(b) = &mut self.building {
                b.end = None;
                b.current = None;
            }
            return;
        }
        let words = tokens(raw);
        let Some((keyword, params)) = words.split_first() else {
            return;
        };
        let keyword = keyword.to_ascii_uppercase();
        match keyword.as_str() {
            "TELEMETRY" | "COMMAND" => {
                self.finish();
                let [target, packet, endian, rest @ ..] = params else {
                    return self.warn(
                        number,
                        format!("{keyword} needs a target, a name and an endianness"),
                    );
                };
                let name = format!("{} {}", target.to_uppercase(), packet.to_uppercase());
                self.building = Some(Building {
                    def: PacketDef {
                        apid: None,
                        label: Some(name.clone()),
                        kind: if keyword == "COMMAND" {
                            Kind::Tc
                        } else {
                            Kind::Tm
                        },
                        name,
                        description: rest.first().cloned().unwrap_or_default(),
                        fields: Vec::new(),
                    },
                    line: number,
                    little_endian: endian.eq_ignore_ascii_case("LITTLE_ENDIAN"),
                    apid: None,
                    end: Some(0),
                    current: None,
                    conversions: 0,
                });
            }
            "SELECT_TELEMETRY" | "SELECT_COMMAND" => {
                self.finish();
                self.warn(
                    number,
                    format!("{keyword} is not supported; its changes are skipped"),
                );
            }
            "MACRO_APPEND_START" | "MACRO_APPEND_END" => {
                if let Some(b) = &mut self.building {
                    b.end = None;
                    b.current = None;
                }
                self.warn(
                    number,
                    "macros are not expanded; appended items after it are skipped",
                );
            }
            "GENERIC_READ_CONVERSION_START" | "GENERIC_WRITE_CONVERSION_START" => {
                self.in_ruby = true;
                if let Some(b) = &mut self.building {
                    b.conversions += usize::from(keyword.contains("READ"));
                }
            }
            "READ_CONVERSION" | "SEG_POLY_READ_CONVERSION" => {
                if let Some(b) = &mut self.building {
                    b.conversions += 1;
                }
            }
            "POLY_READ_CONVERSION" => {
                let poly: Option<Vec<f64>> = params.iter().map(|p| p.parse().ok()).collect();
                self.change_field(number, |field| field.poly = poly.unwrap_or_default());
            }
            "LIMITS" => {
                let numbers: Vec<f64> = params
                    .iter()
                    .skip(3)
                    .filter_map(|p| p.parse().ok())
                    .collect();
                let (Some(set), Some(persistence), Some(enabled), [rl, yl, yh, rh, ..]) = (
                    params.first(),
                    params.get(1).and_then(|p| p.parse().ok()),
                    params.get(2),
                    numbers.as_slice(),
                ) else {
                    return;
                };
                // One set of limits per field here: COSMOS's default set,
                // unless the definition switches it off.
                if set.eq_ignore_ascii_case("DEFAULT") && enabled.eq_ignore_ascii_case("ENABLED") {
                    let limits = Limits {
                        red_low: *rl,
                        yellow_low: *yl,
                        yellow_high: *yh,
                        red_high: *rh,
                        persistence,
                    };
                    self.change_field(number, |field| field.limits = Some(limits));
                }
            }
            "STATE" => self.state(number, params),
            "UNITS" => {
                if let (Some(b), Some(unit)) = (&mut self.building, params.get(1))
                    && let Some(i) = b.current
                {
                    b.def.fields[i].unit = unit.clone();
                }
            }
            k if k.ends_with("ITEM") || k.ends_with("PARAMETER") => {
                if !k.starts_with("SELECT_") {
                    self.item(number, k, params);
                } else if let Some(b) = &mut self.building {
                    b.current = None;
                }
            }
            _ => {}
        }
    }

    /// Applies a change to the field the line belongs to, unless the result
    /// is not a field this tool accepts; then says so and leaves it alone.
    fn change_field(&mut self, number: usize, change: impl FnOnce(&mut FieldDef)) {
        let Some(b) = &mut self.building else { return };
        let Some(i) = b.current else { return };
        let mut changed = b.def.fields[i].clone();
        change(&mut changed);
        match changed.validate() {
            Ok(()) => b.def.fields[i] = changed,
            Err(reason) => {
                let what = format!("{} {}", b.def.name, changed.name);
                self.warn(
                    number,
                    format!("{what}: conversion or limits skipped, {reason}"),
                );
            }
        }
    }

    fn state(&mut self, number: usize, params: &[String]) {
        let Some(b) = &mut self.building else { return };
        let (Some(i), [name, value, ..]) = (b.current, params) else {
            return;
        };
        let field = &mut b.def.fields[i];
        match integer(value) {
            Some(v) if matches!(field.kind, FieldKind::Uint | FieldKind::Int) => {
                field.labels.insert(v.to_string(), name.clone());
            }
            _ => {
                let item = field.name.clone();
                self.warn(
                    number,
                    format!("{item}: state {name} skipped, its value is not a whole number"),
                );
            }
        }
    }

    fn item(&mut self, number: usize, keyword: &str, params: &[String]) {
        let Some(mut b) = self.building.take() else {
            return self.warn(number, format!("{keyword} outside a packet"));
        };
        b.current = None;
        if let Err(reason) = self.add_item(&mut b, keyword, params) {
            let name = params.first().map_or("?", String::as_str);
            self.warn(number, format!("{} {name}: skipped, {reason}", b.def.name));
        }
        self.building = Some(b);
    }

    fn add_item(
        &mut self,
        b: &mut Building,
        keyword: &str,
        params: &[String],
    ) -> Result<(), String> {
        let append = keyword.starts_with("APPEND_");
        let array = keyword.contains("ARRAY");
        let id = keyword.contains("ID_");
        let parameter = keyword.ends_with("PARAMETER");
        let mut rest = params.iter();
        let mut next = |what: &str| rest.next().ok_or(format!("missing {what}"));

        let name = next("name")?.to_uppercase();
        let given_offset = match append {
            true => None,
            false => Some(integer(next("bit offset")?).ok_or("bit offset is not a number")?),
        };
        let size = integer(next("bit size")?).ok_or("bit size is not a number")?;
        let data_type = next("type")?.to_ascii_uppercase();
        let text = data_type == "STRING" || data_type == "BLOCK";
        // Commands carry minimum, maximum and default before the description;
        // text parameters only a default. The last of them is the ID value.
        let values = match (array, parameter, text, id) {
            (true, ..) => 1,
            (false, true, false, _) => 3,
            (false, true, true, _) => 1,
            (false, false, _, true) => 1,
            (false, false, _, false) => 0,
        };
        let mut last = None;
        for _ in 0..values {
            last = Some(next("value")?.clone());
        }
        let _description = rest.next();
        let little_endian = match rest.next() {
            Some(e) => e.eq_ignore_ascii_case("LITTLE_ENDIAN"),
            None => b.little_endian,
        };

        if data_type == "DERIVED" {
            return Err("derived items have no bits to show".into());
        }
        let total = if array {
            integer(last.as_deref().unwrap_or_default()).ok_or("array size is not a number")?
        } else {
            size
        };
        // Work out the position before deciding to keep the item, so that
        // the items appended after a skipped one still land in the right place.
        let offset = match given_offset {
            Some(o) if o < 0 => {
                return Err("offsets from the end of the packet are not supported".into());
            }
            Some(o) => o as u64,
            None => b.end.ok_or("its position is unknown")?,
        };
        if size <= 0 || total <= 0 {
            b.end = None;
            return Err("its size is not fixed".into());
        }
        let after = offset.checked_add(total as u64).ok_or("it is too large")?;
        b.end = b.end.map(|end| end.max(after));

        let count = if array {
            if text || total % size != 0 || total / size > i64::from(MAX_COUNT) {
                return Err(format!(
                    "only arrays of up to {MAX_COUNT} whole numbers are supported"
                ));
            }
            (total / size) as u32
        } else {
            1
        };
        let kind = match data_type.as_str() {
            "UINT" => FieldKind::Uint,
            "INT" => FieldKind::Int,
            "FLOAT" => FieldKind::Float,
            "STRING" => FieldKind::Ascii,
            "BLOCK" => FieldKind::Hex,
            other => return Err(format!("type {other} is not supported")),
        };
        // Byte order cannot matter for text, or for a number within one byte.
        let one_byte = match array {
            true => size == 8 && offset % 8 == 0,
            false => size <= 8 && offset / 8 == (after - 1) / 8,
        };
        let byte_order = if little_endian && !text && !one_byte {
            ByteOrder::Little
        } else {
            ByteOrder::Big
        };
        let field = FieldDef {
            name: name.clone(),
            bit_offset: u32::try_from(offset).map_err(|_| "it is too far into the packet")?,
            bit_length: u32::try_from(size).map_err(|_| "it is too large")?,
            kind,
            unit: String::new(),
            labels: BTreeMap::new(),
            byte_order,
            count,
            poly: Vec::new(),
            limits: None,
            keep: false,
        };
        field.validate()?;
        if id && kind == FieldKind::Uint && offset == 5 && size == 11 {
            match last.as_deref().and_then(integer) {
                Some(apid @ 0..=0x7FF) => b.apid = Some(apid as u16),
                _ => self.out.warnings.push(format!(
                    "{}: {} {name}: APID identifier value is not 0 to 2047",
                    self.file, b.def.name
                )),
            }
        }
        b.def.fields.push(field);
        b.current = Some(b.def.fields.len() - 1);
        Ok(())
    }
}

/// Imports every packet definition in `files`, given as (name, contents).
/// Packets from earlier files win when two claim the same APID and type.
pub fn import(files: &[(String, String)]) -> Import {
    let mut out = Import::default();
    for (name, text) in files {
        let mut importer = Importer {
            file: name,
            out,
            building: None,
            in_ruby: false,
        };
        // A line ending in a lone `&` continues on the next one.
        let mut pending = String::new();
        let mut started = 1;
        for (i, raw) in text.lines().enumerate() {
            if pending.is_empty() {
                started = i + 1;
            }
            match raw.trim_end().strip_suffix(" &") {
                Some(head) => {
                    pending.push_str(head);
                    pending.push(' ');
                }
                None => {
                    pending.push_str(raw);
                    importer.line(started, &pending);
                    pending.clear();
                }
            }
        }
        importer.finish();
        out = importer.out;
    }
    out
}

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Writes packet definitions as the `[[packet]]` tables of a config file.
pub fn to_toml(packets: &[PacketDef]) -> String {
    let mut out = String::new();
    for p in packets {
        out.push_str("[[packet]]\n");
        if let Some(apid) = p.apid {
            out.push_str(&format!("apid = {apid}\n"));
        }
        if let Some(label) = &p.label {
            out.push_str(&format!("label = {}\n", quoted(label)));
        }
        out.push_str(match p.kind {
            Kind::Tm => "type = \"tm\"\n",
            Kind::Tc => "type = \"tc\"\n",
        });
        out.push_str(&format!("name = {}\n", quoted(&p.name)));
        if !p.description.is_empty() {
            out.push_str(&format!("description = {}\n", quoted(&p.description)));
        }
        for f in &p.fields {
            out.push_str(&format!(
                "  [[packet.field]]\n  name = {}\n",
                quoted(&f.name)
            ));
            out.push_str(&format!(
                "  bit_offset = {}\n  bit_length = {}\n",
                f.bit_offset, f.bit_length
            ));
            let kind = match f.kind {
                FieldKind::Uint => "uint",
                FieldKind::Int => "int",
                FieldKind::Float => "float",
                FieldKind::Hex => "hex",
                FieldKind::Ascii => "ascii",
            };
            out.push_str(&format!("  kind = \"{kind}\"\n"));
            if f.byte_order == ByteOrder::Little {
                out.push_str("  byte_order = \"little\"\n");
            }
            if f.count > 1 {
                out.push_str(&format!("  count = {}\n", f.count));
            }
            if !f.unit.is_empty() {
                out.push_str(&format!("  unit = {}\n", quoted(&f.unit)));
            }
            if !f.poly.is_empty() {
                let poly: Vec<String> = f.poly.iter().map(|c| format!("{c:?}")).collect();
                out.push_str(&format!("  poly = [{}]\n", poly.join(", ")));
            }
            if let Some(l) = &f.limits {
                out.push_str(&format!(
                    "  limits = {{ red_low = {:?}, yellow_low = {:?}, yellow_high = {:?}, red_high = {:?}, persistence = {} }}\n",
                    l.red_low, l.yellow_low, l.yellow_high, l.red_high, l.persistence
                ));
            }
            if !f.labels.is_empty() {
                let labels: Vec<String> = f
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{} = {}", quoted(k), quoted(v)))
                    .collect();
                out.push_str(&format!("  labels = {{ {} }}\n", labels.join(", ")));
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::config::Config;

    fn run(text: &str) -> Import {
        import(&[("t.txt".to_string(), text.to_string())])
    }

    const HK: &str = r#"
# Housekeeping
TELEMETRY inst HEALTH_STATUS BIG_ENDIAN "Health and status"
  ITEM CCSDSVER 0 3 UINT "Version"
  ITEM CCSDSTYPE 3 1 UINT "Type"
    STATE TLM 0
    STATE CMD 1
  ITEM CCSDSSHF 4 1 UINT
  ID_ITEM CCSDSAPID 5 11 UINT 0x1A3 "APID"
  ITEM CCSDSSEQFLAGS 16 2 UINT
  ITEM CCSDSSEQCNT 18 14 UINT
  ITEM CCSDSLENGTH 32 16 UINT
  APPEND_ITEM TEMP1 16 UINT "Temperature #1"   # raw counts
    POLY_READ_CONVERSION -100.0 0.00305
    UNITS CELCIUS C
    LIMITS DEFAULT 1 ENABLED -80.0 -70.0 60.0 80.0
  APPEND_ITEM TEMP2 32 FLOAT "Temperature #2"
  APPEND_ARRAY_ITEM ARY 8 UINT 80 "Array data"
  APPEND_ITEM MODE 8 INT "Mode"
    STATE SAFE -1 RED
    STATE RUN 0x02
  APPEND_ITEM WORD 16 UINT "Little" LITTLE_ENDIAN
  APPEND_ITEM FLAG 8 UINT "One byte" LITTLE_ENDIAN
  ITEM CALC 0 0 DERIVED "Computed"
  APPEND_ITEM NOTE 64 STRING "Text"
  APPEND_ITEM REST 0 BLOCK "Everything else"
  APPEND_ITEM AFTER 8 UINT "Cannot be placed"
"#;

    #[test]
    fn imports_a_packet_and_says_what_it_left_out() {
        let got = run(HK);
        assert_eq!(got.packets.len(), 1);
        let p = &got.packets[0];
        assert_eq!((p.apid, p.kind), (Some(0x1A3), Kind::Tm));
        assert_eq!(p.label.as_deref(), Some("INST HEALTH_STATUS"));
        assert_eq!(p.name, "INST HEALTH_STATUS");
        assert_eq!(p.description, "Health and status");
        let field = |name: &str| p.fields.iter().find(|f| f.name == name);
        let at = |name: &str| field(name).map(|f| (f.bit_offset, f.bit_length, f.kind));

        assert_eq!(at("CCSDSAPID"), Some((5, 11, FieldKind::Uint)));
        assert_eq!(field("CCSDSTYPE").unwrap().labels["1"], "CMD");
        // Appended items start where the explicit ones end: bit 48.
        assert_eq!(at("TEMP1"), Some((48, 16, FieldKind::Uint)));
        assert_eq!(field("TEMP1").unwrap().unit, "C");
        assert_eq!(field("TEMP1").unwrap().poly, [-100.0, 0.00305]);
        let limits = field("TEMP1").unwrap().limits.unwrap();
        assert_eq!(
            (
                limits.red_low,
                limits.yellow_low,
                limits.yellow_high,
                limits.red_high,
                limits.persistence
            ),
            (-80.0, -70.0, 60.0, 80.0, 1)
        );
        assert_eq!(at("TEMP2"), Some((64, 32, FieldKind::Float)));
        // An array of ten bytes.
        assert_eq!(at("ARY"), Some((96, 8, FieldKind::Uint)));
        assert_eq!(field("ARY").unwrap().count, 10);
        assert_eq!(at("MODE"), Some((176, 8, FieldKind::Int)));
        assert_eq!(field("MODE").unwrap().labels["-1"], "SAFE");
        assert_eq!(field("MODE").unwrap().labels["2"], "RUN");
        // A little-endian word is kept as one; a single byte has no order.
        assert_eq!(at("WORD"), Some((184, 16, FieldKind::Uint)));
        assert_eq!(field("WORD").unwrap().byte_order, ByteOrder::Little);
        assert_eq!(field("FLAG").unwrap().byte_order, ByteOrder::Big);
        assert_eq!(at("FLAG"), Some((200, 8, FieldKind::Uint)));
        assert_eq!(at("CALC"), None);
        assert_eq!(at("NOTE"), Some((208, 64, FieldKind::Ascii)));
        // Nothing can be placed after an item with no fixed size.
        assert_eq!(at("REST"), None);
        assert_eq!(at("AFTER"), None);

        let all = got.warnings.join("\n");
        for needle in [
            "CALC: skipped, derived items have no bits to show",
            "REST: skipped, its size is not fixed",
            "AFTER: skipped, its position is unknown",
        ] {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
        assert_eq!(got.warnings.len(), 3, "{all}");
    }

    #[test]
    fn the_output_is_a_config_this_tool_accepts() {
        let got = run(HK);
        let toml = to_toml(&got.packets);
        let config = Config::parse(&toml).unwrap_or_else(|e| panic!("{e}\n{toml}"));
        assert_eq!(config.packets, got.packets);
        // Awkward text survives the trip.
        let odd = run(
            "TELEMETRY T P BIG_ENDIAN \"a \\\"quoted\\\" \\\\ name\"\n ID_ITEM A 5 11 UINT 7\n  STATE \"it's\" 7\n",
        );
        let config = Config::parse(&to_toml(&odd.packets)).unwrap();
        assert_eq!(config.packets, odd.packets);
        assert_eq!(config.packets[0].description, "a \"quoted\" \\ name");
    }

    #[test]
    fn commands_carry_their_values_before_the_description() {
        let got = run(r#"
COMMAND INST COLLECT BIG_ENDIAN "Start a collect"
  ID_PARAMETER CCSDSAPID 5 11 UINT 0 2047 99 "APID"
  PARAMETER TYPE 48 16 UINT 0 65535 0 "Collect type" LITTLE_ENDIAN
  APPEND_PARAMETER DURATION 32 FLOAT 0.0 10.0 1.0 "Seconds"
  APPEND_PARAMETER LABEL 32 STRING "ABCD" "Text"
  APPEND_ID_PARAMETER OPCODE 8 UINT 0 255 0xAB "Opcode"
"#);
        let p = &got.packets[0];
        assert_eq!(
            (p.apid, p.kind, p.name.as_str()),
            (Some(99), Kind::Tc, "INST COLLECT")
        );
        let names: Vec<&str> = p.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["CCSDSAPID", "TYPE", "DURATION", "LABEL", "OPCODE"]);
        assert_eq!(p.fields[1].byte_order, ByteOrder::Little);
        assert_eq!(p.fields[2].bit_offset, 64);
        assert_eq!(p.fields[4].bit_offset, 128);
        assert_eq!(got.warnings, [] as [String; 0]);
    }

    #[test]
    fn every_packet_is_kept_under_its_cosmos_name() {
        let got = import(&[
            (
                "a.txt".to_string(),
                "TELEMETRY A ONE BIG_ENDIAN\n ID_ITEM APID 5 11 UINT 5\nTELEMETRY A NOID BIG_ENDIAN\n ITEM X 0 8 UINT\n".to_string(),
            ),
            (
                "b.txt".to_string(),
                "TELEMETRY B SAME BIG_ENDIAN\n ID_ITEM APID 5 11 UINT 5\n ID_ITEM PKTID 48 8 UINT 2\nTELEMETRY a one BIG_ENDIAN\n".to_string(),
            ),
        ]);
        let keys: Vec<(Option<&str>, Option<u16>)> = got
            .packets
            .iter()
            .map(|p| (p.label.as_deref(), p.apid))
            .collect();
        // Two packets on APID 5, and one with no APID at all, are all kept.
        assert_eq!(
            keys,
            [
                (Some("A ONE"), Some(5)),
                (Some("A NOID"), None),
                (Some("B SAME"), Some(5))
            ]
        );
        assert_eq!(
            got.warnings,
            ["b.txt:4: A ONE: skipped, it is defined twice"]
        );
        let config = Config::parse(&to_toml(&got.packets)).unwrap();
        assert_eq!(config.packets, got.packets);
    }

    #[test]
    fn erb_and_ruby_are_not_run() {
        let got = run(r#"
TELEMETRY INST ERB BIG_ENDIAN "<%= @target_name %>"
TELEMETRY INST HK BIG_ENDIAN "Health"
  ID_ITEM CCSDSAPID 5 11 UINT 1
  <%= render "_ccsds_tlm.txt", locals: {apid: 1} %>
  APPEND_ITEM LOST 16 UINT "Position unknown"
  ITEM FIXED 96 8 UINT "Explicit offsets still work"
    GENERIC_READ_CONVERSION_START
      ITEM NOT_A_KEYWORD 0 8 UINT
      value * 2
    GENERIC_READ_CONVERSION_END
    STATE ON 1
"#);
        let p = &got.packets[0];
        let names: Vec<&str> = p.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["CCSDSAPID", "FIXED"]);
        assert_eq!(p.fields[1].labels["1"], "ON");
        let all = got.warnings.join("\n");
        assert!(all.contains("t.txt:2: ERB is not run"), "{all}");
        assert!(all.contains("t.txt:5: ERB is not run"), "{all}");
        assert!(
            all.contains("LOST: skipped, its position is unknown"),
            "{all}"
        );
    }

    #[test]
    fn arbitrary_text_does_not_panic() {
        let words = [
            "TELEMETRY",
            "APPEND_ITEM",
            "ID_ITEM",
            "ARRAY_ITEM",
            "PARAMETER",
            "STATE",
            "UNITS",
            "A",
            "5",
            "11",
            "-8",
            "0",
            "UINT",
            "STRING",
            "\"q",
            "'",
            "\\",
            "#",
            "&",
            "<%",
            "9999999999999999999",
            "0x",
            "LITTLE_ENDIAN",
            "\n",
            "\n",
            "DERIVED",
        ];
        let mut x = 0x2545F491u32;
        for _ in 0..300 {
            let mut text = String::new();
            for _ in 0..60 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                text.push_str(words[x as usize % words.len()]);
                text.push(' ');
            }
            let got = run(&text);
            let _ = Config::parse(&to_toml(&got.packets)).expect("always valid");
        }
    }
}
