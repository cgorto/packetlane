//! The configuration file: everything site or mission specific.
//!
//! It is TOML, every part is optional, and with no file at all the tool still
//! works: sources are named after the first folder in a file's path, text
//! logs are assumed to carry ISO timestamps in UTC, and packets are shown by
//! APID number.
//!
//! ```toml
//! [[source]]                 # name a host and correct its clock
//! path = "bench-a/"          # files whose path within the run starts with this
//! name = "bench-a"
//! utc_offset = "+00:00"      # timezone of this host's text logs
//! clock_offset_ms = 0        # added to this host's receive and log times
//!
//! [[log]]                    # how to find the timestamp in a text log
//! path = "bench-a/sim"       # files whose path within the run starts with this
//! pattern = '^\[(?P<epoch>\d+\.\d+)\]'
//! default_year = 2026        # only for patterns with no year
//!
//! [packet_time]              # where the time is in a packet's secondary header
//! code = "cuc"               # "cuc": seconds + binary fraction; "cds": days + ms of day
//! byte_offset = 6            # from the start of the packet
//! coarse_bytes = 4           # cuc
//! fine_bytes = 2             # cuc
//! epoch = "1958-01-01T00:00:00Z"
//! subtract_seconds = 0       # for example the difference between the timescale and UTC
//!
//! [[packet]]                 # name a packet type and its fields
//! apid = 419               # decimal or hex (0x1A3)
//! type = "tm"                # "tm" (default) or "tc"
//! name = "PAYLOAD_SCIENCE"
//!   [[packet.field]]
//!   name = "MODE"
//!   bit_offset = 96          # from the start of the packet; bit 0 is the top bit of byte 0
//!   bit_length = 8
//!   kind = "uint"            # uint (default), int, float, hex, ascii
//!   unit = ""
//!   labels = { "0" = "IDLE", "1" = "OBSERVE" }
//! ```

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::pure::ccsds::PacketType;
use crate::pure::textlog::LogFormat;
use crate::pure::time::{NS_PER_SEC, parse_iso, parse_utc_offset};

/// Longest `hex` or `ascii` field, in bits.
pub const MAX_BLOB_BITS: u32 = 8 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceRule>,
    #[serde(default, rename = "log")]
    pub logs: Vec<LogRule>,
    #[serde(default)]
    pub packet_time: Option<PacketTime>,
    #[serde(default, rename = "packet")]
    pub packets: Vec<PacketDef>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRule {
    pub path: String,
    pub name: String,
    #[serde(default)]
    pub utc_offset: Option<String>,
    #[serde(default)]
    pub clock_offset_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRule {
    pub path: String,
    pub pattern: String,
    #[serde(default)]
    pub default_year: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeCode {
    Cuc,
    Cds,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketTime {
    pub code: TimeCode,
    #[serde(default = "default_time_offset")]
    pub byte_offset: usize,
    #[serde(default = "default_coarse")]
    pub coarse_bytes: usize,
    #[serde(default = "default_fine")]
    pub fine_bytes: usize,
    #[serde(default = "default_day_bytes")]
    pub day_bytes: usize,
    #[serde(default)]
    pub submillis_bytes: usize,
    #[serde(default = "default_epoch")]
    pub epoch: String,
    #[serde(default)]
    pub subtract_seconds: i64,
}

fn default_time_offset() -> usize {
    6
}
fn default_coarse() -> usize {
    4
}
fn default_fine() -> usize {
    2
}
fn default_day_bytes() -> usize {
    2
}
fn default_epoch() -> String {
    "1958-01-01T00:00:00Z".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Tm,
    Tc,
}

impl Kind {
    pub fn packet_type(self) -> PacketType {
        match self {
            Kind::Tm => PacketType::Telemetry,
            Kind::Tc => PacketType::Command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketDef {
    pub apid: u16,
    #[serde(default, rename = "type")]
    pub kind: Kind,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "field")]
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    #[default]
    Uint,
    Int,
    Float,
    Hex,
    Ascii,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDef {
    pub name: String,
    pub bit_offset: u32,
    pub bit_length: u32,
    #[serde(default)]
    pub kind: FieldKind,
    #[serde(default)]
    pub unit: String,
    /// Names for particular raw values, keyed by the value in decimal.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// A packet time rule with its epoch already turned into a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTime {
    pub code: TimeCode,
    pub byte_offset: usize,
    pub coarse_bytes: usize,
    pub fine_bytes: usize,
    pub day_bytes: usize,
    pub submillis_bytes: usize,
    pub epoch_ns: i64,
    pub subtract_ns: i64,
}

/// What the configuration says about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    pub name: String,
    /// Timezone of the source's text logs, in seconds east of UTC.
    pub utc_offset_s: i64,
    /// Added to the source's receive and log times.
    pub clock_offset_ns: i64,
}

impl Config {
    /// Parses and validates a configuration file. The error is a sentence
    /// that says which entry is wrong.
    pub fn parse(text: &str) -> Result<Config, String> {
        let config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for rule in &self.sources {
            if rule.name.trim().is_empty() {
                return Err(format!("source path {:?}: name is empty", rule.path));
            }
            if let Some(offset) = &rule.utc_offset
                && parse_utc_offset(offset).is_none()
            {
                return Err(format!(
                    "source {:?}: utc_offset {offset:?} must look like \"+02:00\"",
                    rule.name
                ));
            }
        }
        for rule in &self.logs {
            LogFormat::new(&rule.pattern, 0, rule.default_year)
                .map_err(|e| format!("log path {:?}: {e}", rule.path))?;
        }
        if let Some(time) = &self.packet_time {
            time.resolve()?;
        }
        let mut seen = Vec::new();
        for def in &self.packets {
            if def.apid > 0x7FF {
                return Err(format!(
                    "packet {:?}: apid {} must be 0 to 2047",
                    def.name, def.apid
                ));
            }
            if def.name.trim().is_empty() {
                return Err(format!("packet apid {}: name is empty", def.apid));
            }
            if seen.contains(&(def.apid, def.kind)) {
                return Err(format!(
                    "packet {:?}: duplicate apid {} for this type",
                    def.name, def.apid
                ));
            }
            seen.push((def.apid, def.kind));
            for field in &def.fields {
                field
                    .validate()
                    .map_err(|e| format!("packet {:?}, field {:?}: {e}", def.name, field.name))?;
            }
        }
        Ok(())
    }

    /// The definition for a packet type, if the file has one.
    pub fn packet_def(&self, apid: u16, packet_type: PacketType) -> Option<&PacketDef> {
        self.packets
            .iter()
            .find(|d| d.apid == apid && d.kind.packet_type() == packet_type)
    }

    /// Source name and clock corrections for a file, from its path within
    /// the run (forward slashes). With no matching rule the source is the
    /// first folder of the path, or "local" for a file at the top.
    pub fn source_for(&self, rel_path: &str) -> SourceInfo {
        if let Some(rule) = self.sources.iter().find(|r| rel_path.starts_with(&r.path)) {
            return SourceInfo {
                name: rule.name.clone(),
                utc_offset_s: rule
                    .utc_offset
                    .as_deref()
                    .and_then(parse_utc_offset)
                    .unwrap_or(0),
                clock_offset_ns: rule.clock_offset_ms.saturating_mul(1_000_000),
            };
        }
        let name = match rel_path.split_once('/') {
            Some((first, _)) if !first.is_empty() => first.to_string(),
            _ => "local".to_string(),
        };
        SourceInfo {
            name,
            utc_offset_s: 0,
            clock_offset_ns: 0,
        }
    }

    /// The timestamp format for a text log, from its path within the run.
    pub fn log_format_for(&self, rel_path: &str, utc_offset_s: i64) -> LogFormat {
        self.logs
            .iter()
            .find(|r| rel_path.starts_with(&r.path))
            .and_then(|r| LogFormat::new(&r.pattern, utc_offset_s, r.default_year).ok())
            .unwrap_or_else(|| {
                LogFormat::new(crate::pure::textlog::DEFAULT_PATTERN, utc_offset_s, None)
                    .unwrap_or_else(|_| LogFormat::iso())
            })
    }

    pub fn resolved_time(&self) -> Option<ResolvedTime> {
        self.packet_time.as_ref().and_then(|t| t.resolve().ok())
    }
}

impl PacketTime {
    pub fn resolve(&self) -> Result<ResolvedTime, String> {
        let epoch_ns = parse_iso(&self.epoch).ok_or_else(|| {
            format!(
                "packet_time: epoch {:?} must look like \"1958-01-01T00:00:00Z\"",
                self.epoch
            )
        })?;
        match self.code {
            TimeCode::Cuc => {
                if !(1..=4).contains(&self.coarse_bytes) {
                    return Err("packet_time: coarse_bytes must be 1 to 4".to_string());
                }
                if self.fine_bytes > 3 {
                    return Err("packet_time: fine_bytes must be 0 to 3".to_string());
                }
            }
            TimeCode::Cds => {
                if !(2..=3).contains(&self.day_bytes) {
                    return Err("packet_time: day_bytes must be 2 or 3".to_string());
                }
                if self.submillis_bytes != 0 && self.submillis_bytes != 2 {
                    return Err("packet_time: submillis_bytes must be 0 or 2".to_string());
                }
            }
        }
        if self.byte_offset > 65536 {
            return Err("packet_time: byte_offset must be 0 to 65536".to_string());
        }
        let subtract_ns = self
            .subtract_seconds
            .checked_mul(NS_PER_SEC)
            .ok_or("packet_time: subtract_seconds is too large")?;
        Ok(ResolvedTime {
            code: self.code,
            byte_offset: self.byte_offset,
            coarse_bytes: self.coarse_bytes,
            fine_bytes: self.fine_bytes,
            day_bytes: self.day_bytes,
            submillis_bytes: self.submillis_bytes,
            epoch_ns,
            subtract_ns,
        })
    }
}

impl FieldDef {
    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name is empty".to_string());
        }
        match self.kind {
            FieldKind::Uint | FieldKind::Int => {
                if !(1..=64).contains(&self.bit_length) {
                    return Err("bit_length must be 1 to 64".to_string());
                }
            }
            FieldKind::Float => {
                if self.bit_length != 32 && self.bit_length != 64 {
                    return Err("bit_length must be 32 or 64 for float".to_string());
                }
            }
            FieldKind::Hex | FieldKind::Ascii => {
                if self.bit_length == 0
                    || !self.bit_length.is_multiple_of(8)
                    || self.bit_length > MAX_BLOB_BITS
                    || !self.bit_offset.is_multiple_of(8)
                {
                    return Err(format!(
                        "hex and ascii fields must be byte-aligned, 1 to {} bytes",
                        MAX_BLOB_BITS / 8
                    ));
                }
            }
        }
        if let Some(key) = self.labels.keys().find(|k| k.parse::<i128>().is_err()) {
            return Err(format!("labels key {key:?} must be a whole number"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[[source]]
path = "bench-a/"
name = "bench-a"
utc_offset = "-05:00"
clock_offset_ms = 250

[[log]]
path = "bench-a/sim"
pattern = '^\[(?P<epoch>\d+\.\d+)\]'

[packet_time]
code = "cuc"
subtract_seconds = 37

[[packet]]
apid = 0x1A3
name = "PAYLOAD_SCIENCE"
  [[packet.field]]
  name = "MODE"
  bit_offset = 96
  bit_length = 8
  labels = { "0" = "IDLE", "1" = "OBSERVE" }

[[packet]]
apid = 0x1A3
type = "tc"
name = "PAYLOAD_CMD"
"#;

    #[test]
    fn parses_the_documented_example() {
        let config = Config::parse(EXAMPLE).unwrap();
        assert_eq!(config.sources.len(), 1);
        assert_eq!(config.packets.len(), 2);
        let def = config.packet_def(0x1A3, PacketType::Telemetry).unwrap();
        assert_eq!(def.name, "PAYLOAD_SCIENCE");
        assert_eq!(def.fields[0].labels["1"], "OBSERVE");
        assert_eq!(
            config.packet_def(0x1A3, PacketType::Command).unwrap().name,
            "PAYLOAD_CMD"
        );
        assert!(config.packet_def(0x1A4, PacketType::Telemetry).is_none());
        let time = config.resolved_time().unwrap();
        assert_eq!(time.coarse_bytes, 4);
        assert_eq!(time.subtract_ns, 37 * NS_PER_SEC);
        assert_eq!(time.epoch_ns, -378_691_200 * NS_PER_SEC);
    }

    #[test]
    fn empty_file_is_a_valid_config() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn source_rules_and_defaults() {
        let config = Config::parse(EXAMPLE).unwrap();
        let a = config.source_for("bench-a/tlm/pass1.bin");
        assert_eq!(a.name, "bench-a");
        assert_eq!(a.utc_offset_s, -5 * 3600);
        assert_eq!(a.clock_offset_ns, 250_000_000);
        assert_eq!(config.source_for("ground/x.log").name, "ground");
        assert_eq!(config.source_for("x.log").name, "local");
        assert_eq!(config.source_for("ground/x.log").clock_offset_ns, 0);
    }

    #[test]
    fn rejects_what_it_cannot_use() {
        for (text, needle) in [
            ("[[packet]]\napid = 4096\nname = \"X\"", "0 to 2047"),
            ("[[packet]]\napid = 1\nname = \" \"", "name is empty"),
            (
                "[[packet]]\napid = 1\nname = \"A\"\n[[packet]]\napid = 1\nname = \"B\"",
                "duplicate apid",
            ),
            (
                "[[packet]]\napid = 1\nname = \"A\"\n[[packet.field]]\nname = \"F\"\nbit_offset = 0\nbit_length = 65",
                "1 to 64",
            ),
            (
                "[[packet]]\napid = 1\nname = \"A\"\n[[packet.field]]\nname = \"F\"\nbit_offset = 0\nbit_length = 16\nkind = \"float\"",
                "32 or 64",
            ),
            (
                "[[packet]]\napid = 1\nname = \"A\"\n[[packet.field]]\nname = \"F\"\nbit_offset = 4\nbit_length = 16\nkind = \"hex\"",
                "byte-aligned",
            ),
            (
                "[[packet]]\napid = 1\nname = \"A\"\n[[packet.field]]\nname = \"F\"\nbit_offset = 0\nbit_length = 8\nlabels = { \"on\" = \"ON\" }",
                "must be a whole number",
            ),
            (
                "[packet_time]\ncode = \"cuc\"\ncoarse_bytes = 5",
                "coarse_bytes",
            ),
            ("[packet_time]\ncode = \"cds\"\nday_bytes = 4", "day_bytes"),
            (
                "[packet_time]\ncode = \"cuc\"\nepoch = \"yesterday\"",
                "epoch",
            ),
            (
                "[[source]]\npath = \"a\"\nname = \"a\"\nutc_offset = \"east\"",
                "utc_offset",
            ),
            ("[[log]]\npath = \"a\"\npattern = \"(\"", "log path"),
            (
                "[[packet]]\napid = 1\nname = \"A\"\ncolour = \"red\"",
                "colour",
            ),
        ] {
            let err = Config::parse(text).unwrap_err();
            assert!(
                err.contains(needle),
                "{text:?} gave {err:?}, wanted {needle:?}"
            );
        }
    }
}
