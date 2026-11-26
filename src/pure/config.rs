//! The configuration file: everything site or mission specific.
//!
//! It is TOML, every part is optional, and with no file at all the tool still
//! works: sources are named after the first folder in a file's path, text
//! logs are assumed to carry ISO timestamps in UTC (dashes or, as COSMOS
//! message logs write them, slashes in the date), and packets are shown by
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
//! [packet_time]              # where the time is in a packet
//! code = "cuc"               # "cuc": seconds + binary fraction; "cds": days + ms of day;
//!                            # "unix": seconds, then microseconds as a 32-bit number
//! byte_offset = 6            # from the start of the packet
//! coarse_bytes = 4           # cuc, unix: bytes of whole seconds
//! fine_bytes = 2             # cuc
//! epoch = "1958-01-01T00:00:00Z"   # the default, except for unix: 1970
//! subtract_seconds = 0       # for example the difference between the timescale and UTC
//! require_secondary_header = true  # false: read the time whatever the header's flag
//!                            # says, as COSMOS's example packets need
//! applies_to = "all"         # or "telemetry", "commands". The default is "all", or
//!                            # "telemetry" where the flag is not required: with no
//!                            # flag to go by, a command's arguments would be read
//!                            # as a time
//!
//! [frames]                   # only for files of CADUs: sync marker + transfer frame.
//!                            # The first four are detected from each file where its
//!                            # bytes allow; give them to overrule that.
//! kind = "tm"                # "tm" or "aos"
//! randomized = false         # frames are still XORed with the CCSDS random sequence
//! crc = false                # each frame ends with a 16-bit CRC
//! rs_parity_bytes = 0        # Reed-Solomon check symbols kept after each frame
//! rs_correct = true          # use them to correct errors. The default: yes if a
//!                            # frame in the file is a clean codeword, or if any of
//!                            # the next three is given; otherwise they are skipped
//! rs_code = "255,223"        # or "255,239"
//! rs_interleave = 1          # 1, 2, 3, 4, 5 or 8
//! rs_basis = "dual"          # how a byte stands for a symbol: "dual" (Berlekamp,
//!                            # the CCSDS default) or "conventional"
//! ocf = false                # aos only: operational control field present
//! header_check = false       # aos only: 2-byte header check present
//! insert_zone_bytes = 0      # aos only
//!
//! [tc]                       # only for telecommand captures: CLTUs, or TC transfer
//!                            # frames back to back. All three are detected from
//!                            # each file where its bytes allow.
//! crc = true                 # each frame ends with a 16-bit CRC
//! segment_header = true      # frame data starts with a segment header
//! randomized = false         # CLTUs only: frames are XORed with the TC random sequence
//!
//! [[packet]]                 # name a packet type and its fields; `packetlane
//!                            # import-cosmos` writes these from COSMOS 4 files
//! apid = 419               # decimal or hex (0x1A3); optional if label is given
//! label = "INST HK"          # optional: the name the log gives the packet (COSMOS:
//!                            # "TARGET PACKET"). Lets several definitions share an APID
//! type = "tm"                # "tm" (default) or "tc"
//! name = "PAYLOAD_SCIENCE"
//!   [[packet.field]]
//!   name = "MODE"
//!   bit_offset = 96          # from the start of the packet; bit 0 is the top bit of byte 0
//!   bit_length = 8
//!   kind = "uint"            # uint (default), int, float, hex, ascii
//!   byte_order = "big"       # "big" (default) or "little": whole bytes on a byte boundary
//!   count = 1                # more than 1: an array of that many numbers
//!   poly = [-100.0, 0.00305] # engineering value = c0 + c1 x + c2 x^2 ...; unit applies to it
//!   limits = { red_low = -80, yellow_low = -70, yellow_high = 60, red_high = 80, persistence = 1 }
//!                            # leaving the yellow or red range is a finding
//!   keep = false             # true: store the value of every packet, for searching
//!   unit = ""
//!   labels = { "0" = "IDLE", "1" = "OBSERVE" }
//! ```

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::pure::ccsds::{PacketType, PrimaryHeader};
use crate::pure::frame::{FrameKind, FrameParams, Layout};
use crate::pure::rs::{Basis, Code, DEPTHS, RsCode};
use crate::pure::tc::{TcLayout, TcParams};
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
    #[serde(default)]
    pub frames: Frames,
    #[serde(default)]
    pub tc: Tc,
}

/// How telecommand frames are laid out. See `pure/tc.rs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tc {
    pub crc: Option<bool>,
    pub segment_header: Option<bool>,
    pub randomized: Option<bool>,
}

/// How transfer frames are laid out in files of CADUs. The CADU length is
/// not here: it is measured from each file. See `pure/frame.rs`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Frames {
    pub kind: Option<FrameKind>,
    pub randomized: Option<bool>,
    pub crc: Option<bool>,
    pub rs_parity_bytes: Option<usize>,
    pub rs_correct: Option<bool>,
    pub rs_code: Option<Code>,
    pub rs_interleave: Option<usize>,
    pub rs_basis: Option<Basis>,
    pub ocf: bool,
    pub header_check: bool,
    pub insert_zone_bytes: usize,
}

/// More than any real link uses; keeps arithmetic on these far from overflow.
const MAX_FRAME_EXTRA: usize = 4096;

impl Frames {
    /// True if the table names any property of the Reed-Solomon code, which
    /// is a way of saying there is one.
    fn names_rs(&self) -> bool {
        self.rs_code.is_some() || self.rs_interleave.is_some() || self.rs_basis.is_some()
    }

    /// The Reed-Solomon keys must describe one code.
    fn check_rs(&self) -> Result<(), String> {
        if let Some(depth) = self.rs_interleave
            && !DEPTHS.contains(&depth)
        {
            return Err("frames: rs_interleave must be 1, 2, 3, 4, 5 or 8".to_string());
        }
        if self.rs_correct == Some(false) || !(self.names_rs() || self.rs_correct == Some(true)) {
            return Ok(());
        }
        let Some(parity) = self.rs_parity_bytes else {
            return Ok(());
        };
        let code = self.rs_code.unwrap_or_default();
        let per_word = code.check_len();
        let depth = parity / per_word;
        if parity % per_word != 0 || !DEPTHS.contains(&depth) {
            return Err(format!(
                "frames: rs_parity_bytes = {parity} is not {per_word} x an interleave depth \
                 (1, 2, 3, 4, 5 or 8), as {} needs; set rs_correct = false to only skip them",
                code.name()
            ));
        }
        if self.rs_interleave.is_some_and(|given| given != depth) {
            return Err(format!(
                "frames: rs_parity_bytes = {parity} means an interleave depth of {depth}, \
                 not the rs_interleave given"
            ));
        }
        Ok(())
    }

    /// The code to correct with, if any, for a file in which `seen` was
    /// detected. What the table says wins; what neither says is the CCSDS
    /// default: RS(255,223), dual basis.
    fn rs_code_for(&self, seen: Option<RsCode>, crc_parity: Option<usize>) -> Option<RsCode> {
        // A stated length that is not the detected code's says the check
        // symbols are not what detection took them for.
        let seen = seen.filter(|s| {
            self.names_rs()
                || self
                    .rs_parity_bytes
                    .is_none_or(|given| given == s.parity_len())
        });
        let wanted = self.rs_correct.unwrap_or(seen.is_some() || self.names_rs());
        if !wanted {
            return None;
        }
        let code = self.rs_code.or(seen.map(|s| s.code)).unwrap_or_default();
        let from_len = |len: usize| Some(len / code.check_len()).filter(|d| DEPTHS.contains(d));
        let depth = self
            .rs_interleave
            .or(self.rs_parity_bytes.and_then(from_len))
            .or(seen.map(|s| s.depth))
            .or(crc_parity.and_then(from_len))
            .unwrap_or(1);
        let basis = self.rs_basis.or(seen.map(|s| s.basis)).unwrap_or_default();
        Some(RsCode { code, depth, basis })
    }
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
    /// Whole seconds, then microseconds as a 32-bit number: what Unix calls
    /// a timeval, and what COSMOS's example packets carry.
    Unix,
}

/// Which packets the time rule is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppliesTo {
    All,
    Telemetry,
    Commands,
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
    /// Where unset: 1958 (TAI's), or 1970 for the unix code.
    #[serde(default)]
    pub epoch: Option<String>,
    #[serde(default)]
    pub subtract_seconds: i64,
    #[serde(default = "default_true")]
    pub require_secondary_header: bool,
    #[serde(default)]
    pub applies_to: Option<AppliesTo>,
}

fn default_true() -> bool {
    true
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
const TAI_EPOCH: &str = "1958-01-01T00:00:00Z";
const UNIX_EPOCH: &str = "1970-01-01T00:00:00Z";

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
    /// The APID this definition is for. Optional when `label` is given.
    #[serde(default)]
    pub apid: Option<u16>,
    /// The name the log's container gives the packet (COSMOS: "TARGET
    /// PACKET"). A definition with a label applies to packets logged under
    /// that name, whatever their APID, so several can share one APID.
    #[serde(default)]
    pub label: Option<String>,
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
    /// Which byte of a number comes first in the packet.
    #[serde(default)]
    pub byte_order: ByteOrder,
    /// How many numbers of `bit_length` bits follow one another: more than
    /// one makes the field an array.
    #[serde(default = "one")]
    pub count: u32,
    /// Coefficients turning the raw number into an engineering value:
    /// c0 + c1 x + c2 x^2 and so on. Empty means the raw number is the value.
    #[serde(default)]
    pub poly: Vec<f64>,
    /// The range the engineering value should stay in.
    #[serde(default)]
    pub limits: Option<Limits>,
    /// Store this field's value for every packet, so that it can be
    /// searched and sorted. Off by default: it is a row per packet.
    #[serde(default)]
    pub keep: bool,
}

/// Limits on a field's value, in the sense COSMOS gives them: outside the
/// yellow pair is a warning, outside the red pair a problem.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub red_low: f64,
    pub yellow_low: f64,
    pub yellow_high: f64,
    pub red_high: f64,
    /// How many packets in a row must disagree with the current state
    /// before it changes, so that one odd sample is not reported.
    #[serde(default = "one")]
    pub persistence: u32,
}

/// Where a value stands against its limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitState {
    Green,
    YellowLow,
    YellowHigh,
    RedLow,
    RedHigh,
}

impl LimitState {
    pub fn name(self) -> &'static str {
        match self {
            LimitState::Green => "green",
            LimitState::YellowLow => "yellow low",
            LimitState::YellowHigh => "yellow high",
            LimitState::RedLow => "red low",
            LimitState::RedHigh => "red high",
        }
    }

    pub fn is_red(self) -> bool {
        matches!(self, LimitState::RedLow | LimitState::RedHigh)
    }
}

impl Limits {
    /// The comparisons are COSMOS's: a value equal to a yellow limit is
    /// yellow, and one equal to a red limit is red.
    pub fn state(&self, value: f64) -> LimitState {
        if value > self.yellow_low {
            if value < self.yellow_high {
                LimitState::Green
            } else if value < self.red_high {
                LimitState::YellowHigh
            } else {
                LimitState::RedHigh
            }
        } else if value > self.red_low {
            LimitState::YellowLow
        } else {
            LimitState::RedLow
        }
    }
}

fn one() -> u32 {
    1
}

/// Most elements an array field may have.
pub const MAX_COUNT: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteOrder {
    /// Most significant byte first, as space packets themselves are.
    #[default]
    Big,
    Little,
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
    pub require_secondary_header: bool,
    pub applies_to: AppliesTo,
}

impl ResolvedTime {
    /// Whether a packet with this header is one the rule reads a time from.
    pub fn applies(&self, header: &PrimaryHeader) -> bool {
        let kind = match self.applies_to {
            AppliesTo::All => true,
            AppliesTo::Telemetry => header.packet_type == PacketType::Telemetry,
            AppliesTo::Commands => header.packet_type == PacketType::Command,
        };
        kind && (header.has_secondary_header || !self.require_secondary_header)
    }
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
        if self.frames.rs_parity_bytes.unwrap_or(0) > MAX_FRAME_EXTRA {
            return Err(format!(
                "frames: rs_parity_bytes must be 0 to {MAX_FRAME_EXTRA}"
            ));
        }
        self.frames.check_rs()?;
        if self.frames.insert_zone_bytes > MAX_FRAME_EXTRA {
            return Err(format!(
                "frames: insert_zone_bytes must be 0 to {MAX_FRAME_EXTRA}"
            ));
        }
        let mut seen = Vec::new();
        let mut labels: Vec<(&str, Kind)> = Vec::new();
        for def in &self.packets {
            if def.name.trim().is_empty() {
                return Err(match (def.apid, &def.label) {
                    (Some(apid), _) => format!("packet apid {apid}: name is empty"),
                    (None, label) => format!("packet label {label:?}: name is empty"),
                });
            }
            if def.apid.is_none() && def.label.is_none() {
                return Err(format!("packet {:?}: needs an apid or a label", def.name));
            }
            if let Some(apid) = def.apid.filter(|a| *a > 0x7FF) {
                return Err(format!(
                    "packet {:?}: apid {apid} must be 0 to 2047",
                    def.name
                ));
            }
            match (&def.label, def.apid) {
                (Some(label), _) => {
                    if label.trim().is_empty() {
                        return Err(format!("packet {:?}: label is empty", def.name));
                    }
                    if labels.contains(&(label.as_str(), def.kind)) {
                        return Err(format!(
                            "packet {:?}: duplicate label {label:?} for this type",
                            def.name
                        ));
                    }
                    labels.push((label, def.kind));
                }
                // Without a label the APID and type are all there is to go on.
                (None, Some(apid)) => {
                    if seen.contains(&(apid, def.kind)) {
                        return Err(format!(
                            "packet {:?}: duplicate apid {apid} for this type",
                            def.name
                        ));
                    }
                    seen.push((apid, def.kind));
                }
                (None, None) => {}
            }
            for field in &def.fields {
                field
                    .validate()
                    .map_err(|e| format!("packet {:?}, field {:?}: {e}", def.name, field.name))?;
            }
        }
        Ok(())
    }

    /// The definition for everything with one APID and type: what a lane
    /// shows, and what a packet logged without a name is decoded with. That
    /// is the definition with no label, or failing that a labelled one if it
    /// is the only one for this APID and type. Several labelled definitions
    /// on one APID name different packets, so none of them speaks for all.
    pub fn packet_def(&self, apid: u16, packet_type: PacketType) -> Option<&PacketDef> {
        let mut same = self
            .packets
            .iter()
            .filter(|d| d.apid == Some(apid) && d.kind.packet_type() == packet_type);
        let first = same.next()?;
        let others: Vec<&PacketDef> = same.collect();
        std::iter::once(first)
            .chain(others.iter().copied())
            .find(|d| d.label.is_none())
            .or(others.is_empty().then_some(first))
    }

    /// The definition for one logged packet. The name its log gives it
    /// decides, if a definition has that label: the one of the packet's own
    /// type if a command and a telemetry packet share the name, or the only
    /// one if the packet is not a space packet and has no type. Otherwise
    /// the APID and type decide, but a packet that was logged under a name
    /// is never decoded with a definition labelled for a different one.
    pub fn packet_for(
        &self,
        label: Option<&str>,
        header: Option<&PrimaryHeader>,
    ) -> Option<&PacketDef> {
        let labelled = label.and_then(|l| {
            let named: Vec<&PacketDef> = self
                .packets
                .iter()
                .filter(|d| d.label.as_deref() == Some(l))
                .collect();
            match (header, named.as_slice()) {
                (Some(h), _) => named
                    .iter()
                    .copied()
                    .find(|d| d.kind.packet_type() == h.packet_type),
                (None, [only]) => Some(*only),
                (None, _) => None,
            }
        });
        labelled.or_else(|| {
            let def = self.packet_def(header?.apid, header?.packet_type)?;
            (label.is_none() || def.label.is_none()).then_some(def)
        })
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

    /// The frame layout for a file whose CADUs are `cadu_len` bytes apart.
    pub fn frame_params(&self, cadu_len: usize) -> FrameParams {
        self.frame_params_for(&Layout::of_len(cadu_len))
    }

    /// The frame layout for a file, from what was detected in it and what
    /// this configuration says. The configuration wins wherever it speaks;
    /// what neither settles defaults to plain TM frames with no extras.
    pub fn frame_params_for(&self, layout: &Layout) -> FrameParams {
        let f = &self.frames;
        let rs = f.rs_code_for(layout.rs, layout.crc_parity);
        // Check symbols that are not to be used are still there to be
        // stepped over: a code found in the file says how many, even when
        // the configuration says to leave them alone.
        let stated = rs
            .map(|rs| rs.parity_len())
            .or(f.rs_parity_bytes)
            .or(layout.rs.map(|rs| rs.parity_len()));
        // A detected CRC is tied to the check-symbol length it was found
        // with: if the configuration gives a different length, it is not there.
        let has_crc = f.crc.unwrap_or(match (stated, layout.crc_parity) {
            (Some(given), Some(found)) => given == found,
            (None, found) => found.is_some(),
            (Some(_), None) => false,
        });
        let detected_parity = if has_crc { layout.crc_parity } else { None };
        FrameParams {
            cadu_len: layout.cadu_len,
            kind: f.kind.or(layout.kind).unwrap_or_default(),
            randomized: f.randomized.or(layout.randomized).unwrap_or(false),
            rs_parity_len: stated.or(detected_parity).unwrap_or(0),
            rs,
            has_crc,
            aos_has_ocf: f.ocf,
            aos_has_header_check: f.header_check,
            aos_insert_zone_len: f.insert_zone_bytes,
        }
    }

    /// The layout of a telecommand file, of CLTUs or of bare frames, from
    /// what was detected in it and what this configuration says. The
    /// configuration wins wherever it speaks. What neither settles is taken
    /// as most links have it: a CRC, segment headers, no randomising.
    pub fn tc_params_for(&self, layout: &TcLayout, cltu: bool) -> TcParams {
        let tc = &self.tc;
        TcParams {
            cltu,
            has_crc: tc.crc.or(layout.crc).unwrap_or(true),
            segment_header: tc.segment_header.or(layout.segment_header).unwrap_or(true),
            randomized: cltu && tc.randomized.or(layout.randomized).unwrap_or(false),
        }
    }

    pub fn resolved_time(&self) -> Option<ResolvedTime> {
        self.packet_time.as_ref().and_then(|t| t.resolve().ok())
    }
}

impl PacketTime {
    pub fn resolve(&self) -> Result<ResolvedTime, String> {
        let epoch = self.epoch.as_deref().unwrap_or(match self.code {
            TimeCode::Unix => UNIX_EPOCH,
            TimeCode::Cuc | TimeCode::Cds => TAI_EPOCH,
        });
        let epoch_ns = parse_iso(epoch).ok_or_else(|| {
            format!("packet_time: epoch {epoch:?} must look like \"1958-01-01T00:00:00Z\"")
        })?;
        match self.code {
            TimeCode::Cuc | TimeCode::Unix => {
                if !(1..=4).contains(&self.coarse_bytes) {
                    return Err("packet_time: coarse_bytes must be 1 to 4".to_string());
                }
                if self.code == TimeCode::Cuc && self.fine_bytes > 3 {
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
            require_secondary_header: self.require_secondary_header,
            applies_to: self.applies_to.unwrap_or(if self.require_secondary_header {
                AppliesTo::All
            } else {
                AppliesTo::Telemetry
            }),
        })
    }
}

impl FieldDef {
    pub(crate) fn validate(&self) -> Result<(), String> {
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
        let number = !matches!(self.kind, FieldKind::Hex | FieldKind::Ascii);
        if self.byte_order == ByteOrder::Little
            && !(number
                && matches!(self.bit_length, 16 | 32 | 64)
                && self.bit_offset.is_multiple_of(8))
        {
            return Err(
                "byte_order little needs a byte-aligned number of 16, 32 or 64 bits".to_string(),
            );
        }
        if !(1..=MAX_COUNT).contains(&self.count) || (self.count > 1 && !number) {
            return Err(format!(
                "count must be 1 to {MAX_COUNT}, and 1 for hex and ascii"
            ));
        }
        if self.count > 1 && !self.labels.is_empty() {
            return Err("an array field cannot have labels".to_string());
        }
        if (!self.poly.is_empty() || self.limits.is_some()) && (!number || self.count > 1) {
            return Err("poly and limits need a single number".to_string());
        }
        if self.poly.len() > 16 || self.poly.iter().any(|c| !c.is_finite()) {
            return Err("poly takes up to 16 finite coefficients".to_string());
        }
        if let Some(l) = &self.limits {
            let all = [l.red_low, l.yellow_low, l.yellow_high, l.red_high];
            let ordered = l.red_low <= l.yellow_low
                && l.yellow_low < l.yellow_high
                && l.yellow_high <= l.red_high;
            if !ordered || all.iter().any(|v| !v.is_finite()) || l.persistence == 0 {
                return Err(
                    "limits must run red_low <= yellow_low < yellow_high <= red_high, persistence at least 1"
                        .to_string(),
                );
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
    fn packet_time_defaults_follow_the_code_and_the_flag() {
        let time = |text: &str| {
            Config::parse(&format!("[packet_time]\n{text}"))
                .unwrap()
                .resolved_time()
                .unwrap()
        };
        let header = |first: u8| PrimaryHeader::parse(&[first, 1, 0xC0, 0, 0, 0]).unwrap();
        let (tm, tm_flag, tc, tc_flag) = (header(0x00), header(0x08), header(0x10), header(0x18));

        // As it always was: any packet that sets the flag, 1958.
        let cuc = time("code = \"cuc\"");
        assert_eq!(cuc.epoch_ns, -378_691_200 * NS_PER_SEC);
        assert_eq!(
            [&tm, &tm_flag, &tc, &tc_flag].map(|h| cuc.applies(h)),
            [false, true, false, true]
        );

        // Unix time counts from 1970 unless told otherwise.
        assert_eq!(time("code = \"unix\"").epoch_ns, 0);
        assert_eq!(
            time("code = \"unix\"\nepoch = \"1980-01-06T00:00:00Z\"").epoch_ns,
            315_964_800 * NS_PER_SEC
        );

        // Without the flag to go by, only telemetry, unless told otherwise.
        let loose = time("code = \"unix\"\nrequire_secondary_header = false");
        assert_eq!(
            [&tm, &tm_flag, &tc, &tc_flag].map(|h| loose.applies(h)),
            [true, true, false, false]
        );
        let all = time("code = \"unix\"\nrequire_secondary_header = false\napplies_to = \"all\"");
        assert!(
            [&tm, &tm_flag, &tc, &tc_flag]
                .iter()
                .all(|h| all.applies(h))
        );
        let commands = time("code = \"cuc\"\napplies_to = \"commands\"");
        assert_eq!(
            [&tm, &tm_flag, &tc, &tc_flag].map(|h| commands.applies(h)),
            [false, false, false, true]
        );
        assert!(Config::parse("[packet_time]\ncode = \"unix\"\ncoarse_bytes = 5").is_err());
        assert!(Config::parse("[packet_time]\ncode = \"cuc\"\napplies_to = \"some\"").is_err());
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

#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn frames_table_sets_the_frame_layout() {
        let config = Config::parse(
            "[frames]\nkind = \"aos\"\nrandomized = true\ncrc = true\nrs_parity_bytes = 160\n",
        )
        .unwrap();
        let p = config.frame_params(1279);
        assert_eq!((p.cadu_len, p.kind), (1279, FrameKind::Aos));
        assert!(p.randomized && p.has_crc && !p.aos_has_ocf);
        assert_eq!(p.rs_parity_len, 160);
        // With no table at all: plain TM frames and nothing else.
        let plain = Config::default().frame_params(1119);
        assert_eq!(plain.kind, FrameKind::Tm);
        assert!(!plain.randomized && !plain.has_crc && plain.rs_parity_len == 0);

        // What a file shows is used where the configuration is silent.
        let seen = Layout {
            cadu_len: 1279,
            kind: Some(FrameKind::Aos),
            randomized: Some(true),
            crc_parity: Some(160),
            rs: None,
        };
        let p = Config::default().frame_params_for(&seen);
        assert_eq!(
            (p.kind, p.randomized, p.has_crc, p.rs_parity_len),
            (FrameKind::Aos, true, true, 160)
        );
        // And overruled where it speaks.
        let p = Config::parse(
            r#"[frames]
kind = "tm"
randomized = false
crc = false
"#,
        )
        .unwrap()
        .frame_params_for(&seen);
        assert_eq!(
            (p.kind, p.randomized, p.has_crc, p.rs_parity_len),
            (FrameKind::Tm, false, false, 0)
        );
        // A CRC found before 160 check bytes is not a CRC before 32.
        let p = Config::parse("[frames]\nrs_parity_bytes = 32")
            .unwrap()
            .frame_params_for(&seen);
        assert_eq!((p.has_crc, p.rs_parity_len), (false, 32));
        let err = Config::parse("[frames]\nrs_parity_bytes = 99999\n").unwrap_err();
        assert!(err.contains("rs_parity_bytes"), "{err}");
        assert!(Config::parse("[frames]\nkind = \"tc\"\n").is_err());
    }

    #[test]
    fn tc_table_overrules_what_a_file_shows() {
        let seen = TcLayout {
            crc: Some(false),
            segment_header: None,
            randomized: Some(true),
        };
        let p = Config::default().tc_params_for(&seen, true);
        assert_eq!(
            (p.cltu, p.has_crc, p.segment_header, p.randomized),
            (true, false, true, true)
        );
        // Randomising is done in the coding layer: bare frames have none.
        assert!(!Config::default().tc_params_for(&seen, false).randomized);
        let config =
            Config::parse("[tc]\ncrc = true\nsegment_header = false\nrandomized = false\n")
                .unwrap();
        let p = config.tc_params_for(&seen, true);
        assert_eq!(
            (p.has_crc, p.segment_header, p.randomized),
            (true, false, false)
        );
        let blank = Config::default().tc_params_for(&TcLayout::default(), true);
        assert_eq!(
            (blank.has_crc, blank.segment_header, blank.randomized),
            (true, true, false)
        );
        assert!(Config::parse("[tc]\nmap = 3\n").is_err());
    }

    #[test]
    fn reed_solomon_is_used_when_found_or_asked_for() {
        let rs = |code, depth, basis| RsCode { code, depth, basis };
        let of = |toml: &str, seen: &Layout| {
            let p = Config::parse(toml).unwrap().frame_params_for(seen);
            (p.rs, p.rs_parity_len, p.has_crc)
        };
        let blank = Layout::of_len(1279);
        let found = rs(Code::Rs239, 4, Basis::Conventional);
        let seen = Layout {
            crc_parity: Some(64),
            rs: Some(found),
            ..blank
        };

        // Check symbols with nothing known about them are only skipped.
        assert_eq!(
            of("[frames]\nrs_parity_bytes = 160", &blank),
            (None, 160, false)
        );
        // A code found in the file is used, and says how long they are.
        assert_eq!(of("", &seen), (Some(found), 64, true));
        assert_eq!(
            of("[frames]\nrs_parity_bytes = 64", &seen),
            (Some(found), 64, true)
        );
        // Unless the configuration says not to, or gives another length.
        assert_eq!(of("[frames]\nrs_correct = false", &seen), (None, 64, true));
        // Not using them still means stepping over them, CRC or no CRC.
        let no_crc = Layout {
            crc_parity: None,
            ..seen
        };
        assert_eq!(
            of("[frames]\nrs_correct = false", &no_crc),
            (None, 64, false)
        );
        assert_eq!(of("", &no_crc), (Some(found), 64, false));
        assert_eq!(
            of("[frames]\nrs_parity_bytes = 32", &seen),
            (None, 32, false)
        );
        // What the configuration names overrules what was found, piece by piece.
        assert_eq!(
            of("[frames]\nrs_basis = \"dual\"", &seen),
            (Some(rs(Code::Rs239, 4, Basis::Dual)), 64, true)
        );
        assert_eq!(
            of("[frames]\nrs_code = \"255,223\"\nrs_interleave = 5", &seen),
            (Some(rs(Code::Rs223, 5, Basis::Conventional)), 160, false)
        );
        // Asked for with nothing found: the CCSDS defaults fill the gaps.
        assert_eq!(
            of("[frames]\nrs_correct = true\nrs_parity_bytes = 160", &blank),
            (Some(rs(Code::Rs223, 5, Basis::Dual)), 160, false)
        );
        assert_eq!(
            of(
                "[frames]\nrs_code = \"255,239\"\nrs_parity_bytes = 32",
                &blank
            ),
            (Some(rs(Code::Rs239, 2, Basis::Dual)), 32, false)
        );
        assert_eq!(
            of("[frames]\nrs_interleave = 2\ncrc = true", &blank),
            (Some(rs(Code::Rs223, 2, Basis::Dual)), 64, true)
        );
        // A CRC found before filler gives the depth if correction is forced.
        let filler = Layout {
            crc_parity: Some(128),
            ..blank
        };
        assert_eq!(
            of("[frames]\nrs_correct = true", &filler),
            (Some(rs(Code::Rs223, 4, Basis::Dual)), 128, true)
        );

        for (toml, word) in [
            ("rs_interleave = 6", "rs_interleave"),
            ("rs_correct = true\nrs_parity_bytes = 40", "rs_parity_bytes"),
            (
                "rs_code = \"255,239\"\nrs_parity_bytes = 96",
                "rs_parity_bytes",
            ),
            ("rs_interleave = 2\nrs_parity_bytes = 32", "rs_interleave"),
            ("rs_code = \"255,200\"", "rs_code"),
            ("rs_basis = \"other\"", "rs_basis"),
        ] {
            let err = Config::parse(&format!("[frames]\n{toml}\n")).unwrap_err();
            assert!(err.contains(word), "{toml}: {err}");
        }
        // Odd lengths are fine for check symbols that are only skipped.
        assert!(Config::parse("[frames]\nrs_parity_bytes = 40\n").is_ok());
        assert!(Config::parse("[frames]\nrs_correct = false\nrs_parity_bytes = 40\n").is_ok());
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;
    use crate::pure::synth::packet;

    const TWO_ON_ONE_APID: &str = r#"
[[packet]]
apid = 999
type = "tc"
label = "INST COLLECT"
name = "Collect"

[[packet]]
apid = 999
type = "tc"
label = "INST ABORT"
name = "Abort"

[[packet]]
apid = 7
label = "INST HK"
name = "Housekeeping"

[[packet]]
apid = 8
name = "Plain"

[[packet]]
label = "SYSTEM META"
name = "Metadata"

[[packet]]
label = "INST PING"
type = "tc"
name = "Ping command"

[[packet]]
label = "INST PING"
name = "Ping reply"
"#;

    fn header(apid: u16, command: bool) -> PrimaryHeader {
        let mut bytes = packet(apid, 0, &[0]);
        if command {
            bytes[0] |= 0x10;
        }
        PrimaryHeader::parse(&bytes).unwrap()
    }

    #[test]
    fn the_label_picks_among_definitions_that_share_an_apid() {
        let config = Config::parse(TWO_ON_ONE_APID).unwrap();
        let cmd = header(999, true);
        let name = |label: Option<&str>, h: Option<&PrimaryHeader>| {
            config.packet_for(label, h).map(|d| d.name.as_str())
        };
        assert_eq!(name(Some("INST COLLECT"), Some(&cmd)), Some("Collect"));
        assert_eq!(name(Some("INST ABORT"), Some(&cmd)), Some("Abort"));
        // Logged under a name nothing is labelled for: decoding it as
        // Collect or Abort would be a guess, so it gets no definition.
        assert_eq!(name(Some("INST OTHER"), Some(&cmd)), None);
        // No name at all, and two candidates: the same.
        assert_eq!(name(None, Some(&cmd)), None);
        // A lane holds everything on the APID, so it takes neither name.
        assert!(config.packet_def(999, PacketType::Command).is_none());
    }

    #[test]
    fn a_lone_definition_still_serves_packets_logged_without_a_name() {
        let config = Config::parse(TWO_ON_ONE_APID).unwrap();
        let name = |label: Option<&str>, h: Option<&PrimaryHeader>| {
            config.packet_for(label, h).map(|d| d.name.as_str())
        };
        let hk = header(7, false);
        // From a bare packet file or CADUs: the only definition for APID 7.
        assert_eq!(name(None, Some(&hk)), Some("Housekeeping"));
        assert_eq!(
            config.packet_def(7, PacketType::Telemetry).unwrap().name,
            "Housekeeping"
        );
        // But not for a packet COSMOS logged as something else.
        assert_eq!(name(Some("INST OTHER"), Some(&hk)), None);
        // A definition with no label applies whatever the packet was logged as.
        let plain = header(8, false);
        assert_eq!(name(Some("UNKNOWN UNKNOWN"), Some(&plain)), Some("Plain"));
        assert_eq!(name(None, Some(&plain)), Some("Plain"));
        // Same APID, other type: nothing.
        assert_eq!(name(None, Some(&header(7, true))), None);
    }

    #[test]
    fn labels_reach_packets_that_are_not_space_packets() {
        let config = Config::parse(TWO_ON_ONE_APID).unwrap();
        let name = |label: Option<&str>, h: Option<&PrimaryHeader>| {
            config.packet_for(label, h).map(|d| d.name.as_str())
        };
        assert_eq!(name(Some("SYSTEM META"), None), Some("Metadata"));
        assert_eq!(name(None, None), None);
        // A command and a telemetry packet may share a name: the packet's
        // own type picks, and with no type to go by neither is chosen.
        assert_eq!(
            name(Some("INST PING"), Some(&header(1, true))),
            Some("Ping command")
        );
        assert_eq!(
            name(Some("INST PING"), Some(&header(1, false))),
            Some("Ping reply")
        );
        assert_eq!(name(Some("INST PING"), None), None);
    }

    #[test]
    fn refuses_definitions_that_could_not_be_told_apart() {
        for (text, want) in [
            ("[[packet]]\nname = \"X\"", "needs an apid or a label"),
            ("[[packet]]\nlabel = \" \"\nname = \"X\"", "label is empty"),
            (
                "[[packet]]\nlabel = \"A B\"\nname = \"X\"\n[[packet]]\nlabel = \"A B\"\nname = \"Y\"",
                "duplicate label",
            ),
            (
                "[[packet]]\napid = 1\nname = \"X\"\n[[packet]]\napid = 1\nname = \"Y\"",
                "duplicate apid",
            ),
            (
                "[[packet]]\nlabel = \"A B\"\napid = 4096\nname = \"X\"",
                "must be 0 to 2047",
            ),
        ] {
            let err = Config::parse(text).unwrap_err();
            assert!(err.contains(want), "{text:?} gave {err:?}");
        }
    }
}
