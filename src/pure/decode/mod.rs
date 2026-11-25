//! Decoders turn the bytes of a log file into [`Record`]s.
//!
//! A decoder is a push parser: the shell hands it whatever bytes it has, and
//! the decoder says what it found and how many bytes that used. It never
//! reads anything itself. `docs/parsing.md` explains how to write one.

use std::fmt;

use crate::pure::config::Config;

pub mod cadu;
pub mod cosmos4;
pub mod cosmos5;
pub mod raw;

/// No single entry in any supported format may be larger than this. A length
/// field that says otherwise is corruption.
pub const MAX_ENTRY: usize = 16 * 1024 * 1024;

/// One logged item, as found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Byte offset in the file of the first byte of `payload`.
    pub offset: u64,
    /// When the logging host received it, in nanoseconds since the Unix
    /// epoch, if the container records that.
    pub receive_time_ns: Option<i64>,
    /// The container's own name for the item, if it stores one.
    pub label: Option<String>,
    /// What was logged. Usually one space packet, but containers store
    /// whatever their interfaces deliver, so check before trusting it.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes at `offset` cannot be what the format says they should be.
    Implausible { offset: u64, reason: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Implausible { offset, reason } => {
                write!(f, "Stopped at byte {offset:#x}: {reason}")
            }
        }
    }
}

/// The result of offering a decoder some bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// One record. Drop `consumed` bytes from the front and call again.
    Record { consumed: usize, record: Record },
    /// `consumed` bytes of structure (a file header, a declaration) that
    /// produced no record. Drop them and call again.
    Skip { consumed: usize },
    /// The next entry is not complete in the bytes offered. Call again with
    /// the same bytes plus more. At end of file this means a truncated tail.
    NeedMore,
    /// The decoder cannot continue. Do not call it again.
    Fatal(DecodeError),
}

/// A push parser for one file format.
///
/// Rules every decoder follows:
///
/// - `buf` starts at the first unconsumed byte; `offset` is where that byte
///   sits in the file.
/// - `consumed` is never zero.
/// - It never asks for more than [`MAX_ENTRY`] bytes: an entry that claims to
///   be larger is `Fatal`, not `NeedMore`.
/// - It never panics, whatever the bytes are.
pub trait Decoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step;

    /// What the file says about itself, learned while decoding: for example
    /// the configuration and host a COSMOS log was written with. Ask after
    /// the last step. Most formats say nothing.
    fn describe(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Starts with `COSMOS` and `CMD` or `TLM`: the 42-byte header of COSMOS 1.
    Cosmos1,
    /// Starts with `COSMOS2_`: what COSMOS 4 wrote up to version 4.2.
    Cosmos2,
    /// Starts with `COSMOS4_`: COSMOS 4.3 on.
    Cosmos4,
    /// Starts with `COSMOS5_`.
    Cosmos5,
    /// Sync markers at a fixed spacing, each followed by a transfer frame.
    Cadu {
        cadu_len: usize,
    },
    /// Space packets back to back with no container.
    RawCcsds,
    /// Lines of text.
    Text,
    /// Compressed. Decompress a copy first.
    Gzip,
    Empty,
    Unknown,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Cosmos1 => "cosmos1",
            Format::Cosmos2 => "cosmos2",
            Format::Cosmos4 => "cosmos4",
            Format::Cosmos5 => "cosmos5",
            Format::Cadu { .. } => "cadu",
            Format::RawCcsds => "raw",
            Format::Text => "text",
            Format::Gzip => "gzip",
            Format::Empty => "empty",
            Format::Unknown => "unknown",
        }
    }

    /// True if the format was recognised by a magic number or by sync markers
    /// at a fixed spacing, not guessed.
    pub fn is_certain(self) -> bool {
        matches!(
            self,
            Format::Cosmos2
                | Format::Cosmos4
                | Format::Cosmos5
                | Format::Cadu { .. }
                | Format::Gzip
                | Format::Empty
        )
    }
}

/// How many leading bytes are worth passing to [`sniff`].
pub const SNIFF_LEN: usize = 256 * 1024;

/// Guesses the format from the first bytes of a file.
///
/// Magic numbers are certain, and so are sync markers at a fixed spacing:
/// that check comes before the packet one because a sync marker also reads
/// as a version-0 packet header. `RawCcsds` is a guess: every packet header
/// reachable by following length fields through `prefix` has version 0, and
/// there are at least three of them or they end exactly where `prefix` does.
/// `Text` is a guess too: valid UTF-8 with almost no control characters.
pub fn sniff(prefix: &[u8]) -> Format {
    if prefix.is_empty() {
        Format::Empty
    } else if prefix.starts_with(b"COSMOS2_") {
        Format::Cosmos2
    } else if prefix.starts_with(b"COSMOS4_") {
        Format::Cosmos4
    } else if prefix.starts_with(b"COSMOS5_") {
        Format::Cosmos5
    } else if cosmos4::is_cosmos1(prefix) {
        Format::Cosmos1
    } else if prefix.starts_with(&[0x1F, 0x8B]) {
        Format::Gzip
    } else if let Some(cadu_len) = cadu::sniff_cadu_len(prefix) {
        Format::Cadu { cadu_len }
    } else if raw::chains_as_packets(prefix) {
        Format::RawCcsds
    } else if looks_like_text(prefix) {
        Format::Text
    } else {
        Format::Unknown
    }
}

fn looks_like_text(prefix: &[u8]) -> bool {
    // The prefix may end partway through a multi-byte character.
    let text = match std::str::from_utf8(prefix) {
        Ok(s) => s,
        Err(e) if e.error_len().is_none() => {
            match std::str::from_utf8(&prefix[..e.valid_up_to()]) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
        Err(_) => return false,
    };
    let total = text.chars().count();
    let odd = text
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    total > 0 && odd * 100 <= total
}

/// The decoder for a packet format, or `None` if the format holds no packets
/// or has no decoder. Only CADU files need anything from `config`: how their
/// frames are laid out is not written in the file.
pub fn decoder_for(format: Format, config: &Config) -> Option<Box<dyn Decoder>> {
    match format {
        // One decoder: it tells the two layouts apart by the file header.
        Format::Cosmos1 | Format::Cosmos2 | Format::Cosmos4 => {
            Some(Box::new(cosmos4::Cosmos4Decoder::new()))
        }
        Format::Cosmos5 => Some(Box::new(cosmos5::Cosmos5Decoder::new())),
        Format::Cadu { cadu_len } => {
            let decoder = cadu::CaduDecoder::new(config.frame_params(cadu_len))?;
            Some(Box::new(decoder))
        }
        Format::RawCcsds => Some(Box::new(raw::RawDecoder::new())),
        _ => None,
    }
}

/// Runs a decoder over a complete in-memory file. Returns the records, and
/// the error that stopped it, if one did. For tests and small inputs; the
/// shell streams instead.
pub fn decode_all(decoder: &mut dyn Decoder, data: &[u8]) -> (Vec<Record>, Option<DecodeEnd>) {
    let mut records = Vec::new();
    let mut pos = 0usize;
    loop {
        match decoder.step(&data[pos..], pos as u64) {
            Step::Record { consumed, record } => {
                records.push(record);
                pos += consumed.max(1);
            }
            Step::Skip { consumed } => pos += consumed.max(1),
            Step::NeedMore => {
                let end = (pos < data.len()).then_some(DecodeEnd::Truncated {
                    offset: pos as u64,
                    available: data.len() - pos,
                });
                return (records, end);
            }
            Step::Fatal(e) => return (records, Some(DecodeEnd::Error(e))),
        }
        if pos > data.len() {
            return (records, None);
        }
    }
}

/// Why decoding stopped before the end of the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeEnd {
    /// The data ends partway through an entry. Normal for a log that is still
    /// being written, or was cut off.
    Truncated {
        offset: u64,
        available: usize,
    },
    Error(DecodeError),
}

impl fmt::Display for DecodeEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeEnd::Truncated { offset, available } => {
                let unit = if *available == 1 { "byte" } else { "bytes" };
                write!(
                    f,
                    "Truncated at byte {offset:#x} ({available} incomplete {unit})"
                )
            }
            DecodeEnd::Error(e) => e.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::synth::Source;

    #[test]
    fn sniffs_formats() {
        let mut src = Source::new(0x1A3, 0, 5);
        let packets: Vec<u8> = (0..8).flat_map(|_| src.emit()).collect();
        assert_eq!(sniff(b"COSMOStlm_"), Format::Cosmos1);
        assert_eq!(sniff(b"COSMOS is a ground system\n"), Format::Text);
        assert_eq!(sniff(b"COSMOS2_TLM_"), Format::Cosmos2);
        assert_eq!(sniff(b"COSMOS4_TLM_"), Format::Cosmos4);
        assert_eq!(sniff(b"COSMOS5_"), Format::Cosmos5);
        assert_eq!(sniff(&packets), Format::RawCcsds);
        assert_eq!(sniff(&[0x1F, 0x8B, 8, 0]), Format::Gzip);
        assert_eq!(
            sniff(b"2026-01-02 03:04:05 started\nnext line\n"),
            Format::Text
        );
        assert_eq!(sniff(&[0xFF; 32]), Format::Unknown);
        assert_eq!(sniff(b"abc\xff"), Format::Unknown);
        assert_eq!(sniff(b"a\xff\xff\xff"), Format::Unknown);
        assert_eq!(sniff(&[]), Format::Empty);
        // A sync marker reads as a version-0 packet header, so CADUs must be
        // recognised before packets are.
        let cadus =
            crate::pure::synth::demo_cadus(&Config::default().frame_params(64), &packets.repeat(4));
        assert_eq!(sniff(&cadus), Format::Cadu { cadu_len: 64 });
        // Sync markers alone must not pass as frames, packets or text.
        assert_eq!(sniff(&[0x1A, 0xCF, 0xFC, 0x1D].repeat(50)), Format::Unknown);
    }

    #[test]
    fn text_cut_inside_a_character_is_still_text() {
        let s = "temperature 21 °C\n".repeat(4);
        let bytes = s.as_bytes();
        assert_eq!(sniff(&bytes[..bytes.len() - 3]), Format::Text);
    }
}
