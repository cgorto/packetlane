//! Space packets back to back, with no container around them.
//!
//! There is no sync marker in this format, so one bad header ends the
//! decode: nothing says where the next packet starts.

use super::{DecodeError, Decoder, Record, Step};
use crate::pure::ccsds::PrimaryHeader;

#[derive(Debug, Default)]
pub struct RawDecoder;

impl RawDecoder {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for RawDecoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step {
        let Some(header) = PrimaryHeader::parse(buf) else {
            return Step::NeedMore;
        };
        if header.version != 0 {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "packet version is not 0",
            });
        }
        // At most 6 + 65536 bytes, so a corrupt length cannot ask for much.
        let total = header.total_len();
        match buf.get(..total) {
            None => Step::NeedMore,
            Some(packet) => Step::Record {
                consumed: total,
                record: Record {
                    offset,
                    receive_time_ns: None,
                    label: None,
                    payload: packet.to_vec(),
                },
            },
        }
    }
}

/// True if `prefix` reads as packets: every header reachable by following
/// length fields has version 0, and there are at least three of them or they
/// end exactly where `prefix` does.
pub fn chains_as_packets(prefix: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut seen = 0usize;
    while let Some(header) = prefix.get(pos..).and_then(PrimaryHeader::parse) {
        if header.version != 0 {
            return false;
        }
        seen += 1;
        pos = pos.saturating_add(header.total_len());
    }
    seen >= 3 || (seen > 0 && pos == prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::{DecodeEnd, decode_all};
    use crate::pure::synth::Source;

    fn sample() -> Vec<u8> {
        let mut src = Source::new(0x1A3, 16380, 5);
        (0..8).flat_map(|_| src.emit()).collect()
    }

    #[test]
    fn reads_every_packet_with_offsets() {
        let data = sample();
        let (records, end) = decode_all(&mut RawDecoder::new(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), 8);
        assert_eq!(records[0].offset, 0);
        assert_eq!(records[1].offset, 11);
        let last = PrimaryHeader::parse(&records[7].payload).unwrap();
        assert_eq!(last.seq_count, 3); // 16380 + 7, wrapped
    }

    /// Cutting the file at any byte must give whole packets, then at most one
    /// truncation, and never a panic.
    #[test]
    fn truncation_at_every_offset() {
        let data = sample();
        for cut in 0..data.len() {
            let (records, end) = decode_all(&mut RawDecoder::new(), &data[..cut]);
            assert_eq!(records.len(), cut / 11, "cut at {cut}");
            if cut % 11 == 0 {
                assert_eq!(end, None, "cut at {cut}");
            } else {
                assert!(
                    matches!(end, Some(DecodeEnd::Truncated { .. })),
                    "cut at {cut}"
                );
            }
        }
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        // A cheap stand-in for fuzzing until cargo-fuzz is set up.
        let mut x = 0x2545F491u32;
        for len in 0..200usize {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = crate::pure::decode::sniff(&data);
            let _ = decode_all(&mut RawDecoder::new(), &data);
        }
    }
}
