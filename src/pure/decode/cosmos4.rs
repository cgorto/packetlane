//! Push decoder for COSMOS 4 packet log files (`COSMOS4_`).
//!
//! Layout (big-endian, see `docs/parsing.md` section 8):
//! - 128-byte ASCII file header: `COSMOS4_`, `CMD` or `TLM`, `_`, 32-byte
//!   space-padded config name, `_`, 83-byte space-padded hostname.
//! - Repeated entries:
//!   - 1 byte flags (`0x80` stored, `0x40` extra)
//!   - if extra: 4-byte length + that many bytes of JSON
//!   - 4-byte receive time seconds since the Unix epoch (unsigned big-endian)
//!   - 4-byte receive time microseconds (unsigned big-endian)
//!   - 1-byte target name length + name bytes
//!   - 1-byte packet name length + name bytes
//!   - 4-byte packet length + packet bytes

use super::{DecodeError, Decoder, MAX_ENTRY, Record, Step};

const HEADER_LEN: usize = 128;
const MAGIC_PREFIX_LEN: usize = 11;
const FLAG_STORED: u8 = 0x80;
const FLAG_EXTRA: u8 = 0x40;
const ALLOWED_FLAGS: u8 = FLAG_STORED | FLAG_EXTRA;
const MIN_AFTER_EXTRA: usize = 4 + 4 + 1 + 1 + 4;
const MIN_AFTER_TARGET: usize = 1 + 4;
const MIN_AFTER_PACKET_NAME: usize = 4;

#[derive(Debug, Default)]
pub struct Cosmos4Decoder {
    header_seen: bool,
}

impl Cosmos4Decoder {
    pub fn new() -> Self {
        Self::default()
    }
}

fn read_u32_be(buf: &[u8], pos: usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(pos..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn checked_within_max(pos: usize, len: usize, min_remaining: usize) -> Option<usize> {
    let end = pos.checked_add(len)?;
    let total_min = end.checked_add(min_remaining)?;
    (total_min <= MAX_ENTRY).then_some(end)
}

impl Decoder for Cosmos4Decoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step {
        if !self.header_seen {
            let Some(prefix) = buf.get(..MAGIC_PREFIX_LEN) else {
                return Step::NeedMore;
            };
            if prefix != b"COSMOS4_CMD" && prefix != b"COSMOS4_TLM" {
                return Step::Fatal(DecodeError::Implausible {
                    offset,
                    reason: "invalid COSMOS 4 file header",
                });
            }
            if buf.len() < HEADER_LEN {
                return Step::NeedMore;
            }
            self.header_seen = true;
            return Step::Skip {
                consumed: HEADER_LEN,
            };
        }

        let Some(&flags) = buf.first() else {
            return Step::NeedMore;
        };
        if flags & !ALLOWED_FLAGS != 0 {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "unknown COSMOS 4 entry flags",
            });
        }

        let mut pos: usize = 1;

        if flags & FLAG_EXTRA != 0 {
            let Some(raw_extra_len) = read_u32_be(buf, pos) else {
                return Step::NeedMore;
            };
            pos += 4;
            let Ok(extra_len) = usize::try_from(raw_extra_len) else {
                return Step::Fatal(DecodeError::Implausible {
                    offset,
                    reason: "COSMOS 4 extra data too large",
                });
            };
            let Some(after_extra) = checked_within_max(pos, extra_len, MIN_AFTER_EXTRA) else {
                return Step::Fatal(DecodeError::Implausible {
                    offset,
                    reason: "COSMOS 4 entry too large",
                });
            };
            if buf.len() < after_extra {
                return Step::NeedMore;
            }
            pos = after_extra;
        }

        let Some(secs) = read_u32_be(buf, pos) else {
            return Step::NeedMore;
        };
        pos += 4;

        let Some(usecs) = read_u32_be(buf, pos) else {
            return Step::NeedMore;
        };
        pos += 4;

        let Some(&target_len_u8) = buf.get(pos) else {
            return Step::NeedMore;
        };
        pos += 1;
        let target_len = usize::from(target_len_u8);
        let Some(target_end) = checked_within_max(pos, target_len, MIN_AFTER_TARGET) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 4 entry too large",
            });
        };
        let Some(target_bytes) = buf.get(pos..target_end) else {
            return Step::NeedMore;
        };
        pos = target_end;

        let Some(&packet_len_u8) = buf.get(pos) else {
            return Step::NeedMore;
        };
        pos += 1;
        let packet_len = usize::from(packet_len_u8);
        let Some(packet_end) = checked_within_max(pos, packet_len, MIN_AFTER_PACKET_NAME) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 4 entry too large",
            });
        };
        let Some(packet_bytes) = buf.get(pos..packet_end) else {
            return Step::NeedMore;
        };
        pos = packet_end;

        let Some(raw_payload_len) = read_u32_be(buf, pos) else {
            return Step::NeedMore;
        };
        pos += 4;
        let payload_start = pos;
        let Ok(payload_len) = usize::try_from(raw_payload_len) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 4 payload too large",
            });
        };
        let Some(entry_end) = checked_within_max(payload_start, payload_len, 0) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 4 entry too large",
            });
        };
        let Some(payload) = buf.get(payload_start..entry_end) else {
            return Step::NeedMore;
        };

        let Some(payload_offset) = offset.checked_add(payload_start as u64) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 4 offset out of range",
            });
        };

        let receive_time_ns = i64::from(secs) * 1_000_000_000 + i64::from(usecs) * 1_000;
        let label = format!(
            "{} {}",
            String::from_utf8_lossy(target_bytes),
            String::from_utf8_lossy(packet_bytes)
        );

        Step::Record {
            consumed: entry_end,
            record: Record {
                offset: payload_offset,
                receive_time_ns: Some(receive_time_ns),
                label: Some(label),
                payload: payload.to_vec(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::{DecodeEnd, Format, decode_all, decoder_for};
    use crate::pure::synth::{cosmos4_entry, cosmos4_header, packet};

    /// Hand-computed byte vector (not produced by the synthetic writers),
    /// covering both a plain entry and an entry with stored + extra flags.
    #[test]
    fn hand_written_vector() {
        let mut data: Vec<u8> = Vec::new();
        // 128-byte header:
        // "COSMOS4_TLM_" (12) + 32-byte config + "_" (1) + 83-byte host = 128
        data.extend_from_slice(b"COSMOS4_TLM_");
        data.extend_from_slice(b"SIM_CFG");
        data.extend_from_slice(&[b' '; 25]);
        data.push(b'_');
        data.extend_from_slice(b"HOST1");
        data.extend_from_slice(&[b' '; 78]);
        assert_eq!(data.len(), 128);

        // Entry 1 at byte 128:
        // flags=0x00, sec=1_700_000_000 (0x6553F100), usec=123_456 (0x0001E240),
        // target="SIM" (len 3), packet="HK" (len 2), payload=[0xDE, 0xAD, 0xBE, 0xEF] (len 4).
        // Payload starts at 128 + 1 + 4 + 4 + 1 + 3 + 1 + 2 + 4 = 148.
        data.extend_from_slice(&[
            0x00, // flags
            0x65, 0x53, 0xF1, 0x00, // seconds: 1_700_000_000
            0x00, 0x01, 0xE2, 0x40, // microseconds: 123_456
            0x03, b'S', b'I', b'M', // target: "SIM"
            0x02, b'H', b'K', // packet: "HK"
            0x00, 0x00, 0x00, 0x04, // payload len: 4
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ]);
        assert_eq!(data.len(), 152);

        // Entry 2 at byte 152:
        // flags=0xC0 (stored + extra), extra=b"{\"k\":123}" (len 9),
        // sec=1_700_000_001 (0x6553F101), usec=500 (0x000001F4),
        // target="NAV" (len 3), packet="POS" (len 3), payload=[0x01, 0x02] (len 2).
        // Payload starts at 152 + 1 + 4 + 9 + 4 + 4 + 1 + 3 + 1 + 3 + 4 = 186.
        data.extend_from_slice(&[
            0xC0, // flags: stored | extra
            0x00, 0x00, 0x00, 0x09, // extra len: 9
            b'{', b'"', b'k', b'"', b':', b'1', b'2', b'3', b'}', // extra JSON
            0x65, 0x53, 0xF1, 0x01, // seconds: 1_700_000_001
            0x00, 0x00, 0x01, 0xF4, // microseconds: 500
            0x03, b'N', b'A', b'V', // target: "NAV"
            0x03, b'P', b'O', b'S', // packet: "POS"
            0x00, 0x00, 0x00, 0x02, // payload len: 2
            0x01, 0x02, // payload
        ]);

        let (records, end) = decode_all(&mut Cosmos4Decoder::new(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), 2);

        assert_eq!(records[0].offset, 148);
        assert_eq!(records[0].receive_time_ns, Some(1_700_000_000_123_456_000));
        assert_eq!(records[0].label.as_deref(), Some("SIM HK"));
        assert_eq!(records[0].payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(records[1].offset, 186);
        assert_eq!(records[1].receive_time_ns, Some(1_700_000_001_000_500_000));
        assert_eq!(records[1].label.as_deref(), Some("NAV POS"));
        assert_eq!(records[1].payload, vec![0x01, 0x02]);
    }

    #[test]
    fn round_trip_through_writers() {
        let header = cosmos4_header(false, "TEST_CONFIG", "sim-host-01");
        assert_eq!(header.len(), 128);
        assert!(header.starts_with(b"COSMOS4_CMD_"));

        let items: &[(&str, &str, i64, Vec<u8>)] = &[
            (
                "SIM",
                "HK",
                1_700_000_000_001_000_000,
                packet(0x10, 0, &[1, 2]),
            ),
            (
                "NAV",
                "ATTITUDE",
                1_700_000_000_250_500_000,
                packet(0x20, 1, &[3, 4, 5]),
            ),
            ("PWR", "BUS", 1_700_000_001_999_999_000, vec![0xAA, 0xBB]),
            ("SIM", "STATUS", 1_700_000_002_000_000_000, vec![]),
        ];

        let mut data = header;
        for (target, pkt, time_ns, payload) in items {
            data.extend(cosmos4_entry(*time_ns, target, pkt, payload));
        }

        let mut dec = decoder_for(Format::Cosmos4).expect("cosmos4 decoder");
        let (records, end) = decode_all(dec.as_mut(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), items.len());

        for (rec, (target, pkt, time_ns, payload)) in records.iter().zip(items) {
            assert_eq!(rec.receive_time_ns, Some(*time_ns));
            assert_eq!(
                rec.label.as_deref(),
                Some(format!("{target} {pkt}")).as_deref()
            );
            assert_eq!(&rec.payload, payload);
            let off = rec.offset as usize;
            assert_eq!(&data[off..off + payload.len()], payload.as_slice());
        }
    }

    #[test]
    fn truncation_at_every_offset() {
        let mut data = cosmos4_header(true, "CFG", "HOST");
        // Include a normal entry, an entry with extra JSON, and another normal entry.
        data.extend(cosmos4_entry(
            1_700_000_000_000_000_000,
            "SIM",
            "HK",
            &[1, 2, 3],
        ));
        let boundary1 = data.len();
        data.extend_from_slice(&[
            0x40, // extra flag
            0x00, 0x00, 0x00, 0x02, b'{', b'}', // extra JSON
            0x65, 0x53, 0xF1, 0x01, // sec
            0x00, 0x00, 0x00, 0x0A, // usec
            0x03, b'N', b'A', b'V', // target
            0x02, b'I', b'D', // packet
            0x00, 0x00, 0x00, 0x03, 0x10, 0x20, 0x30, // payload
        ]);
        let boundary2 = data.len();
        data.extend(cosmos4_entry(1_700_000_002_000_000_000, "PWR", "BAT", &[9]));

        let (full_records, full_end) = decode_all(&mut Cosmos4Decoder::new(), &data);
        assert_eq!(full_end, None);
        assert_eq!(full_records.len(), 3);

        for cut in 0..=data.len() {
            let (records, end) = decode_all(&mut Cosmos4Decoder::new(), &data[..cut]);
            assert_eq!(
                records.as_slice(),
                &full_records[..records.len()],
                "cut at {cut}"
            );
            let is_clean_boundary =
                cut == 0 || cut == 128 || cut == boundary1 || cut == boundary2 || cut == data.len();
            if is_clean_boundary {
                assert_eq!(end, None, "cut at {cut}");
            } else {
                assert!(
                    matches!(end, Some(DecodeEnd::Truncated { .. })),
                    "expected Truncated at cut {cut}, got {end:?}"
                );
            }
        }
    }

    #[test]
    fn random_bytes_after_header_do_not_panic() {
        let header = cosmos4_header(true, "CFG", "HOST");
        let mut x = 0x9E37_79B9u32;
        for len in 0..256usize {
            let mut data = header.clone();
            data.extend((0..len).map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            }));
            let _ = decode_all(&mut Cosmos4Decoder::new(), &data);
        }
    }

    #[test]
    fn fatal_conditions() {
        // 1. Bad magic prefix.
        let mut bad_magic = vec![b' '; 128];
        bad_magic[..12].copy_from_slice(b"COSMOS5_TLM_");
        let (_, end) = decode_all(&mut Cosmos4Decoder::new(), &bad_magic);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset: 0, .. }))
        ));

        // 2. Bad type after COSMOS4_ (neither CMD nor TLM).
        let mut bad_kind = vec![b' '; 128];
        bad_kind[..12].copy_from_slice(b"COSMOS4_XYZ_");
        let (_, end) = decode_all(&mut Cosmos4Decoder::new(), &bad_kind);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset: 0, .. }))
        ));

        // 3. Unknown flag bits (anything outside 0x80 | 0x40).
        for bad_flag in [0x01u8, 0x02, 0x10, 0x20, 0x3F, 0x81, 0xC1, 0xFF] {
            let mut data = cosmos4_header(true, "CFG", "HOST");
            data.push(bad_flag);
            data.extend_from_slice(&[0u8; 32]);
            let (_, end) = decode_all(&mut Cosmos4Decoder::new(), &data);
            assert!(
                matches!(
                    end,
                    Some(DecodeEnd::Error(DecodeError::Implausible {
                        offset: 128,
                        ..
                    }))
                ),
                "flag {bad_flag:#x} should be Fatal"
            );
        }

        // 4. Extra length exceeding MAX_ENTRY (must fail immediately without needing MAX_ENTRY bytes).
        let mut big_extra = cosmos4_header(true, "CFG", "HOST");
        big_extra.push(0x40);
        big_extra.extend_from_slice(&((MAX_ENTRY as u32) + 1).to_be_bytes());
        let (_, end) = decode_all(&mut Cosmos4Decoder::new(), &big_extra);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible {
                offset: 128,
                ..
            }))
        ));

        // 5. Payload length exceeding MAX_ENTRY.
        let mut big_payload = cosmos4_header(true, "CFG", "HOST");
        big_payload.extend_from_slice(&[
            0x00, // flags
            0, 0, 0, 1, // sec
            0, 0, 0, 0, // usec
            1, b'T', // target
            1, b'P', // packet
        ]);
        big_payload.extend_from_slice(&((MAX_ENTRY as u32) + 1).to_be_bytes());
        let (_, end) = decode_all(&mut Cosmos4Decoder::new(), &big_payload);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible {
                offset: 128,
                ..
            }))
        ));
    }

    #[test]
    fn lossy_utf8_in_names() {
        let mut data = cosmos4_header(true, "CFG", "HOST");
        data.extend_from_slice(&[
            0x00, // flags
            0, 0, 0, 1, // sec
            0, 0, 0, 0, // usec
            0x02, b'T', 0xFF, // invalid UTF-8 target
            0x02, 0xFE, b'P', // invalid UTF-8 packet
            0x00, 0x00, 0x00, 0x01, 0x42, // payload
        ]);
        let (records, end) = decode_all(&mut Cosmos4Decoder::new(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label.as_deref(), Some("T\u{FFFD} \u{FFFD}P"));
    }
}
