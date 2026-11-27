//! Push decoder for COSMOS 4 packet log files, in both layouts that COSMOS 4
//! wrote: `COSMOS2_` (up to 4.2) and `COSMOS4_` (4.3 on). It also reads the
//! 42-byte header of COSMOS 1 (`COSMOS`, `CMD` or `TLM`, a separator, a
//! 32-byte config name), whose entries are the same as under `COSMOS2_`.
//!
//! Layout (big-endian, see `docs/parsing.md` section 8):
//! - 128-byte ASCII file header: `COSMOS4_` or `COSMOS2_`, `CMD` or `TLM`, `_`, 32-byte
//!   space-padded config name, `_`, 83-byte space-padded hostname.
//! - Repeated entries:
//!   - `COSMOS4_` only: 1 byte flags (`0x80` stored, `0x40` extra)
//!   - `COSMOS4_` only, if extra: 4-byte length + that many bytes of JSON
//!   - 4-byte receive time seconds since the Unix epoch (unsigned big-endian)
//!   - 4-byte receive time microseconds (unsigned big-endian)
//!   - 1-byte target name length + name bytes
//!   - 1-byte packet name length + name bytes
//!   - 4-byte packet length + packet bytes

use super::{DecodeError, Decoder, MAX_ENTRY, Record, Step};

const HEADER_LEN: usize = 128;
const COSMOS1_HEADER_LEN: usize = 42;
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
    /// True for `COSMOS4_`: entries begin with a flags byte.
    has_flags: bool,
    /// From the file header: the configuration name and the logging host.
    config: String,
    hostname: String,
    /// From the first SYSTEM META packet: the configuration name and the
    /// COSMOS version that wrote the file.
    meta: Option<(String, String)>,
}

/// Text from a fixed-width field: printable ASCII only, padding trimmed.
/// The bytes come from the file, so nothing else is let through.
fn field_text(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|&b| char::from(b))
        .collect();
    text.trim().to_string()
}

/// True if `prefix` starts with the 42-byte header that COSMOS 1 wrote:
/// `COSMOS`, then `CMD` or `TLM` in either case.
pub fn is_cosmos1(prefix: &[u8]) -> bool {
    prefix.get(..6) == Some(b"COSMOS")
        && prefix
            .get(6..9)
            .is_some_and(|t| t.eq_ignore_ascii_case(b"CMD") || t.eq_ignore_ascii_case(b"TLM"))
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
            // (header length, has flags, where the config name is, where the hostname is)
            let (header_len, has_flags, config, hostname) = match prefix {
                b"COSMOS4_CMD" | b"COSMOS4_TLM" => (HEADER_LEN, true, 12..44, 45..HEADER_LEN),
                b"COSMOS2_CMD" | b"COSMOS2_TLM" => (HEADER_LEN, false, 12..44, 45..HEADER_LEN),
                _ if is_cosmos1(prefix) => (COSMOS1_HEADER_LEN, false, 10..42, 0..0),
                _ => {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "invalid COSMOS 4 file header",
                    });
                }
            };
            let Some(header) = buf.get(..header_len) else {
                return Step::NeedMore;
            };
            self.has_flags = has_flags;
            self.config = field_text(&header[config]);
            self.hostname = field_text(&header[hostname]);
            self.header_seen = true;
            return Step::Skip {
                consumed: header_len,
            };
        }

        let mut pos: usize = 0;
        let mut flags = 0u8;
        if self.has_flags {
            let Some(&byte) = buf.first() else {
                return Step::NeedMore;
            };
            flags = byte;
            pos = 1;
        }
        if flags & !ALLOWED_FLAGS != 0 {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "unknown COSMOS 4 entry flags",
            });
        }

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

        // SYSTEM META: byte 0 is a packet id, bytes 1..33 the configuration
        // name, bytes 33..63 the COSMOS version. COSMOS itself requires 33.
        if self.meta.is_none()
            && target_bytes == b"SYSTEM"
            && packet_bytes == b"META"
            && let Some(config) = payload.get(1..33)
        {
            let version = payload.get(33..63).unwrap_or_default();
            self.meta = Some((field_text(config), field_text(version)));
        }

        let receive_time_ns = i64::from(secs) * 1_000_000_000 + i64::from(usecs) * 1_000;
        let target = String::from_utf8_lossy(target_bytes);
        let packet = String::from_utf8_lossy(packet_bytes);
        let mut label = String::with_capacity(target.len() + 1 + packet.len());
        label.push_str(&target);
        label.push(' ');
        label.push_str(&packet);

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

    /// For example `COSMOS config SIM_CFG on bench-a, COSMOS 4.2.4`. The
    /// name in SYSTEM META wins over the one in the file header: it is what
    /// COSMOS itself switches configuration on.
    fn describe(&self) -> Option<String> {
        let (meta_config, version) = match &self.meta {
            Some((config, version)) => (config.as_str(), version.as_str()),
            None => ("", ""),
        };
        let config = if meta_config.is_empty() {
            &self.config
        } else {
            meta_config
        };
        let mut place = Vec::new();
        if !config.is_empty() {
            place.push(format!("config {config}"));
        }
        if !self.hostname.is_empty() {
            place.push(format!("on {}", self.hostname));
        }
        let mut parts = Vec::new();
        if !place.is_empty() {
            parts.push(place.join(" "));
        }
        if !version.is_empty() {
            parts.push(format!("version {version}"));
        }
        (!parts.is_empty()).then(|| format!("COSMOS {}", parts.join(", ")))
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

        let mut dec = decoder_for(Format::Cosmos4, &Default::default()).expect("cosmos4 decoder");
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

    /// Hand-computed from the COSMOS 4.2.4 writer: a `COSMOS2_` header and
    /// entries with no flags byte. The file opens, as a 4.2.4 log does, with
    /// a SYSTEM META packet that is not a space packet.
    #[test]
    fn cosmos2_hand_written_vector() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"COSMOS2_TLM_");
        data.extend_from_slice(b"SIM_CFG");
        data.extend_from_slice(&[b' '; 25]);
        data.push(b'_');
        data.extend_from_slice(b"HOST1");
        data.extend_from_slice(&[b' '; 78]);
        assert_eq!(data.len(), 128);

        // Entry 1 at byte 128. Payload starts at 128 + 4 + 4 + 1 + 6 + 1 + 4 + 4 = 152.
        // Its first byte, 0x65, would be an unknown flags value if this
        // layout were read as `COSMOS4_`.
        data.extend_from_slice(&[
            0x65, 0x53, 0xF1, 0x00, // seconds: 1_700_000_000
            0x00, 0x01, 0xE2, 0x40, // microseconds: 123_456
            0x06, b'S', b'Y', b'S', b'T', b'E', b'M', // target
            0x04, b'M', b'E', b'T', b'A', // packet
            0x00, 0x00, 0x00, 0x04, // payload len: 4
            0x01, b'C', b'F', b'G', // payload
        ]);
        assert_eq!(data.len(), 156);

        // Entry 2 at byte 156. Payload starts at 156 + 4 + 4 + 1 + 3 + 1 + 2 + 4 = 175.
        data.extend_from_slice(&[
            0x65, 0x53, 0xF1, 0x01, // seconds: 1_700_000_001
            0x00, 0x00, 0x01, 0xF4, // microseconds: 500
            0x03, b'S', b'I', b'M', // target
            0x02, b'H', b'K', // packet
            0x00, 0x00, 0x00, 0x07, // payload len: 7
            0x00, 0x64, 0xC0, 0x00, 0x00, 0x00, 0xAB, // one space packet, APID 100
        ]);

        assert_eq!(crate::pure::decode::sniff(&data), Format::Cosmos2);
        let mut dec = decoder_for(Format::Cosmos2, &Default::default()).expect("decoder");
        let (records, end) = decode_all(dec.as_mut(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), 2);

        assert_eq!(records[0].offset, 152);
        assert_eq!(records[0].receive_time_ns, Some(1_700_000_000_123_456_000));
        assert_eq!(records[0].label.as_deref(), Some("SYSTEM META"));
        assert_eq!(records[0].payload, vec![0x01, b'C', b'F', b'G']);

        assert_eq!(records[1].offset, 175);
        assert_eq!(records[1].receive_time_ns, Some(1_700_000_001_000_500_000));
        assert_eq!(records[1].label.as_deref(), Some("SIM HK"));
        assert_eq!(
            records[1].payload,
            vec![0x00, 0x64, 0xC0, 0x00, 0x00, 0x00, 0xAB]
        );
    }

    #[test]
    fn cosmos2_truncation_at_every_offset() {
        use crate::pure::synth::{cosmos2_entry, cosmos2_header};
        let mut data = cosmos2_header(true, "CFG", "HOST");
        let mut ends = vec![data.len()];
        for (i, payload) in [&[1u8, 2, 3][..], &packet(0x10, 0, &[4, 5]), &[9]]
            .iter()
            .enumerate()
        {
            let t = 1_700_000_000_000_000_000 + i as i64 * 1_000_000_000;
            data.extend(cosmos2_entry(t, "SIM", "HK", payload));
            ends.push(data.len());
        }
        for cut in 0..=data.len() {
            let (records, end) = decode_all(&mut Cosmos4Decoder::new(), &data[..cut]);
            let whole = ends.iter().filter(|&&e| e <= cut).count().saturating_sub(1);
            assert_eq!(records.len(), whole, "cut at {cut}");
            if cut == 0 || ends.contains(&cut) {
                assert_eq!(end, None, "cut at {cut}");
            } else {
                assert!(
                    matches!(end, Some(DecodeEnd::Truncated { .. })),
                    "cut at {cut}"
                );
            }
        }
    }

    /// The two layouts differ only by the flags byte, so the header must
    /// decide: the same entries under the other header do not read the same.
    #[test]
    fn the_header_selects_the_layout() {
        use crate::pure::synth::{cosmos2_entry, cosmos2_header};
        let entry2 = cosmos2_entry(1_700_000_000_000_000_000, "SIM", "HK", &[1, 2, 3]);
        let entry4 = cosmos4_entry(1_700_000_000_000_000_000, "SIM", "HK", &[1, 2, 3]);
        let read = |header: Vec<u8>, entry: &[u8]| {
            decode_all(&mut Cosmos4Decoder::new(), &[&header[..], entry].concat())
        };
        let good2 = read(cosmos2_header(true, "C", "H"), &entry2);
        let good4 = read(cosmos4_header(true, "C", "H"), &entry4);
        assert_eq!(good2.1, None);
        assert_eq!(good2.0[0].payload, good4.0[0].payload);
        assert_eq!(good2.0[0].receive_time_ns, good4.0[0].receive_time_ns);
        // 0x65, the top byte of the seconds, is not a valid flags byte.
        let (records, end) = read(cosmos4_header(true, "C", "H"), &entry2);
        assert!(records.is_empty());
        assert!(matches!(end, Some(DecodeEnd::Error(_))));
        assert_ne!(read(cosmos2_header(true, "C", "H"), &entry4).0, good4.0);
    }

    /// The 42-byte COSMOS 1 header, laid out as the COSMOS 4.2.4 reader
    /// expects it: marker 0..6, log type 6..9, config name 10..42. Entries
    /// are the same as under `COSMOS2_`.
    #[test]
    fn cosmos1_hand_written_vector() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"COSMOStlm_");
        data.extend_from_slice(b"OLD_CFG");
        data.extend_from_slice(&[b' '; 25]);
        assert_eq!(data.len(), 42);
        // Entry at byte 42. Payload starts at 42 + 4 + 4 + 1 + 3 + 1 + 2 + 4 = 61.
        data.extend_from_slice(&[
            0x65, 0x53, 0xF1, 0x00, // seconds: 1_700_000_000
            0x00, 0x00, 0x00, 0x07, // microseconds: 7
            0x03, b'S', b'I', b'M', // target
            0x02, b'H', b'K', // packet
            0x00, 0x00, 0x00, 0x02, // payload len: 2
            0xCA, 0xFE, // payload
        ]);

        assert_eq!(crate::pure::decode::sniff(&data), Format::Cosmos1);
        let mut dec = decoder_for(Format::Cosmos1, &Default::default()).expect("decoder");
        let (records, end) = decode_all(dec.as_mut(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 61);
        assert_eq!(records[0].receive_time_ns, Some(1_700_000_000_000_007_000));
        assert_eq!(records[0].label.as_deref(), Some("SIM HK"));
        assert_eq!(records[0].payload, vec![0xCA, 0xFE]);
        assert_eq!(dec.describe().as_deref(), Some("COSMOS config OLD_CFG"));

        // Cut anywhere: no panic, and never more than the one record.
        for cut in 0..data.len() {
            let (records, _) = decode_all(&mut Cosmos4Decoder::new(), &data[..cut]);
            assert!(records.is_empty(), "cut at {cut}");
        }
    }

    /// A SYSTEM META payload as COSMOS 4.2.4 lays it out: packet id, 32-byte
    /// configuration name, 30-byte COSMOS version, then more.
    fn system_meta(config: &[u8], version: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(config);
        out.resize(33, 0);
        out.extend_from_slice(version);
        out.resize(123, 0);
        out
    }

    #[test]
    fn describes_the_file_from_its_header_and_system_meta() {
        use crate::pure::synth::{cosmos2_entry, cosmos2_header};
        let t = 1_700_000_000_000_000_000;
        let describe = |data: &[u8]| {
            let mut dec = Cosmos4Decoder::new();
            let (_, end) = decode_all(&mut dec, data);
            assert_eq!(end, None);
            dec.describe()
        };

        // Nothing read yet: nothing to say.
        assert_eq!(Cosmos4Decoder::new().describe(), None);

        // Header only.
        let header = cosmos2_header(true, "HDR_CFG", "bench-a");
        assert_eq!(
            describe(&header).as_deref(),
            Some("COSMOS config HDR_CFG on bench-a")
        );

        // SYSTEM META names the configuration COSMOS actually used, and the
        // version. The first one in the file is the one reported.
        let mut data = header.clone();
        data.extend(cosmos2_entry(
            t,
            "SYSTEM",
            "META",
            &system_meta(b"META_CFG", b"4.2.4"),
        ));
        data.extend(cosmos2_entry(t, "SIM", "HK", &packet(0x10, 0, &[1])));
        data.extend(cosmos2_entry(
            t,
            "SYSTEM",
            "META",
            &system_meta(b"LATER", b"9.9.9"),
        ));
        assert_eq!(
            describe(&data).as_deref(),
            Some("COSMOS config META_CFG on bench-a, version 4.2.4")
        );

        // A META too short to hold a configuration name is ignored, as
        // COSMOS ignores it; so is a packet that only shares the name META.
        let mut data = header.clone();
        data.extend(cosmos2_entry(t, "SYSTEM", "META", &[1, b'X']));
        data.extend(cosmos2_entry(
            t,
            "SIM",
            "META",
            &system_meta(b"WRONG", b"1"),
        ));
        assert_eq!(
            describe(&data).as_deref(),
            Some("COSMOS config HDR_CFG on bench-a")
        );

        // The text comes from the file: only printable ASCII gets through.
        let mut data = cosmos2_header(true, "", "");
        data.extend(cosmos2_entry(
            t,
            "SYSTEM",
            "META",
            &system_meta(b"A\x1b[31m<b>\xffB\nC", b"4.2\r\n.4"),
        ));
        assert_eq!(
            describe(&data).as_deref(),
            Some("COSMOS config A[31m<b>BC, version 4.2.4")
        );
    }
}
