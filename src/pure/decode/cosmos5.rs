//! Push decoder for COSMOS 5 packet log files (`COSMOS5_`).
//!
//! Layout (big-endian, see `docs/parsing.md` section 8):
//! - 8-byte magic: `COSMOS5_`
//! - Repeated entries, each a 4-byte length (counting what follows it), a
//!   2-byte flags field, and a body determined by `flags & 0xF000`:
//!   - `0x1000` target declaration: target name; optional trailing 32-byte id if `0x0200`
//!   - `0x2000` packet declaration: 2-byte target index, packet name; optional trailing 32-byte id if `0x0200`.
//!     Target indexes do not start at 0 in every file: see the comment where they are read.
//!   - `0x3000` raw packet: 2-byte packet index, 8-byte time in ns since Unix epoch, payload bytes
//!   - `0x4000` JSON packet: 2-byte packet index, 8-byte time, JSON text (skipped)
//!   - `0x5000` offset marker: string (skipped)

use super::{DecodeError, Decoder, MAX_ENTRY, Record, Step};

const MAGIC: &[u8; 8] = b"COSMOS5_";
const TYPE_MASK: u16 = 0xF000;
const TYPE_TARGET_DECL: u16 = 0x1000;
const TYPE_PACKET_DECL: u16 = 0x2000;
const TYPE_RAW_PACKET: u16 = 0x3000;
const TYPE_JSON_PACKET: u16 = 0x4000;
const TYPE_OFFSET_MARKER: u16 = 0x5000;
const FLAG_HAS_ID: u16 = 0x0200;
const ID_LEN: usize = 32;
const RAW_PACKET_HEADER_LEN: u64 = 4 + 2 + 2 + 8;

#[derive(Debug, Default)]
pub struct Cosmos5Decoder {
    magic_seen: bool,
    targets: Vec<String>,
    /// The number the writer gave the first target declared in this file.
    /// Known once a packet declaration refers to it.
    target_base: Option<u16>,
    packets: Vec<String>,
}

impl Cosmos5Decoder {
    pub fn new() -> Self {
        Self::default()
    }
}

fn read_u16_be(buf: &[u8], pos: usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let bytes: [u8; 2] = buf.get(pos..end)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_u32_be(buf: &[u8], pos: usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(pos..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn read_u64_be(buf: &[u8], pos: usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let bytes: [u8; 8] = buf.get(pos..end)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

impl Decoder for Cosmos5Decoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step {
        if !self.magic_seen {
            let Some(magic) = buf.get(..MAGIC.len()) else {
                return Step::NeedMore;
            };
            if magic != MAGIC {
                return Step::Fatal(DecodeError::Implausible {
                    offset,
                    reason: "invalid COSMOS 5 file header",
                });
            }
            self.magic_seen = true;
            return Step::Skip {
                consumed: MAGIC.len(),
            };
        }

        let Some(raw_len) = read_u32_be(buf, 0) else {
            return Step::NeedMore;
        };
        let Ok(entry_len) = usize::try_from(raw_len) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 5 entry too large",
            });
        };
        let Some(total) = 4usize.checked_add(entry_len).filter(|&n| n <= MAX_ENTRY) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 5 entry too large",
            });
        };
        if entry_len < 2 {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 5 entry too short",
            });
        }

        let Some(flags) = read_u16_be(buf, 4) else {
            return Step::NeedMore;
        };
        let entry_type = flags & TYPE_MASK;
        let has_id = (flags & FLAG_HAS_ID) != 0;

        let min_len = match entry_type {
            TYPE_TARGET_DECL => 2 + if has_id { ID_LEN } else { 0 },
            TYPE_PACKET_DECL => 2 + 2 + if has_id { ID_LEN } else { 0 },
            TYPE_RAW_PACKET | TYPE_JSON_PACKET => 2 + 2 + 8,
            TYPE_OFFSET_MARKER => 2,
            _ => {
                return Step::Fatal(DecodeError::Implausible {
                    offset,
                    reason: "unknown COSMOS 5 entry type",
                });
            }
        };
        if entry_len < min_len {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 5 entry too short",
            });
        }

        let Some(entry) = buf.get(..total) else {
            return Step::NeedMore;
        };
        let Some(body) = entry.get(6..) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "COSMOS 5 entry too short",
            });
        };

        match entry_type {
            TYPE_TARGET_DECL => {
                let name_end = if has_id {
                    body.len().checked_sub(ID_LEN)
                } else {
                    Some(body.len())
                };
                let Some(name_bytes) = name_end.and_then(|end| body.get(..end)) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 target declaration too short",
                    });
                };
                self.targets
                    .push(String::from_utf8_lossy(name_bytes).into_owned());
                Step::Skip { consumed: total }
            }
            TYPE_PACKET_DECL => {
                let Some(target_idx) = read_u16_be(body, 0) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet declaration too short",
                    });
                };
                // The COSMOS 5 writer numbers packets from 0 in each file but
                // targets across every file it has written, so the first
                // target declared here may have any number. A target is
                // declared just before the first packet that refers to it,
                // which fixes what the numbers in this file start from.
                let declared = u16::try_from(self.targets.len()).unwrap_or(u16::MAX);
                let base = *self
                    .target_base
                    .get_or_insert(target_idx.saturating_sub(declared.saturating_sub(1)));
                let known = target_idx
                    .checked_sub(base)
                    .and_then(|i| self.targets.get(usize::from(i)));
                let Some(target_name) = known else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet declaration names unknown target",
                    });
                };
                let name_end = if has_id {
                    body.len().checked_sub(ID_LEN)
                } else {
                    Some(body.len())
                };
                let Some(name_bytes) = name_end.and_then(|end| body.get(2..end)) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet declaration too short",
                    });
                };
                let label = format!("{target_name} {}", String::from_utf8_lossy(name_bytes));
                self.packets.push(label);
                Step::Skip { consumed: total }
            }
            TYPE_RAW_PACKET => {
                let Some(packet_idx) = read_u16_be(body, 0) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet too short",
                    });
                };
                let Some(label) = self.packets.get(usize::from(packet_idx)) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet names unknown definition",
                    });
                };
                let Some(raw_time) = read_u64_be(body, 2) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet too short",
                    });
                };
                let Ok(receive_time_ns) = i64::try_from(raw_time) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 timestamp out of range",
                    });
                };
                let Some(payload) = body.get(10..) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 packet too short",
                    });
                };
                let Some(payload_offset) = offset.checked_add(RAW_PACKET_HEADER_LEN) else {
                    return Step::Fatal(DecodeError::Implausible {
                        offset,
                        reason: "COSMOS 5 offset out of range",
                    });
                };
                Step::Record {
                    consumed: total,
                    record: Record {
                        offset: payload_offset,
                        receive_time_ns: Some(receive_time_ns),
                        label: Some(label.clone()),
                        payload: payload.to_vec(),
                    },
                }
            }
            TYPE_JSON_PACKET | TYPE_OFFSET_MARKER => Step::Skip { consumed: total },
            _ => Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "unknown COSMOS 5 entry type",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::{DecodeEnd, Format, decode_all, decoder_for};
    use crate::pure::synth::{Cosmos5Writer, packet};

    /// Hand-computed byte vector (not produced by Cosmos5Writer), covering
    /// declarations with and without 32-byte ids, offset markers, JSON packets,
    /// and raw telemetry/command packets.
    #[test]
    fn hand_written_vector() {
        let mut data: Vec<u8> = Vec::new();
        // Bytes 0..8: magic
        data.extend_from_slice(b"COSMOS5_");

        // Bytes 8..17: target decl 0 ("SIM"), no id: len=5, flags=0x1000, body="SIM"
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x10, 0x00, b'S', b'I', b'M']);
        assert_eq!(data.len(), 17);

        // Bytes 17..58: target decl 1 ("NAV") with 32-byte id: len=37 (0x25), flags=0x1200
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x25, 0x12, 0x00, b'N', b'A', b'V']);
        data.extend_from_slice(&[0xAA; 32]);
        assert_eq!(data.len(), 58);

        // Bytes 58..68: packet decl 0 (target 0, "HK"), no id: len=6, flags=0x2000
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x06, // len = 6
            0x20, 0x00, // flags
            0x00, 0x00, // target index = 0 ("SIM")
            b'H', b'K', // packet name
        ]);
        assert_eq!(data.len(), 68);

        // Bytes 68..111: packet decl 1 (target 1, "POS") with command + id: len=39 (0x27), flags=0x2A00
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x27, // len = 39
            0x2A, 0x00, // flags: packet decl | command | id
            0x00, 0x01, // target index = 1 ("NAV")
            b'P', b'O', b'S', // packet name
        ]);
        data.extend_from_slice(&[0xBB; 32]);
        assert_eq!(data.len(), 111);

        // Bytes 111..126: offset marker: len=11, flags=0x5000, body="123456789"
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0B, 0x50, 0x00, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
            b'9',
        ]);
        assert_eq!(data.len(), 126);

        // Bytes 126..144: JSON packet (skipped): len=14, flags=0x4000, pkt=0, time=1, body="{}"
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0E, // len = 14
            0x40, 0x00, // flags
            0x00, 0x00, // packet index = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // time = 1
            b'{', b'}', // json
        ]);
        assert_eq!(data.len(), 144);

        // Bytes 144..164: raw packet (pkt 0): len=16, flags=0x3000,
        // time=1_700_000_000_123_456_789 (0x1797_9CFE_3D85_CD15),
        // payload=[0xDE, 0xAD, 0xBE, 0xEF]. Payload starts at 144 + 16 = 160.
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x10, // len = 16
            0x30, 0x00, // flags
            0x00, 0x00, // packet index = 0
            0x17, 0x97, 0x9C, 0xFE, 0x3D, 0x85, 0xCD, 0x15, // time_ns
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ]);
        assert_eq!(data.len(), 164);

        // Bytes 164..182: raw command packet (pkt 1): len=14, flags=0x3800,
        // time=1_700_000_001_000_000_000 (0x1797_9CFE_71C4_CA00),
        // payload=[0x01, 0x02]. Payload starts at 164 + 16 = 180.
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0E, // len = 14
            0x38, 0x00, // flags: raw | command
            0x00, 0x01, // packet index = 1
            0x17, 0x97, 0x9C, 0xFE, 0x71, 0xC4, 0xCA, 0x00, // time_ns
            0x01, 0x02, // payload
        ]);

        let (records, end) = decode_all(&mut Cosmos5Decoder::new(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), 2);

        assert_eq!(records[0].offset, 160);
        assert_eq!(records[0].receive_time_ns, Some(1_700_000_000_123_456_789));
        assert_eq!(records[0].label.as_deref(), Some("SIM HK"));
        assert_eq!(records[0].payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(records[1].offset, 180);
        assert_eq!(records[1].receive_time_ns, Some(1_700_000_001_000_000_000));
        assert_eq!(records[1].label.as_deref(), Some("NAV POS"));
        assert_eq!(records[1].payload, vec![0x01, 0x02]);
    }

    #[test]
    fn round_trip_through_writer() {
        let items: &[(&str, &str, i64, Vec<u8>, bool)] = &[
            (
                "SIM",
                "HK",
                1_700_000_000_000_000_001,
                packet(0x11, 0, &[1, 2]),
                false,
            ),
            (
                "SIM",
                "HK",
                1_700_000_000_500_000_002,
                packet(0x11, 1, &[3, 4]),
                false,
            ),
            (
                "NAV",
                "POS",
                1_700_000_001_000_000_003,
                vec![0x10, 0x20, 0x30],
                false,
            ),
            ("SIM", "RESET", 1_700_000_002_000_000_004, vec![0xFF], true),
            ("PWR", "BUS", 1_700_000_003_000_000_005, vec![], false),
            (
                "SIM",
                "RESET",
                1_700_000_004_000_000_006,
                vec![0xFE, 0xFD],
                true,
            ),
        ];

        let mut writer = Cosmos5Writer::new();
        let mut data = Cosmos5Writer::magic();
        for (target, pkt, time_ns, payload, command) in items {
            data.extend(writer.entry(*time_ns, target, pkt, payload, *command));
        }

        let mut dec = decoder_for(Format::Cosmos5, &Default::default()).expect("cosmos5 decoder");
        let (records, end) = decode_all(dec.as_mut(), &data);
        assert_eq!(end, None);
        assert_eq!(records.len(), items.len());

        for (rec, (target, pkt, time_ns, payload, _)) in records.iter().zip(items) {
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
        let mut writer = Cosmos5Writer::new();
        let mut data = Cosmos5Writer::magic();
        data.extend(writer.entry(1_700_000_000_000_000_000, "SIM", "HK", &[1, 2, 3], false));
        // Insert an offset marker and a JSON packet between raw entries.
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x50, 0x00, b'1', b'2', b'3']);
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0E, 0x40, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1, b'{', b'}',
        ]);
        data.extend(writer.entry(1_700_000_001_000_000_000, "NAV", "CMD", &[4, 5], true));

        let (full_records, full_end) = decode_all(&mut Cosmos5Decoder::new(), &data);
        assert_eq!(full_end, None);
        assert_eq!(full_records.len(), 2);

        for cut in 0..=data.len() {
            let (records, end) = decode_all(&mut Cosmos5Decoder::new(), &data[..cut]);
            assert_eq!(
                records.as_slice(),
                &full_records[..records.len()],
                "cut at {cut}"
            );
            assert!(
                matches!(end, None | Some(DecodeEnd::Truncated { .. })),
                "unexpected Fatal at cut {cut}: {end:?}"
            );
            if cut == 0 || cut == 8 || cut == data.len() {
                assert_eq!(end, None, "cut at {cut}");
            }
        }
    }

    #[test]
    fn random_bytes_after_magic_do_not_panic() {
        let magic = Cosmos5Writer::magic();
        let mut x = 0xD1B5_4A35u32;
        for len in 0..256usize {
            let mut data = magic.clone();
            data.extend((0..len).map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            }));
            let _ = decode_all(&mut Cosmos5Decoder::new(), &data);
        }
    }

    #[test]
    fn fatal_conditions() {
        // 1. Bad magic.
        let (_, end) = decode_all(&mut Cosmos5Decoder::new(), b"COSMOS4_");
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset: 0, .. }))
        ));

        // 2. Packet declaration referencing nonexistent target index.
        let mut bad_target = Cosmos5Writer::magic();
        bad_target.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x20, 0x00, 0x00, 0x00, b'H', b'K']);
        let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &bad_target);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset: 8, .. }))
        ));

        // 2b. A target numbered from 15, as in a file that is not the
        // writer's first, and then a packet declaration outside what
        // has been declared.
        let mut later = Cosmos5Writer::magic();
        later.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x10, 0x00, b'I', b'N', b'S', b'T']);
        later.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x20, 0x00, 0x00, 0x0F, b'H', b'K']);
        let ok_len = later.len() as u64;
        later.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x20, 0x00, 0x00, 0x11, b'X', b'Y']);
        let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &later);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset, .. })) if offset == ok_len
        ));
        // Nor one below where the file's numbers start.
        let mut below = later[..ok_len as usize].to_vec();
        below.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x20, 0x00, 0x00, 0x0E, b'X', b'Y']);
        let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &below);
        assert!(matches!(end, Some(DecodeEnd::Error(_))));

        // 3. Raw packet referencing undeclared packet index.
        let mut bad_packet = Cosmos5Writer::magic();
        bad_packet.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0D, // len = 13
            0x30, 0x00, // raw packet
            0x00, 0x00, // undeclared packet index 0
            0, 0, 0, 0, 0, 0, 0, 1,    // time
            0x42, // payload
        ]);
        let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &bad_packet);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset: 8, .. }))
        ));

        // 4. Raw packet with timestamp above i64::MAX.
        let mut bad_time = Cosmos5Writer::magic();
        bad_time.extend_from_slice(&[0x00, 0x00, 0x00, 0x03, 0x10, 0x00, b'T']);
        bad_time.extend_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, b'P']);
        let raw_offset = bad_time.len() as u64;
        bad_time.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0D, // len = 13
            0x30, 0x00, // raw packet
            0x00, 0x00, // packet index 0
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // i64::MAX + 1
            0x42, // payload
        ]);
        let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &bad_time);
        assert!(matches!(
            end,
            Some(DecodeEnd::Error(DecodeError::Implausible { offset, .. })) if offset == raw_offset
        ));

        // 5. Unknown entry type.
        for bad_type in [0x0000u16, 0x6000, 0xF000] {
            let mut data = Cosmos5Writer::magic();
            data.extend_from_slice(&2u32.to_be_bytes());
            data.extend_from_slice(&bad_type.to_be_bytes());
            let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &data);
            assert!(
                matches!(
                    end,
                    Some(DecodeEnd::Error(DecodeError::Implausible { offset: 8, .. }))
                ),
                "type {bad_type:#x} should be Fatal"
            );
        }

        // 6. Entry length smaller than fixed fields of its type.
        let short_cases: &[(u32, Option<u16>)] = &[
            (0, None),          // smaller than 2-byte flags
            (1, None),          // smaller than 2-byte flags
            (33, Some(0x1200)), // target decl with 32-byte id needs >= 34
            (3, Some(0x2000)),  // packet decl needs >= 4
            (35, Some(0x2200)), // packet decl with 32-byte id needs >= 36
            (11, Some(0x3000)), // raw packet needs >= 12
            (11, Some(0x4000)), // JSON packet needs >= 12
        ];
        for &(len, flags) in short_cases {
            let mut data = Cosmos5Writer::magic();
            data.extend_from_slice(&len.to_be_bytes());
            if let Some(f) = flags {
                data.extend_from_slice(&f.to_be_bytes());
                data.resize(8 + 4 + len as usize, 0);
            } else {
                data.resize(8 + 4 + len as usize, 0);
            }
            let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &data);
            assert!(
                matches!(
                    end,
                    Some(DecodeEnd::Error(DecodeError::Implausible { offset: 8, .. }))
                ),
                "short entry len={len} flags={flags:?} should be Fatal"
            );
        }

        // 7. Entry length larger than MAX_ENTRY (must fail without needing MAX_ENTRY bytes).
        for big_len in [MAX_ENTRY as u32, (MAX_ENTRY as u32) + 1, u32::MAX] {
            let mut data = Cosmos5Writer::magic();
            data.extend_from_slice(&big_len.to_be_bytes());
            let (_, end) = decode_all(&mut Cosmos5Decoder::new(), &data);
            assert!(
                matches!(
                    end,
                    Some(DecodeEnd::Error(DecodeError::Implausible { offset: 8, .. }))
                ),
                "big entry len={big_len} should be Fatal"
            );
        }
    }
}
