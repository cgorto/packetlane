//! Turning packet bytes into named values, using definitions from the
//! configuration file.

use serde::Serialize;

use crate::pure::config::{ByteOrder, FieldDef, FieldKind, PacketDef, ResolvedTime, TimeCode};

/// Reads up to 64 bits starting `bit_offset` bits into `bytes`, most
/// significant bit first. `None` if the range runs past the end.
pub fn extract_bits(bytes: &[u8], bit_offset: u64, bit_length: u32) -> Option<u64> {
    if bit_length == 0 || bit_length > 64 {
        return None;
    }
    let end = bit_offset.checked_add(u64::from(bit_length))?;
    if end > (bytes.len() as u64).checked_mul(8)? {
        return None;
    }
    let mut value: u64 = 0;
    let mut bit = bit_offset;
    let mut left = bit_length;
    while left > 0 {
        let byte = *bytes.get(usize::try_from(bit / 8).ok()?)?;
        let within = (bit % 8) as u32;
        let take = (8 - within).min(left);
        let shifted = (u32::from(byte) >> (8 - within - take)) & ((1u32 << take) - 1);
        value = (value << take) | u64::from(shifted);
        bit += u64::from(take);
        left -= take;
    }
    Some(value)
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits >= 64 {
        value as i64
    } else {
        let shift = 64 - bits;
        ((value << shift) as i64) >> shift
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    UInt(u64),
    Int(i64),
    Float(f64),
    Text(String),
    /// The elements of an array field.
    List(Vec<Value>),
}

impl Serialize for Value {
    /// Integers too large for a browser to hold exactly are written as
    /// strings so no digits are lost.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use crate::pure::sql::MAX_SAFE_INT;
        match self {
            Value::UInt(v) if *v <= MAX_SAFE_INT as u64 => s.serialize_u64(*v),
            Value::UInt(v) => s.serialize_str(&v.to_string()),
            Value::Int(v) if (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(v) => s.serialize_i64(*v),
            Value::Int(v) => s.serialize_str(&v.to_string()),
            Value::Float(v) => s.serialize_f64(*v),
            Value::Text(v) => s.serialize_str(v),
            Value::List(v) => s.collect_seq(v),
        }
    }
}

/// One field of one packet, decoded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Decoded {
    pub name: String,
    /// `None` when the field could not be read; `error` says why.
    pub value: Option<Value>,
    /// The configured name for this value, if there is one.
    pub label: Option<String>,
    pub unit: String,
    pub error: Option<&'static str>,
}

const PAST_END: &str = "Past end of packet";

/// One number of a field's kind and byte order, `bit_offset` bits in.
fn number(field: &FieldDef, packet: &[u8], bit_offset: u64) -> Result<Value, &'static str> {
    let bits = field.bit_length;
    let mut raw = extract_bits(packet, bit_offset, bits).ok_or(PAST_END)?;
    if field.byte_order == ByteOrder::Little {
        // Validation allows this only for whole bytes on a byte boundary,
        // where the first byte in the packet is the least significant.
        raw = raw.swap_bytes() >> (64 - bits.min(64));
    }
    match field.kind {
        FieldKind::Uint => Ok(Value::UInt(raw)),
        FieldKind::Int => Ok(Value::Int(sign_extend(raw, bits))),
        _ => {
            let value = match bits {
                // Through text, so a 32-bit value shows as 28.05, not as the
                // nearest 64-bit number to it, 28.049999237060547.
                32 => {
                    let v = f32::from_bits(raw as u32);
                    v.to_string().parse().unwrap_or(f64::from(v))
                }
                64 => f64::from_bits(raw),
                _ => return Err("Float must be 32 or 64 bits"),
            };
            if value.is_finite() {
                Ok(Value::Float(value))
            } else {
                // JSON has no way to write these as numbers.
                Ok(Value::Text(value.to_string()))
            }
        }
    }
}

fn decode_field(field: &FieldDef, packet: &[u8]) -> Result<(Value, Option<String>), &'static str> {
    match field.kind {
        FieldKind::Uint | FieldKind::Int | FieldKind::Float if field.count > 1 => {
            let each = (0..u64::from(field.count)).map(|i| {
                number(
                    field,
                    packet,
                    u64::from(field.bit_offset) + i * u64::from(field.bit_length),
                )
            });
            Ok((Value::List(each.collect::<Result<_, _>>()?), None))
        }
        FieldKind::Uint | FieldKind::Int | FieldKind::Float => {
            let value = number(field, packet, u64::from(field.bit_offset))?;
            let label = match &value {
                Value::UInt(v) => field.labels.get(&v.to_string()).cloned(),
                Value::Int(v) => field.labels.get(&v.to_string()).cloned(),
                _ => None,
            };
            Ok((value, label))
        }
        FieldKind::Hex | FieldKind::Ascii => {
            if !field.bit_offset.is_multiple_of(8) || !field.bit_length.is_multiple_of(8) {
                return Err("Must be byte-aligned whole bytes");
            }
            let start = (field.bit_offset / 8) as usize;
            let len = (field.bit_length / 8) as usize;
            let bytes = start
                .checked_add(len)
                .and_then(|end| packet.get(start..end))
                .ok_or(PAST_END)?;
            let text = if field.kind == FieldKind::Hex {
                hex(bytes)
            } else {
                bytes
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7F).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect()
            };
            Ok((Value::Text(text), None))
        }
    }
}

/// Decodes every field of a definition against one packet. A field that
/// cannot be read is reported in place; the others are still decoded.
pub fn decode_fields(def: &PacketDef, packet: &[u8]) -> Vec<Decoded> {
    def.fields
        .iter()
        .map(|field| match decode_field(field, packet) {
            Ok((value, label)) => Decoded {
                name: field.name.clone(),
                value: Some(value),
                label,
                unit: field.unit.clone(),
                error: None,
            },
            Err(error) => Decoded {
                name: field.name.clone(),
                value: None,
                label: None,
                unit: field.unit.clone(),
                error: Some(error),
            },
        })
        .collect()
}

/// Lower-case hex, no separators.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0xF)] as char);
    }
    out
}

fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// The packet's own timestamp, in nanoseconds since the Unix epoch, read
/// from its secondary header as the configuration describes. `None` if the
/// packet is too short or the result does not fit.
pub fn packet_time_ns(rule: &ResolvedTime, packet: &[u8]) -> Option<i64> {
    let field = |start: usize, len: usize| -> Option<u64> {
        let end = start.checked_add(len)?;
        packet.get(start..end).map(be_uint)
    };
    // Worked in 128 bits: an epoch far from 1970 can make the intermediate
    // values too large for 64 even when the answer fits.
    let since_epoch_ns: i128 = match rule.code {
        TimeCode::Cuc => {
            let coarse = field(rule.byte_offset, rule.coarse_bytes)?;
            let fine_start = rule.byte_offset.checked_add(rule.coarse_bytes)?;
            let fine = field(fine_start, rule.fine_bytes)?;
            // fine / 256^n seconds, in nanoseconds, rounded down.
            let denominator = 1i128 << (8 * rule.fine_bytes as u32);
            i128::from(coarse) * 1_000_000_000 + i128::from(fine) * 1_000_000_000 / denominator
        }
        TimeCode::Cds => {
            let days = field(rule.byte_offset, rule.day_bytes)?;
            let ms_start = rule.byte_offset.checked_add(rule.day_bytes)?;
            let millis = field(ms_start, 4)?;
            let sub_start = ms_start.checked_add(4)?;
            let submillis = field(sub_start, rule.submillis_bytes)?;
            if millis >= 86_400_000 + 1000 || submillis >= 1000 {
                return None;
            }
            i128::from(days) * 86_400_000_000_000
                + i128::from(millis) * 1_000_000
                + i128::from(submillis) * 1_000
        }
    };
    i64::try_from(i128::from(rule.epoch_ns) + since_epoch_ns - i128::from(rule.subtract_ns)).ok()
}

/// The reverse of [`packet_time_ns`] for the CUC code, for building test
/// packets: the bytes of a time field holding `ns` (Unix epoch).
pub fn cuc_bytes(rule: &ResolvedTime, ns: i64) -> Option<Vec<u8>> {
    let since = ns
        .checked_add(rule.subtract_ns)?
        .checked_sub(rule.epoch_ns)?;
    if since < 0 {
        return None;
    }
    let coarse = (since / 1_000_000_000) as u64;
    let frac_ns = (since % 1_000_000_000) as u128;
    let scale = 1u128 << (8 * rule.fine_bytes as u32);
    // Round up so that decoding (which rounds down) returns the same time
    // whenever the field has the resolution to hold it.
    let fine = (frac_ns * scale).div_ceil(1_000_000_000).min(scale - 1) as u64;
    if rule.coarse_bytes < 8 && coarse >> (8 * rule.coarse_bytes as u32) != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(rule.coarse_bytes + rule.fine_bytes);
    out.extend_from_slice(&coarse.to_be_bytes()[8 - rule.coarse_bytes.min(8)..]);
    out.extend_from_slice(&fine.to_be_bytes()[8 - rule.fine_bytes.min(8)..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::config::Config;

    #[test]
    fn extracts_bits_msb_first() {
        let bytes = [0b1010_0101, 0b1100_0011, 0xFF];
        assert_eq!(extract_bits(&bytes, 0, 1), Some(1));
        assert_eq!(extract_bits(&bytes, 1, 1), Some(0));
        assert_eq!(extract_bits(&bytes, 0, 8), Some(0xA5));
        assert_eq!(extract_bits(&bytes, 4, 8), Some(0x5C));
        assert_eq!(extract_bits(&bytes, 5, 11), Some(0b101_1100_0011));
        assert_eq!(extract_bits(&bytes, 0, 24), Some(0xA5C3FF));
        assert_eq!(extract_bits(&bytes, 23, 1), Some(1));
        assert_eq!(extract_bits(&bytes, 23, 2), None);
        assert_eq!(extract_bits(&bytes, 0, 0), None);
        assert_eq!(extract_bits(&bytes, 0, 65), None);
        assert_eq!(extract_bits(&[], 0, 1), None);
        assert_eq!(extract_bits(&bytes, u64::MAX, 8), None);
    }

    #[test]
    fn extracts_a_full_64_bits_at_any_alignment() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x80];
        assert_eq!(extract_bits(&bytes, 0, 64), Some(0x0123_4567_89AB_CDEF));
        assert_eq!(extract_bits(&bytes, 1, 64), Some(0x0246_8ACF_1357_9BDF));
    }

    #[test]
    fn sign_extension() {
        assert_eq!(sign_extend(0b111, 3), -1);
        assert_eq!(sign_extend(0b011, 3), 3);
        assert_eq!(sign_extend(0x80, 8), -128);
        assert_eq!(sign_extend(u64::MAX, 64), -1);
        assert_eq!(sign_extend(1, 1), -1);
    }

    fn def(fields: &str) -> PacketDef {
        let text = format!("[[packet]]\napid = 1\nname = \"T\"\n{fields}");
        Config::parse(&text).unwrap().packets.remove(0)
    }

    #[test]
    fn decodes_each_kind() {
        let def = def(r#"
[[packet.field]]
name = "MODE"
bit_offset = 0
bit_length = 4
labels = { "10" = "OBSERVE" }
[[packet.field]]
name = "DELTA"
bit_offset = 4
bit_length = 4
kind = "int"
labels = { "-3" = "BACK3" }
[[packet.field]]
name = "TEMP"
bit_offset = 8
bit_length = 32
kind = "float"
unit = "degC"
[[packet.field]]
name = "TAG"
bit_offset = 40
bit_length = 24
kind = "ascii"
[[packet.field]]
name = "RAW"
bit_offset = 40
bit_length = 16
kind = "hex"
[[packet.field]]
name = "MISSING"
bit_offset = 64
bit_length = 8
"#);
        let mut packet = vec![0xAD];
        packet.extend_from_slice(&21.5f32.to_be_bytes());
        packet.extend_from_slice(b"ok\x01");
        let out = decode_fields(&def, &packet);
        assert_eq!(out[0].value, Some(Value::UInt(10)));
        assert_eq!(out[0].label.as_deref(), Some("OBSERVE"));
        assert_eq!(out[1].value, Some(Value::Int(-3)));
        assert_eq!(out[1].label.as_deref(), Some("BACK3"));
        assert_eq!(out[2].value, Some(Value::Float(21.5)));
        let volts = decode_fields(
            &def,
            &[&[0xAD][..], &28.05f32.to_be_bytes(), b"ok\x01"].concat(),
        );
        assert_eq!(volts[2].value, Some(Value::Float(28.05)));
        assert_eq!(out[2].unit, "degC");
        assert_eq!(out[3].value, Some(Value::Text("ok.".to_string())));
        assert_eq!(out[4].value, Some(Value::Text("6f6b".to_string())));
        assert_eq!(out[5].value, None);
        assert!(out[5].error.is_some());
    }

    #[test]
    fn non_finite_floats_become_text() {
        let def = def(
            "[[packet.field]]\nname = \"F\"\nbit_offset = 0\nbit_length = 32\nkind = \"float\"",
        );
        let out = decode_fields(&def, &f32::NAN.to_be_bytes());
        assert_eq!(out[0].value, Some(Value::Text("NaN".to_string())));
        assert!(serde_json::to_string(&out).is_ok());
    }

    fn rule(text: &str) -> ResolvedTime {
        Config::parse(text).unwrap().resolved_time().unwrap()
    }

    #[test]
    fn cuc_time() {
        let rule = rule("[packet_time]\ncode = \"cuc\"\nepoch = \"2000-01-01T00:00:00Z\"");
        // Six header bytes, then 4 coarse + 2 fine: 10 seconds and a half.
        let packet = [0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0x80, 0x00];
        let epoch = 946_684_800_000_000_000i64;
        assert_eq!(packet_time_ns(&rule, &packet), Some(epoch + 10_500_000_000));
        assert_eq!(packet_time_ns(&rule, &packet[..11]), None);
        assert_eq!(
            cuc_bytes(&rule, epoch + 10_500_000_000).unwrap(),
            &packet[6..]
        );
        assert_eq!(cuc_bytes(&rule, epoch - 1), None);
    }

    #[test]
    fn cuc_round_trip_within_field_resolution() {
        let rule = rule("[packet_time]\ncode = \"cuc\"\nfine_bytes = 3\nsubtract_seconds = 37");
        let unix_2026 = 1_767_225_600_000_000_000i64;
        for ms in [0i64, 1, 250, 999, 123_456] {
            let t = unix_2026 + ms * 1_000_000;
            let mut packet = vec![0u8; 6];
            packet.extend(cuc_bytes(&rule, t).unwrap());
            let back = packet_time_ns(&rule, &packet).unwrap();
            assert!(
                (0..60).contains(&(back - t)),
                "ms {ms}: off by {}",
                back - t
            );
        }
    }

    #[test]
    fn cds_time() {
        let rule = rule(
            "[packet_time]\ncode = \"cds\"\nsubmillis_bytes = 2\nepoch = \"1970-01-01T00:00:00Z\"",
        );
        // Day 2, 1500 ms, 250 microseconds.
        let mut packet = vec![0u8; 6];
        packet.extend_from_slice(&[0, 2, 0, 0, 0x05, 0xDC, 0x00, 0xFA]);
        assert_eq!(
            packet_time_ns(&rule, &packet),
            Some(2 * 86_400_000_000_000 + 1_500_000_000 + 250_000)
        );
        // A milliseconds-of-day value that is not a time of day.
        packet[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(packet_time_ns(&rule, &packet), None);
    }

    #[test]
    fn an_epoch_far_from_1970_does_not_overflow() {
        let rule =
            rule("[packet_time]\ncode = \"cds\"\nday_bytes = 3\nepoch = \"1700-01-01T00:00:00Z\"");
        // 2026-01-01 is 119,069 days (0x01D11D) after 1700-01-01.
        let packet = [0, 0, 0, 0, 0, 0, 0x01, 0xD1, 0x1D, 0, 0, 0, 0];
        assert_eq!(
            packet_time_ns(&rule, &packet),
            Some(1_767_225_600_000_000_000)
        );
        // A day count that lands beyond what 64 bits of nanoseconds can hold.
        let late = [0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
        assert_eq!(packet_time_ns(&rule, &late), None);
    }

    #[test]
    fn large_integers_are_serialised_as_strings() {
        let values = [
            Value::UInt(0x0123_4567_89AB_CDEF),
            Value::UInt(42),
            Value::Int(i64::MIN),
            Value::Int(-7),
        ];
        assert_eq!(
            serde_json::to_string(&values).unwrap(),
            r#"["81985529216486895",42,"-9223372036854775808",-7]"#
        );
    }

    #[test]
    fn little_endian_numbers_and_arrays() {
        let def = def(
            "[[packet.field]]\nname = \"W\"\nbit_offset = 0\nbit_length = 16\nbyte_order = \"little\"\n\
             [[packet.field]]\nname = \"I\"\nbit_offset = 16\nbit_length = 32\nkind = \"int\"\nbyte_order = \"little\"\n\
             [[packet.field]]\nname = \"F\"\nbit_offset = 48\nbit_length = 32\nkind = \"float\"\nbyte_order = \"little\"\n\
             [[packet.field]]\nname = \"D\"\nbit_offset = 80\nbit_length = 64\nkind = \"float\"\nbyte_order = \"little\"\n\
             [[packet.field]]\nname = \"A\"\nbit_offset = 144\nbit_length = 16\ncount = 3\nbyte_order = \"little\"\n\
             [[packet.field]]\nname = \"N\"\nbit_offset = 192\nbit_length = 4\nkind = \"int\"\ncount = 4\n\
             [[packet.field]]\nname = \"PAST\"\nbit_offset = 200\nbit_length = 8\ncount = 2\n",
        );
        let mut packet = vec![0x34, 0x12];
        packet.extend((-2i32).to_le_bytes());
        packet.extend(21.5f32.to_le_bytes());
        packet.extend((-0.125f64).to_le_bytes());
        packet.extend([1, 0, 2, 0, 0xFF, 0xFF]);
        packet.extend([0x1F, 0x80]);
        let out = decode_fields(&def, &packet);
        let value = |i: usize| out[i].value.clone().unwrap();
        assert_eq!(value(0), Value::UInt(0x1234));
        assert_eq!(value(1), Value::Int(-2));
        assert_eq!(value(2), Value::Float(21.5));
        assert_eq!(value(3), Value::Float(-0.125));
        assert_eq!(
            value(4),
            Value::List(vec![Value::UInt(1), Value::UInt(2), Value::UInt(65535)])
        );
        let nibbles = [1, -1, -8, 0].map(Value::Int).to_vec();
        assert_eq!(value(5), Value::List(nibbles));
        assert_eq!(serde_json::to_string(&value(4)).unwrap(), "[1,2,65535]");
        // An array that runs off the end is an error as a whole.
        assert_eq!(out[6].error, Some("Past end of packet"));

        for (bad, want) in [
            (
                "bit_offset = 4\nbit_length = 16\nbyte_order = \"little\"",
                "byte_order little",
            ),
            (
                "bit_offset = 0\nbit_length = 12\nbyte_order = \"little\"",
                "byte_order little",
            ),
            ("bit_offset = 0\nbit_length = 8\ncount = 0", "count must be"),
            (
                "bit_offset = 0\nbit_length = 8\ncount = 2000",
                "count must be",
            ),
            (
                "bit_offset = 0\nbit_length = 8\nkind = \"hex\"\ncount = 2",
                "count must be",
            ),
            (
                "bit_offset = 0\nbit_length = 8\ncount = 2\nlabels = { \"1\" = \"A\" }",
                "cannot have labels",
            ),
        ] {
            let text = format!(
                "[[packet]]\napid = 1\nname = \"T\"\n[[packet.field]]\nname = \"X\"\n{bad}"
            );
            let err = Config::parse(&text).unwrap_err();
            assert!(err.contains(want), "{bad:?} gave {err:?}");
        }
    }
}
