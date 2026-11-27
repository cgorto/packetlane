//! Turning packet bytes into named values, using definitions from the
//! configuration file.

use std::fmt;

use serde::Serialize;

use crate::pure::config::{
    ByteOrder, FieldDef, FieldKind, LimitState, PacketDef, ResolvedTime, TimeCode,
};

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
    /// The engineering value, where the field has a conversion.
    pub converted: Option<f64>,
    /// Where the value stands against the field's limits, unless it is
    /// inside them: "yellow low", "red high" and so on.
    pub limit: Option<&'static str>,
}

/// A field's value as a number in engineering units: the raw number put
/// through the field's polynomial, if it has one. `None` for text, arrays
/// and anything unreadable.
pub fn engineering(field: &FieldDef, packet: &[u8]) -> Option<f64> {
    if field.count != 1 {
        return None;
    }
    engineering_of(
        field,
        &number(field, packet, u64::from(field.bit_offset)).ok()?,
    )
}

/// [`engineering`] for a number already read from the packet.
fn engineering_of(field: &FieldDef, value: &Value) -> Option<f64> {
    let raw = match *value {
        Value::UInt(v) => v as f64,
        Value::Int(v) => v as f64,
        Value::Float(v) => v,
        _ => return None,
    };
    if field.poly.is_empty() {
        return Some(raw);
    }
    let mut power = 1.0;
    let mut sum = 0.0;
    for c in &field.poly {
        sum += c * power;
        power *= raw;
    }
    sum.is_finite().then_some(sum)
}

/// Text written to the stack: a number only formatted to be looked at
/// again need not be put on the heap.
struct Digits {
    bytes: [u8; 64],
    len: usize,
}

impl Digits {
    /// `None` if the text does not fit.
    fn of(value: impl fmt::Display) -> Option<Digits> {
        let mut out = Digits {
            bytes: [0; 64],
            len: 0,
        };
        fmt::write(&mut out, format_args!("{value}")).ok()?;
        Some(out)
    }

    fn as_str(&self) -> &str {
        // Only whole `str`s are ever copied in.
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or_default()
    }
}

impl fmt::Write for Digits {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let to = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        to.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The configured name for an integer value, if there is one.
fn label_of(field: &FieldDef, value: &Value) -> Option<String> {
    if field.labels.is_empty() {
        return None;
    }
    let digits = match *value {
        Value::UInt(v) => Digits::of(v),
        Value::Int(v) => Digits::of(v),
        _ => return None,
    }?;
    field.labels.get(digits.as_str()).cloned()
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
                    match Digits::of(v) {
                        Some(text) => text.as_str().parse(),
                        None => v.to_string().parse(),
                    }
                    .unwrap_or(f64::from(v))
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
            let label = label_of(field, &value);
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

/// The values of a packet's fields that are marked `keep`, as (field name,
/// number, text). The number is the engineering value; the text is the
/// value's label, a text field's content, or an array's elements. A field
/// that cannot be read from this packet is left out.
pub fn kept_values<'a>(
    def: &'a PacketDef,
    packet: &[u8],
) -> Vec<(&'a str, Option<f64>, Option<String>)> {
    def.fields
        .iter()
        .filter(|field| field.keep)
        .filter_map(|field| {
            let reading = read_field(field, packet, true);
            Some((field.name.as_str(), reading.num, reading.kept?))
        })
        .collect()
}

/// What the checks need of one field of one packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// The same as [`engineering`].
    pub num: Option<f64>,
    /// Only if asked for: the text [`kept_values`] gives the field, or
    /// `None` if it would leave the field out.
    pub kept: Option<Option<String>>,
}

/// Reads a field's engineering value and, if `keep`, what is kept of it,
/// decoding a single number once for both.
pub fn read_field(field: &FieldDef, packet: &[u8], keep: bool) -> Reading {
    let single_number = matches!(
        field.kind,
        FieldKind::Uint | FieldKind::Int | FieldKind::Float
    ) && field.count == 1;
    if single_number {
        let Ok(value) = number(field, packet, u64::from(field.bit_offset)) else {
            return Reading {
                num: None,
                kept: None,
            };
        };
        let num = engineering_of(field, &value);
        let kept = keep.then(|| match value {
            Value::Text(text) => Some(text),
            _ => label_of(field, &value),
        });
        return Reading { num, kept };
    }
    // Arrays and text: what is kept is decoded on its own terms, and the
    // number, if any, is read as `engineering` reads it.
    let num = engineering(field, packet);
    let kept = keep
        .then(|| decode_field(field, packet).ok())
        .flatten()
        .map(|(value, label)| match value {
            Value::Text(text) => Some(text),
            Value::List(items) => Some(
                items
                    .iter()
                    .map(|v| match v {
                        Value::UInt(n) => n.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(n) => n.to_string(),
                        Value::Text(t) => t.clone(),
                        Value::List(_) => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => label,
        });
    Reading { num, kept }
}

/// Decodes every field of a definition against one packet. A field that
/// cannot be read is reported in place; the others are still decoded.
pub fn decode_fields(def: &PacketDef, packet: &[u8]) -> Vec<Decoded> {
    def.fields
        .iter()
        .map(|field| match decode_field(field, packet) {
            Ok((value, label)) => {
                let number = engineering(field, packet);
                Decoded {
                    name: field.name.clone(),
                    value: Some(value),
                    label,
                    unit: field.unit.clone(),
                    error: None,
                    converted: number.filter(|_| !field.poly.is_empty()),
                    limit: number
                        .zip(field.limits)
                        .map(|(v, limits)| limits.state(v))
                        .filter(|s| *s != LimitState::Green)
                        .map(LimitState::name),
                }
            }
            Err(error) => Decoded {
                name: field.name.clone(),
                value: None,
                label: None,
                unit: field.unit.clone(),
                error: Some(error),
                converted: None,
                limit: None,
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
/// as the configuration describes. Whether the packet is one to read a time
/// from at all is the caller's question: see `ResolvedTime::applies`. `None` if the
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
        TimeCode::Unix => {
            let seconds = field(rule.byte_offset, rule.coarse_bytes)?;
            let micros_start = rule.byte_offset.checked_add(rule.coarse_bytes)?;
            let micros = field(micros_start, 4)?;
            if micros >= 1_000_000 {
                return None;
            }
            i128::from(seconds) * 1_000_000_000 + i128::from(micros) * 1_000
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

    /// What was kept of a field before a single number was decoded once:
    /// the field decoded, its label looked up by its value as text, and the
    /// engineering value read again.
    fn kept_as_before(field: &FieldDef, packet: &[u8]) -> Reading {
        let kept = decode_field(field, packet).ok().map(|(value, _)| {
            let label = match &value {
                Value::UInt(v) => field.labels.get(&v.to_string()).cloned(),
                Value::Int(v) => field.labels.get(&v.to_string()).cloned(),
                _ => None,
            };
            match value {
                Value::Text(text) => Some(text),
                Value::List(items) => Some(
                    items
                        .iter()
                        .map(|v| match v {
                            Value::UInt(n) => n.to_string(),
                            Value::Int(n) => n.to_string(),
                            Value::Float(n) => n.to_string(),
                            Value::Text(t) => t.clone(),
                            Value::List(_) => String::new(),
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                _ => label,
            }
        });
        Reading {
            num: engineering(field, packet),
            kept,
        }
    }

    #[test]
    fn a_field_read_once_reads_as_before() {
        let base =
            def("[[packet.field]]\nname = \"X\"\nbit_offset = 0\nbit_length = 8").fields[0].clone();
        let kinds = [
            FieldKind::Uint,
            FieldKind::Int,
            FieldKind::Float,
            FieldKind::Hex,
            FieldKind::Ascii,
        ];
        let mut fields = Vec::new();
        for kind in kinds {
            for bit_length in [1, 4, 8, 12, 16, 24, 32, 64] {
                for bit_offset in [0, 3, 8, 16] {
                    for count in [1, 3] {
                        for byte_order in [ByteOrder::Big, ByteOrder::Little] {
                            for poly in [vec![], vec![-100.0, 0.5], vec![1e308, 1e308]] {
                                let mut f = base.clone();
                                f.kind = kind;
                                f.bit_length = bit_length;
                                f.bit_offset = bit_offset;
                                f.count = count;
                                f.byte_order = byte_order;
                                f.poly = poly;
                                fields.push(f.clone());
                                f.labels.insert("5".to_string(), "FIVE".to_string());
                                f.labels.insert("-1".to_string(), "MINUS ONE".to_string());
                                fields.push(f);
                            }
                        }
                    }
                }
            }
        }
        let mut packets: Vec<Vec<u8>> = vec![vec![], vec![5], vec![0xFF; 3]];
        packets.push([&f32::NAN.to_be_bytes()[..], &[0; 20]].concat());
        packets.push([&[5u8, 0, 0, 0][..], &28.05f32.to_be_bytes(), &[0; 20]].concat());
        packets.push([&1e-45f32.to_be_bytes()[..], &[0xFF; 20]].concat());
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..40 {
            packets.push(
                (0..24)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        x as u8
                    })
                    .collect(),
            );
        }
        for field in &fields {
            for packet in &packets {
                let before = kept_as_before(field, packet);
                for keep in [true, false] {
                    let now = read_field(field, packet, keep);
                    let want = if keep {
                        before.clone()
                    } else {
                        Reading {
                            num: before.num,
                            kept: None,
                        }
                    };
                    // Compared as bits, so that NaN equals NaN.
                    assert_eq!(
                        (now.num.map(f64::to_bits), &now.kept),
                        (want.num.map(f64::to_bits), &want.kept),
                        "{field:?} {packet:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn floats_written_on_the_stack_read_as_from_the_heap() {
        let specials = [
            0.0f32,
            -0.0,
            1e-45,
            -1e-45,
            f32::MIN_POSITIVE,
            f32::MAX,
            f32::MIN,
            f32::NAN,
            f32::INFINITY,
            28.05,
        ];
        let stepped = (0..=u32::MAX).step_by(65_537).map(f32::from_bits);
        for v in specials.into_iter().chain(stepped) {
            assert_eq!(Digits::of(v).unwrap().as_str(), v.to_string());
        }
        for v in [0u64, 7, u64::MAX] {
            assert_eq!(Digits::of(v).unwrap().as_str(), v.to_string());
        }
        assert_eq!(Digits::of(i64::MIN).unwrap().as_str(), i64::MIN.to_string());
        assert!(Digits::of("x".repeat(65)).is_none());
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
    fn unix_time() {
        use crate::pure::synth::cosmos_tlm;
        let rule = rule("[packet_time]\ncode = \"unix\"");
        // A packet from a real COSMOS log: 0x52D02E78 seconds, 0x000B3F34
        // microseconds, which is 2014-01-10T17:31:36.737076Z.
        let packet = [
            0x00, 0x02, 0xC0, 0x01, 0x00, 0x09, 0x52, 0xD0, 0x2E, 0x78, 0x00, 0x0B, 0x3F, 0x34,
            0x00, 0x01,
        ];
        let t = 1_389_375_096_737_076_000;
        assert_eq!(packet_time_ns(&rule, &packet), Some(t));
        assert_eq!(
            crate::pure::time::format_iso(t),
            "2014-01-10T17:31:36.737076000Z"
        );
        assert_eq!(packet, *cosmos_tlm(2, 1, t, 1, &[]));
        assert_eq!(packet_time_ns(&rule, &packet[..13]), None);
        // A million microseconds is not a time.
        let mut bad = packet;
        bad[10..14].copy_from_slice(&1_000_000u32.to_be_bytes());
        assert_eq!(packet_time_ns(&rule, &bad), None);
        bad[10..14].copy_from_slice(&999_999u32.to_be_bytes());
        assert_eq!(packet_time_ns(&rule, &bad), Some(1_389_375_096_999_999_000));
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
