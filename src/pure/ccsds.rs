//! CCSDS Space Packet primary header (CCSDS 133.0-B).
//!
//! Six bytes, big-endian:
//!
//! ```text
//! word 0: version(3) | type(1) | secondary header flag(1) | APID(11)
//! word 1: sequence flags(2) | sequence count(14)
//! word 2: data length = (bytes after the primary header) - 1
//! ```

pub const PRIMARY_HEADER_LEN: usize = 6;
/// APID reserved for idle (fill) packets. Never checked for continuity.
pub const IDLE_APID: u16 = 0x7FF;
/// The sequence count is 14 bits and wraps to zero at this value.
pub const SEQ_MODULUS: u16 = 1 << 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PacketType {
    Telemetry,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqFlags {
    Continuation,
    First,
    Last,
    Unsegmented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub has_secondary_header: bool,
    pub apid: u16,
    pub seq_flags: SeqFlags,
    pub seq_count: u16,
    /// The raw field: number of bytes after the primary header, minus one.
    pub data_length: u16,
}

impl PrimaryHeader {
    /// Parses the first six bytes of `bytes`. Returns `None` if there are fewer.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let b: &[u8; PRIMARY_HEADER_LEN] = bytes.get(..PRIMARY_HEADER_LEN)?.try_into().ok()?;
        let w0 = u16::from_be_bytes([b[0], b[1]]);
        let w1 = u16::from_be_bytes([b[2], b[3]]);
        let w2 = u16::from_be_bytes([b[4], b[5]]);
        Some(Self {
            version: (w0 >> 13) as u8,
            packet_type: if w0 & 0x1000 == 0 {
                PacketType::Telemetry
            } else {
                PacketType::Command
            },
            has_secondary_header: w0 & 0x0800 != 0,
            apid: w0 & 0x07FF,
            seq_flags: match w1 >> 14 {
                0 => SeqFlags::Continuation,
                1 => SeqFlags::First,
                2 => SeqFlags::Last,
                _ => SeqFlags::Unsegmented,
            },
            seq_count: w1 & 0x3FFF,
            data_length: w2,
        })
    }

    /// Whole packet length in bytes, header included: the length field plus 7.
    pub fn total_len(&self) -> usize {
        PRIMARY_HEADER_LEN + self.data_length as usize + 1
    }

    pub fn encode(&self) -> [u8; PRIMARY_HEADER_LEN] {
        let w0 = (u16::from(self.version & 0x7) << 13)
            | match self.packet_type {
                PacketType::Telemetry => 0,
                PacketType::Command => 0x1000,
            }
            | if self.has_secondary_header { 0x0800 } else { 0 }
            | (self.apid & 0x07FF);
        let flags: u16 = match self.seq_flags {
            SeqFlags::Continuation => 0,
            SeqFlags::First => 1,
            SeqFlags::Last => 2,
            SeqFlags::Unsegmented => 3,
        };
        let w1 = (flags << 14) | (self.seq_count & 0x3FFF);
        let mut out = [0u8; PRIMARY_HEADER_LEN];
        out[0..2].copy_from_slice(&w0.to_be_bytes());
        out[2..4].copy_from_slice(&w1.to_be_bytes());
        out[4..6].copy_from_slice(&self.data_length.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Worked by hand: version 0, telemetry, secondary header present,
    /// APID 0x1A3, unsegmented, count 5, four data bytes (length field 3).
    const VECTOR: [u8; 6] = [0x09, 0xA3, 0xC0, 0x05, 0x00, 0x03];

    #[test]
    fn parses_hand_computed_vector() {
        let h = PrimaryHeader::parse(&VECTOR).unwrap();
        assert_eq!(h.version, 0);
        assert_eq!(h.packet_type, PacketType::Telemetry);
        assert!(h.has_secondary_header);
        assert_eq!(h.apid, 0x1A3);
        assert_eq!(h.seq_flags, SeqFlags::Unsegmented);
        assert_eq!(h.seq_count, 5);
        assert_eq!(h.data_length, 3);
        assert_eq!(h.total_len(), 10);
        assert_eq!(h.encode(), VECTOR);
    }

    #[test]
    fn short_input_is_none() {
        assert!(PrimaryHeader::parse(&VECTOR[..5]).is_none());
    }

    #[test]
    fn command_bit() {
        let h = PrimaryHeader::parse(&[0x18, 0x01, 0xC0, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(h.packet_type, PacketType::Command);
        assert_eq!(h.apid, 1);
        assert_eq!(h.total_len(), 7);
    }
}
