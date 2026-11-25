//! Transfer frames inside CADUs: the layer between a file of fixed-size
//! link blocks and the space packets packed into them.
//!
//! A CADU is the four-byte sync marker followed by one frame, and possibly
//! Reed-Solomon check symbols. Nothing here keeps state: `decode/cadu.rs`
//! owns marker lock and packet reassembly and calls [`parse`] once per CADU.
//!
//! ```text
//! CADU:  sync(4) | header | [insert zone / secondary header] | data zone | [OCF(4)] | [CRC(2)] | [RS parity]
//!
//! TM header (CCSDS 132.0-B), 6 bytes:
//!   word 0: version(2)=0 | spacecraft(10) | virtual channel(3) | OCF flag(1)
//!   byte 2: master channel frame count      byte 3: virtual channel frame count
//!   word 2: secondary header(1) | sync(1) | order(1) | segment(2) | first header pointer(11)
//!
//! AOS header (CCSDS 732.0-B), 6 bytes, optionally + 2 of header check:
//!   word 0: version(2)=1 | spacecraft(8) | virtual channel(6)
//!   bytes 2-4: virtual channel frame count  byte 5: signalling
//!   then the insert zone, if any, then the 2-byte M_PDU header:
//!   spare(5) | first header pointer(11)
//! ```

use std::ops::Range;

use serde::Deserialize;

pub const SYNC: [u8; 4] = [0x1A, 0xCF, 0xFC, 0x1D];
const HEADER_LEN: usize = 6;
const OCF_LEN: usize = 4;
const CRC_LEN: usize = 2;
/// Pointer value: no packet starts in this frame, it is all continuation.
const NO_START: u16 = 0x7FF;
/// Pointer value: the data zone holds only fill.
const IDLE_ONLY: u16 = 0x7FE;
/// AOS virtual channel reserved for fill frames.
const AOS_IDLE_VCID: u8 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    #[default]
    Tm,
    Aos,
}

/// Everything about the link that is not written in the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameParams {
    /// Marker to marker, in bytes.
    pub cadu_len: usize,
    pub kind: FrameKind,
    /// True if the file still holds the frames XORed with the CCSDS
    /// pseudo-random sequence.
    pub randomized: bool,
    /// Check symbols kept after each frame: 32 x interleave depth for
    /// RS(255,223), 0 if the recorder dropped them.
    pub rs_parity_len: usize,
    /// True if each frame ends with a 16-bit CRC.
    pub has_crc: bool,
    /// AOS only: the operational control field is present. TM frames say so
    /// themselves.
    pub aos_has_ocf: bool,
    /// AOS only: the header is followed by a 2-byte header check.
    pub aos_has_header_check: bool,
    /// AOS only: bytes of insert zone after the header.
    pub aos_insert_zone_len: usize,
}

/// Where the first packet header in a frame's data zone is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pointer {
    /// This many bytes into the data zone. Bytes before it finish a packet
    /// begun in an earlier frame.
    At(usize),
    /// No packet starts here: the whole zone continues an earlier packet.
    NoStart,
    /// Fill only. Carries no packet bytes at all.
    Idle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub scid: u16,
    pub vcid: u8,
    /// Virtual channel frame count, for spotting lost frames.
    pub count: u32,
    /// `count` wraps to zero at this value: 2^8 for TM, 2^24 for AOS.
    pub count_modulus: u32,
    pub pointer: Pointer,
    /// The packet bytes, as a range within the CADU (marker included), so
    /// the caller can turn positions into file offsets.
    pub data: Range<usize>,
}

/// Parses one CADU. `cadu` is exactly `params.cadu_len` bytes, starts with
/// the sync marker, and has already been through [`derandomize`] if needed.
pub fn parse(params: &FrameParams, cadu: &[u8]) -> Result<Frame, &'static str> {
    if cadu.len() != params.cadu_len {
        return Err("wrong CADU length");
    }
    if cadu.get(..SYNC.len()) != Some(&SYNC[..]) {
        return Err("no sync marker");
    }
    let frame_end = cadu
        .len()
        .checked_sub(params.rs_parity_len)
        .ok_or("frame parameters exceed CADU length")?;
    let h: &[u8; HEADER_LEN] = cadu
        .get(SYNC.len()..SYNC.len() + HEADER_LEN)
        .and_then(|b| b.try_into().ok())
        .ok_or("frame parameters exceed CADU length")?;
    let w0 = u16::from_be_bytes([h[0], h[1]]);
    let mut start = SYNC.len() + HEADER_LEN;
    let mut trailer = if params.has_crc { CRC_LEN } else { 0 };

    let (scid, vcid, count, count_modulus, raw_pointer) = match params.kind {
        FrameKind::Tm => {
            if w0 >> 14 != 0 {
                return Err("TM frame version is not 0");
            }
            if w0 & 1 != 0 {
                trailer += OCF_LEN;
            }
            let status = u16::from_be_bytes([h[4], h[5]]);
            if status & 0x4000 != 0 {
                return Err("TM frame does not carry packets (sync flag set)");
            }
            if status & 0x8000 != 0 {
                // Secondary header: its first byte holds its own length - 1.
                let first = cadu
                    .get(start)
                    .ok_or("frame parameters exceed CADU length")?;
                start += usize::from(first & 0x3F) + 1;
            }
            let vcid = ((w0 >> 1) & 0x7) as u8;
            (
                (w0 >> 4) & 0x3FF,
                vcid,
                u32::from(h[3]),
                1 << 8,
                status & 0x7FF,
            )
        }
        FrameKind::Aos => {
            if w0 >> 14 != 1 {
                return Err("AOS frame version is not 1");
            }
            if params.aos_has_ocf {
                trailer += OCF_LEN;
            }
            if params.aos_has_header_check {
                start += 2;
            }
            start += params.aos_insert_zone_len;
            let m_pdu: [u8; 2] = cadu
                .get(start..start.saturating_add(2))
                .and_then(|b| b.try_into().ok())
                .ok_or("frame parameters exceed CADU length")?;
            start += 2;
            let vcid = (w0 & 0x3F) as u8;
            let count = u32::from_be_bytes([0, h[2], h[3], h[4]]);
            let pointer = if vcid == AOS_IDLE_VCID {
                IDLE_ONLY
            } else {
                u16::from_be_bytes(m_pdu) & 0x7FF
            };
            ((w0 >> 6) & 0xFF, vcid, count, 1 << 24, pointer)
        }
    };

    let end = frame_end
        .checked_sub(trailer)
        .filter(|&end| end > start)
        .ok_or("frame parameters exceed CADU length")?;
    if params.has_crc {
        let stored = u16::from_be_bytes([cadu[frame_end - 2], cadu[frame_end - 1]]);
        if crc16(&cadu[SYNC.len()..frame_end - CRC_LEN]) != stored {
            return Err("frame CRC mismatch");
        }
    }
    let pointer = match raw_pointer {
        NO_START => Pointer::NoStart,
        IDLE_ONLY => Pointer::Idle,
        p if usize::from(p) < end - start => Pointer::At(usize::from(p)),
        _ => return Err("first header pointer is past the data zone"),
    };
    Ok(Frame {
        scid,
        vcid,
        count,
        count_modulus,
        pointer,
        data: start..end,
    })
}

/// XORs `after_sync` with the CCSDS pseudo-random sequence (131.0-B:
/// x^8 + x^7 + x^5 + x^3 + 1, seeded with all ones at the first byte after
/// each sync marker). Its own inverse: the same call randomises.
pub fn derandomize(after_sync: &mut [u8]) {
    let mut state = 0xFFu8;
    for byte in after_sync {
        let mut mask = 0u8;
        for _ in 0..8 {
            mask = (mask << 1) | (state & 1);
            let feedback = (state ^ (state >> 3) ^ (state >> 5) ^ (state >> 7)) & 1;
            state = (state >> 1) | (feedback << 7);
        }
        *byte ^= mask;
    }
}

/// CRC-16 as CCSDS frames use it: polynomial 0x1021, initial value 0xFFFF,
/// no reflection, no final XOR.
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(kind: FrameKind, cadu_len: usize) -> FrameParams {
        FrameParams {
            cadu_len,
            kind,
            randomized: false,
            rs_parity_len: 0,
            has_crc: false,
            aos_has_ocf: false,
            aos_has_header_check: false,
            aos_insert_zone_len: 0,
        }
    }

    #[test]
    fn randomizer_matches_the_published_sequence() {
        let mut bytes = [0u8; 8];
        derandomize(&mut bytes);
        assert_eq!(bytes, [0xFF, 0x48, 0x0E, 0xC0, 0x9A, 0x0D, 0x70, 0xBC]);
        let mut long = [0u8; 510];
        derandomize(&mut long);
        assert_eq!(long[..255], long[255..]);
    }

    #[test]
    fn crc_check_value() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    /// Worked by hand: spacecraft 0x155, channel 2, OCF present, VC count 9,
    /// first header at byte 3 of the data zone, CRC at the end.
    #[test]
    fn parses_tm_frame() {
        let mut cadu = SYNC.to_vec();
        cadu.extend([0x15, 0x55, 0x07, 0x09, 0x18, 0x03]);
        cadu.extend([0xAA; 10]); // data zone
        cadu.extend([0; 4]); // OCF
        let crc = crc16(&cadu[4..]);
        cadu.extend(crc.to_be_bytes());
        let mut p = params(FrameKind::Tm, cadu.len());
        p.has_crc = true;
        let f = parse(&p, &cadu).unwrap();
        assert_eq!((f.scid, f.vcid, f.count), (0x155, 2, 9));
        assert_eq!(f.pointer, Pointer::At(3));
        assert_eq!(f.data, 10..20);
        cadu[12] ^= 1;
        assert_eq!(parse(&p, &cadu), Err("frame CRC mismatch"));
    }

    /// Spacecraft 0x2A, channel 5, count 0x010203, no packet start.
    #[test]
    fn parses_aos_frame() {
        let mut cadu = SYNC.to_vec();
        cadu.extend([0x4A, 0x85, 0x01, 0x02, 0x03, 0x00]);
        cadu.extend([0x07, 0xFF]); // M_PDU header
        cadu.extend([0xAA; 8]);
        let f = parse(&params(FrameKind::Aos, cadu.len()), &cadu).unwrap();
        assert_eq!((f.scid, f.vcid, f.count), (0x2A, 5, 0x010203));
        assert_eq!(f.pointer, Pointer::NoStart);
        assert_eq!(f.data, 12..20);
    }

    #[test]
    fn arbitrary_bytes_and_params_do_not_panic() {
        let mut x = 0x2545F491u32;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for len in 0..120usize {
            let mut cadu: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if len >= 4 {
                cadu[..4].copy_from_slice(&SYNC);
            }
            for kind in [FrameKind::Tm, FrameKind::Aos] {
                let mut p = params(kind, len);
                p.has_crc = next() & 1 == 0;
                p.aos_has_ocf = next() & 1 == 0;
                p.aos_has_header_check = next() & 1 == 0;
                p.rs_parity_len = (next() % 40) as usize;
                p.aos_insert_zone_len = (next() % 40) as usize;
                if let Ok(f) = parse(&p, &cadu) {
                    assert!(f.data.start < f.data.end && f.data.end <= len);
                }
            }
        }
    }
}
