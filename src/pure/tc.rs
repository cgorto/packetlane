//! Telecommand transfer frames and the CLTUs that carry them up the link:
//! CCSDS 232.0-B (the frame) and 231.0-B (the coding).
//!
//! Nothing here keeps state between calls: `decode/tc.rs` owns sequence
//! checking and packet reassembly.
//!
//! ```text
//! CLTU:   start(2) = EB 90 | codeblock(8) x n | tail(8) = C5 C5 C5 C5 C5 C5 C5 79
//!
//! codeblock: 7 bytes of frame | 7 parity bits, inverted | 1 filler bit = 0
//!   parity: BCH(63,56), generator x^7 + x^6 + x^2 + 1. One wrong bit in
//!   the 63 can be put right; two are noticed.
//!
//! TC frame header, 5 bytes:
//!   word 0: version(2)=0 | bypass(1) | control(1) | spare(2)=0 | spacecraft(10)
//!   word 1: virtual channel(6) | frame length - 1 (10), header and CRC included
//!   byte 4: frame sequence number N(S)
//! then, in a frame that carries data and if the link uses one:
//!   segment header, 1 byte: sequence flags(2) | MAP(6)
//!     flags: 01 first, 00 continuation, 10 last, 11 not segmented
//! then data, then optionally CRC(2), the same CRC as TM frames.
//!
//! bypass control
//!    0      0      AD: sequence controlled; N(S) counts per virtual channel
//!    1      0      BD: expedited; N(S) means nothing
//!    1      1      BC: a control command for the receiver, no packets:
//!                      Unlock = 00, Set V(R) = 82 00 vr
//! ```
//!
//! Traps:
//!
//! - The last codeblock is padded with `55` bytes. They are not part of the
//!   frame, and only the frame's length field says where they begin.
//! - The parity bits are stored inverted, and the eighth bit of the parity
//!   byte is not parity at all. A decoder that includes it, or forgets the
//!   inversion, rejects every block.
//! - The tail is built to be a codeblock that cannot be corrected, which is
//!   how a receiver sees the end. A reader of a file must not depend on it:
//!   half of all random 8-byte blocks pass single-error correction, so a
//!   damaged tail often looks like data, and some recorders drop the tail.
//!   The frame length is what ends a CLTU here.
//! - A BC frame never has a segment header, whatever the link is set to.
//! - If the link randomises (optional), the frame is XORed with a sequence
//!   that restarts with each CLTU, and that happens inside the BCH coding:
//!   correct the codeblocks first, then derandomise. It is a different
//!   sequence from the TM one.

use std::ops::Range;

use crate::pure::ccsds::PrimaryHeader;
use crate::pure::frame::crc16;

pub const START: [u8; 2] = [0xEB, 0x90];
pub const TAIL: [u8; 8] = [0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79];
/// What pads the last codeblock of a CLTU, and what an idle link sends.
pub const FILL: u8 = 0x55;
pub const BLOCK_LEN: usize = 8;
/// Frame bytes per codeblock.
pub const INFO_LEN: usize = 7;
pub const HEADER_LEN: usize = 5;
pub const CRC_LEN: usize = 2;
/// The length field has ten bits.
pub const MAX_FRAME_LEN: usize = 1024;
/// More frames than this in one CLTU is not believed.
const MAX_FRAMES_PER_CLTU: usize = 32;

/// The 7-bit remainder of `info` x^7 on division by x^7 + x^6 + x^2 + 1.
const fn bch_remainder(info: &[u8; INFO_LEN]) -> u8 {
    let mut reg = 0u8;
    let mut i = 0;
    while i < INFO_LEN {
        let mut bit = 8;
        while bit > 0 {
            bit -= 1;
            let feedback = (reg >> 6 ^ info[i] >> bit) & 1;
            reg = (reg << 1) & 0x7F;
            if feedback != 0 {
                reg ^= 0x45; // x^6 + x^2 + 1
            }
        }
        i += 1;
    }
    reg
}

/// The last byte of a codeblock whose first seven are `info`: the parity
/// bits inverted, then the filler bit.
pub fn bch_parity(info: &[u8; INFO_LEN]) -> u8 {
    (!bch_remainder(info) & 0x7F) << 1
}

/// For each non-zero syndrome, which of the 63 bits is wrong plus one, or
/// zero if no single wrong bit gives it. Bits count from the top bit of the
/// first byte.
const fn syndrome_table() -> [u8; 128] {
    let mut table = [0u8; 128];
    let mut bit = 0;
    while bit < 63 {
        let syndrome = if bit < 56 {
            let mut info = [0u8; INFO_LEN];
            info[bit / 8] = 0x80 >> (bit % 8);
            bch_remainder(&info)
        } else {
            0x40 >> (bit - 56)
        };
        table[syndrome as usize] = bit as u8 + 1;
        bit += 1;
    }
    table
}

const WRONG_BIT: [u8; 128] = syndrome_table();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bch {
    Clean,
    /// One bit was wrong and is now right.
    Fixed,
    /// At least two bits are wrong.
    Bad,
}

/// Checks one codeblock and corrects a single wrong bit. The filler bit is
/// not looked at.
pub fn bch_correct(block: &mut [u8; BLOCK_LEN]) -> Bch {
    let info: &[u8; INFO_LEN] = block[..INFO_LEN].try_into().unwrap_or(&[0; INFO_LEN]);
    let syndrome = bch_remainder(info) ^ (!(block[INFO_LEN] >> 1) & 0x7F);
    if syndrome == 0 {
        return Bch::Clean;
    }
    match WRONG_BIT[usize::from(syndrome)] {
        0 => Bch::Bad,
        n => {
            let bit = usize::from(n - 1);
            block[bit / 8] ^= 0x80 >> (bit % 8);
            Bch::Fixed
        }
    }
}

/// XORs `bytes` with the TC pseudo-random sequence (231.0-B:
/// x^8 + x^6 + x^4 + x^3 + x^2 + x + 1, all ones at the first byte of the
/// frame). Its own inverse.
pub fn derandomize(bytes: &mut [u8]) {
    let mut sequence = Sequence::new();
    for byte in bytes {
        *byte ^= sequence.next_byte();
    }
}

/// The TC random sequence, a byte at a time.
struct Sequence(u8);

impl Sequence {
    fn new() -> Self {
        Self(0xFF)
    }

    fn next_byte(&mut self) -> u8 {
        let mut out = 0u8;
        for _ in 0..8 {
            let s = self.0;
            out = (out << 1) | (s & 1);
            let feedback = (s ^ (s >> 1) ^ (s >> 2) ^ (s >> 3) ^ (s >> 4) ^ (s >> 6)) & 1;
            self.0 = (s >> 1) | (feedback << 7);
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcHeader {
    pub bypass: bool,
    pub control: bool,
    pub scid: u16,
    pub vcid: u8,
    /// The whole frame in bytes: header, data and CRC.
    pub len: usize,
    /// N(S).
    pub seq: u8,
}

/// Reads a frame header from the first five bytes of `bytes`. An error is
/// why they cannot be one.
pub fn parse_header(bytes: &[u8]) -> Result<TcHeader, &'static str> {
    let h: &[u8; HEADER_LEN] = bytes
        .get(..HEADER_LEN)
        .and_then(|b| b.try_into().ok())
        .ok_or("TC frame header is incomplete")?;
    if h[0] >> 6 != 0 {
        return Err("TC frame version is not 0");
    }
    if h[0] & 0x0C != 0 {
        return Err("TC frame spare bits are not 0");
    }
    let len = usize::from(u16::from_be_bytes([h[2], h[3]]) & 0x3FF) + 1;
    if len < HEADER_LEN {
        return Err("TC frame length is shorter than its header");
    }
    Ok(TcHeader {
        bypass: h[0] & 0x20 != 0,
        control: h[0] & 0x10 != 0,
        scid: u16::from_be_bytes([h[0], h[1]]) & 0x3FF,
        vcid: h[2] >> 2,
        len,
        seq: h[4],
    })
}

/// True if `frame` (whole, CRC included) passes its CRC.
pub fn crc_ok(frame: &[u8]) -> bool {
    frame.len() >= HEADER_LEN + CRC_LEN && {
        let (body, crc) = frame.split_at(frame.len() - CRC_LEN);
        crc16(body).to_be_bytes() == crc
    }
}

/// Everything about the link that is not written in the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcParams {
    /// True for a file of CLTUs, false for frames back to back.
    pub cltu: bool,
    /// True if each frame ends with a 16-bit CRC.
    pub has_crc: bool,
    /// True if the data of each AD and BD frame starts with a segment header.
    pub segment_header: bool,
    /// CLTUs only: the frames are XORed with the TC random sequence.
    pub randomized: bool,
}

/// What can be read off a telecommand file before decoding it. Anything
/// left `None` has to come from the configuration or a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcLayout {
    pub crc: Option<bool>,
    pub segment_header: Option<bool>,
    pub randomized: Option<bool>,
}

/// One CLTU's worth of frames, read from its codeblocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cltu {
    /// The frame bytes of every codeblock read, corrected and derandomised.
    /// Byte `d` of this came from byte `d / 7 * 8 + d % 7` of the codeblocks.
    pub data: Vec<u8>,
    /// Where the frames are in `data`. Never empty.
    pub frames: Vec<Range<usize>>,
    /// How many codeblocks were read.
    pub blocks: usize,
    /// How many of them had a bit corrected.
    pub fixed: u64,
    /// Why reading stopped before the CLTU's end, if it did: the frames
    /// found up to there are good, what follows is not.
    pub trouble: Option<&'static str>,
    /// True if the last frame ended exactly at the end of a codeblock. Then
    /// nothing has said the CLTU is over: another frame may follow.
    pub open_ended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CltuRead {
    /// The codeblocks offered end before the frame does.
    NeedMore,
    /// The first codeblock is not the start of a frame.
    Bad(&'static str),
    Read(Cltu),
}

/// Reads the frames of one CLTU. `blocks` starts at its first codeblock,
/// after the start sequence, and may run on into whatever follows.
///
/// The frame's own length says how many codeblocks there are. If the frame
/// ends inside a codeblock and the rest of the block is not fill, another
/// frame follows in the same CLTU: 231.0-B allowed that in earlier issues.
/// With randomising on, fill cannot be told from data, and one frame per
/// CLTU is assumed.
pub fn read_cltu(blocks: &[u8], randomized: bool) -> CltuRead {
    let mut sequence = Sequence::new();
    let mut cltu = Cltu {
        data: Vec::new(),
        frames: Vec::new(),
        blocks: 0,
        fixed: 0,
        trouble: None,
        open_ended: false,
    };
    let mut start = 0;
    loop {
        // First enough codeblocks for the header, then for the frame it
        // describes.
        let mut end = start + HEADER_LEN;
        let mut header = None;
        let problem = loop {
            while cltu.data.len() < end {
                let at = cltu.blocks * BLOCK_LEN;
                let Some(mut block) = blocks
                    .get(at..at + BLOCK_LEN)
                    .and_then(|b| <[u8; BLOCK_LEN]>::try_from(b).ok())
                else {
                    return CltuRead::NeedMore;
                };
                match bch_correct(&mut block) {
                    Bch::Clean => {}
                    Bch::Fixed => cltu.fixed += 1,
                    Bch::Bad => break,
                }
                cltu.blocks += 1;
                cltu.data.extend(block[..INFO_LEN].iter().map(|&b| {
                    if randomized {
                        b ^ sequence.next_byte()
                    } else {
                        b
                    }
                }));
            }
            if cltu.data.len() < end {
                break Some("codeblock with more than one bit wrong");
            }
            if header.is_some() {
                break None;
            }
            match parse_header(&cltu.data[start..]) {
                Ok(h) => {
                    header = Some(h);
                    end = start + h.len;
                }
                Err(reason) => break Some(reason),
            }
        };
        if let Some(reason) = problem {
            if cltu.frames.is_empty() {
                return CltuRead::Bad(reason);
            }
            cltu.trouble = Some(reason);
            return CltuRead::Read(cltu);
        }
        cltu.frames.push(start..end);
        start = end;
        let rest = &cltu.data[start..];
        if rest.is_empty() {
            cltu.open_ended = true;
            return CltuRead::Read(cltu);
        }
        if randomized || rest.iter().all(|&b| b == FILL) {
            return CltuRead::Read(cltu);
        }
        if cltu.frames.len() >= MAX_FRAMES_PER_CLTU {
            cltu.trouble = Some("too many frames in one CLTU");
            return CltuRead::Read(cltu);
        }
    }
}

/// True if `bytes` is one or more whole space packets and nothing else.
pub fn is_whole_packets(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    while let Some(header) = PrimaryHeader::parse(rest) {
        if header.version != 0 || header.total_len() > rest.len() {
            return false;
        }
        rest = &rest[header.total_len()..];
    }
    rest.is_empty() && !bytes.is_empty()
}

/// How many frames from the start of a file layout detection looks at.
const SNIFF_FRAMES: usize = 16;

/// What `frames` say about whether they end in a CRC and start their data
/// with a segment header.
///
/// A CRC is there if every frame passes it and not there if none does. With
/// that known, the data of frames that carry data is tried both ways: as
/// whole packets from its first byte, or as a segment header saying "not
/// segmented" in front of whole packets.
fn judge(frames: &[&[u8]]) -> (Option<bool>, Option<bool>) {
    let passing = frames.iter().filter(|f| crc_ok(f)).count();
    let crc = match passing {
        0 => Some(false),
        n if n == frames.len() => Some(true),
        _ => None,
    };
    let Some(has_crc) = crc else {
        return (None, None);
    };
    let trailer = if has_crc { CRC_LEN } else { 0 };
    let data: Vec<&[u8]> = frames
        .iter()
        .filter(|f| f[0] & 0x10 == 0 && f.len() > HEADER_LEN + trailer)
        .map(|f| &f[HEADER_LEN..f.len() - trailer])
        .collect();
    let bare = data.iter().filter(|d| is_whole_packets(d)).count();
    let headed = data
        .iter()
        .filter(|d| d[0] >> 6 == 3 && is_whole_packets(&d[1..]))
        .count();
    let segment_header = match (bare, headed) {
        (n, 0) if n > 0 && n == data.len() => Some(false),
        (0, n) if n > 0 => Some(true),
        _ => None,
    };
    (crc, segment_header)
}

/// How many CLTUs must follow one another before a file whose first
/// codeblock needed correcting is believed to be CLTUs.
const SNIFF_CHAIN: usize = 3;

/// The layout, if `prefix` reads as CLTUs: after any idle fill, a start
/// sequence, a first codeblock with nothing wrong in it that holds a frame
/// header, and the rest of that frame's codeblocks.
///
/// Half of all 8-byte blocks pass once a wrong bit is allowed for, so a
/// first codeblock that needs correcting is weak evidence. It is accepted
/// only if three CLTUs then follow one another with nothing but tails and
/// idle fill between them.
pub fn sniff_cltus(prefix: &[u8]) -> Option<TcLayout> {
    let lead = prefix.iter().take_while(|&&b| b == FILL).count();
    let mut rest = prefix[lead..].strip_prefix(&START)?;
    let mut first: [u8; BLOCK_LEN] = rest.get(..BLOCK_LEN)?.try_into().ok()?;
    let sure = match bch_correct(&mut first) {
        Bch::Clean => first[INFO_LEN] & 1 == 0,
        Bch::Fixed => false,
        Bch::Bad => return None,
    };
    // The random sequence starts with FF, so a randomised frame shows its
    // version bits inverted.
    let randomized = match first[0] >> 6 {
        0 => false,
        3 => true,
        _ => return None,
    };
    let mut cltus = Vec::new();
    while cltus.len() < SNIFF_FRAMES {
        let CltuRead::Read(cltu) = read_cltu(rest, randomized) else {
            break;
        };
        let stop = cltu.trouble.is_some();
        rest = &rest[cltu.blocks * BLOCK_LEN..];
        cltus.push(cltu);
        rest = rest.strip_prefix(&TAIL).unwrap_or(rest);
        let idle = rest.iter().take_while(|&&b| b == FILL).count();
        match rest[idle..].strip_prefix(&START) {
            Some(next) if !stop => rest = next,
            _ => break,
        }
    }
    if cltus.is_empty() || (!sure && cltus.len() < SNIFF_CHAIN) {
        return None;
    }
    let frames: Vec<&[u8]> = cltus
        .iter()
        .flat_map(|c| c.frames.iter().map(|r| &c.data[r.clone()]))
        .collect();
    let (crc, segment_header) = judge(&frames);
    Some(TcLayout {
        crc,
        segment_header,
        randomized: Some(randomized),
    })
}

/// The layout, if `prefix` reads as TC frames back to back. There is no
/// marker to go by, so this asks for a lot: every length field leads to
/// another header of the same spacecraft, three times or exactly to the end
/// of `prefix`, and either every frame passes its CRC or the frames' data
/// reads as whole space packets.
pub fn sniff_frames(prefix: &[u8]) -> Option<TcLayout> {
    let mut frames: Vec<&[u8]> = Vec::new();
    let mut rest = prefix;
    let mut scid = None;
    while rest.len() >= HEADER_LEN && frames.len() < SNIFF_FRAMES {
        let header = parse_header(rest).ok()?;
        if *scid.get_or_insert(header.scid) != header.scid {
            return None;
        }
        let Some(frame) = rest.get(..header.len) else {
            break;
        };
        frames.push(frame);
        rest = &rest[header.len..];
    }
    let to_the_end = rest.is_empty() && !frames.is_empty();
    if frames.len() < 3 && !to_the_end {
        return None;
    }
    let (crc, segment_header) = judge(&frames);
    (crc == Some(true) || segment_header.is_some()).then_some(TcLayout {
        crc,
        segment_header,
        randomized: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codeblock(info: [u8; INFO_LEN]) -> [u8; BLOCK_LEN] {
        let mut block = [0u8; BLOCK_LEN];
        block[..INFO_LEN].copy_from_slice(&info);
        block[INFO_LEN] = bch_parity(&info);
        block
    }

    /// Division done the long way on a 63-bit number, with the generator
    /// written out: a check on the shift register and on which way round
    /// the bits go.
    fn slow_remainder(info: &[u8; INFO_LEN]) -> u8 {
        let mut value = info.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)) << 7;
        let generator = 0b1100_0101u64; // x^7 + x^6 + x^2 + 1
        for bit in (7..63).rev() {
            if value >> bit & 1 != 0 {
                value ^= generator << (bit - 7);
            }
        }
        value as u8
    }

    #[test]
    fn parity_is_the_inverted_remainder_and_a_zero_filler() {
        // Nothing but zeros divides with no remainder; inverted, seven ones.
        assert_eq!(bch_parity(&[0; INFO_LEN]), 0xFE);
        // `C5` is the generator's own bit pattern (1100 0101), so seven of
        // them in a row are a multiple of it: no remainder either. This is
        // what the tail sequence is made from, with its last byte spoiled.
        assert_eq!(bch_parity(&[0xC5; INFO_LEN]), 0xFE);
        assert_eq!(TAIL[..INFO_LEN], [0xC5; INFO_LEN]);
        let mut x = 0x1234_5678u32;
        for _ in 0..500 {
            let info: [u8; INFO_LEN] = std::array::from_fn(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 8) as u8
            });
            let parity = bch_parity(&info);
            assert_eq!(parity & 1, 0);
            assert_eq!(!(parity >> 1) & 0x7F, slow_remainder(&info));
            // A codeword, parity bits put back the right way up, divides
            // by the generator exactly.
            let word = info.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)) << 7
                | u64::from(slow_remainder(&info));
            let mut rest = word;
            for bit in (7..63).rev() {
                if rest >> bit & 1 != 0 {
                    rest ^= 0b1100_0101 << (bit - 7);
                }
            }
            assert_eq!(rest, 0);
        }
    }

    /// All of it, since it is small: every single wrong bit is put right,
    /// every pair of wrong bits is noticed and nothing is changed, and the
    /// filler bit does not matter.
    #[test]
    fn corrects_any_one_bit_and_notices_any_two() {
        let good = codeblock([0x22, 0xF6, 0x00, 0xFF, 0x00, 0x42, 0x1A]);
        let flip = |block: &mut [u8; BLOCK_LEN], bit: usize| block[bit / 8] ^= 0x80 >> (bit % 8);
        assert_eq!(bch_correct(&mut good.clone()), Bch::Clean);
        for a in 0..63 {
            let mut one = good;
            flip(&mut one, a);
            assert_eq!(bch_correct(&mut one), Bch::Fixed, "bit {a}");
            assert_eq!(one, good);
            for b in a + 1..63 {
                let mut two = good;
                flip(&mut two, a);
                flip(&mut two, b);
                let before = two;
                assert_eq!(bch_correct(&mut two), Bch::Bad, "bits {a} and {b}");
                assert_eq!(two, before);
            }
        }
        let mut filler = good;
        filler[7] ^= 1;
        assert_eq!(bch_correct(&mut filler), Bch::Clean);
    }

    /// The tail is meant to be a block no receiver can correct.
    #[test]
    fn the_tail_sequence_cannot_be_corrected() {
        assert_eq!(bch_correct(&mut TAIL.clone()), Bch::Bad);
        // Nor can idle fill be taken for a block.
        assert_eq!(bch_correct(&mut [FILL; BLOCK_LEN]), Bch::Bad);
    }

    #[test]
    fn random_sequence_starts_as_published_and_repeats() {
        let mut bytes = [0u8; 8];
        derandomize(&mut bytes);
        assert_eq!(bytes, [0xFF, 0x39, 0x9E, 0x5A, 0x68, 0xE9, 0x06, 0xF5]);
        let mut long = [0u8; 510];
        derandomize(&mut long);
        assert_eq!(long[..255], long[255..]);
        assert_ne!(long[..127], long[127..254]);
    }

    /// Worked by hand: a BD frame, spacecraft 0x155, channel 9, 12 bytes
    /// long, N(S) 7.
    #[test]
    fn parses_a_header() {
        let h = parse_header(&[0x21, 0x55, 0x24, 0x0B, 0x07]).unwrap();
        assert_eq!(
            h,
            TcHeader {
                bypass: true,
                control: false,
                scid: 0x155,
                vcid: 9,
                len: 12,
                seq: 7,
            }
        );
        assert!(parse_header(&[0x61, 0x55, 0x24, 0x0B, 0x07]).is_err());
        assert!(parse_header(&[0x25, 0x55, 0x24, 0x0B, 0x07]).is_err());
        assert!(parse_header(&[0x21, 0x55, 0x24, 0x03, 0x07]).is_err());
        assert!(parse_header(&[0x21, 0x55, 0x24, 0x0B]).is_err());
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        let mut x = 0x2545_F491u32;
        for len in 0..300usize {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    // Mostly small values, so that headers do parse.
                    if x & 0x300 == 0 { x as u8 } else { 0 }
                })
                .collect();
            let _ = read_cltu(&data, len % 2 == 0);
            let _ = sniff_frames(&data);
            let mut marked = START.to_vec();
            marked.extend(&data);
            let _ = sniff_cltus(&marked);
            let _ = is_whole_packets(&data);
        }
    }
}
