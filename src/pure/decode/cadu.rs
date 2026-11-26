//! CADUs: a sync marker, one transfer frame, repeat. Space packets are
//! packed end to end inside the frames and can straddle them.
//!
//! `pure/frame.rs` reads one frame; this file finds frames and reassembles
//! the packets. The trait allows one record per step, and a frame can finish
//! none or several, so each CADU is consumed in pieces:
//!
//! 1. At a marker: wait for the whole CADU, parse the frame, and `Skip` the
//!    marker, the header and any bytes before the first usable packet byte.
//! 2. In the data zone: take the rest of the current packet or the rest of
//!    the zone, whichever is shorter. `Record` if that finishes a packet,
//!    `Skip` otherwise. The step that reaches the end of the zone consumes
//!    the frame trailer too.
//!
//! If the file's frames carry Reed-Solomon check symbols and the code is
//! known, each frame is corrected before it is parsed (`pure/rs.rs`). A
//! frame with more errors than the code can put right is dropped like any
//! other bad frame. How much was corrected is counted and reported once.
//!
//! Lost data is handled per virtual channel: a jump in the frame count, or a
//! first header pointer that disagrees with the packet in progress, drops
//! that packet and restarts at the next pointer. Bytes that are not a frame
//! are skipped up to the next marker. Each of these is reported as a
//! `Step::Lost`, so the cost of carrying on is on record.

use std::collections::BTreeMap;

use super::{Coding, DecodeError, Decoder, Loss, Notice, Record, Step};
use crate::pure::ccsds::{IDLE_APID, PRIMARY_HEADER_LEN, PrimaryHeader};
use crate::pure::frame::{self, FrameKind, FrameParams, Layout, Pointer, SYNC};
use crate::pure::rs::Basis;

pub const MIN_CADU_LEN: usize = 32;
pub const MAX_CADU_LEN: usize = 16 * 1024;
/// If this many frames fail to parse before any succeeds, the parameters
/// are wrong for this file and carrying on would silently skip all of it.
const GIVE_UP_AFTER: u32 = 16;

/// Reassembly state for one virtual channel of one spacecraft.
#[derive(Debug, Default)]
struct Channel {
    /// The frame count the next frame should carry.
    next_count: Option<u32>,
    /// False until a first header pointer says where a packet starts.
    synced: bool,
    /// The packet in progress.
    partial: Vec<u8>,
    /// File offset of the first byte of `partial`.
    partial_offset: u64,
}

impl Channel {
    /// Bytes still missing from the packet in progress, or `None` while its
    /// header is incomplete and the length unknown.
    fn missing(&self) -> Option<usize> {
        if self.partial.is_empty() {
            return Some(0);
        }
        let header = PrimaryHeader::parse(&self.partial)?;
        Some(header.total_len().saturating_sub(self.partial.len()))
    }
}

/// The CADU being consumed: positions are indexes into `CaduDecoder::cadu`.
#[derive(Debug, Clone, Copy)]
struct Open {
    channel: (u16, u8),
    pos: usize,
    zone_end: usize,
}

#[derive(Debug)]
pub struct CaduDecoder {
    params: FrameParams,
    /// A derandomised copy of the current CADU.
    cadu: Vec<u8>,
    open: Option<Open>,
    channels: BTreeMap<(u16, u8), Channel>,
    good_frames: u64,
    bad_frames: u32,
    /// True from a frame that failed to parse until the next sync marker:
    /// the bytes passed over in between are that frame, not junk.
    in_bad_frame: bool,
    /// Frames Reed-Solomon had to correct: how many, how many bytes it
    /// changed in them, and where the first one is.
    corrected: Option<(u64, u64, u64)>,
}

impl CaduDecoder {
    /// `None` if the CADU length is not a believable one.
    pub fn new(params: FrameParams) -> Option<Self> {
        (MIN_CADU_LEN..=MAX_CADU_LEN)
            .contains(&params.cadu_len)
            .then(|| Self {
                params,
                cadu: Vec::new(),
                open: None,
                channels: BTreeMap::new(),
                good_frames: 0,
                bad_frames: 0,
                in_bad_frame: false,
                corrected: None,
            })
    }

    /// At a CADU boundary: find the marker and read the frame header.
    fn open_cadu(&mut self, buf: &[u8], offset: u64) -> Step {
        if buf.len() < SYNC.len() {
            return Step::NeedMore;
        }
        if !buf.starts_with(&SYNC) {
            // Keep the last three bytes: a marker may be split across reads.
            let consumed = find_sync(&buf[1..]).map_or(buf.len() - 3, |i| i + 1);
            if self.in_bad_frame {
                return Step::Skip { consumed };
            }
            let loss = Loss::Junk {
                bytes: consumed as u64,
            };
            return Step::Lost {
                consumed,
                notice: Notice { offset, loss },
            };
        }
        self.in_bad_frame = false;
        let Some(raw) = buf.get(..self.params.cadu_len) else {
            return Step::NeedMore;
        };
        self.cadu.clear();
        self.cadu.extend_from_slice(raw);
        // The sender coded first and randomised second, so undo in reverse.
        if self.params.randomized {
            frame::derandomize(&mut self.cadu[SYNC.len()..]);
        }
        let fixed = match self.params.rs {
            Some(rs) => rs
                .correct(&mut self.cadu[SYNC.len()..])
                .map_err(|e| e.reason()),
            None => Ok(0),
        };
        let parsed = fixed.and_then(|fixed| match frame::parse(&self.params, &self.cadu) {
            Ok(frame) => Ok((frame, fixed)),
            // Enough errors can carry a block to a different codeword. The
            // CRC is the only thing that can tell.
            Err(frame::CRC_MISMATCH) if fixed > 0 => {
                Err("frame CRC mismatch after Reed-Solomon correction")
            }
            Err(reason) => Err(reason),
        });
        let frame = match parsed {
            Ok((frame, fixed)) => {
                if fixed > 0 {
                    let (frames, bytes, _) = self.corrected.get_or_insert((0, 0, offset));
                    *frames += 1;
                    *bytes += fixed as u64;
                }
                frame
            }
            Err(reason) => {
                self.bad_frames += 1;
                if self.good_frames == 0 && self.bad_frames >= GIVE_UP_AFTER {
                    return Step::Fatal(DecodeError::Implausible { offset, reason });
                }
                // A corrupt frame or a chance marker. Step past the marker
                // only, so a real one just behind it is not jumped over.
                self.in_bad_frame = true;
                return Step::Lost {
                    consumed: SYNC.len(),
                    notice: Notice {
                        offset,
                        loss: Loss::BadFrame { reason },
                    },
                };
            }
        };
        self.good_frames += 1;
        if self.params.kind == FrameKind::Aos && frame.vcid == frame::AOS_IDLE_VCID {
            // Fill frames carry no packets, and whether their count runs
            // on is not something to hold a link to.
            return Step::Skip {
                consumed: self.params.cadu_len,
            };
        }

        let key = (frame.scid, frame.vcid);
        let channel = self.channels.entry(key).or_default();
        let contiguous = channel.next_count == Some(frame.count);
        // The first frame seen on a channel has nothing to follow on from.
        let gap = match channel.next_count {
            Some(expected) if expected != frame.count => {
                let missing = (frame.count + frame.count_modulus - expected) % frame.count_modulus;
                Some(Loss::FrameGap {
                    scid: frame.scid,
                    vcid: frame.vcid,
                    expected,
                    got: frame.count,
                    missing: (missing <= frame.count_modulus / 2).then_some(missing),
                })
            }
            _ => None,
        };
        channel.next_count = Some((frame.count + 1) % frame.count_modulus);
        if !contiguous {
            // Frames were lost: whatever was in progress cannot be finished.
            channel.partial.clear();
            channel.synced = false;
        }
        let zone = frame.data.len();
        let fits = channel.synced
            && match (channel.missing(), frame.pointer) {
                (_, Pointer::Idle) => true,
                (None, _) => true,
                (Some(n), Pointer::At(p)) => n == p,
                (Some(n), Pointer::NoStart) => n >= zone,
            };
        // Where in the zone to start reading, if anywhere.
        let begin = match (fits, frame.pointer) {
            (_, Pointer::Idle) => None,
            (true, _) => Some(0),
            (false, pointer) => {
                channel.partial.clear();
                channel.synced = matches!(pointer, Pointer::At(_));
                match pointer {
                    Pointer::At(p) => Some(p),
                    _ => None,
                }
            }
        };
        let consumed = match begin {
            Some(skip) => {
                let pos = frame.data.start + skip;
                self.open = Some(Open {
                    channel: key,
                    pos,
                    zone_end: frame.data.end,
                });
                pos
            }
            None => self.params.cadu_len,
        };
        match gap {
            Some(loss) => Step::Lost {
                consumed,
                notice: Notice { offset, loss },
            },
            None => Step::Skip { consumed },
        }
    }

    /// Inside a data zone: move one piece of one packet.
    fn read_zone(&mut self, open: Open, buf: &[u8], offset: u64) -> Step {
        // `open_cadu` saw the whole CADU, so this only fails if the caller
        // dropped bytes it was not told to.
        if buf.len() < self.params.cadu_len - open.pos {
            return Step::NeedMore;
        }
        let Some(channel) = self.channels.get_mut(&open.channel) else {
            self.open = None;
            return Step::Skip {
                consumed: self.params.cadu_len - open.pos,
            };
        };
        let have = channel.partial.len();
        let want = match PrimaryHeader::parse(&channel.partial) {
            Some(header) => header.total_len().saturating_sub(have),
            None => PRIMARY_HEADER_LEN - have,
        };
        let left = open.zone_end - open.pos;
        let mut take = want.clamp(1, left);
        if have == 0 {
            channel.partial_offset = offset;
        }
        channel
            .partial
            .extend_from_slice(&self.cadu[open.pos..open.pos + take]);

        let mut record = None;
        if let Some(header) = PrimaryHeader::parse(&channel.partial) {
            if header.version != 0 {
                // Not a packet: this channel has lost its place. Give up on
                // the rest of the zone and wait for the next pointer.
                channel.partial.clear();
                channel.synced = false;
                take = left;
            } else if channel.partial.len() >= header.total_len() {
                let payload = std::mem::take(&mut channel.partial);
                if header.apid != IDLE_APID {
                    record = Some(Record {
                        offset: channel.partial_offset,
                        receive_time_ns: None,
                        label: None,
                        payload,
                    });
                }
            }
        }

        let pos = open.pos + take;
        let consumed = if pos == open.zone_end {
            self.open = None;
            self.params.cadu_len - open.pos
        } else {
            self.open = Some(Open { pos, ..open });
            take
        };
        match record {
            Some(record) => Step::Record { consumed, record },
            None => Step::Skip { consumed },
        }
    }
}

impl Decoder for CaduDecoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step {
        match self.open {
            None => self.open_cadu(buf, offset),
            Some(open) => self.read_zone(open, buf, offset),
        }
    }

    /// The layout the file was read with: part of it is detected or
    /// defaulted, so it is worth being able to see what was assumed.
    fn describe(&self) -> Option<String> {
        let p = &self.params;
        let mut text = format!(
            "{} frames in {}-byte CADUs",
            match p.kind {
                FrameKind::Tm => "TM",
                FrameKind::Aos => "AOS",
            },
            p.cadu_len
        );
        if p.randomized {
            text.push_str(", randomised");
        }
        if p.has_crc {
            text.push_str(", CRC");
        }
        match p.rs {
            Some(rs) => {
                text.push_str(&format!(", {} interleave {}", rs.code.name(), rs.depth));
                if rs.basis == Basis::Conventional {
                    text.push_str(" conventional basis");
                }
            }
            // Present but not used: say so by not naming a code.
            None if p.rs_parity_len > 0 => {
                text.push_str(&format!(", {} check bytes", p.rs_parity_len));
            }
            None => {}
        }
        Some(text)
    }

    fn summary(&self) -> Vec<Notice> {
        self.corrected
            .iter()
            .map(|&(blocks, units, offset)| Notice {
                offset,
                loss: Loss::Corrected {
                    coding: Coding::ReedSolomon,
                    blocks,
                    units,
                },
            })
            .collect()
    }
}

fn find_sync(bytes: &[u8]) -> Option<usize> {
    bytes.windows(SYNC.len()).position(|w| w == SYNC)
}

/// How many whole CADUs from the start of a file layout detection looks at.
const SNIFF_FRAMES: usize = 16;

/// The layout, if `prefix` reads as CADUs: three sync markers at one
/// spacing of a believable size, with no marker between the first two.
/// The rest of the layout is read from the whole CADUs that follow the
/// first marker, as far as they can tell it.
pub fn sniff_layout(prefix: &[u8]) -> Option<Layout> {
    let body = &prefix[find_sync(prefix)?..];
    let len = find_sync(body.get(SYNC.len()..)?)? + SYNC.len();
    let third = body.get(2 * len..2 * len + SYNC.len())?;
    if !(MIN_CADU_LEN..=MAX_CADU_LEN).contains(&len) || third != SYNC {
        return None;
    }
    let cadus: Vec<&[u8]> = body
        .chunks_exact(len)
        .take(SNIFF_FRAMES)
        .take_while(|c| c.starts_with(&SYNC))
        .collect();
    Layout::detect(&cadus)
}

/// The CADU length alone. See [`sniff_layout`].
pub fn sniff_cadu_len(prefix: &[u8]) -> Option<usize> {
    sniff_layout(prefix).map(|layout| layout.cadu_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::{DecodeEnd, decode_all};
    use crate::pure::finding::Kind;
    use crate::pure::rs::{Code, RsCode};
    use crate::pure::synth::{Source, cadus, frame_zones};

    const ZONE: usize = 50;
    const IDLE_POINTER: u16 = 0x7FE;

    fn params(kind: FrameKind) -> FrameParams {
        FrameParams {
            cadu_len: SYNC.len() + if kind == FrameKind::Tm { 6 } else { 8 } + ZONE + 2 + 32,
            kind,
            randomized: true,
            rs_parity_len: 32,
            // Check symbols that are only there to be skipped. The tests
            // further down that end in `_rs` use real ones.
            rs: None,
            has_crc: true,
            aos_has_ocf: false,
            aos_has_header_check: false,
            aos_insert_zone_len: 0,
        }
    }

    /// Packets of 11, 46 and 206 bytes, so that some share a frame, some
    /// straddle two, and some span several.
    fn packets_from(apid: u16) -> Vec<Vec<u8>> {
        let mut a = Source::new(apid, 16380, 5);
        let mut b = Source::new(apid + 1, 0, 40);
        let mut c = Source::new(apid + 2, 7, 200);
        (0..20)
            .flat_map(|_| [a.emit(), b.emit(), c.emit()])
            .collect()
    }

    fn packets() -> Vec<Vec<u8>> {
        packets_from(0x1A3)
    }

    fn zones(packets: &[Vec<u8>]) -> Vec<(u16, Vec<u8>)> {
        frame_zones(packets, ZONE)
    }

    fn frames(p: &FrameParams, vcid: u16, zones: &[(u16, Vec<u8>)]) -> Vec<Vec<u8>> {
        cadus(p, vcid, zones)
    }

    fn pack(p: &FrameParams, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        frames(p, 2, &zones(packets))
    }

    /// The packets with no byte in zone `k`.
    fn untouched_by(packets: &[Vec<u8>], k: usize) -> Vec<Vec<u8>> {
        let mut start = 0;
        let mut out = Vec::new();
        for pk in packets {
            let end = start + pk.len();
            if end <= k * ZONE || start >= (k + 1) * ZONE {
                out.push(pk.clone());
            }
            start = end;
        }
        out
    }

    fn decode(p: &FrameParams, data: &[u8]) -> (Vec<Record>, Option<DecodeEnd>) {
        decode_all(&mut CaduDecoder::new(*p).unwrap(), data)
    }

    fn payloads(records: &[Record]) -> Vec<Vec<u8>> {
        records.iter().map(|r| r.payload.clone()).collect()
    }

    #[test]
    fn reassembles_every_packet_with_offsets() {
        for kind in [FrameKind::Tm, FrameKind::Aos] {
            let p = params(kind);
            let packets = packets();
            let data = pack(&p, &packets).concat();
            let (records, end) = decode(&p, &data);
            assert_eq!(end, None);
            assert_eq!(payloads(&records), packets);
            // Each offset is where the packet's first byte sits in the file.
            let header = p.cadu_len - ZONE - 34;
            let mut start = 0;
            for (record, pk) in records.iter().zip(&packets) {
                let want = (start / ZONE) * p.cadu_len + header + start % ZONE;
                assert_eq!(record.offset, want as u64);
                start += pk.len();
            }
        }
    }

    /// Losing a frame, or failing its CRC, must cost exactly the packets
    /// that had bytes in it.
    #[test]
    fn a_lost_or_corrupt_frame_costs_only_its_packets() {
        let p = params(FrameKind::Tm);
        let packets = packets();
        let cadus = pack(&p, &packets);
        for k in 0..cadus.len() {
            let want = untouched_by(&packets, k);
            let mut dropped = cadus.clone();
            dropped.remove(k);
            let (records, end) = decode(&p, &dropped.concat());
            assert_eq!(end, None, "frame {k} dropped");
            assert_eq!(payloads(&records), want, "frame {k} dropped");

            let mut corrupt = cadus.clone();
            corrupt[k][20] ^= 0x10;
            let (records, end) = decode(&p, &corrupt.concat());
            // A corrupt last frame leaves a tail with no marker after it.
            if k + 1 < cadus.len() {
                assert_eq!(end, None, "frame {k} corrupt");
            } else {
                assert!(matches!(end, Some(DecodeEnd::Truncated { .. })));
            }
            assert_eq!(payloads(&records), want, "frame {k} corrupt");
        }
    }

    /// An idle frame in the middle of a packet does not break it, and a
    /// frame lost just before an idle frame is still noticed.
    #[test]
    fn idle_frames_carry_nothing_and_hide_nothing() {
        let p = params(FrameKind::Tm);
        let packets = packets();
        let plain = zones(&packets);
        for k in 0..plain.len() {
            let mut with_idle = plain.clone();
            with_idle.insert(k + 1, (IDLE_POINTER, vec![0xFF; ZONE]));
            let mut cadus = frames(&p, 2, &with_idle);
            let (records, _) = decode(&p, &cadus.concat());
            assert_eq!(payloads(&records), packets, "idle after frame {k}");

            cadus.remove(k);
            let (records, _) = decode(&p, &cadus.concat());
            assert_eq!(
                payloads(&records),
                untouched_by(&packets, k),
                "frame {k} lost"
            );
        }
    }

    #[test]
    fn virtual_channels_are_reassembled_separately() {
        let p = params(FrameKind::Aos);
        let (one, two) = (packets_from(0x100), packets_from(0x200));
        let data: Vec<u8> = frames(&p, 1, &zones(&one))
            .into_iter()
            .zip(frames(&p, 2, &zones(&two)))
            .flat_map(|(a, b)| [a, b].concat())
            .collect();
        let (records, end) = decode(&p, &data);
        assert_eq!(end, None);
        let got = payloads(&records);
        let of = |set: &[Vec<u8>]| -> Vec<Vec<u8>> {
            got.iter().filter(|pk| set.contains(pk)).cloned().collect()
        };
        assert_eq!(got.len(), one.len() + two.len());
        assert_eq!(of(&one), one);
        assert_eq!(of(&two), two);
    }

    /// Junk between frames, with no frame lost, costs nothing.
    #[test]
    fn skips_junk_between_frames() {
        let p = params(FrameKind::Tm);
        let packets = packets();
        let mut data = vec![0x55; 37];
        for (k, cadu) in pack(&p, &packets).iter().enumerate() {
            data.extend_from_slice(cadu);
            if k % 10 == 3 {
                data.extend([0x1A, 0xCF, 0xFC, 0x55, 0x1A, 0xCF]);
            }
        }
        let (records, end) = decode(&p, &data);
        assert_eq!(end, None);
        assert_eq!(payloads(&records), packets);
    }

    /// Offering the file one more byte at a time must give the same records:
    /// a `NeedMore` step may not change any state.
    #[test]
    fn byte_at_a_time_gives_the_same_records() {
        let p = params(FrameKind::Aos);
        let data = pack(&p, &packets()).concat();
        let (want, _) = decode(&p, &data);
        let mut decoder = CaduDecoder::new(p).unwrap();
        let (mut pos, mut end, mut got) = (0, 0, Vec::new());
        while end <= data.len() {
            match decoder.step(&data[pos..end], pos as u64) {
                Step::Record { consumed, record } => {
                    got.push(record);
                    pos += consumed;
                }
                Step::Skip { consumed } | Step::Lost { consumed, .. } => pos += consumed,
                Step::NeedMore => end += 1,
                Step::Fatal(e) => panic!("{e}"),
            }
            assert!(pos <= end);
        }
        assert_eq!(got, want);
    }

    #[test]
    fn truncation_at_every_offset() {
        let p = params(FrameKind::Tm);
        let data = pack(&p, &packets()).concat();
        let (full, _) = decode(&p, &data);
        for cut in 0..data.len() {
            let (records, end) = decode(&p, &data[..cut]);
            assert!(full.starts_with(&records), "cut at {cut}");
            if cut % p.cadu_len == 0 {
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
    fn wrong_parameters_are_fatal_not_silent() {
        let data = pack(&params(FrameKind::Tm), &packets()).concat();
        let (records, end) = decode(&params(FrameKind::Aos), &data);
        assert!(records.is_empty());
        assert!(matches!(end, Some(DecodeEnd::Error(_))), "{end:?}");
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        let mut p = params(FrameKind::Tm);
        p.randomized = false;
        p.has_crc = false;
        p.cadu_len = MIN_CADU_LEN;
        p.rs_parity_len = 0;
        let mut x = 0x2545F491u32;
        for len in 0..600usize {
            let mut data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            for (i, kind) in [FrameKind::Tm, FrameKind::Aos].into_iter().enumerate() {
                // Markers and the right version bits, so frames do get read.
                for chunk in data.chunks_mut(MIN_CADU_LEN) {
                    if chunk.len() > 5 && chunk[5] & 3 != 0 {
                        chunk[..4].copy_from_slice(&SYNC);
                        chunk[4] = (chunk[4] & 0x3F) | if i == 0 { 0 } else { 0x40 };
                    }
                }
                p.kind = kind;
                let _ = decode(&p, &data);
            }
            let _ = sniff_cadu_len(&data);
        }
    }

    #[test]
    fn sniffs_the_cadu_length() {
        let p = params(FrameKind::Tm);
        let mut data = vec![0x55; 9]; // capture started mid-frame
        data.extend(pack(&p, &packets()).concat());
        assert_eq!(sniff_cadu_len(&data), Some(p.cadu_len));
        assert_eq!(sniff_cadu_len(&data[..2 * p.cadu_len]), None);
        assert_eq!(sniff_cadu_len(&SYNC.repeat(50)), None);
        assert_eq!(sniff_cadu_len(&[]), None);
    }

    fn losses(p: &FrameParams, data: &[u8]) -> Vec<Notice> {
        let mut decoder = CaduDecoder::new(*p).unwrap();
        crate::pure::decode::decode_all_noting(&mut decoder, data)
            .1
            .list
    }

    #[test]
    fn what_is_given_up_is_reported() {
        let p = params(FrameKind::Tm);
        let cadus = pack(&p, &packets());
        let len = p.cadu_len as u64;
        // Frame k carries count (250 + k) mod 256, on spacecraft 0x155 channel 2.
        let gap = |at: u64, expected: u32, got: u32, missing: Option<u32>| Notice {
            offset: at,
            loss: Loss::FrameGap {
                scid: 0x155,
                vcid: 2,
                expected,
                got,
                missing,
            },
        };

        assert_eq!(losses(&p, &cadus.concat()), []);

        let mut dropped = cadus.clone();
        dropped.drain(10..12);
        assert_eq!(
            losses(&p, &dropped.concat()),
            [gap(10 * len, 4, 6, Some(2))]
        );

        // A frame that fails its CRC is one notice, not one for the frame
        // and another for its bytes; the count then shows it missing.
        let mut corrupt = cadus.clone();
        corrupt[10][20] ^= 0x10;
        let bad = Notice {
            offset: 10 * len,
            loss: Loss::BadFrame {
                reason: "frame CRC mismatch",
            },
        };
        assert_eq!(
            losses(&p, &corrupt.concat()),
            [bad, gap(11 * len, 4, 5, Some(1))]
        );

        // An old frame turning up again is a count going back, then forward.
        let mut replay = cadus.clone();
        replay.insert(30, cadus[5].clone());
        assert_eq!(
            losses(&p, &replay.concat()),
            [gap(30 * len, 24, 255, None), gap(31 * len, 0, 24, Some(24))]
        );

        // Bytes before the first marker are normal for a capture; bytes
        // between frames are not. Each run is one notice however it was read.
        let mut junk = vec![0x55; 37];
        junk.extend(cadus[..3].concat());
        junk.extend([0x1A, 0xCF, 0xFC, 0x55, 0x1A, 0xCF]);
        junk.extend(cadus[3..6].concat());
        junk.extend([0xEE; 9]);
        let got = losses(&p, &junk);
        let run = |offset: u64, bytes: u64| Notice {
            offset,
            loss: Loss::Junk { bytes },
        };
        // The last three bytes of the file are left as a truncated tail.
        assert_eq!(
            got,
            [run(0, 37), run(37 + 3 * len, 6), run(43 + 6 * len, 6)]
        );
        assert!(!got[0].is_problem());
        assert!(got[1].is_problem());
        assert_eq!(
            got[1].to_string(),
            format!(
                "6 bytes outside any frame skipped at byte {:#x}",
                37 + 3 * len
            )
        );
        assert_eq!(
            gap(0x40, 4, 6, Some(2)).to_string(),
            "Spacecraft 341 virtual channel 2: 2 frames missing before byte 0x40 (expected frame count 4, got 6)"
        );
    }

    #[test]
    fn a_flood_of_losses_is_counted_not_kept() {
        let p = params(FrameKind::Tm);
        let cadus = pack(&p, &packets());
        // Every other frame missing, many times over.
        let data: Vec<u8> = (0..1500)
            .map(|i| cadus[(i * 2) % cadus.len()].clone())
            .collect::<Vec<_>>()
            .concat();
        let mut decoder = CaduDecoder::new(p).unwrap();
        let notices = crate::pure::decode::decode_all_noting(&mut decoder, &data).1;
        assert_eq!(notices.list.len(), crate::pure::decode::MAX_NOTICES);
        assert_eq!(notices.list.len() as u64 + notices.more, 1499);
    }

    #[test]
    fn sniffs_the_layout_from_the_frames() {
        for kind in [FrameKind::Tm, FrameKind::Aos] {
            for (randomized, has_crc, rs_parity_len) in [
                (true, true, 32),
                (false, true, 0),
                (true, false, 32),
                (false, false, 0),
                (true, true, 160),
            ] {
                let mut p = params(kind);
                p.randomized = randomized;
                p.has_crc = has_crc;
                p.rs_parity_len = rs_parity_len;
                p.cadu_len = p.cadu_len - 34 + rs_parity_len + if has_crc { 2 } else { 0 };
                let data = crate::pure::synth::demo_cadus(&p, &packets().concat());
                let layout = sniff_layout(&data).unwrap();
                assert_eq!(layout.cadu_len, p.cadu_len);
                assert_eq!(layout.kind, Some(kind));
                assert_eq!(layout.randomized, Some(randomized));
                // Without a CRC there is nothing to say how long the check
                // symbols are; that stays for the configuration.
                assert_eq!(layout.crc_parity, has_crc.then_some(rs_parity_len), "{p:?}");
            }
        }
        // Frames that disagree about their version settle nothing.
        let p = params(FrameKind::Tm);
        let mut cadus = pack(&p, &packets());
        cadus[1][4] ^= 0x40;
        assert_eq!(
            sniff_layout(&cadus.concat()),
            Some(Layout::of_len(p.cadu_len))
        );
    }

    /// AOS fill frames on channel 63 are passed over whatever their count
    /// does; they are not reported as frames missing.
    #[test]
    fn aos_fill_frames_are_not_held_to_a_count() {
        let p = params(FrameKind::Aos);
        let packets = packets();
        let real = pack(&p, &packets);
        let fill = cadus(&p, 63, &vec![(0x7FE, vec![0xFF; ZONE]); 3]);
        // The same fill frame, count and all, between every pair of frames.
        let data: Vec<u8> = real
            .iter()
            .flat_map(|c| [c.clone(), fill[1].clone()].concat())
            .collect();
        let mut decoder = CaduDecoder::new(p).unwrap();
        let (records, notices, end) = crate::pure::decode::decode_all_noting(&mut decoder, &data);
        assert_eq!(end, None);
        assert_eq!(notices.list, []);
        assert_eq!(payloads(&records), packets);
    }

    /// A layout with real check symbols: a data zone of about `zone` bytes,
    /// made a little longer where the codeblock has to divide by the depth.
    fn rs_params(kind: FrameKind, rs: RsCode, has_crc: bool, zone: usize) -> (FrameParams, usize) {
        let fixed = if kind == FrameKind::Tm { 6 } else { 8 } + if has_crc { 2 } else { 0 };
        let zone = zone + (rs.depth - (fixed + zone) % rs.depth) % rs.depth;
        let p = FrameParams {
            cadu_len: SYNC.len() + fixed + zone + rs.parity_len(),
            kind,
            randomized: true,
            rs_parity_len: rs.parity_len(),
            rs: Some(rs),
            has_crc,
            aos_has_ocf: false,
            aos_has_header_check: false,
            aos_insert_zone_len: 0,
        };
        assert!(rs.fits(p.cadu_len - SYNC.len()), "{p:?}");
        (p, zone)
    }

    fn rs_cases() -> Vec<RsCode> {
        let mut out = Vec::new();
        for code in [Code::Rs223, Code::Rs239] {
            for (depth, basis) in [
                (1, Basis::Dual),
                (2, Basis::Conventional),
                (5, Basis::Dual),
                (8, Basis::Dual),
            ] {
                out.push(RsCode { code, depth, basis });
            }
        }
        out
    }

    /// Changes `count` different bytes after the marker, never the same
    /// codeword more than `per_word` times. Returns how many it changed.
    fn corrupt(cadu: &mut [u8], rs: &RsCode, per_word: usize, seed: &mut u32) -> usize {
        let block = &mut cadu[SYNC.len()..];
        let words = block.len() / rs.depth;
        let mut changed = 0;
        for lane in 0..rs.depth {
            let mut hit = Vec::new();
            while hit.len() < per_word.min(words) {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 17;
                *seed ^= *seed << 5;
                let at = *seed as usize % words;
                if !hit.contains(&at) {
                    hit.push(at);
                    block[at * rs.depth + lane] ^= (*seed >> 24) as u8 | 1;
                    changed += 1;
                }
            }
        }
        changed
    }

    fn noted(p: &FrameParams, data: &[u8]) -> (Vec<Record>, Vec<Notice>, Option<DecodeEnd>) {
        let mut decoder = CaduDecoder::new(*p).unwrap();
        let (records, notices, end) = crate::pure::decode::decode_all_noting(&mut decoder, data);
        assert_eq!(notices.more, 0);
        (records, notices.list, end)
    }

    /// Every frame damaged as badly as the code allows, in the header, the
    /// packets, the CRC and the check symbols alike: every packet comes
    /// back, and the damage is counted once for the file.
    #[test]
    fn corrects_every_frame_at_the_limit_rs() {
        let mut seed = 0x9E37_79B9u32;
        for kind in [FrameKind::Tm, FrameKind::Aos] {
            for rs in rs_cases() {
                for has_crc in [true, false] {
                    let (p, zone) = rs_params(kind, rs, has_crc, 60);
                    let packets = packets();
                    let mut cadus = cadus(&p, 2, &frame_zones(&packets, zone));
                    let clean = cadus.concat();
                    assert_eq!(noted(&p, &clean).1, [], "{p:?}");

                    let mut changed = 0;
                    for cadu in cadus.iter_mut().skip(1) {
                        changed += corrupt(cadu, &rs, rs.code.power(), &mut seed);
                    }
                    let (records, notices, end) = noted(&p, &cadus.concat());
                    assert_eq!(end, None, "{p:?}");
                    assert_eq!(payloads(&records), packets, "{p:?}");
                    let want = Notice {
                        offset: p.cadu_len as u64,
                        loss: Loss::Corrected {
                            coding: Coding::ReedSolomon,
                            blocks: cadus.len() as u64 - 1,
                            units: changed as u64,
                        },
                    };
                    assert_eq!(notices, std::slice::from_ref(&want), "{p:?}");
                    assert!(!want.is_problem());
                    assert_eq!(want.kind(), Kind::Corrected);
                }
            }
        }
    }

    /// One codeword of one frame with one error too many: that frame is
    /// lost, and only that frame.
    #[test]
    fn a_frame_past_correcting_is_dropped_rs() {
        let mut seed = 0x1357_9BDFu32;
        for rs in rs_cases() {
            let (p, zone) = rs_params(FrameKind::Tm, rs, true, 60);
            let packets = packets();
            let zones = frame_zones(&packets, zone);
            let mut cadus = cadus(&p, 2, &zones);
            let k = 4;
            // Depth 1 for the damage: all of it lands in the first codeword.
            let one = RsCode { depth: 1, ..rs };
            let words = (p.cadu_len - SYNC.len()) / rs.depth;
            let mut word: Vec<u8> = (0..words)
                .map(|i| cadus[k][SYNC.len() + i * rs.depth])
                .collect();
            let mut marked = SYNC.to_vec();
            marked.append(&mut word);
            corrupt(&mut marked, &one, rs.code.power() + 1, &mut seed);
            for i in 0..words {
                cadus[k][SYNC.len() + i * rs.depth] = marked[SYNC.len() + i];
            }

            let (records, notices, end) = noted(&p, &cadus.concat());
            assert_eq!(end, None);
            let mut start = 0;
            let want: Vec<Vec<u8>> = packets
                .iter()
                .filter(|pk| {
                    let end = start + pk.len();
                    let keep = end <= k * zone || start >= (k + 1) * zone;
                    start = end;
                    keep
                })
                .cloned()
                .collect();
            assert_eq!(payloads(&records), want, "{rs:?}");
            assert_eq!(notices.len(), 2, "{notices:?}");
            assert_eq!(
                notices[0],
                Notice {
                    offset: (k * p.cadu_len) as u64,
                    loss: Loss::BadFrame {
                        reason: "more errors than Reed-Solomon can correct"
                    },
                }
            );
            assert!(matches!(
                notices[1].loss,
                Loss::FrameGap {
                    missing: Some(1),
                    ..
                }
            ));
        }
    }

    /// Reed-Solomon can only say a block is a codeword, not that it is the
    /// one that was sent. A corrected frame is still held to its CRC.
    #[test]
    fn a_corrected_frame_must_still_pass_its_crc_rs() {
        let rs = RsCode {
            code: Code::Rs223,
            depth: 1,
            basis: Basis::Dual,
        };
        let (p, zone) = rs_params(FrameKind::Tm, rs, true, 60);
        let mut cadus = cadus(&p, 2, &frame_zones(&packets(), zone));
        // Frame 3 as a different codeword: a data byte changed and the
        // check symbols worked out again, the CRC left as it was.
        let k = 3;
        let block_end = p.cadu_len - p.rs_parity_len;
        frame::derandomize(&mut cadus[k][SYNC.len()..]);
        cadus[k][20] ^= 0x04;
        let parity = rs.encode(&cadus[k][SYNC.len()..block_end]).unwrap();
        cadus[k][block_end..].copy_from_slice(&parity);
        frame::derandomize(&mut cadus[k][SYNC.len()..]);
        let reasons = |data: &[u8]| -> Vec<&'static str> {
            noted(&p, data)
                .1
                .iter()
                .filter_map(|n| match n.loss {
                    Loss::BadFrame { reason } => Some(reason),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(reasons(&cadus.concat()), ["frame CRC mismatch"]);
        cadus[k][40] ^= 0x80;
        assert_eq!(
            reasons(&cadus.concat()),
            ["frame CRC mismatch after Reed-Solomon correction"]
        );
    }

    #[test]
    fn sniffs_the_code_from_a_clean_frame_rs() {
        let mut seed = 0x0F1E_2D3Cu32;
        for kind in [FrameKind::Tm, FrameKind::Aos] {
            for rs in rs_cases() {
                for has_crc in [true, false] {
                    let (p, zone) = rs_params(kind, rs, has_crc, 60);
                    let mut cadus = cadus(&p, 2, &frame_zones(&packets(), zone));
                    let want = Layout {
                        cadu_len: p.cadu_len,
                        kind: Some(kind),
                        randomized: Some(true),
                        crc_parity: has_crc.then_some(rs.parity_len()),
                        rs: Some(rs),
                    };
                    assert_eq!(sniff_layout(&cadus.concat()), Some(want), "{p:?}");
                    // What the configuration makes of that, saying nothing itself.
                    let config = crate::pure::config::Config::default();
                    assert_eq!(config.frame_params_for(&want), p);

                    // A noisy start: only one frame of those looked at is
                    // clean, and one has its version bits hit.
                    for (i, cadu) in cadus.iter_mut().enumerate().take(SNIFF_FRAMES) {
                        if i != 5 {
                            corrupt(cadu, &rs, rs.code.power() - 1, &mut seed);
                        }
                    }
                    cadus[2][SYNC.len()] ^= 0xC0;
                    let noisy = cadus.concat();
                    // Position 0 of codeword 0 may have been hit already,
                    // and one more error there is still within reach.
                    assert_eq!(sniff_layout(&noisy), Some(want), "{p:?}");
                    let (records, notices, _) = noted(&p, &noisy);
                    assert_eq!(payloads(&records), packets());
                    assert!(matches!(
                        notices[..],
                        [Notice {
                            loss: Loss::Corrected { .. },
                            ..
                        }]
                    ));
                }
            }
        }
    }

    /// Check symbols a recorder zeroed are not a code, even behind frames
    /// that are nearly all zeros and so "correct" to the all-zero codeword.
    #[test]
    fn zero_filled_check_symbols_are_not_taken_for_a_code() {
        let mut p = params(FrameKind::Tm);
        p.randomized = false;
        let idle = vec![(IDLE_POINTER, vec![0u8; ZONE]); 6];
        let data = frames(&p, 0, &idle).concat();
        let layout = sniff_layout(&data).unwrap();
        assert_eq!(layout.rs, None);
        assert_eq!(layout.crc_parity, Some(32));
        let p = crate::pure::config::Config::default().frame_params_for(&layout);
        assert_eq!((p.rs, p.rs_parity_len, p.has_crc), (None, 32, true));
        assert_eq!(noted(&p, &data).1, []);
    }

    /// The lengths check symbols can have are 16 and 32 times a depth, and
    /// a CRC in front of filler of any of them is found.
    #[test]
    fn sniffs_a_crc_before_any_length_of_filler() {
        for parity in [0, 16, 32, 48, 64, 80, 96, 128, 160, 256] {
            let mut p = params(FrameKind::Aos);
            p.cadu_len = p.cadu_len - 32 + parity;
            p.rs_parity_len = parity;
            let data = pack(&p, &packets()).concat();
            let layout = sniff_layout(&data).unwrap();
            assert_eq!((layout.crc_parity, layout.rs), (Some(parity), None));
        }
    }
}
