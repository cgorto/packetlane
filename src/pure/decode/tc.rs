//! Telecommand captures: CLTUs as they went up the link, or the TC transfer
//! frames inside them back to back, as ground systems often log them.
//!
//! `pure/tc.rs` reads one CLTU or one frame header; this file walks the
//! file, checks each virtual channel's frame sequence, and takes the space
//! packets out of the frames.
//!
//! A CLTU can hold several packets and has to be read whole before any of
//! them is known, but a step can hand over only one record. So the step
//! that reads a CLTU (or a bare frame) queues what it found, and each step
//! after that hands over one item and consumes one byte, the last one
//! consuming the rest. A CLTU is always longer than what it can yield.
//!
//! Between CLTUs: a tail sequence and idle fill are passed over; anything
//! else is skipped up to the next start sequence and reported. A file of
//! bare frames has no marker to find again, so there a header that cannot
//! be one ends the read.
//!
//! What is checked:
//!
//! - AD frames: N(S) must count up by one per virtual channel. A jump is
//!   reported, and a packet half reassembled on that channel is dropped.
//!   A count that goes back is reported too: on a real link that is a
//!   retransmission, and the packets in it are in the log twice.
//! - BD frames carry no meaningful count. BC frames carry a control command
//!   and no packets: they are counted, not reported as lost. A Set V(R)
//!   command moves the count the next AD frame is held to.
//! - With segment headers, a packet cut into first, continuation and last
//!   segments is put back together per MAP.

use std::collections::{BTreeMap, VecDeque};

use super::{Coding, DecodeError, Decoder, Loss, Notice, Record, Step};
use crate::pure::ccsds::{IDLE_APID, PrimaryHeader};
use crate::pure::frame::CRC_MISMATCH;
use crate::pure::tc::{
    self, BLOCK_LEN, Bch, CRC_LEN, CltuRead, FILL, HEADER_LEN, INFO_LEN, START, TAIL, TcParams,
};

/// If this many frames fail before any succeeds, the file is not what it
/// was taken for.
const GIVE_UP_AFTER: u32 = 16;
/// A space packet cannot be longer than this, so neither can segments that
/// make one up.
const MAX_REASSEMBLED: usize = 6 + 65536;

/// How to turn a position in a unit's frame bytes into a file offset.
#[derive(Debug, Clone, Copy)]
enum Place {
    /// Frames back to back: the offset of the unit's first byte.
    Plain(u64),
    /// Codeblocks: the offset of the first one. Every eighth byte of the
    /// file is parity.
    Coded(u64),
}

impl Place {
    fn at(self, d: usize) -> u64 {
        match self {
            Place::Plain(base) => base + d as u64,
            Place::Coded(base) => base + (d / INFO_LEN * BLOCK_LEN + d % INFO_LEN) as u64,
        }
    }
}

/// A packet being put back together from segments.
#[derive(Debug, Default)]
struct Partial {
    bytes: Vec<u8>,
    /// For each segment: where it starts in `bytes`, and where that byte is
    /// in the file.
    pieces: Vec<(usize, Place, usize)>,
}

impl Partial {
    fn push(&mut self, segment: &[u8], place: Place, d: usize) {
        self.pieces.push((self.bytes.len(), place, d));
        self.bytes.extend_from_slice(segment);
    }

    /// The file offset of byte `k` of the packet.
    fn offset_of(&self, k: usize) -> u64 {
        self.pieces
            .iter()
            .rev()
            .find(|(start, _, _)| *start <= k)
            .map_or(0, |(start, place, d)| place.at(d + k - start))
    }
}

#[derive(Debug)]
enum Item {
    Record(Record),
    Notice(Notice),
}

#[derive(Debug)]
pub struct TcDecoder {
    params: TcParams,
    /// What the unit just read yielded and has not been handed over yet.
    pending: VecDeque<Item>,
    /// Bytes of that unit not yet consumed.
    owed: usize,
    /// Per spacecraft and virtual channel: the N(S) the next AD frame
    /// should carry.
    channels: BTreeMap<(u16, u8), u8>,
    /// Per spacecraft, virtual channel and MAP.
    partials: BTreeMap<(u16, u8, u8), Partial>,
    good_frames: u64,
    bad_frames: u32,
    /// True from a CLTU that could not be read to the next start sequence:
    /// the bytes passed over in between are that CLTU, not junk.
    in_bad_cltu: bool,
    /// The spacecraft of the last frame, if its CLTU ended exactly at the
    /// end of a codeblock: more of the same CLTU may follow.
    open_ended: Option<u16>,
    /// Codeblocks with a bit corrected, and where the first one is.
    corrected: Option<(u64, u64)>,
    /// Control frames: Unlock, Set V(R), other; and where the first one is.
    control: Option<([u64; 3], u64)>,
}

impl TcDecoder {
    pub fn new(params: TcParams) -> Self {
        Self {
            params,
            pending: VecDeque::new(),
            owed: 0,
            channels: BTreeMap::new(),
            partials: BTreeMap::new(),
            good_frames: 0,
            bad_frames: 0,
            in_bad_cltu: false,
            open_ended: None,
            corrected: None,
            control: None,
        }
    }

    fn lost(&mut self, offset: u64, reason: &'static str) {
        self.pending.push_back(Item::Notice(Notice {
            offset,
            loss: Loss::BadFrame { reason },
        }));
    }

    /// Queues the packets in `bytes`, which should be whole packets back to
    /// back. `offset_of` gives the file offset of a position in `bytes`.
    fn packets(&mut self, bytes: &[u8], offset_of: impl Fn(usize) -> u64) {
        let mut pos = 0;
        while pos < bytes.len() {
            let rest = &bytes[pos..];
            let header = PrimaryHeader::parse(rest).filter(|h| h.version == 0);
            let Some(packet) = header.and_then(|h| rest.get(..h.total_len())) else {
                self.lost(offset_of(pos), "frame data is not whole space packets");
                return;
            };
            if header.is_some_and(|h| h.apid != IDLE_APID) {
                self.pending.push_back(Item::Record(Record {
                    offset: offset_of(pos),
                    receive_time_ns: None,
                    label: None,
                    payload: packet.to_vec(),
                }));
            }
            pos += packet.len();
        }
    }

    /// One frame: `frame` is byte `d` on of a unit whose bytes are at
    /// `place`. Queues what it yields.
    fn frame(&mut self, frame: &[u8], place: Place, d: usize) {
        let at = place.at(d);
        let header = match tc::parse_header(frame) {
            Ok(header) => header,
            Err(reason) => return self.bad(at, reason),
        };
        let mut end = frame.len();
        if self.params.has_crc {
            if !tc::crc_ok(frame) {
                return self.bad(at, CRC_MISMATCH);
            }
            end -= CRC_LEN;
        }
        let data = &frame[HEADER_LEN..end];
        let channel = (header.scid, header.vcid);

        if header.control {
            if !header.bypass {
                return self.bad(at, "TC frame flags say control command without bypass");
            }
            self.good_frames += 1;
            let (counts, _) = self.control.get_or_insert(([0; 3], at));
            match *data {
                [0x00] => counts[0] += 1,
                [0x82, 0x00, vr] => {
                    counts[1] += 1;
                    // The receiver now expects this number next.
                    self.channels.insert(channel, vr);
                }
                _ => counts[2] += 1,
            }
            return;
        }
        self.good_frames += 1;

        if !header.bypass {
            let expected = self.channels.insert(channel, header.seq.wrapping_add(1));
            if let Some(expected) = expected.filter(|&e| e != header.seq) {
                let missing = u32::from(header.seq.wrapping_sub(expected));
                self.pending.push_back(Item::Notice(Notice {
                    offset: at,
                    loss: Loss::FrameGap {
                        scid: header.scid,
                        vcid: header.vcid,
                        expected: u32::from(expected),
                        got: u32::from(header.seq),
                        missing: (missing <= 128).then_some(missing),
                    },
                }));
                // Whatever was half put together cannot be finished.
                self.partials.retain(|&(s, v, _), _| (s, v) != channel);
            }
        }

        let d = d + HEADER_LEN;
        if !self.params.segment_header {
            return self.packets(data, |k| place.at(d + k));
        }
        let Some((&first, body)) = data.split_first() else {
            return self.lost(at, "TC frame has no room for its segment header");
        };
        let d = d + 1;
        let key = (header.scid, header.vcid, first & 0x3F);
        let flags = first >> 6;
        let open = self.partials.remove(&key);
        match flags {
            0b11 | 0b01 => {
                // A fresh start: anything still open on this MAP was never
                // finished.
                if open.is_some() {
                    self.lost(at, "segmented packet was not finished");
                }
                if flags == 0b11 {
                    return self.packets(body, |k| place.at(d + k));
                }
                let mut partial = Partial::default();
                partial.push(body, place, d);
                self.partials.insert(key, partial);
            }
            _ => {
                let Some(mut partial) = open else {
                    return self.lost(at, "segment continues a packet whose start was not seen");
                };
                partial.push(body, place, d);
                if partial.bytes.len() > MAX_REASSEMBLED {
                    self.lost(at, "segments add up to more than a space packet");
                } else if flags == 0b10 {
                    self.packets(&partial.bytes, |k| partial.offset_of(k));
                } else {
                    self.partials.insert(key, partial);
                }
            }
        }
    }

    /// A frame that cannot be used.
    fn bad(&mut self, offset: u64, reason: &'static str) {
        self.bad_frames += 1;
        self.lost(offset, reason);
    }

    /// Hands over the next queued item, or passes over the unit's bytes if
    /// it yielded nothing.
    fn hand_over(&mut self) -> Step {
        // Cannot happen (see the top of this file), but a step must not
        // consume more than the unit has.
        self.pending.truncate(self.owed.max(1));
        let consumed = if self.pending.len() > 1 { 1 } else { self.owed };
        self.owed -= consumed;
        match self.pending.pop_front() {
            Some(Item::Record(record)) => Step::Record { consumed, record },
            Some(Item::Notice(notice)) => Step::Lost { consumed, notice },
            None => Step::Skip { consumed },
        }
    }

    /// `Fatal` if nothing has ever been read right and a lot has gone wrong.
    fn given_up(&self, offset: u64, reason: &'static str) -> Option<Step> {
        (self.good_frames == 0 && self.bad_frames >= GIVE_UP_AFTER)
            .then_some(Step::Fatal(DecodeError::Implausible { offset, reason }))
    }

    /// Takes in a CLTU that was read: `lead` bytes of start sequence, then
    /// its codeblocks, at `offset`.
    fn cltu(&mut self, cltu: tc::Cltu, offset: u64, lead: usize) -> Step {
        let place = Place::Coded(offset + lead as u64);
        if cltu.fixed > 0 {
            self.corrected.get_or_insert((0, offset)).0 += cltu.fixed;
        }
        let mut last_scid = None;
        for range in &cltu.frames {
            let frame = &cltu.data[range.clone()];
            last_scid = tc::parse_header(frame).ok().map(|h| h.scid);
            self.frame(frame, place, range.start);
        }
        if let Some(reason) = cltu.trouble {
            self.bad(place.at(cltu.data.len()), reason);
        }
        self.in_bad_cltu = cltu.trouble.is_some();
        self.open_ended = last_scid.filter(|_| cltu.open_ended);
        self.owed = lead + cltu.blocks * BLOCK_LEN;
        self.given_up(offset, "no usable TC frame in the CLTUs")
            .unwrap_or_else(|| self.hand_over())
    }

    /// Between CLTUs.
    fn find_cltu(&mut self, buf: &[u8], offset: u64) -> Step {
        let Some(&first) = buf.first() else {
            return Step::NeedMore;
        };
        if first == START[0] && buf.len() < START.len() {
            return Step::NeedMore;
        }
        if let Some(blocks) = buf.strip_prefix(&START) {
            return match tc::read_cltu(blocks, self.params.randomized) {
                CltuRead::NeedMore => Step::NeedMore,
                CltuRead::Read(cltu) => self.cltu(cltu, offset, START.len()),
                CltuRead::Bad(reason) => {
                    self.bad_frames += 1;
                    self.open_ended = None;
                    if let Some(fatal) = self.given_up(offset, reason) {
                        return fatal;
                    }
                    // Damage, or these two bytes by chance. Step past them
                    // only, so a real start just behind is not jumped over.
                    self.in_bad_cltu = true;
                    Step::Lost {
                        consumed: START.len(),
                        notice: Notice {
                            offset,
                            loss: Loss::BadFrame { reason },
                        },
                    }
                }
            };
        }
        if first == FILL {
            // An idle link. Whatever CLTU came before is over.
            self.open_ended = None;
            let consumed = buf.iter().take_while(|&&b| b == FILL).count();
            return Step::Skip { consumed };
        }
        if TAIL.starts_with(&buf[..buf.len().min(TAIL.len())]) {
            if buf.len() < TAIL.len() {
                return Step::NeedMore;
            }
            self.open_ended = None;
            return Step::Skip {
                consumed: TAIL.len(),
            };
        }
        if let Some(scid) = self.open_ended.filter(|_| !self.in_bad_cltu) {
            // The last CLTU ended on a codeblock boundary and nothing has
            // closed it. If this is a clean codeblock holding a header of
            // the same spacecraft, it is the next frame of that CLTU.
            let Some(mut block) = buf
                .get(..BLOCK_LEN)
                .and_then(|b| <[u8; BLOCK_LEN]>::try_from(b).ok())
            else {
                return Step::NeedMore;
            };
            let follows = !self.params.randomized
                && tc::bch_correct(&mut block) == Bch::Clean
                && tc::parse_header(&block).is_ok_and(|h| h.scid == scid);
            if follows {
                match tc::read_cltu(buf, false) {
                    CltuRead::NeedMore => return Step::NeedMore,
                    CltuRead::Read(cltu) => return self.cltu(cltu, offset, 0),
                    CltuRead::Bad(_) => {}
                }
            }
            self.open_ended = None;
        }
        // Not a CLTU: skip to the next thing that might start one. The last
        // byte is kept, as a start sequence may be split across reads.
        let consumed = (1..buf.len())
            .find(|&i| buf[i] == START[0] && buf.get(i + 1).is_none_or(|&b| b == START[1]))
            .unwrap_or(buf.len());
        if self.in_bad_cltu {
            return Step::Skip { consumed };
        }
        Step::Lost {
            consumed,
            notice: Notice {
                offset,
                loss: Loss::Junk {
                    bytes: consumed as u64,
                },
            },
        }
    }

    /// At the start of a bare frame.
    fn bare_frame(&mut self, buf: &[u8], offset: u64) -> Step {
        if buf.len() < HEADER_LEN {
            return Step::NeedMore;
        }
        let header = match tc::parse_header(buf) {
            Ok(header) => header,
            // Nothing says where the next frame starts.
            Err(reason) => return Step::Fatal(DecodeError::Implausible { offset, reason }),
        };
        let Some(frame) = buf.get(..header.len) else {
            return Step::NeedMore;
        };
        self.frame(frame, Place::Plain(offset), 0);
        self.owed = header.len;
        self.given_up(offset, "no usable TC frame")
            .unwrap_or_else(|| self.hand_over())
    }
}

impl Decoder for TcDecoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step {
        if self.owed > 0 {
            // The unit was whole when it was read, so this only fails if
            // the caller dropped bytes it was not told to.
            if buf.len() < self.owed {
                return Step::NeedMore;
            }
            return self.hand_over();
        }
        match self.params.cltu {
            true => self.find_cltu(buf, offset),
            false => self.bare_frame(buf, offset),
        }
    }

    /// The layout the file was read with: most of it is detected or
    /// defaulted, so it is worth being able to see what was assumed.
    fn describe(&self) -> Option<String> {
        let p = &self.params;
        let mut text = String::from(match p.cltu {
            true => "TC frames in CLTUs",
            false => "TC frames back to back",
        });
        if p.cltu && p.randomized {
            text.push_str(", randomised");
        }
        text.push_str(if p.has_crc { ", CRC" } else { ", no CRC" });
        text.push_str(match p.segment_header {
            true => ", segment headers",
            false => ", no segment headers",
        });
        Some(text)
    }

    fn summary(&self) -> Vec<Notice> {
        let corrected = self.corrected.map(|(blocks, offset)| Notice {
            offset,
            loss: Loss::Corrected {
                coding: Coding::Bch,
                blocks,
                units: blocks,
            },
        });
        let control = self
            .control
            .map(|([unlock, set_vr, other], offset)| Notice {
                offset,
                loss: Loss::ControlFrames {
                    unlock,
                    set_vr,
                    other,
                },
            });
        corrected.into_iter().chain(control).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::{DecodeEnd, Format, decode_all, decode_all_noting, sniff};
    use crate::pure::synth::{TcFrame, cltu, tc_packet, tc_segments};
    use crate::pure::tc::{TcLayout, sniff_cltus, sniff_frames};

    const CLTU: TcParams = TcParams {
        cltu: true,
        has_crc: true,
        segment_header: true,
        randomized: false,
    };
    const BARE: TcParams = TcParams {
        cltu: false,
        ..CLTU
    };

    /// Commands of 8 to 40 bytes on two APIDs.
    fn commands(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let apid = if i % 3 == 0 { 0x0C8 } else { 0x0C9 };
                tc_packet(apid, i as u16, &vec![i as u8; 2 + (i * 7) % 33])
            })
            .collect()
    }

    /// One AD frame per command on channel 1, N(S) from 250 so it wraps.
    fn frames(p: &TcParams, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        packets
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                let frame = TcFrame::ad(0x155, 1, 250u8.wrapping_add(i as u8));
                match p.segment_header {
                    true => frame.build(&tc_segments(3, pk, 1000)[0], p.has_crc),
                    false => frame.build(pk, p.has_crc),
                }
            })
            .collect()
    }

    fn wrap(p: &TcParams, frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
        frames
            .iter()
            .map(|f| match p.cltu {
                true => cltu(f, p.randomized),
                false => f.clone(),
            })
            .collect()
    }

    fn file(p: &TcParams, packets: &[Vec<u8>]) -> Vec<u8> {
        wrap(p, &frames(p, packets)).concat()
    }

    fn decode(p: &TcParams, data: &[u8]) -> (Vec<Record>, Vec<Notice>, Option<DecodeEnd>) {
        let (records, notices, end) = decode_all_noting(&mut TcDecoder::new(*p), data);
        assert_eq!(notices.more, 0);
        (records, notices.list, end)
    }

    fn payloads(records: &[Record]) -> Vec<Vec<u8>> {
        records.iter().map(|r| r.payload.clone()).collect()
    }

    fn every_layout() -> Vec<TcParams> {
        let mut out = Vec::new();
        for cltu in [true, false] {
            for has_crc in [true, false] {
                for segment_header in [true, false] {
                    for randomized in [false, true] {
                        if cltu || !randomized {
                            out.push(TcParams {
                                cltu,
                                has_crc,
                                segment_header,
                                randomized,
                            });
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn reads_every_packet_with_offsets() {
        for p in every_layout() {
            let packets = commands(40);
            let units = wrap(&p, &frames(&p, &packets));
            let (records, notices, end) = decode(&p, &units.concat());
            assert_eq!((notices, end), (vec![], None), "{p:?}");
            assert_eq!(payloads(&records), packets, "{p:?}");
            // Each offset is where the packet's first byte sits in the file:
            // past the header and segment header, which in a CLTU are both
            // in the first codeblock.
            let mut start = 0;
            for (record, unit) in records.iter().zip(&units) {
                let lead = if p.cltu { 2 } else { 0 };
                let header = HEADER_LEN + usize::from(p.segment_header);
                assert_eq!(record.offset, (start + lead + header) as u64, "{p:?}");
                start += unit.len();
            }
        }
    }

    /// A CLTU by hand, so that the builder is not the only witness: one BD
    /// frame holding one 7-byte command, no CRC, no segment header. Twelve
    /// frame bytes are two codeblocks with two bytes of fill.
    #[test]
    fn reads_a_cltu_written_out_by_hand() {
        let frame = [
            0x21, 0x55, 0x04, 0x0B, 0x00, // BD, spacecraft 0x155, channel 1, 12 bytes
            0x10, 0xC8, 0xC0, 0x05, 0x00, 0x00, 0xAB, // command on APID 0xC8
        ];
        let mut data = vec![0xEB, 0x90];
        data.extend(&frame[..7]);
        data.push(tc::bch_parity(frame[..7].try_into().unwrap()));
        let last: [u8; 7] = [0xC0, 0x05, 0x00, 0x00, 0xAB, 0x55, 0x55];
        assert_eq!(frame[7..], last[..5]);
        data.extend(last);
        data.push(tc::bch_parity(&last));
        data.extend(TAIL);
        let p = TcParams {
            has_crc: false,
            segment_header: false,
            ..CLTU
        };
        let (records, notices, end) = decode(&p, &data);
        assert_eq!((notices, end), (vec![], None));
        assert_eq!(payloads(&records), [frame[5..].to_vec()]);
        // Frame byte 5 is the sixth byte of the first codeblock.
        assert_eq!(records[0].offset, 7);
        assert_eq!(cltu(&frame, false), data);
    }

    #[test]
    fn one_wrong_bit_per_codeblock_is_corrected_and_counted() {
        for randomized in [false, true] {
            let p = TcParams { randomized, ..CLTU };
            let packets = commands(30);
            let mut data = file(&p, &packets);
            // One bit in every third codeblock of every CLTU, parity
            // bytes and filler bits included.
            let mut fixed = 0;
            let mut at = 0;
            for unit in wrap(&p, &frames(&p, &packets)) {
                let blocks = (unit.len() - START.len() - TAIL.len()) / BLOCK_LEN;
                for block in (0..blocks).step_by(3) {
                    let bit = (at * 5 + block * 11) % 64;
                    data[at + 2 + block * 8 + bit / 8] ^= 0x80 >> (bit % 8);
                    fixed += u64::from(bit != 63);
                }
                at += unit.len();
            }
            let (records, notices, end) = decode(&p, &data);
            assert_eq!(end, None);
            assert_eq!(payloads(&records), packets);
            let want = Notice {
                offset: 0,
                loss: Loss::Corrected {
                    coding: Coding::Bch,
                    blocks: fixed,
                    units: fixed,
                },
            };
            assert_eq!(notices, std::slice::from_ref(&want));
            assert!(!want.is_problem());
            assert_eq!(
                want.to_string(),
                format!("BCH corrected {fixed} bits in {fixed} codeblocks, the first at byte 0x0")
            );
        }
    }

    /// Two wrong bits in a codeblock lose that CLTU's frame and nothing
    /// else, and the frame count shows what went.
    #[test]
    fn a_codeblock_past_correcting_costs_its_frame() {
        let packets = commands(20);
        let units = wrap(&CLTU, &frames(&CLTU, &packets));
        for k in 0..units.len() {
            let blocks = (units[k].len() - 10) / 8;
            for block in [0, blocks - 1] {
                let mut damaged = units.clone();
                damaged[k][2 + block * 8] ^= 0x81;
                let (records, notices, end) = decode(&CLTU, &damaged.concat());
                assert_eq!(end, None);
                let mut want = packets.clone();
                want.remove(k);
                assert_eq!(payloads(&records), want, "CLTU {k} block {block}");
                let bad: Vec<_> = notices
                    .iter()
                    .filter(|n| matches!(n.loss, Loss::BadFrame { .. }))
                    .collect();
                assert_eq!(bad.len(), 1, "{notices:?}");
                let gaps = notices
                    .iter()
                    .filter(|n| matches!(n.loss, Loss::FrameGap { .. }))
                    .count();
                // Not before the first frame: there was no count to follow.
                assert_eq!(gaps, usize::from(k > 0 && k + 1 < units.len()));
                // The rest of the damaged CLTU is not reported again as junk.
                assert_eq!(notices.len(), 1 + gaps, "{notices:?}");
            }
        }
    }

    #[test]
    fn frame_sequence_is_checked_for_ad_frames_only() {
        for p in [CLTU, BARE] {
            let packets = commands(12);
            let seg = |pk: &Vec<u8>| tc_segments(0, pk, 1000).remove(0);
            let gap = |expected: u32, got: u32, missing: Option<u32>| Loss::FrameGap {
                scid: 0x155,
                vcid: 1,
                expected,
                got,
                missing,
            };
            let losses = |frames: &[Vec<u8>]| -> Vec<Loss> {
                let (records, notices, end) = decode(&p, &wrap(&p, frames).concat());
                assert_eq!(end, None);
                assert_eq!(records.len(), frames.len());
                notices.into_iter().map(|n| n.loss).collect()
            };
            let ad = |n: u8, pk: &Vec<u8>| TcFrame::ad(0x155, 1, n).build(&seg(pk), true);
            let bd = |n: u8, pk: &Vec<u8>| TcFrame::bd(0x155, 1, n).build(&seg(pk), true);

            // Counting up through the wrap: nothing to say.
            let run: Vec<_> = (0..6)
                .map(|i| ad(253u8.wrapping_add(i), &packets[0]))
                .collect();
            assert_eq!(losses(&run), []);
            // Two missing, then one sent again.
            let frames = [
                ad(5, &packets[0]),
                ad(8, &packets[1]),
                ad(9, &packets[2]),
                ad(9, &packets[2]),
                ad(10, &packets[3]),
            ];
            assert_eq!(losses(&frames), [gap(6, 8, Some(2)), gap(10, 9, None)]);
            // Expedited frames in between count for nothing, whatever they carry.
            let frames = [
                ad(5, &packets[0]),
                bd(77, &packets[1]),
                bd(0, &packets[2]),
                ad(6, &packets[3]),
            ];
            assert_eq!(losses(&frames), []);
            // Another virtual channel has its own count.
            let frames = [
                ad(5, &packets[0]),
                TcFrame::ad(0x155, 2, 200).build(&seg(&packets[1]), true),
                ad(6, &packets[2]),
                TcFrame::ad(0x155, 2, 201).build(&seg(&packets[3]), true),
            ];
            assert_eq!(losses(&frames), []);
        }
    }

    #[test]
    fn control_frames_are_counted_and_cost_nothing() {
        for p in [CLTU, BARE] {
            let packets = commands(3);
            let seg = |pk: &Vec<u8>| tc_segments(0, pk, 1000).remove(0);
            let frames = [
                TcFrame::bc(0x155, 1).build(&[0x00], true),
                TcFrame::bc(0x155, 1).build(&[0x82, 0x00, 40], true),
                TcFrame::ad(0x155, 1, 40).build(&seg(&packets[0]), true),
                TcFrame::ad(0x155, 1, 41).build(&seg(&packets[1]), true),
                TcFrame::bc(0x155, 1).build(&[0x00], true),
                TcFrame::bc(0x155, 1).build(&[0x99, 0x01], true),
                TcFrame::ad(0x155, 1, 42).build(&seg(&packets[2]), true),
            ];
            let units = wrap(&p, &frames);
            let (records, notices, end) = decode(&p, &units.concat());
            assert_eq!(end, None);
            assert_eq!(payloads(&records), packets);
            let want = Notice {
                offset: if p.cltu { 2 } else { 0 },
                loss: Loss::ControlFrames {
                    unlock: 2,
                    set_vr: 1,
                    other: 1,
                },
            };
            assert_eq!(notices, std::slice::from_ref(&want));
            assert!(!want.is_problem());
            assert_eq!(want.kind(), "control_frame");

            // Set V(R) says what the next AD frame is held to.
            let mut skipped = units.clone();
            skipped.remove(2);
            let (_, notices, _) = decode(&p, &skipped.concat());
            assert!(
                matches!(
                    notices[0].loss,
                    Loss::FrameGap {
                        expected: 40,
                        got: 41,
                        missing: Some(1),
                        ..
                    }
                ),
                "{notices:?}"
            );
        }
        // A control command needs the bypass flag.
        let mut odd = TcFrame::bc(0x155, 1);
        odd.bypass = false;
        let (records, notices, _) = decode(&BARE, &odd.build(&[0x00], true));
        assert!(records.is_empty());
        assert!(matches!(notices[0].loss, Loss::BadFrame { .. }));
    }

    #[test]
    fn segments_are_put_back_together_per_map() {
        for p in [CLTU, BARE] {
            let big = tc_packet(0x0C8, 1, &[0xA5; 300]);
            let other = tc_packet(0x0C9, 9, &[0x5A; 200]);
            let small = tc_packet(0x0CA, 2, &[1, 2, 3]);
            let a = tc_segments(3, &big, 64);
            let b = tc_segments(4, &other, 64);
            assert!(a.len() == 5 && b.len() == 4);
            let mut n = 0u8;
            let mut ad = |data: &Vec<u8>| {
                n += 1;
                TcFrame::ad(0x155, 1, n).build(data, true)
            };
            // Two MAPs taking turns, and a whole packet on a third between.
            let mut frames = Vec::new();
            for i in 0..5 {
                frames.push(ad(&a[i]));
                if i < 4 {
                    frames.push(ad(&b[i]));
                }
                if i == 1 {
                    frames.push(ad(&tc_segments(5, &small, 64)[0]));
                }
            }
            let units = wrap(&p, &frames);
            let (records, notices, end) = decode(&p, &units.concat());
            assert_eq!((notices, end), (vec![], None));
            assert_eq!(
                payloads(&records),
                [small.clone(), other.clone(), big.clone()]
            );
            // A reassembled packet is found where its first segment's data
            // starts: in the first unit for `big`, the second for `other`.
            let lead = if p.cltu { 2 } else { 0 } + HEADER_LEN + 1;
            assert_eq!(records[2].offset, lead as u64);
            assert_eq!(records[1].offset, (units[0].len() + lead) as u64);

            // A segment gone: the frame count says so, and that packet goes
            // with it. The other MAP's packet goes too, since the count is
            // the channel's; what follows is read again.
            let mut dropped = units.clone();
            dropped.remove(5);
            dropped.extend(wrap(&p, &[ad(&tc_segments(3, &small, 64)[0])]));
            let (records, notices, _) = decode(&p, &dropped.concat());
            assert_eq!(payloads(&records), [small.clone(), small.clone()]);
            assert!(matches!(notices[0].loss, Loss::FrameGap { .. }));
            assert!(notices[1..].iter().all(|n| matches!(
                n.loss,
                Loss::BadFrame {
                    reason: "segment continues a packet whose start was not seen"
                }
            )));
            assert_eq!(notices.len(), 1 + 4);

            // A first segment while one is open: the open one is given up.
            let again = wrap(&p, &[ad(&a[0]), ad(&a[1]), ad(&b[0])]).concat();
            let fresh: Vec<Vec<u8>> = a.iter().map(&mut ad).collect();
            let (records, notices, _) = decode(&p, &[again, wrap(&p, &fresh).concat()].concat());
            assert_eq!(payloads(&records), std::slice::from_ref(&big));
            assert_eq!(notices.len(), 1);
            assert_eq!(
                notices[0].loss,
                Loss::BadFrame {
                    reason: "segmented packet was not finished"
                }
            );
        }
    }

    /// Several packets in one frame, and frame data that is not packets.
    #[test]
    fn a_frame_can_hold_several_packets_or_none() {
        let packets = commands(5);
        for segment_header in [true, false] {
            let p = TcParams {
                segment_header,
                ..BARE
            };
            let mut data = if segment_header { vec![0xC2] } else { vec![] };
            data.extend(packets.concat());
            let frame = TcFrame::bd(0x155, 0, 0).build(&data, true);
            let (records, notices, _) = decode(&p, &frame);
            assert_eq!(payloads(&records), packets);
            assert_eq!(notices, []);

            // The same with five stray bytes after the packets.
            data.extend([1, 2, 3, 4, 5]);
            let frame = TcFrame::bd(0x155, 0, 0).build(&data, true);
            let (records, notices, _) = decode(&p, &frame);
            assert_eq!(payloads(&records), packets);
            assert_eq!(
                notices,
                [Notice {
                    offset: (frame.len() - 2 - 5) as u64,
                    loss: Loss::BadFrame {
                        reason: "frame data is not whole space packets"
                    },
                }]
            );
        }
    }

    #[test]
    fn a_frame_failing_its_crc_is_dropped() {
        for p in [CLTU, BARE] {
            let packets = commands(6);
            let mut frames = frames(&p, &packets);
            let last = frames[2].len() - 1;
            frames[2][last] ^= 0x01;
            let (records, notices, end) = decode(&p, &wrap(&p, &frames).concat());
            assert_eq!(end, None);
            let mut want = packets.clone();
            want.remove(2);
            assert_eq!(payloads(&records), want);
            assert_eq!(notices.len(), 2);
            assert_eq!(
                notices[0].loss,
                Loss::BadFrame {
                    reason: CRC_MISMATCH
                }
            );
            assert!(matches!(notices[1].loss, Loss::FrameGap { .. }));
        }
    }

    /// What lies between CLTUs: tails and idle fill are expected, anything
    /// else is reported, and a missing tail does not matter.
    #[test]
    fn idle_fill_missing_tails_and_junk_between_cltus() {
        let packets = commands(8);
        let units = wrap(&CLTU, &frames(&CLTU, &packets));
        let mut data = vec![FILL; 16]; // the acquisition sequence
        let mut junk_at = Vec::new();
        for (k, unit) in units.iter().enumerate() {
            match k % 4 {
                0 => data.extend(unit),
                1 => data.extend(&unit[..unit.len() - TAIL.len()]),
                2 => {
                    data.extend(unit);
                    data.extend([FILL; 11]);
                }
                _ => {
                    data.extend(unit);
                    junk_at.push(data.len() as u64);
                    data.extend([0x12, 0x34, 0xEB, 0x56, 0x78]);
                }
            }
        }
        let (records, notices, end) = decode(&CLTU, &data);
        assert_eq!(end, None);
        assert_eq!(payloads(&records), packets);
        let want: Vec<Notice> = junk_at
            .iter()
            .map(|&offset| Notice {
                offset,
                loss: Loss::Junk { bytes: 5 },
            })
            .collect();
        assert_eq!(want.len(), 2);
        assert_eq!(notices, want);
    }

    /// Two frames in one CLTU, as early issues of the standard allowed:
    /// both where the second starts inside a codeblock and where the first
    /// ends exactly on one and nothing but the next header says more follows.
    #[test]
    fn a_cltu_can_hold_more_than_one_frame() {
        let p = CLTU;
        // Payloads of 0 to 8 bytes more than a round number: one of the
        // frames is a whole number of codeblocks long.
        let packets: Vec<Vec<u8>> = (0..9)
            .map(|i| tc_packet(0x0C8, i as u16, &vec![i as u8; 4 + i]))
            .collect();
        let all = frames(&p, &packets);
        assert!(all.iter().any(|f| f.len() % INFO_LEN == 0));
        for first in 0..8 {
            let pair = [all[first].clone(), all[first + 1].clone()].concat();
            let mut data = wrap(&p, &all[..first]).concat();
            data.extend(cltu(&pair, false));
            data.extend(wrap(&p, &all[first + 2..]).concat());
            let (records, notices, end) = decode(&p, &data);
            assert_eq!((notices, end), (vec![], None), "pair at {first}");
            assert_eq!(payloads(&records), packets, "pair at {first}");
        }
    }

    /// Offering the file one more byte at a time must give the same
    /// records and notices: a `NeedMore` step may not change any state.
    #[test]
    fn byte_at_a_time_gives_the_same_result() {
        for p in every_layout() {
            let packets = commands(12);
            let mut frames = frames(&p, &packets);
            frames.insert(3, TcFrame::bc(0x155, 1).build(&[0x00], p.has_crc));
            frames.remove(6);
            let mut data = wrap(&p, &frames).concat();
            if p.cltu {
                data[40] ^= 0x10;
            }
            let (want, want_notices, _) = decode(&p, &data);
            let mut decoder = TcDecoder::new(p);
            let (mut pos, mut end, mut got, mut notices) = (0, 0, Vec::new(), Vec::new());
            while end <= data.len() {
                match decoder.step(&data[pos..end], pos as u64) {
                    Step::Record { consumed, record } => {
                        got.push(record);
                        pos += consumed;
                    }
                    Step::Lost { consumed, notice } => {
                        notices.push(notice);
                        pos += consumed;
                    }
                    Step::Skip { consumed } => pos += consumed,
                    Step::NeedMore => end += 1,
                    Step::Fatal(e) => panic!("{e}"),
                }
                assert!(pos <= end);
            }
            notices.extend(decoder.summary());
            assert_eq!(got, want, "{p:?}");
            assert_eq!(notices, want_notices, "{p:?}");
            assert_eq!(pos, data.len());
        }
    }

    #[test]
    fn truncation_at_every_offset() {
        for p in [CLTU, BARE] {
            let data = file(&p, &commands(10));
            let (full, _, _) = decode(&p, &data);
            for cut in 0..data.len() {
                let (records, end) = decode_all(&mut TcDecoder::new(p), &data[..cut]);
                assert!(full.starts_with(&records), "cut at {cut}");
                if end.is_some() {
                    assert!(
                        matches!(end, Some(DecodeEnd::Truncated { .. })),
                        "cut at {cut}"
                    );
                }
            }
        }
    }

    #[test]
    fn wrong_parameters_and_noise_are_loud_or_harmless() {
        // CLTUs read with the CRC they do not have: every frame fails.
        let p = TcParams {
            has_crc: false,
            ..CLTU
        };
        let data = file(&p, &commands(30));
        let (records, _, end) = decode(&CLTU, &data);
        assert!(records.is_empty());
        assert!(matches!(end, Some(DecodeEnd::Error(_))), "{end:?}");
        // Bare frames with rubbish after them: read, then stopped.
        let mut data = file(&BARE, &commands(4));
        data.extend([0xFF; 9]);
        let (records, _, end) = decode(&BARE, &data);
        assert_eq!(records.len(), 4);
        assert!(matches!(end, Some(DecodeEnd::Error(_))), "{end:?}");

        let mut x = 0x2545_F491u32;
        for len in 0..400usize {
            let mut data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    if x & 0x700 == 0 { x as u8 } else { 0 }
                })
                .collect();
            for p in every_layout() {
                let _ = decode_all(&mut TcDecoder::new(p), &data);
            }
            // Start sequences and good first codeblocks, so CLTUs do get read.
            for chunk in data.chunks_mut(40) {
                if chunk.len() > 10 {
                    chunk[..2].copy_from_slice(&START);
                    chunk[2] &= 0x33;
                    chunk[9] = tc::bch_parity(chunk[2..9].try_into().unwrap());
                }
            }
            for p in every_layout() {
                let _ = decode_all(&mut TcDecoder::new(p), &data);
            }
        }
    }

    #[test]
    fn sniffs_cltus_and_what_their_frames_show() {
        for p in every_layout().into_iter().filter(|p| p.cltu) {
            let mut data = vec![FILL; 5];
            data.extend(file(&p, &commands(10)));
            let want = TcLayout {
                crc: Some(p.has_crc),
                segment_header: Some(p.segment_header),
                randomized: Some(p.randomized),
            };
            assert_eq!(sniff_cltus(&data), Some(want), "{p:?}");
            assert_eq!(sniff(&data), Format::Cltu(want));
            // A prefix that ends partway through the second CLTU still shows it.
            let one = cltu(&frames(&p, &commands(1))[0], p.randomized).len();
            assert!(sniff_cltus(&data[..5 + one + 7]).is_some());
            // A wrong bit in the first codeblock: believed for the CLTUs
            // that follow, not on its own.
            data[9] ^= 0x04;
            assert_eq!(sniff_cltus(&data), Some(want), "{p:?}");
            assert_eq!(sniff_cltus(&data[..5 + one + 7]), None);
            // Two wrong bits: not a codeblock.
            data[9] ^= 0x03;
            assert_eq!(sniff_cltus(&data), None);
        }
        assert_eq!(sniff_cltus(&[0xEB, 0x90]), None);
        assert_eq!(sniff_cltus(&[0xEB, 0x90, 1, 2, 3, 4, 5, 6, 7, 8, 9]), None);
        assert_eq!(sniff_cltus(&[FILL; 64]), None);
        assert_eq!(sniff_cltus(&[]), None);
        // Only control frames: a CRC shows, a segment header cannot.
        let unlock = TcFrame::bc(0x155, 1).build(&[0x00], true);
        assert_eq!(
            sniff_cltus(&cltu(&unlock, false)),
            Some(TcLayout {
                crc: Some(true),
                segment_header: None,
                randomized: Some(false),
            })
        );
    }

    #[test]
    fn sniffs_bare_frames_only_on_good_evidence() {
        for p in every_layout().into_iter().filter(|p| !p.cltu) {
            let data = file(&p, &commands(10));
            let want = TcLayout {
                crc: Some(p.has_crc),
                segment_header: Some(p.segment_header),
                randomized: None,
            };
            assert_eq!(sniff_frames(&data), Some(want), "{p:?}");
            assert_eq!(sniff(&data), Format::TcFrames(want), "{p:?}");
            // One whole frame is enough if it is all there is.
            let one = frames(&p, &commands(1)).remove(0);
            assert_eq!(sniff_frames(&one), Some(want), "{p:?}");
            // Two and a bit are not.
            let two = frames(&p, &commands(3))[..2].concat();
            assert_eq!(sniff_frames(&[two, vec![0x00, 0x01]].concat()), None);
        }
        // Lengths that chain are not enough without a CRC or packets.
        let frame = TcFrame::bd(0x155, 1, 0).build(&[0xC0, 0xFF, 0xFF, 0xFF], false);
        assert_eq!(sniff_frames(&frame.repeat(5)), None);
        // Space packets are not taken for TC frames, nor zeros, nor text.
        let packets = commands(10).concat();
        assert_eq!(sniff_frames(&packets), None);
        assert_eq!(sniff(&packets), Format::RawCcsds);
        assert_eq!(sniff_frames(&[0; 64]), None);
        assert_eq!(sniff_frames(b"plain text\n"), None);
        assert_eq!(sniff_frames(&[]), None);
    }
}
