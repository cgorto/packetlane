//! Reading log files. Inputs are opened read-only and never written.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::pure::checksum::{FNV_OFFSET, fnv1a_update};
use crate::pure::config::Config;
use crate::pure::decode::cadu::MAX_CADU_LEN;
use crate::pure::decode::{
    DecodeEnd, DecodeError, Decoder, Format, MAX_ENTRY, Notices, Record, SNIFF_LEN, Step,
    decoder_for, sniff,
};
use crate::pure::frame::SYNC;

const CHUNK: usize = 64 * 1024;

/// Opens a file read-only and guesses its format from the first bytes.
/// The returned file is positioned at the start.
pub fn open_sniffed(path: &Path) -> io::Result<(Format, File)> {
    let mut file = File::open(path)?;
    let mut prefix = vec![0u8; SNIFF_LEN];
    let n = read_full(&mut file, &mut prefix)?;
    prefix.truncate(n);
    file.seek(SeekFrom::Start(0))?;
    Ok((sniff(&prefix), file))
}

/// How far past a packet's first byte to keep decoding before giving up on
/// finding its end: packets of other virtual channels may lie in between.
const READ_BACK_SPAN: u64 = 4 * 1024 * 1024;
/// How many sync markers before a packet to try starting from. The nearest
/// is the right one unless the marker's bytes also occur in the data.
const READ_BACK_TRIES: usize = 8;

/// Reads one logged item back from its file: the `length` bytes whose first
/// byte is at `offset`, as the decoder delivered them at ingest. `accept`
/// says whether bytes are the ones wanted (a checksum); `None` means the
/// file no longer holds them.
///
/// In most formats an item is a plain run of bytes. In a CADU file it is
/// not: it is spread over frames and may be randomised, so the frames from
/// the sync marker before it are decoded again.
pub fn read_back(
    path: &Path,
    config: &Config,
    offset: u64,
    length: usize,
    accept: impl Fn(&[u8]) -> bool,
) -> io::Result<Option<Vec<u8>>> {
    let (format, mut file) = open_sniffed(path)?;
    if !matches!(format, Format::Cadu(_)) {
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0u8; length];
        let got = read_full(&mut file, &mut bytes)?;
        return Ok((got == length && accept(&bytes)).then_some(bytes));
    }

    let from = offset.saturating_sub(MAX_CADU_LEN as u64);
    file.seek(SeekFrom::Start(from))?;
    let mut window = vec![0u8; (offset - from) as usize];
    let got = read_full(&mut file, &mut window)?;
    window.truncate(got);
    let markers: Vec<u64> = window
        .windows(SYNC.len())
        .enumerate()
        .filter(|(_, w)| *w == SYNC)
        .map(|(i, _)| from + i as u64)
        .collect();
    for &start in markers.iter().rev().take(READ_BACK_TRIES) {
        let Some(decoder) = decoder_for(format, config) else {
            break;
        };
        file.seek(SeekFrom::Start(start))?;
        for item in Records::starting_at(io::BufReader::new(&file), decoder, start) {
            match item {
                Ok(r) if r.offset == offset => {
                    if r.payload.len() == length && accept(&r.payload) {
                        return Ok(Some(r.payload));
                    }
                    break;
                }
                Ok(r) if r.offset > offset + READ_BACK_SPAN => break,
                Ok(_) => {}
                Err(ReadError::Io(e)) => return Err(e),
                Err(ReadError::Decode(_)) => break,
            }
        }
    }
    Ok(None)
}

/// Fills `buf` as far as the source allows and returns how many bytes it got.
pub fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Passes reads through while keeping a checksum and byte count of them.
pub struct Hashing<R> {
    inner: R,
    state: u64,
    bytes: u64,
}

impl<R: Read> Hashing<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            state: FNV_OFFSET,
            bytes: 0,
        }
    }

    /// Reads whatever is left, then returns (checksum, total bytes).
    pub fn finish(mut self) -> io::Result<(u64, u64)> {
        let mut sink = vec![0u8; CHUNK];
        while self.read(&mut sink)? > 0 {}
        Ok((self.state, self.bytes))
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.state = fnv1a_update(self.state, &buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Decode(DecodeEnd),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "Read failed: {e}"),
            ReadError::Decode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReadError {}

/// Drives a decoder from a reader: the read loop that the pure decoders do
/// not have. Yields records, then at most one error, then stops.
pub struct Records<R> {
    inner: R,
    decoder: Box<dyn Decoder>,
    buf: Vec<u8>,
    start: usize,
    base: u64,
    eof: bool,
    done: bool,
    notices: Notices,
}

impl<R: Read> Records<R> {
    pub fn new(inner: R, decoder: Box<dyn Decoder>) -> Self {
        Self::starting_at(inner, decoder, 0)
    }

    /// For a reader that is already `base` bytes into its file, so that
    /// record offsets still count from the start of the file.
    pub fn starting_at(inner: R, decoder: Box<dyn Decoder>, base: u64) -> Self {
        Self {
            inner,
            decoder,
            buf: Vec::new(),
            start: 0,
            base,
            eof: false,
            done: false,
            notices: Notices::default(),
        }
    }

    /// What the decoder gave up on so far to keep reading.
    pub fn notices(&self) -> &Notices {
        &self.notices
    }

    /// What the decoder learned about the file. Ask once reading is done.
    pub fn describe(&self) -> Option<String> {
        self.decoder.describe()
    }

    /// Gives the reader back, for example to finish a checksum.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn fail(&mut self, e: ReadError) -> Option<Result<Record, ReadError>> {
        self.done = true;
        Some(Err(e))
    }

    fn implausible(&mut self, reason: &'static str) -> Option<Result<Record, ReadError>> {
        let offset = self.base + self.start as u64;
        self.fail(ReadError::Decode(DecodeEnd::Error(
            DecodeError::Implausible { offset, reason },
        )))
    }
}

impl<R: Read> Iterator for Records<R> {
    type Item = Result<Record, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let offset = self.base + self.start as u64;
            let pending = &self.buf[self.start..];
            match self.decoder.step(pending, offset) {
                Step::Record { consumed, record } => {
                    if consumed == 0 || consumed > pending.len() {
                        return self.implausible("invalid decoder step");
                    }
                    self.start += consumed;
                    return Some(Ok(record));
                }
                Step::Skip { consumed } => {
                    if consumed == 0 || consumed > pending.len() {
                        return self.implausible("invalid decoder step");
                    }
                    self.start += consumed;
                }
                Step::Lost { consumed, notice } => {
                    if consumed == 0 || consumed > pending.len() {
                        return self.implausible("invalid decoder step");
                    }
                    self.start += consumed;
                    self.notices.push(notice);
                }
                Step::Fatal(e) => return self.fail(ReadError::Decode(DecodeEnd::Error(e))),
                Step::NeedMore => {
                    let available = pending.len();
                    if self.eof {
                        self.done = true;
                        if available == 0 {
                            return None;
                        }
                        return Some(Err(ReadError::Decode(DecodeEnd::Truncated {
                            offset,
                            available,
                        })));
                    }
                    if available > MAX_ENTRY {
                        return self.implausible("entry too large");
                    }
                    self.buf.drain(..self.start);
                    self.base += self.start as u64;
                    self.start = 0;
                    let old = self.buf.len();
                    self.buf.resize(old + CHUNK, 0);
                    match read_full(&mut self.inner, &mut self.buf[old..]) {
                        Ok(n) => {
                            self.buf.truncate(old + n);
                            if n < CHUNK {
                                self.eof = true;
                            }
                        }
                        Err(e) => {
                            self.buf.truncate(old);
                            return self.fail(ReadError::Io(e));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::decode::raw::RawDecoder;
    use crate::pure::synth::Source;

    /// Hands out one byte per read, to exercise every refill path.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((&b, rest)), Some(slot)) => {
                    *slot = b;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut src = Source::new(0x1A3, 0, 500);
        (0..n).flat_map(|_| src.emit()).collect()
    }

    #[test]
    fn streams_across_chunk_boundaries() {
        let data = sample(400); // about 200 KiB: several refills
        let records: Vec<_> = Records::new(&data[..], Box::new(RawDecoder::new()))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 400);
        assert_eq!(records[399].offset, 399 * 506);
    }

    #[test]
    fn trickled_input_gives_the_same_records() {
        let data = sample(5);
        let records: Vec<_> = Records::new(Trickle(&data), Box::new(RawDecoder::new()))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 5);
    }

    #[test]
    fn truncated_tail_is_reported_once() {
        let data = sample(3);
        let items: Vec<_> =
            Records::new(&data[..data.len() - 7], Box::new(RawDecoder::new())).collect();
        assert_eq!(items.len(), 3);
        assert!(items[0].is_ok() && items[1].is_ok());
        assert!(matches!(
            items[2],
            Err(ReadError::Decode(DecodeEnd::Truncated {
                offset: 1012,
                available: 499
            }))
        ));
    }

    #[test]
    fn hashing_matches_a_direct_checksum() {
        let data = sample(50);
        let mut records = Records::new(Hashing::new(&data[..]), Box::new(RawDecoder::new()));
        assert_eq!(records.by_ref().take(2).count(), 2);
        let (sum, bytes) = records.into_inner().finish().unwrap();
        assert_eq!(bytes, data.len() as u64);
        assert_eq!(sum, crate::pure::checksum::fnv1a(&data));
    }
}
