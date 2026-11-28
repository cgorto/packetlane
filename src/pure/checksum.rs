//! Checksums: FNV-1a, 64-bit, of each packet's bytes, to recognise a packet
//! seen before (and logged by another source); and a quicker one of each
//! whole file ([`FileSum`]), to recognise a file already read. Neither is a
//! cryptographic hash and must not be used as one.

pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Folds `bytes` into a running checksum. Start from [`FNV_OFFSET`].
pub fn fnv1a_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        state ^= u64::from(b);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    fnv1a_update(FNV_OFFSET, bytes)
}

/// The checksum of a whole file: 64 bits, eight bytes at a time in four
/// independent lanes, so that it costs little more than reading the file.
/// Kept with each file only to tell whether the file has changed since it
/// was read; nothing else depends on it. Fed in pieces of any size, it
/// gives what it gives fed all at once.
#[derive(Debug, Clone)]
pub struct FileSum {
    lanes: [u64; 4],
    /// Bytes of an unfinished block of 32, and how many.
    held: [u8; 32],
    count: usize,
    len: u64,
}

const FILE_SUM_K: u64 = 0x9e37_79b9_7f4a_7c15;

impl Default for FileSum {
    fn default() -> Self {
        FileSum {
            lanes: [FNV_OFFSET, FNV_OFFSET ^ 1, FNV_OFFSET ^ 2, FNV_OFFSET ^ 3],
            held: [0; 32],
            count: 0,
            len: 0,
        }
    }
}

impl FileSum {
    fn block(lanes: &mut [u64; 4], block: &[u8]) {
        for (lane, word) in lanes.iter_mut().zip(block.chunks_exact(8)) {
            let mut w = [0u8; 8];
            w.copy_from_slice(word);
            *lane = (lane.rotate_left(23) ^ u64::from_le_bytes(w)).wrapping_mul(FILE_SUM_K);
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.len += bytes.len() as u64;
        if self.count > 0 {
            let take = (32 - self.count).min(bytes.len());
            self.held[self.count..self.count + take].copy_from_slice(&bytes[..take]);
            self.count += take;
            bytes = &bytes[take..];
            if self.count < 32 {
                return;
            }
            let held = self.held;
            FileSum::block(&mut self.lanes, &held);
            self.count = 0;
        }
        let mut blocks = bytes.chunks_exact(32);
        for block in &mut blocks {
            FileSum::block(&mut self.lanes, block);
        }
        let rest = blocks.remainder();
        self.held[..rest.len()].copy_from_slice(rest);
        self.count = rest.len();
    }

    pub fn finish(&self) -> u64 {
        let mut lanes = self.lanes;
        let mut last = [0u8; 32];
        last[..self.count].copy_from_slice(&self.held[..self.count]);
        FileSum::block(&mut lanes, &last);
        let mut h = self.len.wrapping_mul(FILE_SUM_K);
        for lane in lanes {
            h = (h ^ lane).wrapping_mul(FILE_SUM_K).rotate_left(31);
        }
        // A final mix, so that every bit of the input reaches every bit.
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^ (h >> 33)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_vectors() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn a_file_sum_fed_in_pieces_is_the_file_sum_of_the_whole() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut whole = FileSum::default();
        whole.update(&data);
        for cut in [0, 1, 7, 8, 31, 32, 33, 100, 999, 1000] {
            for step in [1, 3, 32, 64, 1000] {
                let mut parts = FileSum::default();
                parts.update(&data[..cut]);
                for piece in data[cut..].chunks(step) {
                    parts.update(piece);
                }
                assert_eq!(parts.finish(), whole.finish(), "cut {cut} step {step}");
            }
        }
        // Any one byte changed, or one more or fewer, changes the sum.
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(whole.finish()));
        for n in [0, 1, 31, 32, 33, 999] {
            let mut shorter = FileSum::default();
            shorter.update(&data[..n]);
            assert!(seen.insert(shorter.finish()), "length {n}");
        }
        for at in 0..data.len() {
            let mut changed = data.clone();
            changed[at] ^= 1;
            let mut sum = FileSum::default();
            sum.update(&changed);
            assert!(seen.insert(sum.finish()), "byte {at}");
        }
    }

    #[test]
    fn chunking_does_not_matter() {
        let whole = fnv1a(b"hello world");
        let parts = fnv1a_update(fnv1a_update(FNV_OFFSET, b"hello "), b"world");
        assert_eq!(whole, parts);
    }
}
