//! FNV-1a, 64-bit. Used to recognise a file or packet seen before. It is not
//! a cryptographic hash and must not be used as one.

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
    fn chunking_does_not_matter() {
        let whole = fnv1a(b"hello world");
        let parts = fnv1a_update(fnv1a_update(FNV_OFFSET, b"hello "), b"world");
        assert_eq!(whole, parts);
    }
}
