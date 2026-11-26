//! Reed-Solomon coding as CCSDS 131.0-B puts it on TM and AOS frames:
//! RS(255,223), which corrects 16 wrong bytes per codeword, and RS(255,239),
//! which corrects 8.
//!
//! ```text
//! field       GF(256), x^8 + x^7 + x^2 + x + 1, alpha = x
//! generator   product of (x - alpha^(11 j)) for j = 128-E .. 127+E
//!             E = 16: j = 112..143        E = 8: j = 120..135
//! codeword    data symbols, then 2E check symbols; the first byte sent is
//!             the highest power of x
//! codeblock   I codewords interleaved: byte i belongs to codeword i mod I.
//!             I is 1, 2, 3, 4, 5 or 8
//! ```
//!
//! Three things about it are easy to get wrong.
//!
//! **Symbol representation.** A byte on the link is, by default, not the
//! field element whose polynomial coefficients are its bits. It is the
//! element's coordinates in Berlekamp's dual basis, which made the 1970s
//! encoder hardware small. Every byte, check symbols included, goes through
//! a fixed 8x8 bit matrix on the way into the arithmetic and through the
//! inverse on the way out. Some links skip this ("conventional"
//! representation). A codeword in one representation is not one in the
//! other, so decoding with the wrong one fails on every block.
//!
//! **Virtual fill.** A frame shorter than 223 x I bytes is coded as if zeros
//! stood in front of it. The zeros are never sent. For the arithmetic this
//! only means the codeword is short: the missing symbols are the high powers
//! of x and are zero. An "error" located among them shows the block cannot
//! be corrected.
//!
//! **Order.** The sender codes first and randomises second, check symbols
//! included. The reader must undo the randomising before decoding. The sync
//! marker is in front of the codeblock, not in it.
//!
//! Nothing here is specific to frames: a codeblock is a byte slice.

use serde::Deserialize;

/// How many check symbols RS(255,223) has. Arrays are sized for it.
const MAX_CHECK: usize = 32;
/// Symbols in a full codeword.
const N: usize = 255;
/// The generator's roots are powers of alpha^11, not of alpha.
const ROOT_STEP: usize = 11;

/// The interleave depths 131.0-B allows.
pub const DEPTHS: [usize; 6] = [1, 2, 3, 4, 5, 8];

const fn exp_table() -> [u8; 2 * N] {
    let mut table = [0u8; 2 * N];
    let mut x = 1u16;
    let mut i = 0;
    while i < 2 * N {
        table[i] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x187;
        }
        i += 1;
    }
    table
}

const fn log_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < N {
        table[EXP[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// `EXP[i]` is alpha^i. Twice as long as it needs to be so that the sum of
/// two logarithms indexes it without a reduction.
const EXP: [u8; 2 * N] = exp_table();
/// `LOG[x]` is the power of alpha that gives `x`. `LOG[0]` is meaningless.
const LOG: [u8; 256] = log_table();

const fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

/// `a / b`. `b` must not be zero.
fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        0
    } else {
        EXP[usize::from(LOG[usize::from(a)]) + N - usize::from(LOG[usize::from(b)])]
    }
}

/// alpha^(11 k): the k-th power of the element the roots are powers of.
fn root_power(k: usize) -> u8 {
    EXP[(ROOT_STEP * k) % N]
}

/// What bit `1 << i` of a conventional symbol contributes to its dual-basis
/// byte. These are the rows of the matrix in 131.0-B annex F, last row
/// first. A test rebuilds them from the definition of the dual basis.
const TO_DUAL_ROWS: [u8; 8] = [0x7B, 0xAF, 0x99, 0xFA, 0x86, 0xEC, 0xEF, 0x8D];
/// The inverse matrix, the same way round.
const FROM_DUAL_ROWS: [u8; 8] = [0xCC, 0xAC, 0x79, 0xF0, 0xFD, 0x2E, 0x42, 0xC5];

const fn bit_matrix_table(rows: [u8; 8]) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut v = 0;
    while v < 256 {
        let mut bit = 0;
        while bit < 8 {
            if v >> bit & 1 != 0 {
                table[v] ^= rows[bit];
            }
            bit += 1;
        }
        v += 1;
    }
    table
}

const TO_DUAL: [u8; 256] = bit_matrix_table(TO_DUAL_ROWS);
const FROM_DUAL: [u8; 256] = bit_matrix_table(FROM_DUAL_ROWS);

/// How a byte on the link stands for a field element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    /// Berlekamp's dual basis: what 131.0-B specifies.
    #[default]
    Dual,
    /// The bits are the polynomial's coefficients.
    Conventional,
}

/// Which of the two codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum Code {
    /// 32 check symbols per codeword; corrects 16.
    #[default]
    #[serde(rename = "255,223")]
    Rs223,
    /// 16 check symbols per codeword; corrects 8.
    #[serde(rename = "255,239")]
    Rs239,
}

impl Code {
    /// Check symbols per codeword: 2E.
    pub const fn check_len(self) -> usize {
        match self {
            Code::Rs223 => 32,
            Code::Rs239 => 16,
        }
    }

    /// The most wrong symbols per codeword that can be put right: E.
    pub const fn power(self) -> usize {
        self.check_len() / 2
    }

    /// The generator's first root is alpha^(11 x this).
    const fn first_root(self) -> usize {
        128 - self.power()
    }

    pub fn name(self) -> &'static str {
        match self {
            Code::Rs223 => "RS(255,223)",
            Code::Rs239 => "RS(255,239)",
        }
    }

    /// The generator polynomial, highest power first, the leading 1
    /// included: `check_len() + 1` coefficients.
    const fn generator(self) -> [u8; MAX_CHECK + 1] {
        let mut g = [0u8; MAX_CHECK + 1];
        g[0] = 1;
        let mut degree = 0;
        while degree < self.check_len() {
            let root = EXP[(ROOT_STEP * (self.first_root() + degree)) % N];
            // Multiply by (x + root): in characteristic 2, minus is plus.
            degree += 1;
            let mut i = degree;
            while i > 0 {
                g[i] ^= mul(g[i - 1], root);
                i -= 1;
            }
        }
        g
    }

    /// For each value the top of the division register can hold, that value
    /// times the generator without its leading term: what one step of long
    /// division subtracts.
    const fn feedback_table(self) -> [[u8; MAX_CHECK]; 256] {
        let g = self.generator();
        let mut table = [[0u8; MAX_CHECK]; 256];
        let mut v = 0;
        while v < 256 {
            let mut i = 0;
            while i < self.check_len() {
                table[v][i] = mul(v as u8, g[i + 1]);
                i += 1;
            }
            v += 1;
        }
        table
    }

    fn feedback(self) -> &'static [[u8; MAX_CHECK]; 256] {
        static RS223: [[u8; MAX_CHECK]; 256] = Code::Rs223.feedback_table();
        static RS239: [[u8; MAX_CHECK]; 256] = Code::Rs239.feedback_table();
        match self {
            Code::Rs223 => &RS223,
            Code::Rs239 => &RS239,
        }
    }

    /// The remainder of the polynomial `symbols` (highest power first) on
    /// division by the generator, in the first `check_len()` bytes. Zero for
    /// a codeword. Fed data followed by `check_len()` zeros, it is the check
    /// symbols.
    fn remainder(self, symbols: impl Iterator<Item = u8>) -> [u8; MAX_CHECK] {
        let table = self.feedback();
        let last = self.check_len() - 1;
        let mut reg = [0u8; MAX_CHECK];
        for symbol in symbols {
            let row = &table[usize::from(reg[0])];
            reg.copy_within(1..=last, 0);
            reg[last] = symbol;
            for (r, f) in reg.iter_mut().zip(row) {
                *r ^= f;
            }
        }
        reg
    }
}

/// Everything that says how a codeblock was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RsCode {
    pub code: Code,
    /// How many codewords are interleaved: one of [`DEPTHS`].
    pub depth: usize,
    pub basis: Basis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsError {
    /// The codeblock's length is not one this code and depth can have.
    DoesNotFit,
    /// More symbols are wrong than the code can put right.
    Uncorrectable,
}

impl RsError {
    pub fn reason(self) -> &'static str {
        match self {
            RsError::DoesNotFit => "codeblock length does not fit the Reed-Solomon code",
            RsError::Uncorrectable => "more errors than Reed-Solomon can correct",
        }
    }
}

impl RsCode {
    /// Check symbols at the end of each codeblock, in bytes.
    pub fn parity_len(&self) -> usize {
        self.code.check_len() * self.depth
    }

    /// The length of one codeword in a codeblock of `block_len` bytes, check
    /// symbols included, if such a codeblock can exist: a whole number of
    /// codewords, each with at least one data symbol and no more than 255.
    fn codeword_len(&self, block_len: usize) -> Option<usize> {
        if !DEPTHS.contains(&self.depth) || !block_len.is_multiple_of(self.depth) {
            return None;
        }
        let n = block_len / self.depth;
        (n > self.code.check_len() && n <= N).then_some(n)
    }

    /// True if a codeblock of `block_len` bytes can be of this code.
    pub fn fits(&self, block_len: usize) -> bool {
        self.codeword_len(block_len).is_some()
    }

    fn field_of(&self, byte: u8) -> u8 {
        match self.basis {
            Basis::Dual => FROM_DUAL[usize::from(byte)],
            Basis::Conventional => byte,
        }
    }

    fn byte_of(&self, symbol: u8) -> u8 {
        match self.basis {
            Basis::Dual => TO_DUAL[usize::from(symbol)],
            Basis::Conventional => symbol,
        }
    }

    /// The check symbols for `data`, ready to append to it. `None` if data
    /// of that length cannot be coded: see [`RsCode::fits`].
    pub fn encode(&self, data: &[u8]) -> Option<Vec<u8>> {
        let check = self.code.check_len();
        self.codeword_len(data.len() + self.parity_len())?;
        let mut parity = vec![0u8; self.parity_len()];
        for lane in 0..self.depth {
            let symbols = data
                .iter()
                .skip(lane)
                .step_by(self.depth)
                .map(|&b| self.field_of(b))
                .chain(std::iter::repeat_n(0, check));
            let rem = self.code.remainder(symbols);
            for (k, &symbol) in rem[..check].iter().enumerate() {
                parity[k * self.depth + lane] = self.byte_of(symbol);
            }
        }
        Some(parity)
    }

    /// Puts right what it can in one codeblock (data then check symbols, no
    /// sync marker, already derandomised) and says how many bytes it
    /// changed. On an error the block is left exactly as it was: a codeblock
    /// with one codeword past saving is not half corrected.
    pub fn correct(&self, block: &mut [u8]) -> Result<usize, RsError> {
        let n = self.codeword_len(block.len()).ok_or(RsError::DoesNotFit)?;
        let mut fixes: Vec<(usize, u8)> = Vec::new();
        let mut word = [0u8; N];
        for lane in 0..self.depth {
            let symbols = block.iter().skip(lane).step_by(self.depth);
            // The cheap test first: nearly every block is clean.
            let rem = self
                .code
                .remainder(symbols.clone().map(|&b| self.field_of(b)));
            if rem == [0; MAX_CHECK] {
                continue;
            }
            for (w, &b) in word.iter_mut().zip(symbols) {
                *w = self.field_of(b);
            }
            for (at, value) in locate(self.code, &word[..n]).ok_or(RsError::Uncorrectable)? {
                let i = at * self.depth + lane;
                fixes.push((i, self.byte_of(word[at] ^ value)));
            }
        }
        for &(i, byte) in &fixes {
            block[i] = byte;
        }
        Ok(fixes.len())
    }
}

/// The values of `word` (highest power first) at the generator's roots.
/// All zero for a codeword.
fn syndromes(code: Code, word: &[u8]) -> [u8; MAX_CHECK] {
    let mut out = [0u8; MAX_CHECK];
    for (k, s) in out[..code.check_len()].iter_mut().enumerate() {
        let root = root_power(code.first_root() + k);
        *s = word.iter().fold(0, |acc, &symbol| mul(acc, root) ^ symbol);
    }
    out
}

/// Finds the errors in one codeword of field elements: where (index into
/// `word`) and what to XOR in. `None` if they cannot be found. The steps are
/// the textbook ones: syndromes, Berlekamp-Massey for the locator
/// polynomial, a search for its roots, Forney's formula for the values.
fn locate(code: Code, word: &[u8]) -> Option<Vec<(usize, u8)>> {
    let check = code.check_len();
    let s = syndromes(code, word);
    if s == [0; MAX_CHECK] {
        return Some(Vec::new());
    }

    // Berlekamp-Massey: the shortest recurrence the syndromes obey. Its
    // coefficients are the locator polynomial, lowest power first.
    let mut lambda = [0u8; MAX_CHECK + 1];
    let mut prev = [0u8; MAX_CHECK + 1];
    lambda[0] = 1;
    prev[0] = 1;
    let (mut len, mut shift, mut prev_gap) = (0usize, 1usize, 1u8);
    for r in 0..check {
        let mut gap = s[r];
        for i in 1..=len {
            gap ^= mul(lambda[i], s[r - i]);
        }
        if gap == 0 {
            shift += 1;
            continue;
        }
        let scale = div(gap, prev_gap);
        let before = lambda;
        for i in 0..=MAX_CHECK - shift {
            lambda[i + shift] ^= mul(scale, prev[i]);
        }
        if 2 * len <= r {
            len = r + 1 - len;
            prev = before;
            prev_gap = gap;
            shift = 1;
        } else {
            shift += 1;
        }
    }
    if len > code.power() {
        return None;
    }

    // The error evaluator: syndromes x locator, cut off at x^2E.
    let mut omega = [0u8; MAX_CHECK];
    for (i, o) in omega[..check].iter_mut().enumerate() {
        for j in 0..=i.min(len) {
            *o ^= mul(lambda[j], s[i - j]);
        }
    }

    // A symbol `p` places from the end of the word is the coefficient of
    // x^p; an error there shows as the locator having a root at the inverse
    // of (alpha^11)^p. Only places the word really has are tried, so a root
    // that would fall in the virtual fill leaves the count short.
    let mut found = Vec::with_capacity(len);
    for p in 0..word.len() {
        let inverse = root_power(N - p);
        let (mut value, mut odd, mut power) = (0u8, 0u8, 1u8);
        for (i, &c) in lambda[..=len].iter().enumerate() {
            let term = mul(c, power);
            value ^= term;
            if i % 2 == 1 {
                odd ^= term;
            }
            power = mul(power, inverse);
        }
        if value != 0 {
            continue;
        }
        // The derivative keeps the odd terms, each one power lower.
        let slope = div(odd, inverse);
        if slope == 0 {
            return None;
        }
        let top = omega[..check]
            .iter()
            .rev()
            .fold(0, |acc, &c| mul(acc, inverse) ^ c);
        // Forney, for roots that start at alpha^(11 b) and not at 1: the
        // value carries an extra factor X^(1-b), X being (alpha^11)^p.
        let turn = (p * (N + 1 - code.first_root())) % N;
        found.push((word.len() - 1 - p, mul(div(top, slope), root_power(turn))));
    }
    if found.len() != len {
        return None;
    }
    // Believe the result only if it makes a codeword.
    let mut fixed = [0u8; N];
    fixed[..word.len()].copy_from_slice(word);
    for &(at, value) in &found {
        fixed[at] ^= value;
    }
    (syndromes(code, &fixed[..word.len()]) == [0; MAX_CHECK]).then_some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUAL: Basis = Basis::Dual;
    const PLAIN: Basis = Basis::Conventional;

    fn code(code: Code, depth: usize, basis: Basis) -> RsCode {
        RsCode { code, depth, basis }
    }

    /// A small generator: the tests must not depend on a random source.
    struct Noise(u32);

    impl Noise {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 8) as u8).collect()
        }

        /// `count` different positions below `len`.
        fn places(&mut self, count: usize, len: usize) -> Vec<usize> {
            let mut out = Vec::new();
            while out.len() < count {
                let at = self.next() as usize % len;
                if !out.contains(&at) {
                    out.push(at);
                }
            }
            out
        }

        fn nonzero(&mut self) -> u8 {
            (self.next() % 255) as u8 + 1
        }
    }

    fn block(c: &RsCode, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        out.extend(c.encode(data).unwrap());
        out
    }

    /// Multiplication done the slow way, bit by bit, with the field
    /// polynomial written out: a check on the tables.
    fn slow_mul(a: u8, b: u8) -> u8 {
        let (mut a, mut b, mut out) = (u16::from(a), b, 0u16);
        while b != 0 {
            if b & 1 != 0 {
                out ^= a;
            }
            a <<= 1;
            if a & 0x100 != 0 {
                a ^= 0x100 | 0x80 | 0x04 | 0x02 | 0x01; // x^8 + x^7 + x^2 + x + 1
            }
            b >>= 1;
        }
        out as u8
    }

    fn trace(x: u8) -> u8 {
        let (mut sum, mut y) = (0, x);
        for _ in 0..8 {
            sum ^= y;
            y = slow_mul(y, y);
        }
        sum
    }

    #[test]
    fn field_tables_match_the_polynomial() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), slow_mul(a, b));
            }
        }
        // alpha generates all 255 non-zero elements.
        let mut seen = [false; 256];
        for &x in &EXP[..N] {
            assert!(!seen[usize::from(x)]);
            seen[usize::from(x)] = true;
        }
        assert!(!seen[0]);
        for a in 1..=255u8 {
            assert_eq!(div(mul(a, 0x53), a), 0x53);
        }
    }

    /// The generators' coefficients as powers of alpha, highest first, up
    /// to the middle one. The RS(255,223) list is the one 131.0-B prints,
    /// as remembered; the RS(255,239) list is only what the definition
    /// gives, kept so that a change shows. What does not rest on memory or
    /// on this code: the palindrome, and the zeros at the listed roots,
    /// which are worked out with the slow multiply.
    #[test]
    fn generators_have_the_roots_the_standard_lists() {
        const E16: [u8; 17] = [
            0, 249, 59, 66, 4, 43, 126, 251, 97, 30, 3, 213, 50, 66, 170, 5, 24,
        ];
        const E8: [u8; 9] = [0, 30, 230, 49, 235, 129, 81, 76, 173];
        for (code, half) in [(Code::Rs223, &E16[..]), (Code::Rs239, &E8[..])] {
            let g = code.generator();
            let g = &g[..=code.check_len()];
            let logs: Vec<u8> = g.iter().map(|&c| LOG[usize::from(c)]).collect();
            assert!(g.iter().all(|&c| c != 0));
            assert_eq!(&logs[..half.len()], half, "{code:?}");
            // The roots come in inverse pairs, so it reads the same backwards.
            assert!(g.iter().eq(g.iter().rev()), "{code:?}");
            // Zero at alpha^(11 j) for exactly the j the standard lists.
            for j in 0..N {
                let root = root_power(j);
                let value = g.iter().fold(0, |acc, &c| slow_mul(acc, root) ^ c);
                let listed = (128 - code.power()..128 + code.power()).contains(&j);
                assert_eq!(value == 0, listed, "{code:?} at j = {j}");
            }
        }
    }

    /// The dual basis from its definition, not from the typed-in matrix:
    /// bit i of the dual byte (bit 0 sent first, so the top bit) is the
    /// trace of the element times alpha^(117 i).
    #[test]
    fn dual_basis_tables_match_the_definition() {
        for v in 0..=255u8 {
            let mut dual = 0u8;
            for i in 0..8 {
                dual |= trace(slow_mul(v, EXP[(117 * i) % N])) << (7 - i);
            }
            assert_eq!(TO_DUAL[usize::from(v)], dual, "{v:#04x}");
            assert_eq!(FROM_DUAL[usize::from(dual)], v);
        }
        // The first entries of the tables as other decoders carry them.
        assert_eq!(
            TO_DUAL[..8],
            [0x00, 0x7B, 0xAF, 0xD4, 0x99, 0xE2, 0x36, 0x4D]
        );
        assert_eq!(
            FROM_DUAL[..8],
            [0x00, 0xCC, 0xAC, 0x60, 0x79, 0xB5, 0xD5, 0x19]
        );
    }

    /// Checked without the encoder's division: every encoded word is zero
    /// at every root, by plain evaluation with the slow multiply.
    #[test]
    fn encoded_words_are_zero_at_the_roots() {
        let mut noise = Noise(0x1234_5678);
        for c in [Code::Rs223, Code::Rs239] {
            for data_len in [1, 7, 100, N - c.check_len()] {
                let rs = code(c, 1, PLAIN);
                let word = block(&rs, &noise.bytes(data_len));
                for j in 128 - c.power()..128 + c.power() {
                    let root = root_power(j);
                    let value = word.iter().fold(0, |acc, &x| slow_mul(acc, root) ^ x);
                    assert_eq!(value, 0, "{c:?}, {data_len} data bytes, j = {j}");
                }
                assert_eq!(syndromes(c, &word), [0; MAX_CHECK]);
            }
            // Nothing coded is nothing sent: the all-zero word is a codeword.
            assert_eq!(syndromes(c, &[0; N]), [0; MAX_CHECK]);
            assert_eq!(
                code(c, 1, DUAL).encode(&[0; 100]).unwrap(),
                vec![0; c.check_len()]
            );
        }
    }

    /// A single wrong symbol gives syndromes that can be written down by
    /// hand: value x root^place. This pins the order of symbols and roots
    /// without going through the decoder.
    #[test]
    fn syndromes_of_one_error_are_as_calculated() {
        for c in [Code::Rs223, Code::Rs239] {
            let mut word = [0u8; 200];
            let (at, value) = (37, 0xA6);
            word[at] = value;
            let place = word.len() - 1 - at;
            let s = syndromes(c, &word);
            for (k, &got) in s[..c.check_len()].iter().enumerate() {
                let j = 128 - c.power() + k;
                let mut want = value;
                for _ in 0..place {
                    want = slow_mul(want, EXP[(11 * j) % N]);
                }
                assert_eq!(got, want);
            }
        }
    }

    #[test]
    fn corrects_up_to_its_power_and_no_further() {
        let mut noise = Noise(0x0BAD_5EED);
        let mut miscorrected = 0;
        for c in [Code::Rs223, Code::Rs239] {
            for basis in [DUAL, PLAIN] {
                for depth in DEPTHS {
                    // Full length, and shortened by different amounts.
                    for data_per_word in [N - c.check_len(), 150, 20, 1] {
                        let rs = code(c, depth, basis);
                        let data = noise.bytes(data_per_word * depth);
                        let good = block(&rs, &data);
                        assert_eq!(rs.correct(&mut good.clone()), Ok(0));
                        let n = good.len() / depth;

                        // Every codeword at its limit: E errors each.
                        let mut bad = good.clone();
                        let errors = c.power().min(n);
                        for lane in 0..depth {
                            for at in noise.places(errors, n) {
                                bad[at * depth + lane] ^= noise.nonzero();
                            }
                        }
                        assert_eq!(rs.correct(&mut bad), Ok(errors * depth), "{rs:?}");
                        assert_eq!(bad, good);

                        // One codeword one past the limit.
                        if n > c.power() {
                            let mut bad = good.clone();
                            let lane = noise.next() as usize % depth;
                            for at in noise.places(c.power() + 1, n) {
                                bad[at * depth + lane] ^= noise.nonzero();
                            }
                            let before = bad.clone();
                            match rs.correct(&mut bad) {
                                Err(RsError::Uncorrectable) => assert_eq!(bad, before),
                                // It can happen that E + 1 errors land within
                                // E of another codeword. It must be rare.
                                Ok(_) => miscorrected += 1,
                                Err(e) => panic!("{e:?}"),
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(miscorrected, 0);
    }

    #[test]
    fn errors_in_the_check_symbols_are_corrected_too() {
        let mut noise = Noise(77);
        for c in [Code::Rs223, Code::Rs239] {
            for basis in [DUAL, PLAIN] {
                let rs = code(c, 4, basis);
                let good = block(&rs, &noise.bytes(4 * 180));
                let mut bad = good.clone();
                let parity_from = good.len() - rs.parity_len();
                // All of one codeword's power spent on its check symbols,
                // and the very last byte of the block as well.
                for k in 0..c.power() {
                    bad[parity_from + 4 * k] ^= noise.nonzero();
                }
                *bad.last_mut().unwrap() ^= 0x01;
                assert_eq!(rs.correct(&mut bad), Ok(c.power() + 1));
                assert_eq!(bad, good);
            }
        }
    }

    /// A burst no longer than depth x E bytes is spread evenly over the
    /// codewords, which is what interleaving is for.
    #[test]
    fn interleaving_spreads_a_burst() {
        let mut noise = Noise(5);
        let rs = code(Code::Rs223, 5, DUAL);
        let good = block(&rs, &noise.bytes(5 * 223));
        let mut bad = good.clone();
        for b in &mut bad[400..400 + 5 * 16] {
            *b ^= 0xFF;
        }
        assert_eq!(rs.correct(&mut bad), Ok(80));
        assert_eq!(bad, good);
        bad[400..400 + 5 * 16 + 1]
            .iter_mut()
            .for_each(|b| *b ^= 0xFF);
        assert_eq!(rs.correct(&mut bad), Err(RsError::Uncorrectable));
    }

    /// The two representations are different codes, and so are the two
    /// depths that share a check-symbol length.
    #[test]
    fn the_wrong_code_does_not_decode() {
        let mut noise = Noise(99);
        let data = noise.bytes(2 * 100);
        let made = code(Code::Rs223, 2, DUAL);
        let good = block(&made, &data);
        for other in [
            code(Code::Rs223, 2, PLAIN),
            code(Code::Rs223, 1, DUAL),
            code(Code::Rs239, 4, DUAL),
        ] {
            if other.fits(good.len()) {
                let mut copy = good.clone();
                assert_eq!(other.correct(&mut copy), Err(RsError::Uncorrectable));
                assert_eq!(copy, good);
            }
        }
        // But an RS(255,223) codeword is also an RS(255,239) one: its roots
        // include the smaller code's. Detection has to try the larger first.
        let short = code(Code::Rs223, 1, DUAL);
        let word = block(&short, &data[..100]);
        assert_eq!(code(Code::Rs239, 1, DUAL).correct(&mut word.clone()), Ok(0));
    }

    #[test]
    fn lengths_that_cannot_be_codeblocks_are_refused() {
        let rs = code(Code::Rs223, 4, DUAL);
        assert!(rs.fits(4 * 255) && rs.fits(4 * 33));
        assert!(!rs.fits(4 * 32) && !rs.fits(4 * 256) && !rs.fits(4 * 100 + 1));
        assert!(!code(Code::Rs223, 6, DUAL).fits(6 * 100));
        assert!(!code(Code::Rs223, 0, DUAL).fits(100));
        assert_eq!(rs.correct(&mut [0; 401]), Err(RsError::DoesNotFit));
        assert_eq!(rs.encode(&[0; 4 * 224]), None);
        assert_eq!(rs.encode(&[]), None);
    }

    #[test]
    fn arbitrary_blocks_do_not_panic() {
        let mut noise = Noise(0xC0FFEE);
        for round in 0..400 {
            let depth = DEPTHS[round % DEPTHS.len()];
            let c = if round % 2 == 0 {
                Code::Rs223
            } else {
                Code::Rs239
            };
            let len = depth * (1 + noise.next() as usize % 255);
            let mut data = noise.bytes(len);
            if round % 3 == 0 {
                // Mostly zeros: the shapes Berlekamp-Massey finds awkward.
                data.iter_mut().skip(3).for_each(|b| *b = 0);
            }
            let before = data.clone();
            if code(c, depth, DUAL).correct(&mut data).is_err() {
                assert_eq!(data, before);
            }
        }
    }
}
