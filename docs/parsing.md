# Writing a decoder for a new log format

This tool reads space packet logs from many machines. The packets inside the
logs follow a public standard, CCSDS (Consultative Committee for Space Data
Systems), so the packet checks and timeline are shared code. The files that
wrap those packets vary from one logging program to the next. Writing a
**decoder** (the piece of code that peels off a file's wrapper and hands out
the raw **payload** bytes — the inner packet data without the container's
wrapper) is the part most likely to need new work at a new site.

This guide starts from zero binary-parsing experience and walks through
inspecting an undocumented log file, working out its byte layout, turning that
layout into a decoder in this codebase, defending it against corrupt input, and
testing it. Terms are defined where first used and collected in the
[glossary](#glossary).

---

## 1. How to think about the problem

### A log file is layers wrapped around your data

A log file rarely contains only the data you care about. Recording software
adds headers, timestamps, lengths, and names around each item, and some links
pack packets inside fixed-size blocks before writing them to disk. A log file
can capture data at three depths:

```text
file container      whatever the logging program wraps around each entry
  transfer frames   fixed-size link-layer blocks (only in some logs)
    space packets   the thing this tool cares about
```

- **Bare packets**: space packets back to back, with nothing around them. This
  is the simplest case (`src/pure/decode/raw.rs`).
- **Container around packets**: each packet has a per-entry header added by the
  logger (usually a receive timestamp, a length, and sometimes names), and the
  file may begin with its own file header. Most ground-software logs look like
  this (`cosmos4.rs` and `cosmos5.rs`).
- **Transfer frames**: fixed-size link-layer blocks, each usually starting with
  the four-byte **sync marker** `1A CF FC 1D` (a fixed pattern placed at the
  start of every frame so a receiver can find frame boundaries). Space packets
  are packed inside frames and can straddle two frames, so they must be
  reassembled before packet parsing. Treat transfer frames as a separate layer
  that outputs a packet stream; do not mix reassembly into a packet parser.
  (This codebase does not implement a transfer-frame layer yet.)

A decoder's job ends at: "here is one logged item, the byte offset where its
payload starts in the file, and the receive time and label if the container
stored them." Everything after that (checking whether the payload is a valid
space packet, tracking **sequence counts** — per-APID 14-bit packet counters —
and storing rows) is shared code.

### Work from what you know toward what you do not

When a log format has no documentation, you still know one thing: the space
packets inside it follow the CCSDS Space Packet standard. Every space packet
starts with a 6-byte **primary header** whose bytes you can predict if you know
the **APID** (Application Process Identifier, an 11-bit number identifying a
packet stream) and whether a **secondary header** (mission-defined bytes right
after the primary header, usually a timestamp) is present.

Use those known packet headers as a ruler. Find two consecutive packets, use
the first packet's length field to find where it ends, and look at the gap
between that end and the next packet's start. That gap is the unknown container
header.

### The working loop

Reverse-engineering a binary format follows a four-step loop:

1. **Look.** Inspect the raw bytes of the file before writing code.
2. **Guess.** Form one concrete hypothesis about a field (for example: "bytes
   12 to 15 of each entry are a 4-byte payload length").
3. **Test on the whole file.** Walk entry by entry from byte 0 to the end of
   the file. Checking only the first three entries misses optional flags,
   varying name lengths, footers, and rare entry types.
4. **Write it down.** Record the layout as a table and label each field
   **confirmed** or **guessed**. Put that table in the decoder's module comment
   when you write the code.

### Never trust a length or count read from a file

A file on disk is untrusted input. A single flipped bit, a crash mid-write, or
a misaligned read can turn a 20-byte length into 3,000,000,000 bytes. If your
decoder allocates memory or buffers bytes based on that number without checking
it first, it will exhaust memory, hang, or panic. Always check every length
against a sane lower bound and upper bound before slicing or waiting for more
bytes.

### What "done" looks like

A decoder is finished when all five of these hold:

- It walks real sample files cleanly to the end, or stops with an exact byte
  offset on truncation or corruption.
- It handles every byte-level truncation of a valid file without panicking.
- It survives random noise without panicking.
- Its output matches one byte vector computed by hand on paper, independent of
  any synthetic writer.
- Its packet counts per APID match an independent tool on a real log file.

### Practical habits

- **Ask for the interface document early.** Even an old draft, a header file,
  or a colleague's one-page note can save a day of guessing. Do not wait until
  you are stuck to ask whether a specification exists.
- **Make the smallest step that can be checked.** Confirm the file header size
  and magic bytes before decoding timestamps. Confirm entry boundaries across
  the whole file before decoding labels.
- **Keep a notes file of confirmed versus guessed.** Write down the exact byte
  offsets and sample values that proved each field. A guess you forget is a
  guess that turns into a silent bug later.
- **Change one thing at a time.** When a walk through a file loses sync, adjust
  one assumption (for example, byte order or an optional field) and re-run.
- **Compare against an independent count.** A decoder can fail silently by
  skipping a whole entry type. Check total packets and per-APID counts against
  another reader.
- **When you are stuck, go back to the bytes.** Stop reading your own code and
  dump the 64 bytes around the failing offset with `xxd`. The bytes always tell
  the truth; your mental model is usually what drifted.
- **Know when to stop and ask someone.** If a field's meaning does not show up
  in the bytes (for example, an opaque bitmask, an unknown timestamp epoch, or
  compressed/encrypted payloads), stop guessing and ask the people who own the
  logger.

---

## 2. Binary basics

### Bits, bytes, and hexadecimal

A **bit** is a single binary digit, `0` or `1`. A **byte** is 8 bits, holding
an integer from `0` to `255`.

Writing binary files in decimal or binary is hard to read, so tools display
bytes in **hexadecimal** (base 16, called **hex**), using digits `0`–`9` and
`A`–`F` (where `A` = 10 through `F` = 15). One hex digit represents exactly 4
bits (`0000` to `1111`), so two hex digits represent one byte (`00` to `FF`).
In Rust and prose, hex numbers are written with a `0x` prefix, such as `0x1A3`.

Bit positions inside a packet are numbered from **bit 0** at the leftmost
(**most significant**) bit of byte 0. This matches both the CCSDS standard and
this tool's configuration format.

### Reading a hex dump

A **hex dump** prints a file's raw bytes alongside their positions and any
printable **ASCII** text (the standard mapping of byte values `0x20`–`0x7E` to
characters like letters, digits, and punctuation). Running `xxd` on a file
produces three columns:

```text
00000000: 504b 4c47 0001 0000 6553 f100 0003 d090  PKLG....eS......
^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^
 offset            16 bytes in hex                  ASCII column
```

- **Offset column** (left): the **byte offset** (distance in bytes from the
  start of the file, counted from 0) of the first byte on that row, written in
  hex. Each row holds 16 (`0x10`) bytes, so row offsets go `00000000`,
  `00000010`, `00000020`, and so on.
- **Bytes column** (middle): the 16 bytes on that row, grouped in two-byte
  pairs for readability. Byte `0x00` is `50`, byte `0x01` is `4b`, byte `0x02`
  is `4c`, byte `0x03` is `47`, and byte `0x08` is `65`.
- **ASCII column** (right): each byte shown as its ASCII character if it is
  printable, or `.` if it is not. Here `50 4b 4c 47` spells `PKLG`. Notice `eS`
  at bytes `0x08`–`0x09`: those bytes are `65 53`, which happen to be the ASCII
  codes for `'e'` and `'S'` even though they are part of a binary timestamp.
  Treat the ASCII column as a hint, not proof that bytes are text.

### Big-endian versus little-endian

Numbers larger than 255 take more than one byte. **Byte order** (or
**endianness**) is the order in which those bytes are laid out in the file:

- **Big-endian**: most significant byte first (the same order humans write
  numbers). CCSDS space packets and both COSMOS formats are big-endian.
- **Little-endian**: least significant byte first. Common in logs written
  directly from x86/ARM memory structures.

Worked example with the 4-byte unsigned integer **1000** (`0x000003E8`, since
`3 × 256 + 232 = 768 + 232 = 1000`):

| Byte order | Bytes in file | Calculation | Value |
|---|---|---|---|
| Big-endian | `00 00 03 E8` | `0×16777216 + 0×65536 + 3×256 + 232` | `1000` |
| Little-endian | `E8 03 00 00` | `232 + 3×256 + 0×65536 + 0×16777216` | `1000` |

If you read big-endian `00 00 03 E8` as little-endian by mistake, you get
`0xE8030000` = `3,892,510,720`. Absurdly huge numbers that become small,
reasonable numbers when you reverse the bytes are the fastest sign that you
picked the wrong byte order.

In Rust, use `u16::from_be_bytes` / `u32::from_be_bytes` for big-endian and
`from_le_bytes` for little-endian.

### Pulling apart packed bit fields

A **bit field** packs several small values into one integer so no bits are
wasted. You unpack them with **bit shifts** (`>>`, which slides bits right) and
**bit masks** (`&`, which zeroes out bits you do not want).

Worked example: the first two bytes of a CCSDS space packet, `09 A3` (from the
test vector in `src/pure/ccsds.rs`).

First combine the two big-endian bytes into one 16-bit word `w0 = 0x09A3`, and
write it in binary:

```text
hex:        0      9      A      3
binary:   0000   1001   1010   0011

bits:    [000] [0] [1] [001 1010 0011]
          ^^^   ^   ^   ^^^^^^^^^^^^^
        version |   |       APID (11 bits)
        (3 bits)|   secondary header flag (1 bit)
                type (1 bit)
```

Now extract each field (matching `PrimaryHeader::parse` in `src/pure/ccsds.rs`):

| Field | Bit position | Operation on `w0 = 0x09A3` | Binary result | Value |
|---|---|---|---|---|
| Version | top 3 bits (0..3) | `w0 >> 13` | `000` | `0` (CCSDS space packet) |
| Type | bit 3 (1 bit) | `(w0 & 0x1000) != 0` | `0` | `0` (telemetry; `1` is command) |
| Secondary header flag | bit 4 (1 bit) | `(w0 & 0x0800) != 0` | `1` | `true` (secondary header present) |
| APID | bottom 11 bits (5..16) | `w0 & 0x07FF` | `001 1010 0011` | `419` (`0x1A3`) |

Check the APID conversion: `0x1A3 = 1×256 + 10×16 + 3 = 256 + 160 + 3 = 419`.

You can also run this in reverse to predict header bytes when searching a hex
dump. For telemetry (`type = 0`), version `0`, secondary header present (`1`),
and APID 419 (`0x1A3`): `0x0800 | 0x01A3 = 0x09A3`, so every packet on that
stream starts with `09 A3`.

### Length fields stored as "minus one"

A 16-bit unsigned integer holds values from `0` to `65535`. If a protocol
forbids zero-byte payloads, storing `0` is wasted. Storing **length minus one**
instead lets the same 16 bits represent `1` to `65536` bytes.

The CCSDS primary header's `data_length` field (bytes 4 and 5) works this way:
it holds the number of bytes after the 6-byte primary header, **minus one**.

- If `data_length` is `0x0003` (`3`), there are `3 + 1 = 4` data bytes after
  the primary header.
- Including the 6-byte primary header, the total packet length is
  `6 + data_length + 1` = **`data_length + 7`**.
- For `data_length = 3`, the whole packet is `3 + 7 = 10` bytes.
- Minimum space packet size: `0 + 7 = 7` bytes (6-byte header + 1 data byte).
- Maximum space packet size: `65535 + 7 = 65542` bytes (6-byte header + 65536
  data bytes).

---

## 3. First look at an unknown file

Before writing any code, run four read-only commands on a copy of the log:

```sh
xxd -l 256 file.bin          # the first 256 bytes
xxd -s -256 file.bin         # the last 256 bytes (footers, truncation)
strings -n 6 file.bin | head # readable ASCII strings of length >= 6
ls -l file.bin               # exact file size in bytes
```

Look for five clues:

- **A magic string** at offset `0`. **Magic bytes** (or a **magic string**) are
  a fixed identifier written at the start of a file so readers recognise the
  format. Two public ones this tool already recognises are `COSMOS4_` and
  `COSMOS5_` (layouts in section 8).
- **Repeated readable names** through the file (`strings` shows them). This
  usually means the container stores target, channel, or packet names inline.
- **A file size that divides evenly** by a round number (for example, 1024 or
  1115 bytes). That points to fixed-size records or transfer frames.
- **The sync marker `1A CF FC 1D`** repeating at a fixed spacing. That means
  transfer frames, and the spacing in bytes is the frame length.
- **Predictable space packet header bytes.** If you expect telemetry on APID 419
  (`0x1A3`) with a secondary header, its packets start with `09 A3`. Search the
  dump for `09a3` (or `09 a3`).

---

## 4. Worked example: reversing a container from a hex dump

Suppose you are handed an undocumented 89-byte log file (invented for this
guide) and told only that it should contain telemetry on APID 419 (`0x1A3`)
with a secondary header. You run `xxd` on the file:

```text
00000000: 504b 4c47 0001 0000 6553 f100 0003 d090  PKLG....eS......
00000010: 0353 4349 0000 000a 09a3 c005 0003 aabb  .SCI............
00000020: ccdd 6553 f101 0007 a120 0353 4349 0000  ..eS..... .SCI..
00000030: 000c 09a3 c006 0005 1122 3344 5566 6553  ........."3DUfeS
00000040: f102 0001 86a0 0448 4b30 3100 0000 0a08  .......HK01.....
00000050: 64c0 0000 0310 2030 40                   d..... 0@
```

Walk through the file step by step.

### Step 1: Look at the start of the file

Offset `0x00` begins with `50 4b 4c 47`, which is `PKLG` in ASCII. That is
almost certainly a 4-byte magic string. The next four bytes (`0x04..0x08`) are
`00 01 00 00` — possibly a version number (`1`) and two reserved bytes, or
flags. Write this in your notes as a **guess** and move on.

### Step 2: Find two consecutive packets you can predict

From section 2, telemetry on APID 419 (`0x1A3`) with a secondary header starts
with `09 a3`. Scan the dump for `09a3`:

1. **First match at offset `0x18` (byte 24):** `09 a3 c0 05 00 03`
   - Word 0 (`09 a3`): version `0`, telemetry, secondary header `1`, APID 419
     (`0x1A3`).
   - Word 1 (`c0 05`): top two bits are `11` (`3`, whole unsegmented packet);
     bottom 14 bits are `0x0005` (sequence count **5**).
   - Word 2 (`00 03`): `data_length = 3`. Total packet length is `3 + 7 = 10`
     bytes (`0x0A`).
   - Therefore Packet 1 occupies `0x18..0x22` (`09 a3 c0 05 00 03 aa bb cc dd`).

2. **Second match at offset `0x32` (byte 50):** `09 a3 c0 06 00 05`
   - Word 0 (`09 a3`): version `0`, telemetry, secondary header `1`, APID 419
     (`0x1A3`).
   - Word 1 (`c0 06`): unsegmented, sequence count **6** — exactly one higher
     than Packet 1. That confirms both matches are real packets, not random
     bytes.
   - Word 2 (`00 05`): `data_length = 5`. Total packet length is `5 + 7 = 12`
     bytes (`0x0C`).
   - Therefore Packet 2 occupies `0x32..0x3E`
     (`09 a3 c0 06 00 05 11 22 33 44 55 66`).

### Step 3: Isolate the container header

Packet 1 ends at `0x22`. Packet 2 begins at `0x32`. The 16 bytes between them
(`0x22..0x32`) must be the container header for Entry 2:

```text
Entry 2 header (0x22..0x32): 65 53 f1 01 | 00 07 a1 20 | 03 53 43 49 | 00 00 00 0c
```

Look 16 bytes back from Packet 1 (`0x18 - 0x10 = 0x08`) to see if Entry 1 has
the same structure:

```text
Entry 1 header (0x08..0x18): 65 53 f1 00 | 00 03 d0 90 | 03 53 43 49 | 00 00 00 0a
```

They line up byte for byte, and `0x08` sits immediately after
`50 4b 4c 47 00 01 00 00`. That confirms the file header is **8 bytes**
(`0x00..0x08`) and entries begin at byte 8.

### Step 4: Work out each field in the 16-byte entry header

Compare the two entry headers side by side:

- **Bytes `+12..+16` (the 4 bytes right before the packet):**
  - Entry 1 (`0x14..0x18`): `00 00 00 0a` = `10` in big-endian `u32`. Packet 1
    is 10 bytes.
  - Entry 2 (`0x2e..0x32`): `00 00 00 0c` = `12` in big-endian `u32`. Packet 2
    is 12 bytes.
  - Little-endian would give `0x0a000000` (`167,772,160`), which is impossible.
  - **Result:** 4-byte big-endian payload length.

- **Bytes `+8..+12`:**
  - Entry 1 (`0x10..0x14`): `03 53 43 49` — byte `03` followed by three ASCII
    characters `SCI`.
  - Entry 2 (`0x2a..0x2e`): `03 53 43 49` — byte `03` followed by `SCI`.
  - **Guess:** a **length-prefixed** name (1-byte length `n`, followed by `n`
    ASCII bytes). Both entries have length 3, so we still need an entry with a
    different length to confirm it is not a fixed 4-byte field.

- **Bytes `+0..+8`:**
  - Entry 1 (`0x08..0x10`): `65 53 f1 00`, then `00 03 d0 90`.
  - Entry 2 (`0x22..0x2a`): `65 53 f1 01`, then `00 07 a1 20`.
  - First 4 bytes: `0x6553F100` = `1,700,000,000`; `0x6553F101` =
    `1,700,000,001`. It increments by 1 and equals `2023-11-14T22:13:20Z` in
    seconds since the **Unix epoch** (`1970-01-01T00:00:00Z`).
  - Next 4 bytes: `0x0003D090` = `250,000`; `0x0007A120` = `500,000`. Values in
    `0..999,999` following Unix seconds are microseconds.
  - **Result:** 4-byte big-endian Unix seconds, then 4-byte big-endian
    microseconds.

### Step 5: Test the hypothesis on the rest of the file

Packet 2 ends at `0x3E`. Apply the proposed layout starting at `0x3E` and see
if it lands cleanly on the end of the 89-byte (`0x59`) file:

- `0x3E..0x42`: `65 53 f1 02` = `1,700,000,002` seconds (one second after
  Entry 2).
- `0x42..0x46`: `00 01 86 a0` = `100,000` microseconds (valid, under
  `1,000,000`).
- `0x46`: `04` -> read 4 bytes (`0x47..0x4B`): `48 4b 30 31` = `"HK01"`. The
  length byte changed from `03` to `04` and the name grew from 3 bytes to 4
  bytes. That **confirms** the length-prefixed name hypothesis.
- `0x4B..0x4F`: `00 00 00 0a` = `10` bytes of payload.
- `0x4F..0x59`: `08 64 c0 00 00 03 10 20 30 40`:
  - `08 64`: `0x0864 >> 13 = 0` (version 0), `0x0864 & 0x1000 = 0` (telemetry),
    `0x0864 & 0x0800 != 0` (secondary header present), `0x0864 & 0x07FF = 0x064`
    = **APID 100 (`0x064`)**.
  - `c0 00`: unsegmented, sequence count 0.
  - `00 03`: `data_length = 3` -> total packet length `3 + 7 = 10` bytes,
    matching the container's length field `10`.
- End of Entry 3: `0x4F + 0x0A = 0x59` = 89 bytes — the exact end of the file,
  with zero leftover bytes.

### Step 6: Write down the layout table

Put this table in your notes and later in the top doc-comment of your decoder
module. Mark anything not yet proved across multiple files as a guess.

**File header (8 bytes, big-endian):**

| Offset | Size | Field | Status |
|---|---|---|---|
| `0` | 4 | Magic ASCII `PKLG` (`50 4B 4C 47`) | Confirmed |
| `4` | 2 | Format version (`00 01` = 1) | Guessed — check more files or spec |
| `6` | 2 | Reserved (`00 00`) | Guessed — check more files or spec |

**Per-entry layout (repeated to end of file, big-endian):**

| Size | Field | Status |
|---|---|---|
| 4 | Receive time, seconds since Unix epoch (`u32`) | Confirmed |
| 4 | Receive time, microseconds (`u32`, `0..999_999`) | Confirmed |
| `1 + n` | Channel name length (`u8`), then `n` ASCII bytes | Confirmed (`n = 3`, `n = 4`) |
| `4 + m` | Payload length (`u32`), then `m` payload bytes | Confirmed (`m = 10`, `m = 12`) |

No footer and no index.

---

## 5. Turning a layout into a decoder

### How decoders fit into this codebase

This project uses a **functional core, imperative shell** split (see
`docs/architecture.md`):

- Decoders live under `src/pure/decode/`. Each decoder is a **push parser**:
  the caller hands it whatever bytes are currently buffered and the byte offset
  of `buf[0]` in the file, and the decoder answers with one record, a skip,
  "need more bytes", or a fatal error.
- A decoder never opens or reads a file. In production, `shell::files::Records`
  owns the read-only file handle and refill loop. In unit tests,
  `pure::decode::decode_all` drives the same decoder over an in-memory `&[u8]`.
- Look at the existing decoders as references:
  - `src/pure/decode/raw.rs`: smallest decoder (stateless, no file header).
  - `src/pure/decode/cosmos4.rs`: file header, flags, variable-length names,
    receive timestamp.
  - `src/pure/decode/cosmos5.rs`: keeps state (target and packet name tables)
    between calls.

### The `Decoder` trait and `Step` enum

These are the exact definitions in `src/pure/decode/mod.rs`:

```rust
pub const MAX_ENTRY: usize = 16 * 1024 * 1024;

pub struct Record {
    /// Byte offset in the file of the first byte of `payload`.
    pub offset: u64,
    /// When the logging host received it, in nanoseconds since the Unix
    /// epoch, if the container records that.
    pub receive_time_ns: Option<i64>,
    /// The container's own name for the item, if it stores one.
    pub label: Option<String>,
    /// What was logged. Usually one space packet, but containers store
    /// whatever their interfaces deliver, so check before trusting it.
    pub payload: Vec<u8>,
}

pub enum DecodeError {
    /// The bytes at `offset` cannot be what the format says they should be.
    Implausible { offset: u64, reason: &'static str },
}

pub enum Step {
    /// One record. Drop `consumed` bytes from the front and call again.
    Record { consumed: usize, record: Record },
    /// `consumed` bytes of structure (a file header, a declaration) that
    /// produced no record. Drop them and call again.
    Skip { consumed: usize },
    /// The next entry is not complete in the bytes offered. Call again with
    /// the same bytes plus more. At end of file this means a truncated tail.
    NeedMore,
    /// The decoder cannot continue. Do not call it again.
    Fatal(DecodeError),
}

pub trait Decoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step;
}
```

Pay close attention to `Record.offset`: it is the byte offset in the file of
the **first byte of `payload`**, not the start of the container wrapper. The
store uses this offset to seek straight to the packet bytes later when showing
packet details.

### Annotated decoder skeleton for `PKLG`

Save a new decoder as `src/pure/decode/pklg.rs`. The skeleton below implements
the layout from section 4 and compiles against `src/pure/decode/mod.rs`:

```rust
//! Push decoder for invented PKLG packet logs.

use super::{DecodeError, Decoder, MAX_ENTRY, Record, Step};

const HEADER_LEN: usize = 8;
const MAGIC: &[u8; 4] = b"PKLG";

#[derive(Debug, Default)]
pub struct PklgDecoder {
    header_seen: bool,
}

impl PklgDecoder {
    pub fn new() -> Self {
        Self::default()
    }
}

fn read_u32_be(buf: &[u8], pos: usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(pos..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

impl Decoder for PklgDecoder {
    fn step(&mut self, buf: &[u8], offset: u64) -> Step {
        // 1. File header: verify magic once, then skip all 8 header bytes.
        // Once bytes 4..8 are confirmed from a spec, validate them here too.
        if !self.header_seen {
            let Some(magic) = buf.get(..MAGIC.len()) else {
                return Step::NeedMore;
            };
            if magic != MAGIC {
                return Step::Fatal(DecodeError::Implausible {
                    offset,
                    reason: "invalid PKLG magic",
                });
            }
            if buf.len() < HEADER_LEN {
                return Step::NeedMore;
            }
            self.header_seen = true;
            return Step::Skip {
                consumed: HEADER_LEN,
            };
        }

        // 2. Fixed fields: 4-byte seconds, 4-byte microseconds, 1-byte name length.
        let Some(secs) = read_u32_be(buf, 0) else {
            return Step::NeedMore;
        };
        let Some(usecs) = read_u32_be(buf, 4) else {
            return Step::NeedMore;
        };
        if usecs >= 1_000_000 {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "PKLG microseconds out of range",
            });
        }
        let Some(&name_len_u8) = buf.get(8) else {
            return Step::NeedMore;
        };
        let name_start = 9usize;
        let name_end = name_start + usize::from(name_len_u8);
        let Some(name_bytes) = buf.get(name_start..name_end) else {
            return Step::NeedMore;
        };

        // 3. Payload length: check against MAX_ENTRY before waiting for payload bytes.
        let Some(raw_len) = read_u32_be(buf, name_end) else {
            return Step::NeedMore;
        };
        let payload_start = name_end + 4;
        let Ok(payload_len) = usize::try_from(raw_len) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "PKLG payload length exceeds MAX_ENTRY",
            });
        };
        let Some(entry_end) = payload_start
            .checked_add(payload_len)
            .filter(|&end| end <= MAX_ENTRY)
        else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "PKLG entry exceeds MAX_ENTRY",
            });
        };
        let Some(payload) = buf.get(payload_start..entry_end) else {
            return Step::NeedMore;
        };

        // 4. Build the Record. Offset points to the payload, not the entry header.
        let Some(payload_offset) = offset.checked_add(payload_start as u64) else {
            return Step::Fatal(DecodeError::Implausible {
                offset,
                reason: "PKLG payload offset overflow",
            });
        };
        let receive_time_ns = i64::from(secs) * 1_000_000_000 + i64::from(usecs) * 1_000;
        let label = String::from_utf8_lossy(name_bytes).into_owned();

        Step::Record {
            consumed: entry_end,
            record: Record {
                offset: payload_offset,
                receive_time_ns: Some(receive_time_ns),
                label: Some(label),
                payload: payload.to_vec(),
            },
        }
    }
}
```

### Registering the new format

All wiring lives in `src/pure/decode/mod.rs`. Nothing in `src/shell/` needs to
change because `check` and `ingest` dispatch through `sniff` and `decoder_for`.
Make five small additions in `src/pure/decode/mod.rs`:

1. Expose the module: `pub mod pklg;`
2. Add a variant to `Format`: `Pklg,`
3. Name it in `Format::name` (`Format::Pklg => "pklg"`) and add it to
   `Format::is_certain` if it is recognised by magic bytes rather than guessed.
4. Detect it in `sniff` from the first bytes — **before** the heuristic guesses
   (`RawCcsds` and `Text`), never from the file name:
   ```rust
   } else if prefix.starts_with(b"PKLG") {
       Format::Pklg
   ```
5. Construct it in `decoder_for`:
   ```rust
   Format::Pklg => Some(Box::new(pklg::PklgDecoder::new())),
   ```

A site-specific decoder can live in a private copy of the crate: it is one new
file plus these lines in `src/pure/decode/mod.rs`.

### Rules every decoder follows

- **No I/O in `src/pure/`.** Decoders touch only the byte slice handed to
  `step`. `tests/purity.rs` fails `cargo test` if any file under `src/pure/`
  references `std::fs`, `std::io`, `std::net`, `std::time`, `std::env`,
  `std::process`, `std::thread`, `rusqlite`, `println!`, `eprintln!`, `print!`,
  or `dbg!`.
- **Never panic.** Whatever bytes arrive, return a `Step` variant.
- **Never consume zero bytes.** Both `Step::Record` and `Step::Skip` must have
  `consumed >= 1`. `shell::files::Records` treats `consumed == 0` as a fatal
  decoder bug; without that check, the read loop would spin forever on the same
  offset.
- **Treat an oversized entry as `Fatal`, not `NeedMore`.** Check every length
  against `MAX_ENTRY` (16 MiB) before checking `buf.len()`.
- **Report byte offsets.** Put the payload's file offset on `Record.offset`,
  and the offending entry's file offset on `DecodeError::Implausible.offset`.
- **Keep container and packet parsing apart.** Return the raw payload bytes in
  `Record.payload`. Shared code (`pure::ingest::whole_packet_header` and
  `shell::cli`) decides whether the payload is a space packet and routes
  non-packets to their own lane.
- **Convert receive times to Unix nanoseconds.** If the container carries a
  receive timestamp, store it as `Option<i64>` nanoseconds since
  `1970-01-01T00:00:00Z`.

---

## 6. Defensive parsing

Real log files are cut off mid-write, copied while open, and occasionally
corrupt. A decoder that panics or loops forever on one damaged file breaks the
tool on the day it is needed.

### Truncated tails

**What goes wrong without handling it:** A logger crashes or loses power halfway
through writing the last entry. If the decoder rejects the entire file, you
lose hours of valid packets recorded before the cut. If it indexes past the end
of `buf`, it panics.

**Rule:** Whenever `buf` has fewer bytes than the current entry needs (and all
lengths read so far are plausible), return `Step::NeedMore`. At end of file,
the driver (`decode_all` or `shell::files::Records`) keeps every complete
record already returned and emits one `DecodeEnd::Truncated { offset, available }`
reporting where the incomplete entry starts and how many bytes of it were left.

### Files copied while being written

**What goes wrong without handling it:** Engineers routinely copy a log off a
test host while the logger is still appending to it. The copy normally ends
mid-entry (a truncated tail). If a tool opens live logs read-write or creates
sidecar files next to them, it risks corrupting or colliding with the running
system.

**Rule:** Work on copies on a workstation. `shell::files::open_sniffed` opens
inputs read-only and never writes next to them. Treating a truncated tail as
normal handles in-progress copies cleanly.

### Corrupt lengths and integer overflow

**What goes wrong without checking:**

- **Memory exhaustion or stalling:** A flipped bit turns a 16-byte length into
  2 GiB. Calling `Vec::with_capacity(len)` crashes with out-of-memory. Returning
  `Step::NeedMore` forces `Records` to keep reading and buffering chunks until
  it hits the `MAX_ENTRY` buffer guard.
- **Overflow:** Computing `payload_start + payload_len` on a corrupt `u32::MAX`
  panics in debug builds or wraps around to a small number in release builds,
  causing you to consume the wrong slice.
- **Underflow:** In formats whose entry length counts its own fixed header
  (like COSMOS 5, where `entry_len` includes the 2-byte flags), a corrupt
  length of `0` or `1` makes `entry_len - 2` panic or wrap.

**Rule:** Validate every length from the file immediately after reading it:

1. Check it is at least as large as the fixed fields it covers.
2. Convert with `usize::try_from` and compute total size with `checked_add`.
3. Reject anything above `MAX_ENTRY` (16 MiB) with `Step::Fatal` **before**
   checking `buf.len()`. Remember that a single CCSDS space packet is at most
   65,542 bytes; a container entry claiming 3 GB is corruption, not data.

### No panics on untrusted bytes

**What goes wrong without it:** One damaged file in a folder of fifty crashes
the whole `check` or `ingest` command before the other forty-nine files are
inspected.

**Rule:** Never index a slice with `buf[i]` or `buf[a..b]` using values derived
from the file; use `buf.get(...)` and handle `None`. Never call `.unwrap()` or
`.expect()` on anything parsed from input bytes. Use `String::from_utf8_lossy`
for container names so one non-UTF-8 byte in a label does not abort a whole
file.

### Fail loudly, with a byte offset

**What goes wrong without it:** Returning a generic `"parse error"` gives you
no way to check whether the bug is in your decoder or in the file. Silently
guessing and continuing hides data loss and injects fake packets into
continuity checks.

**Rule:** When a magic value, flag bit, length, or index violates the format,
return `Step::Fatal(DecodeError::Implausible { offset, reason })` with a
specific reason string. With the offset printed in hex (`byte 0x4f2a10`), you
can jump straight to the bytes with `xxd -s 0x4f2a10 -l 64 file.bin`.

### Resynchronising after corruption

**What goes wrong with a bad policy:**

- In a length-prefixed format with no sync marker, one bad length lands the
  reader inside the middle of a later payload. Every subsequent read treats
  payload bytes as container headers, producing either garbage or an immediate
  error.
- Trying to recover by scanning byte-by-byte for a single plausible-looking
  CCSDS header fails badly: checking only `version == 0` (three zero bits)
  matches roughly 1 in 8 random positions by chance, manufacturing fake packets
  that corrupt sequence-count checks.

**Rule:** Decide the resynchronisation policy per format:

- **Formats with a sync marker** (such as transfer frames starting with
  `1A CF FC 1D`): scan forward to the next marker, verify markers repeat at the
  expected frame spacing, and report how many bytes were skipped. (Not yet
  implemented in this codebase.)
- **Length-prefixed formats with no marker** (bare packets, COSMOS 4, COSMOS 5,
  `PKLG`): one bad length loses the rest of the stream. The built-in decoders
  stop with `Step::Fatal`. Note that `Step` currently has no "skipped corrupt
  range with warning" variant — `Step::Skip` is silent and is only for normal
  container structure such as file headers or declarations. If a custom format
  ever requires scanning past corruption, resync only at a position where
  several entries in a row chain cleanly (plausible lengths, CCSDS version 0,
  known APIDs) and report the skipped byte range explicitly.

---

## 7. Testing a decoder

Core decoders have no I/O, so every test runs on plain `Vec<u8>` buffers with
no temporary files and no mocks. Follow these five steps for every new decoder:

### 1. Generate inputs with a writer

Add a small writer function for the format in `src/pure/synth.rs` (or inside
the decoder's `#[cfg(test)]` module). Build a multi-entry buffer with varied
payload sizes, names, timestamps, and optional fields, pass it to
`pure::decode::decode_all` via `decoder_for(Format::YourFormat)`, and assert:

- `end` is `None`;
- every `receive_time_ns`, `label`, and `payload` matches what was written;
- for every record, `&data[rec.offset as usize .. rec.offset as usize + rec.payload.len()] == rec.payload.as_slice()`.

Never commit a real log file, and never paste real APID names or real packet
contents into tests.

### 2. Write one hand-computed byte vector

Work out one small file (a header and one or two entries) byte by byte on
paper, write it as a literal byte array without calling your writer, and assert
every decoded field. See `hand_written_vector` in `src/pure/decode/cosmos4.rs`
and `cosmos5.rs`, and `VECTOR` in `src/pure/ccsds.rs`.

Why this step is mandatory: if your writer and your decoder share a mistake
(for example, both use little-endian where the real format uses big-endian, or
both are off by one on a length), the round-trip test in step 1 still passes.
A hand-computed vector catches shared assumptions.

### 3. Cut the file at every byte

Loop over every prefix `&data[..cut]` for `cut` in `0..=data.len()` and run
`decode_all` with a fresh decoder each time. See `truncation_at_every_offset`
in `src/pure/decode/raw.rs`, `cosmos4.rs`, and `cosmos5.rs`. Assert that:

- every returned record equals the corresponding record from the full decode;
- at clean entry boundaries (including `0`, the end of the file header, and
  `data.len()`), `end` is `None`;
- at every other cut, `end` is `Some(DecodeEnd::Truncated { .. })`;
- no cut panics or returns an unexpected `Fatal`.

### 4. Throw noise and fatal edge cases at it

- **Pseudo-random noise:** generate deterministic byte sequences of lengths
  `0..256` (both from byte 0 and appended right after a valid file header) and
  pass them to `sniff` and `decode_all`. See `arbitrary_bytes_do_not_panic` in
  `raw.rs` and `random_bytes_after_header_do_not_panic` in `cosmos4.rs`. They
  must return cleanly without panicking. If a decoder becomes complex, fuzz it
  with `cargo fuzz`.
- **Targeted fatal tests:** construct one test per rejection path — bad magic,
  unknown flag bits, length smaller than fixed fields, length equal to
  `MAX_ENTRY + 1` (with only a few bytes in `buf`, confirming it returns
  `Fatal` immediately instead of `NeedMore`), and out-of-range timestamps or
  indices. See `fatal_conditions` in `cosmos4.rs` and `cosmos5.rs`.

### 5. Compare counts against another tool

Run `cargo test` first — this runs your unit tests and `tests/purity.rs`
(confirming no I/O entered `src/pure/`). Then run `packetlane check <file>` on
a real log copy kept outside the repository. Compare the total packet count and
the per-APID packet counts against another tool that reads the same format (the
ground system's own exporter or an independent script). Investigate any
discrepancy before finishing.

---

## 8. Reference: space packets, time, COSMOS formats, and text logs

### Space packet primary header

Six bytes, big-endian (`src/pure/ccsds.rs`, CCSDS 133.0-B). This part is the
same across missions.

| Bits | Field | Notes |
|---|---|---|
| 3 | version | always 0 |
| 1 | type | 0 telemetry, 1 command |
| 1 | secondary header flag | 1 if a secondary header follows |
| 11 | APID | 2047 (`0x7FF`) is idle fill: skip it in checks |
| 2 | sequence flags | 3 = whole packet; 1, 0, 2 = first, middle, last segment |
| 14 | sequence count | per APID, wraps from 16383 to 0 |
| 16 | data length | bytes after this header, **minus one** |

- Total packet length is the length field **plus 7** (minimum 7 bytes, maximum
  65,542 bytes).
- Telemetry and commands with the same APID number are separate streams with
  separate sequence counters.
- Commands may carry a name-based or always-zero count instead of a running
  counter. Check before reporting command gaps.
- The **secondary header is mission defined**. It usually starts with a
  timestamp, but its width, **epoch** (the zero point a clock counts from), and
  encoding come from the mission's interface documents. Two common encodings
  (both supported in `[packet_time]` in `src/pure/config.rs`) are an
  unsegmented count (**CUC**: seconds plus a binary fraction) and a
  day-segmented one (**CDS**: days since an epoch plus milliseconds of day).
  Take the format from configuration; never hard-code it in a decoder.

### Time and the three clocks

Keep three clocks apart (see `README.md`): **packet time** (from the packet's
secondary header), **receive time** (from the log container), and **text log
time** (from text log lines).

- Store every time as integer nanoseconds (`i64`) plus which clock it belongs
  to.
- Packet time may be on an atomic **timescale** with its own epoch, not **UTC**
  (Coordinated Universal Time); the difference from UTC is a whole number of
  seconds that changes with leap seconds. Convert only when configuration says
  how (`[packet_time]` `epoch` and `subtract_seconds`).
- Packet time does not have to advance with wall time: a simulator can be
  paused, restarted, or run from a preset time. Out-of-order packet times are
  something to inspect in the data, not a parser bug.
- Each host's receive time has its own **clock skew** (offset or drift relative
  to true time). Allow a per-source offset (`[[source]]` `clock_offset_ms`).

### Two public container formats: COSMOS 4 and COSMOS 5

Both are from the open-source COSMOS ground system and are documented by its
public source. Both are big-endian, uncompressed, store packets as received,
and carry no text logs. Both already have decoders in this codebase
(`src/pure/decode/cosmos4.rs` and `src/pure/decode/cosmos5.rs`). Implement any
new readers from format layouts; do not port original source code without
checking its licence against this project's.

#### COSMOS 4 (`COSMOS4_` and `COSMOS2_`)

COSMOS 4 wrote two layouts. Versions up to 4.2 start the file with `COSMOS2_`
and have no flags byte and no extra block; versions from 4.3 start it with
`COSMOS4_` and have both. Everything else is the same, and one decoder reads
both, choosing by the file header.

File header, 128 ASCII bytes: `COSMOS4_` or `COSMOS2_`, then `CMD` or `TLM`, `_`, a 32-byte
space-padded configuration name, `_`, an 83-byte space-padded hostname.

Each entry:

| Size | Field |
|---|---|
| 1 | `COSMOS4_` only. Flags: `0x80` stored, `0x40` extra |
| 4 + n | `COSMOS4_` only, and only if extra: length, then that many bytes of JSON |
| 4 | receive time, seconds since the Unix epoch |
| 4 | receive time, microseconds |
| 1 + n | target name length, then the name |
| 1 + n | packet name length, then the name |
| 4 + n | packet length, then the packet |

No index, no footer. A log normally begins with one metadata packet, `SYSTEM
META`, that is not a space packet: byte 0 is a packet id, bytes 1 to 32 the
configuration name, bytes 33 to 62 the COSMOS version. The decoder reports the
configuration, host and version through `Decoder::describe`, and ingest keeps
that text in the file's note.

COSMOS 1 logs start with a 42-byte header instead: `COSMOS`, then `CMD` or
`TLM` in either case, one separator byte, and a 32-byte configuration name.
Their entries are the same as under `COSMOS2_`.

#### COSMOS 5 (`COSMOS5_`)

After the 8-byte magic (`COSMOS5_`), every entry is a 4-byte length (counting
what follows it), a 2-byte flags field, then a body chosen by `flags & 0xF000`:

| Type | Body |
|---|---|
| `0x1000` target declaration | target name; optional 32-byte id |
| `0x2000` packet declaration | 2-byte target index, packet name; optional 32-byte id |
| `0x3000` raw packet | 2-byte packet index, 8-byte time in ns since the Unix epoch, packet bytes |
| `0x4000` JSON packet | same header, JSON text instead of bytes |
| `0x5000` offset marker | a string; skip it |

Other flag bits: `0x0800` command (otherwise telemetry), `0x0400` stored,
`0x0200` an id is present. Names appear once, in declarations; packets refer to
them by index, counted from zero in order of appearance. The reader therefore
keeps the two name tables as it goes. A separate `.idx` file maps entries to
byte offsets and is not needed for a forward read.

In both COSMOS formats, do not assume the stored bytes are space packets: these
systems log whatever their interfaces deliver. Check the header and report
anything that is not.

### Text logs

Text logs do not use `Decoder`; this codebase parses them with
`src/pure/textlog.rs` and `src/pure/time.rs`, configured via `[[log]]` in
`packetlane.toml`. General rules for handling text logs:

- Use one pattern per log type, with named capture groups for the timestamp
  parts (`year`, `month`, `day`, `hour`, `minute`, `second`, `frac`, `tz`, or
  `epoch`). Parse the groups to a time yourself; a few dozen lines of date
  arithmetic avoids a dependency.
- A line that does not match belongs to the entry above it (stack traces,
  wrapped messages). Do not drop it and do not give it its own timestamp.
- Timezone comes from configuration per source (`[[source]]` `utc_offset`).
  Many logs do not state their timezone.
- Some formats omit the year. Take it from the file's context (`default_year`)
  and handle the new-year rollover.
- Rotated logs (`.1`, `.2`, dated suffixes) belong to one stream; order by
  content time, not by file name. Decompress compressed logs (such as `.gz`) to
  a copy first.

---

## 9. Checklist for a new format

### Before you start

- [ ] Copy a sample log to a workstation; never touch live logs or write next to inputs.
- [ ] Ask whether an interface document, header file, or existing reader exists.
- [ ] Find out which APIDs (and whether secondary headers) are expected in the sample.
- [ ] Start a notes file separating **confirmed** facts from **guesses**.

### Inspect and reverse-engineer

- [ ] Run `xxd -l 256`, `xxd -s -256`, `strings -n 6 | head`, and `ls -l` on the copy.
- [ ] Identify the layer: bare packets, container around packets, or transfer frames.
- [ ] Find two consecutive predictable packet headers and compute where the first ends (`data_length + 7`).
- [ ] Decode the bytes between them (length, byte order, timestamp, flags, names).
- [ ] Walk the entire file from offset 0 to EOF and confirm zero unexpected leftover bytes.
- [ ] Check at least two files if available, including different packet types or optional flags.
- [ ] Write the layout table (file header + entry layout) with confirmed vs guessed notes.

### Implement and register

- [ ] Create `src/pure/decode/<format>.rs` implementing `Decoder` with the layout table in the module comment.
- [ ] Use only `buf.get(...)`, `checked_add`/`checked_sub`, and `usize::try_from`; no `unwrap` on input.
- [ ] Check every length against its minimum and `MAX_ENTRY` before checking `buf.len()`.
- [ ] Verify `consumed` is never `0` in `Step::Record` and `Step::Skip`.
- [ ] Set `Record.offset` to the byte offset of the payload, not the entry header.
- [ ] Convert container receive timestamps to `i64` nanoseconds since the Unix epoch.
- [ ] Register the format in `src/pure/decode/mod.rs`: `pub mod`, `Format`, `Format::name`, `Format::is_certain`, `sniff` (before heuristic guesses), and `decoder_for`.

### Test and verify

- [ ] Add a synthetic writer and round-trip test (no real logs or real names in the repo).
- [ ] Add one hand-computed byte vector test independent of the writer.
- [ ] Add a `truncation_at_every_offset` test covering `0..=data.len()`.
- [ ] Add a noise test and targeted `Fatal` tests (bad magic, bad flags, short length, length > `MAX_ENTRY`).
- [ ] Run `cargo test` (verifies all unit tests and `tests/purity.rs`).
- [ ] Run `packetlane check` on a real copy outside the repo and match per-APID counts against another tool.

---

## 10. Common mistakes

- **Forgetting `+ 7` on CCSDS packet length.** `data_length` is the byte count
  after the 6-byte header *minus one*. Using `6 + data_length` leaves you 1
  byte short on every packet.
- **Wrong byte order.** Reading a big-endian length as little-endian (or vice
  versa) produces a multi-million-byte length on entry 1. Try both orders.
- **Setting `Record.offset` to the entry start instead of the payload start.**
  `Record.offset` must point to the first byte of `payload` (`offset + payload_start`),
  while `DecodeError::Implausible.offset` points to where the bad data starts.
- **Checking `buf.len()` before checking `MAX_ENTRY`.** On a corrupt 2 GB
  length in a 1 KB file, checking `buf.len()` first returns `NeedMore`
  (reported as `Truncated`) instead of `Fatal(Implausible)`. Always validate
  lengths before slicing or returning `NeedMore`.
- **Returning `consumed: 0`.** A zero-byte `Skip` or `Record` makes no forward
  progress and is rejected as an error by `Records`.
- **Testing only against your own writer.** A shared bug between writer and
  decoder passes round-trip tests. Always write one hand-computed byte vector.
- **Assuming every logged entry is a space packet.** Ground-system containers
  often record metadata or non-CCSDS items alongside space packets. Do not fail
  the container decoder when a payload is not a valid space packet; let shared
  code classify it.
- **Checking only the first three entries.** Optional flags, variable-length
  names, JSON entries, or footers often appear later in a real file. Always
  walk to the end.
- **Mistaking binary bytes for ASCII text.** Two bytes of a timestamp or
  counter (like `65 53` -> `eS`) can fall in the printable ASCII range by
  coincidence. Verify from offsets and values, not the ASCII column alone.
- **Committing real logs or mission names.** Keep all test inputs synthetic and
  invented.

---

## Glossary

- **APID**: Application Process Identifier. An 11-bit number (`0`–`2047`)
  naming the stream a space packet belongs to, such as one instrument's science
  data. Shown in decimal in this tool (for example, APID 419, which is `0x1A3`
  in hex).
- **ASCII**: American Standard Code for Information Interchange. A character
  encoding mapping bytes `0x20`–`0x7E` to printable English letters, digits,
  and punctuation.
- **Big-endian**: Byte order with the most significant byte stored first. Used
  by CCSDS space packets and both COSMOS container formats.
- **Bit**: One binary digit (`0` or `1`).
- **Bit field**: Multiple small fields packed side by side inside one integer
  or byte sequence, unpacked with shifts and bit masks.
- **Bit mask**: A fixed binary pattern combined with `&` (bitwise AND) to keep
  only the bits of one field (for example, `w0 & 0x07FF` keeps the bottom 11
  bits for the APID).
- **Byte**: Eight bits, holding an unsigned integer from `0` to `255`
  (`0x00`–`0xFF`).
- **CCSDS**: Consultative Committee for Space Data Systems, the body that
  publishes the Space Packet Protocol standard (`CCSDS 133.0-B`).
- **CDS**: CCSDS Day Segmented Time Code — a secondary-header timestamp format
  storing days since an epoch, milliseconds of day, and optional sub-milliseconds.
- **Clock skew**: The difference between a host's local clock and true time.
- **Container**: Whatever file structure a logging program wraps around the
  data it records (file headers, per-entry timestamps, lengths, and names).
- **CUC**: CCSDS Unsegmented Time Code — a secondary-header timestamp format
  storing coarse seconds since an epoch plus a binary fractional second.
- **Decoder**: Code that strips one log format's container wrapper and emits
  raw payload records (`pure::decode::Decoder`).
- **Decommutation**: Turning packet bytes into named, scaled values using the
  packet definitions.
- **Epoch**: The zero point that a clock or timestamp counts forward from (for
  example, the **Unix epoch** is `1970-01-01T00:00:00Z`).
- **Hexadecimal (hex)**: Base-16 notation using digits `0`–`9` and `A`–`F`. Two
  hex digits represent one byte.
- **Hex dump**: A text view of a binary file showing byte offsets, hex byte
  values, and an ASCII preview column (for example, the output of `xxd`).
- **Idle packet**: Fill data on APID 2047 (`0x7FF`), sent to keep a link busy
  and skipped in continuity checks.
- **Length-prefixed**: A variable-length field preceded immediately by an
  integer stating how many bytes follow.
- **Little-endian**: Byte order with the least significant byte stored first.
- **Magic bytes (magic string)**: A fixed sequence of bytes at the start of a
  file used to identify its format (such as `COSMOS4_` or `COSMOS5_`).
- **Offset (byte offset)**: A position in a file counted in bytes from byte `0`
  at the start of the file.
- **Payload**: The inner data carried inside a container entry (usually one
  space packet) or inside a space packet after its header.
- **Primary header**: The fixed 6-byte big-endian header at the start of every
  CCSDS space packet, carrying version, type, secondary-header flag, APID,
  sequence flags, sequence count, and data length.
- **Push parser (push decoder)**: A parser that does no I/O of its own; the
  caller feeds it buffered bytes and it returns parsed records, bytes consumed,
  "need more", or an error.
- **Resynchronisation (resync)**: Finding the next valid entry or frame
  boundary after corrupt bytes so decoding can continue.
- **Secondary header**: Mission-defined bytes immediately after the 6-byte
  primary header, usually starting with the packet's timestamp.
- **Sequence count**: A per-APID 14-bit counter (`0`–`16383`) incremented by
  the emitter for each packet. Its continuity is how lost, repeated, or mixed
  streams are found.
- **Space packet**: The CCSDS unit of application data: a 6-byte primary
  header, an optional secondary header, then data.
- **Sync marker**: The fixed 4-byte pattern `1A CF FC 1D` that marks the start
  of a telemetry transfer frame.
- **Timescale**: A system for counting time (such as UTC, or an atomic
  timescale with no leap seconds).
- **Transfer frame**: A fixed-size link-layer block that carries packets over a
  space link. One frame can hold several packets or part of one.
- **Truncation (truncated tail)**: A file ending partway through an entry,
  common when a logger crashes or a file is copied while still being written.
- **UTC**: Coordinated Universal Time, the civil time standard used as the
  reference for timestamps in this tool.
- **Virtual channel**: A numbered sub-stream within transfer frames, used to
  separate kinds of traffic on one link.
