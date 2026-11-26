//! What every decoder must do with damaged input, checked by feeding each
//! one thousands of cut, flipped, spliced and random files.
//!
//! The rules come from the `Decoder` trait: never panic, never report zero
//! bytes consumed or more than it was given, and never make up data. Two
//! more follow from how the shell uses decoders:
//!
//! - **Reading in pieces changes nothing.** The shell hands a decoder
//!   whatever it has read so far. The records must not depend on where the
//!   reads happened to end.
//! - **A cut file is the start of the whole one.** What is read from a file
//!   cut short must be the first records of what is read from all of it.
//!
//! Inputs are made here from a fixed seed, so a failure repeats. Each
//! failure names its case; `one_case` at the bottom reruns a single one.

use std::panic::{AssertUnwindSafe, catch_unwind};

use packetlane::pure::config::Config;
use packetlane::pure::decode::{
    DecodeEnd, Decoder, Format, MAX_ENTRY, Notices, Record, Step, decoder_for, sniff,
};
use packetlane::pure::synth::{
    Cosmos5Writer, Source, TcFrame, cltu, cosmos_cmd, cosmos_tlm, cosmos2_entry, cosmos2_header,
    cosmos4_entry, cosmos4_header, demo_cadus, demo_run, system_meta, tc_packet, tc_segments,
};

/// A small repeatable random number generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number below `n`, or 0 if `n` is 0.
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// One sound file and what reads it.
struct Sample {
    name: &'static str,
    data: Vec<u8>,
    config: Config,
    format: Format,
}

impl Sample {
    fn new(name: &'static str, data: Vec<u8>, config: &str) -> Sample {
        let config = Config::parse(config).unwrap();
        let format = sniff(&data);
        assert!(
            decoder_for(format, &config).is_some(),
            "{name}: sniffed as {}, which has no decoder",
            format.name()
        );
        Sample {
            name,
            data,
            config,
            format,
        }
    }

    fn decoder(&self) -> Box<dyn Decoder> {
        decoder_for(self.format, &self.config).unwrap()
    }
}

fn packets(count: usize) -> Vec<u8> {
    let mut a = Source::new(0x064, 16380, 9);
    let mut b = Source::new(0x1A3, 0, 40);
    (0..count)
        .flat_map(|i| if i % 3 == 0 { a.emit() } else { b.emit() })
        .collect()
}

fn samples() -> Vec<Sample> {
    let t0 = 1_767_225_600_000_000_000i64;
    let config_name = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
    let mut out = vec![Sample::new("raw", packets(40), "")];

    let mut cosmos2 = cosmos2_header(true, config_name, "GSE-PC");
    let mut cosmos4 = cosmos4_header(true, config_name, "GSE-PC");
    let mut writer = Cosmos5Writer::like_cosmos(3);
    let mut cosmos5 = Cosmos5Writer::magic();
    let meta = system_meta(config_name, "4.2.4");
    cosmos2.extend(cosmos2_entry(t0, "SYSTEM", "META", &meta));
    cosmos4.extend(cosmos4_entry(t0, "SYSTEM", "META", &meta));
    for i in 0..30u16 {
        let t = t0 + i64::from(i) * 100_000_000;
        let tlm = cosmos_tlm(2, i + 1, t, 1, &[i as u8; 20]);
        let cmd = cosmos_cmd(999, 0, 2, &[1, 2, 3]);
        cosmos2.extend(cosmos2_entry(t, "INST", "ADCS", &tlm));
        cosmos4.extend(cosmos4_entry(t, "INST", "ADCS", &tlm));
        cosmos5.extend(writer.entry(t, "INST", "ADCS", &tlm, false));
        if i % 7 == 0 {
            cosmos2.extend(cosmos2_entry(t, "INST", "ABORT", &cmd));
            cosmos4.extend(cosmos4_entry(t, "INST", "ABORT", &cmd));
            cosmos5.extend(writer.entry(t, "INST", "ABORT", &cmd, true));
        }
    }
    cosmos5.extend(Cosmos5Writer::offset_marker("1767225600000-0"));
    out.push(Sample::new("cosmos2", cosmos2, ""));
    out.push(Sample::new("cosmos4", cosmos4, ""));
    out.push(Sample::new("cosmos5", cosmos5, ""));

    // Frames: plain TM; TM with a CRC, still randomised; AOS with a CRC.
    for (name, len, config) in [
        ("cadu-tm", 64, ""),
        (
            "cadu-tm-crc-random",
            96,
            "[frames]\ncrc = true\nrandomized = true",
        ),
        ("cadu-aos-crc", 128, "[frames]\nkind = \"aos\"\ncrc = true"),
    ] {
        let params = Config::parse(config).unwrap().frame_params(len);
        out.push(Sample::new(name, demo_cadus(&params, &packets(60)), config));
    }

    // Frames with Reed-Solomon check symbols, randomised, with a CRC.
    let coded = "[frames]\nrandomized = true\ncrc = true\nrs_parity_bytes = 32\nrs_correct = true";
    let params = Config::parse(coded).unwrap().frame_params(256);
    out.push(Sample::new(
        "cadu-rs",
        demo_cadus(&params, &packets(60)),
        coded,
    ));

    // Telecommands: CLTUs plain and randomised, and frames back to back.
    // Each has control frames, whole commands, and one cut into segments.
    let commands: Vec<Vec<u8>> = (0..8u16)
        .map(|i| tc_packet(0x0C8 + i % 2, i / 2, &vec![i as u8; 3 + usize::from(i) * 5]))
        .collect();
    let long = tc_packet(0x0CA, 0, &[0xA5; 300]);
    let mut frames: Vec<Vec<u8>> = vec![
        TcFrame::bc(0x155, 1).build(&[0x00], true),
        TcFrame::bc(0x155, 1).build(&[0x82, 0x00, 10], true),
    ];
    let mut n = 9u8;
    let mut data: Vec<Vec<u8>> = Vec::new();
    for (i, command) in commands.iter().enumerate() {
        data.push(tc_segments(2, command, 1000).remove(0));
        if i == 3 {
            data.extend(tc_segments(7, &long, 80));
        }
    }
    for field in &data {
        n = n.wrapping_add(1);
        frames.push(TcFrame::ad(0x155, 1, n).build(field, true));
    }
    frames.push(TcFrame::bd(0x155, 1, 0).build(&tc_segments(2, &commands[0], 1000)[0], true));
    for (name, randomized) in [("cltu", false), ("cltu-random", true)] {
        let mut file = vec![0x55u8; 16];
        for frame in &frames {
            file.extend(cltu(frame, randomized));
        }
        out.push(Sample::new(name, file, ""));
    }
    out.push(Sample::new("tc-frames", frames.concat(), ""));

    // And what `packetlane demo` writes, which is what a new user reads first.
    for file in demo_run(3) {
        if file.rel.ends_with(".bin") {
            out.push(Sample::new(
                file.rel,
                file.bytes,
                packetlane::pure::synth::DEMO_CONFIG,
            ));
        }
    }
    out
}

/// What came of reading one input.
#[derive(Debug, PartialEq)]
struct Outcome {
    records: Vec<Record>,
    notices: Notices,
    end: Option<DecodeEnd>,
}

/// Feeds `data` to a decoder as the shell does, `chunk` more bytes each time
/// it asks, and checks every step against the trait's rules.
fn drive(mut decoder: Box<dyn Decoder>, data: &[u8], chunk: usize) -> Result<Outcome, String> {
    let mut out = Outcome {
        records: Vec::new(),
        notices: Notices::default(),
        end: None,
    };
    let (mut pos, mut have) = (0usize, chunk.min(data.len()));
    let mut carried = 0usize;
    loop {
        let buf = &data[pos..have];
        let used = match decoder.step(buf, pos as u64) {
            Step::Record { consumed, record } => {
                if record.offset > data.len() as u64 {
                    return Err(format!(
                        "record at byte {}, past the end ({})",
                        record.offset,
                        data.len()
                    ));
                }
                carried += record.payload.len();
                out.records.push(record);
                consumed
            }
            Step::Skip { consumed } => consumed,
            Step::Lost { consumed, notice } => {
                out.notices.push(notice);
                consumed
            }
            Step::NeedMore => {
                if have == data.len() {
                    out.end = (pos < have).then_some(DecodeEnd::Truncated {
                        offset: pos as u64,
                        available: have - pos,
                    });
                    break;
                }
                if buf.len() > MAX_ENTRY {
                    return Err(format!("asked for more than {MAX_ENTRY} bytes at {pos}"));
                }
                have = (have + chunk).min(data.len());
                continue;
            }
            Step::Fatal(e) => {
                out.end = Some(DecodeEnd::Error(e));
                break;
            }
        };
        if used == 0 || used > buf.len() {
            return Err(format!(
                "consumed {used} of {} bytes at byte {pos}",
                buf.len()
            ));
        }
        pos += used;
    }
    if carried > data.len() {
        return Err(format!(
            "{carried} bytes of records from a {}-byte input",
            data.len()
        ));
    }
    Ok(out)
}

/// Reads one input whole and in pieces of several sizes, and checks that
/// the answer is the same each time. A panic is reported, not propagated.
fn read(sample: &Sample, data: &[u8]) -> Result<Outcome, String> {
    read_in(sample, data, &[1, 7, 61, 1024])
}

/// [`read`], with the piece sizes to try.
fn read_in(sample: &Sample, data: &[u8], chunks: &[usize]) -> Result<Outcome, String> {
    catch_unwind(AssertUnwindSafe(|| {
        let whole = drive(sample.decoder(), data, usize::MAX)?;
        for &chunk in chunks {
            let pieces = drive(sample.decoder(), data, chunk)?;
            if pieces.records != whole.records {
                let at = (0..)
                    .find(|&i| pieces.records.get(i) != whole.records.get(i))
                    .unwrap();
                return Err(format!(
                    "read {chunk} bytes at a time gives {} records, whole gives {}; \
                     they differ from record {at}",
                    pieces.records.len(),
                    whole.records.len()
                ));
            }
            if pieces.end != whole.end {
                return Err(format!(
                    "read {chunk} bytes at a time ends with {:?}, whole with {:?}",
                    pieces.end, whole.end
                ));
            }
            if pieces.notices != whole.notices {
                return Err(format!(
                    "read {chunk} bytes at a time notes {:?}, whole notes {:?}",
                    pieces.notices, whole.notices
                ));
            }
        }
        // Sniffing sees damaged files before any decoder does.
        let guessed = sniff(data);
        if let Some(decoder) = decoder_for(guessed, &sample.config) {
            drive(decoder, data, usize::MAX)?;
        }
        Ok(whole)
    }))
    .unwrap_or_else(|panic| {
        let text = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        Err(format!("panicked: {text}"))
    })
}

/// The damaged version of `data` that `case` names. The same case number
/// always gives the same bytes.
fn damage(data: &[u8], other: &[u8], case: u64) -> Vec<u8> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (case + 1).wrapping_mul(0xD6E8_FEB8_6659_FD93));
    let mut out = data.to_vec();
    for _ in 0..1 + rng.below(3) {
        let at = rng.below(out.len());
        match rng.below(8) {
            // One bit, as a bad link or disk would do.
            0 | 1 => {
                if let Some(b) = out.get_mut(at) {
                    *b ^= 1 << rng.below(8);
                }
            }
            // A byte set to a value length fields find awkward.
            2 => {
                if let Some(b) = out.get_mut(at) {
                    *b = [0x00, 0xFF, 0x7F, 0x80][rng.below(4)];
                }
            }
            // A run overwritten with noise.
            3 => {
                let n = rng.below(24).min(out.len() - at.min(out.len()));
                let noise = rng.bytes(n);
                out[at..at + n].copy_from_slice(&noise);
            }
            // Bytes missing.
            4 => {
                let n = rng.below(40).min(out.len() - at.min(out.len()));
                out.drain(at..at + n);
            }
            // Bytes that should not be there.
            5 => {
                let n = rng.below(40);
                let noise = rng.bytes(n);
                out.splice(at..at, noise);
            }
            // A piece of the file repeated.
            6 => {
                let from = rng.below(out.len());
                let n = rng.below(80).min(out.len() - from.min(out.len()));
                let piece = out[from..from + n].to_vec();
                out.splice(at..at, piece);
            }
            // The rest replaced by part of a file of another format.
            _ => {
                let from = rng.below(other.len());
                out.truncate(at);
                out.extend_from_slice(&other[from..]);
            }
        }
    }
    out
}

/// How many damaged versions of each sample are tried.
const CASES: u64 = 400;

#[test]
fn sound_files_read_the_same_whole_and_in_pieces() {
    for sample in samples() {
        let out = read(&sample, &sample.data).unwrap_or_else(|e| panic!("{}: {e}", sample.name));
        assert!(!out.records.is_empty(), "{}: no records", sample.name);
        assert_eq!(out.end, None, "{}", sample.name);
    }
}

#[test]
fn a_cut_file_reads_as_the_start_of_the_whole_one() {
    for sample in samples() {
        let whole = read(&sample, &sample.data).unwrap().records;
        // Every length for small files; for larger ones a spread of them,
        // and always the lengths around each record's edges.
        let len = sample.data.len();
        let mut cuts: Vec<usize> = (0..len).step_by(1 + len / 800).collect();
        for r in &whole {
            let at = r.offset as usize;
            cuts.extend([at.saturating_sub(1), at, at + 1, at + r.payload.len()]);
        }
        cuts.retain(|&c| c < len);
        cuts.sort_unstable();
        cuts.dedup();
        for cut in cuts {
            // One piece size here: the other tests try the rest, and this
            // one reads each file hundreds of times over.
            let got = read_in(&sample, &sample.data[..cut], &[61])
                .unwrap_or_else(|e| panic!("{} cut to {cut} bytes: {e}", sample.name));
            assert!(
                got.records.len() <= whole.len() && got.records == whole[..got.records.len()],
                "{} cut to {cut} bytes: its {} records are not the first of the whole file's {}",
                sample.name,
                got.records.len(),
                whole.len()
            );
            // The end of a cut file is where the data ran out, never a
            // complaint about bytes that are simply not there yet.
            assert!(
                !matches!(got.end, Some(DecodeEnd::Error(_))),
                "{} cut to {cut} bytes: {:?}",
                sample.name,
                got.end
            );
        }
    }
}

#[test]
fn damaged_files_are_read_without_breaking_the_rules() {
    let samples = samples();
    let mut failures = Vec::new();
    for (i, sample) in samples.iter().enumerate() {
        let other = &samples[(i + 3) % samples.len()].data;
        for case in 0..CASES {
            if let Err(e) = read(sample, &damage(&sample.data, other, case)) {
                failures.push(format!("{} case {case}: {e}", sample.name));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases failed; the first few:\n{}",
        failures.len(),
        samples.len() as u64 * CASES,
        failures[..failures.len().min(12)].join("\n")
    );
}

#[test]
fn noise_is_read_without_breaking_the_rules() {
    let samples = samples();
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    for round in 0..300 {
        let len = rng.below(3000);
        let noise = rng.bytes(len);
        for sample in &samples {
            // Pure noise, and noise behind a sound start, which gets past
            // the checks a decoder makes on a file's first bytes.
            let keep = rng.below(sample.data.len().min(400));
            let mut headed = sample.data[..keep].to_vec();
            headed.extend_from_slice(&noise);
            for (what, data) in [("noise", &noise), ("noise after a sound start", &headed)] {
                read(sample, data)
                    .unwrap_or_else(|e| panic!("{} round {round}, {what}: {e}", sample.name));
            }
        }
    }
}

/// Reruns one case from a failure message, to work on it:
/// `CASE=cadu-tm:17 cargo test --test robustness one_case -- --nocapture`
#[test]
fn one_case() {
    let Ok(spec) = std::env::var("CASE") else {
        return;
    };
    let (name, case) = spec.rsplit_once(':').expect("CASE=name:number");
    let case: u64 = case.parse().expect("CASE=name:number");
    let samples = samples();
    let i = samples
        .iter()
        .position(|s| s.name == name)
        .expect("no sample of that name");
    let other = &samples[(i + 3) % samples.len()].data;
    let data = damage(&samples[i].data, other, case);
    println!("{name} case {case}: {} bytes", data.len());
    match read(&samples[i], &data) {
        Ok(out) => println!(
            "ok: {} records, {} notices, end {:?}",
            out.records.len(),
            out.notices.list.len(),
            out.end
        ),
        Err(e) => panic!("{e}"),
    }
}
