//! Reading a file of an ingest without the store: hashing it, telling what
//! it holds and, for packets, checking them and writing its segment with
//! the file's own lane numbers. What the store must add (ids, rows) is left
//! for the step that commits the file (`shell::store`). Files are read so
//! on several threads at once; see [`run`].

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::pure::config::Config;
use crate::pure::decode::{Format, decoder_for};
use crate::pure::finding::FileFinding;
use crate::pure::ingest::LaneKey;
use crate::pure::pipeline::{FileCheck, Seen};
use crate::pure::segment as layout;
use crate::shell::files::{Hashing, ReadError, Records, open_sniffed};
use crate::shell::segment::Writer;
use crate::shell::store::Result;

/// How many records are read between looks at whether the ingest is
/// stopping.
const STOP_EVERY: u64 = 1 << 12;

/// One file of an ingest: where it is, its path within the run, and what
/// the store held for that path when the ingest began (id, size,
/// checksum).
#[derive(Debug, Clone)]
pub struct Job {
    pub path: PathBuf,
    pub rel: String,
    pub known: Option<(i64, i64, i64)>,
}

/// What reading a file came to.
pub enum Read<'a> {
    /// The same size and checksum as the store holds for it.
    Unchanged,
    /// Reading failed; the file is left as the store has it.
    Failed(String),
    /// Nothing to store: empty, or a format with no decoder.
    Nothing {
        format: Format,
        size: i64,
        checksum: i64,
    },
    /// A text log, read when it is committed.
    Text { size: i64, checksum: i64 },
    /// Packets, written to a segment that is not yet finished.
    Packets(Box<Packets<'a>>),
}

/// What a packet file's reading leaves for its commit.
pub struct Packets<'a> {
    pub format: Format,
    pub size: i64,
    pub checksum: i64,
    pub source: String,
    /// The file's lanes by its own number: those of its packets in the
    /// order it met them, then those only its findings name, in their
    /// order. The store gives them ids in that order.
    pub keys: Vec<LaneKey>,
    pub packets: u64,
    /// In the order they are stored; a packet is its index in the file.
    pub findings: Vec<FileFinding>,
    /// How many numbers were kept of each field of each lane (its own
    /// number), for the list of what the run has to plot.
    pub series: Vec<((u32, &'a str, &'a str), i64)>,
    /// What the file says about itself, then why reading stopped early.
    pub note: String,
    pub gzip: bool,
    /// Why the compressed data gave out, if it did.
    pub fault: Option<String>,
}

impl Read<'_> {
    /// The size and checksum read, if the file is to be stored.
    pub fn identity(&self) -> Option<(i64, i64)> {
        match self {
            Read::Unchanged | Read::Failed(_) => None,
            Read::Nothing { size, checksum, .. } | Read::Text { size, checksum } => {
                Some((*size, *checksum))
            }
            Read::Packets(p) => Some((p.size, p.checksum)),
        }
    }
}

/// Numbers a file's lanes in the order it meets them.
#[derive(Default)]
struct OwnLanes {
    known: layout::Map<LaneKey, u32>,
    keys: Vec<LaneKey>,
}

impl OwnLanes {
    fn number(&mut self, key: LaneKey) -> Result<u32> {
        if let Some(&n) = self.known.get(&key) {
            return Ok(n);
        }
        let n = u32::try_from(self.keys.len()).map_err(|_| "too many lanes in one file")?;
        self.known.insert(key, n);
        self.keys.push(key);
        Ok(n)
    }
}

/// Reads one file. A packet file's segment is written as far as it can be
/// without ids, by a writer whose temporary files are named from `stem`
/// and whose sorters hold `chunk_bytes` each; the writer is handed back
/// with what was read. Stops early, with an error, once `stop` is set.
pub fn read_file<'a>(
    job: &Job,
    config: &'a Config,
    folder: &Path,
    stem: &str,
    chunk_bytes: usize,
    stop: &AtomicBool,
) -> Result<(Read<'a>, Option<Writer>)> {
    let (checksum, size) = Hashing::new(File::open(&job.path)?).finish()?;
    let (checksum, size) = (checksum as i64, i64::try_from(size)?);
    if job
        .known
        .is_some_and(|(_, s, c)| (s, c) == (size, checksum))
    {
        return Ok((Read::Unchanged, None));
    }
    let (format, mut file) = open_sniffed(&job.path)?;
    if format == Format::Text {
        return Ok((Read::Text { size, checksum }, None));
    }
    let Some(decoder) = decoder_for(format, config) else {
        let nothing = Read::Nothing {
            format,
            size,
            checksum,
        };
        return Ok((nothing, None));
    };
    let source = config.source_for(&job.rel);
    let mut writer = Writer::start(folder, stem, chunk_bytes)?;
    let mut check = FileCheck::new(config, &source);
    let mut lanes = OwnLanes::default();
    let mut series: layout::Map<(u32, &'a str, &'a str), i64> = layout::Map::default();
    let mut end = None;
    let mut records = Records::new(BufReader::new(&mut file), decoder);
    let mut seen = 0u64;
    for item in &mut records {
        seen += 1;
        if seen.is_multiple_of(STOP_EVERY) && stop.load(Ordering::Relaxed) {
            return Err("the ingest stopped".into());
        }
        let record = match item {
            Ok(record) => record,
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(ReadError::Decode(e)) => {
                end = Some(e);
                break;
            }
        };
        let Seen { row, values } = check.observe(&record);
        let lane = lanes.number(row.lane())?;
        writer.push(i64::from(lane), &row, record.label.as_deref())?;
        for v in values {
            writer.push_value(v.packet, v.field, v.num, v.text.as_deref())?;
            if v.num.is_some() {
                *series.entry((lane, v.packet, v.field)).or_default() += 1;
            }
        }
    }
    let report = check.finish();
    let findings = report.findings(&records.notices(), end.as_ref());
    for finding in &findings {
        if let Some(key) = finding.lane {
            lanes.number(key)?;
        }
    }
    let note: Vec<String> = records
        .describe()
        .into_iter()
        .chain(end.map(|e| e.to_string()))
        .collect();
    drop(records);
    let packets = Packets {
        format,
        size,
        checksum,
        source: source.name,
        keys: lanes.keys,
        packets: report.records,
        findings,
        series: series.into_iter().collect(),
        note: note.join("; "),
        gzip: file.is_gzip(),
        fault: file.fault().map(str::to_string),
    };
    Ok((Read::Packets(Box::new(packets)), Some(writer)))
}

/// A name for the temporary files of the writer of job `job`, unique to
/// this process and this ingest: `ingest-<process>-<ingest>-<job>`.
pub fn stem(job: usize) -> String {
    use std::sync::atomic::AtomicU64;
    static INGESTS: AtomicU64 = AtomicU64::new(0);
    let n = INGESTS.fetch_add(1, Ordering::Relaxed);
    format!("ingest-{}-{n}-{job}", std::process::id())
}
