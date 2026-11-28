//! Reading a file of an ingest without the store: hashing it, telling what
//! it holds and, for packets, checking them and writing its segment with
//! the file's own lane numbers. What the store must add (ids, rows) is left
//! for the step that commits the file (`shell::store`). Files are read so
//! on several threads at once; see [`run`].

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::time::Instant;

use crate::pure::config::Config;
use crate::pure::decode::{Format, decoder_for};
use crate::pure::finding::FileFinding;
use crate::pure::ingest::LaneKey;
use crate::pure::ingest::PacketRow;
use crate::pure::pipeline::{FileCheck, KeptValue, Seen};
use crate::pure::segment as layout;
use crate::shell::files::{Hashing, ReadError, Records, open_sniffed};
use crate::shell::segment::{self, Ids, Writer, Written};
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
    hook: Option<&Hook>,
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
    let writer = Writer::start(folder, stem, chunk_bytes)?;
    let mut check = FileCheck::new(config, &source);
    let mut lanes = OwnLanes::default();
    let mut series: layout::Map<(u32, &'a str, &'a str), i64> = layout::Map::default();
    let mut end = None;
    let mut records = Records::new(BufReader::new(&mut file), decoder);
    // Records are decoded and checked on this thread, and written to the
    // segment on another, a batch at a time.
    let (batches, to_write) = mpsc::sync_channel::<Vec<Item<'a>>>(BATCHES_AHEAD);
    let (writer, read) = std::thread::scope(|scope| {
        let rel = job.rel.as_str();
        let writing = scope.spawn(move || write_batches(writer, to_write, rel, hook));
        let read = (|| -> Result<()> {
            let mut batch = Vec::with_capacity(BATCH);
            let mut seen = 0u64;
            // Labels numbered as they first come, as the segment numbers
            // them, so that each is copied once.
            let mut labels: layout::Map<String, u32> = layout::Map::default();
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
                if seen == 1
                    && let Some(hook) = hook
                {
                    hook(&job.rel, Stage::Decoding);
                }
                let lane = lanes.number(row.lane())?;
                for v in &values {
                    if v.num.is_some() {
                        *series.entry((lane, v.packet, v.field)).or_default() += 1;
                    }
                }
                let (label, new_label) = match record.label {
                    None => (None, None),
                    Some(text) => match labels.get(text.as_str()) {
                        Some(&n) => (Some(n), None),
                        None => {
                            let n = u32::try_from(labels.len())
                                .map_err(|_| "too many labels for a segment")?;
                            labels.insert(text.clone(), n);
                            (Some(n), Some(text))
                        }
                    },
                };
                batch.push(Item {
                    lane,
                    row,
                    label,
                    new_label,
                    values,
                });
                if batch.len() >= BATCH {
                    let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
                    // The writing thread stopped: it says why below.
                    if batches.send(full).is_err() {
                        return Ok(());
                    }
                }
            }
            let _ = batches.send(batch);
            Ok(())
        })();
        drop(batches);
        let writer = writing
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
        (writer, read)
    });
    // What went wrong writing comes first: it may be why reading stopped.
    let writer = writer?;
    read?;
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

/// Records decoded and checked, handed to the thread writing them to the
/// segment this many at a time, at most [`BATCHES_AHEAD`] batches ahead.
const BATCH: usize = 512;
const BATCHES_AHEAD: usize = 2;

/// A record as the thread writing the segment gets it: its label by
/// number, with the label itself the first time.
struct Item<'a> {
    lane: u32,
    row: PacketRow,
    label: Option<u32>,
    new_label: Option<String>,
    values: Vec<KeptValue<'a>>,
}

/// Writes batches of records to a segment until there are no more, and
/// hands the writer back.
fn write_batches(
    mut writer: Writer,
    batches: mpsc::Receiver<Vec<Item<'_>>>,
    rel: &str,
    hook: Option<&Hook>,
) -> Result<Writer> {
    for (n, batch) in batches.into_iter().enumerate() {
        if n == 0
            && let Some(hook) = hook
        {
            hook(rel, Stage::Writing);
        }
        for item in batch {
            if let Some(text) = item.new_label {
                writer.add_label(text)?;
            }
            writer.push_numbered(i64::from(item.lane), &item.row, item.label)?;
            for v in item.values {
                writer.push_value(v.packet, v.field, v.num, v.text.as_deref())?;
            }
        }
    }
    Ok(writer)
}

/// A name for the temporary files of the writer of job `job`, unique to
/// this process and this ingest: `ingest-<process>-<ingest>-<job>`.
pub fn stem(job: usize) -> String {
    use std::sync::atomic::AtomicU64;
    static INGESTS: AtomicU64 = AtomicU64::new(0);
    let n = INGESTS.fetch_add(1, Ordering::Relaxed);
    format!("ingest-{}-{n}-{job}", std::process::id())
}

// ---- reading files in parallel ---------------------------------------------------

/// Most threads reading files at once, whatever the setting.
pub const MAX_WORKERS: usize = 64;
/// Threads reading files unless `PACKETLANE_INGEST_THREADS` says otherwise
/// (and never more than the machine has cores).
pub const DEFAULT_WORKERS: usize = 4;
/// What the sorters of all the threads hold together, at most: each
/// thread's six sorters share an equal part, at most
/// [`segment::CHUNK_BYTES`] each and at least [`MIN_CHUNK_BYTES`].
pub const SORT_BUDGET: usize = 12 << 20;
pub const MIN_CHUNK_BYTES: usize = 256 << 10;

/// How many threads read files, and what each sorter holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub workers: usize,
    pub chunk_bytes: usize,
}

impl Settings {
    /// `workers` threads (at most [`MAX_WORKERS`]), their sorters sharing
    /// [`SORT_BUDGET`]; none reads every file on the calling thread.
    pub fn with_workers(workers: usize) -> Settings {
        let workers = workers.min(MAX_WORKERS);
        let chunk_bytes =
            (SORT_BUDGET / (6 * workers.max(1))).clamp(MIN_CHUNK_BYTES, segment::CHUNK_BYTES);
        Settings {
            workers,
            chunk_bytes,
        }
    }

    /// As the environment variable `PACKETLANE_INGEST_THREADS` says (0 to
    /// [`MAX_WORKERS`]; 0 reads every file on the calling thread), else
    /// [`DEFAULT_WORKERS`] or as many as the machine has cores, if fewer.
    pub fn from_env() -> Settings {
        let set = std::env::var("PACKETLANE_INGEST_THREADS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|n| *n <= MAX_WORKERS);
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        Settings::with_workers(set.unwrap_or(DEFAULT_WORKERS.min(cores)))
    }

    /// Files read ahead of the one being stored, at most: each holds its
    /// findings and a finished segment until its turn.
    pub fn window(&self) -> usize {
        2 * self.workers + 2
    }
}

/// Where a reading thread is with a file, as a [`Hook`] is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Its first record decoded and checked, on the thread that reads it.
    Decoding,
    /// Its first records taken, on the thread that writes them to the
    /// segment.
    Writing,
    /// Read, its segment written as far as it can be without ids.
    Read,
    /// About to finish its segment, the ids given.
    Finish,
}

/// Called by a reading thread with a file's path in its run as it passes
/// each [`Stage`]: for tests, to delay a file or make it fail there.
pub type Hook = Arc<dyn Fn(&str, Stage) + Send + Sync>;

/// What the step that stores files does with what the threads read. Both
/// are called in the order of the jobs, on the thread that called [`run`].
pub trait Commit<'a> {
    /// The ids a packet file is foreseen to get, if it is stored when its
    /// turn comes; `None` for any other file. Takes into account what
    /// every earlier job is foreseen to do to the store.
    fn foresee(&mut self, job: usize, read: &Read<'a>) -> Option<Ids>;

    /// Stores a job: what was read, and for a packet file the ids its
    /// segment was finished with and how that went.
    fn store(&mut self, job: usize, read: Read<'a>, finished: Option<Finished>) -> Result<Flow>;
}

/// How a packet file's segment was finished: with these ids, and either
/// written (`None` if the file had no packets) or failed.
pub type Finished = (Ids, std::result::Result<Option<Written>, String>);

/// What comes after a stored job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    /// The job was stored with other ids than foreseen: what was foreseen
    /// for later jobs no longer holds, and they are read again.
    Again,
}

/// Hands jobs out in order, no further ahead of the one being stored than
/// the window allows, until stopped.
struct Gate {
    state: Mutex<(usize, usize)>,
    turn: Condvar,
    stopping: AtomicBool,
}

impl Gate {
    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, usize)> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next job, once the window reaches it; `None` once there are no
    /// more or the gate is stopped.
    fn claim(&self, end: usize) -> Option<usize> {
        let mut state = self.lock();
        loop {
            let (next, limit) = *state;
            if self.stopping.load(Ordering::Relaxed) || next >= end {
                return None;
            }
            if next < limit {
                state.0 += 1;
                return Some(next);
            }
            state = self
                .turn
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn open_to(&self, limit: usize) {
        self.lock().1 = limit;
        self.turn.notify_all();
    }

    fn stop(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        let _held = self.lock();
        self.turn.notify_all();
    }
}

/// Stops the gate when dropped, however the step that stores files ends.
struct StopOnDrop<'g>(&'g Gate);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

enum Event<'a> {
    /// A file read; a packet file's thread waits on `reply` for its ids.
    Read {
        job: usize,
        read: Read<'a>,
        reply: Option<mpsc::Sender<Ids>>,
    },
    Finished {
        job: usize,
        finished: Finished,
    },
}

/// What the step that stores files holds of jobs not yet stored.
#[derive(Default)]
struct Board<'a> {
    read: BTreeMap<usize, (Read<'a>, Option<mpsc::Sender<Ids>>)>,
    /// Foreseen, with whether a finished segment is still to come.
    ready: BTreeMap<usize, (Read<'a>, bool)>,
    finished: BTreeMap<usize, Finished>,
}

impl Board<'_> {
    /// Removes the segments finished for jobs that were not stored.
    fn discard(&mut self, folder: &Path) {
        for (_, (_, result)) in std::mem::take(&mut self.finished) {
            if let Ok(Some(w)) = result {
                let _ = segment::remove(folder, &w.name);
            }
        }
    }
}

/// The text of a panic's payload.
fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    let text = payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_string());
    format!("Reading the file failed unexpectedly: {text}")
}

/// Runs `f`, its error or panic as text.
pub fn caught<T>(f: impl FnOnce() -> Result<T>) -> std::result::Result<T, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.to_string()),
        Err(payload) => Err(panic_text(payload)),
    }
}

/// What a reading thread needs, shared by all of them.
struct Shared<'s, 'a> {
    jobs: &'s [Job],
    config: &'a Config,
    folder: &'s Path,
    settings: Settings,
    hook: Option<&'s Hook>,
    gate: &'s Gate,
}

/// A reading thread: takes jobs in turn, reads each, and for a packet file
/// waits for its ids and finishes its segment; with `PACKETLANE_TIMING`
/// set, says how long each part took. An error or a panic is the
/// job's failure; the thread goes on with the next.
fn work<'a>(shared: &Shared<'_, 'a>, events: mpsc::Sender<Event<'a>>) {
    let Shared {
        jobs,
        config,
        folder,
        settings,
        hook,
        gate,
    } = shared;
    let timing = std::env::var_os("PACKETLANE_TIMING").is_some();
    while let Some(job) = gate.claim(jobs.len()) {
        let j = &jobs[job];
        let started = Instant::now();
        let read = caught(|| {
            let stem = stem(job);
            let read = read_file(
                j,
                config,
                folder,
                &stem,
                settings.chunk_bytes,
                &gate.stopping,
                *hook,
            )?;
            if let Some(hook) = hook {
                hook(&j.rel, Stage::Read);
            }
            Ok(read)
        });
        let (read, writer) = read.unwrap_or_else(|e| (Read::Failed(e), None));
        let Some(writer) = writer else {
            let event = Event::Read {
                job,
                read,
                reply: None,
            };
            if events.send(event).is_err() {
                return;
            }
            continue;
        };
        let read_in = started.elapsed();
        let (reply, ids) = mpsc::channel();
        let event = Event::Read {
            job,
            read,
            reply: Some(reply),
        };
        if events.send(event).is_err() {
            return;
        }
        // No ids: the ingest is stopping, and the writer's files go with it.
        let Ok(ids) = ids.recv() else {
            continue;
        };
        let waited = started.elapsed() - read_in;
        let result = caught(|| {
            if let Some(hook) = hook {
                hook(&j.rel, Stage::Finish);
            }
            writer.finish_with(&ids)
        });
        if timing {
            let finished = started.elapsed() - read_in - waited;
            eprintln!(
                "  file {}: read {:.2} s, waited {:.2} s, finished {:.2} s",
                j.rel,
                read_in.as_secs_f64(),
                waited.as_secs_f64(),
                finished.as_secs_f64()
            );
        }
        let event = Event::Finished {
            job,
            finished: (ids, result),
        };
        if let Err(mpsc::SendError(Event::Finished { finished, .. })) = events.send(event) {
            if let (_, Ok(Some(w))) = finished {
                let _ = segment::remove(folder, &w.name);
            }
            return;
        }
    }
}

/// Reads `jobs[from..]` on `settings.workers` threads and stores them in
/// order through `commit`. Returns where to start again if a job was
/// stored with other ids than foreseen ([`Flow::Again`]): every job
/// before that is stored; nothing of the jobs after it is.
pub fn run<'a>(
    jobs: &[Job],
    from: usize,
    settings: Settings,
    config: &'a Config,
    folder: &Path,
    hook: Option<&Hook>,
    commit: &mut dyn Commit<'a>,
) -> Result<Option<usize>> {
    let gate = Gate {
        state: Mutex::new((from, from + settings.window())),
        turn: Condvar::new(),
        stopping: AtomicBool::new(false),
    };
    let shared = Shared {
        jobs,
        config,
        folder,
        settings,
        hook,
        gate: &gate,
    };
    std::thread::scope(|scope| {
        let (sender, events) = mpsc::channel();
        for _ in 0..settings.workers.min(jobs.len() - from.min(jobs.len())) {
            let sender = sender.clone();
            let shared = &shared;
            scope.spawn(move || work(shared, sender));
        }
        drop(sender);
        let mut board = Board::default();
        let result = {
            let _stop = StopOnDrop(&gate);
            coordinate(
                jobs.len(),
                from,
                settings,
                &gate,
                &events,
                &mut board,
                commit,
            )
        };
        // Threads waiting for ids are let go, and what is still being
        // read or finished is waited for and thrown away.
        board.read.clear();
        board.discard(folder);
        for event in events.iter() {
            if let Event::Finished {
                finished: (_, Ok(Some(w))),
                ..
            } = event
            {
                let _ = segment::remove(folder, &w.name);
            }
        }
        result
    })
}

/// The step that stores files: foresees each file's ids as soon as it and
/// every file before it have been read, and stores each once it and every
/// file before it are done.
fn coordinate<'a>(
    end: usize,
    from: usize,
    settings: Settings,
    gate: &Gate,
    events: &mpsc::Receiver<Event<'a>>,
    board: &mut Board<'a>,
    commit: &mut dyn Commit<'a>,
) -> Result<Option<usize>> {
    let (mut foreseen, mut stored) = (from, from);
    while stored < end {
        loop {
            let mut moved = false;
            while let Some((read, reply)) = board.read.remove(&foreseen) {
                // A thread let go without ids drops its writer; a thread
                // that is gone has its job fail when stored.
                let ids = commit.foresee(foreseen, &read);
                let waits = match (reply, ids) {
                    (Some(reply), Some(ids)) => reply.send(ids).is_ok(),
                    _ => false,
                };
                board.ready.insert(foreseen, (read, waits));
                foreseen += 1;
                moved = true;
            }
            if let Some(&(_, waits)) = board.ready.get(&stored)
                && (!waits || board.finished.contains_key(&stored))
                && let Some((read, _)) = board.ready.remove(&stored)
            {
                let finished = board.finished.remove(&stored);
                if commit.store(stored, read, finished)? == Flow::Again {
                    return Ok(Some(stored + 1));
                }
                stored += 1;
                gate.open_to(stored + settings.window());
                moved = true;
            }
            if !moved || stored >= end {
                break;
            }
        }
        if stored >= end {
            break;
        }
        match events.recv() {
            Ok(Event::Read { job, read, reply }) => {
                board.read.insert(job, (read, reply));
            }
            Ok(Event::Finished { job, finished }) => {
                board.finished.insert(job, finished);
            }
            Err(_) => return Err("the threads reading files stopped".into()),
        }
    }
    Ok(None)
}
