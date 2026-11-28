# Architecture

Functional core, imperative shell.

```
src/pure/    the core: values in, values out
src/shell/   the shell: files, sockets, database, clock, terminal
src/main.rs  hands the arguments to the shell
web/         the browser UI, embedded into the binary at build time
```

## The rule

Code under `src/pure/` does no I/O of any kind: no files, network, clock,
randomness, environment, processes, threads, database handles or printing.
`tests/purity.rs` fails the build if a core file names one of those APIs.

Pure crates that only transform values (`regex`, `serde`, `serde_json`,
`toml`) may be used in the core. `rusqlite` may not.

The shell contains no rules. Whenever it has to decide something, it gathers
the facts and asks the core.

## How each feature is split

| Feature | Core decides | Shell does |
|---|---|---|
| Reading logs | `decode`: push decoders take bytes and return records, bytes used, "need more" or an error | `files`: opens read-only, owns the read loop and buffer |
| Text logs | `textlog`: lines in, timestamped entries out | reads lines |
| Checks | `continuity`, `order`, `limits`, `cross`: packets or stored counts in, findings out, all as one type (`finding`) with a fixed list of kinds; `pipeline` runs the per-file ones; `cross` also says what a run's packets in checksum order come to, one checksum at a time | prints or stores them; `cross` merges the segments' checksum sections with bounded fan-in and keeps what must be given back later in temporary files |
| Naming and decoding packets | `config`, `format`: definitions plus bytes give named values | reads the config file, reads packet bytes back from the log |
| Store | `sql`: schema text, statements and their parameters; `ingest`: records to rows; `oracle`: for tests only, the tables of packets the store used to keep and the statements it ran over them | `store`: owns the connection, runs statements; `vtab`: serves the tables `packets` and `field_values` from the segment files |
| Segment files | `segment`: record and directory layouts, the bucket grids and which levels are kept, how a density view or a plot is put together from stored buckets and single values | `segment`: writes a file's packets and kept values beside the store as it is read (sorting in bounded chunks), reads them back with positioned reads, merges item lists across files; `store` lists them in the `segments` table, and what each holds of each lane in `segment_lanes` |
| Web API | `http`: bytes to request, response to bytes; `api`: request to an authorised command, results to JSON | `server`: owns the socket, runs the command against the store |
| File browser | `paths`: is this canonical path inside the allowed roots | canonicalises paths, lists directories |
| Access token | compares tokens | supplies the random bytes |
| Time | `time`: calendar arithmetic, parsing, packet time codes | supplies "now" when a timestamp of the present is needed |

## Where things are stored

Each packet file's packets and kept values are written to a segment file of
their own, in a folder beside the SQLite file (`<store>.seg/`), listed in
the store's `segments` table; SQLite holds no packet rows. Read from the
segments: the timeline's density, its item list, plots of kept fields and
arrival delay, a packet's details (with its file and source from SQLite),
the packet times of a run's findings, at the end of an ingest the
comparison of sources (each segment's packets in checksum order, merged),
and the tables `packets` and `field_values` that SQL sees. Read from
SQLite: runs, files, lanes, findings, text logs and the list of what can
be plotted (`file_series`). A lane's count and time ranges are added up
from `segment_lanes`, written with each file; the next packet id is one
more than the highest any segment holds.

`packets` and `field_values` are eponymous-only virtual tables
(`shell::vtab`), registered on every connection the store opens, with the
columns the SQLite tables of those names had. Nothing about them is in
the database file, so a stock `sqlite3` opens it and sees every other
table, but not these two. The store reads the `segments` rows inside the
read transaction a statement runs in and hands them to the tables, so a
statement reads the segments listed when it started; if one of them was
replaced meanwhile, the statement is run once more on a fresh list. A
page's reads of the segment files do the same, with all their SQL in one
read transaction. Constraints only ever skip what cannot match, and
SQLite checks every row it gets; `packets` is read in id order or in
order of a time clock (from the time-order sections), either way up,
`field_values` in packet order, or for a field in order of number (from
the value-order section, merged across series and segments), and a
field's narrow range of numbers is gathered from there and handed out in
packet order. A count of every packet or every value reads no record. The
time limit of a read-only connection is checked inside those reads,
where SQLite's own progress handler does not run.

A segment's sorted sections (time orders, kept numbers by lane and
series, checksums, values by series and number) are written through
bounded sorters (`shell::segment::Sorter`): what arrives after everything
written so far extends one long run in a file of its own, the rest
extends or starts other runs, and runs are merged with a heap, the run
with the lowest record handing out everything up to the next run's head
at once. Input in order costs one write and one read of the section;
grouped input (kept numbers arrive interleaved by lane and series, each
group in time order) costs a heap step per group per run, not per record;
only real disorder (checksums) pays a full merge. Bucket levels are sized
as the values come in order, and each coarser level is counted from the
one before it rather than from the packets again.

The format is described in `src/pure/segment.rs`. A store from a build
before schema 7 is refused, and a segment of a format version other than
this build's fails to read: ingest such a store again.

Each file read commits on its own, and the end of an ingest (lane totals,
the comparison of sources) commits after them. A run whose end did not
commit is listed in `unfinished`, and its next ingest does that end
again even if no file has changed.

The tests open stores with `Store::open_with_oracle`, which also writes
the rows the old `packets` and `field_values` tables held to
`oracle_packets` and `oracle_field_values`, and check the segment files,
and the same SQL over the virtual tables, against them.

## Decoders

A decoder implements `pure::decode::Decoder`:

```rust
fn step(&mut self, buf: &[u8], offset: u64) -> Step;
```

`buf` starts at the first unconsumed byte and `offset` is that byte's position
in the file. The answer is one of `Record { consumed, record }`,
`Skip { consumed }`, `NeedMore` or `Fatal(error)`. A decoder may keep state
between calls (name tables, "header seen"), never panics, never returns
`consumed == 0`, and treats any entry larger than `MAX_ENTRY` as `Fatal`.

`pure::decode::decode_all` runs a decoder over an in-memory buffer for tests.
`shell::files::Records` runs one over a file.

## Testing

- Core code is tested with plain values, no temp files and no mocks.
- All test data is generated by `pure::synth`. No real logs in the repository.
- Each decoder has: one hand-computed byte vector, a cut-at-every-offset test,
  and a noise test that must not panic.
- Shell code is tested against real temp files, a real SQLite file and real
  sockets on loopback.
