# packetlane

*Working name.* A read-only tool for making sense of CCSDS space packet logs
that were recorded on several machines: check them, load them into one
queryable table, and look at them on a timeline next to the text logs from the
same run.

The problem it exists for: something odd shows up in a packet stream on a
multi-host test setup, and finding out why means logging in to each machine,
hunting for the right log files, copying them somewhere, and running one-off
parsers over them. This tool turns that into "point it at a folder and read
the problems list".

## Try it

```
cargo build --release
./target/release/packetlane demo demo-run        # writes a generated three-host run
./target/release/packetlane serve demo-run       # ingests it, prints an address to open
```

The generated run has three faults built in: a
power cycle that resets a counter, three packets lost on the way to the ground
host, and a host whose clock runs fast. All names in it are invented.

## Principles

- **Read-only.** Input logs are opened read-only and never modified. The store
  lives elsewhere (your state folder by default). Work on copies, on a
  workstation, not on the machines under test.
- **Offline, one binary.** No network calls. The web UI is embedded in the
  binary and served on loopback only.
- **Generic.** The code knows public standards only. Everything mission
  specific (APID names, packet fields, hosts, log formats, time formats) is
  configuration that lives outside this repository.
- **Few dependencies.** Each one has to be reviewed wherever the tool is
  adopted, so each one has to earn its place.
- **Synthetic data only.** Tests and examples are generated. Real logs never
  go in this repository.
- **Functional core, imperative shell.** See `docs/architecture.md`.

## Commands

```
packetlane check <file>...              Report sequence-count problems per APID
packetlane ingest [options] <path>...   Ingest files or folders as one run
packetlane query [options] <sql>        Run one read-only SQL statement
packetlane serve [options] [path]...    Ingest paths and serve the timeline on loopback
packetlane demo <folder> [--seconds N]  Write a sample run to a new folder

  --db <file>       Store file (default: packetlane.db in your state folder)
  --config <file>   Config file (default: packetlane.toml in run folder, then user config)
  --root <folder>   Folder the file browser may show; repeatable (serve)
  --port <n>        Port to listen on (serve; default 8737, 0 for any free port)
```

`check` and `ingest` exit with 0 when clean, 1 when problems were found and 2
when they could not run, so they can gate a script.

## What it does

### Reading

- **Formats**, detected from the first bytes: bare packet streams, COSMOS 4
  packet logs (the `COSMOS2_` and `COSMOS4_` layouts, and the older COSMOS 1
  header), COSMOS 5 packet logs, files of CADUs (sync marker plus TM or AOS
  transfer frame), telecommand captures (CLTUs, or TC transfer frames back
  to back), and text logs. Site-specific formats are added as decoders
  (`docs/parsing.md`).
- **CADU files**: packets are reassembled from the frames, per virtual
  channel. Frame type, randomisation, frame CRC, and the Reed-Solomon code
  or the length of the check symbols are read from the file where its bytes
  show them; the `[frames]` table overrules or fills in the rest.
- **Reed-Solomon correction** of TM and AOS frames (CCSDS 131.0-B): RS(255,223)
  and RS(255,239), interleave depths 1, 2, 3, 4, 5 and 8, shortened codeblocks, dual-basis
  or conventional symbols. A frame is derandomised, corrected, and then held
  to its CRC if it has one. The code is taken from the file when one of the
  first frames is a clean codeword, so a recorder's zero-filled check symbols
  are skipped as before and not mistaken for a code. It has been tested
  against the standard's constants (typed in from memory, and cross-checked
  against their definitions) and against this tool's own encoder, not
  against a recorded downlink: see `docs/parsing.md`.
- **Telecommand captures** (CCSDS 231.0-B and 232.0-B): CLTUs are found by
  their start sequence, each BCH codeblock has a single wrong bit corrected,
  and fill is dropped by the frame's length. Packets are taken from the TC
  frames with or without segment headers, and segmented ones are put back
  together per MAP. Whether frames end in a CRC, carry segment headers or
  are randomised is read from the file where it shows; the `[tc]` table
  overrules. Frames logged without CLTUs around them are recognised only
  when their lengths chain and their CRCs pass or their data reads as whole
  packets.
- **Gzip files** are read as what they hold.
- **Text logs**: one configurable pattern per log type picks out the
  timestamp; lines without one stay attached to the entry above.
- Truncated files are read as far as they go, then reported, not rejected.
- Logged items that are not space packets are kept and shown in their own
  lane.
- A command in a log that names its items (the COSMOS formats) is taken as a
  packet even when its length field claims fewer bytes than the log recorded,
  and the file gets a note saying so. COSMOS fills that field from the
  command's definition, and the definition can be wrong.

### Checks

Per file, for every APID and packet type:

- lost packets, repeated packets, counter restarts, packets out of order;
- a stream whose sequence count is the same on every packet (three or more)
  is noted as not counting, and is not reported as repeats;
- **two emitters sharing one APID** (interleaved sequence counters);
- segmented packets whose segments do not come as first, continuation, last;
- packet time stepping backwards (a note, since replayed data does this);
- a field leaving the **limits** its definition gives it, once per excursion.

Per CADU file, what was given up to keep reading: frames missing from a
virtual channel's count, frames that fail their CRC, have more errors than
Reed-Solomon can correct or do not parse, and bytes outside any frame. How
many bytes Reed-Solomon corrected, in how many frames, is one note per file.
A corrected frame that then fails its CRC is dropped: the code can land on
the wrong codeword, and only the CRC can tell.

Per telecommand file: AD frames missing from a virtual channel's sequence
(N(S)), or sent again; frames that fail their CRC; codeblocks with more than
one wrong bit; segments that do not come as first, continuation, last; frame
data that is not whole packets; bytes between CLTUs that are neither tail nor
idle fill. Notes, not problems: how many codeblocks had a bit corrected, and
how many control frames (Unlock, Set V(R)) went by. Expedited (BD) frames are
not held to a sequence.

Across the files of a run:

- packets one host logged that another host's log of the same stream lacks;
- for a stream with two emitters, which hosts' logs hold copies of its
  packets: the likely sources.

Limits of working from counters alone are listed at the top of
`src/pure/continuity.rs`.

### Store

- One SQLite file. A run is a folder; each file in it is identified
  by its place in the run and a checksum of its content: ingesting it again
  changes nothing, and a file that has changed replaces what was read before.
  Changing the configuration makes the whole run be read again.
- Each packet file's packets are also written to a segment file of their
  own, in a folder beside the store named after it (`packetlane.db.seg/`
  for `packetlane.db`), with the values of fields marked `keep`. The
  timeline's packet counts, its single packets, its plots, a packet's
  details and the times of the findings it lists are read from these, and
  so is the comparison of sources at the end of an ingest, from each
  segment's packets in checksum order. Each lane's count and time range
  is added up from what each segment holds of it, kept per file in the
  store (`segment_lanes`). SQLite holds no packets: text logs and the
  lists of runs, lanes, files and findings are read from it, and the
  tables `packets` and `field_values` that SQL sees are served from the
  segment files (see below). A
  segment is written whole before the store lists it, replaced when its
  file is read again, and one the store does not list is removed the next
  time the store is opened for writing.
  Delete the folder with the store. The layout is described at the top of
  `src/pure/segment.rs`.
- Views `packet_view`, `log_view`, `finding_view`, `file_view` and
  `value_view` (the stored values of fields marked `keep`) are the
  friendly way in for queries: one row per item, with the run, source and
  file by name and times as text.
- `packetlane query` and the SQL box in the UI accept one statement that
  reads. The connection they use cannot write.
- `packets` and `field_values` are not tables in the SQLite file: they
  are served from the segment files, on every connection this tool opens,
  with the columns, types and meaning the tables of those names had, so
  the same SQL works and gives the same rows. A stock `sqlite3` opening
  the store sees every other table, but not these two, nor the views over
  them. A range of ids or of receive or packet time, one file, one lane or
  one packet's values reads only what it needs. A field with an order by
  its number (the query builder's sort by value), or with a range of
  numbers, reads that field's values in order of number from each
  segment; a field alone skips the segments that have none of it but
  reads the kept values of the others whole (400 ms for the three million
  values of one field); anything else reads the segments from end to end.
  Counting every packet or every value reads no record, but SQLite still
  steps through each row: 180 ms for ten million packets, 40 ms for 2.2
  million values (SQLite counted its own tables in 25 to 45 ms). What the
  builder's statements cost, and what they cost at the commit before this
  measurement (ebc1b5f), is in the table below. The rowids of
  `field_values` are not the ones the old table gave (those were the order
  rows were inserted in, kept nowhere now). A statement reads the segments
  listed when it started; if one of them was replaced by an ingest
  meanwhile, it is run once more.
- A store made by an earlier build with a different layout is refused, and
  says so (this build's is layout 8): delete it, and its `.seg` folder,
  and ingest again. A segment written by a build with another segment
  format (this build's is 6) cannot be read either: ingest the store
  again. Nothing in it is not in the logs.
- Files are read on several threads at once, four unless
  `PACKETLANE_INGEST_THREADS` says otherwise (0 to 64; never more than
  the machine has cores by default; 0 reads each file on the calling
  thread and stores it before the next is read). A packet file is
  decoded and checked on one thread and written to its segment on
  another, and its segment is written back to disk on a third as it is
  finished; one file is never split further, so a run of one large file
  goes no faster than that file. What is stored is the same whatever the
  number, row for row and segment byte for byte: a file is read, checked
  and its segment written with lanes numbered as the file meets them,
  then the files are stored in their order, each in its own transaction
  as before; the ids a segment holds (its first packet, its lanes) are
  foreseen from the files before it and checked by that transaction, and
  a file not given the ids foreseen (another writer stored meanwhile) is
  read again, as is every file read ahead of one that fails. The first
  passes of the comparison of sources run on the same number of threads.
- Writing uses at most about 50 MB with four threads, whatever the size
  of the run or the number of files (measured: 25 MB for ten million
  packets in 12 lanes, 31 MB for three million in 900 lanes with six
  million values kept, 49 MB for 200 files of 50,000 packets in 3,000
  lanes from ten sources; 19, 21 and 33 MB on one thread). Each thread's
  six sorters (time orders, kept numbers and delays, checksums, values in
  order of number) share 12 MB with the others' (1 MB each on one or two
  threads, 512 KB on four, never under 256 KB), taken when a file is
  started; up to four batches of 512 records wait between a file's two
  threads (under 1 MB with kept values); finishing a segment takes a
  2 MB merge buffer, or 2 MB for one part of the checksums and 2 MB to
  put it in order, and 0.8 MB of write buffers. That is about 9 MB a
  thread at four, beside the process, SQLite's page cache (2 MB, filled
  only as far as it writes; `PACKETLANE_CACHE_MB` sets it) and the
  comparison of sources (5 MB, 13 MB for the 27,000 pairs of lanes of
  the 200 files). The allocator keeps what each thread has held, so more
  threads cost more than the arithmetic says: eight threads peaked at
  59 MB on the 200 files. More than four is a choice of memory for
  speed.
- The store file holds no packets either: 6.6 MB for that run of ten
  million packets (1.95 GB before layout 6), 1.5 MB for the run of three
  million (1.0 GB), beside segment folders of 1.76 GB and 1.05 GB (176
  and 350 bytes a packet; 1.71 and 0.93 GB at layout 6: the values in
  order of number take 20 bytes each, 44 MB and 120 MB here); 11.4 MB
  and 1.82 GB for the 200 files.
- Ingest takes 3.1 s for the ten million packets in 12 lanes (3.2
  million a second), 1.85 s for the three million in 900 lanes (1.6
  million a second) and 6.5 s for the 200 files (1.5 million a second)
  on four threads; 5.4, 4.2 and 10.9 s on one; 7.3, 4.9 and 12.4 s at
  c991d80. Medians of three, alternating builds, on an i7-11700K (8
  cores, 16 threads), NVMe and btrfs, with a desktop session running
  (load about 1). By threads:

  | threads | long | wide | 200 files | peak MB (long, wide, 200 files) |
  |---|---|---|---|---|
  | 1 | 5.3–5.4 s | 4.2–4.3 s | 10.8–11.0 s | 19, 21, 33 |
  | 2 | 4.3 s | 3.0 s | 7.9 s | 25, 33, 44 |
  | 3 | 4.0–4.1 s | 1.8–2.4 s | 6.9–7.0 s | 26, 34, 47 |
  | 4 | 3.1–3.3 s | 1.9 s | 6.4 s | 25, 31, 49 |
  | 8 | 3.2 s | 1.9–2.4 s | 5.9–6.0 s | 24, 27, 59 |

  The long run's largest file (five million packets) bounds it: read in
  1.25 s on its two threads and finished in 1.1 s, then 0.45 s to
  compare sources. With three threads that file is taken last of the
  three large ones, which is why three are slower than four there. The
  200 files are bound by the comparison of ten sources logging the same
  300 streams at the end: 2.9 s to merge the checksums and 0.9 s to count
  what partners lack, mostly on one thread. With every sorter off the
  largest files take 1.2 and 0.8 s (long, wide run); of the rest the kept
  numbers and delays take about 0.5 and 0.4 s, the checksums 0.5 and
  0.05 s, the time orders 0.3 and 0.1 s, the values in order of number
  0.05 and 0.25 s. Sorting costs what the input's disorder costs: input
  in time order is written once and read back once, kept numbers
  (interleaved by lane and series, each in time order) cost a step a
  group, and the checksums, which are in no order, are spread over 256
  parts by their first byte as they come and each part put in order in
  memory at the end. A file's checksum (to tell it has not changed) is
  taken eight bytes at a time: ingesting the ten million again with
  nothing changed takes 0.06 s (0.5 s at c991d80). A file read again
  costs only itself: 2.9 s for 96 MB of one file of that run with 1%
  added, the other segments untouched; a small run added to a store that
  holds the ten million costs 0.03 to 0.05 s (both measured at c991d80).
- An ingest writes temporary files in the segment folder, each removed
  when done with (or, after a crash, the next time the store is opened for
  writing and no ingest holds the folder): while a file is read, its
  segment under a temporary name and the sorted runs of its sections,
  together up to about twice the size of that segment, for each file
  being read at once (at c991d80, one file at a time, the most measured
  was 1.1 GB for a run of ten million packets in four files and 420 MB
  for one of three million in three); and when a run
  that more than one source logged is compared, 12 bytes for each packet
  that a source holds and another source logging the same stream lacks,
  12 for each copy of a packet repeated more than 65,536 times, and for a
  run of more than 64 files 30 bytes for each packet of the streams more
  than one source logged, twice over. The comparison makes no temporary
  table. SQLite itself needs little temporary space now: for counting text
  log entries into buckets. It puts it in the folder named by
  `SQLITE_TMPDIR` or `TMPDIR`, else the system's.

What the query builder's statements and a few others take, from start to
end of `packetlane query` (the process alone takes about 4 ms), at
ebc1b5f and now, on the long run (ten million packets, 1.1 million values
of the field asked for) and the wide one (three million packets, three
million values of the field `TEMP` in 300 packets), each alone in its
store. Medians of five, the two numbers being two rounds, with a game
running on the same machine. The same rows come back from both.

| statement | long before ms | long now | wide before | wide now |
|---|---|---|---|---|
| values, a field, sorted by value | 452–471 | 5–6 | 1115–1302 | 10–16 |
| the same, descending | 575–632 | 5–6 | 1113–1272 | 13–17 |
| values, a field and a packet, sorted by value | 684–697 | 5–8 | 75–82 | 8–10 |
| values, a field above a number, sorted by value | 31–35 | 5–6 | 63–70 | 12–15 |
| values, a field above a number | 6–7 | 6–7 | 64–73 | 12–14 |
| values, a field above any number | 26 | 5 | 64–73 | 11–12 |
| values, a field | 5 | 5–6 | 5–7 | 6–8 |
| values, after a receive time | 70–73 | 72–78 | 652–823 | 646–711 |
| `count(*)` of `packets` | 269–274 | 179–190 | 83–98 | 65–72 |
| `count(*)` of `field_values` | 55–56 | 38–41 | 137–160 | 105–110 |
| packets, the run's first | 5 | 6–8 | 5–8 | 5–6 |
| packets, after a receive time | 141–143 | 144–158 | 243–273 | 240–261 |
| packets per APID, whole store | 2846–2881 | 2814–2966 | 698–817 | 841–846 |

Values after a receive time look each value's packet up to test its
time, one lookup a value; SQLite's own tables did that in 414 ms on the
wide run, the segment files take about 150 ms more.

Measured again for files read in parallel (c991d80 against this build,
the same statements, two rounds of medians of five, alternating, in the
state described for ingest): every statement returns the same rows, and
every time is within the rounds' own spread (statements of a few
milliseconds move between 4 and 20 ms in both builds); the slowest,
packets per APID over the whole store, took 2454–2459 and 2483 ms on
the long run, 629–631 and 625–628 ms on the wide one. A plot or a
density read straight from the store (no server) takes the same at both,
to 0.01 ms.

### Timeline

- Opens fitted to the whole run. Lanes are created per host and APID (shown as
  a decimal number, with its name if the configuration gives one); text
  logs get lanes too.
- Density bars when zoomed out, single packets when zoomed in. Packets are
  counted from their segment files: each holds counts per stream in
  buckets across its own span, at widths from 4,096 buckets to the span
  down to one, each width kept only if it holds at most half the counts of
  the finer one kept before it (a file of hundreds of streams keeps only
  the coarser ones). A view takes whole the buckets of the coarsest width
  no wider than its own bars, counting only its two ends packet by packet;
  a narrower view counts the packets in it from the file's time order. A
  stored bucket is counted in the bar its start falls in. Text log entries
  are counted in the store, from counts made at ingest where the view is
  wide enough.
- **Problems** lists the findings; choosing one jumps to it and opens the
  packet.
- **Details** shows a packet's decoded fields, header values and a hex dump,
  or a log entry in full.
- **Search** covers lane names, APIDs and log text; log matches are marked on
  the timeline and listed under **Hits**.
- Three clocks: **Receive** (when each host logged it), **Packet** (the
  packet's own timestamp) and **Order** (order of ingest, for packets with no
  usable time).
- **Plots** sit under the lanes on the same time axis. The **Plot…** menu
  lists what the run can plot:
  - any field marked `keep = true` in its packet definition, as its
    engineering value, with the definition's limits shaded behind it;
  - for any lane whose packets carry a time of their own, **receive − packet
    time** in milliseconds: how long after the packet was stamped the host
    logged it. A paused, restarted or stalled simulator shows here without
    any packet definitions.

  Zoomed out, each pixel column shows the lowest and highest value that
  fell in it, so a one-packet spike is not averaged away. The lane's
  findings are drawn as vertical lines, and the pointer marks the same
  moment on every plot.

  A plot reads only its own lane's values in view, from the segment
  files, where each lane's values of each field (and its delays) lie
  together in time order. Each file also keeps, for a lane with at least
  four values a bucket, the lowest and highest value in each of up to
  16,384 buckets across the file, and a view wide enough is drawn from
  those: a whole-run plot on the receive or packet clock takes well under
  a millisecond on a run of ten million packets; on the order clock it
  reads every value of the lane, tens of milliseconds there. A stored
  bucket is drawn in the plot column its start falls in, so a value can
  sit one column early.
- The view (run, clock, range, lanes, plots, selection, search) is kept in
  the address, so it can be bookmarked while the server is running.

The UI carries almost no text, so the controls are listed here:

| Do this | To |
|---|---|
| wheel | zoom around the pointer |
| drag, or horizontal wheel, or ← → | pan |
| shift + drag | zoom to the dragged range |
| ctrl + drag (or alt, or ⌘) | measure an interval |
| double-click, `f` or `0` | fit the whole run |
| `+` `-` | zoom in and out |
| click a packet or log mark | open it in Details |
| click a red or blue marker | jump to that finding |
| `n` `p` | next and previous finding |
| drag in the strip at the bottom | move the view |
| ○ and ✕ on a lane | pin it to the top; hide it |
| **Plot…** menu; ✕ on a plot | add a plot; remove it |
| wheel, drag or double-click on a plot | zoom, pan or fit, as on the lanes |
| `/` | search |
| `Esc` | clear the selection |

### Query builder

**SQL** opens a small builder, so common questions need no typing: choose a
table (packets, logs, problems or files), add filters, a column to sort by
and a row limit. It writes the statement into the box below, where it can be
edited before running. `∋` means "contains".

### File browser

**Files** lists the folders given at launch. Each file shows its detected
format, size and whether it is already ingested. Tick files or folders (or
tick nothing, to take the folder you are in) and choose **Ingest**: they
become one run, named after the folder that contains them all. Nothing is
uploaded; the tool reads the files where they are.

### Naming and decoding packets

A configuration file gives packet types names and describes their fields, and
the Details panel then shows named values:

```toml
[[packet]]
apid = 419                 # decimal or hex (0x1A3)
name = "PAYLOAD_SCIENCE"
  [[packet.field]]
  name = "MODE"
  bit_offset = 96            # from the start of the packet; bit 0 is the top bit of byte 0
  bit_length = 8
  kind = "uint"              # uint (default), int, float, hex, ascii
  labels = { "0" = "IDLE", "1" = "OBSERVE" }
```

The same file names hosts, corrects their clocks, says where the timestamp is
in a packet and how to find the timestamp in a text log. Every part is
optional. The full format is documented at the top of `src/pure/config.rs`,
and `packetlane demo` writes a complete example.

### Frame and link settings

What a file of frames does not say about itself comes from two tables. Both
are optional, and most keys are detected per file; a key given here wins.

```toml
[frames]                   # files of CADUs
kind = "tm"                # "tm" or "aos"
randomized = false         # frames still XORed with the CCSDS random sequence
crc = false                # each frame ends with a 16-bit CRC
rs_parity_bytes = 0        # Reed-Solomon check symbols kept after each frame
rs_correct = true          # use them. Default: yes if a frame in the file is a clean
                           # codeword or any rs_ key below is given; otherwise skip them
rs_code = "255,223"        # or "255,239"
rs_interleave = 1          # 1, 2, 3, 4, 5 or 8
rs_basis = "dual"          # "dual" (Berlekamp, the CCSDS default) or "conventional"
ocf = false                # aos only: operational control field present
header_check = false       # aos only: 2-byte header check present
insert_zone_bytes = 0      # aos only

[tc]                       # CLTUs, or TC transfer frames back to back
crc = true                 # each frame ends with a 16-bit CRC
segment_header = true      # frame data starts with a segment header
randomized = false         # CLTUs only: frames XORed with the TC random sequence
```

Each file's note in the file list says what it was read as, for example
`AOS frames in 1024-byte CADUs, randomised, CRC, RS(255,223) interleave 4` or
`TC frames in CLTUs, CRC, segment headers`. A file whose check symbols are
skipped says `32 check bytes` and names no code.

## Time

Three clocks are in play and they do not agree:

| Clock | Comes from | Catch |
|---|---|---|
| Packet time | the packet, usually its secondary header | format and epoch are mission defined; independent of wall time |
| Receive time | the log container | each host's clock is skewed differently |
| Log time | text log lines | timezone often unstated; sometimes no year |

Everything is stored as integer nanoseconds. Each source can be given a
timezone and a fixed clock offset in configuration. The timeline shows one
clock at a time, chosen in the top bar; text logs appear on both the receive
and packet clocks at their own log time.

## Safety of the local server

Any web page open in the same browser can send requests to a loopback port, so
"localhost only" is not enough on its own:

- It binds to 127.0.0.1 only.
- Requests whose `Host` is not the tool's own address, or that come from
  another origin or site, are refused.
- Every request needs a random token generated at each launch and printed with
  the address.
- The file browser and ingest cannot leave the folders given at launch,
  including through symlinks or `..`. Symlinks are not listed or followed.
- Packet bytes shown in Details are read back only from files still inside
  those folders.
- The SQL box runs on a read-only connection that cannot attach other files,
  and each statement has a time limit and a size limit. The time limit
  holds inside reads of the segment files too, for SQL and for the
  page's own requests.

`tests/end_to_end.rs` checks each of these against a running server.

## Dependencies

| Crate | For |
|---|---|
| `rusqlite` (bundled SQLite) | the store |
| `serde`, `serde_json` | JSON between server and browser; reading configuration |
| `regex` | text log timestamp patterns |
| `toml` | the configuration file |
| `flate2` | reading gzip files |

Written on the standard library instead of adding crates: the HTTP server,
packet parsing, time arithmetic, argument parsing, checksums. The frontend is
plain JavaScript on a canvas, with no libraries and no build step.
`cargo vendor` gives one offline bundle of everything.

## Development container

`container/` has a stub Containerfile that adds the Rust toolchain and the
Helix editor to a RHEL 9 base image, and the `podman` commands to build and
run it with your home folder mounted. See `container/README.md`. It has not
been built here.

## Not done

- **Log grab**: collecting logs for a time window from a list of hosts.
- **Compare two runs** of the same scenario on a shared time axis.
- **Live tail** of a log that is still being written, and **live ingest**
  from a TCP or UDP port a simulator sends telemetry on.
- **A watch panel**: choose a packet (or APID) and see its fields as a
  table that follows the cursor or the newest packet, each value coloured
  by how it changed from the packet before: green for up, red for down,
  stronger for a bigger change as a percentage of the value (with another
  measure for values at or near zero). Most useful with live ingest.
- **Segment records described once**: each fixed-width record of a segment
  file is written and read by code that keeps its byte offsets by hand, in
  two places. One description per record, with the writer and the reader
  both made from it, would rule out a field written at one offset and read
  at another. For when the format has settled.
- **Ingest beyond one file a thread**: a file is read on two threads and
  finished on one, and the comparison of sources at the end of an ingest
  runs on one thread after its first passes; the first bounds a run of one
  large file, the second a run of many sources logging the same streams
  (2.9 s of the 6.4 s of 200 files from ten sources). Files are also taken
  in their order, so with fewer threads than large files the largest may
  start last.
- **An export of packets to a plain SQLite file**, with `packets` and
  `field_values` as real tables, for tools that open the store without
  this program.
- **Problem report export** to attach to a ticket.
- Other channel codes: convolutional, turbo and LDPC (a file must hold hard
  decisions that are already frame-aligned; Reed-Solomon and BCH are the only
  codes applied). No erasure decoding, and no bit-level frame synchronisation:
  CADUs and CLTUs must be byte-aligned in the file.
- TM frames with a Reed-Solomon code but none of the first sixteen clean, and
  no `[frames]` entry naming the code: nothing then says the check symbols
  are there. With a CRC their length is still found and they are stepped
  over; without one they are read as frame data.
- Telecommand: COP-1 is not followed (no FARM state, no CLCW from the
  downlink compared against the uplink; a retransmitted frame is reported as
  the count going back and its packets appear twice). No SDLS security
  header or trailer. LDPC-coded CLTUs are not read. More than one frame per
  CLTU is read only without randomising. Segments must add up to one
  packet. A last codeblock padded with anything but `55` is read as the
  start of another frame and reported. A CLTU's packets are shown by
  decoding back from the nearest start sequence, and bare TC frames from the
  start of the file, which is slow for a very large one.
- Reed-Solomon and the telecommand formats have been checked against the
  standards' constants as remembered and against synthetic files only. No
  recorded RS-coded downlink or uplink capture has been read with them yet.
- Plots show one series each: no overlaying two fields, no fixed or shared
  value scale, no markers for commands, no export. Only fields marked `keep`
  before ingest can be plotted.
- Packet definitions cover fixed-size numbers, text and arrays, polynomial
  conversions and one set of limits. Not covered: little-endian bit fields,
  items placed from the end of a packet, other conversions, and telling
  packets on one APID apart outside COSMOS logs.
- Importing packet definitions from a spreadsheet or database. (COSMOS 4
  definition files can be converted with `packetlane import-cosmos`; it keeps
  what this tool can show and lists what it left out.)
- Removing a run from the store (delete the store file to start over).
- Windows: paths are handled the Unix way only.

## Layout

```
src/pure/     functional core: decoders, frames and codes, checks, config, SQL text, HTTP and API as values.
              pipeline.rs is where a file's records become rows and findings, for the store and for `check` alike
              finding.rs is the one shape every check reports in, and the list of finding kinds
src/shell/    imperative shell: files, SQLite, segment files, sockets, command line
web/          the page: structure, style, script (embedded at build time)
tests/        end-to-end tests, decoders against damaged input, and the test
              that keeps I/O out of src/pure
              load.rs measures large runs and is run only when asked for;
              store_sql.rs pins which index the oracle statements use
              vtab.rs runs the same SQL over the tables served from the segment
              files and over the oracle tables a store opened for tests
              writes, and pins the plans of the query builder's statements
              parallel.rs checks that files read on several threads, out of
              order or failing, are stored as files read one at a time
tools/        ui-load.js measures the page in a headless Chrome
docs/         architecture.md, parsing.md
container/    development container stub and editor settings
```

## Load tests

Two tests measure large runs. Neither runs with `cargo test`, because they
take minutes and gigabytes.

```
cargo test --release --test load -- --ignored --nocapture --test-threads 1
```

generates a long run (few streams, a million packets) and a wide one (900
lanes from three hosts, values kept and limits on every stream), ingests
each with the built program (on the threads `PACKETLANE_INGEST_THREADS`
says), and prints how long ingest took and how long each file took to
read and to finish, the memory it held, and how long the server took to answer each request the page makes,
at four zoom levels and while another ingest is running. `LOAD_PACKETS`
sets the size and `LOAD_DIR` keeps the stores; the top of `tests/load.rs`
lists the other settings. It fails on what does not depend on the machine:
packets not stored, an answer too large to send, ingest holding a run in
memory. Times fail it only if `LOAD_BUDGET_MS` is set.

To see what a change did, run once with `LOAD_DIR=before`, make the
change, and run again with `LOAD_DIR=after LOAD_BASELINE=before`: each
time is printed with its change, and marked where that is more than the
times move on their own. `LOAD_PACKETS=300000` does both runs in under a
minute.

Measured at `LOAD_PACKETS=1000000` on an i7-11700K (8 cores, 16 threads),
NVMe and btrfs with a desktop session running, c991d80 against this build
(medians; two runs of each, both shown where they differ):

| | long before | long now | wide before | wide now |
|---|---|---|---|---|
| ingest | 0.7–0.8 s | 0.3 s | 1.6 s | 0.6–0.7 s |
| peak memory of ingest | 16 MB | 23 MB | 17 MB | 28 MB |
| ingest again, nothing changed | 0.06 s | 0.02 s | 0.06 s | 0.02 s |
| store with segments | 185 MB | 185 MB | 351 MB | 351 MB |
| opening the page | 1.0–1.1 ms | 1.1–4.6 ms | 33–36 ms | 32 ms |
| one view with 6 plots, a tenth | 5.3–5.5 ms | 5.0–5.6 ms | 33 ms | 32–33 ms |
| query: count packets | 17 ms | 17 ms | 16–19 ms | 17 ms |
| query: largest values of a field | 1.0 ms | 1.0 ms | 2.6–2.7 ms | 2.5–2.6 ms |
| query: packets per stream | 281 ms | 282–284 ms | 228 ms | 230–231 ms |
| query: newest packets | 1154–1167 ms | 1145–1179 ms | 1146–1150 ms | 1133–1163 ms |

Requests of a millisecond or two are marked as changed now and then by
the test (opening the long run's page 1.1 ms one run, 4.6 ms the next;
the wide run's narrowest plots 0.7 and 1.8 ms), and the earlier build's
two runs differ as much (its whole-run density 5.3 and 2.3 ms); read
straight from the stores those requests take the same at both builds.

At `LOAD_PACKETS=10000000`, in the same state: the long run ingested in
7.4 s with 18 MB at c991d80 and 3.1 s with 24 MB now (3.3 million
packets a second), the wide one in 16.6 s with 19 MB and 6.8 s with
33 MB (1.5 million a second); ingesting again with nothing changed 0.52
and 0.06 s, 0.48 and 0.04 s; stores 1.76 and 3.43 GB at both; count
packets 160 and 157 ms at both, packets per stream 3270 and 3289 ms on
the long run. At both, the "newest packets" query is stopped by the
server's 10 s time limit.

```
packetlane serve --db store.db --root <run folder>
node tools/ui-load.js '<the URL that printed>' [--run N] [--budget ms]
```

drives the page in a headless Chrome through opening, zooming, panning,
plots, hovering, jumping to a problem and searching, and prints for each
how long the page took to settle and the longest it could not respond. It
needs Node 22 or later and Chrome, and nothing else.

## Licence

Provisionally MIT OR Apache-2.0. Not published.
