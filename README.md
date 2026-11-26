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
- Views `packet_view`, `log_view`, `finding_view`, `file_view` and
  `value_view` (the stored values of fields marked `keep`) are the
  friendly way in for queries: one row per item, with the run, source and
  file by name and times as text.
- `packetlane query` and the SQL box in the UI accept one statement that
  reads. The connection they use cannot write.

### Timeline

- Opens fitted to the whole run. Lanes are created per host and APID (shown as
  a decimal number, with its name if the configuration gives one); text
  logs get lanes too.
- Density bars when zoomed out, single packets when zoomed in. Whole-run views
  are drawn from counts made at ingest, so millions of packets stay quick.
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

  A plot reads the packets in view each time the view moves; nothing is
  precomputed for it as it is for the lanes. On a run of 900,000 packets
  with a million kept values, a whole-run plot takes 0.1 to 0.2 s and a
  zoomed-in one a few milliseconds, and opening the run takes 0.4 s longer
  than without kept values. Expect ten times that at ten times the size.
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
  and each statement has a time limit and a size limit.

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
- **Live tail** of a log that is still being written.
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
src/pure/     functional core: decoders, frames and codes, checks, config, SQL text, HTTP and API as values
src/shell/    imperative shell: files, SQLite, sockets, command line
web/          the page: structure, style, script (embedded at build time)
tests/        end-to-end tests, and the test that keeps I/O out of src/pure
docs/         architecture.md, parsing.md
container/    development container stub and editor settings
```

## Licence

Provisionally MIT OR Apache-2.0. Not published.
