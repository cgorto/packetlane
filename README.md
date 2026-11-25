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
  (both the `COSMOS2_` and `COSMOS4_` layouts) and COSMOS 5 packet logs, and text logs. Site-specific formats are added as
  decoders (`docs/parsing.md`).
- **Text logs**: one configurable pattern per log type picks out the
  timestamp; lines without one stay attached to the entry above.
- Truncated files are read as far as they go, then reported, not rejected.
- Logged items that are not space packets are kept and shown in their own
  lane.

### Checks

Per file, for every APID and packet type:

- lost packets, repeated packets, counter restarts, packets out of order;
- **two emitters sharing one APID** (interleaved sequence counters).

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
- Views `packet_view`, `log_view`, `finding_view` and `file_view` are the
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
- The view (run, clock, range, lanes, selection, search) is kept in the
  address, so it can be bookmarked while the server is running.

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

## Time

Three clocks are in play and they do not agree:

| Clock | Comes from | Catch |
|---|---|---|
| Packet time | the packet's secondary header | format and epoch are mission defined; independent of wall time |
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
- **Transfer frame** layer, for logs that store frames instead of packets.
- **Live tail** of a log that is still being written.
- **Problem report export** to attach to a ticket.
- Decoded field values are shown per packet; they cannot be searched or
  plotted.
- Importing packet definitions from a spreadsheet or database. (COSMOS 4
  definition files can be converted with `packetlane import-cosmos`; it keeps
  what this tool can show and lists what it left out.)
- Removing a run from the store (delete the store file to start over).
- Windows: paths are handled the Unix way only.

## Layout

```
src/pure/     functional core: decoders, checks, config, SQL text, HTTP and API as values
src/shell/    imperative shell: files, SQLite, sockets, command line
web/          the page: structure, style, script (embedded at build time)
tests/        end-to-end tests, and the test that keeps I/O out of src/pure
docs/         architecture.md, parsing.md
container/    development container stub and editor settings
```

## Licence

Provisionally MIT OR Apache-2.0. Not published.
