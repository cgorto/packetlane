//! Load tests: how long ingest takes and how quickly the server answers the
//! requests the page makes, on runs far larger than the other tests use.
//!
//! They take minutes and gigabytes, so they are ignored unless asked for:
//!
//! ```text
//! cargo test --release --test load -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Settings, all from the environment:
//!
//! - `LOAD_PACKETS`: packets per run, about. Default 1,000,000.
//! - `LOAD_DIR`: where to work. Default: a folder in the temporary
//!   directory, removed afterwards. A folder given here is kept, with its
//!   stores, so the page can be opened on them (see `tools/ui-load.js`).
//! - `LOAD_BUDGET_MS`: fail if the median answer to any request the page
//!   makes while panning or zooming takes longer. Default: no limit, the
//!   times are only printed, because they depend on the machine.
//! - `LOAD_MAX_RSS_MB`: fail if ingest uses more memory. Default 96, which
//!   is several times what it uses at any size and far less than a run.
//!
//! What always fails a test is what does not depend on the machine: packets
//! not all stored, an answer larger than the page should ever be sent, or
//! ingest holding a whole run in memory.

use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use packetlane::pure::synth::{cosmos_tlm, cosmos2_entry, cosmos2_header};
use packetlane::shell::server::{Options, Server};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_packetlane");
/// The largest answer the page should ever be sent.
const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;
/// Above this many packets in view the page asks for counts, not packets.
const ITEM_LIMIT: i64 = 1500;

fn setting(name: &str) -> Option<u64> {
    let text = std::env::var(name).ok()?;
    Some(
        text.replace('_', "")
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a whole number")),
    )
}

/// The folder to work in, and whether to remove it afterwards.
fn work_dir(name: &str) -> (PathBuf, bool) {
    let (base, ours) = match std::env::var_os("LOAD_DIR") {
        Some(dir) => (PathBuf::from(dir), false),
        None => (
            std::env::temp_dir().join(format!("packetlane-load-{}", std::process::id())),
            true,
        ),
    };
    let dir = base.join(name);
    // Start clean: a store left by an earlier run would make ingest a no-op.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    (fs::canonicalize(dir).unwrap(), ours)
}

fn folder_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let meta = entry.metadata().unwrap();
        total += if meta.is_dir() {
            folder_bytes(&entry.path())
        } else {
            meta.len()
        };
    }
    total
}

/// Runs the built program and waits for it. Returns how long it took, the
/// most memory it held (MB, from the kernel's own high-water mark), and
/// what it printed.
fn run(args: &[&str]) -> (Duration, u64, String) {
    let started = Instant::now();
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let status_path = format!("/proc/{}/status", child.id());
    let mut peak_kb = 0u64;
    let mut out = String::new();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    loop {
        if let Ok(status) = fs::read_to_string(&status_path) {
            let hwm = status
                .lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok());
            peak_kb = peak_kb.max(hwm.unwrap_or(0));
        }
        if let Some(status) = child.try_wait().unwrap() {
            // 1 is what ingest returns when the run has problems, as these do.
            assert!(
                matches!(status.code(), Some(0 | 1)),
                "{args:?} failed: {status}"
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    out.push_str(&reader.join().unwrap());
    (started.elapsed(), peak_kb / 1024, out)
}

/// An answer's body, or `None` if the server gave up on the request because
/// it ran past its time limit. That is a result to report, not a broken test.
type Answer = Option<String>;

/// One request to the server: how long the whole answer took, and its body.
struct Client {
    port: u16,
    token: String,
}

impl Client {
    fn send(&self, request: &str) -> (Duration, Answer) {
        let started = Instant::now();
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let took = started.elapsed();
        let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
        if body.contains("\"interrupted\"") {
            return (took, None);
        }
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "{}: {head} {body}",
            request.lines().next().unwrap_or("")
        );
        (took, Some(body.to_string()))
    }

    fn get(&self, target: &str) -> (Duration, Answer) {
        self.send(&format!(
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Packetlane-Token: {}\r\n\r\n",
            self.port, self.token
        ))
    }

    fn json(&self, target: &str) -> Value {
        let body = self.get(target).1;
        let body = body.unwrap_or_else(|| panic!("{target}: stopped by the server's time limit"));
        serde_json::from_str(&body).unwrap()
    }

    fn query(&self, sql: &str) -> (Duration, Answer) {
        let body = serde_json::json!({ "sql": sql }).to_string();
        self.send(&format!(
            "POST /api/query HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-Packetlane-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.token,
            body.len(),
            port = self.port,
        ))
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The times of one kind of request, and the largest answer.
struct Timing {
    name: String,
    /// Whether the page makes this request on every pan and zoom.
    interactive: bool,
    first: f64,
    median: f64,
    worst: f64,
    bytes: usize,
    /// How many of the requests the server gave up on.
    stopped: usize,
}

struct Table {
    rows: Vec<Timing>,
}

impl Table {
    /// Makes the request `repeats` times, one after another.
    fn time(
        &mut self,
        name: &str,
        interactive: bool,
        repeats: usize,
        mut ask: impl FnMut() -> (Duration, Option<usize>),
    ) {
        let mut times = Vec::new();
        let mut bytes = 0;
        let mut stopped = 0;
        for _ in 0..repeats {
            let (took, size) = ask();
            times.push(ms(took));
            bytes = bytes.max(size.unwrap_or(0));
            stopped += usize::from(size.is_none());
        }
        let first = times[0];
        times.sort_by(f64::total_cmp);
        assert!(
            bytes <= MAX_ANSWER_BYTES,
            "{name}: an answer of {bytes} bytes is more than the page should be sent"
        );
        self.rows.push(Timing {
            name: name.to_string(),
            interactive,
            first,
            median: times[times.len() / 2],
            worst: times[times.len() - 1],
            bytes,
            stopped,
        });
    }

    fn print(&self) {
        println!(
            "  {:<44} {:>9} {:>9} {:>9} {:>10}",
            "request", "first ms", "median", "worst", "bytes"
        );
        for row in &self.rows {
            let note = if row.stopped > 0 {
                "  STOPPED by the server's time limit"
            } else {
                ""
            };
            println!(
                "  {:<44} {:>9.1} {:>9.1} {:>9.1} {:>10}{note}",
                row.name, row.first, row.median, row.worst, row.bytes
            );
        }
    }
}

/// Ingests the folder with the built program, then times the server on
/// what was stored. `expect_packets` is how many packets must be stored,
/// where the test knows.
fn measure(name: &str, dir: &Path, run_dir: &Path, expect_packets: Option<u64>) {
    if cfg!(debug_assertions) {
        println!("NOTE: this is a debug build; its times mean nothing. Use --release.");
    }
    let db = dir.join("store.db");
    let db_text = db.to_str().unwrap();
    let run_text = run_dir.to_str().unwrap();
    let input = folder_bytes(run_dir);

    let (took, peak_mb, out) = run(&["ingest", "--db", db_text, run_text]);
    println!("\n== {name} ==");
    println!("  {}", out.lines().last().unwrap_or(""));
    let max_rss = setting("LOAD_MAX_RSS_MB").unwrap_or(96);
    assert!(
        peak_mb <= max_rss,
        "ingest held {peak_mb} MB, more than {max_rss} MB"
    );

    let server = Server::bind(Options {
        db: db.clone(),
        roots: vec![run_dir.to_path_buf()],
        config: None,
        user_config: None,
        port: 0,
    })
    .unwrap();
    let client = Client {
        port: server.port(),
        token: server.token().to_string(),
    };
    std::thread::spawn(move || server.run());

    let mut table = Table { rows: Vec::new() };
    let sized = |(took, body): (Duration, Answer)| (took, body.map(|b| b.len()));

    table.time("runs", false, 5, || sized(client.get("/api/runs")));
    let run_id = client.json("/api/runs")["runs"][0]["id"].as_i64().unwrap();
    let stored = client.json("/api/runs")["runs"][0]["packets"]
        .as_u64()
        .unwrap();
    if let Some(expected) = expect_packets {
        assert_eq!(stored, expected, "not every packet was stored");
    }
    assert!(stored > 0, "nothing was stored");
    let secs = took.as_secs_f64();
    println!(
        "  ingest: {:.1} s for {:.0} MB, {:.1} MB/s, {:.0} packets/s, peak memory {peak_mb} MB",
        secs,
        input as f64 / 1e6,
        input as f64 / 1e6 / secs,
        stored as f64 / secs,
    );
    let (again, _, _) = run(&["ingest", "--db", db_text, run_text]);
    let store_bytes = fs::metadata(&db).unwrap().len();
    println!(
        "  ingest again, nothing changed: {:.2} s; store {:.0} MB, {:.1} times the logs",
        again.as_secs_f64(),
        store_bytes as f64 / 1e6,
        store_bytes as f64 / input as f64
    );

    table.time("run (opening the page)", false, 5, || {
        sized(client.get(&format!("/api/run?run={run_id}")))
    });
    let meta = client.json(&format!("/api/run?run={run_id}"));
    let origin = meta["clocks"]["receive"]["origin"].as_str().unwrap();
    let span = meta["clocks"]["receive"]["span"].as_i64().unwrap();
    let lanes = meta["lanes"].as_array().unwrap().len();
    let findings = meta["findings"].as_array().unwrap().len();
    println!(
        "  {stored} packets, {lanes} lanes, {findings} findings listed, {:.1} h of receive time",
        span as f64 / 3.6e12
    );

    // The plots a person might have open: up to three of values, three of
    // arrival delay, on the busiest lanes.
    let mut series: Vec<&Value> = meta["series"].as_array().unwrap().iter().collect();
    let lane_count = |s: &Value| {
        meta["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["id"] == s["lane"])
            .and_then(|l| l["count"].as_i64())
            .unwrap_or(0)
    };
    series.sort_by_key(|s| -lane_count(s));
    let plots: Vec<String> = ["value", "lag"]
        .iter()
        .flat_map(|kind| series.iter().filter(move |s| s["kind"] == *kind).take(3))
        .map(|s| {
            let mut q = format!("&lane={}", s["lane"]);
            if s["kind"] == "value" {
                q += &format!(
                    "&packet={}&field={}",
                    s["packet"].as_str().unwrap(),
                    s["field"].as_str().unwrap()
                );
            }
            q
        })
        .collect();

    // What the page asks for at one view, as it asks: packet counts and
    // every plot at once, then the packets themselves if few enough.
    let view = |from: i64, to: i64| {
        let window = format!("run={run_id}&clock=receive&origin={origin}&from={from}&to={to}");
        let half = (to - from) / 2;
        let wide = format!(
            "run={run_id}&clock=receive&origin={origin}&from={}&to={}",
            from - half,
            to + half
        );
        (window, wide)
    };
    let burst = |from: i64, to: i64| -> (Duration, Option<usize>) {
        let (window, wide) = view(from, to);
        let started = Instant::now();
        // The size of every answer, or `None` if any was given up on.
        let mut sizes: Vec<Option<usize>> = Vec::new();
        std::thread::scope(|scope| {
            let jobs: Vec<_> = plots
                .iter()
                .map(|plot| {
                    let target = format!("/api/series?{wide}&buckets=1200{plot}");
                    let client = &client;
                    scope.spawn(move || client.get(&target).1.map(|b| b.len()))
                })
                .collect();
            let density = client.get(&format!("/api/density?{window}&buckets=400")).1;
            sizes.push(density.as_ref().map(|d| d.len()));
            let total = density
                .and_then(|d| serde_json::from_str::<Value>(&d).ok())
                .and_then(|d| d["total"].as_i64())
                .unwrap_or(i64::MAX);
            if total <= ITEM_LIMIT {
                let items = client.get(&format!("/api/items?{window}&limit={}", ITEM_LIMIT + 500));
                sizes.push(items.1.map(|b| b.len()));
            }
            for job in jobs {
                sizes.push(job.join().unwrap());
            }
        });
        (started.elapsed(), sizes.into_iter().sum())
    };

    let mid = span / 2;
    let zooms = [
        ("whole run", 0, span),
        ("a tenth", mid - span / 20, mid + span / 20),
        ("a thousandth", mid - span / 2000, mid + span / 2000),
        ("ten seconds", mid - 5_000_000_000, mid + 5_000_000_000),
    ];
    for (zoom, from, to) in zooms {
        let (window, wide) = view(from, to);
        table.time(&format!("density, {zoom}"), true, 7, || {
            sized(client.get(&format!("/api/density?{window}&buckets=400")))
        });
        if let Some(plot) = plots.first() {
            table.time(&format!("value plot, {zoom}"), true, 7, || {
                sized(client.get(&format!("/api/series?{wide}&buckets=1200{plot}")))
            });
        }
        if let Some(plot) = plots.iter().find(|p| !p.contains("&field=")) {
            table.time(&format!("delay plot, {zoom}"), true, 7, || {
                sized(client.get(&format!("/api/series?{wide}&buckets=1200{plot}")))
            });
        }
        table.time(
            &format!("one view with {} plots, {zoom}", plots.len()),
            true,
            7,
            || burst(from, to),
        );
    }
    let (window, _) = view(mid - 5_000_000_000, mid + 5_000_000_000);
    table.time("packets in view, ten seconds", true, 7, || {
        sized(client.get(&format!("/api/items?{window}&limit={}", ITEM_LIMIT + 500)))
    });
    let some_packet = client
        .query("SELECT MAX(id) / 2 FROM packets")
        .1
        .expect("an answer");
    let some_packet = serde_json::from_str::<Value>(&some_packet).unwrap()["rows"][0][0]
        .as_i64()
        .unwrap();
    table.time("one packet", false, 7, || {
        sized(client.get(&format!("/api/packet?id={some_packet}")))
    });
    table.time("search of text logs", false, 3, || {
        sized(client.get(&format!("/api/search?run={run_id}&origin={origin}&q=a")))
    });
    for (what, sql) in [
        ("count packets", "SELECT COUNT(*) FROM packets"),
        (
            "packets per stream",
            "SELECT apid, COUNT(*) FROM packet_view GROUP BY apid ORDER BY 2 DESC",
        ),
        (
            "newest packets",
            "SELECT * FROM packet_view ORDER BY receive_time DESC LIMIT 100",
        ),
        ("problems", "SELECT * FROM finding_view LIMIT 500"),
    ] {
        table.time(&format!("query: {what}"), false, 3, || {
            sized(client.query(sql))
        });
    }

    // The same view while another run is being ingested into the store.
    let extra = dir.join("extra");
    run(&["demo", "--seconds", "20000", extra.to_str().unwrap()]);
    let extra_text = extra.to_str().unwrap().to_string();
    let db_copy = db_text.to_string();
    let writer = std::thread::spawn(move || run(&["ingest", "--db", &db_copy, &extra_text]));
    let mut during = Vec::new();
    while !writer.is_finished() {
        during.push(ms(burst(mid - span / 20, mid + span / 20).0));
    }
    let (ingest_took, _, _) = writer.join().unwrap();
    during.sort_by(f64::total_cmp);

    table.print();
    println!(
        "  one view, a tenth, during a {:.1} s ingest of another run: {} asked, median {:.1} ms, worst {:.1} ms",
        ingest_took.as_secs_f64(),
        during.len(),
        during[during.len() / 2],
        during[during.len() - 1]
    );

    let stopped: Vec<&str> = table
        .rows
        .iter()
        .filter(|r| r.interactive && r.stopped > 0)
        .map(|r| r.name.as_str())
        .collect();
    assert!(
        stopped.is_empty(),
        "the server gave up on requests the page makes: {stopped:?}"
    );
    if let Some(budget) = setting("LOAD_BUDGET_MS") {
        let slow: Vec<String> = table
            .rows
            .iter()
            .filter(|r| r.interactive && r.median > budget as f64)
            .map(|r| format!("{} ({:.0} ms)", r.name, r.median))
            .collect();
        assert!(slow.is_empty(), "slower than {budget} ms: {slow:?}");
    }
}

/// The demo run stretched to many hours: few lanes, each very long.
#[test]
#[ignore = "takes minutes; see the top of this file"]
fn a_long_run() {
    let packets = setting("LOAD_PACKETS").unwrap_or(1_000_000);
    let (dir, ours) = work_dir("long");
    let run_dir = dir.join("run");
    // The demo makes just over 18 packets a second.
    let seconds = (packets / 18).max(60);
    let (took, _, _) = run(&[
        "demo",
        "--seconds",
        &seconds.to_string(),
        run_dir.to_str().unwrap(),
    ]);
    println!("generated in {:.1} s", took.as_secs_f64());
    measure("long run", &dir, &run_dir, None);
    if ours {
        // Only this test's folder: the other test may still be using its own.
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir(dir.parent().unwrap());
    }
}

const WIDE_APIDS: u16 = 300;
const WIDE_SOURCES: [&str; 3] = ["gse-a", "gse-b", "gse-c"];

/// The configuration for the wide run: every stream named, two values kept
/// from each, one with limits.
fn wide_config() -> String {
    let mut toml =
        String::from("[packet_time]\ncode = \"unix\"\nrequire_secondary_header = false\n\n");
    for apid in 0..WIDE_APIDS {
        toml += &format!(
            r#"[[packet]]
apid = {a}
label = "UNIT{u} TLM{apid}"
name = "TLM{apid}"
  [[packet.field]]
  name = "TEMP"
  bit_offset = 128
  bit_length = 8
  keep = true
  limits = {{ red_low = -1, yellow_low = 5, yellow_high = 200, red_high = 240 }}
  [[packet.field]]
  name = "COUNT"
  bit_offset = 136
  bit_length = 16
  keep = true

"#,
            a = 0x100 + apid,
            u = apid % 12,
        );
    }
    toml
}

/// Writes the wide run: three hosts each logging the same 300 streams at
/// ten packets a second in all, with packets dropped and values leaving
/// their limits now and then. A packet is the same bytes on every host
/// that logged it. Returns how many packets were written.
fn write_wide(run_dir: &Path, packets: u64) -> u64 {
    fs::create_dir_all(run_dir).unwrap();
    fs::write(run_dir.join("packetlane.toml"), wide_config()).unwrap();
    let per_source = packets / WIDE_SOURCES.len() as u64;
    let t0 = 1_767_225_600_000_000_000i64;
    let mut written = 0;
    for (s, source) in WIDE_SOURCES.iter().enumerate() {
        let dir = run_dir.join(source);
        fs::create_dir_all(&dir).unwrap();
        let mut file = BufWriter::new(File::create(dir.join("tlm.bin")).unwrap());
        file.write_all(&cosmos2_header(
            true,
            "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
            source,
        ))
        .unwrap();
        for i in 0..per_source {
            let n = (i % u64::from(WIDE_APIDS)) as u16;
            let t = t0 + i as i64 * 100_000_000 + s as i64 * 3_000_000;
            let seq = ((i / u64::from(WIDE_APIDS)) % 16384) as u16;
            // Each host loses a packet now and then, and not the same ones.
            if i % 4_099 == 17 * (s as u64 + 1) {
                continue;
            }
            written += 1;
            // A slow wave that crosses the yellow limit, and a rare spike
            // past the red one.
            let wave = 100.0 + 110.0 * ((i / u64::from(WIDE_APIDS)) as f64 / 40.0).sin();
            let temp = if i % 50_021 == 0 {
                250
            } else {
                wave.clamp(6.0, 239.0) as u8
            };
            let mut body = vec![temp];
            body.extend_from_slice(&((i / u64::from(WIDE_APIDS)) as u16).to_be_bytes());
            body.extend_from_slice(&[0; 5]);
            // The same bytes on every host, as one packet seen three times.
            let sent = t0 + i as i64 * 100_000_000 - 2_000_000;
            let packet = cosmos_tlm(0x100 + n, seq, sent, 1, &body);
            file.write_all(&cosmos2_entry(
                t,
                &format!("UNIT{}", n % 12),
                &format!("TLM{n}"),
                &packet,
            ))
            .unwrap();
        }
        file.flush().unwrap();
    }
    written
}

/// Many streams from several hosts, every one with kept values and limits:
/// hundreds of lanes and thousands of findings.
#[test]
#[ignore = "takes minutes; see the top of this file"]
fn a_wide_run() {
    let packets = setting("LOAD_PACKETS").unwrap_or(1_000_000);
    let (dir, ours) = work_dir("wide");
    let run_dir = dir.join("run");
    let started = Instant::now();
    let written = write_wide(&run_dir, packets);
    println!("generated in {:.1} s", started.elapsed().as_secs_f64());
    measure("wide run", &dir, &run_dir, Some(written));
    if ours {
        // Only this test's folder: the other test may still be using its own.
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir(dir.parent().unwrap());
    }
}
