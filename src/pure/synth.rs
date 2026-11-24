//! Synthetic packet generators. All test data comes from here; real logs
//! never go in this repository.

use crate::pure::ccsds::{PacketType, PrimaryHeader, SEQ_MODULUS, SeqFlags};

/// Builds one unsegmented telemetry packet with no secondary header.
/// A space packet carries at least one data byte, so an empty payload is
/// sent as a single zero.
pub fn packet(apid: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let payload: &[u8] = if payload.is_empty() { &[0] } else { payload };
    let len = payload.len().min(65536);
    let header = PrimaryHeader {
        version: 0,
        packet_type: PacketType::Telemetry,
        has_secondary_header: false,
        apid,
        seq_flags: SeqFlags::Unsegmented,
        seq_count: seq % SEQ_MODULUS,
        data_length: (len - 1) as u16,
    };
    let mut out = header.encode().to_vec();
    out.extend_from_slice(&payload[..len]);
    out
}

/// One emitter of one APID, with its own sequence counter.
#[derive(Debug, Clone)]
pub struct Source {
    pub apid: u16,
    pub next_seq: u16,
    pub payload_len: usize,
}

impl Source {
    pub fn new(apid: u16, first_seq: u16, payload_len: usize) -> Self {
        Self {
            apid,
            next_seq: first_seq % SEQ_MODULUS,
            payload_len,
        }
    }

    pub fn emit(&mut self) -> Vec<u8> {
        let seq = self.next_seq;
        self.next_seq = (seq + 1) % SEQ_MODULUS;
        let fill = (seq & 0xFF) as u8;
        packet(self.apid, seq, &vec![fill; self.payload_len.max(1)])
    }

    /// Advances the counter without emitting, to fake lost packets.
    pub fn skip(&mut self, n: u16) {
        self.next_seq = (self.next_seq + n % SEQ_MODULUS) % SEQ_MODULUS;
    }
}

/// Alternates packets from two sources. When both use the same APID this is
/// the two-emitter fault the continuity check looks for.
pub fn interleaved(a: &mut Source, b: &mut Source, pairs: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..pairs {
        out.extend(a.emit());
        out.extend(b.emit());
    }
    out
}

fn push_space_padded(out: &mut Vec<u8>, text: &str, width: usize) {
    let bytes = text.as_bytes();
    let take = bytes.len().min(width);
    out.extend_from_slice(&bytes[..take]);
    out.resize(out.len() + (width - take), b' ');
}

/// Builds a 128-byte COSMOS 4 file header.
pub fn cosmos4_header(telemetry: bool, config_name: &str, hostname: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"COSMOS4_");
    out.extend_from_slice(if telemetry { b"TLM" } else { b"CMD" });
    out.push(b'_');
    push_space_padded(&mut out, config_name, 32);
    out.push(b'_');
    push_space_padded(&mut out, hostname, 83);
    out
}

/// Builds one COSMOS 4 entry (no extra JSON, not marked stored).
pub fn cosmos4_entry(time_ns: i64, target: &str, packet: &str, payload: &[u8]) -> Vec<u8> {
    let ns = time_ns.max(0) as u64;
    let secs = (ns / 1_000_000_000) as u32;
    let usecs = ((ns % 1_000_000_000) / 1_000) as u32;
    let target_bytes = &target.as_bytes()[..target.len().min(u8::MAX as usize)];
    let packet_bytes = &packet.as_bytes()[..packet.len().min(u8::MAX as usize)];

    let mut out = Vec::with_capacity(
        1 + 4 + 4 + 1 + target_bytes.len() + 1 + packet_bytes.len() + 4 + payload.len(),
    );
    out.push(0); // flags: neither stored nor extra
    out.extend_from_slice(&secs.to_be_bytes());
    out.extend_from_slice(&usecs.to_be_bytes());
    out.push(target_bytes.len() as u8);
    out.extend_from_slice(target_bytes);
    out.push(packet_bytes.len() as u8);
    out.extend_from_slice(packet_bytes);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Builds synthetic COSMOS 5 log entries, emitting target and packet
/// declarations on first use.
#[derive(Debug, Default)]
pub struct Cosmos5Writer {
    targets: std::collections::HashMap<String, u16>,
    packets: std::collections::HashMap<(u16, String, bool), u16>,
}

impl Cosmos5Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn magic() -> Vec<u8> {
        b"COSMOS5_".to_vec()
    }

    pub fn entry(
        &mut self,
        time_ns: i64,
        target: &str,
        packet: &str,
        payload: &[u8],
        command: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();

        let target_idx = if let Some(&idx) = self.targets.get(target) {
            idx
        } else {
            let idx = self.targets.len() as u16;
            self.targets.insert(target.to_string(), idx);
            let name = target.as_bytes();
            let entry_len = (2 + name.len()) as u32;
            out.extend_from_slice(&entry_len.to_be_bytes());
            out.extend_from_slice(&0x1000u16.to_be_bytes());
            out.extend_from_slice(name);
            idx
        };

        let pkt_key = (target_idx, packet.to_string(), command);
        let cmd_flag: u16 = if command { 0x0800 } else { 0 };
        let packet_idx = if let Some(&idx) = self.packets.get(&pkt_key) {
            idx
        } else {
            let idx = self.packets.len() as u16;
            self.packets.insert(pkt_key, idx);
            let name = packet.as_bytes();
            let entry_len = (2 + 2 + name.len()) as u32;
            out.extend_from_slice(&entry_len.to_be_bytes());
            out.extend_from_slice(&(0x2000u16 | cmd_flag).to_be_bytes());
            out.extend_from_slice(&target_idx.to_be_bytes());
            out.extend_from_slice(name);
            idx
        };

        let time = time_ns.max(0) as u64;
        let entry_len = (2 + 2 + 8 + payload.len()) as u32;
        out.extend_from_slice(&entry_len.to_be_bytes());
        out.extend_from_slice(&(0x3000u16 | cmd_flag).to_be_bytes());
        out.extend_from_slice(&packet_idx.to_be_bytes());
        out.extend_from_slice(&time.to_be_bytes());
        out.extend_from_slice(payload);

        out
    }
}

/// Builds one telemetry packet with a secondary header: `time` bytes first,
/// then `body`.
pub fn timed_packet(apid: u16, seq: u16, time: &[u8], body: &[u8]) -> Vec<u8> {
    let mut data = time.to_vec();
    data.extend_from_slice(body);
    let mut out = packet(apid, seq, &data);
    if let Some(first) = out.first_mut() {
        *first |= 0x08;
    }
    out
}

/// One file of a generated run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoFile {
    /// Path within the run folder, with forward slashes.
    pub rel: &'static str,
    pub bytes: Vec<u8>,
}

/// The configuration file that goes with [`demo_run`]. Every name in it is
/// invented.
pub const DEMO_CONFIG: &str = r#"# Generated by `packetlane demo`. All names here are invented.

[[source]]
path = "ground/"
name = "ground"
clock_offset_ms = -250        # this host's clock runs a quarter second fast

[[log]]
path = "bench-b/"
pattern = '^\[(?P<epoch>\d+\.\d+)\]'

[packet_time]
code = "cuc"
byte_offset = 6
coarse_bytes = 4
fine_bytes = 2
epoch = "1958-01-01T00:00:00Z"

[[packet]]
apid = 100
name = "SIM_HK"
description = "Unit housekeeping, once a second"
  [[packet.field]]
  name = "MODE"
  bit_offset = 96
  bit_length = 8
  labels = { "0" = "STANDBY", "1" = "RUNNING", "2" = "CYCLING" }
  [[packet.field]]
  name = "CYCLE"
  bit_offset = 104
  bit_length = 16
  [[packet.field]]
  name = "BUS_VOLTS"
  bit_offset = 120
  bit_length = 32
  kind = "float"
  unit = "V"
  [[packet.field]]
  name = "FLAGS"
  bit_offset = 152
  bit_length = 16
  kind = "hex"

[[packet]]
apid = 419
name = "PAYLOAD_SCIENCE"
description = "Payload science frames, five a second"
  [[packet.field]]
  name = "ORIGIN"
  bit_offset = 96
  bit_length = 32
  kind = "ascii"
  [[packet.field]]
  name = "FRAME"
  bit_offset = 128
  bit_length = 32

[[packet]]
apid = 420
name = "AUX_DATA"
description = "Auxiliary frames from the second bench, five a second"
  [[packet.field]]
  name = "ORIGIN"
  bit_offset = 96
  bit_length = 32
  kind = "ascii"
  [[packet.field]]
  name = "FRAME"
  bit_offset = 128
  bit_length = 32

[[packet]]
apid = 200
type = "tc"
name = "SIM_CMD"
  [[packet.field]]
  name = "OPCODE"
  bit_offset = 48
  bit_length = 8
  labels = { "1" = "NOOP", "7" = "POWER_CYCLE" }
"#;

const DEMO_START_S: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z
const CUC_EPOCH_S: i64 = -378_691_200; // 1958-01-01T00:00:00Z
const NS: i64 = 1_000_000_000;
const MS: i64 = 1_000_000;

fn cuc(t_ns: i64) -> [u8; 6] {
    let since = t_ns - CUC_EPOCH_S * NS;
    let coarse = (since / NS) as u32;
    let fine = (((since % NS) as u128 * 65536).div_ceil(NS as u128)).min(65535) as u16;
    let mut out = [0u8; 6];
    out[..4].copy_from_slice(&coarse.to_be_bytes());
    out[4..].copy_from_slice(&fine.to_be_bytes());
    out
}

fn iso_utc(t_ns: i64) -> String {
    crate::pure::time::format_iso(t_ns).replace(".000000000Z", ".000Z")
}

/// A generated run from an invented three-host test setup, `seconds` long
/// (at least 60), with these faults built in:
///
/// - the unit on `bench-a` is power cycled, so its housekeeping counter resets;
/// - `ground` loses three housekeeping packets;
/// - the clock on `ground` runs a quarter of a second fast.
pub fn demo_run(seconds: u32) -> Vec<DemoFile> {
    let seconds = i64::from(seconds.max(60));
    let t0 = DEMO_START_S * NS;
    let second_from = seconds * 2 / 5;
    let cycle_at = seconds * 3 / 5;
    let drop_from = seconds / 4;
    const GROUND_DELAY: i64 = 40 * MS;
    const GROUND_SKEW: i64 = 250 * MS;

    // (emit time, emitting host, target, packet name, bytes)
    let mut emitted: Vec<(i64, u8, &str, &str, Vec<u8>)> = Vec::new();

    let mut hk_seq = 0u16;
    for s in 0..seconds {
        if s == cycle_at {
            hk_seq = 0;
        }
        let t = t0 + s * NS;
        let mode: u8 = if s == cycle_at { 2 } else { 1 };
        let mut body = vec![mode];
        body.extend_from_slice(&((s % 65536) as u16).to_be_bytes());
        body.extend_from_slice(&(28.0f32 + (s % 7) as f32 * 0.05).to_be_bytes());
        body.extend_from_slice(&[0x00, if s % 30 == 0 { 0x81 } else { 0x01 }]);
        emitted.push((
            t,
            0,
            "SIM",
            "HK",
            timed_packet(0x064, hk_seq, &cuc(t), &body),
        ));
        hk_seq = (hk_seq + 1) % SEQ_MODULUS;
    }

    let science = |apid: u16, origin: &[u8; 4], frame: u32, seq: u16, t: i64| {
        let mut body = origin.to_vec();
        body.extend_from_slice(&frame.to_be_bytes());
        body.extend((0..16u32).map(|i| (frame.wrapping_mul(31).wrapping_add(i * 7) & 0xFF) as u8));
        timed_packet(apid, seq, &cuc(t), &body)
    };
    // The science stream from bench-a.
    for i in 0..seconds * 5 {
        let t = t0 + i * 200 * MS;
        let seq = (i % i64::from(SEQ_MODULUS)) as u16;
        emitted.push((
            t,
            0,
            "SIM",
            "SCIENCE",
            science(0x1A3, b"GENA", i as u32, seq, t),
        ));
    }
    // bench-b sends a stream of its own, starting partway in.
    for i in 0..(seconds - second_from) * 5 {
        let t = t0 + second_from * NS + i * 200 * MS + 100 * MS;
        let seq = (i % i64::from(SEQ_MODULUS)) as u16;
        emitted.push((
            t,
            1,
            "GEN",
            "AUX",
            science(0x1A4, b"GENB", i as u32, seq, t),
        ));
    }
    emitted.sort_by_key(|e| e.0);

    let mut bench_a = Cosmos5Writer::magic();
    let mut bench_a_writer = Cosmos5Writer::new();
    let mut bench_b = cosmos4_header(true, "gen_demo", "bench-b");
    let mut ground = Cosmos5Writer::magic();
    let mut ground_writer = Cosmos5Writer::new();
    for (t, host, target, name, bytes) in &emitted {
        if *host == 0 {
            bench_a.extend(bench_a_writer.entry(t + MS, target, name, bytes, false));
        } else {
            bench_b.extend(cosmos4_entry(t + MS, target, name, bytes));
        }
        let second = (t - t0) / NS;
        let dropped = *name == "HK" && (drop_from..drop_from + 3).contains(&second);
        if !dropped {
            let at = t + GROUND_DELAY + GROUND_SKEW;
            ground.extend(ground_writer.entry(at, "DOWNLINK", name, bytes, false));
        }
    }

    // Commands sent from the ground host, logged there.
    let mut commands = cosmos4_header(false, "ground_demo", "ground");
    let command_times = [10, cycle_at - 1, seconds - 20];
    for (n, &s) in command_times.iter().enumerate() {
        let opcode: u8 = if s == cycle_at - 1 { 7 } else { 1 };
        let mut bytes = packet(0x0C8, n as u16, &[opcode, 0, 0, n as u8]);
        if let Some(first) = bytes.first_mut() {
            *first |= 0x10;
        }
        let t = t0 + s * NS + 500 * MS + GROUND_SKEW;
        commands.extend(cosmos4_entry(t, "SIM", "CMD", &bytes));
    }

    let mut sim_log = String::new();
    sim_log.push_str(&format!(
        "{} INFO  unit started, scenario demo-01\n",
        iso_utc(t0)
    ));
    for s in (10..seconds).step_by(10) {
        if s > cycle_at && s - cycle_at < 10 {
            continue;
        }
        sim_log.push_str(&format!("{} INFO  cycle {s} ok\n", iso_utc(t0 + s * NS)));
        if s <= cycle_at && cycle_at < s + 10 {
            let r = t0 + cycle_at * NS;
            sim_log.push_str(&format!(
                "{} INFO  power cycle command received\n",
                iso_utc(r - 400 * MS)
            ));
            sim_log.push_str(&format!(
                "{} WARN  power cycling; state follows\n  mode=CYCLING\n  bus=B\n",
                iso_utc(r - 300 * MS)
            ));
            sim_log.push_str(&format!(
                "{} INFO  unit started, scenario demo-01\n",
                iso_utc(r)
            ));
        }
    }

    let mut gen_log = String::new();
    let epoch = |t: i64| format!("[{}.{:03}]", t / NS, (t % NS) / MS);
    let i0 = t0 + second_from * NS;
    gen_log.push_str(&format!("{} generator started\n", epoch(i0 - 200 * MS)));
    gen_log.push_str(&format!(
        "{} first frame sent on APID 420\n",
        epoch(i0 + 100 * MS)
    ));
    for s in (second_from + 20..seconds).step_by(20) {
        gen_log.push_str(&format!(
            "{} sent {} frames\n",
            epoch(t0 + s * NS),
            (s - second_from) * 5
        ));
    }

    // The ground host writes local time, five hours behind UTC, on its fast clock.
    let local = |t: i64| {
        let shifted = crate::pure::time::format_iso(t + GROUND_SKEW - 5 * 3600 * NS);
        format!("{}-05:00", &shifted[..23])
    };
    let mut ground_log = String::new();
    ground_log.push_str(&format!(
        "{} INFO  pass started, link up\n",
        local(t0 + 2 * NS)
    ));
    ground_log.push_str(&format!(
        "{} WARN  housekeeping gap: 3 packets not received\n",
        local(t0 + (drop_from + 3) * NS + 60 * MS)
    ));
    ground_log.push_str(&format!(
        "{} INFO  aux stream APID 420 acquired\n  first frame 0\n  rate 5 Hz\n",
        local(i0 + 150 * MS)
    ));
    ground_log.push_str(&format!(
        "{} INFO  command POWER_CYCLE sent\n",
        local(t0 + (cycle_at - 1) * NS + 500 * MS)
    ));
    ground_log.push_str(&format!(
        "{} WARN  housekeeping counter went back to 0\n",
        local(t0 + cycle_at * NS + 60 * MS)
    ));
    ground_log.push_str(&format!("{} INFO  pass ended\n", local(t0 + seconds * NS)));

    vec![
        DemoFile {
            rel: "packetlane.toml",
            bytes: DEMO_CONFIG.as_bytes().to_vec(),
        },
        DemoFile {
            rel: "bench-a/tlm.bin",
            bytes: bench_a,
        },
        DemoFile {
            rel: "bench-a/sim.log",
            bytes: sim_log.into_bytes(),
        },
        DemoFile {
            rel: "bench-b/gen.bin",
            bytes: bench_b,
        },
        DemoFile {
            rel: "bench-b/gen.log",
            bytes: gen_log.into_bytes(),
        },
        DemoFile {
            rel: "ground/downlink.bin",
            bytes: ground,
        },
        DemoFile {
            rel: "ground/commands.bin",
            bytes: commands,
        },
        DemoFile {
            rel: "ground/ground.log",
            bytes: ground_log.into_bytes(),
        },
    ]
}

#[cfg(test)]
mod demo_tests {
    use super::*;
    use crate::pure::config::Config;
    use crate::pure::continuity::{Checker, FindingKind};
    use crate::pure::decode::{Format, decode_all, decoder_for, sniff};
    use crate::pure::format::packet_time_ns;
    use crate::pure::ingest::whole_packet_header;

    #[test]
    fn demo_config_is_valid() {
        let config = Config::parse(DEMO_CONFIG).unwrap();
        assert_eq!(config.packets.len(), 4);
        assert_eq!(config.source_for("ground/x").clock_offset_ns, -250_000_000);
    }

    #[test]
    fn demo_files_decode_and_show_the_built_in_faults() {
        let files = demo_run(120);
        let rule = Config::parse(DEMO_CONFIG).unwrap().resolved_time().unwrap();
        let kinds_in = |rel: &str| {
            let file = files.iter().find(|f| f.rel == rel).unwrap();
            let format = sniff(&file.bytes);
            assert!(matches!(format, Format::Cosmos4 | Format::Cosmos5), "{rel}");
            let mut decoder = decoder_for(format).unwrap();
            let (records, end) = decode_all(decoder.as_mut(), &file.bytes);
            assert_eq!(end, None, "{rel}");
            let mut checker = Checker::new();
            for r in &records {
                let header = whole_packet_header(&r.payload).expect("a whole packet");
                checker.observe(&header, r.offset);
                if header.has_secondary_header {
                    let t = packet_time_ns(&rule, &r.payload).unwrap();
                    assert!(
                        (t - DEMO_START_S * NS).abs() < 200 * NS,
                        "{rel}: packet time {t}"
                    );
                }
            }
            let mut kinds: Vec<String> = checker
                .finish()
                .findings
                .iter()
                .map(|f| match f.kind {
                    FindingKind::Gap { missing, .. } => format!("gap{missing}"),
                    FindingKind::Reset { .. } => "reset".to_string(),
                    FindingKind::Interleaved { counters } => format!("interleaved{counters}"),
                    _ => "other".to_string(),
                })
                .collect();
            kinds.sort();
            kinds
        };
        assert_eq!(kinds_in("bench-a/tlm.bin"), ["reset"]);
        assert_eq!(kinds_in("bench-b/gen.bin"), Vec::<String>::new());
        assert_eq!(kinds_in("ground/downlink.bin"), ["gap3", "reset"]);
        assert_eq!(kinds_in("ground/commands.bin"), Vec::<String>::new());
        for rel in ["bench-a/sim.log", "bench-b/gen.log", "ground/ground.log"] {
            let file = files.iter().find(|f| f.rel == rel).unwrap();
            assert_eq!(sniff(&file.bytes), Format::Text, "{rel}");
        }
    }
}
