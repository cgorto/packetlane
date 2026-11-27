//! What reading a run costs with nothing written: each file hashed, its
//! records decoded and every check run on them, as an ingest does. Run by
//! hand on a run folder:
//!
//! `FLOOR_DIR=<run> cargo test --release --test read_floor -- --ignored --nocapture`

use std::fs::{self, File};
use std::hint::black_box;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

use packetlane::pure::config::Config;
use packetlane::pure::decode::{Format, decoder_for};
use packetlane::pure::ingest::relative_path;
use packetlane::pure::pipeline::FileCheck;
use packetlane::shell::files::{Hashing, ReadError, Records, open_sniffed};
use packetlane::shell::ingest::{RUN_CONFIG, components, walk};

#[test]
#[ignore = "a measurement; needs FLOOR_DIR"]
fn read_floor() {
    let Some(dir) = std::env::var_os("FLOOR_DIR") else {
        panic!("set FLOOR_DIR to a run folder");
    };
    let root = fs::canonicalize(PathBuf::from(dir)).unwrap();
    let config_text = fs::read_to_string(root.join(RUN_CONFIG)).unwrap_or_default();
    let config = Config::parse(&config_text).unwrap();
    let root_parts = components(&root).unwrap();
    let mut files = Vec::new();
    walk(&root, &mut files).unwrap();

    let started = Instant::now();
    let mut packets = 0u64;
    let mut findings = 0usize;
    for path in &files {
        let rel = relative_path(&root_parts, &components(path).unwrap()).unwrap();
        let (checksum, size) = Hashing::new(File::open(path).unwrap()).finish().unwrap();
        black_box((checksum, size));
        let (format, file) = open_sniffed(path).unwrap();
        if format == Format::Text {
            continue;
        }
        let Some(decoder) = decoder_for(format, &config) else {
            continue;
        };
        let mut records = Records::new(BufReader::new(file), decoder);
        let mut check = FileCheck::new(&config, &config.source_for(&rel));
        let mut end = None;
        for item in &mut records {
            let record = match item {
                Ok(record) => record,
                Err(ReadError::Io(e)) => panic!("{rel}: {e}"),
                Err(ReadError::Decode(e)) => {
                    end = Some(e);
                    break;
                }
            };
            let seen = check.observe(&record);
            black_box(&seen.row);
            for v in &seen.values {
                black_box(v);
            }
            black_box(seen);
        }
        let report = check.finish();
        packets += report.packets;
        findings += report.findings(&records.notices(), end.as_ref()).len();
    }
    let took = started.elapsed().as_secs_f64();
    println!(
        "{} files, {packets} packets, {findings} findings, {took:.3} s, {:.0} ns/packet",
        files.len(),
        took * 1e9 / packets.max(1) as f64
    );
}
