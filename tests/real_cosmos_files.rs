//! Checks the synthetic writers in `pure::synth` against real COSMOS log
//! files, byte for byte: each real file is decoded, written again from what
//! was decoded, and compared. Real logs are not kept in this repository, so
//! these tests do nothing unless told where some are:
//!
//! - `REAL4`: a folder holding `tlm.bin` and `cmd.bin` as COSMOS 4.2 wrote
//!   them (the COSMOS repository has a pair under `autohotkey/outputs/logs`
//!   at tag `v4.2.4`).
//! - `REAL5`: a folder holding `raw.bin`, a COSMOS 5 raw packet log (the
//!   COSMOS repository has one, with a long name ending `__rt__raw.bin`,
//!   under `cosmos-cmd-tlm-api/spec/fixtures/files` at tag `v5.0.5`).
//!
//! `REAL4=... REAL5=... cargo test --test real_cosmos_files -- --nocapture`
use packetlane::pure::decode::{decode_all, decoder_for, sniff};
use packetlane::pure::synth::{
    Cosmos5Writer, cosmos_cmd, cosmos_tlm, cosmos2_entry, cosmos2_header,
};
use std::fs;

fn records(data: &[u8]) -> Vec<packetlane::pure::decode::Record> {
    let mut decoder = decoder_for(sniff(data), &Default::default()).unwrap();
    decode_all(decoder.as_mut(), data).0
}

#[test]
fn cosmos2_writer_reproduces_a_real_file() {
    let Ok(dir) = std::env::var("REAL4") else {
        return;
    };
    for (name, telemetry) in [("tlm.bin", true), ("cmd.bin", false)] {
        let real = fs::read(format!("{dir}/{name}")).unwrap();
        let config = std::str::from_utf8(&real[12..44]).unwrap();
        let host = std::str::from_utf8(&real[45..128]).unwrap().trim_end();
        let mut rebuilt = cosmos2_header(telemetry, config, host);
        let recs = records(&real);
        for r in &recs {
            let (target, packet) = r.label.as_deref().unwrap().split_once(' ').unwrap();
            rebuilt.extend(cosmos2_entry(
                r.receive_time_ns.unwrap(),
                target,
                packet,
                &r.payload,
            ));
        }
        assert_eq!(rebuilt.len(), real.len(), "{name}");
        assert!(rebuilt == real, "{name}: container bytes differ");
        println!("{name}: {} entries, container identical", recs.len());

        // And the packets themselves, rebuilt from their fields, where
        // they have the shape COSMOS's example target gives them. Logs of
        // other targets will have packets that do not; those are counted.
        let (mut same, mut other) = (0, 0);
        for r in &recs {
            let p = &r.payload;
            let label = r.label.as_deref().unwrap();
            let shaped = p.len() >= if telemetry { 16 } else { 8 }
                && p[0] >> 5 == 0
                && (p[0] & 0x10 != 0) != telemetry
                && p[2] >> 6 == 3;
            if !shaped {
                other += 1;
                continue;
            }
            let apid = u16::from_be_bytes([p[0], p[1]]) & 0x7FF;
            let seq = u16::from_be_bytes([p[2], p[3]]) & 0x3FFF;
            let again = if telemetry {
                let secs = u32::from_be_bytes(p[6..10].try_into().unwrap());
                let usecs = u32::from_be_bytes(p[10..14].try_into().unwrap());
                let t = i64::from(secs) * 1_000_000_000 + i64::from(usecs) * 1_000;
                let id = u16::from_be_bytes([p[14], p[15]]);
                cosmos_tlm(apid, seq, t, id, &p[16..])
            } else {
                let length = u16::from_be_bytes([p[4], p[5]]);
                let id = u16::from_be_bytes([p[6], p[7]]);
                cosmos_cmd(apid, length, id, &p[8..])
            };
            // The builders always write a count for commands of 0 and
            // clear the secondary header flag, as the example target does.
            if again == *p {
                same += 1;
            } else {
                println!("{name} {label}: not the example target's shape (count {seq})");
                other += 1;
            }
        }
        println!(
            "{name}: {same} packets rebuilt identically from their fields, {other} of another shape"
        );
    }
}

#[test]
fn cosmos5_writer_reproduces_a_real_file() {
    let Ok(dir) = std::env::var("REAL5") else {
        return;
    };
    let real = fs::read(format!("{dir}/raw.bin")).unwrap();
    let recs = records(&real);
    let first_target = u16::from_be_bytes([real[24], real[25]]);
    let mut writer = Cosmos5Writer::like_cosmos(first_target);
    let mut rebuilt = Cosmos5Writer::magic();
    for r in &recs {
        let (target, packet) = r.label.as_deref().unwrap().split_once(' ').unwrap();
        rebuilt.extend(writer.entry(
            r.receive_time_ns.unwrap(),
            target,
            packet,
            &r.payload,
            false,
        ));
    }
    let marker_at = real.len() - (4 + 2 + 15);
    let marker = std::str::from_utf8(&real[marker_at + 6..]).unwrap();
    rebuilt.extend(Cosmos5Writer::offset_marker(marker));
    assert_eq!(rebuilt.len(), real.len());
    // The packet declaration's id is a digest this tool cannot know: bytes
    // 32..64. Everything else must match.
    let differing: Vec<usize> = (0..real.len()).filter(|&i| rebuilt[i] != real[i]).collect();
    assert!(
        differing.iter().all(|i| (32..64).contains(i)),
        "{:?}",
        &differing[..differing.len().min(8)]
    );
    println!(
        "raw.bin: {} entries, identical outside the 32-byte id; target numbered {first_target}; marker {marker}",
        recs.len()
    );
}
