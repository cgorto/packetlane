//! Checks that compare one source's log with another's. The store runs the
//! comparison queries; this module turns their numbers into findings.

use crate::pure::ingest::{SEVERITY_INFO, SEVERITY_PROBLEM};

#[derive(Debug, Clone, PartialEq)]
pub struct CrossFinding {
    pub lane_id: i64,
    pub packet_id: Option<i64>,
    pub severity: &'static str,
    pub kind: &'static str,
    pub message: String,
}

/// Lane `a` and lane `b` carry the same stream as logged by two sources.
/// `shared` packets of `a` are also in `b`; `missing` packets of `a` are not,
/// although they sit between packets that are.
pub fn hop_finding(
    lane_a: i64,
    source_a: &str,
    source_b: &str,
    shared: i64,
    missing: i64,
    first_missing: Option<i64>,
) -> Option<CrossFinding> {
    (shared > 0 && missing > 0).then(|| {
        let unit = if missing == 1 { "packet" } else { "packets" };
        CrossFinding {
            lane_id: lane_a,
            packet_id: first_missing,
            severity: SEVERITY_PROBLEM,
            kind: "hop_missing",
            message: format!(
                "{missing} {unit} from {source_a} missing in {source_b} ({shared} shared)"
            ),
        }
    })
}

/// A stream with interleaved counters, and the other sources whose logs
/// hold copies of its packets: the likely emitters.
pub fn origin_finding(
    lane_id: i64,
    packet_id: Option<i64>,
    origins: &[(String, i64)],
) -> Option<CrossFinding> {
    if origins.is_empty() {
        return None;
    }
    let list: Vec<String> = origins
        .iter()
        .map(|(source, n)| format!("{source} ({n})"))
        .collect();
    Some(CrossFinding {
        lane_id,
        packet_id,
        severity: SEVERITY_INFO,
        kind: "origins",
        message: format!("Packet copies found in {}", list.join(", ")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_finding_needs_overlap_and_loss() {
        assert!(hop_finding(1, "ground", "bench-a", 0, 40, None).is_none());
        assert!(hop_finding(1, "ground", "bench-a", 40, 0, None).is_none());
        let f = hop_finding(1, "ground", "bench-a", 25, 25, Some(9)).unwrap();
        assert_eq!(f.packet_id, Some(9));
        assert_eq!(
            f.message,
            "25 packets from ground missing in bench-a (25 shared)"
        );
    }

    #[test]
    fn origins_are_listed() {
        assert!(origin_finding(1, None, &[]).is_none());
        let f = origin_finding(1, None, &[("bench-a".into(), 25), ("bench-b".into(), 25)]).unwrap();
        assert!(f.message.ends_with("bench-a (25), bench-b (25)"));
        assert_eq!(f.severity, SEVERITY_INFO);
    }
}
