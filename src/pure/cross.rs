//! Checks that compare one source's log with another's: what the packets
//! of a run, in checksum order, come to, and the findings made of that.
//! `shell::cross` reads the packets from the segment files.

use std::collections::HashMap;

use crate::pure::finding::{Finding, Kind, Severity};

/// A finding about stored lanes: `lane` and `packet` are their ids in the
/// store.
pub type CrossFinding = Finding<i64, i64>;

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
        Finding {
            lane: lane_a,
            packet: first_missing,
            severity: Severity::Problem,
            kind: Kind::HopMissing,
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
    Some(Finding {
        lane: lane_id,
        packet: packet_id,
        severity: Severity::Info,
        kind: Kind::Origins,
        message: format!("Packet copies found in {}", list.join(", ")),
    })
}

// ---- comparing sources by checksum ---------------------------------------------
//
// Lane `a` and lane `b` carry the same stream as logged by two sources (a
// pair). For each pair: `shared` is how many of a's packets have a checksum
// that occurs in b, `lo` and `hi` the lowest and highest id among those;
// `missing` is how many of a's packets with an id in `lo..=hi` have a
// checksum that does not occur in b, with the lowest such id. A stream with
// interleaved counters is traced: for each other lane of its stream, how
// many of its packets that lane holds a packet of with the same checksum,
// sequence count and length.
//
// The answers are put together from every space packet of the run in the
// order of [`Logged`], one checksum (a group) at a time. Nothing here holds
// more than one group's lanes. The ids of a group's packets that a partner
// lacks are not known to matter until every group has been seen, so they
// are handed back ([`Comparison::candidates`]) to be kept elsewhere and
// given back once ([`Comparison::replay`]).

/// One space packet as the comparison of sources reads it, ordered as it
/// is read: checksum, sequence count, length, lane, id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Logged {
    pub sum: i64,
    pub seq: u16,
    pub length: i64,
    pub lane: u32,
    pub id: i64,
}

/// What one pair of lanes comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PairCount {
    pub shared: i64,
    /// Lowest and highest id among the shared packets.
    pub span: Option<(i64, i64)>,
    pub missing: i64,
    pub first_missing: Option<i64>,
}

/// One lane within the current group: how many packets, lowest and
/// highest id.
#[derive(Debug, Clone, Copy)]
struct InGroup {
    lane: u32,
    count: i64,
    lo: i64,
    hi: i64,
}

/// The comparison of a run's sources, fed one packet at a time.
#[derive(Debug)]
pub struct Comparison {
    pairs: Vec<(u32, u32)>,
    counts: Vec<PairCount>,
    /// The pairs each lane is the first lane of, as (lane, pair), sorted.
    partners: Vec<(u32, usize)>,
    /// Streams being traced, sorted; and per (traced lane, other lane), how
    /// many of the traced lane's packets the other holds.
    traced: Vec<u32>,
    copies: HashMap<(u32, u32), i64>,
    /// The current group and its lanes.
    group: Option<i64>,
    lanes: Vec<InGroup>,
    /// The current checksum, sequence count and length, and the packets of
    /// each lane with them.
    sub: Option<(i64, u16, i64)>,
    sub_lanes: Vec<(u32, i64)>,
    /// The pairs of the group just ended whose second lane it lacks, as
    /// (first lane, pair), sorted.
    absent: Vec<(u32, usize)>,
}

impl Comparison {
    /// Compares the lanes of `pairs`, in the order given, and traces the
    /// lanes of `traced`.
    pub fn new(pairs: &[(u32, u32)], traced: &[u32]) -> Comparison {
        let mut partners: Vec<(u32, usize)> =
            pairs.iter().enumerate().map(|(i, p)| (p.0, i)).collect();
        partners.sort_unstable();
        let mut traced = traced.to_vec();
        traced.sort_unstable();
        traced.dedup();
        Comparison {
            pairs: pairs.to_vec(),
            counts: vec![PairCount::default(); pairs.len()],
            partners,
            traced,
            copies: HashMap::new(),
            group: None,
            lanes: Vec::new(),
            sub: None,
            sub_lanes: Vec::new(),
            absent: Vec::new(),
        }
    }

    /// Whether the comparison has any use for a lane's packets.
    pub fn wants(&self, lane: u32) -> bool {
        self.partners_of(lane).next().is_some()
    }

    /// Every lane the comparison has a use for, sorted.
    pub fn lanes(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.partners.iter().map(|p| p.0).collect();
        out.dedup();
        out
    }

    fn partners_of(&self, lane: u32) -> impl Iterator<Item = usize> + '_ {
        of_lane(&self.partners, lane)
    }

    /// Whether `next` begins another group than the current one: if so,
    /// [`Comparison::end_group`] must be called before it is added.
    pub fn ends_group(&self, next: &Logged) -> bool {
        self.group.is_some_and(|sum| sum != next.sum)
    }

    /// Adds the next packet, which must not come before the last in the
    /// order of [`Logged`], and must belong to the current group.
    pub fn add(&mut self, p: &Logged) {
        self.group = Some(p.sum);
        let key = (p.sum, p.seq, p.length);
        if self.sub.is_some_and(|k| k != key) {
            self.end_sub();
        }
        self.sub = Some(key);
        match self.sub_lanes.last_mut() {
            Some(l) if l.0 == p.lane => l.1 += 1,
            _ => self.sub_lanes.push((p.lane, 1)),
        }
        match self.lanes.iter_mut().find(|l| l.lane == p.lane) {
            Some(l) => {
                l.count += 1;
                l.lo = l.lo.min(p.id);
                l.hi = l.hi.max(p.id);
            }
            None => self.lanes.push(InGroup {
                lane: p.lane,
                count: 1,
                lo: p.id,
                hi: p.id,
            }),
        }
    }

    /// The end of a run of packets with one checksum, sequence count and
    /// length: each traced lane among them is found in each other lane of
    /// its stream that is there too.
    fn end_sub(&mut self) {
        if !self.traced.is_empty() {
            for &(x, n) in &self.sub_lanes {
                if self.traced.binary_search(&x).is_err() {
                    continue;
                }
                for &(l, _) in &self.sub_lanes {
                    let partner = self.partners_of(x).any(|p| self.pairs[p].1 == l);
                    if l != x && partner {
                        *self.copies.entry((x, l)).or_default() += n;
                    }
                }
            }
        }
        self.sub = None;
        self.sub_lanes.clear();
    }

    /// Ends the current group: every pair whose two lanes are both in it
    /// shares the first lane's packets in it. Afterwards
    /// [`Comparison::candidates`] says, for each of the group's packets,
    /// which pairs lack it, until the next group is added.
    pub fn end_group(&mut self) {
        self.end_sub();
        self.absent.clear();
        for l in &self.lanes {
            for p in of_lane(&self.partners, l.lane) {
                let b = self.pairs[p].1;
                if self.lanes.iter().any(|m| m.lane == b) {
                    let c = &mut self.counts[p];
                    c.shared += l.count;
                    c.span = Some(match c.span {
                        Some((lo, hi)) => (lo.min(l.lo), hi.max(l.hi)),
                        None => (l.lo, l.hi),
                    });
                } else {
                    self.absent.push((l.lane, p));
                }
            }
        }
        self.absent.sort_unstable();
        self.group = None;
        self.lanes.clear();
    }

    /// Whether any packet of the group just ended is lacking from a
    /// partner.
    pub fn any_absent(&self) -> bool {
        !self.absent.is_empty()
    }

    /// The pairs that lack a packet (of lane `lane`) of the group just
    /// ended, to be handed back with its id through
    /// [`Comparison::replay`] once every group has been seen.
    pub fn candidates(&self, lane: u32) -> impl Iterator<Item = usize> + '_ {
        of_lane(&self.absent, lane)
    }

    /// A packet with id `id` of the first lane of pair `pair` whose
    /// checksum the second lane lacks, after every group has been seen. It
    /// is missing if it lies among the packets they share.
    pub fn replay(&mut self, pair: usize, id: i64) {
        let Some(c) = self.counts.get_mut(pair) else {
            return;
        };
        if c.span.is_some_and(|(lo, hi)| (lo..=hi).contains(&id)) {
            c.missing += 1;
            c.first_missing = Some(c.first_missing.map_or(id, |f| f.min(id)));
        }
    }

    /// What each pair came to, in the order the pairs were given.
    pub fn counts(&self) -> &[PairCount] {
        &self.counts
    }

    /// How many of a traced lane's packets another lane holds a copy of.
    pub fn copies(&self, traced: u32, other: u32) -> i64 {
        self.copies.get(&(traced, other)).copied().unwrap_or(0)
    }
}

/// The second of each (lane, n) in a list sorted by lane whose lane is
/// `lane`.
fn of_lane(list: &[(u32, usize)], lane: u32) -> impl Iterator<Item = usize> + '_ {
    let at = list.partition_point(|p| p.0 < lane);
    list[at..]
        .iter()
        .take_while(move |p| p.0 == lane)
        .map(|p| p.1)
}

/// Compares sources over packets given in the order of [`Logged`], holding
/// every candidate in memory: the rule in its plainest form, for tests and
/// small inputs.
pub fn compare_all(
    pairs: &[(u32, u32)],
    traced: &[u32],
    packets: impl IntoIterator<Item = Logged>,
) -> Comparison {
    let mut c = Comparison::new(pairs, traced);
    let mut group: Vec<Logged> = Vec::new();
    let mut held: Vec<(usize, i64)> = Vec::new();
    let mut flush = |c: &mut Comparison, group: &mut Vec<Logged>| {
        c.end_group();
        for p in group.drain(..) {
            held.extend(c.candidates(p.lane).map(|pair| (pair, p.id)));
        }
    };
    for p in packets {
        if !c.wants(p.lane) {
            continue;
        }
        if c.ends_group(&p) {
            flush(&mut c, &mut group);
        }
        c.add(&p);
        group.push(p);
    }
    flush(&mut c, &mut group);
    for (pair, id) in held {
        c.replay(pair, id);
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_finding_needs_overlap_and_loss() {
        assert!(hop_finding(1, "ground", "bench-a", 0, 40, None).is_none());
        assert!(hop_finding(1, "ground", "bench-a", 40, 0, None).is_none());
        let f = hop_finding(1, "ground", "bench-a", 25, 25, Some(9)).unwrap();
        assert_eq!(f.packet, Some(9));
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
        assert_eq!(f.severity, Severity::Info);
    }

    /// Packets with few distinct checksums, so that groups hold several
    /// lanes and repeats, and checksums shared by packets of other
    /// sequence counts or lengths. Lanes 1 to 3 are one stream from three
    /// sources, 4 and 5 another.
    pub(crate) fn mixed_packets(n: usize, seed: u64) -> Vec<Logged> {
        let mut x = seed;
        let mut next = move |m: u64| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 33) % m
        };
        let mut out: Vec<Logged> = (0..n)
            .map(|i| {
                let lane = 1 + next(5) as u32;
                Logged {
                    sum: next(40) as i64 - 20,
                    seq: next(2) as u16,
                    length: 10 + next(2) as i64,
                    lane,
                    id: i as i64 + 1,
                }
            })
            .collect();
        out.sort_unstable();
        out
    }

    pub(crate) const PAIRS: [(u32, u32); 8] = [
        (1, 2),
        (1, 3),
        (2, 1),
        (2, 3),
        (3, 1),
        (3, 2),
        (4, 5),
        (5, 4),
    ];

    #[test]
    fn the_comparison_is_what_its_definition_says() {
        for seed in 1..20 {
            let packets = mixed_packets(400, seed);
            let c = compare_all(&PAIRS, &[1, 5], packets.iter().copied());
            let of = |lane: u32| packets.iter().filter(move |p| p.lane == lane);
            for (i, &(a, b)) in PAIRS.iter().enumerate() {
                let in_b = |sum: i64| of(b).any(|q| q.sum == sum);
                let shared: Vec<i64> = of(a).filter(|p| in_b(p.sum)).map(|p| p.id).collect();
                let span = shared
                    .iter()
                    .min()
                    .map(|&lo| (lo, *shared.iter().max().unwrap_or(&lo)));
                let missing: Vec<i64> = of(a)
                    .filter(|p| span.is_some_and(|(lo, hi)| (lo..=hi).contains(&p.id)))
                    .filter(|p| !in_b(p.sum))
                    .map(|p| p.id)
                    .collect();
                let want = PairCount {
                    shared: shared.len() as i64,
                    span,
                    missing: missing.len() as i64,
                    first_missing: missing.iter().min().copied(),
                };
                assert_eq!(c.counts()[i], want, "seed {seed} pair {a} {b}");
            }
            for (x, others) in [(1u32, [2u32, 3]), (5, [4, 4])] {
                for l in others {
                    let n = of(x)
                        .filter(|p| {
                            of(l).any(|q| (q.sum, q.seq, q.length) == (p.sum, p.seq, p.length))
                        })
                        .count();
                    assert_eq!(c.copies(x, l), n as i64, "seed {seed} {x} in {l}");
                }
            }
            // A lane that is not traced, and a lane of another stream.
            assert_eq!(c.copies(2, 1), 0);
            assert_eq!(c.copies(1, 4), 0);
        }
    }
}
