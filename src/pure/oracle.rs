//! Test support only: the tables of packets and kept values the store used
//! to keep in SQLite, as an oracle for what is now read from the segment
//! files. A store opened with `Store::open_with_oracle` (which only tests
//! call) also writes `oracle_packets` and `oracle_field_values`, with
//! exactly the rows and ids `packets` and `field_values` had, and removes
//! them with their file. Nothing the program ships writes or reads them.
//!
//! The statements here are the ones the store ran over those tables before
//! the segment files answered the same questions; tests run them against
//! the oracle tables and compare.

use crate::pure::sql::{Clock, Param, Query, bucket_width};

/// The oracle tables, their indexes and the views over them, made by a
/// store opened with the oracle.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS oracle_packets (
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL REFERENCES files(id),
  lane_id INTEGER NOT NULL REFERENCES lanes(id),
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  length INTEGER NOT NULL,
  receive_ns INTEGER,
  packet_ns INTEGER,
  apid INTEGER,
  ptype INTEGER,
  seq INTEGER,
  sum INTEGER NOT NULL,
  label TEXT
);
CREATE INDEX IF NOT EXISTS oracle_packets_receive ON oracle_packets (receive_ns, lane_id);
CREATE INDEX IF NOT EXISTS oracle_packets_packet ON oracle_packets (packet_ns, lane_id);
CREATE INDEX IF NOT EXISTS oracle_packets_lane_receive
  ON oracle_packets (lane_id, receive_ns, packet_ns);
CREATE INDEX IF NOT EXISTS oracle_packets_lane_packet
  ON oracle_packets (lane_id, packet_ns, receive_ns);
CREATE TABLE IF NOT EXISTS oracle_field_values (
  packet_id INTEGER NOT NULL REFERENCES oracle_packets(id),
  file_id INTEGER NOT NULL REFERENCES files(id),
  packet TEXT NOT NULL,
  field TEXT NOT NULL,
  num REAL,
  text TEXT
);
CREATE INDEX IF NOT EXISTS oracle_field_values_field ON oracle_field_values (field, num);
CREATE INDEX IF NOT EXISTS oracle_field_values_packet ON oracle_field_values (packet_id);
DROP VIEW IF EXISTS oracle_value_view;
CREATE VIEW oracle_value_view AS
  SELECT v.packet_id AS id, r.root AS run, l.source, f.rel AS file, p.apid, v.packet, v.field,
         v.num AS value, v.text,
         strftime('%Y-%m-%dT%H:%M:%f', p.receive_ns / 1000000000.0, 'unixepoch') AS receive_time,
         strftime('%Y-%m-%dT%H:%M:%f', p.packet_ns / 1000000000.0, 'unixepoch') AS packet_time,
         p.idx, p.receive_ns, p.packet_ns
  FROM oracle_field_values v
  JOIN oracle_packets p ON p.id = v.packet_id
  JOIN files f ON f.id = v.file_id
  JOIN lanes l ON l.id = p.lane_id
  JOIN runs r ON r.id = f.run_id;
DROP VIEW IF EXISTS oracle_packet_view;
CREATE VIEW oracle_packet_view AS
  SELECT p.id, r.root AS run, l.source, f.rel AS file, p.apid,
         CASE p.ptype WHEN 0 THEN 'tm' WHEN 1 THEN 'tc' END AS type,
         p.seq, p.length,
         strftime('%Y-%m-%dT%H:%M:%f', p.receive_ns / 1000000000.0, 'unixepoch') AS receive_time,
         strftime('%Y-%m-%dT%H:%M:%f', p.packet_ns / 1000000000.0, 'unixepoch') AS packet_time,
         p.label, p.idx, p.offset, p.ptype, p.receive_ns, p.packet_ns
  FROM oracle_packets p
  JOIN files f ON f.id = p.file_id
  JOIN lanes l ON l.id = p.lane_id
  JOIN runs r ON r.id = f.run_id;
";

pub const INSERT_PACKET: &str = "INSERT INTO oracle_packets
     (id, file_id, lane_id, idx, offset, length, receive_ns, packet_ns, apid, ptype, seq, sum, label)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

/// One kept field value of one packet: the number, the text, or both.
pub const INSERT_VALUE: &str = "INSERT INTO oracle_field_values
     (packet_id, file_id, packet, field, num, text) VALUES (?, ?, ?, ?, ?, ?)";

/// The ids of a file's packets, as `BETWEEN` wants them, from the file's
/// row (`first_packet`, `last_packet`).
const FILE_PACKETS: &str = "(SELECT first_packet FROM files WHERE id = ?1)
                                AND (SELECT last_packet FROM files WHERE id = ?1)";

/// Removes the oracle rows of one file. Takes the file id; the file's row
/// must still be there.
pub fn delete_file_packets() -> [String; 2] {
    [
        format!("DELETE FROM oracle_field_values WHERE packet_id BETWEEN {FILE_PACKETS}"),
        format!("DELETE FROM oracle_packets WHERE id BETWEEN {FILE_PACKETS}"),
    ]
}

/// What to write after `oracle_packets` and any alias in a query that
/// reads a window of every lane of a run: the index that finds packets by
/// this clock.
pub fn all_lanes(clock: Clock) -> &'static str {
    match clock {
        Clock::Receive => "INDEXED BY oracle_packets_receive",
        Clock::Packet => "INDEXED BY oracle_packets_packet",
        Clock::Order => "NOT INDEXED",
    }
}

/// What to write after `oracle_packets` and any alias in a query that
/// reads a window of one lane: the index that finds a lane's packets by
/// this clock.
pub fn one_lane(clock: Clock) -> &'static str {
    match clock {
        Clock::Receive => "INDEXED BY oracle_packets_lane_receive",
        Clock::Packet => "INDEXED BY oracle_packets_lane_packet",
        Clock::Order => "NOT INDEXED",
    }
}

const RUN_LANES: &str = "(SELECT id FROM lanes WHERE run_id = ?)";

/// Packet counts per lane and bucket, every packet counted. Columns: lane,
/// bucket, count.
pub fn packet_density(run: i64, clock: Clock, from: i64, to: i64, buckets: i64) -> Query {
    let c = clock.packet_column();
    let index = all_lanes(clock);
    Query::new(
        format!(
            "SELECT lane_id, ({c} - ?) / ? AS b, COUNT(*) FROM oracle_packets {index}
             WHERE {c} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             GROUP BY lane_id, b"
        ),
        vec![
            from.into(),
            bucket_width(from, to, buckets).into(),
            from.into(),
            to.into(),
            run.into(),
        ],
    )
}

/// One kept field of one lane over a window, reduced to the lowest and
/// highest value in each bucket. Columns: bucket, min, max, count.
#[allow(clippy::too_many_arguments)]
pub fn value_series(
    run: i64,
    clock: Clock,
    lane: i64,
    packet: &str,
    field: &str,
    from: i64,
    to: i64,
    buckets: i64,
) -> Query {
    let grid = (from, bucket_width(from, to, buckets));
    series_range(run, clock, lane, Some((packet, field)), grid, from, to)
}

/// How long after its own time each packet of a lane was received, in
/// milliseconds, by bucket. Columns: bucket, min, max, count.
pub fn lag_series(run: i64, clock: Clock, lane: i64, from: i64, to: i64, buckets: i64) -> Query {
    let grid = (from, bucket_width(from, to, buckets));
    series_range(run, clock, lane, None, grid, from, to)
}

fn series_range(
    run: i64,
    clock: Clock,
    lane: i64,
    field: Option<(&str, &str)>,
    grid: (i64, i64),
    lo: i64,
    hi: i64,
) -> Query {
    let c = clock.packet_column();
    let index = one_lane(clock);
    let mut params: Vec<Param> = vec![
        grid.0.into(),
        grid.1.into(),
        lane.into(),
        run.into(),
        lo.into(),
        hi.into(),
    ];
    let sql = match field {
        Some((packet, field)) => {
            params.push(packet.into());
            params.push(field.into());
            format!(
                "SELECT (p.{c} - ?) / ? AS b, MIN(v.num), MAX(v.num), COUNT(*)
                 FROM oracle_packets p {index}
                 CROSS JOIN oracle_field_values v ON v.packet_id = p.id
                 WHERE p.lane_id = ? AND p.lane_id IN {RUN_LANES} AND p.{c} BETWEEN ? AND ?
                   AND v.packet = ? AND v.field = ? AND v.num IS NOT NULL
                 GROUP BY b ORDER BY b"
            )
        }
        None => format!(
            "SELECT ({c} - ?) / ? AS b, MIN(receive_ns - packet_ns) / 1000000.0,
                    MAX(receive_ns - packet_ns) / 1000000.0, COUNT(*)
             FROM oracle_packets {index}
             WHERE lane_id = ? AND lane_id IN {RUN_LANES} AND {c} BETWEEN ? AND ?
               AND receive_ns IS NOT NULL AND packet_ns IS NOT NULL
             GROUP BY b ORDER BY b"
        ),
    };
    Query::new(sql, params)
}

/// Individual packets in a window. Columns: id, lane, time, seq, length.
pub fn packet_items(run: i64, clock: Clock, from: i64, to: i64, limit: i64) -> Query {
    let c = clock.packet_column();
    let index = all_lanes(clock);
    Query::new(
        format!(
            "SELECT id, lane_id, {c}, seq, length FROM oracle_packets {index}
             WHERE {c} BETWEEN ? AND ? AND lane_id IN {RUN_LANES}
             ORDER BY {c} LIMIT ?"
        ),
        vec![from.into(), to.into(), run.into(), limit.into()],
    )
}

/// One packet with its file and source.
pub fn packet_detail(id: i64) -> Query {
    Query::new(
        "SELECT p.id, p.idx, p.offset, p.length, p.receive_ns, p.packet_ns, p.apid, p.ptype,
                p.seq, p.label, p.lane_id, f.path, f.rel, l.source, f.run_id, f.format, p.sum
         FROM oracle_packets p JOIN files f ON f.id = p.file_id JOIN lanes l ON l.id = p.lane_id
         WHERE p.id = ?",
        vec![id.into()],
    )
}

/// A run's findings in the order the page lists them, with their packets'
/// times.
pub fn run_findings(run: i64) -> Query {
    Query::new(
        "SELECT x.id, x.severity, x.kind, x.message, x.lane_id, x.file_id, x.packet_id,
                p.receive_ns, p.packet_ns,
                COALESCE((SELECT f.rel FROM files f WHERE f.id = x.file_id), '')
         FROM findings x LEFT JOIN oracle_packets p ON p.id = x.packet_id
         WHERE x.run_id = ?
         ORDER BY x.severity = 'info', COALESCE(p.receive_ns, p.packet_ns, x.packet_id, 0), x.id",
        vec![run.into()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn density_reads_the_oracle_by_the_clock() {
        let q = packet_density(3, Clock::Packet, 100, 199, 10);
        assert!(q.sql.contains("packet_ns BETWEEN"));
        assert!(
            q.sql
                .contains("oracle_packets INDEXED BY oracle_packets_packet")
        );
        assert_eq!(
            q.params,
            vec![100.into(), 10.into(), 100.into(), 199.into(), 3.into()]
        );
    }
}
