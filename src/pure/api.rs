//! The web API as values: a request becomes an authorised [`Command`] or a
//! refusal, and query results become JSON responses. The shell runs the
//! command in between.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Value, json};

use crate::pure::ccsds::PrimaryHeader;
use crate::pure::config::Config;
use crate::pure::format::{decode_fields, hex};
use crate::pure::http::{Method, Request, Response};
use crate::pure::ingest::{LANE_LOG, ptype_from_code, whole_packet_header};
use crate::pure::sql::{Cell, Clock, Table};
use crate::pure::time::format_iso;

/// Header that carries the access token on API calls.
pub const TOKEN_HEADER: &str = "x-packetlane-token";
/// Most bytes of a packet shown as a hex dump.
pub const MAX_HEX_BYTES: usize = 4096;
const MAX_SQL_LEN: usize = 20_000;
const MAX_INGEST_PATHS: usize = 500;

/// What a request must match to be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guard {
    pub port: u16,
    pub token: String,
}

/// A time window on one clock, in absolute values of that clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub run: i64,
    pub clock: Clock,
    /// The value the browser treats as zero; responses are relative to it.
    pub origin: i64,
    pub from: i64,
    pub to: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Page,
    Runs,
    Run {
        run: i64,
    },
    Density {
        window: Window,
        buckets: i64,
    },
    Items {
        window: Window,
        limit: i64,
    },
    Packet {
        id: i64,
    },
    Log {
        id: i64,
    },
    Search {
        run: i64,
        origin: i64,
        needle: String,
    },
    Query {
        sql: String,
    },
    Browse {
        path: Option<String>,
    },
    Ingest {
        paths: Vec<String>,
    },
}

/// Compares two strings in time that depends only on their lengths.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A first check on SQL typed by the user: one statement, and one that
/// reads. The store enforces the same on its side; this gives a clear
/// message early.
pub fn check_user_sql(sql: &str) -> Result<(), String> {
    let trimmed = sql.trim().trim_end_matches(';').trim_end();
    if trimmed.is_empty() {
        return Err("Enter a SQL statement".to_string());
    }
    if trimmed.len() > MAX_SQL_LEN {
        return Err("SQL statement is too long".to_string());
    }
    if trimmed.contains(';') {
        return Err("Run one SQL statement at a time".to_string());
    }
    let first: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase();
    if !matches!(first.as_str(), "SELECT" | "WITH" | "EXPLAIN" | "VALUES") {
        return Err("Only SELECT statements are allowed".to_string());
    }
    Ok(())
}

fn int(req: &Request, name: &str) -> Result<i64, Response> {
    req.param(name)
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or_else(|| Response::error(400, &format!("Invalid parameter: {name}")))
}

fn window(req: &Request) -> Result<Window, Response> {
    let clock = req
        .param("clock")
        .and_then(Clock::parse)
        .ok_or_else(|| Response::error(400, "Invalid parameter: clock"))?;
    let origin = int(req, "origin")?;
    let from = origin.checked_add(int(req, "from")?);
    let to = origin.checked_add(int(req, "to")?);
    match (from, to) {
        // The span must fit too, or arithmetic on it in the store would not.
        (Some(from), Some(to)) if from <= to && to.checked_sub(from).is_some() => Ok(Window {
            run: int(req, "run")?,
            clock,
            origin,
            from,
            to,
        }),
        _ => Err(Response::error(400, "Invalid time window")),
    }
}

fn body_json(req: &Request) -> Result<Value, Response> {
    serde_json::from_slice(&req.body).map_err(|_| Response::error(400, "Request body must be JSON"))
}

/// Decides whether a request is allowed and what it asks for.
///
/// A loopback port is reachable by any page open in the same browser, so
/// every request must name this server as its Host (which stops a foreign
/// name being pointed at it), must not come from another origin, and must
/// carry the token printed at launch.
pub fn route(guard: &Guard, req: &Request) -> Result<Command, Response> {
    let allowed_hosts = [
        format!("127.0.0.1:{}", guard.port),
        format!("localhost:{}", guard.port),
    ];
    if !req
        .header("host")
        .is_some_and(|h| allowed_hosts.iter().any(|a| a == h))
    {
        return Err(Response::error(403, "Unexpected Host header"));
    }
    if let Some(origin) = req.header("origin")
        && !allowed_hosts
            .iter()
            .any(|a| origin == format!("http://{a}"))
    {
        return Err(Response::error(403, "Request from another origin"));
    }

    if req.path == "/" {
        if req.method != Method::Get {
            return Err(Response::error(405, "Method not allowed"));
        }
        if !constant_time_eq(req.param("t").unwrap_or(""), &guard.token) {
            return Err(Response::error(
                401,
                "Open the address printed when packetlane started",
            ));
        }
        return Ok(Command::Page);
    }

    if req
        .header("sec-fetch-site")
        .is_some_and(|s| s != "same-origin")
    {
        return Err(Response::error(403, "Request from another site"));
    }
    if !constant_time_eq(req.header(TOKEN_HEADER).unwrap_or(""), &guard.token) {
        return Err(Response::error(401, "Missing or invalid access token"));
    }

    match (req.method, req.path.as_str()) {
        (Method::Get, "/api/runs") => Ok(Command::Runs),
        (Method::Get, "/api/run") => Ok(Command::Run {
            run: int(req, "run")?,
        }),
        (Method::Get, "/api/density") => Ok(Command::Density {
            window: window(req)?,
            buckets: int(req, "buckets")?.clamp(1, 4000),
        }),
        (Method::Get, "/api/items") => Ok(Command::Items {
            window: window(req)?,
            limit: int(req, "limit")?.clamp(1, 5000),
        }),
        (Method::Get, "/api/packet") => Ok(Command::Packet {
            id: int(req, "id")?,
        }),
        (Method::Get, "/api/log") => Ok(Command::Log {
            id: int(req, "id")?,
        }),
        (Method::Get, "/api/search") => {
            let needle = req.param("q").unwrap_or("").trim();
            if needle.is_empty() || needle.len() > 200 {
                return Err(Response::error(400, "Invalid parameter: q"));
            }
            Ok(Command::Search {
                run: int(req, "run")?,
                origin: int(req, "origin")?,
                needle: needle.to_string(),
            })
        }
        (Method::Get, "/api/browse") => Ok(Command::Browse {
            path: req
                .param("path")
                .filter(|p| !p.is_empty())
                .map(str::to_string),
        }),
        (Method::Post, "/api/query") => {
            let body = body_json(req)?;
            let sql = body.get("sql").and_then(Value::as_str).unwrap_or("");
            check_user_sql(sql).map_err(|e| Response::error(400, &e))?;
            Ok(Command::Query {
                sql: sql.trim().trim_end_matches(';').to_string(),
            })
        }
        (Method::Post, "/api/ingest") => {
            let body = body_json(req)?;
            let paths: Option<Vec<String>> = body
                .get("paths")
                .and_then(Value::as_array)
                .and_then(|a| a.iter().map(|v| v.as_str().map(str::to_string)).collect());
            match paths {
                Some(paths) if !paths.is_empty() && paths.len() <= MAX_INGEST_PATHS => {
                    Ok(Command::Ingest { paths })
                }
                _ => Err(Response::error(400, "Provide 1 to 500 paths")),
            }
        }
        (
            _,
            "/api/runs" | "/api/run" | "/api/density" | "/api/items" | "/api/packet" | "/api/log"
            | "/api/search" | "/api/browse" | "/api/query" | "/api/ingest",
        ) => Err(Response::error(405, "Method not allowed")),
        _ => Err(Response::error(404, "Not found")),
    }
}

// ---- responses -------------------------------------------------------------

fn cell(row: &[Cell], i: usize) -> &Cell {
    row.get(i).unwrap_or(&Cell::Null)
}

fn opt_int(row: &[Cell], i: usize) -> Option<i64> {
    cell(row, i).int()
}

fn text(row: &[Cell], i: usize) -> &str {
    cell(row, i).text().unwrap_or("")
}

fn offset(value: Option<i64>, origin: Option<i64>) -> Value {
    match (value, origin) {
        (Some(v), Some(o)) => v.checked_sub(o).map_or(Value::Null, Value::from),
        _ => Value::Null,
    }
}

pub fn render_runs(runs: &Table) -> Response {
    let list: Vec<Value> = runs
        .rows
        .iter()
        .map(|r| {
            json!({
                "id": cell(r, 0), "root": cell(r, 1),
                "ingested": opt_int(r, 2).map(format_iso),
                "files": cell(r, 3), "packets": cell(r, 4), "entries": cell(r, 5),
                "problems": cell(r, 6),
            })
        })
        .collect();
    Response::json(200, &json!({ "runs": list }))
}

/// Start, end and size of what a run holds on one clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Extent {
    min: Option<i64>,
    max: Option<i64>,
    count: i64,
}

impl Extent {
    fn add(&mut self, min: Option<i64>, max: Option<i64>, count: i64) {
        self.min = [self.min, min].into_iter().flatten().min();
        self.max = [self.max, max].into_iter().flatten().max();
        self.count += count;
    }

    fn json(&self) -> Value {
        json!({
            "origin": self.min.map(|v| v.to_string()),
            "span": offset(self.max, self.min),
            "count": self.count,
        })
    }
}

/// Everything the page needs to draw a run: clocks, lanes, files, findings.
pub fn render_run(run: &Table, lanes: &Table, files: &Table, findings: &Table) -> Response {
    let Some(run_row) = run.rows.first() else {
        return Response::error(404, "Run not found");
    };
    let config = Config::parse(text(run_row, 2)).unwrap_or_default();

    let (mut receive, mut packet, mut order) =
        (Extent::default(), Extent::default(), Extent::default());
    for r in &lanes.rows {
        receive.add(opt_int(r, 7), opt_int(r, 8), opt_int(r, 9).unwrap_or(0));
        packet.add(opt_int(r, 10), opt_int(r, 11), opt_int(r, 12).unwrap_or(0));
        if text(r, 2) != LANE_LOG {
            order.add(opt_int(r, 13), opt_int(r, 14), opt_int(r, 6).unwrap_or(0));
        }
    }

    let lane_list: Vec<Value> = lanes
        .rows
        .iter()
        .map(|r| {
            let apid = opt_int(r, 3).filter(|a| *a >= 0);
            let ptype = opt_int(r, 4).and_then(ptype_from_code);
            let def = match (apid, ptype) {
                (Some(a), Some(t)) => u16::try_from(a).ok().and_then(|a| config.packet_def(a, t)),
                _ => None,
            };
            let range =
                |lo: usize, hi: usize, extent: &Extent| match (opt_int(r, lo), opt_int(r, hi)) {
                    (Some(a), Some(b)) => {
                        json!([offset(Some(a), extent.min), offset(Some(b), extent.min)])
                    }
                    _ => Value::Null,
                };
            let is_log = text(r, 2) == LANE_LOG;
            json!({
                "id": cell(r, 0), "source": cell(r, 1), "kind": cell(r, 2),
                "apid": apid, "command": opt_int(r, 4) == Some(1),
                "name": def.map(|d| d.name.as_str()),
                "file": cell(r, 15), "count": cell(r, 6),
                "receive": range(7, 8, &receive),
                "packet": range(10, 11, &packet),
                "order": if is_log { Value::Null } else { range(13, 14, &order) },
            })
        })
        .collect();

    let file_list: Vec<Value> = files
        .rows
        .iter()
        .map(|r| {
            json!({
                "id": cell(r, 0), "rel": cell(r, 1), "source": cell(r, 2), "format": cell(r, 3),
                "size": cell(r, 4), "packets": cell(r, 5), "entries": cell(r, 6), "note": cell(r, 7),
            })
        })
        .collect();

    let finding_list: Vec<Value> = findings
        .rows
        .iter()
        .map(|r| {
            json!({
                "id": cell(r, 0), "severity": cell(r, 1), "kind": cell(r, 2), "message": cell(r, 3),
                "lane": cell(r, 4), "file": cell(r, 9), "packet": cell(r, 6),
                "receive": offset(opt_int(r, 7), receive.min),
                "packetTime": offset(opt_int(r, 8), packet.min),
                "order": offset(opt_int(r, 6), order.min),
            })
        })
        .collect();

    Response::json(
        200,
        &json!({
            "id": cell(run_row, 0), "root": cell(run_row, 1),
            "clocks": { "receive": receive.json(), "packet": packet.json(), "order": order.json() },
            "lanes": lane_list, "files": file_list, "findings": finding_list,
        }),
    )
}

/// Counts per lane and bucket. Each table has columns lane, bucket, count.
pub fn render_density(window: &Window, width: i64, tables: &[&Table]) -> Response {
    let mut lanes: BTreeMap<i64, Vec<[i64; 2]>> = BTreeMap::new();
    let mut total = 0i64;
    for table in tables {
        for r in &table.rows {
            if let (Some(lane), Some(bucket), Some(count)) =
                (opt_int(r, 0), opt_int(r, 1), opt_int(r, 2))
            {
                lanes.entry(lane).or_default().push([bucket, count]);
                total += count;
            }
        }
    }
    Response::json(
        200,
        &json!({
            "from": window.from.saturating_sub(window.origin),
            "width": width, "total": total, "lanes": lanes,
        }),
    )
}

/// Individual packets (id, lane, time, seq, length) and log entries
/// (id, lane, time, text), with times relative to the window's origin.
pub fn render_items(window: &Window, packets: &Table, logs: Option<&Table>) -> Response {
    let relative = |table: &Table| -> Vec<Value> {
        table
            .rows
            .iter()
            .map(|r| {
                json!([
                    cell(r, 0),
                    cell(r, 1),
                    offset(opt_int(r, 2), Some(window.origin)),
                    cell(r, 3),
                    cell(r, 4)
                ])
            })
            .collect()
    };
    Response::json(
        200,
        &json!({
            "packets": relative(packets),
            "logs": logs.map(relative).unwrap_or_default(),
            "truncated": packets.truncated || logs.is_some_and(|t| t.truncated),
        }),
    )
}

/// Where a packet's bytes are: (file path, offset, length, checksum, run).
pub fn packet_location(detail: &Table) -> Option<(String, u64, usize, i64, i64)> {
    let r = detail.rows.first()?;
    Some((
        text(r, 11).to_string(),
        u64::try_from(opt_int(r, 2)?).ok()?,
        usize::try_from(opt_int(r, 3)?).ok()?,
        opt_int(r, 16)?,
        opt_int(r, 14)?,
    ))
}

fn header_json(h: &PrimaryHeader) -> Value {
    json!({
        "version": h.version,
        "command": matches!(h.packet_type, crate::pure::ccsds::PacketType::Command),
        "secondary": h.has_secondary_header,
        "apid": h.apid,
        "flags": format!("{:?}", h.seq_flags).to_lowercase(),
        "count": h.seq_count,
        "length": h.data_length,
    })
}

/// One packet in full. `bytes` is the packet as read back from its log, or
/// the reason it could not be read.
pub fn render_packet(detail: &Table, bytes: Result<&[u8], &str>, config_text: &str) -> Response {
    let Some(r) = detail.rows.first() else {
        return Response::error(404, "Packet not found");
    };
    let config = Config::parse(config_text).unwrap_or_default();
    let header = bytes.ok().and_then(whole_packet_header);
    let def = header.and_then(|h| config.packet_def(h.apid, h.packet_type));
    let fields = match (def, bytes) {
        (Some(def), Ok(b)) => json!(decode_fields(def, b)),
        _ => json!([]),
    };
    Response::json(
        200,
        &json!({
            "id": cell(r, 0), "index": cell(r, 1), "offset": cell(r, 2), "length": cell(r, 3),
            "receive": opt_int(r, 4).map(format_iso),
            "packet": opt_int(r, 5).map(format_iso),
            "apid": cell(r, 6), "command": opt_int(r, 7) == Some(1), "count": cell(r, 8),
            "label": cell(r, 9), "lane": cell(r, 10),
            "file": cell(r, 12), "source": cell(r, 13), "format": cell(r, 15),
            "name": def.map(|d| d.name.as_str()),
            "description": def.map(|d| d.description.as_str()).filter(|d| !d.is_empty()),
            "header": header.as_ref().map(header_json),
            "hex": bytes.ok().map(|b| hex(&b[..b.len().min(MAX_HEX_BYTES)])),
            "fields": fields,
            "error": bytes.err(),
        }),
    )
}

pub fn render_log(detail: &Table) -> Response {
    let Some(r) = detail.rows.first() else {
        return Response::error(404, "Log entry not found");
    };
    Response::json(
        200,
        &json!({
            "id": cell(r, 0), "offset": cell(r, 1),
            "time": opt_int(r, 2).map(format_iso),
            "text": cell(r, 3), "lane": cell(r, 4), "file": cell(r, 5), "source": cell(r, 6),
        }),
    )
}

/// Log entries matching a search: id, lane, time relative to `origin`, text.
pub fn render_search(origin: i64, hits: &Table) -> Response {
    let rows: Vec<Value> = hits
        .rows
        .iter()
        .map(|r| {
            json!([
                cell(r, 0),
                cell(r, 1),
                offset(opt_int(r, 2), Some(origin)),
                cell(r, 3)
            ])
        })
        .collect();
    Response::json(200, &json!({ "logs": rows, "truncated": hits.truncated }))
}

pub fn render_query(result: Result<&Table, &str>) -> Response {
    match result {
        Ok(table) => Response::json(200, table),
        Err(message) => Response::error(400, message),
    }
}

/// One row of the file browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowseEntry {
    pub name: String,
    pub path: String,
    pub dir: bool,
    pub size: u64,
    pub format: Option<&'static str>,
    pub ingested: bool,
    pub packets: i64,
    pub entries: i64,
    pub note: String,
}

/// A folder as the file browser shows it. With no `path`, the entries are
/// the allowed root folders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listing {
    pub path: Option<String>,
    pub parent: Option<String>,
    pub entries: Vec<BrowseEntry>,
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pure::http::{Parsed, parse_request};

    fn guard() -> Guard {
        Guard {
            port: 8737,
            token: "s3cret".to_string(),
        }
    }

    fn request(text: &str) -> Request {
        match parse_request(text.as_bytes()) {
            Parsed::Complete(r) => r,
            other => panic!("{other:?}"),
        }
    }

    fn get(target: &str, extra: &str) -> Result<Command, u16> {
        let text = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:8737\r\n{extra}\r\n");
        route(&guard(), &request(&text)).map_err(|r| r.status)
    }

    const TOKEN: &str = "X-Packetlane-Token: s3cret\r\n";

    #[test]
    fn the_page_needs_the_token_in_its_address() {
        assert_eq!(get("/?t=s3cret", ""), Ok(Command::Page));
        assert_eq!(get("/", ""), Err(401));
        assert_eq!(get("/?t=wrong", ""), Err(401));
        assert_eq!(get("/?t=s3cre", ""), Err(401));
    }

    #[test]
    fn api_calls_need_the_token_header() {
        assert_eq!(get("/api/runs", TOKEN), Ok(Command::Runs));
        assert_eq!(get("/api/runs", ""), Err(401));
        assert_eq!(get("/api/runs?t=s3cret", ""), Err(401));
        assert_eq!(get("/api/runs", "X-Packetlane-Token: nope\r\n"), Err(401));
    }

    #[test]
    fn other_hosts_origins_and_sites_are_refused() {
        let with_host = |host: &str| {
            let text = format!("GET /api/runs HTTP/1.1\r\nHost: {host}\r\n{TOKEN}\r\n");
            route(&guard(), &request(&text)).map_err(|r| r.status)
        };
        assert_eq!(with_host("localhost:8737"), Ok(Command::Runs));
        assert_eq!(with_host("evil.example:8737"), Err(403));
        assert_eq!(with_host("127.0.0.1:9999"), Err(403));
        assert_eq!(with_host("127.0.0.1"), Err(403));
        let no_host = request(&format!("GET /api/runs HTTP/1.1\r\n{TOKEN}\r\n"));
        assert_eq!(route(&guard(), &no_host).map_err(|r| r.status), Err(403));

        let origin = |o: &str| get("/api/runs", &format!("{TOKEN}Origin: {o}\r\n"));
        assert_eq!(origin("http://127.0.0.1:8737"), Ok(Command::Runs));
        assert_eq!(origin("http://evil.example"), Err(403));
        assert_eq!(origin("null"), Err(403));
        assert_eq!(origin("https://127.0.0.1:8737"), Err(403));

        let site = |s: &str| get("/api/runs", &format!("{TOKEN}Sec-Fetch-Site: {s}\r\n"));
        assert_eq!(site("same-origin"), Ok(Command::Runs));
        assert_eq!(site("cross-site"), Err(403));
        assert_eq!(site("same-site"), Err(403));
    }

    #[test]
    fn windows_are_relative_to_the_origin() {
        let cmd = get(
            "/api/density?run=2&clock=receive&origin=1000&from=-10&to=500&buckets=99999",
            TOKEN,
        );
        assert_eq!(
            cmd,
            Ok(Command::Density {
                window: Window {
                    run: 2,
                    clock: Clock::Receive,
                    origin: 1000,
                    from: 990,
                    to: 1500
                },
                buckets: 4000,
            })
        );
        for bad in [
            "/api/density?run=2&clock=receive&origin=0&from=5&to=4&buckets=10",
            "/api/density?run=2&clock=sundial&origin=0&from=0&to=4&buckets=10",
            "/api/density?run=2&clock=receive&origin=9223372036854775807&from=1&to=4&buckets=10",
            "/api/density?run=x&clock=receive&origin=0&from=0&to=4&buckets=10",
            "/api/density?run=2&clock=receive&origin=0&from=-9223372036854775807&to=9000000000000000000&buckets=10",
            "/api/items?run=2&clock=receive&origin=0&from=0&to=4",
            "/api/search?run=1&origin=0&q=%20",
        ] {
            assert_eq!(get(bad, TOKEN), Err(400), "{bad}");
        }
        assert_eq!(get("/api/nope", TOKEN), Err(404));
        assert_eq!(get("/api/query", TOKEN), Err(405));
    }

    fn post(path: &str, body: &str) -> Result<Command, u16> {
        let text = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:8737\r\n{TOKEN}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        route(&guard(), &request(&text)).map_err(|r| r.status)
    }

    #[test]
    fn query_bodies_are_checked() {
        assert_eq!(
            post("/api/query", r#"{"sql":" select 1; "}"#),
            Ok(Command::Query {
                sql: "select 1".to_string()
            })
        );
        for bad in [
            r#"{"sql":"DELETE FROM packets"}"#,
            r#"{"sql":"select 1; drop table runs"}"#,
            r#"{"sql":"ATTACH 'x' AS y"}"#,
            r#"{"sql":"PRAGMA query_only = 0"}"#,
            r#"{"sql":""}"#,
            r#"{"nope":1}"#,
            "not json",
        ] {
            assert_eq!(post("/api/query", bad), Err(400), "{bad}");
        }
        assert_eq!(post("/", "{}"), Err(405));
    }

    #[test]
    fn ingest_bodies_are_checked() {
        assert_eq!(
            post("/api/ingest", r#"{"paths":["/r/a"]}"#),
            Ok(Command::Ingest {
                paths: vec!["/r/a".to_string()]
            })
        );
        for bad in [r#"{"paths":[]}"#, r#"{"paths":[1]}"#, r#"{"paths":"/r/a"}"#] {
            assert_eq!(post("/api/ingest", bad), Err(400), "{bad}");
        }
    }

    #[test]
    fn user_sql_rules() {
        assert!(check_user_sql("SELECT 1").is_ok());
        assert!(check_user_sql("  with x as (select 1) select * from x ;").is_ok());
        assert!(check_user_sql("explain query plan select 1").is_ok());
        assert!(check_user_sql("").is_err());
        assert!(check_user_sql("vacuum into '/tmp/x'").is_err());
        assert!(check_user_sql("insert into runs values (1)").is_err());
        assert!(check_user_sql(&format!("select '{}'", "a".repeat(MAX_SQL_LEN))).is_err());
    }

    #[test]
    fn token_comparison() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    fn table(rows: Vec<Vec<Cell>>) -> Table {
        Table {
            columns: vec![],
            rows,
            truncated: false,
        }
    }

    #[test]
    fn run_summary_is_relative_to_each_clock() {
        use Cell::{Int, Null, Text};
        let t = |s: &str| Text(s.to_string());
        let run = table(vec![vec![
            Int(1),
            t("/r"),
            t("[[packet]]\napid = 100\nname = \"HK\""),
            Int(0),
        ]]);
        let lanes = table(vec![
            vec![
                Int(5),
                t("a"),
                t("packet"),
                Int(100),
                Int(0),
                Int(0),
                Int(10),
                Int(1_000),
                Int(1_900),
                Int(10),
                Null,
                Null,
                Int(0),
                Int(21),
                Int(30),
                t(""),
            ],
            vec![
                Int(6),
                t("a"),
                t("log"),
                Int(-1),
                Int(-1),
                Int(3),
                Int(4),
                Int(900),
                Int(2_000),
                Int(4),
                Int(900),
                Int(2_000),
                Int(4),
                Null,
                Null,
                t("a/x.log"),
            ],
        ]);
        let findings = table(vec![vec![
            Int(1),
            t("problem"),
            t("gap"),
            t("3 packet(s) missing"),
            Int(5),
            Int(3),
            Int(25),
            Int(1_500),
            Null,
            t("a/t.bin"),
        ]]);
        let body: Value =
            serde_json::from_slice(&render_run(&run, &lanes, &table(vec![]), &findings).body)
                .unwrap();
        assert_eq!(
            body["clocks"]["receive"],
            json!({"origin": "900", "span": 1100, "count": 14})
        );
        assert_eq!(
            body["clocks"]["packet"],
            json!({"origin": "900", "span": 1100, "count": 4})
        );
        assert_eq!(
            body["clocks"]["order"],
            json!({"origin": "21", "span": 9, "count": 10})
        );
        assert_eq!(body["lanes"][0]["name"], "HK");
        assert_eq!(body["lanes"][0]["receive"], json!([100, 1000]));
        assert_eq!(body["lanes"][0]["packet"], Value::Null);
        assert_eq!(body["lanes"][0]["order"], json!([0, 9]));
        assert_eq!(body["lanes"][1]["order"], Value::Null);
        assert_eq!(body["lanes"][1]["apid"], Value::Null);
        assert_eq!(body["findings"][0]["receive"], 600);
        assert_eq!(body["findings"][0]["packetTime"], Value::Null);
        assert_eq!(body["findings"][0]["order"], 4);
        assert_eq!(
            render_run(&table(vec![]), &lanes, &table(vec![]), &findings).status,
            404
        );
    }

    #[test]
    fn packet_detail_decodes_fields_when_bytes_are_available() {
        use Cell::{Int, Null, Text};
        let t = |s: &str| Text(s.to_string());
        let detail = table(vec![vec![
            Int(9),
            Int(0),
            Int(128),
            Int(8),
            Int(1_000_000_000),
            Null,
            Int(100),
            Int(0),
            Int(5),
            Null,
            Int(5),
            t("/r/a/t.bin"),
            t("a/t.bin"),
            t("a"),
            Int(1),
            t("cosmos5"),
            Int(77),
        ]]);
        assert_eq!(
            packet_location(&detail),
            Some(("/r/a/t.bin".to_string(), 128, 8, 77, 1))
        );
        let config = "[[packet]]\napid = 100\nname = \"HK\"\n[[packet.field]]\nname = \"MODE\"\nbit_offset = 48\nbit_length = 8\nlabels = { \"2\" = \"RUN\" }";
        let bytes = crate::pure::synth::packet(100, 5, &[2, 0xFF]);
        let body: Value =
            serde_json::from_slice(&render_packet(&detail, Ok(&bytes), config).body).unwrap();
        assert_eq!(body["name"], "HK");
        assert_eq!(body["receive"], "1970-01-01T00:00:01.000000000Z");
        assert_eq!(body["header"]["count"], 5);
        assert_eq!(body["hex"], "0064c00500010 2ff".replace(' ', ""));
        assert_eq!(body["fields"][0]["label"], "RUN");
        assert_eq!(body["error"], Value::Null);

        let body: Value =
            serde_json::from_slice(&render_packet(&detail, Err("file is gone"), config).body)
                .unwrap();
        assert_eq!(body["error"], "file is gone");
        assert_eq!(body["hex"], Value::Null);
        assert_eq!(body["fields"], json!([]));
    }
}
