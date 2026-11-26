//! The loopback web server: sockets, threads, and running commands against
//! the store. Parsing, access decisions and response bodies come from
//! `pure::http` and `pure::api`.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::pure::api::{
    self, Command, Guard, packet_location, render_density, render_items, render_log, render_packet,
    render_query, render_run, render_runs, render_search, render_series,
};
use crate::pure::checksum::fnv1a;
use crate::pure::config::Config;
use crate::pure::format::hex;
use crate::pure::http::{MAX_BODY, MAX_HEAD, Parsed, Response, parse_request};
use crate::pure::sql::{self, bucket_width};
use crate::shell::browse;
use crate::shell::files::read_back;
use crate::shell::ingest::{components, ingest_targets};
use crate::shell::store::{Result, Store};

/// The whole page: one document with its style and script inline, so the
/// server has exactly one thing to serve besides the API.
const PAGE: &str = concat!(
    "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    "<title>packetlane</title>\n<link rel=\"icon\" href=\"data:,\">\n<style>\n",
    include_str!("../../web/style.css"),
    "</style>\n</head>\n<body>\n",
    include_str!("../../web/body.html"),
    "<script>\n",
    include_str!("../../web/app.js"),
    "</script>\n</body>\n</html>\n"
);

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest a client may take to send one whole request.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
const API_BUDGET: Duration = Duration::from_secs(30);
const QUERY_BUDGET: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 32;
/// Most bytes of one logged item read back for the inspector.
const MAX_ITEM_BYTES: usize = 128 * 1024;

pub struct Options {
    pub db: PathBuf,
    /// Folders the file browser may show. Canonical.
    pub roots: Vec<PathBuf>,
    pub config: Option<PathBuf>,
    /// The user's own configuration file, for runs that have none.
    pub user_config: Option<PathBuf>,
    /// 0 picks any free port.
    pub port: u16,
}

struct Shared {
    guard: Guard,
    db: PathBuf,
    roots: Vec<PathBuf>,
    root_parts: Vec<Vec<String>>,
    config: Option<PathBuf>,
    user_config: Option<PathBuf>,
    /// Held while ingesting: one writer at a time.
    writer: Mutex<()>,
    connections: AtomicUsize,
}

pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
}

/// Sixteen random bytes as hex, from the operating system.
fn new_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    match File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)) {
        Ok(()) => Ok(hex(&bytes)),
        Err(_) => {
            // No such device here. The standard library seeds its hash maps
            // from the operating system's random source; draw from that.
            use std::hash::{BuildHasher, Hasher};
            let mut out = String::new();
            for _ in 0..2 {
                let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
                hasher.write_u64(0);
                out.push_str(&format!("{:016x}", hasher.finish()));
            }
            Ok(out)
        }
    }
}

impl Server {
    /// Binds to loopback only and prepares the store.
    pub fn bind(options: Options) -> Result<Server> {
        let mut root_parts = Vec::new();
        for root in &options.roots {
            let parts = components(root)
                .filter(|p| !p.is_empty())
                .ok_or_else(|| format!("{}: invalid root folder", root.display()))?;
            root_parts.push(parts);
        }
        // Create the store if it is not there, so readers can open it.
        drop(Store::open(&options.db)?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))?;
        let port = listener.local_addr()?.port();
        Ok(Server {
            listener,
            shared: Arc::new(Shared {
                guard: Guard {
                    port,
                    token: new_token()?,
                },
                db: options.db,
                roots: options.roots,
                root_parts,
                config: options.config,
                user_config: options.user_config,
                writer: Mutex::new(()),
                connections: AtomicUsize::new(0),
            }),
        })
    }

    pub fn port(&self) -> u16 {
        self.shared.guard.port
    }

    pub fn token(&self) -> &str {
        &self.shared.guard.token
    }

    /// The address to open in a browser. It carries the access token.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/?t={}", self.port(), self.token())
    }

    /// Serves until the process ends.
    pub fn run(self) {
        for stream in self.listener.incoming().flatten() {
            let shared = Arc::clone(&self.shared);
            if shared.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                shared.connections.fetch_sub(1, Ordering::SeqCst);
                respond(stream, &Response::error(503, "Too many connections"));
                continue;
            }
            std::thread::spawn(move || {
                handle(stream, &shared);
                shared.connections.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

fn respond(mut stream: TcpStream, response: &Response) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.write_all(&response.to_bytes());
    let _ = stream.shutdown(Shutdown::Write);
}

fn handle(mut stream: TcpStream, shared: &Shared) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    // A sender that trickles bytes would otherwise hold a connection open
    // for as long as it liked.
    let started = Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let response = loop {
        match parse_request(&buf) {
            Parsed::Complete(request) => {
                break match api::route(&shared.guard, &request) {
                    Ok(command) => execute(shared, command)
                        .unwrap_or_else(|e| Response::error(500, &e.to_string())),
                    Err(refusal) => refusal,
                };
            }
            Parsed::Bad(status, reason) => break Response::error(status, reason),
            Parsed::Partial => {}
        }
        if started.elapsed() > REQUEST_DEADLINE {
            return;
        }
        if buf.len() > MAX_HEAD + MAX_BODY + 4 {
            break Response::error(413, "Request too large");
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    respond(stream, &response);
}

/// Reads one logged item back from its file and checks it is still the
/// bytes that were ingested.
fn read_item(
    path: &str,
    roots: &[Vec<String>],
    config: &Config,
    offset: u64,
    length: usize,
    sum: i64,
) -> std::result::Result<Vec<u8>, String> {
    if length > MAX_ITEM_BYTES {
        return Err("Too large to show".to_string());
    }
    // The path comes from the store, which may hold runs ingested from
    // elsewhere, and the file may have been swapped since. Resolve it again
    // and serve it only if it is still a plain file inside the roots.
    let canonical = browse::resolve(path, roots).map_err(|(_, reason)| reason)?;
    if !canonical.is_file() {
        return Err("Not a file".to_string());
    }
    let same = |bytes: &[u8]| fnv1a(bytes) as i64 == sum;
    read_back(&canonical, config, offset, length, same)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "File changed since ingest; ingest it again".to_string())
}

fn execute(shared: &Shared, command: Command) -> Result<Response> {
    let reader = || Store::open_read_only(&shared.db, API_BUDGET);
    Ok(match command {
        Command::Page => Response::html(PAGE),
        Command::Runs => render_runs(&reader()?.query(&sql::runs(), 1000)?),
        Command::Run { run } => {
            let store = reader()?;
            // If the list of kept fields cannot be read the run still
            // opens, with only the plots that need no list.
            let series = store
                .query(&sql::run_series(run), 10_000)
                .unwrap_or_else(|_| sql::Table {
                    columns: Vec::new(),
                    rows: Vec::new(),
                    truncated: false,
                });
            render_run(
                &store.query(&sql::run_row(run), 1)?,
                &store.query(&sql::run_lanes(run), 100_000)?,
                &store.query(&sql::run_files(run), 100_000)?,
                &store.query(&sql::run_findings(run), 10_000)?,
                &series,
            )
        }
        Command::Density { window, buckets } => {
            let store = reader()?;
            let w = &window;
            let meta = store.query(&sql::coarse_meta(w.run, w.clock), 1)?;
            let coarse = meta
                .rows
                .first()
                .and_then(|r| Some((r[0].int()?, r[1].int()?)));
            let mut tables = Vec::new();
            for q in sql::density(w.run, w.clock, w.from, w.to, buckets, coarse) {
                tables.push(store.query(&q, 2_000_000)?);
            }
            let tables: Vec<&sql::Table> = tables.iter().collect();
            render_density(w, bucket_width(w.from, w.to, buckets), &tables)
        }
        Command::Items { window, limit } => {
            let store = reader()?;
            let w = &window;
            let limit_rows = usize::try_from(limit).unwrap_or(1);
            let packets = store.query(
                &sql::packet_items(w.run, w.clock, w.from, w.to, limit + 1),
                limit_rows,
            )?;
            let logs = match sql::log_items(w.run, w.clock, w.from, w.to, limit + 1) {
                Some(q) => Some(store.query(&q, limit_rows)?),
                None => None,
            };
            render_items(w, &packets, logs.as_ref())
        }
        Command::Series {
            window,
            buckets,
            lane,
            field,
        } => {
            let w = &window;
            let query = match &field {
                Some((packet, field)) => {
                    sql::value_series(w.run, w.clock, lane, packet, field, w.from, w.to, buckets)
                }
                None => sql::lag_series(w.run, w.clock, lane, w.from, w.to, buckets),
            };
            let table = reader()?.query(&query, 4001)?;
            render_series(w, bucket_width(w.from, w.to, buckets), &table)
        }
        Command::Packet { id } => {
            let store = reader()?;
            let detail = store.query(&sql::packet_detail(id), 1)?;
            match packet_location(&detail) {
                None => render_packet(&detail, Err("Packet not found"), ""),
                Some((path, offset, length, sum, run)) => {
                    let config = store.query(&sql::run_config(run), 1)?;
                    let config = config
                        .rows
                        .first()
                        .and_then(|r| r.first())
                        .and_then(|c| c.text())
                        .unwrap_or("");
                    // A configuration that no longer parses was accepted at
                    // ingest; fall back to none, as rendering does.
                    let parsed = Config::parse(config).unwrap_or_default();
                    let bytes = read_item(&path, &shared.root_parts, &parsed, offset, length, sum);
                    render_packet(&detail, bytes.as_deref().map_err(String::as_str), config)
                }
            }
        }
        Command::Log { id } => render_log(&reader()?.query(&sql::log_detail(id), 1)?),
        Command::Search {
            run,
            origin,
            needle,
        } => render_search(
            origin,
            &reader()?.query(&sql::search_logs(run, &needle, 501), 500)?,
        ),
        Command::Query { sql } => {
            let store = Store::open_read_only(&shared.db, QUERY_BUDGET)?;
            let result = store.query_user(&sql, 1000).map_err(|e| e.to_string());
            render_query(result.as_ref().map_err(String::as_str))
        }
        Command::Browse { path } => {
            match browse::list(
                path.as_deref(),
                &shared.roots,
                &shared.root_parts,
                &reader()?,
            ) {
                Ok(listing) => Response::json(200, &listing),
                Err((status, reason)) => Response::error(status, &reason),
            }
        }
        Command::Ingest { paths } => {
            let mut targets = Vec::with_capacity(paths.len());
            for path in &paths {
                match browse::resolve(path, &shared.root_parts) {
                    Ok(target) => targets.push(target),
                    Err((status, reason)) => return Ok(Response::error(status, &reason)),
                }
            }
            let _one_writer = shared.writer.lock().unwrap_or_else(|e| e.into_inner());
            let mut store = Store::open(&shared.db)?;
            match ingest_targets(
                &mut store,
                &targets,
                shared.config.as_deref(),
                Some(&shared.root_parts),
                shared.user_config.as_deref(),
            ) {
                Ok(summary) => Response::json(200, &summary),
                Err(e) => Response::error(400, &e.to_string()),
            }
        }
    })
}

/// Canonical form of a root folder given on the command line.
pub fn canonical_root(path: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{}: not a folder", path.display()).into());
    }
    Ok(canonical)
}
