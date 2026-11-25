//! Command line: parse arguments, do the I/O, print what `pure` decided.

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::pure::api::check_user_sql;
use crate::pure::args::Args;
use crate::pure::continuity::Checker;
use crate::pure::cosmos_defs;
use crate::pure::decode::decoder_for;
use crate::pure::ingest::{non_packet_message, whole_packet_header};
use crate::pure::order::OrderChecker;
use crate::pure::sql::Cell;
use crate::pure::synth::demo_run;
use crate::shell::files::{Records, open_sniffed};
use crate::shell::ingest::{default_db_path, ingest_targets, user_config_path};
use crate::shell::server::{Options, Server, canonical_root};
use crate::shell::store::{Status, Store};

const USAGE: &str = "\
Usage:
  packetlane check <file>...              Report sequence-count problems per APID
  packetlane ingest [options] <path>...   Ingest files or folders as one run
  packetlane query [options] <sql>        Run one read-only SQL statement
  packetlane serve [options] [path]...    Ingest paths and serve the timeline on loopback
  packetlane demo <folder> [--seconds N]  Write a sample run to a new folder
  packetlane import-cosmos <file>...      Print COSMOS 4 packet definitions as [[packet]] config

Options:
  --db <file>       Store file (default: packetlane.db in your state folder)
  --config <file>   Config file (default: packetlane.toml in run folder, then user config)
  --root <folder>   Folder the file browser may show; repeatable (serve)
  --port <n>        Port to listen on (serve; default 8737)

Exit status: 0 clean, 1 problems found, 2 error";

fn plural<'a>(n: u64, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

pub fn run(args: &[String]) -> ExitCode {
    match args.split_first() {
        Some((cmd, files)) if cmd == "check" && !files.is_empty() => check(files),
        Some((cmd, rest)) if cmd == "ingest" => report(ingest(rest)),
        Some((cmd, rest)) if cmd == "query" => report(query(rest)),
        Some((cmd, rest)) if cmd == "demo" => report(demo(rest)),
        Some((cmd, rest)) if cmd == "import-cosmos" => report(import_cosmos(rest)),
        Some((cmd, rest)) if cmd == "serve" => report(serve(rest)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check(files: &[String]) -> ExitCode {
    let mut problems = false;
    let mut unreadable = false;
    for path in files {
        match check_one(path) {
            Ok(found) => problems |= found,
            Err(e) => {
                eprintln!("{path}: {e}");
                unreadable = true;
            }
        }
    }
    if unreadable {
        ExitCode::from(2)
    } else if problems {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn check_one(path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let (format, file) = open_sniffed(Path::new(path))?;
    let Some(decoder) = decoder_for(format, &Default::default()) else {
        return Err(format!("Format {} holds no readable packets", format.name()).into());
    };
    let certainty = if format.is_certain() {
        ""
    } else {
        " (guessed)"
    };
    let wrapped = if file.is_gzip() { ", in gzip" } else { "" };
    println!("{path}: format {}{certainty}{wrapped}", format.name());

    let mut checker = Checker::new();
    let mut order = OrderChecker::new();
    let mut packets = 0u64;
    let mut other = 0u64;
    let mut read_problem = None;
    let mut file = file;
    let mut records = Records::new(BufReader::new(&mut file), decoder);
    for item in &mut records {
        match item {
            Ok(record) => match whole_packet_header(&record.payload) {
                Some(header) => {
                    // No configuration here, so no packet time to compare.
                    order.observe(packets, &header, None);
                    packets += 1;
                    checker.observe(&header, record.offset);
                }
                None => other += 1,
            },
            Err(e) => read_problem = Some(e.to_string()),
        }
    }
    let report = checker.finish();
    if let Some(about) = records.describe() {
        println!("{path}: {about}");
    }

    let streams = report.streams.len() as u64;
    println!(
        "{path}: {packets} {}, {streams} {}",
        plural(packets, "packet", "packets"),
        plural(streams, "stream", "streams"),
    );
    if other > 0 {
        println!("  {}", non_packet_message(other));
    }
    for (key, count) in &report.streams {
        println!("  {key}: {count} {}", plural(*count, "packet", "packets"));
    }
    for finding in &report.findings {
        println!("  Problem: {finding}");
    }
    let order = order.finish();
    for finding in &order {
        match finding.packet_index {
            Some(i) => println!(
                "  Problem: {}: {} at packet #{i}",
                finding.key, finding.message
            ),
            None => println!("  Problem: {}: {}", finding.key, finding.message),
        }
    }
    let notices = records.notices().clone();
    drop(records);
    if let Some(why) = file.fault() {
        read_problem
            .get_or_insert_with(|| format!("Compressed data unreadable past this point: {why}"));
    }
    for notice in &notices.list {
        let what = if notice.is_problem() {
            "Problem"
        } else {
            "Note"
        };
        println!("  {what}: {notice}");
    }
    if notices.more > 0 {
        println!("  Problem: {} more losses are not listed", notices.more);
    }
    if let Some(e) = &read_problem {
        println!("  Problem: {e}");
    }
    let lost = notices.more > 0 || notices.list.iter().any(|n| n.is_problem());
    Ok(!report.findings.is_empty() || !order.is_empty() || read_problem.is_some() || lost)
}

type CliResult = Result<ExitCode, Box<dyn std::error::Error + Send + Sync>>;

fn report(result: CliResult) -> ExitCode {
    result.unwrap_or_else(|e| {
        eprintln!("packetlane: {e}");
        ExitCode::from(2)
    })
}

fn db_path(args: &Args) -> std::io::Result<PathBuf> {
    match args.one("db") {
        Some(path) => Ok(PathBuf::from(path)),
        None => default_db_path(),
    }
}

fn ingest(rest: &[String]) -> CliResult {
    let args = Args::parse(rest, &["db", "config"])?;
    if args.positional.is_empty() {
        return Err("Ingest needs at least one file or folder".into());
    }
    let targets = args
        .positional
        .iter()
        .map(|p| std::fs::canonicalize(p).map_err(|e| format!("{p}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let db = db_path(&args)?;
    let mut store = Store::open(&db)?;
    let summary = ingest_targets(
        &mut store,
        &targets,
        args.one("config").map(Path::new),
        None,
        user_config_path().as_deref(),
    )?;

    println!("Run {} at {}", summary.run, summary.root);
    if summary.reread {
        println!("  Config changed; existing files re-read");
    }
    for file in &summary.files {
        let what = match file.status {
            Status::Ingested => format!(
                "{}: {} {}, {} {}",
                file.format,
                file.packets,
                plural(file.packets, "packet", "packets"),
                file.entries,
                plural(file.entries, "log entry", "log entries"),
            ),
            Status::AlreadyIngested => "already ingested".to_string(),
            Status::NotReadable => "not read".to_string(),
        };
        let note = if file.note.is_empty() {
            String::new()
        } else {
            format!(" ({})", file.note)
        };
        println!("  {}: {what}{note}", file.rel);
    }
    println!(
        "{} {} in this run; store: {}",
        summary.problems,
        plural(summary.problems as u64, "problem", "problems"),
        db.display()
    );
    Ok(if summary.problems > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn query(rest: &[String]) -> CliResult {
    let args = Args::parse(rest, &["db"])?;
    let [statement] = args.positional.as_slice() else {
        return Err("Query needs one quoted SQL statement".into());
    };
    check_user_sql(statement)?;
    let store = Store::open_read_only(&db_path(&args)?, Duration::from_secs(60))?;
    let table = store.query_user(statement, 100_000)?;
    println!("{}", table.columns.join("\t"));
    for row in &table.rows {
        let cells: Vec<String> = row
            .iter()
            .map(|c| match c {
                Cell::Null => String::new(),
                Cell::Int(v) => v.to_string(),
                Cell::Real(v) => v.to_string(),
                Cell::Text(v) => v.replace(['\t', '\n'], " "),
            })
            .collect();
        println!("{}", cells.join("\t"));
    }
    if table.truncated {
        eprintln!("packetlane: More rows than shown; add a LIMIT");
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints the configuration on standard output and what was left out on
/// standard error, so the output can be redirected straight into a file.
fn import_cosmos(files: &[String]) -> CliResult {
    if files.is_empty() {
        return Err("import-cosmos needs at least one cmd_tlm definition file".into());
    }
    let mut sources = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        sources.push((path.clone(), text));
    }
    let import = cosmos_defs::import(&sources);
    for warning in &import.warnings {
        eprintln!("{warning}");
    }
    let fields: usize = import.packets.iter().map(|p| p.fields.len()).sum();
    eprintln!(
        "{} {}, {fields} {}, {} {}",
        import.packets.len(),
        plural(import.packets.len() as u64, "packet", "packets"),
        plural(fields as u64, "field", "fields"),
        import.warnings.len(),
        plural(import.warnings.len() as u64, "warning", "warnings"),
    );
    print!("{}", cosmos_defs::to_toml(&import.packets));
    Ok(if import.packets.is_empty() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn demo(rest: &[String]) -> CliResult {
    let args = Args::parse(rest, &["seconds"])?;
    let [dir] = args.positional.as_slice() else {
        return Err("Demo needs a new folder path".into());
    };
    let seconds: u32 = match args.one("seconds") {
        Some(s) => s.parse().map_err(|_| "--seconds needs a whole number")?,
        None => 300,
    };
    let dir = Path::new(dir);
    // create_dir, not create_dir_all: refuse to write into an existing folder.
    std::fs::create_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for file in demo_run(seconds) {
        let path = dir.join(file.rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| f.write_all(&file.bytes))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let bytes = file.bytes.len() as u64;
        println!(
            "Wrote {} ({bytes} {})",
            path.display(),
            plural(bytes, "byte", "bytes")
        );
    }
    println!("Next: packetlane serve --root {}", dir.display());
    Ok(ExitCode::SUCCESS)
}

fn serve(rest: &[String]) -> CliResult {
    let args = Args::parse(rest, &["db", "config", "root", "port"])?;
    let port: u16 = match args.one("port") {
        Some(p) => p
            .parse()
            .map_err(|_| "--port needs a number from 0 to 65535")?,
        None => 8737,
    };
    let config = args.one("config").map(PathBuf::from);

    // Paths given without --root are ingested first, and their folders
    // become roots too.
    let mut roots = Vec::new();
    for root in args.all("root") {
        roots.push(canonical_root(Path::new(root))?);
    }
    let mut targets = Vec::new();
    for path in &args.positional {
        let target = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
        let folder = if target.is_dir() {
            Some(target.as_path())
        } else {
            target.parent()
        };
        roots.extend(folder.map(Path::to_path_buf));
        targets.push(target);
    }
    roots.sort();
    roots.dedup();
    if roots.is_empty() {
        return Err("Serve needs a folder: pass <folder> or --root <folder>".into());
    }
    let db = db_path(&args)?;
    if !targets.is_empty() {
        let mut store = Store::open(&db)?;
        let summary = ingest_targets(
            &mut store,
            &targets,
            config.as_deref(),
            None,
            user_config_path().as_deref(),
        )?;
        let read = summary
            .files
            .iter()
            .filter(|f| f.status != Status::NotReadable)
            .count() as u64;
        eprintln!(
            "{}: {read} {}, {} {}",
            summary.root,
            plural(read, "file", "files"),
            summary.problems,
            plural(summary.problems as u64, "problem", "problems"),
        );
    }

    let server = Server::bind(Options {
        db,
        roots,
        config,
        user_config: user_config_path(),
        port,
    })
    .map_err(|e| format!("Could not listen on port {port}: {e}; try --port 0"))?;
    println!("{}", server.url());
    server.run();
    Ok(ExitCode::SUCCESS)
}
