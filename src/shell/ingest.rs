//! Gathering what an ingest needs from the outside world: canonical paths,
//! the files under a folder, the configuration text and the current time.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pure::ingest::relative_path;
use crate::pure::paths::{common_dir, confined};
use crate::shell::store::{IngestSummary, Result, Store};

/// Name of a configuration file that applies to the run folder it sits in.
pub const RUN_CONFIG: &str = "packetlane.toml";
/// Most files taken in one ingest.
const MAX_FILES: usize = 10_000;

pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn home_dir(var: &str, fallback: &str) -> Option<PathBuf> {
    match std::env::var_os(var) {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(|h| PathBuf::from(h).join(fallback)),
    }
}

/// Where the store lives when `--db` is not given. Never next to the logs.
pub fn default_db_path() -> io::Result<PathBuf> {
    let dir = home_dir("XDG_STATE_HOME", ".local/state")
        .unwrap_or_else(|| PathBuf::from("."))
        .join("packetlane");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("packetlane.db"))
}

/// The user's own configuration file, used when a run has none.
pub fn user_config_path() -> Option<PathBuf> {
    Some(home_dir("XDG_CONFIG_HOME", ".config")?.join("packetlane/config.toml"))
}

/// The components of an absolute path as text, or `None` if any part is not
/// valid UTF-8. Such paths are refused, so that every decision about a path
/// is made on exactly the bytes the file system has.
pub fn components(path: &Path) -> Option<Vec<String>> {
    path.components()
        .filter(|c| !matches!(c, Component::RootDir | Component::Prefix(_)))
        .map(|c| c.as_os_str().to_str().map(str::to_string))
        .collect()
}

/// Regular files under `dir`, sorted. Symbolic links are not followed and
/// hidden entries are skipped, as is the run configuration file.
pub fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        let hidden = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_none_or(|n| n.starts_with('.') || n == RUN_CONFIG);
        if hidden {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            walk(&path, out)?;
        } else if meta.is_file() {
            out.push(path);
        }
        if out.len() > MAX_FILES {
            return Err(io::Error::other(format!(
                "More than {MAX_FILES} files; ingest a smaller folder"
            )));
        }
    }
    Ok(())
}

/// The configuration text for a run: the given file, else the run folder's
/// own, else the user's, else none.
fn config_text(
    root: &Path,
    override_path: Option<&Path>,
    user_config: Option<&Path>,
) -> io::Result<String> {
    if let Some(path) = override_path {
        return fs::read_to_string(path);
    }
    // The run folder's own file counts only if it is a plain file: a link
    // could point anywhere.
    let in_run =
        Some(root.join(RUN_CONFIG)).filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.is_file()));
    let candidates = [in_run, user_config.map(Path::to_path_buf)];
    for path in candidates.into_iter().flatten() {
        match fs::read_to_string(&path) {
            Ok(text) => return Ok(text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(String::new())
}

/// Ingests files and folders as one run. The run folder is the deepest
/// folder that contains every target. Targets must already be canonical.
pub fn ingest_targets(
    store: &mut Store,
    targets: &[PathBuf],
    config_override: Option<&Path>,
    allowed: Option<&[Vec<String>]>,
    user_config: Option<&Path>,
) -> Result<IngestSummary> {
    let mut described = Vec::new();
    let mut files = Vec::new();
    for target in targets {
        let parts = components(target)
            .ok_or_else(|| format!("{}: path is not valid UTF-8", target.display()))?;
        let meta = fs::symlink_metadata(target)?;
        if meta.is_dir() {
            walk(target, &mut files)?;
        } else if meta.is_file() {
            files.push(target.clone());
        } else {
            return Err(format!("{}: not a file or folder", target.display()).into());
        }
        described.push((parts, meta.is_dir()));
    }
    let root_parts = common_dir(&described);
    if root_parts.is_empty() {
        return Err("Selected paths share no common folder".into());
    }
    // The run folder is where the configuration is looked for, so it must be
    // inside the allowed folders as well as the items themselves.
    if let Some(allowed) = allowed
        && !confined(&root_parts, allowed)
    {
        return Err("Selected paths must be inside one allowed folder".into());
    }
    let root: PathBuf = std::iter::once(Component::RootDir.as_os_str().to_owned())
        .chain(root_parts.iter().map(Into::into))
        .collect();

    files.sort();
    files.dedup();
    let mut named = Vec::with_capacity(files.len());
    for file in files {
        let rel = components(&file).and_then(|parts| relative_path(&root_parts, &parts));
        match rel {
            Some(rel) => named.push((file, rel)),
            None => return Err(format!("{}: path is not valid UTF-8", file.display()).into()),
        }
    }
    let config = config_text(&root, config_override, user_config)?;
    store.ingest(&root, &named, &config, now_ns())
}
