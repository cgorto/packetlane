//! Listing folders for the file browser. Every path is resolved first, and
//! `pure::paths` then decides whether it may be shown.

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::pure::api::{BrowseEntry, Listing};
use crate::pure::decode::sniff;
use crate::pure::paths::confined;
use crate::pure::sql;
use crate::shell::files::read_full;
use crate::shell::ingest::{RUN_CONFIG, components};
use crate::shell::store::Store;

/// Bytes read from each file to guess its format for the listing.
const PEEK: usize = 64 * 1024;
const MAX_ENTRIES: usize = 2000;

/// A refusal: HTTP status and reason.
pub type Refusal = (u16, String);

/// Resolves a path given by the browser and checks it against the allowed
/// roots. The result is canonical: symlinks followed, no `..` left.
pub fn resolve(path: &str, roots: &[Vec<String>]) -> Result<PathBuf, Refusal> {
    // One answer whether the path is missing or outside, so the reply does
    // not reveal what exists elsewhere on the machine.
    let refused = || (403, "Path is outside the allowed folders".to_string());
    let canonical = fs::canonicalize(path).map_err(|_| refused())?;
    let parts = components(&canonical).ok_or_else(refused)?;
    if !confined(&parts, roots) {
        return Err(refused());
    }
    Ok(canonical)
}

fn peek_format(path: &Path) -> Option<&'static str> {
    let mut file = File::open(path).ok()?;
    let mut prefix = vec![0u8; PEEK];
    let n = read_full(&mut file, &mut prefix).ok()?;
    Some(sniff(&prefix[..n]).name())
}

pub fn list(
    path: Option<&str>,
    roots: &[PathBuf],
    root_parts: &[Vec<String>],
    store: &Store,
) -> Result<Listing, Refusal> {
    let Some(path) = path else {
        let entries = roots
            .iter()
            .map(|root| BrowseEntry {
                name: root.to_string_lossy().into_owned(),
                path: root.to_string_lossy().into_owned(),
                dir: true,
                size: 0,
                format: None,
                ingested: false,
                packets: 0,
                entries: 0,
                note: String::new(),
            })
            .collect();
        return Ok(Listing {
            path: None,
            parent: None,
            entries,
            truncated: false,
        });
    };

    let dir = resolve(path, root_parts)?;
    if !dir.is_dir() {
        return Err((400, "Not a folder".to_string()));
    }
    let dir_text = dir.to_string_lossy().into_owned();

    let known = store
        .query(&sql::files_under(&format!("{dir_text}/")), 100_000)
        .map_err(|e| (500, e.to_string()))?;
    let ingested: HashMap<&str, (i64, i64, &str)> = known
        .rows
        .iter()
        .filter_map(|r| Some((r[0].text()?, (r[1].int()?, r[2].int()?, r[3].text()?))))
        .collect();

    let mut entries = Vec::new();
    let mut truncated = false;
    let reader = fs::read_dir(&dir).map_err(|e| (500, e.to_string()))?;
    for entry in reader.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') || name == RUN_CONFIG {
            continue;
        }
        let path = entry.path();
        // Symbolic links are not listed: following one could leave the roots.
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() && !meta.is_file() {
            continue;
        }
        if entries.len() >= MAX_ENTRIES {
            truncated = true;
            break;
        }
        let path_text = path.to_string_lossy().into_owned();
        let seen = ingested.get(path_text.as_str());
        entries.push(BrowseEntry {
            format: if meta.is_file() {
                peek_format(&path)
            } else {
                None
            },
            name,
            dir: meta.is_dir(),
            size: if meta.is_file() { meta.len() } else { 0 },
            ingested: seen.is_some(),
            packets: seen.map_or(0, |s| s.0),
            entries: seen.map_or(0, |s| s.1),
            note: seen.map_or(String::new(), |s| s.2.to_string()),
            path: path_text,
        });
    }
    entries.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.cmp(&b.name)));

    let parent = dir
        .parent()
        .filter(|p| components(p).is_some_and(|parts| confined(&parts, root_parts)))
        .map(|p| p.to_string_lossy().into_owned());
    Ok(Listing {
        path: Some(dir_text),
        parent,
        entries,
        truncated,
    })
}
