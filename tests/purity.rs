//! The functional core must not do I/O. This test fails if any file under
//! `src/pure/` names an API that reaches outside the process.

use std::fs;
use std::path::{Path, PathBuf};

const BANNED: &[&str] = &[
    "std::fs",
    "std::net",
    "std::io",
    "std::env",
    "std::process",
    "std::thread",
    "std::time",
    "SystemTime",
    "Instant::",
    "rusqlite",
    "println!",
    "eprintln!",
    "print!(",
    "dbg!(",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src/pure") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn pure_modules_do_no_io() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pure");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(!files.is_empty());

    let mut violations = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).expect("read source file");
        for (n, line) in text.lines().enumerate() {
            for banned in BANNED {
                if line.contains(banned) {
                    violations.push(format!("{}:{}: {banned}", file.display(), n + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "I/O in the pure core:\n{}",
        violations.join("\n")
    );
}
