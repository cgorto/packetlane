//! Decisions about paths, made on canonical paths the shell has already
//! resolved (symlinks followed, no `.` or `..` left) and split into
//! components.

/// True if `path` is `root` or lies beneath it.
pub fn is_within(path: &[String], root: &[String]) -> bool {
    path.len() >= root.len() && path.iter().zip(root).all(|(a, b)| a == b)
}

/// True if `path` is inside at least one of the allowed roots.
pub fn confined(path: &[String], roots: &[Vec<String>]) -> bool {
    roots.iter().any(|root| is_within(path, root))
}

/// The deepest folder that contains every one of `paths`, given whether each
/// is itself a folder. One folder is its own answer; one file gives its
/// parent. Empty input gives an empty path.
pub fn common_dir(paths: &[(Vec<String>, bool)]) -> Vec<String> {
    let mut dirs = paths.iter().map(|(p, is_dir)| {
        if *is_dir {
            p.as_slice()
        } else {
            &p[..p.len().saturating_sub(1)]
        }
    });
    let Some(first) = dirs.next() else {
        return Vec::new();
    };
    let mut common = first.len();
    for dir in dirs {
        let shared = first.iter().zip(dir).take_while(|(a, b)| a == b).count();
        common = common.min(shared);
    }
    first[..common].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Vec<String> {
        s.split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn within_is_by_whole_components() {
        assert!(is_within(&p("/data/runs/a/x.bin"), &p("/data/runs")));
        assert!(is_within(&p("/data/runs"), &p("/data/runs")));
        assert!(!is_within(&p("/data/runs-old/x.bin"), &p("/data/runs")));
        assert!(!is_within(&p("/data"), &p("/data/runs")));
        assert!(!is_within(&p("/etc/passwd"), &p("/data/runs")));
        // An empty root would allow everything; the shell never passes one.
        assert!(is_within(&p("/etc/passwd"), &p("")));
    }

    #[test]
    fn confined_needs_one_matching_root() {
        let roots = vec![p("/data/runs"), p("/home/me/logs")];
        assert!(confined(&p("/home/me/logs/a"), &roots));
        assert!(!confined(&p("/home/me/secrets"), &roots));
        assert!(!confined(&p("/data/runs"), &[]));
    }

    #[test]
    fn common_dir_cases() {
        assert_eq!(common_dir(&[]), p(""));
        assert_eq!(common_dir(&[(p("/r/a"), true)]), p("/r/a"));
        assert_eq!(common_dir(&[(p("/r/a/x.bin"), false)]), p("/r/a"));
        assert_eq!(
            common_dir(&[(p("/r/a/h1/x.bin"), false), (p("/r/a/h2"), true)]),
            p("/r/a")
        );
        assert_eq!(common_dir(&[(p("/r/a"), true), (p("/q/b"), true)]), p(""));
    }
}
