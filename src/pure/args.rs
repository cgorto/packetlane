//! Command-line argument splitting. No environment access: the shell passes
//! the arguments in.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Args {
    pub positional: Vec<String>,
    /// Values given for each `--flag`, in order.
    pub flags: BTreeMap<String, Vec<String>>,
}

impl Args {
    /// Splits arguments into positionals and `--flag value` pairs. Only the
    /// flags named in `known` are accepted; every flag takes one value.
    /// `--` ends flag parsing.
    pub fn parse(args: &[String], known: &[&str]) -> Result<Args, String> {
        let mut out = Args::default();
        let mut iter = args.iter();
        let mut flags_done = false;
        while let Some(arg) = iter.next() {
            if flags_done || !arg.starts_with("--") {
                out.positional.push(arg.clone());
            } else if arg == "--" {
                flags_done = true;
            } else {
                let (name, inline) = match arg[2..].split_once('=') {
                    Some((n, v)) => (n, Some(v.to_string())),
                    None => (&arg[2..], None),
                };
                if !known.contains(&name) {
                    return Err(format!("Unknown option --{name}"));
                }
                let value = match inline {
                    Some(v) => v,
                    None => iter
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("--{name} needs a value"))?,
                };
                out.flags.entry(name.to_string()).or_default().push(value);
            }
        }
        Ok(out)
    }

    /// The last value given for a flag.
    pub fn one(&self, name: &str) -> Option<&str> {
        self.flags.get(name)?.last().map(String::as_str)
    }

    pub fn all(&self, name: &str) -> &[String] {
        self.flags.get(name).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_flags_and_positionals() {
        let a = Args::parse(
            &v(&[
                "a",
                "--db",
                "x.db",
                "--root=/r1",
                "b",
                "--root",
                "/r2",
                "--",
                "--c",
            ]),
            &["db", "root"],
        )
        .unwrap();
        assert_eq!(a.positional, v(&["a", "b", "--c"]));
        assert_eq!(a.one("db"), Some("x.db"));
        assert_eq!(a.all("root"), v(&["/r1", "/r2"]));
        assert_eq!(a.one("port"), None);
        assert!(a.all("port").is_empty());
    }

    #[test]
    fn rejects_unknown_and_incomplete_flags() {
        assert_eq!(
            Args::parse(&v(&["--nope", "1"]), &["db"]).unwrap_err(),
            "Unknown option --nope"
        );
        assert_eq!(
            Args::parse(&v(&["--db"]), &["db"]).unwrap_err(),
            "--db needs a value"
        );
    }
}
