//! Turning lines of a text log into timestamped entries.

use regex::Regex;

use crate::pure::time::{self, Civil, NS_PER_SEC};

/// Matches an ISO-like timestamp anywhere in the first 64 characters of a line.
pub const DEFAULT_PATTERN: &str = r"^.{0,64}?(?P<year>\d{4})[-/](?P<month>\d{2})[-/](?P<day>\d{2})[T ](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:[.,](?P<frac>\d{1,9}))?(?P<tz>Z|[+-]\d{2}:?\d{2})?";

const MAX_ENTRY_BYTES: usize = 65_536;
const TRUNCATED_SUFFIX: &str = "\n[truncated]";
const TRUNCATED_BUDGET: usize = MAX_ENTRY_BYTES - TRUNCATED_SUFFIX.len();

/// Compiled timestamp pattern and timezone/year defaults for a text log format.
#[derive(Debug, Clone)]
pub struct LogFormat {
    regex: Regex,
    utc_offset_s: i64,
    default_year: Option<i64>,
}

enum MatchKind {
    Epoch(i64),
    Calendar {
        year: Option<i64>,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        nanos: u32,
        offset_s: i64,
    },
}

fn parse_ascii_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok()
}

fn parse_year(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

fn parse_month(s: &str) -> Option<u32> {
    if let Some(n) = parse_ascii_u32(s) {
        return (1..=12).contains(&n).then_some(n);
    }
    const MONTHS: [(&str, &str, u32); 12] = [
        ("jan", "january", 1),
        ("feb", "february", 2),
        ("mar", "march", 3),
        ("apr", "april", 4),
        ("may", "may", 5),
        ("jun", "june", 6),
        ("jul", "july", 7),
        ("aug", "august", 8),
        ("sep", "september", 9),
        ("oct", "october", 10),
        ("nov", "november", 11),
        ("dec", "december", 12),
    ];
    for &(short, full, num) in &MONTHS {
        if s.eq_ignore_ascii_case(short) || s.eq_ignore_ascii_case(full) {
            return Some(num);
        }
    }
    None
}

fn parse_epoch_ns(s: &str) -> Option<i64> {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (sec_str, frac_str) = match rest.find(['.', ',']) {
        Some(pos) => (rest.get(..pos)?, Some(rest.get(pos + 1..)?)),
        None => (rest, None),
    };
    if sec_str.is_empty() || !sec_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = sec_str.parse::<i128>().ok()?;
    let nanos = match frac_str {
        Some(f) => i128::from(time::parse_frac_ns(f.as_bytes())?),
        None => 0,
    };
    let mag = secs
        .checked_mul(i128::from(NS_PER_SEC))?
        .checked_add(nanos)?;
    let signed = if neg { mag.checked_neg()? } else { mag };
    i64::try_from(signed).ok()
}

impl LogFormat {
    /// Compiles `pattern` into a [`LogFormat`].
    ///
    /// Fails with a readable error if `pattern` does not compile or defines
    /// neither `epoch` nor the calendar date groups (`month` and `day`).
    pub fn new(
        pattern: &str,
        utc_offset_s: i64,
        default_year: Option<i64>,
    ) -> Result<Self, String> {
        let regex = Regex::new(pattern).map_err(|e| format!("invalid pattern: {e}"))?;
        let mut has_epoch = false;
        let mut has_month = false;
        let mut has_day = false;
        for name in regex.capture_names().flatten() {
            match name {
                "epoch" => has_epoch = true,
                "month" => has_month = true,
                "day" => has_day = true,
                _ => {}
            }
        }
        if !(has_epoch || (has_month && has_day)) {
            return Err("pattern must capture 'epoch', or both 'month' and 'day'".to_string());
        }
        Ok(Self {
            regex,
            utc_offset_s,
            default_year,
        })
    }

    /// Standard ISO-8601 format (`DEFAULT_PATTERN`, UTC offset 0, no default year).
    pub fn iso() -> Self {
        Self::new(DEFAULT_PATTERN, 0, None).expect("DEFAULT_PATTERN is a valid timestamp regex")
    }

    fn parse_match(&self, line: &str) -> Option<MatchKind> {
        let caps = self.regex.captures(line)?;
        if let Some(m) = caps.name("epoch") {
            return Some(MatchKind::Epoch(parse_epoch_ns(m.as_str())?));
        }
        let year = match caps.name("year") {
            Some(m) => Some(parse_year(m.as_str())?),
            None => None,
        };
        let month = parse_month(caps.name("month")?.as_str())?;
        let day = parse_ascii_u32(caps.name("day")?.as_str())?;
        let hour = match caps.name("hour") {
            Some(m) => parse_ascii_u32(m.as_str())?,
            None => 0,
        };
        let minute = match caps.name("minute") {
            Some(m) => parse_ascii_u32(m.as_str())?,
            None => 0,
        };
        let second = match caps.name("second") {
            Some(m) => parse_ascii_u32(m.as_str())?,
            None => 0,
        };
        let nanos = match caps.name("frac") {
            Some(m) => time::parse_frac_ns(m.as_str().as_bytes())?,
            None => 0,
        };
        let offset_s = match caps.name("tz") {
            Some(m) => time::parse_utc_offset(m.as_str())?,
            None => self.utc_offset_s,
        };
        Some(MatchKind::Calendar {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanos,
            offset_s,
        })
    }

    /// Extracts the UTC timestamp of `line` in nanoseconds, or `None` if the
    /// line has no valid timestamp.
    pub fn timestamp(&self, line: &str) -> Option<i64> {
        match self.parse_match(line)? {
            MatchKind::Epoch(ns) => Some(ns),
            MatchKind::Calendar {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanos,
                offset_s,
            } => {
                let year = year.or(self.default_year)?;
                let civil = Civil {
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanos,
                };
                time::civil_to_ns_with_offset(&civil, offset_s)
            }
        }
    }
}

/// A single assembled text log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub offset: u64,
    pub time_ns: Option<i64>,
    pub text: String,
}

fn floor_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    let mut i = max_bytes;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[derive(Debug, Clone)]
struct PendingEntry {
    offset: u64,
    time_ns: Option<i64>,
    text: String,
    truncated: bool,
}

impl PendingEntry {
    fn new(offset: u64, time_ns: Option<i64>, first_line: &str) -> Self {
        if first_line.len() <= MAX_ENTRY_BYTES {
            Self {
                offset,
                time_ns,
                text: first_line.to_string(),
                truncated: false,
            }
        } else {
            let cut = floor_char_boundary(first_line, TRUNCATED_BUDGET);
            let mut text = String::with_capacity(cut + TRUNCATED_SUFFIX.len());
            if let Some(prefix) = first_line.get(..cut) {
                text.push_str(prefix);
            }
            text.push_str(TRUNCATED_SUFFIX);
            Self {
                offset,
                time_ns,
                text,
                truncated: true,
            }
        }
    }

    fn push_continuation(&mut self, line: &str) {
        if self.truncated {
            return;
        }
        let needed = self.text.len().saturating_add(1).saturating_add(line.len());
        if needed <= MAX_ENTRY_BYTES {
            self.text.push('\n');
            self.text.push_str(line);
            return;
        }
        if self.text.len() > TRUNCATED_BUDGET {
            let cut = floor_char_boundary(&self.text, TRUNCATED_BUDGET);
            self.text.truncate(cut);
        } else {
            let room_after_nl = TRUNCATED_BUDGET.saturating_sub(self.text.len() + 1);
            let cut = floor_char_boundary(line, room_after_nl);
            if cut > 0
                && let Some(prefix) = line.get(..cut)
            {
                self.text.push('\n');
                self.text.push_str(prefix);
            }
        }
        self.text.push_str(TRUNCATED_SUFFIX);
        self.truncated = true;
    }

    fn into_entry(self) -> Entry {
        Entry {
            offset: self.offset,
            time_ns: self.time_ns,
            text: self.text,
        }
    }
}

/// Groups lines of a text log into multi-line [`Entry`] values.
#[derive(Debug, Clone)]
pub struct Assembler {
    format: LogFormat,
    current_year: Option<i64>,
    last_month: Option<u32>,
    pending: Option<PendingEntry>,
}

impl Assembler {
    pub fn new(format: LogFormat) -> Self {
        let current_year = format.default_year;
        Self {
            format,
            current_year,
            last_month: None,
            pending: None,
        }
    }

    fn parse_line_time(&mut self, line: &str) -> Option<i64> {
        match self.format.parse_match(line)? {
            MatchKind::Epoch(ns) => {
                self.last_month = Some(time::ns_to_civil(ns).month);
                Some(ns)
            }
            MatchKind::Calendar {
                year: Some(year),
                month,
                day,
                hour,
                minute,
                second,
                nanos,
                offset_s,
            } => {
                let civil = Civil {
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanos,
                };
                let ns = time::civil_to_ns_with_offset(&civil, offset_s)?;
                self.last_month = Some(month);
                Some(ns)
            }
            MatchKind::Calendar {
                year: None,
                month,
                day,
                hour,
                minute,
                second,
                nanos,
                offset_s,
            } => {
                let base_year = self.current_year?;
                let candidate_year = match self.last_month {
                    Some(prev) if prev > month && prev - month > 6 => base_year.checked_add(1)?,
                    _ => base_year,
                };
                let civil = Civil {
                    year: candidate_year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanos,
                };
                let ns = time::civil_to_ns_with_offset(&civil, offset_s)?;
                self.current_year = Some(candidate_year);
                self.last_month = Some(month);
                Some(ns)
            }
        }
    }

    /// Feeds one line (without trailing newline) starting at byte `offset`.
    /// Returns the previous entry when this line starts a new one.
    pub fn push_line(&mut self, offset: u64, line: &str) -> Option<Entry> {
        if let Some(time_ns) = self.parse_line_time(line) {
            let prev = self
                .pending
                .replace(PendingEntry::new(offset, Some(time_ns), line));
            prev.map(PendingEntry::into_entry)
        } else {
            match &mut self.pending {
                Some(entry) => entry.push_continuation(line),
                None => {
                    self.pending = Some(PendingEntry::new(offset, None, line));
                }
            }
            None
        }
    }

    /// Returns the last pending entry, if any.
    pub fn finish(&mut self) -> Option<Entry> {
        self.pending.take().map(PendingEntry::into_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso_ns(s: &str) -> i64 {
        time::parse_iso(s).expect("valid test ISO timestamp")
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        let err = LogFormat::new("(?P<year>[unclosed", 0, None).unwrap_err();
        assert!(!err.is_empty());

        let no_groups = LogFormat::new(r"\d{4}-\d{2}-\d{2}", 0, None).unwrap_err();
        assert!(!no_groups.is_empty());

        let only_unrelated = LogFormat::new(r"(?P<level>INFO|WARN)", 0, None).unwrap_err();
        assert!(!only_unrelated.is_empty());

        let only_year = LogFormat::new(r"(?P<year>\d{4})", 0, None).unwrap_err();
        assert!(!only_year.is_empty());
    }

    #[test]
    fn default_iso_pattern_and_first_64_chars() {
        let fmt = LogFormat::iso();
        // COSMOS message logs write the date with slashes.
        assert_eq!(
            fmt.timestamp("2026/01/02 03:04:05.123  INFO: Log File Opened : x.bin"),
            Some(iso_ns("2026-01-02T03:04:05.123Z"))
        );
        assert_eq!(
            fmt.timestamp("[INFO] 2026-01-02T03:04:05.123Z link up"),
            Some(iso_ns("2026-01-02T03:04:05.123Z"))
        );
        assert_eq!(
            fmt.timestamp("2026-01-02 03:04:05,456789+02:00 telemetry ready"),
            Some(iso_ns("2026-01-02T01:04:05.456789Z"))
        );
        // Two timestamps on one line: first one wins (lazy prefix)
        assert_eq!(
            fmt.timestamp("2026-01-02T03:04:05Z window 2026-01-02T04:00:00Z"),
            Some(iso_ns("2026-01-02T03:04:05Z"))
        );
        // Timestamp past the first 64 characters is ignored
        let deep = format!("{}2026-01-02T03:04:05Z", "x".repeat(70));
        assert_eq!(fmt.timestamp(&deep), None);
        // Invalid calendar date in match returns None
        assert_eq!(fmt.timestamp("2025-02-29T00:00:00Z impossible"), None);
    }

    #[test]
    fn named_groups_month_names_and_tz_override() {
        let pat = r"^(?P<month>[A-Za-z]+)\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<frac>\d{1,9}))?(?:\s+(?P<tz>Z|[+-]\d{2}(?::?\d{2})?))?";
        // Default offset: +02:00 (7200s east of UTC)
        let fmt = LogFormat::new(pat, 7_200, None).expect("valid pattern");

        // Full month name, mixed case, default offset applied
        assert_eq!(
            fmt.timestamp("fEbRuArY 28 2026 05:00:00.25 event"),
            Some(iso_ns("2026-02-28T03:00:00.25Z"))
        );
        // 3-letter abbreviation, uppercase, explicit tz overrides default offset
        assert_eq!(
            fmt.timestamp("DEC 31 2025 19:00:00 -0500 override"),
            Some(iso_ns("2026-01-01T00:00:00Z"))
        );
        // Explicit Z overrides non-zero default offset
        assert_eq!(
            fmt.timestamp("sep 5 2026 10:20:30.000000007 Z utc"),
            Some(iso_ns("2026-09-05T10:20:30.000000007Z"))
        );
        // All 12 months accepted (abbreviations & full names)
        for (i, name) in [
            "Jan",
            "February",
            "MAR",
            "april",
            "May",
            "jun",
            "July",
            "AUG",
            "September",
            "oct",
            "November",
            "dec",
        ]
        .iter()
        .enumerate()
        {
            let line = format!("{name} 1 2026 02:00:00 msg");
            let expected = iso_ns(&format!("2026-{:02}-01T00:00:00Z", i + 1));
            assert_eq!(fmt.timestamp(&line), Some(expected), "month {name}");
        }
        // Unknown month name -> None
        assert_eq!(fmt.timestamp("Foo 1 2026 02:00:00 msg"), None);
    }

    #[test]
    fn epoch_group_ignores_calendar_groups() {
        let pat =
            r"^t=(?P<epoch>-?\d+(?:\.\d+)?)\s+(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})";
        let fmt = LogFormat::new(pat, 3_600, None).expect("valid epoch pattern");

        // Calendar fields are bogus (99-99) and offset is +1h, both ignored for epoch
        assert_eq!(
            fmt.timestamp("t=1700000000.123456 2026-99-99 ping"),
            Some(1_700_000_000_123_456_000)
        );
        assert_eq!(fmt.timestamp("t=0 1970-01-01 origin"), Some(0));
        assert_eq!(
            fmt.timestamp("t=-0.5 1969-12-31 half before"),
            Some(-500_000_000)
        );
        assert_eq!(
            fmt.timestamp("t=-1.25 1969-12-31 negative"),
            Some(-1_250_000_000)
        );
        // Overflowing epoch returns None without panic
        assert_eq!(
            fmt.timestamp("t=99999999999999999999 2026-01-01 overflow"),
            None
        );
    }

    #[test]
    fn default_year_absent_without_default_returns_none() {
        let pat = r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})";
        let fmt = LogFormat::new(pat, 0, None).expect("valid pattern");
        assert_eq!(fmt.timestamp("Jan 02 03:04:05 no year"), None);
    }

    #[test]
    fn default_year_with_new_year_rollover() {
        let pat = r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})";
        let fmt = LogFormat::new(pat, 0, Some(2023)).expect("valid syslog pattern");
        let mut asm = Assembler::new(fmt);

        let lines = [
            (0u64, "Nov 30 23:59:00 first"),
            (25, "Dec 31 23:59:59 almost"),
            // Invalid date during rollover must not corrupt year state; treated as continuation
            (40, "Jan 32 00:00:00 bogus date"),
            // Month jumps Dec -> Jan (12 - 1 = 11 > 6): increments year 2023 -> 2024
            (50, "Jan 01 00:00:01 happy new year"),
            // Feb 29 is valid in 2024 (leap year)
            (85, "Feb 29 12:00:00 leap day"),
            // Small backward month jump (<= 6 months) does NOT roll over
            (115, "Jan 15 00:00:00 clock skew"),
            (145, "Dec 20 10:00:00 end of 2024"),
            // Second rollover into 2025
            (175, "Jan 02 01:02:03 next year"),
        ];

        let mut entries = Vec::new();
        for (off, line) in lines {
            if let Some(e) = asm.push_line(off, line) {
                entries.push(e);
            }
        }
        if let Some(e) = asm.finish() {
            entries.push(e);
        }

        let times: Vec<Option<i64>> = entries.iter().map(|e| e.time_ns).collect();
        assert_eq!(
            times,
            vec![
                Some(iso_ns("2023-11-30T23:59:00Z")),
                Some(iso_ns("2023-12-31T23:59:59Z")),
                Some(iso_ns("2024-01-01T00:00:01Z")),
                Some(iso_ns("2024-02-29T12:00:00Z")),
                Some(iso_ns("2024-01-15T00:00:00Z")),
                Some(iso_ns("2024-12-20T10:00:00Z")),
                Some(iso_ns("2025-01-02T01:02:03Z")),
            ]
        );
    }

    #[test]
    fn leading_lines_and_continuations() {
        let mut asm = Assembler::new(LogFormat::iso());

        assert_eq!(asm.push_line(0, "banner line 1"), None);
        assert_eq!(asm.push_line(14, "banner line 2"), None);

        let e0 = asm
            .push_line(28, "2026-03-10T08:00:00Z started")
            .expect("flushes leading entry");
        assert_eq!(
            e0,
            Entry {
                offset: 0,
                time_ns: None,
                text: "banner line 1\nbanner line 2".to_string(),
            }
        );

        assert_eq!(asm.push_line(57, "  detail A"), None);
        assert_eq!(asm.push_line(68, "  detail B"), None);

        let e1 = asm
            .push_line(79, "2026-03-10T08:00:05Z done")
            .expect("flushes first timestamped entry");
        assert_eq!(
            e1,
            Entry {
                offset: 28,
                time_ns: Some(iso_ns("2026-03-10T08:00:00Z")),
                text: "2026-03-10T08:00:00Z started\n  detail A\n  detail B".to_string(),
            }
        );

        let e2 = asm.finish().expect("flushes final entry");
        assert_eq!(
            e2,
            Entry {
                offset: 79,
                time_ns: Some(iso_ns("2026-03-10T08:00:05Z")),
                text: "2026-03-10T08:00:05Z done".to_string(),
            }
        );
        assert_eq!(asm.finish(), None);
    }

    #[test]
    fn text_cap_and_multibyte_utf8_boundary() {
        let mut asm = Assembler::new(LogFormat::iso());

        // Case 1: continuation line pushes past 65536 with a 3-byte char ('€')
        // straddling the truncation boundary.
        let header = "2026-05-01T00:00:00Z "; // 21 bytes
        // Fill so header + '\n' + prefix leaves 1 byte before TRUNCATED_BUDGET,
        // placing a 3-byte '€' across TRUNCATED_BUDGET.
        assert_eq!(asm.push_line(0, header), None);
        let pad_len = TRUNCATED_BUDGET - header.len() - 1 - 1;
        let cont = format!("{}€€€€trailing", "a".repeat(pad_len));
        assert_eq!(asm.push_line(22, &cont), None);
        // Further continuation lines must be dropped and marker added only once
        assert_eq!(asm.push_line(70_000, "dropped line 1"), None);
        assert_eq!(asm.push_line(70_020, "dropped line 2"), None);

        // Case 2: single line exceeding 65536 with a 4-byte emoji at boundary
        let long_first = format!(
            "2026-05-01T00:01:00Z {}🦀🦀🦀end",
            "b".repeat(TRUNCATED_BUDGET - 21 - 2)
        );
        let e1 = asm
            .push_line(80_000, &long_first)
            .expect("flushes capped continuation entry");
        assert!(e1.text.len() <= MAX_ENTRY_BYTES);
        assert!(e1.text.ends_with(TRUNCATED_SUFFIX));
        assert_eq!(e1.text.matches(TRUNCATED_SUFFIX).count(), 1);
        assert!(!e1.text.contains("dropped line"));
        // The '€' that straddled the boundary was not split or partially included
        assert!(!e1.text.contains('€'));

        assert_eq!(asm.push_line(150_000, "also dropped"), None);
        let e2 = asm.finish().expect("flushes capped single-line entry");
        assert!(e2.text.len() <= MAX_ENTRY_BYTES);
        assert!(e2.text.ends_with(TRUNCATED_SUFFIX));
        assert_eq!(e2.text.matches(TRUNCATED_SUFFIX).count(), 1);
        assert!(!e2.text.contains('🦀'));
        assert!(!e2.text.contains("also dropped"));

        // Case 3: exact 65536-byte entry is not truncated
        let mut asm2 = Assembler::new(LogFormat::iso());
        let exact = format!("2026-05-01T00:02:00Z {}", "c".repeat(MAX_ENTRY_BYTES - 21));
        assert_eq!(exact.len(), MAX_ENTRY_BYTES);
        assert_eq!(asm2.push_line(0, &exact), None);
        let e3 = asm2.finish().expect("exact entry");
        assert_eq!(e3.text.len(), MAX_ENTRY_BYTES);
        assert!(!e3.text.ends_with(TRUNCATED_SUFFIX));

        // Case 4: entry initially between TRUNCATED_BUDGET and MAX_ENTRY_BYTES
        // with a multi-byte char straddling TRUNCATED_BUDGET, followed by a continuation
        let mut asm3 = Assembler::new(LogFormat::iso());
        let near_full = format!(
            "2026-05-01T00:03:00Z {}€€€",
            "d".repeat(TRUNCATED_BUDGET - 21 - 1)
        );
        assert!(near_full.len() > TRUNCATED_BUDGET && near_full.len() <= MAX_ENTRY_BYTES);
        assert_eq!(asm3.push_line(0, &near_full), None);
        assert_eq!(asm3.push_line(70_000, "pushes over cap"), None);
        let e4 = asm3.finish().expect("flushes truncated near-full entry");
        assert!(e4.text.len() <= MAX_ENTRY_BYTES);
        assert!(e4.text.ends_with(TRUNCATED_SUFFIX));
        assert_eq!(e4.text.matches(TRUNCATED_SUFFIX).count(), 1);
        assert!(!e4.text.contains('€'));
    }
}
