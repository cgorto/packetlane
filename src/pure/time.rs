//! Calendar arithmetic on the proleptic Gregorian calendar, UTC, with no leap
//! seconds.
//!
//! All instants are `i64` nanoseconds since `1970-01-01T00:00:00Z` (covering
//! `1677-09-21T00:12:43.145224192Z` through `2262-04-11T23:47:16.854775807Z`).

pub const NS_PER_SEC: i64 = 1_000_000_000;
const SECS_PER_DAY: i64 = 86_400;

/// Civil date and time components in the proleptic Gregorian calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub nanos: u32,
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// Howard Hinnant's civil-to-days algorithm in `i128` to avoid intermediate
/// overflow for any `i64` year.
fn days_from_civil_i128(year: i64, month: u32, day: u32) -> i128 {
    let m = i128::from(month);
    let d = i128::from(day);
    let y = i128::from(year) - i128::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Days since `1970-01-01` in the proleptic Gregorian calendar.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let days = days_from_civil_i128(year, month, day);
    days.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// Proleptic Gregorian `(year, month, day)` for `days` since `1970-01-01`.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = i128::from(days) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i128::from(m <= 2);
    (year as i64, m as u32, d as u32)
}

/// Converts a local civil timestamp with `utc_offset_s` (seconds east of UTC)
/// into UTC nanoseconds since the Unix epoch.
pub(crate) fn civil_to_ns_with_offset(c: &Civil, utc_offset_s: i64) -> Option<i64> {
    let max_day = days_in_month(c.year, c.month)?;
    if c.day == 0 || c.day > max_day {
        return None;
    }
    if c.hour >= 24 || c.minute >= 60 || c.second >= 60 || c.nanos >= NS_PER_SEC as u32 {
        return None;
    }
    let days = days_from_civil_i128(c.year, c.month, c.day);
    let secs_of_day = i128::from(c.hour) * 3600 + i128::from(c.minute) * 60 + i128::from(c.second);
    let local_secs = days
        .checked_mul(i128::from(SECS_PER_DAY))?
        .checked_add(secs_of_day)?;
    let utc_secs = local_secs.checked_sub(i128::from(utc_offset_s))?;
    let total_ns = utc_secs
        .checked_mul(i128::from(NS_PER_SEC))?
        .checked_add(i128::from(c.nanos))?;
    i64::try_from(total_ns).ok()
}

/// Converts a UTC [`Civil`] date/time to nanoseconds since `1970-01-01T00:00:00Z`.
///
/// Returns `None` if any field is out of range (including day 31 in a 30-day
/// month, Feb 29 in a non-leap year, or second 60) or if the result overflows
/// `i64`.
pub fn civil_to_ns(c: &Civil) -> Option<i64> {
    civil_to_ns_with_offset(c, 0)
}

/// Converts nanoseconds since `1970-01-01T00:00:00Z` to a UTC [`Civil`].
/// Handles negative timestamps including `i64::MIN`.
pub fn ns_to_civil(ns: i64) -> Civil {
    let total_secs = ns.div_euclid(NS_PER_SEC);
    let nanos = ns.rem_euclid(NS_PER_SEC) as u32;
    let days = total_secs.div_euclid(SECS_PER_DAY);
    let secs_of_day = total_secs.rem_euclid(SECS_PER_DAY) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos,
    }
}

/// Formats `ns` as UTC ISO-8601 with always 9 fractional digits, e.g.
/// `"2026-01-02T03:04:05.123456789Z"`.
pub fn format_iso(ns: i64) -> String {
    let c = ns_to_civil(ns);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.nanos
    )
}

fn parse_two_digits(bytes: &[u8]) -> Option<u32> {
    let [a, b] = *bytes else {
        return None;
    };
    if !a.is_ascii_digit() || !b.is_ascii_digit() {
        return None;
    }
    Some(u32::from(a - b'0') * 10 + u32::from(b - b'0'))
}

fn parse_four_digits(bytes: &[u8]) -> Option<i64> {
    let [a, b, c, d] = *bytes else {
        return None;
    };
    if !a.is_ascii_digit() || !b.is_ascii_digit() || !c.is_ascii_digit() || !d.is_ascii_digit() {
        return None;
    }
    Some(
        i64::from(a - b'0') * 1000
            + i64::from(b - b'0') * 100
            + i64::from(c - b'0') * 10
            + i64::from(d - b'0'),
    )
}

/// Parses 1 to 9 ASCII fractional-second digits into nanoseconds.
pub(crate) fn parse_frac_ns(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 9 {
        return None;
    }
    let mut nanos = 0u32;
    let mut scale = 100_000_000u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        nanos += u32::from(b - b'0') * scale;
        scale /= 10;
    }
    Some(nanos)
}

/// Parses a UTC offset (`"Z"`, `"+02:00"`, `"-0530"`, `"+02"`) into seconds east
/// of UTC. Returns `None` for any other input.
pub fn parse_utc_offset(s: &str) -> Option<i64> {
    if s == "Z" {
        return Some(0);
    }
    let bytes = s.as_bytes();
    let (&sign_byte, rest) = bytes.split_first()?;
    let sign = match sign_byte {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let (hours, minutes) = match rest.len() {
        2 => (parse_two_digits(rest)?, 0),
        4 => (
            parse_two_digits(rest.get(0..2)?)?,
            parse_two_digits(rest.get(2..4)?)?,
        ),
        5 => {
            if *rest.get(2)? != b':' {
                return None;
            }
            (
                parse_two_digits(rest.get(0..2)?)?,
                parse_two_digits(rest.get(3..5)?)?,
            )
        }
        _ => return None,
    };
    if hours >= 24 || minutes >= 60 {
        return None;
    }
    Some(sign * (i64::from(hours) * 3600 + i64::from(minutes) * 60))
}

/// Parses an ISO-8601 timestamp (`"YYYY-MM-DD"`, `'T'` or `' '`, `"HH:MM:SS"`,
/// optional `'.'` or `','` with 1..=9 digits, optional UTC offset) into
/// nanoseconds since `1970-01-01T00:00:00Z`.
///
/// An omitted offset is treated as UTC. Surrounding whitespace is rejected.
pub fn parse_iso(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    let head = bytes.get(0..19)?;
    if *head.get(4)? != b'-'
        || *head.get(7)? != b'-'
        || !matches!(*head.get(10)?, b'T' | b' ')
        || *head.get(13)? != b':'
        || *head.get(16)? != b':'
    {
        return None;
    }
    let year = parse_four_digits(head.get(0..4)?)?;
    let month = parse_two_digits(head.get(5..7)?)?;
    let day = parse_two_digits(head.get(8..10)?)?;
    let hour = parse_two_digits(head.get(11..13)?)?;
    let minute = parse_two_digits(head.get(14..16)?)?;
    let second = parse_two_digits(head.get(17..19)?)?;

    let mut rest = bytes.get(19..)?;
    let nanos = if matches!(rest.first(), Some(b'.' | b',')) {
        let after_sep = rest.get(1..)?;
        let digits = after_sep.iter().take_while(|b| b.is_ascii_digit()).count();
        let n = parse_frac_ns(after_sep.get(0..digits)?)?;
        rest = after_sep.get(digits..)?;
        n
    } else {
        0
    };

    let offset_s = if rest.is_empty() {
        0
    } else {
        let tz = std::str::from_utf8(rest).ok()?;
        parse_utc_offset(tz)?
    };

    let civil = Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos,
    };
    civil_to_ns_with_offset(&civil, offset_s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn civil(
        year: i64,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        nanos: u32,
    ) -> Civil {
        Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanos,
        }
    }

    #[test]
    fn known_dates() {
        // Unix epoch
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_to_ns(&civil(1970, 1, 1, 0, 0, 0, 0)), Some(0));
        assert_eq!(ns_to_civil(0), civil(1970, 1, 1, 0, 0, 0, 0));
        assert_eq!(format_iso(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));

        // 2000-02-29 (century leap year, divisible by 400)
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        let y2k_leap = 11_016 * SECS_PER_DAY * NS_PER_SEC;
        assert_eq!(civil_to_ns(&civil(2000, 2, 29, 0, 0, 0, 0)), Some(y2k_leap));
        assert_eq!(format_iso(y2k_leap), "2000-02-29T00:00:00.000000000Z");

        // 1969-12-31T23:59:59.999999999Z (-1 ns)
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(
            civil_to_ns(&civil(1969, 12, 31, 23, 59, 59, 999_999_999)),
            Some(-1)
        );
        assert_eq!(
            ns_to_civil(-1),
            civil(1969, 12, 31, 23, 59, 59, 999_999_999)
        );
        assert_eq!(format_iso(-1), "1969-12-31T23:59:59.999999999Z");
        assert_eq!(parse_iso("1969-12-31T23:59:59.999999999Z"), Some(-1));

        // 2100 is not a leap year (divisible by 100, not 400)
        let feb28 = days_from_civil(2100, 2, 28);
        let mar01 = days_from_civil(2100, 3, 1);
        assert_eq!(mar01 - feb28, 1);
        assert_eq!(civil_from_days(feb28), (2100, 2, 28));
        assert_eq!(civil_from_days(mar01), (2100, 3, 1));
        assert_eq!(civil_to_ns(&civil(2100, 2, 29, 0, 0, 0, 0)), None);

        // Far-future dates: both within i64 ns range and far beyond it in days
        let far_ns = parse_iso("2250-06-15T12:34:56.789012345Z").expect("valid far future");
        assert_eq!(format_iso(far_ns), "2250-06-15T12:34:56.789012345Z");
        assert_eq!(
            ns_to_civil(far_ns),
            civil(2250, 6, 15, 12, 34, 56, 789_012_345)
        );

        let d_9999 = days_from_civil(9999, 12, 31);
        assert_eq!(civil_from_days(d_9999), (9999, 12, 31));
        assert_eq!(civil_from_days(d_9999 + 1), (10_000, 1, 1));
        // 10000 is divisible by 400 -> leap year
        assert_eq!(
            days_from_civil(10_000, 3, 1) - days_from_civil(10_000, 2, 28),
            2
        );
    }

    #[test]
    fn day_round_trips_and_continuity() {
        // Span > 800 years (two full Gregorian 400-year cycles) crossing epoch
        let start = days_from_civil(1600, 1, 1);
        let end = days_from_civil(2401, 1, 1);
        let mut prev = civil_from_days(start - 1);
        for d in start..=end {
            let cur = civil_from_days(d);
            assert_eq!(days_from_civil(cur.0, cur.1, cur.2), d);
            // Verify strict monotonic calendar progression
            assert!(cur > prev, "expected {cur:?} > {prev:?} at day {d}");
            prev = cur;
        }
    }

    #[test]
    fn ns_round_trips_including_extremes() {
        for ns in [
            i64::MIN,
            i64::MIN + 1,
            -NS_PER_SEC * 86_400 - 1,
            -NS_PER_SEC,
            -1,
            0,
            1,
            NS_PER_SEC - 1,
            NS_PER_SEC,
            1_767_323_045_123_456_789,
            i64::MAX - 1,
            i64::MAX,
        ] {
            let c = ns_to_civil(ns);
            assert_eq!(civil_to_ns(&c), Some(ns), "failed for ns={ns}");
            let s = format_iso(ns);
            assert_eq!(parse_iso(&s), Some(ns), "ISO round-trip failed for {s}");
        }
    }

    #[test]
    fn civil_to_ns_rejections() {
        let valid = civil(2025, 4, 15, 12, 30, 45, 0);
        assert!(civil_to_ns(&valid).is_some());

        // Bad months
        assert_eq!(civil_to_ns(&civil(2025, 0, 1, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(2025, 13, 1, 0, 0, 0, 0)), None);

        // Bad days
        assert_eq!(civil_to_ns(&civil(2025, 1, 0, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(2025, 1, 32, 0, 0, 0, 0)), None);
        // Day 31 in 30-day months
        for m in [4, 6, 9, 11] {
            assert_eq!(civil_to_ns(&civil(2025, m, 31, 0, 0, 0, 0)), None);
        }
        // Feb 29 in non-leap years, Feb 30 in leap year
        assert_eq!(civil_to_ns(&civil(2025, 2, 29, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(1900, 2, 29, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(2100, 2, 29, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(2000, 2, 30, 0, 0, 0, 0)), None);

        // Bad time fields (including leap second 60)
        assert_eq!(civil_to_ns(&civil(2025, 1, 1, 24, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(2025, 1, 1, 0, 60, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(2025, 1, 1, 0, 0, 60, 0)), None);
        assert_eq!(
            civil_to_ns(&civil(2025, 1, 1, 0, 0, 0, NS_PER_SEC as u32)),
            None
        );

        // Overflow (high and low, including 1 ns past i64 bounds)
        assert_eq!(
            civil_to_ns(&civil(2262, 4, 11, 23, 47, 16, 854_775_808)),
            None
        );
        assert_eq!(
            civil_to_ns(&civil(1677, 9, 21, 0, 12, 43, 145_224_191)),
            None
        );
        assert_eq!(civil_to_ns(&civil(2300, 1, 1, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(1600, 1, 1, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(i64::MAX, 1, 1, 0, 0, 0, 0)), None);
        assert_eq!(civil_to_ns(&civil(i64::MIN, 1, 1, 0, 0, 0, 0)), None);
    }

    #[test]
    fn parse_utc_offset_cases() {
        assert_eq!(parse_utc_offset("Z"), Some(0));
        assert_eq!(parse_utc_offset("+00:00"), Some(0));
        assert_eq!(parse_utc_offset("-00:00"), Some(0));
        assert_eq!(parse_utc_offset("+02:00"), Some(7_200));
        assert_eq!(parse_utc_offset("-0530"), Some(-19_800));
        assert_eq!(parse_utc_offset("+02"), Some(7_200));
        assert_eq!(parse_utc_offset("-11"), Some(-39_600));
        assert_eq!(parse_utc_offset("+23:59"), Some(86_340));
        assert_eq!(parse_utc_offset("-2359"), Some(-86_340));

        for bad in [
            "", "z", " Z", "Z ", "+2", "+020", "+02:0", "+02:000", "02:00", "+24:00", "-24:00",
            "+02:60", "+02-00", "UTC", "+ab:cd", "+02:00 ",
        ] {
            assert_eq!(parse_utc_offset(bad), None, "expected None for {bad:?}");
        }
    }

    #[test]
    fn parse_iso_valid_and_rejections() {
        let base = civil_to_ns(&civil(2026, 1, 2, 3, 4, 5, 0)).expect("base");
        assert_eq!(parse_iso("2026-01-02T03:04:05Z"), Some(base));
        assert_eq!(parse_iso("2026-01-02T03:04:05"), Some(base));
        assert_eq!(parse_iso("2026-01-02 03:04:05"), Some(base));
        assert_eq!(
            parse_iso("2026-01-02T03:04:05.5Z"),
            Some(base + 500_000_000)
        );
        assert_eq!(
            parse_iso("2026-01-02 03:04:05,123456789Z"),
            Some(base + 123_456_789)
        );
        assert_eq!(parse_iso("2026-01-02T05:04:05+02:00"), Some(base));
        assert_eq!(parse_iso("2026-01-01T21:34:05-0530"), Some(base));
        assert_eq!(parse_iso("2026-01-02T05:04:05+02"), Some(base));

        for bad in [
            "",
            "2026-01-02",
            "2026-01-02T03:04Z",
            " 2026-01-02T03:04:05Z",
            "2026-01-02T03:04:05Z ",
            "2026-01-02T03:04:05\n",
            "2026-01-02t03:04:05Z",
            "2026-01-02  03:04:05Z",
            "2026/01/02T03:04:05Z",
            "2026-01-02T03-04-05Z",
            "2026-1-02T03:04:05Z",
            "2026-01-02T03:04:05.",
            "2026-01-02T03:04:05.Z",
            "2026-01-02T03:04:05,Z",
            "2026-01-02T03:04:05.1234567890Z",
            "2026-01-02T03:04:05+24:00",
            "2026-01-02T03:04:05UTC",
            "2026-01-02T03:04:05Zextra",
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-01-02T24:00:00Z",
            "2026-01-02T03:60:00Z",
            "2026-01-02T03:04:60Z",
            "1600-01-01T00:00:00Z",
            "2300-01-01T00:00:00Z",
            "2026-01-02T03:04:05é",
            "🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀",
        ] {
            assert_eq!(parse_iso(bad), None, "expected None for {bad:?}");
        }
    }
}
