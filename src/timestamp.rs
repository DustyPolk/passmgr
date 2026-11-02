//! Presentation of the Unix-second timestamps stored in a vault.
//!
//! The encrypted payload stores whole seconds since 1970-01-01T00:00:00Z.
//! `0` means "unknown": it is what entries migrated from a pre-v4 payload
//! carry, because inventing a date at migration time would be a lie. Agent
//! output renders known values as RFC 3339 strings in UTC and unknown values
//! as `null`, so a consumer never has to guess a timezone or a sentinel.

use serde_json::Value;

/// Format `unix` seconds as an RFC 3339 UTC timestamp, for example
/// `2026-11-02T18:20:00Z`.
///
/// Every value a validated vault can hold (up to
/// [`store::MAX_TIMESTAMP_UNIX`](crate::store::MAX_TIMESTAMP_UNIX)) formats as
/// a four-digit year. Values above that bound are rejected by the store before
/// they reach this function; if one did, it would render with a five-digit
/// year rather than panic.
pub fn format_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let seconds_of_day = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The JSON form of a stored timestamp: a UTC string, or `null` when the value
/// is unknown (`0`, e.g. an entry migrated from a pre-v4 payload).
pub fn to_json(unix: u64) -> Value {
    if unix == 0 {
        Value::Null
    } else {
        Value::String(format_utc(unix))
    }
}

/// Convert days since 1970-01-01 to a proleptic Gregorian (year, month, day).
///
/// This is Howard Hinnant's `civil_from_days` algorithm, which is exact for the
/// whole `i64` range. Kept private so the only public surface is formatting.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of the cycle.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097); // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors generated with `date -u -d @<seconds> +%Y-%m-%dT%H:%M:%SZ`.
    #[test]
    fn formats_known_instants() {
        for (unix, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (86_400, "1970-01-02T00:00:00Z"),
            (951_782_399, "2000-02-28T23:59:59Z"),
            (951_782_400, "2000-02-29T00:00:00Z"), // leap day in a leap century
            (951_868_800, "2000-03-01T00:00:00Z"),
            (1_000_000_000, "2001-09-09T01:46:40Z"),
            (1_709_164_799, "2024-02-28T23:59:59Z"),
            (1_709_251_200, "2024-03-01T00:00:00Z"),
            (1_735_689_600, "2025-01-01T00:00:00Z"),
            (2_147_483_647, "2038-01-19T03:14:07Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"), // 2100 is not a leap year
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(format_utc(unix), expected, "unix seconds {unix}");
        }
    }

    #[test]
    fn zero_is_unknown_in_json_but_formats_as_the_epoch() {
        assert_eq!(to_json(0), Value::Null);
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            to_json(1_735_689_600),
            Value::String("2025-01-01T00:00:00Z".into())
        );
    }

    /// Every minute of a leap year round-trips to a fixed-width UTC string;
    /// the day after the leap day must be March 1, not February 30.
    #[test]
    fn leap_year_days_are_contiguous() {
        let start = 1_704_067_200; // 2024-01-01T00:00:00Z
        let days = 366;
        let mut previous = String::new();
        for day in 0..days {
            let rendered = format_utc(start + day * 86_400);
            assert_eq!(rendered.len(), 20);
            assert!(rendered.ends_with('Z'));
            assert!(rendered > previous, "{rendered} must follow {previous}");
            previous = rendered;
        }
        assert_eq!(format_utc(start + 59 * 86_400), "2024-02-29T00:00:00Z");
        assert_eq!(format_utc(start + 60 * 86_400), "2024-03-01T00:00:00Z");
    }
}
