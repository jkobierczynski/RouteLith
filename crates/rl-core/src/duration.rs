//! Human-readable durations: `300s`, `5m`, `1.5s`, `250ms`, `500us`.

use std::time::Duration;

/// Parse a number with an optional unit (`h`, `m`, `s`, `ms`, `us` or `µs`;
/// seconds when there is none). Decimals are allowed; negative values,
/// NaN and infinity are not.
pub fn parse(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = match s.find(|c: char| c.is_ascii_alphabetic() || c == 'µ') {
        Some(i) => s.split_at(i),
        None => (s, "s"),
    };
    let num = num.trim();
    // One leading '+' is allowed, as Rust's float parser accepts it.
    let num = num.strip_prefix('+').unwrap_or(num);
    // Plain decimal digits only: rejects "-1", "inf", "NaN" and exponents.
    let valid = !num.is_empty()
        && num.bytes().filter(|&b| b == b'.').count() <= 1
        && num.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && num != ".";
    if !valid {
        return Err(format!("invalid duration: {s:?}"));
    }
    let value: f64 = num
        .parse()
        .map_err(|_| format!("invalid duration: {s:?}"))?;
    let secs = match unit {
        "h" => value * 3600.0,
        "m" => value * 60.0,
        "s" => value,
        "ms" => value / 1e3,
        "us" | "µs" => value / 1e6,
        _ => {
            return Err(format!("unknown unit in {s:?} (use h, m, s, ms or us)"));
        }
    };
    Duration::try_from_secs_f64(secs).map_err(|_| format!("invalid duration: {s:?}"))
}

/// Short display form: whole hours, minutes or seconds where exact,
/// otherwise milliseconds (with a fraction below 1 ms).
pub fn format(d: Duration) -> String {
    if d.subsec_nanos() % 1_000_000 != 0 {
        let ms = d.as_secs_f64() * 1e3;
        let s = format!("{ms:.6}");
        return format!("{}ms", s.trim_end_matches('0').trim_end_matches('.'));
    }
    let ms = d.as_millis();
    if ms % 1000 != 0 {
        return format!("{ms}ms");
    }
    let s = d.as_secs();
    if s != 0 && s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s != 0 && s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(parse("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse("2"), Ok(Duration::from_secs(2)));
        assert_eq!(parse("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse("500us"), Ok(Duration::from_micros(500)));
        assert_eq!(parse("500µs"), Ok(Duration::from_micros(500)));
        assert_eq!(parse(" 10 s "), Ok(Duration::from_secs(10)));
        assert_eq!(parse("+250ms"), Ok(Duration::from_millis(250)));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "", "s", "-1s", "++1s", "+-1s", "+", "inf", "NaN", "1e3s", "1.2.3s", ".s", "5d",
            "5 min",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn display() {
        assert_eq!(format(Duration::from_secs(300)), "5m");
        assert_eq!(format(Duration::from_secs(7200)), "2h");
        assert_eq!(format(Duration::from_secs(90)), "90s");
        assert_eq!(format(Duration::from_millis(1500)), "1500ms");
        assert_eq!(format(Duration::ZERO), "0s");
        assert_eq!(format(Duration::from_micros(500)), "0.5ms");
        assert_eq!(format(Duration::from_micros(1_000_250)), "1000.25ms");
    }
}
