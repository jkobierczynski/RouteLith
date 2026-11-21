//! Silences (architecture doc §12, §21.5 F6): times when alerts are still
//! raised and logged but not sent. A silence is one window with a start
//! and an end, or a recurring one: a small RRULE subset (FREQ=DAILY or
//! WEEKLY, BYDAY, BYHOUR, BYMINUTE) plus a duration, in UTC.
//!
//! ```toml
//! [[silence]]
//! name     = "sunday-maintenance"
//! groups   = ["datacenter"]
//! rrule    = "FREQ=WEEKLY;BYDAY=SU;BYHOUR=2;BYMINUTE=0"
//! duration = "2h"
//!
//! [[silence]]
//! name    = "isp-works"
//! targets = ["isp-gw"]
//! start   = "2026-12-01T22:00:00Z"
//! end     = "2026-12-02T04:00:00+01:00"
//! ```

use std::fmt::Write as _;

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// A validated silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Silence {
    pub name: String,
    /// Targets it covers; with `groups` empty too, it covers every target.
    pub targets: Vec<String>,
    pub groups: Vec<String>,
    /// Alert rules it covers; empty for all of them.
    pub alerts: Vec<String>,
    pub when: When,
    /// Line of the `[[silence]]` table, for messages.
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum When {
    /// `start <= t < end`, Unix milliseconds.
    Once { start_ms: i64, end_ms: i64 },
    /// Every occurrence of `rule`, for `duration_ms`, optionally only
    /// within `start <= t < end`.
    Every {
        rule: Recurrence,
        duration_ms: i64,
        start_ms: Option<i64>,
        end_ms: Option<i64>,
    },
}

/// When a recurring silence starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recurrence {
    /// Days of the week it starts on, 0 = Monday; empty for every day.
    pub days: Vec<u8>,
    /// Start times within the day, (hour, minute), UTC, sorted.
    pub times: Vec<(u8, u8)>,
    /// The rule as written, for listings.
    pub text: String,
}

const WEEKDAYS: [&str; 7] = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"];

impl Silence {
    /// Whether it covers an alert of `rule` on `target` in `group`.
    pub fn applies(&self, target: &str, group: &str, rule: &str) -> bool {
        let everywhere = self.targets.is_empty() && self.groups.is_empty();
        let place = everywhere
            || self.targets.iter().any(|t| t == target)
            || self.groups.iter().any(|g| g == group);
        place && (self.alerts.is_empty() || self.alerts.iter().any(|a| a == rule))
    }

    /// Whether it is in force at `t_ms`.
    pub fn active_at(&self, t_ms: i64) -> bool {
        match &self.when {
            When::Once { start_ms, end_ms } => *start_ms <= t_ms && t_ms < *end_ms,
            When::Every {
                rule,
                duration_ms,
                start_ms,
                end_ms,
            } => {
                if start_ms.is_some_and(|s| t_ms < s) || end_ms.is_some_and(|e| t_ms >= e) {
                    return false;
                }
                // Occurrences that began up to `duration` ago.
                let today = t_ms.div_euclid(DAY_MS);
                let back = (duration_ms + DAY_MS - 1) / DAY_MS;
                (today - back..=today).any(|day| {
                    // 1970-01-01 was a Thursday (3, counting from Monday).
                    let weekday = u8::try_from((day + 3).rem_euclid(7)).unwrap_or(0);
                    (rule.days.is_empty() || rule.days.contains(&weekday))
                        && rule.times.iter().any(|&(h, m)| {
                            let o =
                                day * DAY_MS + i64::from(h) * HOUR_MS + i64::from(m) * MINUTE_MS;
                            o <= t_ms && t_ms < o + duration_ms
                        })
                })
            }
        }
    }

    /// When it applies, in one line.
    pub fn summary(&self) -> String {
        match &self.when {
            When::Once { start_ms, end_ms } => {
                format!("{} to {}", format_time(*start_ms), format_time(*end_ms))
            }
            When::Every {
                rule,
                duration_ms,
                start_ms,
                end_ms,
            } => {
                let mut s = format!(
                    "{} for {}",
                    rule.text,
                    crate::duration::format(std::time::Duration::from_millis(
                        u64::try_from(*duration_ms).unwrap_or(0)
                    ))
                );
                if let Some(t) = start_ms {
                    let _ = write!(s, ", from {}", format_time(*t));
                }
                if let Some(t) = end_ms {
                    let _ = write!(s, ", until {}", format_time(*t));
                }
                s
            }
        }
    }
}

/// `FREQ=DAILY|WEEKLY` with BYDAY, BYHOUR and BYMINUTE (UTC). A weekly
/// rule needs BYDAY, since there is no DTSTART to take the day from.
pub fn parse_rrule(s: &str) -> Result<Recurrence, String> {
    let text = s.trim().strip_prefix("RRULE:").unwrap_or(s.trim());
    let mut freq = None;
    let mut days = Vec::new();
    let mut hours = vec![0u8];
    let mut minutes = vec![0u8];
    let list = |v: &str, max: u8, key: &str| -> Result<Vec<u8>, String> {
        let mut out: Vec<u8> = v
            .split(',')
            .map(|x| match x.trim().parse::<u8>() {
                Ok(n) if n <= max => Ok(n),
                _ => Err(format!(
                    "rrule {key}: {x:?} is not a number from 0 to {max}"
                )),
            })
            .collect::<Result<_, _>>()?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    };
    for part in text.split(';').filter(|p| !p.trim().is_empty()) {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("rrule: {part:?} is not KEY=VALUE"))?;
        match k.trim().to_ascii_uppercase().as_str() {
            "FREQ" => match v.trim().to_ascii_uppercase().as_str() {
                f @ ("DAILY" | "WEEKLY") => freq = Some(f.to_string()),
                other => {
                    return Err(format!(
                        "rrule FREQ={other} is not supported; use DAILY or WEEKLY"
                    ));
                }
            },
            "BYDAY" => {
                for d in v.split(',') {
                    let d = d.trim().to_ascii_uppercase();
                    let i = WEEKDAYS
                        .iter()
                        .position(|w| *w == d)
                        .ok_or_else(|| format!("rrule BYDAY: {d:?} is not one of MO … SU"))?;
                    days.push(u8::try_from(i).unwrap_or(0));
                }
                days.sort_unstable();
                days.dedup();
            }
            "BYHOUR" => hours = list(v, 23, "BYHOUR")?,
            "BYMINUTE" => minutes = list(v, 59, "BYMINUTE")?,
            other => {
                return Err(format!(
                    "rrule {other} is not supported; use FREQ, BYDAY, BYHOUR and BYMINUTE"
                ));
            }
        }
    }
    let freq = freq.ok_or("rrule needs FREQ=DAILY or FREQ=WEEKLY")?;
    if freq == "WEEKLY" && days.is_empty() {
        return Err("a weekly rrule needs BYDAY, as in \"FREQ=WEEKLY;BYDAY=SU\"".into());
    }
    let times = hours
        .iter()
        .flat_map(|&h| minutes.iter().map(move |&m| (h, m)))
        .collect();
    Ok(Recurrence {
        days,
        times,
        text: text.to_string(),
    })
}

/// An RFC 3339 time with an offset (`Z` or `±hh:mm`), seconds optional:
/// `2026-12-01T22:00:00Z`, `2026-12-01T23:00+01:00`. Unix milliseconds.
pub fn parse_time(s: &str) -> Result<i64, String> {
    let bad = || {
        format!(
            "{s:?} is not a time with a zone, as in \"2026-12-01T22:00:00Z\" or \
             \"2026-12-01T23:00:00+01:00\""
        )
    };
    let s = s.trim();
    let (date, rest) = s.split_once(['T', 't', ' ']).ok_or_else(bad)?;
    let num = |x: &str, lo: i64, hi: i64| -> Result<i64, String> {
        match x.parse::<i64>() {
            Ok(n) if x.len() >= 2 && (lo..=hi).contains(&n) => Ok(n),
            _ => Err(bad()),
        }
    };
    let d: Vec<&str> = date.split('-').collect();
    let [y, mo, da] = d[..] else {
        return Err(bad());
    };
    let (y, mo) = (num(y, 1970, 9999)?, num(mo, 1, 12)?);
    let da = num(da, 1, days_in_month(y, mo))?;
    let (clock, offset_ms) = if let Some(c) = rest.strip_suffix(['Z', 'z']) {
        (c, 0)
    } else {
        let i = rest.rfind(['+', '-']).ok_or_else(bad)?;
        let (c, off) = rest.split_at(i);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':').ok_or_else(bad)?;
        (
            c,
            sign * (num(oh, 0, 23)? * HOUR_MS + num(om, 0, 59)? * MINUTE_MS),
        )
    };
    let t: Vec<&str> = clock.split(':').collect();
    let (h, mi, sec) = match t[..] {
        [h, m] => (h, m, "00"),
        [h, m, s] => (h, m, s),
        _ => return Err(bad()),
    };
    // Fractional seconds are allowed; milliseconds are kept.
    let (sec, frac_ms) = match sec.split_once('.') {
        None => (sec, 0),
        Some((sec, frac)) if !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit()) => {
            let digits: String = frac.chars().chain("00".chars()).take(3).collect();
            (sec, digits.parse::<i64>().map_err(|_| bad())?)
        }
        Some(_) => return Err(bad()),
    };
    let (h, mi, sec) = (num(h, 0, 23)?, num(mi, 0, 59)?, num(sec, 0, 59)?);
    Ok(
        days_from_civil(y, mo, da) * DAY_MS + h * HOUR_MS + mi * MINUTE_MS + sec * 1000 + frac_ms
            - offset_ms,
    )
}

/// `2026-12-01 22:00 UTC`.
pub fn format_time(ms: i64) -> String {
    let (y, m, d) = civil_from_days(ms.div_euclid(DAY_MS));
    let in_day = ms.rem_euclid(DAY_MS);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        in_day / HOUR_MS,
        in_day % HOUR_MS / MINUTE_MS
    )
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every(rrule: &str, duration_ms: i64) -> Silence {
        Silence {
            name: "s".into(),
            targets: Vec::new(),
            groups: Vec::new(),
            alerts: Vec::new(),
            when: When::Every {
                rule: parse_rrule(rrule).unwrap(),
                duration_ms,
                start_ms: None,
                end_ms: None,
            },
            line: 1,
        }
    }

    fn t(s: &str) -> i64 {
        parse_time(s).unwrap()
    }

    #[test]
    fn times_parse_with_their_zone() {
        assert_eq!(t("1970-01-01T00:00:00Z"), 0);
        assert_eq!(t("2026-12-01T22:00:00Z"), 1_796_162_400_000);
        assert_eq!(t("2026-12-01T23:00+01:00"), t("2026-12-01T22:00:00Z"));
        assert_eq!(t("2026-12-01T20:30:00-01:30"), t("2026-12-01T22:00:00Z"));
        assert_eq!(
            t("2024-02-29T00:00:00Z") + DAY_MS,
            t("2024-03-01T00:00:00Z")
        );
        // Fractional seconds, kept to the millisecond.
        assert_eq!(t("2026-12-01T22:00:00.5Z"), t("2026-12-01T22:00:00Z") + 500);
        assert_eq!(
            t("2026-12-01T22:00:01.123456Z"),
            t("2026-12-01T22:00:00Z") + 1123
        );
        for bad in [
            "2026-12-01T22:00:00.Z",
            "2026-12-01T22:00:00.5xZ",
            "2026-12-01T22:00:00",
            "2026-12-01",
            "2026-02-30T00:00Z",
            "2026-13-01T00:00Z",
            "2026-12-01T24:00Z",
            "26-12-01T22:00Z",
            "2026-12-01T22:00:00+0100",
            "yesterday",
        ] {
            assert!(parse_time(bad).is_err(), "{bad}");
        }
        assert_eq!(
            format_time(t("2026-12-01T23:05:00+01:00")),
            "2026-12-01 22:05 UTC"
        );
    }

    #[test]
    fn rrules_take_the_supported_subset() {
        let r = parse_rrule("RRULE:FREQ=WEEKLY;BYDAY=SU,MO;BYHOUR=2,14;BYMINUTE=30").unwrap();
        assert_eq!(r.days, [0, 6]);
        assert_eq!(r.times, [(2, 30), (14, 30)]);
        assert_eq!(parse_rrule("FREQ=DAILY").unwrap().times, [(0, 0)]);
        for bad in [
            "FREQ=MONTHLY",
            "FREQ=WEEKLY",
            "BYHOUR=2",
            "FREQ=DAILY;BYHOUR=24",
            "FREQ=DAILY;BYDAY=XX",
            "FREQ=DAILY;INTERVAL=2",
            "FREQ=DAILY;COUNT",
        ] {
            assert!(parse_rrule(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn recurring_windows_cover_their_occurrences() {
        // 2026-11-22 is a Sunday.
        let s = every("FREQ=WEEKLY;BYDAY=SU;BYHOUR=23;BYMINUTE=0", 2 * HOUR_MS);
        assert!(!s.active_at(t("2026-11-22T22:59:59Z")));
        assert!(s.active_at(t("2026-11-22T23:00:00Z")));
        // Into Monday, past midnight.
        assert!(s.active_at(t("2026-11-23T00:59:59Z")));
        assert!(!s.active_at(t("2026-11-23T01:00:00Z")));
        assert!(!s.active_at(t("2026-11-25T23:30:00Z")));
        assert!(s.active_at(t("2026-11-29T23:30:00Z")));
        // A window longer than a day.
        let s = every("FREQ=DAILY;BYHOUR=12", 30 * HOUR_MS);
        assert!(s.active_at(t("2026-11-23T11:00:00Z")));
        let mut bounded = every("FREQ=DAILY;BYHOUR=1", HOUR_MS);
        if let When::Every {
            start_ms, end_ms, ..
        } = &mut bounded.when
        {
            *start_ms = Some(t("2026-11-23T00:00:00Z"));
            *end_ms = Some(t("2026-11-24T00:00:00Z"));
        }
        assert!(!bounded.active_at(t("2026-11-22T01:30:00Z")));
        assert!(bounded.active_at(t("2026-11-23T01:30:00Z")));
        assert!(!bounded.active_at(t("2026-11-24T01:30:00Z")));
        assert_eq!(
            bounded.summary(),
            "FREQ=DAILY;BYHOUR=1 for 1h, from 2026-11-23 00:00 UTC, until 2026-11-24 00:00 UTC"
        );
    }

    #[test]
    fn scope_is_targets_groups_and_rules() {
        let mut s = every("FREQ=DAILY", HOUR_MS);
        assert!(s.applies("a", "g", "slow"));
        s.groups = vec!["dc".into()];
        assert!(!s.applies("a", "g", "slow"));
        assert!(s.applies("a", "dc", "slow"));
        s.targets = vec!["a".into()];
        assert!(s.applies("a", "g", "slow"));
        s.alerts = vec!["loss".into()];
        assert!(!s.applies("a", "g", "slow"));
        assert!(s.applies("a", "g", "loss"));
    }
}
