//! Just enough DER to read a certificate's `notAfter` (RFC 5280 §4.1),
//! so certificate expiry can be exported without an X.509 library.
//!
//! The input comes from the network, so every length is bounds-checked and
//! anything unexpected yields `None`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SEQUENCE: u8 = 0x30;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT Version` in the TBSCertificate.
const VERSION_TAG: u8 = 0xa0;

/// The `notAfter` time of a DER-encoded certificate.
pub(crate) fn not_after(der: &[u8]) -> Option<SystemTime> {
    let (tag, cert, _) = tlv(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, mut tbs, _) = tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    // Skip the optional version, then serialNumber, signature and issuer.
    let (tag, _, rest) = tlv(tbs)?;
    if tag == VERSION_TAG {
        tbs = rest;
        let (_, _, rest) = tlv(tbs)?;
        tbs = rest;
    } else {
        tbs = rest;
    }
    for _ in 0..2 {
        let (_, _, rest) = tlv(tbs)?;
        tbs = rest;
    }
    let (tag, validity, _) = tlv(tbs)?;
    if tag != SEQUENCE {
        return None;
    }
    let (_, _, rest) = tlv(validity)?; // notBefore
    let (tag, time, _) = tlv(rest)?;
    parse_time(tag, time)
}

/// One tag-length-value: `(tag, value, rest)`. Only single-byte tags and
/// definite lengths, which is all DER allows for these fields.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | usize::from(b);
        }
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    Some((tag, value, rest))
}

/// `YYMMDDHHMMSSZ` (UTCTime, years 1950–2049) or `YYYYMMDDHHMMSSZ`
/// (GeneralizedTime), as RFC 5280 requires them.
fn parse_time(tag: u8, s: &[u8]) -> Option<SystemTime> {
    let digits = |r: &[u8]| -> Option<u64> {
        r.iter().try_fold(0u64, |acc, &b| {
            b.is_ascii_digit().then(|| acc * 10 + u64::from(b - b'0'))
        })
    };
    let (year, rest) = match tag {
        UTC_TIME if s.len() == 13 => {
            let yy = digits(&s[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        GENERALIZED_TIME if s.len() == 15 => (digits(&s[..4])?, &s[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86_400 + hour * 3600 + min * 60 + sec;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm); `None` before 1970.
fn days_from_civil(y: u64, m: u64, d: u64) -> Option<u64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2000, 3, 1), Some(11_017));
        assert_eq!(days_from_civil(2026, 11, 19), Some(20_776));
        assert_eq!(days_from_civil(1969, 12, 31), None);
    }

    #[test]
    fn times() {
        let t = parse_time(UTC_TIME, b"491231235959Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            2_524_607_999
        );
        let g = parse_time(GENERALIZED_TIME, b"20491231235959Z").unwrap();
        assert_eq!(t, g);
        assert!(parse_time(UTC_TIME, b"491231235959+0100").is_none());
        assert!(parse_time(UTC_TIME, b"491331235959Z").is_none());
    }

    #[test]
    fn rcgen_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["lab.test".into()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 6, 15);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let t = not_after(cert.der()).unwrap();
        let days = t.duration_since(UNIX_EPOCH).unwrap().as_secs() / 86_400;
        assert_eq!(days, days_from_civil(2031, 6, 15).unwrap());
    }

    #[test]
    fn garbage_is_rejected_without_panicking() {
        assert!(not_after(&[]).is_none());
        assert!(not_after(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        assert!(not_after(&[0x30, 0x03, 0x30, 0x01]).is_none());
        // Every truncation of a real certificate.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der();
        for n in 0..der.len() {
            let _ = not_after(&der[..n]);
        }
    }
}
