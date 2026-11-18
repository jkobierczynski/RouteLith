//! ICMP / ICMPv6 echo messages.
//!
//! Layout: 8-byte ICMP header (type, code, checksum, identifier, sequence), then
//! the payload. The first 8 payload bytes are a per-request nonce, so stray or
//! duplicate replies are rejected; the rest is a fixed fill pattern.

/// Smallest payload that still carries the nonce.
pub const MIN_PAYLOAD: usize = 8;
/// Default payload size, as `ping`.
pub const DEFAULT_PAYLOAD: u16 = 56;

const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;
const HEADER: usize = 8;

/// Build an echo request. `payload_size` is raised to [`MIN_PAYLOAD`] if smaller.
///
/// For ICMPv4 the checksum is filled in; for ICMPv6 it is left zero because the
/// kernel must compute it over the pseudo-header. (Linux ping sockets overwrite
/// the v4 checksum and the identifier anyway.)
pub fn build_echo_request(
    v6: bool,
    ident: u16,
    seq: u16,
    nonce: u64,
    payload_size: usize,
) -> Vec<u8> {
    let payload_size = payload_size.max(MIN_PAYLOAD);
    let mut buf = vec![0u8; HEADER + payload_size];
    buf[0] = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST_V4 };
    buf[4..6].copy_from_slice(&ident.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..16].copy_from_slice(&nonce.to_be_bytes());
    for (i, b) in buf[16..].iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    if !v6 {
        let sum = checksum(&buf);
        buf[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    buf
}

/// The parts of an echo reply used for matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoReply {
    pub ident: u16,
    pub seq: u16,
    /// `None` if the payload was too short to hold a nonce.
    pub nonce: Option<u64>,
}

/// Parse an echo reply that starts at the ICMP header (as ping sockets deliver it).
/// Returns `None` for anything that is not an echo reply of the given family.
pub fn parse_echo_reply(v6: bool, buf: &[u8]) -> Option<EchoReply> {
    if buf.len() < HEADER {
        return None;
    }
    let expected = if v6 { ECHO_REPLY_V6 } else { ECHO_REPLY_V4 };
    if buf[0] != expected || buf[1] != 0 {
        return None;
    }
    let ident = u16::from_be_bytes([buf[4], buf[5]]);
    let seq = u16::from_be_bytes([buf[6], buf[7]]);
    let nonce = buf
        .get(8..16)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes);
    Some(EchoReply { ident, seq, nonce })
}

/// RFC 1071 Internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_request_has_valid_checksum() {
        let pkt = build_echo_request(false, 0x1234, 7, 0xdead_beef, 56);
        assert_eq!(pkt.len(), 64);
        assert_eq!(pkt[0], 8);
        // A correct checksum makes the checksum over the whole message zero.
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        // RFC 1071 §3 example bytes: sum = 0xddf2, checksum = !0xddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2);
    }

    #[test]
    fn odd_length_checksum_pads_with_zero() {
        assert_eq!(checksum(&[0xab]), !0xab00);
    }

    #[test]
    fn payload_is_at_least_the_nonce() {
        let pkt = build_echo_request(true, 1, 1, 1, 0);
        assert_eq!(pkt.len(), 16);
        assert_eq!(pkt[0], 128);
        assert_eq!(&pkt[2..4], &[0, 0], "v6 checksum is left to the kernel");
    }

    #[test]
    fn reply_round_trip() {
        for v6 in [false, true] {
            let mut pkt = build_echo_request(v6, 0x4242, 513, 0x0102_0304_0506_0708, 56);
            pkt[0] = if v6 { 129 } else { 0 };
            let reply = parse_echo_reply(v6, &pkt).unwrap();
            assert_eq!(reply.ident, 0x4242);
            assert_eq!(reply.seq, 513);
            assert_eq!(reply.nonce, Some(0x0102_0304_0506_0708));
        }
    }

    #[test]
    fn rejects_requests_and_wrong_family() {
        let req = build_echo_request(false, 1, 1, 1, 56);
        assert_eq!(parse_echo_reply(false, &req), None);
        let mut reply_v4 = req.clone();
        reply_v4[0] = 0;
        assert_eq!(parse_echo_reply(true, &reply_v4), None);
        assert_eq!(parse_echo_reply(false, &reply_v4[..4]), None);
    }
}
