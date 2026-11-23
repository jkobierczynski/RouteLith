// The Windows Event Log message table (doc §11.3, F8), shared by build.rs
// and a test in src/main.rs.

/// Event ID ranges routelith writes (see rl-out's `event_id`): alerts and
/// target changes, agents, the server. Every ID shows its first insertion
/// string, the event's message, as its text.
const RANGES: [(u32, u32); 3] = [(1000, 1099), (2000, 2099), (3000, 3099)];

/// A MESSAGE_RESOURCE_DATA block, as `mc.exe` would build it: a block count,
/// one (low ID, high ID, offset) triple per range, then one
/// MESSAGE_RESOURCE_ENTRY per ID (length, flags = 1 for UTF-16, text with
/// its NUL, padded to 4 bytes).
fn message_table() -> Vec<u8> {
    let mut text: Vec<u8> = "%1\r\n\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    while (text.len() + 4) % 4 != 0 {
        text.push(0);
    }
    let entry_len = u16::try_from(4 + text.len()).expect("short entry");
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(RANGES.len()).expect("few ranges").to_le_bytes());
    let mut offset = 4 + 12 * RANGES.len();
    for (low, high) in RANGES {
        out.extend_from_slice(&low.to_le_bytes());
        out.extend_from_slice(&high.to_le_bytes());
        out.extend_from_slice(&u32::try_from(offset).expect("small table").to_le_bytes());
        offset += (high - low + 1) as usize * usize::from(entry_len);
    }
    for (low, high) in RANGES {
        for _ in low..=high {
            out.extend_from_slice(&entry_len.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes());
            out.extend_from_slice(&text);
        }
    }
    out
}
