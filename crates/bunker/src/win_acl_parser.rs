//! Bounds-checked parsing of the simple Windows ACL entries Bunker supports.
use anyhow::{ensure, Result};

pub(crate) struct Ace<'a> {
    pub kind: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: &'a [u8],
}

pub(crate) fn sid_length(bytes: &[u8]) -> Result<usize> {
    ensure!(bytes.len() >= 8, "truncated SID header");
    let length = 8 + 4 * usize::from(bytes[1]);
    ensure!(
        length <= bytes.len(),
        "SID extends beyond access control entry"
    );
    Ok(length)
}

pub(crate) fn parse_acl(bytes: &[u8]) -> Result<Vec<Ace<'_>>> {
    ensure!(bytes.len() >= 8, "truncated ACL header");
    let size = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    ensure!(size >= 8 && size <= bytes.len(), "invalid ACL size");
    let count = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    // Header + mask + minimum SID, before allocating or walking any entries.
    ensure!(count <= (size - 8) / 16, "invalid ACL entry count");
    let mut offset = 8;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        ensure!(size - offset >= 4, "truncated ACE header");
        let entry_size = usize::from(u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]));
        ensure!(
            entry_size >= 16 && entry_size % 4 == 0 && entry_size <= size - offset,
            "invalid ACE size"
        );
        let entry = &bytes[offset..offset + entry_size];
        ensure!(entry[0] <= 1, "unsupported access control entry");
        let sid = &entry[8..];
        let length = sid_length(sid)?;
        entries.push(Ace {
            kind: entry[0],
            flags: entry[1],
            mask: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
            sid: &sid[..length],
        });
        offset += entry_size;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        // One allow ACE with a one-subauthority SID.
        vec![
            2, 0, 28, 0, 1, 0, 0, 0, 0, 3, 20, 0, 0xff, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0,
            0,
        ]
    }

    #[test]
    fn simple_acl_fields_are_preserved() {
        let bytes = fixture();
        let entries = parse_acl(&bytes).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (entries[0].kind, entries[0].flags, entries[0].mask),
            (0, 3, 255)
        );
        assert_eq!(entries[0].sid.len(), 12);
    }

    #[test]
    fn truncated_and_oversized_acl_entries_fail_closed() {
        let original = fixture();
        for length in 0..original.len() {
            assert!(parse_acl(&original[..length]).is_err(), "length {length}");
        }
        for (offset, value) in [
            (2, 7),
            (2, 255),
            (4, 2),
            (10, 0),
            (10, 12),
            (10, 19),
            (10, 24),
            (17, 2),
            (8, 5),
        ] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            assert!(parse_acl(&bytes).is_err(), "offset {offset}, value {value}");
        }
    }
}
