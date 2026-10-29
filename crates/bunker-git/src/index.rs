use crate::{safe_path, valid_oid, IndexEntry};
use anyhow::{ensure, Context, Result};
use sha1::{Digest, Sha1};

fn hex(oid: &str) -> Result<Vec<u8>> {
    valid_oid(oid)?;
    (0..40)
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&oid[i..i + 2], 16)?))
        .collect()
}
pub(crate) fn encode(entries: &[IndexEntry]) -> Result<Vec<u8>> {
    let mut out = b"DIRC\0\0\0\x02".to_vec();
    out.extend(u32::try_from(entries.len())?.to_be_bytes());
    let mut previous: Option<&str> = None;
    for e in entries {
        safe_path(&e.path)?;
        ensure!(
            previous.is_none_or(|p| p.as_bytes() < e.path.as_bytes()),
            "index paths must be unique and sorted"
        );
        previous = Some(&e.path);
        ensure!(
            e.mode == "100644" || e.mode == "100755",
            "unsupported index mode"
        );
        let start = out.len();
        out.extend([0u8; 24]); // ctime, mtime, device, inode
        out.extend(u32::from_str_radix(&e.mode, 8)?.to_be_bytes());
        out.extend([0u8; 12]); // uid, gid, size: force worktree revalidation
        out.extend(hex(&e.oid)?);
        out.extend((e.path.len().min(4095) as u16).to_be_bytes());
        out.extend(e.path.as_bytes());
        out.push(0);
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
    }
    out.extend(Sha1::digest(&out));
    Ok(out)
}
pub(crate) fn decode(bytes: &[u8], max_entries: usize) -> Result<Vec<IndexEntry>> {
    ensure!(bytes.len() >= 32 && &bytes[..4] == b"DIRC", "invalid index");
    let end = bytes.len() - 20;
    ensure!(
        Sha1::digest(&bytes[..end])[..] == bytes[end..],
        "index checksum mismatch"
    );
    let version = u32::from_be_bytes(bytes[4..8].try_into()?);
    ensure!(
        version == 2 || version == 3,
        "unsupported index version (only v2/v3)"
    );
    let count = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    ensure!(count <= max_entries, "index entry cap exceeded");
    let mut entries = Vec::new();
    let mut pos = 12;
    for _ in 0..count {
        let start = pos;
        ensure!(pos + 62 < end, "truncated index");
        let mode = u32::from_be_bytes(bytes[pos + 24..pos + 28].try_into()?);
        let oid = bytes[pos + 40..pos + 60]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let flags = u16::from_be_bytes(bytes[pos + 60..pos + 62].try_into()?);
        ensure!(
            flags & 0xf000 == 0,
            "unsupported index flags/stages (conflict, assume-unchanged, intent-to-add or sparse)"
        );
        pos += 62;
        let len = bytes[pos..end]
            .iter()
            .position(|b| *b == 0)
            .context("unterminated index path")?;
        let path = std::str::from_utf8(&bytes[pos..pos + len])
            .context("non-UTF-8 index path unsupported")?
            .to_owned();
        ensure!(
            flags & 4095 == len.min(4095) as u16,
            "index path length mismatch"
        );
        pos += len + 1;
        while !(pos - start).is_multiple_of(8) {
            ensure!(bytes.get(pos) == Some(&0), "invalid index padding");
            pos += 1;
        }
        entries.push(IndexEntry {
            path,
            oid,
            mode: format!("{mode:o}"),
        });
    }
    // Optional caches are intentionally discarded; mandatory extensions cannot be reconstructed.
    while pos < end {
        ensure!(pos + 8 <= end, "truncated index extension");
        ensure!(
            bytes[pos].is_ascii_uppercase(),
            "unsupported mandatory index extension (split/sparse index)"
        );
        let len = u32::from_be_bytes(bytes[pos + 4..pos + 8].try_into()?) as usize;
        pos = pos
            .checked_add(8 + len)
            .context("index extension overflow")?;
        ensure!(pos <= end, "truncated index extension payload");
    }
    ensure!(pos == end, "index entries exceed payload");
    encode(&entries)?;
    Ok(entries)
}
