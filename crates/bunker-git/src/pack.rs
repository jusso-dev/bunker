use crate::{Limits, Object};
use anyhow::{ensure, Context, Result};
use flate2::{bufread::ZlibDecoder, write::ZlibEncoder, Compression};
use sha1::{Digest, Sha1};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

pub(crate) fn oid(kind: &str, bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{kind} {}\0", bytes.len()));
    h.update(bytes);
    format!("{:x}", h.finalize())
}
fn kind_num(kind: &str) -> Result<u8> {
    Ok(match kind {
        "commit" => 1,
        "tree" => 2,
        "blob" => 3,
        "tag" => 4,
        _ => anyhow::bail!("unsupported object type"),
    })
}
pub(crate) fn encode(objects: &BTreeMap<String, Object>, limits: &Limits) -> Result<Vec<u8>> {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend(u32::try_from(objects.len())?.to_be_bytes());
    for o in objects.values() {
        let mut size = o.bytes.len();
        let mut first = kind_num(&o.kind)? << 4 | (size & 15) as u8;
        size >>= 4;
        if size != 0 {
            first |= 128;
        }
        pack.push(first);
        while size != 0 {
            let mut b = (size & 127) as u8;
            size >>= 7;
            if size != 0 {
                b |= 128;
            }
            pack.push(b);
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&o.bytes)?;
        pack.extend(encoder.finish()?);
        ensure!(
            pack.len() + 20 <= limits.max_pack_bytes,
            "pack exceeds size cap"
        );
    }
    ensure!(
        pack.len() + 20 <= limits.max_pack_bytes,
        "pack exceeds size cap"
    );
    let sum = Sha1::digest(&pack);
    pack.extend(sum);
    Ok(pack)
}
pub(crate) fn decode(pack: &[u8], limits: &Limits) -> Result<BTreeMap<String, Object>> {
    ensure!(
        pack.len() >= 32 && pack.len() <= limits.max_pack_bytes,
        "invalid pack size"
    );
    ensure!(&pack[..8] == b"PACK\0\0\0\x02", "unsupported pack version");
    let end = pack.len() - 20;
    ensure!(
        Sha1::digest(&pack[..end])[..] == pack[end..],
        "pack checksum mismatch"
    );
    let count = u32::from_be_bytes(pack[8..12].try_into()?) as usize;
    ensure!(count <= limits.max_objects, "too many pack objects");
    let mut pos = 12;
    let mut total = 0usize;
    let mut objects = BTreeMap::new();
    for _ in 0..count {
        let first = *pack.get(pos).context("truncated pack")?;
        pos += 1;
        let kind = match (first >> 4) & 7 {
            1 => "commit",
            2 => "tree",
            3 => "blob",
            4 => "tag",
            _ => anyhow::bail!("delta or invalid object forbidden; pack must be self-contained"),
        };
        let mut size = (first & 15) as usize;
        let mut b = first;
        let mut shift = 4;
        while b & 128 != 0 {
            ensure!(shift < usize::BITS - 7 && pos < end, "invalid object size");
            b = pack[pos];
            pos += 1;
            size |= ((b & 127) as usize) << shift;
            shift += 7;
        }
        total = total.checked_add(size).context("object size overflow")?;
        ensure!(
            size <= limits.max_object_bytes && total <= limits.max_total_object_bytes,
            "object size cap exceeded"
        );
        ensure!(pos < end, "truncated compressed object");
        let mut decoder = ZlibDecoder::new(&pack[pos..end]);
        let mut bytes = Vec::new();
        decoder
            .by_ref()
            .take(size as u64 + 1)
            .read_to_end(&mut bytes)
            .context("invalid compressed object")?;
        ensure!(bytes.len() == size, "object length mismatch");
        pos += usize::try_from(decoder.total_in())?;
        let id = oid(kind, &bytes);
        ensure!(
            objects
                .insert(
                    id,
                    Object {
                        kind: kind.into(),
                        bytes
                    }
                )
                .is_none(),
            "duplicate pack object"
        );
    }
    ensure!(pos == end, "trailing pack data");
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_packs_and_delta_or_bomb_payloads_are_rejected() {
        let limits = Limits::default();
        let bytes = b"fixture bytes".to_vec();
        let objects = BTreeMap::from([(
            oid("blob", &bytes),
            Object {
                kind: "blob".into(),
                bytes,
            },
        )]);
        let valid = encode(&objects, &limits).unwrap();
        assert_eq!(decode(&valid, &limits).unwrap().len(), 1);
        for len in 0..valid.len() {
            assert!(decode(&valid[..len], &limits).is_err());
        }
        for i in 0..valid.len() {
            let mut broken = valid.clone();
            broken[i] ^= 0xff;
            assert!(decode(&broken, &limits).is_err());
        }
        let mut delta = valid.clone();
        delta[12] = (delta[12] & 15) | 0x70;
        let end = delta.len() - 20;
        let sum = Sha1::digest(&delta[..end]);
        delta[end..].copy_from_slice(&sum);
        assert!(decode(&delta, &limits)
            .unwrap_err()
            .to_string()
            .contains("delta"));
        let tiny = Limits {
            max_object_bytes: 1,
            ..Default::default()
        };
        assert!(decode(&valid, &tiny).is_err());
        // Deterministic malformed-input smoke corpus; cargo-fuzz target supplements it.
        let mut seed = 0x12345678u32;
        for len in 0..512 {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            assert!(decode(&data, &limits).is_err());
        }
    }
}
