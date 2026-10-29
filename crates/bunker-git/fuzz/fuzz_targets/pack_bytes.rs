#![no_main]
use bunker_git::{Capture, Limits};
use libfuzzer_sys::fuzz_target;
use sha1::{Digest, Sha1};
fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let limits = Limits {
        max_objects: 256,
        max_object_bytes: 64 * 1024,
        max_total_object_bytes: 256 * 1024,
        max_pack_bytes: 256 * 1024,
        max_metadata_bytes: 64 * 1024,
        ..Default::default()
    };
    let metadata = br#"{"version":1,"object_format":"sha1","head_ref":"refs/heads/main","heads":{},"stash":[],"index":[],"packed_objects":[],"prerequisites":[],"had_remote_tracking_refs":false}"#;
    let _ = Capture::from_parts(metadata, data.to_vec(), &limits);
    // Repair the checksum so coverage reaches object headers/zlib.
    if data.len() >= 32 {
        let mut pack = data.to_vec();
        pack[..8].copy_from_slice(b"PACK\0\0\0\x02");
        pack[8..11].fill(0);
        let end = pack.len() - 20;
        let sum = Sha1::digest(&pack[..end]);
        pack[end..].copy_from_slice(&sum);
        let _ = Capture::from_parts(metadata, pack, &limits);
    }
});
