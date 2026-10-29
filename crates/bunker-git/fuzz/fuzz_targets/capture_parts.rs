#![no_main]
use bunker_git::{Capture, Limits};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 2);
    let limits = Limits {
        max_objects: 256,
        max_object_bytes: 64 * 1024,
        max_total_object_bytes: 256 * 1024,
        max_pack_bytes: 256 * 1024,
        max_metadata_bytes: 64 * 1024,
        ..Default::default()
    };
    let _ = Capture::from_parts(&data[2..2 + split], data[2 + split..].to_vec(), &limits);
});
