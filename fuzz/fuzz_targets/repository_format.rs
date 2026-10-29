#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise truncation/authentication handling before any manifest is parsed.
    let _ = bunker::crypto::open(&[0; 32], data, b"bunker-fuzz-v1");
    // Model an authenticated plaintext manifest supplied by a damaged or hostile
    // repository writer. This target does not claim to exercise filesystem I/O.
    if let Ok(manifest) = serde_json::from_slice::<bunker::repository::Manifest>(data) {
        for file in manifest.files {
            let _ = bunker::repository::safe_path(&file.path);
        }
    }
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = bunker::repository::safe_path(path);
    }
});
