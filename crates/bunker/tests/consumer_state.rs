#![cfg(unix)]
use bunker::{
    consumer_state::ConsumerState,
    consumer_storage::{ConsumerEvidence, ConsumerLocation, EvidenceSink, RefreshTokenSink},
    storage::StorageConfig,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};
fn config() -> StorageConfig {
    let reference = format!(
        "BUNKER_TEST_CLIENT_{}",
        uuid::Uuid::new_v4().simple().to_string().to_uppercase()
    );
    std::env::set_var(&reference, "fixture-public-client-id");
    StorageConfig {
        service: "gdrive".into(),
        immutable: false,
        options: BTreeMap::from([("root".into(), "fixture-folder".into())]),
        credential_env: BTreeMap::from([
            ("client_id".into(), reference),
            ("client_secret".into(), "FIXTURE_SECRET".into()),
            ("refresh_token".into(), "FIXTURE_REFRESH".into()),
        ]),
    }
}
#[test]
fn invalid_rebind_inputs_never_bind_a_new_state_directory() {
    let lab = tempfile::tempdir().unwrap();
    let path = lab.path().canonicalize().unwrap().join("state");
    let mut good = config();
    let secret_ref = format!("{}_SECRET", good.credential_env["client_id"]);
    std::env::set_var(&secret_ref, "fixture-secret");
    good.credential_env
        .insert("client_secret".into(), secret_ref);
    let mut bad: StorageConfig = toml::from_str(&toml::to_string(&good).unwrap()).unwrap();
    bad.credential_env.remove("client_secret");
    assert!(ConsumerState::open_for_rebind(&path, &bad, "fixture-replacement").is_err());
    assert!(!path.exists());
    assert!(ConsumerState::open_for_rebind(&path, &good, "").is_err());
    assert!(!path.exists());
    let state = ConsumerState::open_for_rebind(&path, &good, "fixture-replacement").unwrap();
    state.rebind_refresh("fixture-replacement").unwrap();
    drop(state);
    ConsumerState::open(&path, &good).unwrap();
}
#[test]
fn rotation_survives_restart_and_state_is_exclusive_and_bound() {
    let lab = tempfile::tempdir().unwrap();
    let path = lab.path().canonicalize().unwrap().join("state");
    let config = config();
    let state = ConsumerState::open(&path, &config).unwrap();
    assert!(ConsumerState::open(&path, &config).is_err());
    assert!(RefreshTokenSink::load(&state, "FIXTURE_REFRESH")
        .unwrap()
        .is_none());
    RefreshTokenSink::persist(&state, "FIXTURE_REFRESH", "fixture-rotated-token").unwrap();
    assert!(RefreshTokenSink::persist(&state, "OTHER", "fixture-token").is_err());
    assert_eq!(
        fs::metadata(path.join("credentials.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(state);
    let state = ConsumerState::open(&path, &config).unwrap();
    assert_eq!(
        RefreshTokenSink::load(&state, "FIXTURE_REFRESH")
            .unwrap()
            .unwrap()
            .as_str(),
        "fixture-rotated-token"
    );
    drop(state);
    let mut other = config;
    other.options.insert("root".into(), "other-folder".into());
    assert!(ConsumerState::open(&path, &other).is_err());
}
#[test]
fn malformed_linked_or_broadly_readable_saved_tokens_fail_closed() {
    let lab = tempfile::tempdir().unwrap();
    let root = lab.path().canonicalize().unwrap();
    let config = config();
    let state = ConsumerState::open(&root.join("state"), &config).unwrap();
    let path = state.directory().join("credentials.json");
    fs::write(&path, b"fixture-token").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(RefreshTokenSink::load(&state, "FIXTURE_REFRESH").is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, root.join("linked")).unwrap();
    assert!(RefreshTokenSink::load(&state, "FIXTURE_REFRESH").is_err());
    fs::remove_file(&path).unwrap();
    symlink(root.join("linked"), &path).unwrap();
    assert!(RefreshTokenSink::load(&state, "FIXTURE_REFRESH").is_err());
}
#[test]
fn exact_id_evidence_is_private_durable_and_reloaded() {
    let lab = tempfile::tempdir().unwrap();
    let path = lab.path().canonicalize().unwrap().join("state");
    let config = config();
    let state = ConsumerState::open(&path, &config).unwrap();
    let evidence = ConsumerEvidence {
        version: 1,
        location: ConsumerLocation {
            service: "gdrive".into(),
            drive_id: None,
            root: "fixture-folder".into(),
        },
        objects: BTreeMap::new(),
    };
    EvidenceSink::persist(&state, &evidence).unwrap();
    drop(state);
    let state = ConsumerState::open(&path, &config).unwrap();
    assert_eq!(state.evidence().unwrap().unwrap(), evidence);
    fs::write(path.join("evidence.json"), b"invalid").unwrap();
    assert!(state.evidence().is_err());
}
