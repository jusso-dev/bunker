#![cfg(unix)]
use bunker::{
    checkpoint,
    host_service::RemotePolicy,
    host_storage::{HostStorageAdapter, HostStorageConfig},
    policy::Policy,
    repository::{KeySource, Repository},
    storage::StorageConfig,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    repo: Repository,
    work: PathBuf,
    remote: PathBuf,
    config: HostStorageConfig,
    snapshot: String,
}

fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn private_file(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn policy() -> RemotePolicy {
    serde_json::from_value(serde_json::json!({
        "name":"fixture", "hostId":null, "intervalMinutes":60, "endOfSession":false,
        "retentionDays":30, "exclusions":[], "sizeCapBytes":10000000, "immutable":false,
        "drCopy":false, "residency":"unrestricted", "storage":"local", "storageRef":"archive",
        "keyRef":"wrapped", "massDeleteThreshold":20, "missedBackupMinutes":120,
        "restoreTestIntervalHours":24, "channels":["dashboard"]
    }))
    .unwrap()
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let work = base.join("work");
        private_dir(&work);
        let remote = base.join("remote");
        private_dir(&remote);
        fs::write(work.join("file"), "snapshot payload").unwrap();
        let repo = Repository::init(&base.join("repo"), "host-storage-fixture").unwrap();
        let snapshot = repo
            .snapshot(&work, &Policy::default(), None, None, "fixture")
            .unwrap()
            .id;
        let primary = base.join("storage.toml");
        private_file(
            &primary,
            format!(
                "service = 'local'\n[options]\nroot = '{}'\n",
                remote.display()
            ),
        );
        let config = HostStorageConfig {
            primary,
            secondary: None,
            required_until: None,
            report_directory: base.join("reports"),
            consumer_state: None,
        };
        Self {
            _temp: temp,
            base,
            repo,
            work,
            remote,
            config,
            snapshot,
        }
    }
    fn adapter(&self) -> HostStorageAdapter {
        HostStorageAdapter::open(&self.config, &self.repo, &self.work, "archive", "wrapped")
            .unwrap()
    }
    fn run(&self, adapter: &HostStorageAdapter) -> anyhow::Result<()> {
        adapter.replicate_snapshots(&self.repo, &policy(), std::slice::from_ref(&self.snapshot))
    }
    fn file(&self, extension: &str) -> PathBuf {
        fs::read_dir(&self.config.report_directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == extension))
            .unwrap()
    }
    fn checkpoint_count(&self) -> usize {
        fs::read_dir(self.remote.join(self.repo.identity()).join("checkpoints"))
            .unwrap()
            .count()
    }
}

#[test]
fn restart_reuses_receipt_without_new_chain_and_existing_recovery_works() {
    let fixture = Fixture::new();
    fixture.run(&fixture.adapter()).unwrap();
    let latest = fs::read(fixture.repo.root().join("checkpoints/latest")).unwrap();
    let receipt = fs::read(fixture.file("receipt")).unwrap();
    for _ in 0..3 {
        fixture.run(&fixture.adapter()).unwrap();
    }
    assert_eq!(fixture.checkpoint_count(), 1);
    assert_eq!(
        fs::read(fixture.repo.root().join("checkpoints/latest")).unwrap(),
        latest
    );
    assert_eq!(fs::read(fixture.file("receipt")).unwrap(), receipt);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.file("json")).unwrap()).unwrap();
    let storage = StorageConfig::load(&fixture.config.primary)
        .unwrap()
        .operator()
        .unwrap();
    let restored = fixture.base.join("restored");
    let key = KeySource::Passphrase(zeroize::Zeroizing::new("host-storage-fixture".into()));
    let count = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(checkpoint::recover(
            &storage,
            report["namespace"].as_str().unwrap(),
            &restored,
            &key,
            None,
        ))
        .unwrap();
    assert_eq!(count, 1);
    Repository::open(&restored, "host-storage-fixture")
        .unwrap()
        .verify(&fixture.snapshot)
        .unwrap();
}

#[test]
fn receipt_survives_crash_before_local_checkpoint_write() {
    let fixture = Fixture::new();
    fixture.run(&fixture.adapter()).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.file("json")).unwrap()).unwrap();
    let checkpoint = report["namespace"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap();
    fs::remove_file(fixture.repo.root().join("checkpoints/latest")).unwrap();
    fs::remove_file(fixture.repo.root().join("checkpoints").join(checkpoint)).unwrap();
    fixture.run(&fixture.adapter()).unwrap();
    assert_eq!(fixture.checkpoint_count(), 1);
}

#[test]
fn receipt_replay_with_missing_or_older_head_preserves_exact_locator_recovery() {
    for older_head in [false, true] {
        let fixture = Fixture::new();
        let adapter = fixture.adapter();
        fixture.run(&adapter).unwrap();
        let first_head = fs::read(fixture.repo.root().join("checkpoints/latest")).unwrap();
        let capture = |text: &str| {
            fs::write(fixture.work.join("file"), text).unwrap();
            fixture
                .repo
                .snapshot(&fixture.work, &Policy::default(), None, None, "fixture")
                .unwrap()
                .id
        };
        let reports = |snapshot: &str| -> serde_json::Value {
            fs::read_dir(&fixture.config.report_directory)
                .unwrap()
                .filter_map(|entry| {
                    let path = entry.unwrap().path();
                    if path.extension().is_none_or(|extension| extension != "json") {
                        return None;
                    }
                    let report: serde_json::Value =
                        serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                    (report["snapshot"] == snapshot).then_some(report)
                })
                .next()
                .unwrap()
        };
        let second = capture("second snapshot");
        adapter
            .replicate_snapshots(&fixture.repo, &policy(), std::slice::from_ref(&second))
            .unwrap();
        let second_report = reports(&second);
        if older_head {
            fs::write(fixture.repo.root().join("checkpoints/latest"), &first_head).unwrap();
        } else {
            fs::remove_file(fixture.repo.root().join("checkpoints/latest")).unwrap();
        }
        adapter
            .replicate_snapshots(&fixture.repo, &policy(), std::slice::from_ref(&second))
            .unwrap();
        assert_eq!(fixture.checkpoint_count(), 2);
        let third = capture("third snapshot");
        adapter
            .replicate_snapshots(&fixture.repo, &policy(), std::slice::from_ref(&third))
            .unwrap();
        let third_report = reports(&third);
        assert_eq!(third_report["sequence"], if older_head { 2 } else { 1 });
        assert_ne!(third_report["namespace"], second_report["namespace"]);
        let backend = StorageConfig::load(&fixture.config.primary)
            .unwrap()
            .operator()
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for (index, (snapshot, report)) in [(second, second_report), (third, third_report)]
            .into_iter()
            .enumerate()
        {
            let destination = fixture.base.join(format!("recovered-{index}"));
            runtime
                .block_on(checkpoint::recover(
                    &backend,
                    report["namespace"].as_str().unwrap(),
                    &destination,
                    &KeySource::passphrase("host-storage-fixture"),
                    None,
                ))
                .unwrap();
            Repository::open(&destination, "host-storage-fixture")
                .unwrap()
                .verify(&snapshot)
                .unwrap();
        }
    }
}

#[test]
fn synchronous_adapter_is_safe_inside_tokio_runtime() {
    let fixture = Fixture::new();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        fixture.run(&fixture.adapter()).unwrap();
    });
}

#[test]
fn altered_or_missing_external_report_never_reuses_receipt() {
    for remove in [false, true] {
        let fixture = Fixture::new();
        fixture.run(&fixture.adapter()).unwrap();
        let report = fixture.file("json");
        if remove {
            fs::remove_file(report).unwrap();
        } else {
            fs::write(report, b"{}").unwrap();
        }
        assert!(fixture.run(&fixture.adapter()).is_err());
        assert_eq!(fixture.checkpoint_count(), 1);
    }
}

#[test]
fn corrupted_receipt_and_remote_bytes_fail_closed() {
    let fixture = Fixture::new();
    fixture.run(&fixture.adapter()).unwrap();
    let receipt_path = fixture.file("receipt");
    let original = fs::read(&receipt_path).unwrap();
    let mut corrupt = original.clone();
    corrupt[0] ^= 1;
    fs::write(&receipt_path, corrupt).unwrap();
    assert!(fixture.run(&fixture.adapter()).is_err());
    fs::write(receipt_path, original).unwrap();
    fs::write(
        fixture
            .remote
            .join(fixture.repo.identity())
            .join("snapshots")
            .join(&fixture.snapshot),
        "different ciphertext",
    )
    .unwrap();
    assert!(fixture.run(&fixture.adapter()).is_err());
    assert_eq!(fixture.checkpoint_count(), 1);
}

#[test]
fn policy_revision_and_snapshot_each_get_distinct_receipts() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.run(&adapter).unwrap();
    let mut changed = policy();
    changed.retention_days = 31;
    adapter
        .replicate_snapshots(
            &fixture.repo,
            &changed,
            std::slice::from_ref(&fixture.snapshot),
        )
        .unwrap();
    adapter
        .replicate_snapshots(
            &fixture.repo,
            &changed,
            std::slice::from_ref(&fixture.snapshot),
        )
        .unwrap();
    assert_eq!(fixture.checkpoint_count(), 2);
    fs::write(fixture.work.join("file"), "second payload").unwrap();
    let second = fixture
        .repo
        .snapshot(&fixture.work, &Policy::default(), None, None, "fixture")
        .unwrap()
        .id;
    adapter
        .replicate_snapshots(&fixture.repo, &policy(), &[second])
        .unwrap();
    assert_eq!(fixture.checkpoint_count(), 3);
}

#[test]
fn config_change_is_rejected_by_open_binding_before_state_write() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    let different = fixture.base.join("other-remote");
    private_dir(&different);
    private_file(
        &fixture.config.primary,
        format!(
            "service = 'local'\n[options]\nroot = '{}'\n",
            different.display()
        ),
    );
    assert!(fixture.run(&adapter).is_err());
    assert!(!fixture.config.report_directory.exists());
    // An explicit restart binds the newly configured destination, without reusing the old receipt.
    fixture.run(&fixture.adapter()).unwrap();
    assert!(different.join(fixture.repo.identity()).exists());
}

#[test]
fn unsupported_capabilities_and_mismatched_labels_fail_before_writes() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    for field in [
        "storage",
        "storageRef",
        "keyRef",
        "residency",
        "immutable",
        "drCopy",
    ] {
        let mut value = serde_json::json!({
            "name":"fixture", "hostId":null, "intervalMinutes":60, "endOfSession":false,
            "retentionDays":30, "exclusions":[], "sizeCapBytes":10000000, "immutable":false,
            "drCopy":false, "residency":"unrestricted", "storage":"local", "storageRef":"archive",
            "keyRef":"wrapped", "massDeleteThreshold":20, "missedBackupMinutes":120,
            "restoreTestIntervalHours":24, "channels":["dashboard"]
        });
        value[field] = if matches!(field, "immutable" | "drCopy") {
            true.into()
        } else {
            "AU".into()
        };
        let changed = serde_json::from_value(value).unwrap();
        assert!(adapter
            .replicate_snapshots(
                &fixture.repo,
                &changed,
                std::slice::from_ref(&fixture.snapshot)
            )
            .is_err());
    }
    assert!(!fixture.config.report_directory.exists());
    let mut dr = fixture.config.clone();
    dr.secondary = Some(fixture.base.join("secondary.toml"));
    private_file(
        dr.secondary.as_ref().unwrap(),
        fs::read(&dr.primary).unwrap(),
    );
    assert!(
        HostStorageAdapter::open(&dr, &fixture.repo, &fixture.work, "archive", "wrapped").is_err()
    );
}

#[test]
fn unsafe_paths_permissions_and_nested_state_are_rejected_without_writes() {
    let fixture = Fixture::new();
    for path in [
        fixture.work.join("state"),
        fixture.repo.root().join("state"),
        fixture.base.clone(),
    ] {
        let mut config = fixture.config.clone();
        config.report_directory = path;
        assert!(config
            .validate_paths(fixture.repo.root(), &fixture.work)
            .is_err());
    }
    let alias = fixture.base.join("alias");
    std::os::unix::fs::symlink(&fixture.work, &alias).unwrap();
    let mut config = fixture.config.clone();
    config.report_directory = alias.join("state");
    assert!(config
        .validate_paths(fixture.repo.root(), &fixture.work)
        .is_err());
    assert!(!fixture.work.join("state").exists());
    fs::set_permissions(&fixture.config.primary, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(HostStorageAdapter::open(
        &fixture.config,
        &fixture.repo,
        &fixture.work,
        "archive",
        "wrapped"
    )
    .is_err());
    assert!(!fixture.config.report_directory.exists());
}

#[test]
fn report_destination_failure_cannot_advance_checkpoint_or_return_success() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    private_file(&fixture.config.report_directory, b"not a directory");
    assert!(fixture.run(&adapter).is_err());
    assert!(!fixture.repo.root().join("checkpoints/latest").exists());
    assert!(!fixture.remote.join(fixture.repo.identity()).exists());
}

#[test]
fn receipt_and_report_symlinks_are_not_followed() {
    let fixture = Fixture::new();
    fixture.run(&fixture.adapter()).unwrap();
    let report = fixture.file("json");
    let elsewhere = fixture.base.join("copied-report");
    fs::rename(&report, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &report).unwrap();
    assert!(fixture.run(&fixture.adapter()).is_err());
    assert_eq!(fixture.checkpoint_count(), 1);
}

// Names are unique per fixture; these are inert, fabricated credentials, never live accounts.
struct FixtureEnv(Vec<String>);
impl FixtureEnv {
    fn new(values: &[&str]) -> Self {
        let prefix = format!("BUNKER_HOST_FIXTURE_{}", uuid::Uuid::new_v4().simple());
        let names: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, value)| {
                let name = format!("{prefix}_{i}").to_uppercase();
                std::env::set_var(&name, value);
                name
            })
            .collect();
        Self(names)
    }
}
impl Drop for FixtureEnv {
    fn drop(&mut self) {
        for name in &self.0 {
            std::env::remove_var(name);
        }
    }
}

#[test]
fn explicit_deadline_must_cover_snapshot_policy_horizon_before_writes() {
    let mut fixture = Fixture::new();
    let env = FixtureEnv::new(&["fixture-access", "fixture-secret"]);
    private_file(&fixture.config.primary, format!(
        "service='s3'\nimmutable=true\n[options]\nendpoint='https://s3.us-east-1.amazonaws.com'\nregion='us-east-1'\nbucket='fixture-bucket'\n[credential_env]\naccess_key_id='{}'\nsecret_access_key='{}'\n", env.0[0], env.0[1]));
    fixture.config.required_until =
        Some(chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp() + 86400, 0).unwrap());
    let adapter = fixture.adapter();
    let mut remote = policy();
    remote.storage = "s3".into();
    remote.immutable = true;
    let error = adapter
        .replicate_snapshots(
            &fixture.repo,
            &remote,
            std::slice::from_ref(&fixture.snapshot),
        )
        .unwrap_err();
    assert!(error.to_string().contains("policy horizon"));
    assert!(!fixture.config.report_directory.exists());
    assert!(!fixture.repo.root().join("checkpoints/latest").exists());
}

#[test]
fn protected_dr_requires_different_backing_and_credential_identities() {
    let mut fixture = Fixture::new();
    let env = FixtureEnv::new(&[
        "fixture-access-a",
        "fixture-secret-a",
        "fixture-access-b",
        "fixture-secret-b",
    ]);
    let storage = |bucket: &str, access: &str, secret: &str| {
        format!(
        "service='s3'\nimmutable=true\n[options]\nendpoint='https://s3.us-east-1.amazonaws.com'\nregion='us-east-1'\nbucket='{bucket}'\n[credential_env]\naccess_key_id='{access}'\nsecret_access_key='{secret}'\n")
    };
    private_file(
        &fixture.config.primary,
        storage("fixture-primary", &env.0[0], &env.0[1]),
    );
    let secondary = fixture.base.join("secondary.toml");
    fixture.config.secondary = Some(secondary.clone());
    fixture.config.required_until = Some(
        chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp() + 86400 * 31, 0).unwrap(),
    );
    for (bucket, access, secret) in [
        ("fixture-primary", &env.0[2], &env.0[3]),
        ("fixture-secondary", &env.0[0], &env.0[1]),
    ] {
        private_file(&secondary, storage(bucket, access, secret));
        assert!(HostStorageAdapter::open(
            &fixture.config,
            &fixture.repo,
            &fixture.work,
            "archive",
            "wrapped"
        )
        .is_err());
    }
    private_file(
        &secondary,
        storage("fixture-secondary", &env.0[2], &env.0[3]),
    );
    fixture.adapter(); // Constructor validates static identities without network access.
    assert!(!fixture.config.report_directory.exists());
}

#[test]
fn consumer_preflight_uses_durable_rotated_token_and_rejects_uncertain_refresh() {
    use bunker::consumer_storage::RefreshTokenSink;
    let mut fixture = Fixture::new();
    let env = FixtureEnv::new(&[
        "fixture-client",
        "fixture-client-secret",
        "fixture-bootstrap",
    ]);
    private_file(&fixture.config.primary, format!(
        "service='gdrive'\n[options]\nroot='folder-123'\n[credential_env]\nclient_id='{}'\nclient_secret='{}'\nrefresh_token='{}'\n", env.0[0], env.0[1], env.0[2]));
    fixture.config.consumer_state = Some(fixture.base.join("oauth"));
    let first = fixture.adapter();
    assert!(!fixture.config.consumer_state.as_ref().unwrap().exists());
    let storage = StorageConfig::load(&fixture.config.primary).unwrap();
    let state = bunker::consumer_state::ConsumerState::open(
        fixture.config.consumer_state.as_ref().unwrap(),
        &storage,
    )
    .unwrap();
    state.persist(&env.0[2], "fixture-rotated").unwrap();
    std::env::remove_var(&env.0[2]);
    let mut remote = policy();
    remote.storage = "gdrive".into();
    first.binding().validate(&fixture.repo, &remote).unwrap();
    fixture.adapter(); // Does not require the obsolete environment bootstrap token.
    state.begin_refresh(&env.0[2], "fixture-rotated").unwrap();
    assert!(HostStorageAdapter::open(
        &fixture.config,
        &fixture.repo,
        &fixture.work,
        "archive",
        "wrapped"
    )
    .is_err());
    assert!(!fixture.config.report_directory.exists());
}

#[test]
fn unavailable_consumer_bootstrap_cannot_bind_new_state() {
    let mut fixture = Fixture::new();
    let env = FixtureEnv::new(&["fixture-client", "fixture-secret", "fixture-bootstrap"]);
    std::env::remove_var(&env.0[2]);
    private_file(&fixture.config.primary, format!(
        "service='gdrive'\n[options]\nroot='folder-123'\n[credential_env]\nclient_id='{}'\nclient_secret='{}'\nrefresh_token='{}'\n", env.0[0], env.0[1], env.0[2]));
    fixture.config.consumer_state = Some(fixture.base.join("oauth"));
    assert!(HostStorageAdapter::open(
        &fixture.config,
        &fixture.repo,
        &fixture.work,
        "archive",
        "wrapped"
    )
    .is_err());
    assert!(!fixture.config.consumer_state.as_ref().unwrap().exists());
    assert!(!fixture.config.report_directory.exists());
}

#[test]
fn r2_and_consumer_immutable_capabilities_are_never_inferred() {
    for service in ["r2", "gdrive", "onedrive"] {
        let mut fixture = Fixture::new();
        private_file(
            &fixture.config.primary,
            format!("service='{service}'\nimmutable=true\n"),
        );
        fixture.config.required_until = Some(
            chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp() + 86400 * 31, 0)
                .unwrap(),
        );
        assert!(HostStorageAdapter::open(
            &fixture.config,
            &fixture.repo,
            &fixture.work,
            "archive",
            "wrapped"
        )
        .is_err());
        assert!(!fixture.config.report_directory.exists());
    }
}
