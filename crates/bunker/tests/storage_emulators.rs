//! Live storage emulator tests: MinIO (S3 and Object Lock) and Azurite (Azure Blob).
//!
//! Skipped unless the variables written by `tests/emulators/start.sh` are set.
//! CI sets BUNKER_TEST_REQUIRE_EMULATORS=1 so a missing emulator fails the job
//! instead of skipping. Production endpoint validation is unchanged: emulators
//! serve HTTPS with a CA generated per run. In-process tests trust only that CA
//! through an injected client; child CLI processes get it via SSL_CERT_FILE.
use bunker::{
    checkpoint::{self, RemoteStore},
    protected_replication,
    protected_storage::{
        ProtectedBackend, Request, Response, SystemClock, Transport, TransportError,
    },
    repository::{KeySource, Repository},
    storage::{StorageConfig, TransferStore},
};
use chrono::{Duration, Utc};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};

const PASSPHRASE: &str = "emulator-fixture-passphrase";

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required with the emulator"))
}
/// True when the emulator is configured. Missing configuration fails under CI.
fn enabled(name: &str) -> bool {
    if std::env::var(name).is_ok_and(|v| !v.is_empty()) {
        return true;
    }
    assert!(
        std::env::var("BUNKER_TEST_REQUIRE_EMULATORS").as_deref() != Ok("1"),
        "{name} is not set but BUNKER_TEST_REQUIRE_EMULATORS=1"
    );
    eprintln!("skipping: {name} is not set (see crates/bunker/tests/emulators/start.sh)");
    false
}
fn ca_pem() -> Vec<u8> {
    fs::read(var("BUNKER_TEST_CA_FILE")).unwrap()
}
/// OpenDAL HTTP client that trusts only the generated test CA.
fn opendal_context() -> opendal::OperationContext {
    let client = reqwest_opendal::Client::builder()
        .tls_certs_only([reqwest_opendal::Certificate::from_pem(&ca_pem()).unwrap()])
        .https_only(true)
        .no_proxy()
        .build()
        .unwrap();
    opendal::OperationContext::new().with_http_transport(opendal::HttpTransporter::new(
        opendal_http_transport_reqwest::ReqwestTransport::new(client),
    ))
}
/// Protected-storage transport equivalent to production, trusting only the test CA.
struct CaTransport(reqwest::blocking::Client);
impl CaTransport {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            reqwest::blocking::Client::builder()
                .tls_built_in_root_certs(false)
                .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem()).unwrap())
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        ))
    }
}
impl Transport for CaTransport {
    fn send(&self, request: Request) -> Result<Response, TransportError> {
        let response = self
            .0
            .request(request.method, request.url)
            .headers(request.headers)
            .body(request.body)
            .send()
            .map_err(|_| TransportError)?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        response
            .take(request.maximum_response + 1)
            .read_to_end(&mut body)
            .map_err(|_| TransportError)?;
        if body.len() as u64 > request.maximum_response {
            return Err(TransportError);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

fn unique_root() -> String {
    format!("bunker-test/{}", uuid::Uuid::new_v4())
}
fn s3_config(bucket: &str, root: &str, immutable: bool, extra: &[(&str, &str)]) -> StorageConfig {
    let mut options = BTreeMap::from([
        ("endpoint".into(), var("BUNKER_TEST_S3_ENDPOINT")),
        ("region".into(), var("BUNKER_TEST_S3_REGION")),
        ("bucket".into(), bucket.into()),
        ("root".into(), root.into()),
    ]);
    options.extend(extra.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    StorageConfig {
        service: "s3".into(),
        options,
        credential_env: BTreeMap::from([
            ("access_key_id".into(), "BUNKER_TEST_S3_ACCESS_KEY".into()),
            ("secret_access_key".into(), "BUNKER_TEST_S3_SECRET_KEY".into()),
        ]),
        immutable,
    }
}
fn azure_config(root: &str, extra: &[(&str, &str)]) -> StorageConfig {
    let mut options = BTreeMap::from([
        ("endpoint".into(), var("BUNKER_TEST_AZURITE_ENDPOINT")),
        ("account_name".into(), var("BUNKER_TEST_AZURITE_ACCOUNT")),
        ("container".into(), var("BUNKER_TEST_AZURITE_CONTAINER")),
        ("root".into(), root.into()),
    ]);
    options.extend(extra.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    StorageConfig {
        service: "azure".into(),
        options,
        credential_env: BTreeMap::from([("account_key".into(), "BUNKER_TEST_AZURITE_KEY".into())]),
        immutable: false,
    }
}
/// Configured credential values that must never appear in output or objects.
fn sentinels() -> Vec<String> {
    [
        "BUNKER_TEST_S3_ACCESS_KEY",
        "BUNKER_TEST_S3_SECRET_KEY",
        "BUNKER_TEST_AZURITE_KEY",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok())
    .filter(|value| !value.is_empty())
    .collect()
}
fn assert_no_sentinel(label: &str, bytes: &[u8]) {
    for secret in sentinels() {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "configured credential value leaked into {label}"
        );
    }
}
fn assert_tree_has_no_sentinel(root: &Path) {
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            assert_no_sentinel(
                &entry.path().display().to_string(),
                &fs::read(entry.path()).unwrap(),
            );
        }
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    repo: Repository,
    snapshot: String,
    files: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        let mut files = BTreeMap::new();
        files.insert("notes.md".to_owned(), b"emulator fixture\n".to_vec());
        // Large enough for several content-defined chunks.
        let mut large = vec![0u8; 12 * 1024 * 1024];
        rand::Rng::fill(&mut rand::thread_rng(), large.as_mut_slice());
        files.insert("large.bin".to_owned(), large);
        for (name, bytes) in &files {
            fs::write(work.join(name), bytes).unwrap();
        }
        let repo = Repository::init(&dir.path().join("repo"), PASSPHRASE).unwrap();
        let snapshot = repo
            .snapshot(
                &work,
                &bunker::policy::Policy::default(),
                None,
                None,
                "emulator",
            )
            .unwrap()
            .id;
        Self {
            dir,
            repo,
            snapshot,
            files,
        }
    }
    fn assert_recovered(&self, destination: &Path) {
        let recovered = Repository::open(destination, PASSPHRASE).unwrap();
        let manifest = recovered.verify(&self.snapshot).unwrap();
        assert_eq!(manifest.files.len(), self.files.len());
        for file in &manifest.files {
            assert_eq!(
                recovered.file_bytes(file).unwrap().as_slice(),
                self.files[&file.path].as_slice(),
                "recovered bytes differ for {}",
                file.path
            );
        }
    }
}

/// snapshot -> replicate -> recover -> verify through StorageConfig::operator().
fn round_trip(config: &StorageConfig) {
    let fixture = Fixture::new();
    let store = TransferStore::new(
        config.operator().unwrap().with_context(opendal_context()),
        config.transfer_limits().unwrap(),
    );
    assert_eq!(store.limits().multipart_chunk_bytes, Some(5 * 1024 * 1024));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let report = checkpoint::replicate(&fixture.repo, &store, None)
            .await
            .unwrap();
        // Replicating again is idempotent and never rewrites existing objects.
        let again = checkpoint::replicate(&fixture.repo, &store, None)
            .await
            .unwrap();
        assert_eq!(again.sequence, report.sequence + 1);

        // An object above the chunk size uses a conditional multipart/block upload.
        let mut probe = vec![0u8; 11 * 1024 * 1024];
        rand::Rng::fill(&mut rand::thread_rng(), probe.as_mut_slice());
        store
            .create_verified("multipart-probe", probe.clone())
            .await
            .unwrap();
        store
            .create_verified("multipart-probe", probe.clone())
            .await
            .unwrap();
        let mut different = probe.clone();
        different[0] ^= 1;
        assert!(store
            .create_verified("multipart-probe", different)
            .await
            .is_err());
        assert_eq!(
            store
                .read_bounded("multipart-probe", probe.len() as u64)
                .await
                .unwrap(),
            probe
        );

        let destination = fixture.dir.path().join("recovered");
        checkpoint::recover(
            store.operator(),
            &again.namespace,
            &destination,
            &KeySource::passphrase(PASSPHRASE),
            None,
        )
        .await
        .unwrap();
        fixture.assert_recovered(&destination);

        // Stored objects are ciphertext only and contain no credential material.
        use futures_util::TryStreamExt;
        let mut lister = store
            .operator()
            .lister_with("")
            .recursive(true)
            .await
            .unwrap();
        let mut objects = 0;
        while let Some(entry) = lister.try_next().await.unwrap() {
            if entry.metadata().is_file() {
                let bytes = store.operator().read(entry.path()).await.unwrap().to_vec();
                assert_no_sentinel(entry.path(), &bytes);
                assert!(!bytes.windows(16).any(|w| w == b"emulator fixture"));
                objects += 1;
            }
        }
        assert!(objects >= report.objects_verified);
    });
}

#[test]
fn minio_s3_snapshot_replicate_recover_verify() {
    if !enabled("BUNKER_TEST_S3_ENDPOINT") {
        return;
    }
    round_trip(&s3_config(
        &var("BUNKER_TEST_S3_BUCKET"),
        &unique_root(),
        false,
        &[
            ("multipart_chunk_bytes", "5242880"),
            ("upload_bytes_per_second", "1073741824"),
        ],
    ));
}

#[test]
fn azurite_blob_snapshot_replicate_recover_verify() {
    if !enabled("BUNKER_TEST_AZURITE_ENDPOINT") {
        return;
    }
    round_trip(&azure_config(
        &unique_root(),
        &[
            ("multipart_chunk_bytes", "5242880"),
            ("upload_bytes_per_second", "1073741824"),
        ],
    ));
}

#[test]
fn minio_object_lock_refuses_delete_and_overwrite_before_retention_ends() {
    if !enabled("BUNKER_TEST_S3_ENDPOINT") {
        return;
    }
    let root = unique_root();
    let bucket = var("BUNKER_TEST_S3_LOCK_BUCKET");
    let config = s3_config(&bucket, &root, true, &[]);
    let until = chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
        + Duration::days(1);
    let resolve = |name: &str| std::env::var(name).ok();
    let primary = ProtectedBackend::with_transport(
        &config,
        until,
        CaTransport::new(),
        Arc::new(SystemClock),
        resolve,
    )
    .unwrap();
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let report = runtime
        .block_on(protected_replication::replicate(
            &fixture.repo,
            &primary,
            None,
            None,
        ))
        .unwrap();
    let evidence = &report.backends[0];
    assert_eq!(
        evidence.region.as_deref(),
        Some(var("BUNKER_TEST_S3_REGION").as_str())
    );
    assert_eq!(evidence.objects.len(), report.objects_per_backend);
    for proof in evidence.objects.values() {
        assert_eq!(proof.mode, "COMPLIANCE");
        assert!(proof.retain_until >= until);
    }
    assert_no_sentinel("protected report", &serde_json::to_vec(&report).unwrap());

    // The same root credentials, through an ordinary operator, cannot remove or
    // replace any locked version while retention is in force.
    let attacker = s3_config(&bucket, &root, false, &[])
        .operator()
        .unwrap()
        .with_context(opendal_context());
    runtime.block_on(async {
        for (path, proof) in &evidence.objects {
            let error = attacker
                .delete_with(path)
                .version(&proof.version)
                .await
                .expect_err("locked version deletion must fail");
            assert_eq!(
                error.kind(),
                opendal::ErrorKind::PermissionDenied,
                "unexpected delete failure: {error}"
            );
            assert!(attacker
                .write_with(path, b"tampered".to_vec())
                .if_not_exists(true)
                .await
                .is_err());
            // An unconditional PUT may only add a newer version (or be refused);
            // the locked version itself cannot change.
            let _ = attacker.write(path, b"tampered".to_vec()).await;
            let _ = attacker.delete(path).await;
            let bytes = attacker
                .read_with(path)
                .version(&proof.version)
                .await
                .unwrap()
                .to_vec();
            assert_eq!(blake3::hash(&bytes).to_hex().as_str(), proof.blake3);
        }
    });

    // Recovery pins the saved versions despite the newer tampered/deleted latest.
    let recovery = ProtectedBackend::for_recovery_with_transport(
        &config,
        evidence,
        CaTransport::new(),
        Arc::new(SystemClock),
        resolve,
    )
    .unwrap();
    let destination = fixture.dir.path().join("recovered");
    runtime
        .block_on(checkpoint::recover(
            &recovery,
            &report.namespace,
            &destination,
            &KeySource::passphrase(PASSPHRASE),
            None,
        ))
        .unwrap();
    fixture.assert_recovered(&destination);
}

fn bunker(repo: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_bunker"))
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env("BUNKER_PASSPHRASE", PASSPHRASE)
        // Child-only trust for the generated CA. Production code is unchanged.
        .env("SSL_CERT_FILE", var("BUNKER_TEST_CA_FILE"))
        .envs(extra_env.iter().copied())
        .output()
        .unwrap();
    assert_no_sentinel("CLI stdout", &output.stdout);
    assert_no_sentinel("CLI stderr", &output.stderr);
    assert!(
        output.status.success(),
        "bunker {} failed: {}",
        args[0],
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}
struct CliFixture {
    dir: tempfile::TempDir,
    repo: PathBuf,
}
impl CliFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("notes.md"), "cli emulator fixture\n").unwrap();
        bunker(&repo, &["init"], &[]);
        bunker(
            &repo,
            &["snapshot", "--workspace", work.to_str().unwrap()],
            &[],
        );
        Self { dir, repo }
    }
    fn storage(&self, name: &str, config: &StorageConfig) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, toml::to_string(config).unwrap()).unwrap();
        path
    }
}

#[test]
fn cli_protected_minio_replication_records_region_and_keeps_credentials_private() {
    if !enabled("BUNKER_TEST_S3_ENDPOINT") {
        return;
    }
    let fixture = CliFixture::new();
    let config = s3_config(
        &var("BUNKER_TEST_S3_LOCK_BUCKET"),
        &unique_root(),
        true,
        &[],
    );
    let storage = fixture.storage("lock.toml", &config);
    let report = fixture.dir.path().join("protection-report.json");
    let output = bunker(
        &fixture.repo,
        &[
            "replicate",
            "--storage",
            storage.to_str().unwrap(),
            "--retain-days",
            "1",
            "--report",
            report.to_str().unwrap(),
        ],
        &[],
    );
    assert!(output.stderr.is_empty(), "S3 Object Lock needs no warning");
    let value = json(&output);
    let region = var("BUNKER_TEST_S3_REGION");
    assert_eq!(value["storage"]["service"], "s3");
    assert_eq!(value["storage"]["region"], region.as_str());
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(saved["backends"][0]["region"], region.as_str());
    assert_no_sentinel("protection report", &fs::read(&report).unwrap());

    let recovered = fixture.dir.path().join("recovered");
    let output = bunker(
        &recovered,
        &[
            "recover",
            "--storage",
            storage.to_str().unwrap(),
            "--namespace",
            value["namespace"].as_str().unwrap(),
            "--protection-report",
            report.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(json(&output)["verified_snapshots"], 1);
    assert_tree_has_no_sentinel(fixture.dir.path());
}

/// OpenDAL uses rustls-platform-verifier, which honours SSL_CERT_FILE on Linux
/// only. macOS and Windows use the OS trust store, so this child-process test
/// runs on the Linux CI job; the in-process tests above cover every platform.
#[cfg(target_os = "linux")]
#[test]
fn cli_plain_replication_records_region_and_keeps_credentials_private() {
    let s3 = enabled("BUNKER_TEST_S3_ENDPOINT");
    let azure = enabled("BUNKER_TEST_AZURITE_ENDPOINT");
    let fixture = CliFixture::new();
    let mut targets = vec![];
    if s3 {
        targets.push((
            "s3.toml",
            s3_config(&var("BUNKER_TEST_S3_BUCKET"), &unique_root(), false, &[]),
            Some(var("BUNKER_TEST_S3_REGION")),
        ));
    }
    if azure {
        targets.push((
            "azure.toml",
            azure_config(&unique_root(), &[("region", "australiaeast")]),
            Some("australiaeast".to_owned()),
        ));
    }
    for (name, config, region) in targets {
        let storage = fixture.storage(name, &config);
        let output = bunker(
            &fixture.repo,
            &["replicate", "--storage", storage.to_str().unwrap()],
            &[],
        );
        let value = json(&output);
        assert_eq!(value["storage"]["region"].as_str(), region.as_deref());
        assert_eq!(value["immutable"], false);
        let recovered = fixture.dir.path().join(format!("recovered-{name}"));
        let output = bunker(
            &recovered,
            &[
                "recover",
                "--storage",
                storage.to_str().unwrap(),
                "--namespace",
                value["namespace"].as_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(json(&output)["verified_snapshots"], 1);
    }
    assert_tree_has_no_sentinel(fixture.dir.path());
}
