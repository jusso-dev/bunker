#![cfg(unix)]
use bunker::{
    checkpoint, consumer_replication,
    consumer_state::ConsumerState,
    consumer_storage::*,
    policy::Policy,
    repository::{KeySource, Repository},
    storage::StorageConfig,
};
use http::{HeaderMap, HeaderValue, Method};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct GoogleFixture {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}
fn response(body: serde_json::Value) -> Response {
    Response {
        status: 200,
        headers: HeaderMap::new(),
        body: serde_json::to_vec(&body).unwrap(),
    }
}
impl Transport for GoogleFixture {
    fn send(&self, request: Request) -> std::result::Result<Response, TransportError> {
        let path = request.url.path();
        if path.ends_with("/token") {
            return Ok(response(
                json!({"access_token":"fixture-access","refresh_token":"fixture-rotated","token_type":"Bearer","expires_in":3600}),
            ));
        }
        if path == "/drive/v3/files/folder-123" {
            return Ok(response(
                json!({"id":"folder-123","mimeType":"application/vnd.google-apps.folder","trashed":false}),
            ));
        }
        if request.method == Method::POST && path == "/upload/drive/v3/files" {
            let mut objects = self.objects.lock().unwrap();
            let id = format!("file{}", objects.len() + 1);
            objects.insert(id.clone(), vec![]);
            let mut headers = HeaderMap::new();
            headers.insert(
                "location",
                HeaderValue::from_str(&format!(
                    "https://www.googleapis.com/upload/drive/v3/files?upload_id={id}"
                ))
                .unwrap(),
            );
            return Ok(Response {
                status: 200,
                headers,
                body: vec![],
            });
        }
        let id = if path == "/upload/drive/v3/files" {
            request
                .url
                .query_pairs()
                .find(|(key, _)| key == "upload_id")
                .unwrap()
                .1
                .to_string()
        } else {
            path.strip_prefix("/drive/v3/files/")
                .unwrap()
                .split('/')
                .next()
                .unwrap()
                .to_owned()
        };
        let mut objects = self.objects.lock().unwrap();
        if request.method == Method::PUT {
            *objects.get_mut(&id).unwrap() = request.body;
        }
        let bytes = &objects[&id];
        if request
            .url
            .query_pairs()
            .any(|(key, value)| key == "alt" && value == "media")
        {
            return Ok(Response {
                status: 200,
                headers: HeaderMap::new(),
                body: bytes.clone(),
            });
        }
        if path.contains("/revisions/") {
            return Ok(response(
                json!({"id":"revision1","mimeType":"application/octet-stream","keepForever":true,"size":bytes.len().to_string()}),
            ));
        }
        Ok(response(
            json!({"id":id,"mimeType":"application/octet-stream","parents":["folder-123"],"trashed":false,"size":bytes.len().to_string(),"headRevisionId":"revision1"}),
        ))
    }
}
fn config() -> StorageConfig {
    let name = format!(
        "BUNKER_TEST_PIPELINE_{}",
        uuid::Uuid::new_v4().simple().to_string().to_uppercase()
    );
    std::env::set_var(&name, "fixture-client");
    StorageConfig {
        service: "gdrive".into(),
        immutable: false,
        options: BTreeMap::from([("root".into(), "folder-123".into())]),
        credential_env: BTreeMap::from([
            ("client_id".into(), name),
            ("client_secret".into(), "FIXTURE_SECRET".into()),
            ("refresh_token".into(), "FIXTURE_REFRESH".into()),
        ]),
    }
}
#[test]
fn full_pipeline_persists_proofs_and_rotations_then_recovers_exact_ids() {
    let lab = tempfile::tempdir().unwrap();
    let root = lab.path().canonicalize().unwrap();
    let config = config();
    let state = Arc::new(ConsumerState::open(&root.join("state"), &config).unwrap());
    let wire = Arc::new(GoogleFixture::default());
    let backend = ConsumerBackend::with_transport(
        &config,
        None,
        false,
        wire.clone(),
        Arc::new(SystemClock),
        |_| Some("fixture-client".into()),
        state.clone(),
        state.clone(),
    )
    .unwrap();
    let repo = Repository::init(&root.join("repo"), "pipeline-fixture").unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("file"), b"exact workspace bytes").unwrap();
    let snapshot = repo
        .snapshot(&work, &Policy::default(), None, None, "fixture")
        .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let report = runtime
        .block_on(consumer_replication::replicate(
            &repo, &backend, &state, None,
        ))
        .unwrap();
    let checkpoint = report.namespace.rsplit(':').next().unwrap();
    assert_eq!(
        state.load_report(checkpoint).unwrap().to_vec().unwrap(),
        report.to_vec().unwrap()
    );
    assert!(repo.root().join("checkpoints/latest").exists());
    assert_eq!(
        RefreshTokenSink::load(&*state, "FIXTURE_REFRESH")
            .unwrap()
            .unwrap()
            .as_str(),
        "fixture-rotated"
    );
    let recovery = ConsumerBackend::with_transport(
        &config,
        Some(&report.evidence),
        true,
        wire,
        Arc::new(SystemClock),
        |_| Some("fixture-client".into()),
        state.clone(),
        state.clone(),
    )
    .unwrap();
    let destination = root.join("recovered");
    runtime
        .block_on(checkpoint::recover(
            &recovery,
            &report.namespace,
            &destination,
            &KeySource::passphrase("pipeline-fixture"),
            None,
        ))
        .unwrap();
    Repository::open(&destination, "pipeline-fixture")
        .unwrap()
        .verify(&snapshot.id)
        .unwrap();
}
#[test]
fn consumer_report_failure_keeps_local_checkpoint_unadvanced() {
    let lab = tempfile::tempdir().unwrap();
    let root = lab.path().canonicalize().unwrap();
    let config = config();
    let state = Arc::new(ConsumerState::open(&root.join("state"), &config).unwrap());
    fs::write(state.directory().join("reports"), b"blocked").unwrap();
    let backend = ConsumerBackend::with_transport(
        &config,
        None,
        false,
        Arc::new(GoogleFixture::default()),
        Arc::new(SystemClock),
        |_| Some("fixture-client".into()),
        state.clone(),
        state.clone(),
    )
    .unwrap();
    let repo = Repository::init(&root.join("repo"), "pipeline-fixture").unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("file"), b"fixture").unwrap();
    repo.snapshot(&work, &Policy::default(), None, None, "fixture")
        .unwrap();
    assert!(tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(consumer_replication::replicate(
            &repo, &backend, &state, None
        ))
        .is_err());
    assert!(!repo.root().join("checkpoints/latest").exists());
    assert!(state.evidence().unwrap().unwrap().objects.len() >= 4);
}

#[test]
fn ambiguous_refresh_survives_restart_until_explicit_changed_credential_rebind() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct LostRefresh(AtomicUsize);
    impl Transport for LostRefresh {
        fn send(&self, _: Request) -> std::result::Result<Response, TransportError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(TransportError)
        }
    }
    let lab = tempfile::tempdir().unwrap();
    let root = lab.path().canonicalize().unwrap();
    let config = config();
    let path = root.join("state");
    let state = Arc::new(ConsumerState::open(&path, &config).unwrap());
    let wire = Arc::new(LostRefresh(AtomicUsize::new(0)));
    let backend = ConsumerBackend::with_transport(
        &config,
        None,
        false,
        wire.clone(),
        Arc::new(SystemClock),
        |_| Some("fixture-client".into()),
        state.clone(),
        state.clone(),
    )
    .unwrap();
    let address = format!("{}/chunks/{}", "a".repeat(64), "b".repeat(64));
    assert!(tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(checkpoint::RemoteStore::create_verified(
            &backend,
            &address,
            b"fixture-ciphertext".to_vec()
        ))
        .is_err());
    assert_eq!(wire.0.load(Ordering::SeqCst), 1);
    drop(backend);
    drop(state);
    let state = Arc::new(ConsumerState::open(&path, &config).unwrap());
    assert!(ConsumerBackend::with_transport(
        &config,
        None,
        false,
        wire.clone(),
        Arc::new(SystemClock),
        |_| Some("fixture-client".into()),
        state.clone(),
        state.clone()
    )
    .is_err());
    assert_eq!(wire.0.load(Ordering::SeqCst), 1);
    assert!(state.rebind_refresh("fixture-client").is_err());
    state.rebind_refresh("fixture-rebound").unwrap();
    RefreshTokenSink::finish_refresh(&*state, "FIXTURE_REFRESH").unwrap();
    assert_eq!(
        RefreshTokenSink::load(&*state, "FIXTURE_REFRESH")
            .unwrap()
            .unwrap()
            .as_str(),
        "fixture-rebound"
    );
    assert!(ConsumerBackend::with_transport(
        &config,
        None,
        false,
        wire.clone(),
        Arc::new(SystemClock),
        |_| Some("fixture-client".into()),
        state.clone(),
        state.clone()
    )
    .is_ok());
    assert_eq!(wire.0.load(Ordering::SeqCst), 1);
}
