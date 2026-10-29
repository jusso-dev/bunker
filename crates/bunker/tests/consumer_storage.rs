//! Offline wire fixtures against the registered production adapter.
use bunker::{checkpoint, consumer_storage, storage};
use checkpoint::RemoteStore;
use chrono::{DateTime, Duration, Utc};
use consumer_storage::*;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const BYTES: &[u8] = b"encrypted-object-fixture";
const DOWNLOAD: &str =
    "https://public.dm.files.1drv.com/y4mFixture/content?tempauth=fixture-capability";
const UPLOAD: &str = "https://sn3302.up.1drv.com/up/fixture-session?auth=fixture-upload";
fn now() -> DateTime<Utc> {
    "2026-10-29T12:00:00Z".parse().unwrap()
}
fn path() -> String {
    format!("{}/chunks/{}", "a".repeat(64), "b".repeat(64))
}
struct Fixed(Mutex<DateTime<Utc>>);
impl Clock for Fixed {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}
#[derive(Default)]
struct Fixture {
    responses: Mutex<VecDeque<std::result::Result<Response, TransportError>>>,
    requests: Mutex<Vec<Request>>,
    tokens: Mutex<Option<Arc<Tokens>>>,
}
impl Transport for Fixture {
    fn send(&self, request: Request) -> std::result::Result<Response, TransportError> {
        if let Some(tokens) = &*self.tokens.lock().unwrap() {
            let refreshing = request.url.path().ends_with("/token");
            assert_eq!(tokens.pending.load(Ordering::SeqCst), refreshing);
        }
        // A blocking transport must run outside the async runtime's polling thread.
        // Creating/dropping this tiny local runtime would panic in an async context.
        drop(
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        );
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected network request")
    }
}
impl Fixture {
    fn add(&self, responses: Vec<Response>) {
        self.responses
            .lock()
            .unwrap()
            .extend(responses.into_iter().map(Ok));
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn drained(&self) {
        assert!(self.responses.lock().unwrap().is_empty());
    }
}
#[derive(Default)]
struct Tokens {
    values: Mutex<Vec<(String, String)>>,
    fail: AtomicBool,
    begins: Mutex<Vec<(String, String)>>,
    finishes: AtomicUsize,
    pending: AtomicBool,
    fail_begin: AtomicBool,
    fail_finish: AtomicBool,
}
impl RefreshTokenSink for Tokens {
    fn begin_refresh(
        &self,
        reference: &str,
        token: &str,
    ) -> std::result::Result<(), PersistenceError> {
        self.begins
            .lock()
            .unwrap()
            .push((reference.into(), token.into()));
        if self.fail_begin.load(Ordering::SeqCst) || self.pending.swap(true, Ordering::SeqCst) {
            return Err(PersistenceError);
        }
        Ok(())
    }
    fn finish_refresh(&self, reference: &str) -> std::result::Result<(), PersistenceError> {
        assert_eq!(reference, "FIXTURE_REFRESH");
        assert!(self.pending.load(Ordering::SeqCst));
        self.finishes.fetch_add(1, Ordering::SeqCst);
        if self.fail_finish.load(Ordering::SeqCst) {
            return Err(PersistenceError);
        }
        self.pending.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn persist(&self, reference: &str, token: &str) -> std::result::Result<(), PersistenceError> {
        assert!(self.pending.load(Ordering::SeqCst));
        self.values
            .lock()
            .unwrap()
            .push((reference.into(), token.into()));
        if self.fail.load(Ordering::SeqCst) {
            Err(PersistenceError)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
struct Evidence {
    values: Mutex<Vec<ConsumerEvidence>>,
    fail: AtomicBool,
}
impl EvidenceSink for Evidence {
    fn persist(&self, evidence: &ConsumerEvidence) -> std::result::Result<(), PersistenceError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PersistenceError);
        }
        self.values.lock().unwrap().push(evidence.clone());
        Ok(())
    }
}
struct Harness {
    backend: ConsumerBackend,
    wire: Arc<Fixture>,
    tokens: Arc<Tokens>,
    evidence: Arc<Evidence>,
    clock: Arc<Fixed>,
}
fn config(google: bool) -> storage::StorageConfig {
    storage::StorageConfig {
        service: if google { "gdrive" } else { "onedrive" }.into(),
        immutable: false,
        options: if google {
            BTreeMap::from([("root".into(), "folder-123".into())])
        } else {
            BTreeMap::from([
                ("root".into(), "folder-123".into()),
                ("drive_id".into(), "0123456789ABCDEF".into()),
            ])
        },
        credential_env: BTreeMap::from([
            ("client_id".into(), "FIXTURE_CLIENT".into()),
            ("client_secret".into(), "FIXTURE_SECRET".into()),
            ("refresh_token".into(), "FIXTURE_REFRESH".into()),
        ]),
    }
}
fn resolve(name: &str) -> Option<String> {
    match name {
        "FIXTURE_CLIENT" => Some("fixture-client"),
        "FIXTURE_SECRET" => Some("fixture-secret&=+"),
        "FIXTURE_REFRESH" => Some("fixture-refresh&=+"),
        _ => None,
    }
    .map(str::to_owned)
}
fn harness(google: bool, saved: Option<&ConsumerEvidence>, recovery: bool) -> Harness {
    let wire = Arc::new(Fixture::default());
    let tokens = Arc::new(Tokens::default());
    *wire.tokens.lock().unwrap() = Some(tokens.clone());
    let evidence = Arc::new(Evidence::default());
    let clock = Arc::new(Fixed(Mutex::new(now())));
    let backend = ConsumerBackend::with_transport(
        &config(google),
        saved,
        recovery,
        wire.clone(),
        clock.clone(),
        resolve,
        tokens.clone(),
        evidence.clone(),
    )
    .unwrap();
    Harness {
        backend,
        wire,
        tokens,
        evidence,
        clock,
    }
}
fn run(f: impl std::future::Future<Output = ()>) {
    tokio::runtime::Runtime::new().unwrap().block_on(f);
}
fn raw(status: u16, body: &[u8]) -> Response {
    Response {
        status,
        headers: HeaderMap::new(),
        body: body.to_vec(),
    }
}
fn response(status: u16, body: Value) -> Response {
    raw(status, &serde_json::to_vec(&body).unwrap())
}
fn token(rotated: Option<&str>) -> Response {
    response(
        200,
        json!({"access_token":"fixture-access", "refresh_token":rotated, "token_type":"Bearer", "expires_in":3600}),
    )
}
fn root(google: bool) -> Response {
    response(
        200,
        if google {
            json!({"id":"folder-123", "mimeType":"application/vnd.google-apps.folder", "trashed":false})
        } else {
            json!({"id":"folder-123", "folder":{}, "parentReference":{"id":"parent-1", "driveId":"0123456789ABCDEF"}})
        },
    )
}
fn google_meta() -> Value {
    json!({"id":"1aBcDriveFile", "mimeType":"application/octet-stream", "parents":["folder-123"], "trashed":false,
    "size": BYTES.len().to_string(), "headRevisionId":"0B_revision-123"})
}
fn google_revision() -> Value {
    json!({"id":"0B_revision-123", "mimeType":"application/octet-stream", "keepForever":true, "size": BYTES.len().to_string()})
}
fn graph_meta(size: usize) -> Value {
    json!({"id":"0123456789ABCDEF!123", "name":"opaque-publication-name", "size":size, "eTag":"\"{ABC-DEF},2\"", "cTag":"\"c:{ABC-DEF},1\"", "file":{"mimeType":"application/octet-stream"}, "parentReference":{"id":"folder-123", "driveId":"0123456789ABCDEF"}, "@microsoft.graph.downloadUrl":DOWNLOAD})
}
fn session(url: &str) -> Response {
    response(
        200,
        json!({"uploadUrl":url, "expirationDateTime":"2026-10-29T12:30:00Z"}),
    )
}
fn reads(google: bool) -> Vec<Response> {
    if google {
        vec![
            response(200, google_meta()),
            response(200, google_revision()),
            raw(200, BYTES),
        ]
    } else {
        vec![
            response(200, graph_meta(BYTES.len())),
            raw(200, BYTES),
            response(200, graph_meta(BYTES.len())),
        ]
    }
}
fn google_session(url: &str) -> Response {
    let mut response = raw(200, b"");
    response
        .headers
        .insert(http::header::LOCATION, HeaderValue::from_str(url).unwrap());
    response
}
fn publication(google: bool) -> Vec<Response> {
    let mut responses = vec![token(None), root(google)];
    if google {
        responses.extend([google_session("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=fixture-session"),response(200, google_meta()), response(200, google_revision())]);
    } else {
        responses.extend([session(UPLOAD), response(201, graph_meta(BYTES.len()))]);
    }
    responses.extend(reads(google));
    responses
}
fn saved(google: bool) -> ConsumerEvidence {
    ConsumerEvidence {
        version: 1,
        location: ConsumerLocation {
            service: config(google).service,
            root: "folder-123".into(),
            drive_id: config(google).options.get("drive_id").cloned(),
        },
        objects: BTreeMap::from([(
            path(),
            ObjectProof {
                file_id: if google {
                    "1aBcDriveFile"
                } else {
                    "0123456789ABCDEF!123"
                }
                .into(),
                revision: if google {
                    Revision::Google {
                        revision_id: "0B_revision-123".into(),
                    }
                } else {
                    Revision::OneDrive {
                        etag: "\"{ABC-DEF},2\"".into(),
                        ctag: "\"c:{ABC-DEF},1\"".into(),
                    }
                },
                bytes: BYTES.len() as u64,
                blake3: blake3::hash(BYTES).to_hex().to_string(),
            },
        )]),
    }
}

#[test]
fn publication_and_exact_id_recovery_both_providers() {
    run(async {
        for google in [true, false] {
            let h = harness(google, None, false);
            h.wire.add(publication(google));
            h.backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .unwrap();
            h.wire.drained();
            let evidence = h.backend.evidence().unwrap();
            assert_eq!(evidence, saved(google));
            assert_eq!(
                h.evidence.values.lock().unwrap().as_slice(),
                std::slice::from_ref(&evidence)
            );
            let bytes = evidence.to_vec().unwrap();
            let parsed = ConsumerEvidence::from_slice(&bytes).unwrap();
            assert_eq!(parsed, evidence);
            let recovery = harness(google, Some(&parsed), true);
            recovery.wire.add(vec![token(None)]);
            recovery.wire.add(reads(google));
            assert_eq!(
                recovery
                    .backend
                    .read_bounded(&path(), MAX_OBJECT)
                    .await
                    .unwrap(),
                BYTES
            );
            assert!(recovery
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            recovery.wire.drained();
            let requests = h.wire.requests.lock().unwrap();
            let oauth = &requests[0];
            assert_eq!(oauth.method, Method::POST);
            assert_eq!(
                oauth.url.as_str(),
                if google {
                    "https://oauth2.googleapis.com/token"
                } else {
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                }
            );
            let form: BTreeMap<_, _> = url::form_urlencoded::parse(&oauth.body)
                .into_owned()
                .collect();
            assert_eq!(form["client_secret"], "fixture-secret&=+");
            assert_eq!(form["refresh_token"], "fixture-refresh&=+");
            assert_eq!(form["grant_type"], "refresh_token");
            assert!(!oauth.headers.contains_key("authorization"));
            for request in requests.iter().skip(1) {
                assert_eq!(request.url.scheme(), "https");
                if request
                    .url
                    .host_str()
                    .is_some_and(|s| s.ends_with("1drv.com"))
                {
                    assert!(!request.headers.contains_key("authorization"));
                } else {
                    assert_eq!(request.headers["authorization"], "Bearer fixture-access");
                    assert!(request.headers["authorization"].is_sensitive());
                }
                assert!(!request.url.as_str().contains("fixture-refresh"));
                assert!(!request.url.path().ends_with("/children"));
            }
            if google {
                assert!(requests[2].url.path().starts_with("/upload/drive/v3/files"));
                assert_eq!(requests[2].method, Method::POST);
                let body = String::from_utf8_lossy(&requests[2].body);
                assert!(body.contains("application/octet-stream"));
                assert!(body.contains("folder-123"));
                assert!(requests
                    .last()
                    .unwrap()
                    .url
                    .path()
                    .ends_with("/revisions/0B_revision-123"));
            } else {
                assert!(requests[2].url.path().ends_with(":/createUploadSession"));
                let payload: Value = serde_json::from_slice(&requests[2].body).unwrap();
                assert_eq!(payload["item"]["@microsoft.graph.conflictBehavior"], "fail");
                assert_eq!(payload["deferCommit"], false);
                assert_eq!(requests[3].url.as_str(), UPLOAD);
                assert_eq!(
                    requests[3].headers["content-range"],
                    format!("bytes 0-{}/{}", BYTES.len() - 1, BYTES.len())
                );
                assert_eq!(requests[3].body, BYTES);
            }
        }
    });
}

#[test]
fn existing_proof_reuses_ids_but_never_overwrites_different_ciphertext() {
    run(async {
        for google in [true, false] {
            let h = harness(google, Some(&saved(google)), false);
            assert!(h
                .backend
                .create_verified(&path(), b"different ciphertext".to_vec())
                .await
                .is_err());
            assert_eq!(h.wire.count(), 0);
            h.wire.add(vec![token(None)]);
            h.wire.add(reads(google));
            h.backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .unwrap();
            assert!(h
                .wire
                .requests
                .lock()
                .unwrap()
                .iter()
                .skip(1)
                .all(|r| r.method == Method::GET));
            h.wire.drained();
        }
    });
}

#[test]
fn missing_evidence_never_lists_or_resolves_latest_or_duplicate_names() {
    run(async {
        for google in [true, false] {
            let h = harness(google, None, false);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            assert!(h.backend.read_bounded("latest", MAX_OBJECT).await.is_err());
            assert_eq!(h.wire.count(), 0);
            let pinned = harness(google, Some(&saved(google)), true);
            pinned.wire.add(vec![
                token(None),
                response(
                    404,
                    json!({"error":"fixture missing; other same-name files exist"}),
                ),
            ]);
            assert!(pinned
                .backend
                .read_bounded(&path(), MAX_OBJECT)
                .await
                .is_err());
            assert_eq!(pinned.wire.count(), 2);
            pinned.wire.drained();
        }
    });
}

#[test]
fn refresh_intent_failure_prevents_all_network_work() {
    run(async {
        for google in [true, false] {
            let h = harness(google, Some(&saved(google)), true);
            h.tokens.fail_begin.store(true, Ordering::SeqCst);
            for _ in 0..2 {
                let error = h
                    .backend
                    .read_bounded(&path(), MAX_OBJECT)
                    .await
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("durable private token-store intent"));
                assert!(!error.contains("fixture-refresh"));
            }
            assert_eq!(h.wire.count(), 0);
            assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 0);
            h.tokens.fail_begin.store(false, Ordering::SeqCst);
            h.wire.add(vec![token(None)]);
            h.wire.add(reads(google));
            h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
            assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 1);
            h.wire.drained();
        }
    });
}

#[test]
fn refresh_completion_failure_blocks_work_until_durable_cleanup() {
    run(async {
        for google in [true, false] {
            for rotated in [None, Some("fixture-new")] {
                let h = harness(google, Some(&saved(google)), true);
                h.tokens.fail_finish.store(true, Ordering::SeqCst);
                h.wire.add(vec![token(rotated)]);
                for _ in 0..2 {
                    let error = h
                        .backend
                        .read_bounded(&path(), MAX_OBJECT)
                        .await
                        .unwrap_err()
                        .to_string();
                    assert!(error.contains("durable private token-store completion"));
                    assert!(!error.contains("fixture-new"));
                }
                assert_eq!(h.wire.count(), 1);
                assert_eq!(h.tokens.begins.lock().unwrap().len(), 1);
                assert_eq!(
                    h.tokens.values.lock().unwrap().len(),
                    usize::from(rotated.is_some())
                );
                assert!(h.tokens.pending.load(Ordering::SeqCst));
                h.tokens.fail_finish.store(false, Ordering::SeqCst);
                if rotated.is_some() {
                    // The replacement was saved before parsing/caching access.
                    h.wire.add(vec![token(None)]);
                }
                h.wire.add(reads(google));
                h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
                if let Some(rotated) = rotated {
                    assert_eq!(h.tokens.begins.lock().unwrap()[1].1, rotated);
                } else {
                    assert_eq!(h.tokens.begins.lock().unwrap().len(), 1);
                }
                assert!(!h.tokens.pending.load(Ordering::SeqCst));
                h.wire.drained();
            }
        }
    });
}

#[test]
fn pending_rotation_retries_persistence_and_completion_before_network() {
    run(async {
        let h = harness(false, Some(&saved(false)), true);
        h.tokens.fail.store(true, Ordering::SeqCst);
        h.wire.add(vec![token(Some("fixture-new"))]);
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 0);
        h.tokens.fail.store(false, Ordering::SeqCst);
        h.tokens.fail_finish.store(true, Ordering::SeqCst);
        for _ in 0..2 {
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        }
        assert_eq!(h.wire.count(), 1);
        assert_eq!(h.tokens.values.lock().unwrap().len(), 2);
        assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 2);
        assert!(h.tokens.pending.load(Ordering::SeqCst));
        h.tokens.fail_finish.store(false, Ordering::SeqCst);
        h.wire.add(vec![token(None)]);
        h.wire.add(reads(false));
        h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
        assert_eq!(h.tokens.begins.lock().unwrap()[1].1, "fixture-new");
        assert!(!h.tokens.pending.load(Ordering::SeqCst));
        h.wire.drained();
    });
}

#[test]
fn malformed_rotating_response_clears_guard_only_after_replacement_is_durable() {
    run(async {
        for google in [true, false] {
            let h = harness(google, Some(&saved(google)), true);
            h.wire.add(vec![response(
                200,
                json!({"refresh_token":"fixture-new", "access_token":42}),
            )]);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            assert_eq!(h.tokens.values.lock().unwrap()[0].1, "fixture-new");
            assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 1);
            assert!(!h.tokens.pending.load(Ordering::SeqCst));
            h.wire.add(vec![token(None)]);
            h.wire.add(reads(google));
            h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
            assert_eq!(h.tokens.begins.lock().unwrap()[1].1, "fixture-new");
            h.wire.drained();
        }
    });
}

#[test]
fn malformed_nonrotating_response_keeps_durable_guard() {
    run(async {
        for google in [true, false] {
            for value in [
                json!({"token_type":"Bearer", "expires_in":3600}),
                json!({"access_token":42,"token_type":"Bearer","expires_in":3600}),
                json!({"access_token":"fixture-access","token_type":42,"expires_in":3600}),
                json!({"access_token":"fixture-access","token_type":"Bearer","expires_in":"3600"}),
                json!({"access_token":"fixture-access","token_type":"Bearer","expires_in":0}),
                json!({"refresh_token":"fixture-refresh&=+", "expires_in":3600}),
                json!({"refresh_token":"", "access_token":"fixture-access","token_type":"Bearer","expires_in":3600}),
            ] {
                let h = harness(google, Some(&saved(google)), true);
                h.wire.add(vec![response(200, value)]);
                for _ in 0..2 {
                    assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
                }
                assert_eq!(h.wire.count(), 1);
                assert!(h.tokens.pending.load(Ordering::SeqCst));
                assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 0);
                assert!(h.tokens.values.lock().unwrap().is_empty());
            }
        }
    });
}

#[test]
fn oauth_rotation_persisted_before_provider_access_and_next_refresh_uses_it() {
    run(async {
        let h = harness(false, Some(&saved(false)), true);
        h.wire.add(vec![token(Some("fixture-rotated-refresh"))]);
        h.wire.add(reads(false));
        h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
        assert_eq!(
            h.tokens.values.lock().unwrap().as_slice(),
            &[("FIXTURE_REFRESH".into(), "fixture-rotated-refresh".into())]
        );
        *h.clock.0.lock().unwrap() = now() + Duration::hours(1);
        h.wire.add(vec![token(None)]);
        h.wire.add(reads(false));
        h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
        let requests = h.wire.requests.lock().unwrap();
        let form: BTreeMap<_, _> = url::form_urlencoded::parse(&requests[4].body)
            .into_owned()
            .collect();
        assert_eq!(form["refresh_token"], "fixture-rotated-refresh");
        h.wire.drained();
    });
}

#[test]
fn rotation_sink_failure_retains_credential_and_blocks_remote_work() {
    run(async {
        let h = harness(false, Some(&saved(false)), true);
        h.tokens.fail.store(true, Ordering::SeqCst);
        h.wire.add(vec![token(Some("fixture-rotated-refresh"))]);
        let error = h
            .backend
            .read_bounded(&path(), MAX_OBJECT)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("durable private token-store"));
        assert!(!error.contains("fixture-rotated-refresh"));
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert_eq!(h.wire.count(), 1);
        h.tokens.fail.store(false, Ordering::SeqCst);
        h.wire.add(vec![token(None)]);
        h.wire.add(reads(false));
        h.backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
        let requests = h.wire.requests.lock().unwrap();
        let form: BTreeMap<_, _> = url::form_urlencoded::parse(&requests[1].body)
            .into_owned()
            .collect();
        assert_eq!(form["refresh_token"], "fixture-rotated-refresh");
        h.wire.drained();
    });
}

#[test]
fn ambiguous_refresh_is_never_retried_and_errors_are_redacted() {
    run(async {
        for status in [302, 400, 401, 429, 500] {
            let h = harness(true, Some(&saved(true)), true);
            h.wire.add(vec![raw(
                status,
                b"fixture-access fixture-secret fixture-refresh plaintext-body",
            )]);
            let error = h
                .backend
                .read_bounded(&path(), MAX_OBJECT)
                .await
                .unwrap_err();
            assert!(!format!("{error:#}").contains("fixture-"));
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            assert_eq!(h.wire.count(), 1);
            assert!(h.tokens.pending.load(Ordering::SeqCst));
            assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 0);
        }
        let h = harness(true, Some(&saved(true)), true);
        h.wire
            .responses
            .lock()
            .unwrap()
            .push_back(Err(TransportError));
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert_eq!(h.wire.count(), 1);
        assert!(h.tokens.pending.load(Ordering::SeqCst));
        assert_eq!(h.tokens.finishes.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn malformed_access_response_still_persists_rotated_refresh() {
    run(async {
        let h = harness(true, Some(&saved(true)), true);
        h.wire.add(vec![response(200,json!({"refresh_token":"fixture-rotated-refresh", "token_type":"Bearer", "expires_in":3600}))]);
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert_eq!(
            h.tokens.values.lock().unwrap()[0].1,
            "fixture-rotated-refresh"
        );
        assert_eq!(h.wire.count(), 1);
    });
}

#[test]
fn durable_evidence_failure_does_not_acknowledge_or_upload_again() {
    run(async {
        for google in [true, false] {
            let h = harness(google, None, false);
            h.evidence.fail.store(true, Ordering::SeqCst);
            h.wire.add(publication(google));
            assert!(h
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            assert!(h.evidence.values.lock().unwrap().is_empty());
            assert_eq!(h.backend.evidence().unwrap(), saved(google));
            let count = h.wire.count();
            h.evidence.fail.store(false, Ordering::SeqCst);
            h.wire.add(reads(google));
            h.backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .unwrap();
            assert!(h
                .wire
                .requests
                .lock()
                .unwrap()
                .iter()
                .skip(count)
                .all(|r| r.method == Method::GET));
            h.wire.drained();
        }
    });
}

#[test]
fn wrong_hash_revision_metadata_and_changed_onedrive_revision_fail_closed() {
    run(async {
        for google in [true, false] {
            let h = harness(google, Some(&saved(google)), true);
            h.wire.add(vec![token(None)]);
            let mut responses = reads(google);
            let body = if google { 2 } else { 1 };
            responses[body] = raw(200, &vec![b'x'; BYTES.len()]);
            h.wire.add(responses);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            h.wire.drained();
        }
        for field in ["eTag", "cTag", "id"] {
            let h = harness(false, Some(&saved(false)), true);
            let mut metadata = graph_meta(BYTES.len());
            metadata[field] = json!("changed");
            h.wire.add(vec![token(None), response(200, metadata)]);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            assert_eq!(h.wire.count(), 2);
        }
        let h = harness(false, Some(&saved(false)), true);
        let mut after = graph_meta(BYTES.len());
        after["eTag"] = json!("changed");
        h.wire.add(vec![
            token(None),
            response(200, graph_meta(BYTES.len())),
            raw(200, BYTES),
            response(200, after),
        ]);
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        h.wire.drained();
        let h = harness(true, Some(&saved(true)), true);
        let mut revision = google_revision();
        revision["keepForever"] = json!(false);
        h.wire.add(vec![
            token(None),
            response(200, google_meta()),
            response(200, revision),
        ]);
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        h.wire.drained();
    });
}

#[test]
fn redirects_untrusted_capability_origins_and_oversized_bodies_are_rejected() {
    run(async {
        for url in [
            "http://public.dm.files.1drv.com/f",
            "https://public.dm.files.1drv.com.evil.invalid/f",
            "https://127.0.0.1/f",
            "https://u:p@tenant.sharepoint.com/f",
            "https://tenant.sharepoint.com:444/f",
            "https://tenant.sharepoint.com/f#fragment",
            "https://graph.microsoft.com/f",
        ] {
            let h = harness(false, Some(&saved(false)), true);
            let mut metadata = graph_meta(BYTES.len());
            metadata["@microsoft.graph.downloadUrl"] = json!(url);
            h.wire.add(vec![token(None), response(200, metadata)]);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            assert_eq!(h.wire.count(), 2);
        }
        for response in [raw(302, b""), raw(200, &vec![b'x'; BYTES.len() + 1])] {
            let h = harness(false, Some(&saved(false)), true);
            h.wire.add(vec![token(None), response_fn_graph(), response]);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            h.wire.drained();
        }
        let h = harness(true, Some(&saved(true)), true);
        h.wire.add(vec![raw(200, &vec![b'x'; 65537])]);
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert_eq!(h.wire.count(), 1);
    });
}
fn response_fn_graph() -> Response {
    response(200, graph_meta(BYTES.len()))
}

#[test]
fn conflicts_and_uncertain_uploads_never_fallback_to_replace() {
    run(async {
        for status in [409, 412, 429, 500, 302] {
            let h = harness(false, None, false);
            h.wire.add(vec![
                token(None),
                root(false),
                session(UPLOAD),
                raw(status, b"sensitive-provider-body"),
            ]);
            assert!(h
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            assert_eq!(h.wire.count(), 4);
            assert!(h.backend.evidence().unwrap().objects.is_empty());
            h.wire.drained();
        }
        let h = harness(true, None, false);
        h.wire.add(vec![token(None), root(true)]);
        h.wire
            .responses
            .lock()
            .unwrap()
            .push_back(Err(TransportError));
        assert!(h
            .backend
            .create_verified(&path(), BYTES.to_vec())
            .await
            .is_err());
        assert_eq!(h.wire.count(), 3);
    });
}

#[test]
fn strict_configuration_and_evidence_bounds_fail_before_network_or_ambient_resolution() {
    let build = |cfg: &storage::StorageConfig, ev: Option<&ConsumerEvidence>, recovery: bool| {
        ConsumerBackend::with_transport(
            cfg,
            ev,
            recovery,
            Arc::new(Fixture::default()),
            Arc::new(Fixed(Mutex::new(now()))),
            resolve,
            Arc::new(Tokens::default()),
            Arc::new(Evidence::default()),
        )
    };
    for google in [true, false] {
        let mut cfg = config(google);
        cfg.immutable = true;
        assert!(build(&cfg, None, false).is_err());
        cfg.immutable = false;
        cfg.options
            .insert("endpoint".into(), "https://evil.invalid".into());
        assert!(build(&cfg, None, false).is_err());
        cfg.options.remove("endpoint");
        for invalid in ["/folder", "root", "me", "../folder", "folder?token=secret"] {
            cfg.options.insert("root".into(), invalid.into());
            assert!(build(&cfg, None, false).is_err());
        }
        cfg = config(google);
        cfg.credential_env
            .insert("access_token".into(), "AMBIENT_TOKEN".into());
        assert!(build(&cfg, None, false).is_err());
        cfg = config(google);
        cfg.credential_env.remove("client_secret");
        assert!(build(&cfg, None, false).is_err());
        assert!(build(&config(google), None, true).is_err());
        let mut ev = saved(google);
        ev.location.root = "other-folder".into();
        assert!(build(&config(google), Some(&ev), true).is_err());
        let mut ev = saved(google);
        ev.objects.get_mut(&path()).unwrap().file_id = "../../other".into();
        assert!(build(&config(google), Some(&ev), true).is_err());
    }
    let mut cfg = config(false);
    cfg.options.remove("drive_id");
    assert!(build(&cfg, None, false).is_err());
    let mut value = serde_json::to_value(saved(true)).unwrap();
    value["secret"] = json!("nope");
    assert!(ConsumerEvidence::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(ConsumerEvidence::from_slice(&vec![b' '; MAX_EVIDENCE + 1]).is_err());
}

#[test]
fn read_and_publication_size_limits_precede_network() {
    run(async {
        let h = harness(false, Some(&saved(false)), false);
        assert!(h.backend.read_bounded(&path(), 1).await.is_err());
        assert!(h
            .backend
            .create_verified("latest", BYTES.to_vec())
            .await
            .is_err());
        assert!(h.backend.create_verified(&path(), vec![]).await.is_err());
        assert!(h
            .backend
            .create_verified(&path(), vec![0; MAX_OBJECT as usize + 1])
            .await
            .is_err());
        assert_eq!(h.wire.count(), 0);
    });
}

#[test]
fn onedrive_fragments_are_bounded_ordered_and_verified() {
    run(async {
        const FRAGMENT: usize = 10 * 1024 * 1024;
        let bytes = vec![42; FRAGMENT + 3];
        let h = harness(false, None, false);
        h.wire.add(vec![token(None),root(false),session(UPLOAD),response(202,json!({"expirationDateTime":"2026-10-29T12:30:00Z","nextExpectedRanges":[format!("{FRAGMENT}-")]})),response(201,graph_meta(bytes.len())),response(200,graph_meta(bytes.len())),raw(200,&bytes),response(200,graph_meta(bytes.len()))]);
        h.backend
            .create_verified(&path(), bytes.clone())
            .await
            .unwrap();
        h.wire.drained();
        let requests = h.wire.requests.lock().unwrap();
        assert_eq!(requests[3].body.len(), FRAGMENT);
        assert_eq!(requests[4].body.len(), 3);
        assert_eq!(
            requests[4].headers["content-range"],
            format!("bytes {}-{}/{}", FRAGMENT, FRAGMENT + 2, FRAGMENT + 3)
        );
        assert_eq!(
            h.backend.evidence().unwrap().objects[&path()].blake3,
            blake3::hash(&bytes).to_hex().as_str()
        );
    });
}

#[test]
fn session_url_progress_expiry_and_root_mismatch_stop_uploads() {
    run(async {
        for url in [
            "https://evil.invalid/upload",
            "http://sn3302.up.1drv.com/upload",
            "https://sn3302.up.1drv.com.evil.invalid/upload",
        ] {
            let h = harness(false, None, false);
            h.wire.add(vec![token(None), root(false), session(url)]);
            assert!(h
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            assert_eq!(h.wire.count(), 3);
        }
        for expiry in ["2026-10-29T11:00:00Z", "2030-01-01T00:00:00Z"] {
            let h = harness(false, None, false);
            h.wire.add(vec![
                token(None),
                root(false),
                response(200, json!({"uploadUrl":UPLOAD,"expirationDateTime":expiry})),
            ]);
            assert!(h
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            assert_eq!(h.wire.count(), 3);
        }
        for google in [true, false] {
            let h = harness(google, None, false);
            h.wire.add(vec![token(None), raw(404, b"folder missing")]);
            assert!(h
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            assert_eq!(h.wire.count(), 2);
        }
        let h = harness(false, None, false);
        h.wire.add(vec![
            token(None),
            root(false),
            session(UPLOAD),
            response(
                202,
                json!({"expirationDateTime":"2026-10-29T12:30:00Z","nextExpectedRanges":["0-"]}),
            ),
        ]);
        assert!(h
            .backend
            .create_verified(&path(), vec![42; 10 * 1024 * 1024 + 1])
            .await
            .is_err());
        assert_eq!(h.wire.count(), 4);
    });
}

#[test]
fn response_header_budget_is_enforced_even_for_injected_transport() {
    run(async {
        let h = harness(true, Some(&saved(true)), true);
        let mut response = token(None);
        response.headers.insert(
            "x-fixture",
            HeaderValue::from_str(&"x".repeat(65537)).unwrap(),
        );
        h.wire.add(vec![response]);
        assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
        assert_eq!(h.wire.count(), 1);
    });
}

#[test]
fn restart_loads_protected_rotation_without_resolving_stale_refresh_environment() {
    run(async {
        struct Stored;
        impl RefreshTokenSink for Stored {
            fn begin_refresh(&self, _: &str, _: &str) -> std::result::Result<(), PersistenceError> {
                Ok(())
            }
            fn finish_refresh(&self, _: &str) -> std::result::Result<(), PersistenceError> {
                Ok(())
            }
            fn load(
                &self,
                reference: &str,
            ) -> std::result::Result<Option<zeroize::Zeroizing<String>>, PersistenceError>
            {
                assert_eq!(reference, "FIXTURE_REFRESH");
                Ok(Some(zeroize::Zeroizing::new(
                    "fixture-saved-rotation".into(),
                )))
            }
            fn persist(&self, _: &str, _: &str) -> std::result::Result<(), PersistenceError> {
                Ok(())
            }
        }
        let wire = Arc::new(Fixture::default());
        let backend = ConsumerBackend::with_transport(
            &config(false),
            Some(&saved(false)),
            true,
            wire.clone(),
            Arc::new(Fixed(Mutex::new(now()))),
            |name| {
                assert_ne!(name, "FIXTURE_REFRESH");
                resolve(name)
            },
            Arc::new(Stored),
            Arc::new(Evidence::default()),
        )
        .unwrap();
        wire.add(vec![token(None)]);
        wire.add(reads(false));
        backend.read_bounded(&path(), MAX_OBJECT).await.unwrap();
        let requests = wire.requests.lock().unwrap();
        let form: BTreeMap<_, _> = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(form["refresh_token"], "fixture-saved-rotation");
    });
}

#[test]
fn unreadable_or_invalid_saved_rotation_never_falls_back_to_environment() {
    struct Stored(bool);
    impl RefreshTokenSink for Stored {
        fn begin_refresh(&self, _: &str, _: &str) -> std::result::Result<(), PersistenceError> {
            unreachable!()
        }
        fn finish_refresh(&self, _: &str) -> std::result::Result<(), PersistenceError> {
            unreachable!()
        }
        fn load(
            &self,
            _: &str,
        ) -> std::result::Result<Option<zeroize::Zeroizing<String>>, PersistenceError> {
            if self.0 {
                Err(PersistenceError)
            } else {
                Ok(Some(zeroize::Zeroizing::new(String::new())))
            }
        }
        fn persist(&self, _: &str, _: &str) -> std::result::Result<(), PersistenceError> {
            Ok(())
        }
    }
    for fail in [true, false] {
        let result = ConsumerBackend::with_transport(
            &config(false),
            None,
            false,
            Arc::new(Fixture::default()),
            Arc::new(Fixed(Mutex::new(now()))),
            |name| {
                assert_ne!(name, "FIXTURE_REFRESH");
                resolve(name)
            },
            Arc::new(Stored(fail)),
            Arc::new(Evidence::default()),
        );
        assert!(result.is_err());
    }
}

#[test]
fn malformed_oauth_access_fields_cannot_discard_valid_rotation() {
    run(async {
        for value in [
            json!({"refresh_token":"fixture-new", "access_token":42,"token_type":"Bearer","expires_in":3600}),
            json!({"refresh_token":"fixture-new", "access_token":"fixture-access","token_type":42,"expires_in":3600}),
            json!({"refresh_token":"fixture-new", "access_token":"fixture-access","token_type":"Bearer","expires_in":"invalid"}),
        ] {
            let h = harness(true, Some(&saved(true)), true);
            h.wire.add(vec![response(200, value)]);
            assert!(h.backend.read_bounded(&path(), MAX_OBJECT).await.is_err());
            assert_eq!(h.tokens.values.lock().unwrap()[0].1, "fixture-new");
            assert_eq!(h.wire.count(), 1);
        }
    });
}

#[test]
fn google_upload_session_location_cannot_redirect_credentials() {
    run(async {
        for url in [
            "https://evil.invalid/upload/drive/v3/files?upload_id=fixture",
            "http://www.googleapis.com/upload/drive/v3/files?upload_id=fixture",
            "https://www.googleapis.com/other?upload_id=fixture",
            "https://www.googleapis.com/upload/drive/v3/files",
            "https://user@www.googleapis.com/upload/drive/v3/files?upload_id=fixture",
        ] {
            let h = harness(true, None, false);
            h.wire
                .add(vec![token(None), root(true), google_session(url)]);
            assert!(h
                .backend
                .create_verified(&path(), BYTES.to_vec())
                .await
                .is_err());
            assert_eq!(h.wire.count(), 3);
        }
    });
}

#[test]
fn proof_count_and_revision_kind_are_bounded_and_validated() {
    let mut evidence = saved(true);
    let proof = evidence.objects[&path()].clone();
    evidence.objects.clear();
    for index in 0..=MAX_PROOFS {
        evidence.objects.insert(
            format!("{}/chunks/{index:064x}", "a".repeat(64)),
            proof.clone(),
        );
    }
    assert!(evidence.to_vec().is_err());
    let mut evidence = saved(true);
    evidence.objects.get_mut(&path()).unwrap().revision = Revision::OneDrive {
        etag: "etag".into(),
        ctag: "ctag".into(),
    };
    assert!(evidence.to_vec().is_err());
    let mut evidence = saved(true);
    evidence.objects.get_mut(&path()).unwrap().bytes = MAX_OBJECT + 1;
    assert!(evidence.to_vec().is_err());
}
