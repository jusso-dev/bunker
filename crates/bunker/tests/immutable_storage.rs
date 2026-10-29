//! Offline protocol fixtures only. No cloud requests or credentials are used.
use bunker::{protected_storage::*, storage::StorageConfig};
use chrono::{DateTime, Duration, Utc};
use http::{HeaderMap, HeaderValue, Method};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

const BYTES: &[u8] = b"encrypted-fixture";
const PATH: &str = "repo/chunks/abc";
fn now() -> DateTime<Utc> {
    "2026-10-29T12:00:00Z".parse().unwrap()
}
fn until() -> DateTime<Utc> {
    now() + Duration::days(30)
}
struct Fixed(DateTime<Utc>);
impl Clock for Fixed {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}
#[derive(Default)]
struct Fixture {
    responses: Mutex<VecDeque<std::result::Result<Response, TransportError>>>,
    requests: Mutex<Vec<Request>>,
}
impl Transport for Fixture {
    fn send(&self, request: Request) -> std::result::Result<Response, TransportError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected fixture request")
    }
}
fn config(azure: bool) -> StorageConfig {
    let mut options = BTreeMap::from([(
        "endpoint".into(),
        if azure {
            "https://fixture.blob.core.windows.net"
        } else {
            "https://s3.us-east-1.amazonaws.com"
        }
        .into(),
    )]);
    let credential_env = if azure {
        options.insert("account_name".into(), "fixture".into());
        options.insert("container".into(), "backup".into());
        BTreeMap::from([("account_key".into(), "FIXTURE_ACCOUNT_KEY".into())])
    } else {
        options.insert("bucket".into(), "backup".into());
        options.insert("region".into(), "us-east-1".into());
        BTreeMap::from([
            ("access_key_id".into(), "FIXTURE_ACCESS_ID".into()),
            ("secret_access_key".into(), "FIXTURE_SECRET".into()),
        ])
    };
    StorageConfig {
        service: if azure { "azure" } else { "s3" }.into(),
        options,
        credential_env,
        immutable: true,
    }
}
fn credential(name: &str) -> Option<String> {
    Some(
        match name {
            "FIXTURE_ACCOUNT_KEY" => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "FIXTURE_ACCESS_ID" => "AKIDEXAMPLE",
            "FIXTURE_SECRET" => "fixture-only-secret-not-a-real-key",
            "OTHER_ID" => "OTHERFIXTUREID",
            _ => return None,
        }
        .into(),
    )
}
fn build(config: &StorageConfig, responses: Vec<Response>) -> (ProtectedBackend, Arc<Fixture>) {
    let fixture = Arc::new(Fixture {
        responses: Mutex::new(responses.into_iter().map(Ok).collect()),
        ..Fixture::default()
    });
    let backend = ProtectedBackend::with_transport(
        config,
        until(),
        fixture.clone(),
        Arc::new(Fixed(now())),
        credential,
    )
    .unwrap();
    (backend, fixture)
}
fn response(
    azure: bool,
    status: u16,
    version: Option<&str>,
    retention: Option<(&str, DateTime<Utc>)>,
    bytes: &[u8],
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "date",
        HeaderValue::from_str(&httpdate::fmt_http_date(now().into())).unwrap(),
    );
    if let Some(version) = version {
        headers.insert(
            if azure {
                "x-ms-version-id"
            } else {
                "x-amz-version-id"
            },
            HeaderValue::from_str(version).unwrap(),
        );
    }
    if let Some((mode, date)) = retention {
        headers.insert(
            if azure {
                "x-ms-immutability-policy-mode"
            } else {
                "x-amz-object-lock-mode"
            },
            HeaderValue::from_str(mode).unwrap(),
        );
        let date = if azure {
            httpdate::fmt_http_date(date.into())
        } else {
            date.to_rfc3339()
        };
        headers.insert(
            if azure {
                "x-ms-immutability-policy-until-date"
            } else {
                "x-amz-object-lock-retain-until-date"
            },
            HeaderValue::from_str(&date).unwrap(),
        );
    }
    Response {
        status,
        headers,
        body: bytes.to_vec(),
    }
}
fn protected(azure: bool) -> Response {
    response(
        azure,
        200,
        Some("v1"),
        Some((if azure { "locked" } else { "COMPLIANCE" }, until())),
        &[],
    )
}
fn successful_existing(azure: bool) -> Vec<Response> {
    vec![
        protected(azure),
        response(azure, 200, Some("v1"), None, BYTES),
        protected(azure),
        protected(azure),
        protected(azure),
    ]
}
fn evidence(backend: &ProtectedBackend) -> ProtectionEvidence {
    ProtectionEvidence {
        identity: backend.identity().clone(),
        required_until: until(),
        objects: BTreeMap::from([(
            PATH.into(),
            ObjectProof {
                version: "v1".into(),
                retain_until: until(),
                mode: "COMPLIANCE".into(),
                bytes: BYTES.len() as u64,
                blake3: blake3::hash(BYTES).to_hex().to_string(),
            },
        )]),
    }
}

#[test]
fn existing_compliance_and_locked_versions_are_verified_without_mutation() {
    for azure in [false, true] {
        let (backend, fixture) = build(&config(azure), successful_existing(azure));
        backend.create_verified(PATH, BYTES.to_vec()).unwrap();
        let proof = &backend.evidence().unwrap().objects[PATH];
        assert_eq!(proof.version, "v1");
        assert_eq!(proof.retain_until, until());
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 5);
        assert!(requests.iter().all(|r| r.method != Method::PUT));
        assert!(requests[1].url.query().unwrap().contains("v1"));
        assert!(requests
            .iter()
            .all(|r| !r.headers.contains_key("x-amz-bypass-governance-retention")));
        assert!(fixture.responses.lock().unwrap().is_empty());
    }
}
#[test]
fn new_objects_are_conditionally_created_with_retention_and_byte_checksum() {
    for azure in [false, true] {
        let mut responses = vec![
            response(azure, 404, None, None, &[]),
            response(azure, 201, Some("v1"), None, &[]),
        ];
        responses.extend(successful_existing(azure));
        let (backend, fixture) = build(&config(azure), responses);
        backend.create_verified(PATH, BYTES.to_vec()).unwrap();
        let requests = fixture.requests.lock().unwrap();
        let create = &requests[1];
        assert_eq!(create.method, Method::PUT);
        assert_eq!(create.headers["if-none-match"], "*");
        assert!(create.headers.contains_key("content-md5"));
        assert!(create.headers.contains_key(if azure {
            "x-ms-immutability-policy-until-date"
        } else {
            "x-amz-object-lock-retain-until-date"
        }));
        assert_eq!(create.body, BYTES);
        assert_eq!(backend.evidence().unwrap().objects.len(), 1);
    }
}
#[test]
fn retention_extension_is_version_bound_and_read_back_independently() {
    for azure in [false, true] {
        let mode = if azure { "locked" } else { "COMPLIANCE" };
        let responses = vec![
            protected(azure),
            response(azure, 200, Some("v1"), None, BYTES),
            response(
                azure,
                200,
                Some("v1"),
                Some((mode, now() + Duration::days(1))),
                &[],
            ),
            response(azure, 200, None, None, &[]),
            protected(azure),
            protected(azure),
        ];
        let (backend, fixture) = build(&config(azure), responses);
        backend.create_verified(PATH, BYTES.to_vec()).unwrap();
        let requests = fixture.requests.lock().unwrap();
        let extension = &requests[3];
        assert_eq!(extension.method, Method::PUT);
        assert_eq!(
            extension.url.query(),
            Some(if azure {
                "comp=immutabilityPolicies&versionid=v1"
            } else {
                "retention=&versionId=v1"
            })
        );
        assert!(!extension
            .headers
            .contains_key("x-amz-bypass-governance-retention"));
        if !azure {
            let body = std::str::from_utf8(&extension.body).unwrap();
            assert!(body.contains("<Mode>COMPLIANCE</Mode>"));
            assert!(body.contains("2026-11-28T12:00:00Z"));
        }
    }
}
#[test]
fn missing_retention_requires_actual_application_then_verification() {
    let responses = vec![
        protected(false),
        response(false, 200, Some("v1"), None, BYTES),
        response(false, 200, Some("v1"), None, &[]),
        response(false, 200, None, None, &[]),
        response(false, 200, Some("v1"), None, &[]),
    ];
    let (backend, fixture) = build(&config(false), responses);
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("missing after application"));
    assert_eq!(fixture.requests.lock().unwrap()[3].method, Method::PUT);
    assert!(backend.evidence().unwrap().objects.is_empty());
}
#[test]
fn governance_unlocked_incomplete_invalid_and_short_retention_are_refused() {
    for azure in [false, true] {
        let mode = if azure { "locked" } else { "COMPLIANCE" };
        let mode_header = if azure {
            "x-ms-immutability-policy-mode"
        } else {
            "x-amz-object-lock-mode"
        };
        let date_header = if azure {
            "x-ms-immutability-policy-until-date"
        } else {
            "x-amz-object-lock-retain-until-date"
        };
        let mut cases = vec![response(
            azure,
            200,
            Some("v1"),
            Some((if azure { "unlocked" } else { "GOVERNANCE" }, until())),
            &[],
        )];
        let mut incomplete = protected(azure);
        incomplete.headers.remove(date_header);
        cases.push(incomplete);
        let mut incomplete = protected(azure);
        incomplete.headers.remove(mode_header);
        cases.push(incomplete);
        let mut invalid = protected(azure);
        invalid.headers.insert(
            date_header,
            HeaderValue::from_static("invalid-date-secret-marker"),
        );
        cases.push(invalid);
        let mut duplicate = protected(azure);
        duplicate
            .headers
            .append(mode_header, HeaderValue::from_str(mode).unwrap());
        cases.push(duplicate);
        for bad in cases {
            let responses = vec![
                protected(azure),
                response(azure, 200, Some("v1"), None, BYTES),
                bad,
            ];
            let (backend, fixture) = build(&config(azure), responses);
            let error = backend
                .create_verified(PATH, BYTES.to_vec())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret-marker"));
            assert!(fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.method != Method::PUT));
        }
        let responses = vec![
            protected(azure),
            response(azure, 200, Some("v1"), None, BYTES),
            response(azure, 200, Some("v1"), None, &[]),
            response(azure, 200, None, None, &[]),
            response(
                azure,
                200,
                Some("v1"),
                Some((mode, now() + Duration::days(1))),
                &[],
            ),
        ];
        let (backend, _) = build(&config(azure), responses);
        assert!(backend
            .create_verified(PATH, BYTES.to_vec())
            .unwrap_err()
            .to_string()
            .contains("minimum"));
    }
}
#[test]
fn existing_ciphertext_mismatch_is_not_overwritten_or_locked() {
    let (backend, fixture) = build(
        &config(false),
        vec![
            protected(false),
            response(false, 200, Some("v1"), None, b"wrong"),
        ],
    );
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("ciphertext differs"));
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
}
#[test]
fn version_mismatch_missing_null_and_latest_replacement_are_refused() {
    for version in [None, Some("null")] {
        let (backend, _) = build(
            &config(false),
            vec![response(false, 200, version, None, &[])],
        );
        assert!(backend.create_verified(PATH, BYTES.to_vec()).is_err());
    }
    let mut responses = successful_existing(false);
    responses[1] = response(false, 200, Some("v2"), None, BYTES);
    let (backend, _) = build(&config(false), responses);
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("different object version"));
    let mut responses = successful_existing(false);
    responses[4] = response(false, 200, Some("v2"), None, &[]);
    let (backend, _) = build(&config(false), responses);
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("latest pointer changed"));
    assert!(backend.evidence().unwrap().objects.is_empty());
}
#[test]
fn invalid_stale_or_missing_server_clock_prevents_protection_claim() {
    for date in [
        None,
        Some("Fri, 30 Oct 2026 12:00:00 GMT"),
        Some("not-a-date"),
    ] {
        let mut first = protected(false);
        first.headers.remove("date");
        if let Some(date) = date {
            first
                .headers
                .insert("date", HeaderValue::from_str(date).unwrap());
        }
        let (backend, _) = build(&config(false), vec![first]);
        assert!(backend.create_verified(PATH, BYTES.to_vec()).is_err());
    }
}
#[test]
fn retry_is_bounded_and_permission_failure_is_not_retried_or_echoed() {
    let (backend, fixture) = build(
        &config(false),
        vec![
            response(false, 503, None, None, b"sensitive-provider-body"),
            response(false, 503, None, None, &[]),
            response(false, 503, None, None, &[]),
        ],
    );
    let error = backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("sensitive"));
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    let (backend, fixture) = build(
        &config(false),
        vec![response(false, 403, None, None, b"sensitive-provider-body")],
    );
    assert!(backend.create_verified(PATH, BYTES.to_vec()).is_err());
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    let (backend, fixture) = build(&config(false), vec![]);
    *fixture.responses.lock().unwrap() = VecDeque::from([
        Err(TransportError),
        Err(TransportError),
        Err(TransportError),
    ]);
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("bounded retries"));
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
}
#[test]
fn conditional_create_race_requires_existing_version_verification() {
    let mut responses = vec![
        response(false, 404, None, None, &[]),
        response(false, 412, None, None, &[]),
    ];
    responses.extend(successful_existing(false));
    let (backend, _) = build(&config(false), responses);
    backend.create_verified(PATH, BYTES.to_vec()).unwrap();
}
#[test]
fn oversized_response_and_unsafe_object_paths_fail_closed() {
    let (backend, fixture) = build(&config(false), vec![]);
    for path in ["../bad", "a/../b", "a//b", "/a", "a?secret", "a#secret"] {
        assert!(backend.create_verified(path, BYTES.to_vec()).is_err());
    }
    assert!(fixture.requests.lock().unwrap().is_empty());
    let (backend, _) = build(
        &config(false),
        vec![
            protected(false),
            response(false, 200, Some("v1"), None, &vec![0; BYTES.len() + 1]),
        ],
    );
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("safety limit"));
}
#[test]
fn config_rejects_ambient_credentials_r2_sas_and_non_https_endpoints() {
    let empty = Arc::new(Fixture::default());
    let check = |c: &StorageConfig| {
        ProtectedBackend::with_transport(
            c,
            until(),
            empty.clone(),
            Arc::new(Fixed(now())),
            credential,
        )
        .is_err()
    };
    let mut c = config(false);
    c.credential_env.clear();
    assert!(check(&c));
    let mut c = config(false);
    c.service = "r2".into();
    assert!(check(&c));
    for endpoint in [
        "http://example.com",
        "https://secret@example.com",
        "https://example.com?secret=1",
        "https://example.com/prefix",
        "https://example.com/#secret",
        "https://account.r2.cloudflarestorage.com",
    ] {
        let mut c = config(false);
        c.options.insert("endpoint".into(), endpoint.into());
        assert!(check(&c));
    }
    let mut c = config(true);
    c.credential_env
        .insert("sas_token".into(), "FIXTURE_SAS".into());
    assert!(check(&c));
    let mut c = config(false);
    c.immutable = false;
    assert!(check(&c));
    assert!(empty.requests.lock().unwrap().is_empty());
}
#[test]
fn dr_rejects_prefix_aliases_and_same_identity_even_with_renamed_env_refs() {
    let (primary, _) = build(&config(false), vec![]);
    let mut dr = config(false);
    dr.options.insert("root".into(), "different-prefix".into());
    let (same_bucket, _) = build(&dr, vec![]);
    assert!(primary.ensure_independent(&same_bucket).is_err());
    dr.options
        .insert("bucket".into(), "different-bucket".into());
    let (same_identity, _) = build(&dr, vec![]);
    assert!(primary.ensure_independent(&same_identity).is_err());
    dr.credential_env
        .insert("access_key_id".into(), "OTHER_ID".into());
    let (independent, _) = build(&dr, vec![]);
    primary.ensure_independent(&independent).unwrap();
    let mut alias = config(false);
    alias
        .options
        .insert("endpoint".into(), "https://s3.amazonaws.com".into());
    let (alias, _) = build(&alias, vec![]);
    assert!(primary.ensure_independent(&alias).is_err());
}
#[test]
fn saved_evidence_binds_backend_location_and_has_strict_limits() {
    let (writer, _) = build(&config(false), vec![]);
    let good = evidence(&writer);
    assert!(writer.load_evidence(&good).is_err());
    let backend = ProtectedBackend::for_recovery_with_transport(
        &config(false),
        &good,
        Arc::new(Fixture::default()),
        Arc::new(Fixed(now())),
        credential,
    )
    .unwrap();
    let mut bad = good.clone();
    bad.identity.backend = "s3:other".into();
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    bad.identity.location = "other-root".into();
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    bad.objects.get_mut(PATH).unwrap().version = "null".into();
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    bad.objects.get_mut(PATH).unwrap().bytes = 65 * 1024 * 1024;
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    bad.objects.get_mut(PATH).unwrap().blake3 = "g".repeat(64);
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    bad.objects.get_mut(PATH).unwrap().mode = "GOVERNANCE".into();
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    bad.objects.get_mut(PATH).unwrap().retain_until = now();
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    let proof = bad.objects.remove(PATH).unwrap();
    bad.objects.insert("../escape".into(), proof);
    assert!(backend.load_evidence(&bad).is_err());
    let mut bad = good.clone();
    let proof = bad.objects[PATH].clone();
    bad.objects = (0..100_001)
        .map(|n| (format!("repo/chunks/{n}"), proof.clone()))
        .collect();
    assert!(backend.load_evidence(&bad).is_err());
}
#[test]
fn recovery_uses_exact_saved_versions_after_retention_expiry_without_a_protection_claim() {
    let (original, _) = build(&config(false), vec![]);
    let saved = evidence(&original);
    let expired = until() + Duration::days(1);
    let mut read = response(false, 200, Some("v1"), None, BYTES);
    read.headers.insert(
        "date",
        HeaderValue::from_str(&httpdate::fmt_http_date(expired.into())).unwrap(),
    );
    let fixture = Arc::new(Fixture {
        responses: Mutex::new(VecDeque::from([Ok(read)])),
        ..Fixture::default()
    });
    let recovery = ProtectedBackend::for_recovery_with_transport(
        &config(false),
        &saved,
        fixture.clone(),
        Arc::new(Fixed(expired)),
        credential,
    )
    .unwrap();
    assert_eq!(recovery.read_bounded(PATH, 1024).unwrap(), BYTES);
    assert!(recovery.create_verified(PATH, BYTES.to_vec()).is_err());
    assert!(recovery.evidence().is_err());
    assert!(recovery.read_bounded("repo/chunks/missing", 1024).is_err());
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].url.query(), Some("versionId=v1"));
}
#[test]
fn recovery_rejects_replaced_ciphertext_and_encodes_opaque_version_ids() {
    let (original, _) = build(&config(false), vec![]);
    let mut saved = evidence(&original);
    saved.objects.get_mut(PATH).unwrap().version = "v1+/= space".into();
    let fixture = Arc::new(Fixture {
        responses: Mutex::new(VecDeque::from([Ok(response(
            false,
            200,
            Some("v1+/= space"),
            None,
            b"altered",
        ))])),
        ..Fixture::default()
    });
    let recovery = ProtectedBackend::for_recovery_with_transport(
        &config(false),
        &saved,
        fixture.clone(),
        Arc::new(Fixed(now())),
        credential,
    )
    .unwrap();
    assert!(recovery
        .read_bounded(PATH, 1024)
        .unwrap_err()
        .to_string()
        .contains("evidence mismatch"));
    assert_eq!(
        fixture.requests.lock().unwrap()[0].url.query(),
        Some("versionId=v1%2B%2F%3D%20space")
    );
}

#[derive(Default)]
struct ProviderFixture {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    published: Mutex<Vec<String>>,
    fail_chunks: bool,
    invalid_chunk_retention: bool,
}
impl Transport for ProviderFixture {
    fn send(&self, request: Request) -> std::result::Result<Response, TransportError> {
        let path = request.url.path().to_owned();
        let mut objects = self.objects.lock().unwrap();
        match request.method {
            Method::PUT => {
                assert_eq!(request.headers["if-none-match"], "*");
                assert_eq!(request.headers["x-amz-object-lock-mode"], "COMPLIANCE");
                assert!(request.headers.contains_key("content-md5"));
                if self.fail_chunks && path.contains("/chunks/") {
                    return Ok(response(false, 403, None, None, &[]));
                }
                if objects.contains_key(&path) {
                    return Ok(response(false, 412, None, None, &[]));
                }
                objects.insert(path.clone(), request.body);
                self.published.lock().unwrap().push(path);
                Ok(response(false, 200, Some("v1"), None, &[]))
            }
            Method::HEAD => Ok(if objects.contains_key(&path) {
                if self.invalid_chunk_retention && path.contains("/chunks/") {
                    response(false, 200, Some("v1"), Some(("GOVERNANCE", until())), &[])
                } else {
                    protected(false)
                }
            } else {
                response(false, 404, None, None, &[])
            }),
            Method::GET => {
                assert_eq!(request.url.query(), Some("versionId=v1"));
                Ok(match objects.get(&path) {
                    Some(bytes) => response(false, 200, Some("v1"), None, bytes),
                    None => response(false, 404, None, None, &[]),
                })
            }
            _ => panic!("unexpected provider operation"),
        }
    }
}
fn provider_backend(config: &StorageConfig, fixture: Arc<ProviderFixture>) -> ProtectedBackend {
    ProtectedBackend::with_transport(config, until(), fixture, Arc::new(Fixed(now())), credential)
        .unwrap()
}
fn dr_config() -> StorageConfig {
    let mut c = config(false);
    c.options.insert("bucket".into(), "drbackup".into());
    c.credential_env
        .insert("access_key_id".into(), "OTHER_ID".into());
    c
}
#[test]
fn dr_failure_never_publishes_a_final_checkpoint_or_advances_local_inventory() {
    for invalid_retention in [false, true] {
        let lab = tempfile::tempdir().unwrap();
        let work = lab.path().join("work");
        std::fs::create_dir(&work).unwrap();
        std::fs::write(work.join("fixture"), "fixture").unwrap();
        let repo = bunker::repository::Repository::init(
            &lab.path().join("repo"),
            "fixture-test-passphrase",
        )
        .unwrap();
        repo.snapshot(
            &work,
            &bunker::policy::Policy::default(),
            None,
            None,
            "manual",
        )
        .unwrap();
        let a = Arc::new(ProviderFixture::default());
        let b = Arc::new(ProviderFixture {
            fail_chunks: !invalid_retention,
            invalid_chunk_retention: invalid_retention,
            ..ProviderFixture::default()
        });
        let primary = provider_backend(&config(false), a.clone());
        let secondary = provider_backend(&dr_config(), b.clone());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(runtime
            .block_on(bunker::protected_replication::replicate(
                &repo,
                &primary,
                Some(&secondary),
                None
            ))
            .is_err());
        assert!(!repo.root().join("checkpoints/latest").exists());
        for fixture in [&a, &b] {
            assert!(fixture
                .published
                .lock()
                .unwrap()
                .iter()
                .all(|p| !p.contains("/checkpoints/")));
        }
    }
}
#[test]
fn paired_success_has_identical_ciphertext_inventory_and_independent_version_locators() {
    let lab = tempfile::tempdir().unwrap();
    let work = lab.path().join("work");
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("fixture"), "fixture").unwrap();
    let repo =
        bunker::repository::Repository::init(&lab.path().join("repo"), "fixture-test-passphrase")
            .unwrap();
    repo.snapshot(
        &work,
        &bunker::policy::Policy::default(),
        None,
        None,
        "manual",
    )
    .unwrap();
    let a = Arc::new(ProviderFixture::default());
    let b = Arc::new(ProviderFixture::default());
    let primary = provider_backend(&config(false), a.clone());
    let secondary = provider_backend(&dr_config(), b.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let report = runtime
        .block_on(bunker::protected_replication::replicate(
            &repo,
            &primary,
            Some(&secondary),
            None,
        ))
        .unwrap();
    report.validate().unwrap();
    let checkpoint = report.namespace.rsplit(':').next().unwrap();
    let saved =
        bunker::protected_replication::ProtectedReport::load_local(&repo, checkpoint).unwrap();
    assert_eq!(
        serde_json::to_value(&saved).unwrap(),
        serde_json::to_value(&report).unwrap()
    );
    let report_file = repo.root().join("checkpoints/reports").join(checkpoint);
    let encrypted = std::fs::read(&report_file).unwrap();
    assert!(!encrypted
        .windows(report.namespace.len())
        .any(|w| w == report.namespace.as_bytes()));
    let mut corrupt = encrypted.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&report_file, corrupt).unwrap();
    assert!(bunker::protected_replication::ProtectedReport::load_local(&repo, checkpoint).is_err());
    std::fs::write(&report_file, encrypted).unwrap();
    assert_eq!(report.backends.len(), 2);
    let (first, second) = (&report.backends[0], &report.backends[1]);
    assert_ne!(first.identity.backend, second.identity.backend);
    assert_eq!(first.objects, second.objects);
    assert_eq!(first.objects.len(), report.objects_per_backend);
    for fixture in [&a, &b] {
        let published = fixture.published.lock().unwrap();
        assert!(published.last().unwrap().contains("/checkpoints/"));
        assert!(published[..published.len() - 1]
            .iter()
            .all(|p| !p.contains("/checkpoints/")));
    }
    let recovery = ProtectedBackend::for_recovery_with_transport(
        &dr_config(),
        second,
        b,
        Arc::new(Fixed(now())),
        credential,
    )
    .unwrap();
    let recovered = lab.path().join("recovered");
    runtime
        .block_on(bunker::checkpoint::recover(
            &recovery,
            &report.namespace,
            &recovered,
            &bunker::repository::KeySource::passphrase("fixture-test-passphrase"),
            None,
        ))
        .unwrap();
    let root = repo.root().to_path_buf();
    drop(repo);
    for (output, succeeds) in [
        (root.join("report.json"), false),
        (lab.path().join("external-report.json"), true),
    ] {
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_bunker"))
            .arg("--repo")
            .arg(&root)
            .args(["protection-report", checkpoint, "--output"])
            .arg(&output)
            .env("BUNKER_PASSPHRASE", "fixture-test-passphrase")
            .output()
            .unwrap();
        assert_eq!(status.status.success(), succeeds);
        assert_eq!(output.exists(), succeeds);
    }
}

#[test]
fn provider_clock_cannot_prove_retention_that_has_already_expired_server_side() {
    let deadline = now() + Duration::seconds(10);
    let mut responses = successful_existing(false);
    for response in &mut responses {
        response.headers.insert(
            "date",
            HeaderValue::from_str(&httpdate::fmt_http_date(
                (now() + Duration::seconds(60)).into(),
            ))
            .unwrap(),
        );
        if response
            .headers
            .contains_key("x-amz-object-lock-retain-until-date")
        {
            response.headers.insert(
                "x-amz-object-lock-retain-until-date",
                HeaderValue::from_str(&deadline.to_rfc3339()).unwrap(),
            );
        }
    }
    let fixture = Arc::new(Fixture {
        responses: Mutex::new(responses.into_iter().map(Ok).collect()),
        ..Fixture::default()
    });
    let backend = ProtectedBackend::with_transport(
        &config(false),
        deadline,
        fixture,
        Arc::new(Fixed(now())),
        credential,
    )
    .unwrap();
    assert!(backend
        .create_verified(PATH, BYTES.to_vec())
        .unwrap_err()
        .to_string()
        .contains("minimum"));
    assert!(backend.evidence().unwrap().objects.is_empty());
}

#[test]
fn blocked_local_evidence_prevents_checkpoint_advance() {
    let lab = tempfile::tempdir().unwrap();
    let work = lab.path().join("work");
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("file"), "fixture").unwrap();
    let repo =
        bunker::repository::Repository::init(&lab.path().join("repo"), "fixture-test-passphrase")
            .unwrap();
    repo.snapshot(
        &work,
        &bunker::policy::Policy::default(),
        None,
        None,
        "manual",
    )
    .unwrap();
    std::fs::create_dir(repo.root().join("checkpoints")).unwrap();
    std::fs::write(
        repo.root().join("checkpoints/reports"),
        b"blocked evidence directory",
    )
    .unwrap();
    let provider = Arc::new(ProviderFixture::default());
    let backend = provider_backend(&config(false), provider.clone());
    assert!(tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(bunker::protected_replication::replicate(
            &repo, &backend, None, None
        ))
        .is_err());
    assert!(provider
        .published
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .contains("/checkpoints/"));
    assert!(!repo.root().join("checkpoints/latest").exists());
}
