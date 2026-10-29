//! Disposable local fixture servers and repositories only. No real identity/configuration.
use anyhow::Result;
use bunker::{control_plane, host_service, policy, repository};
use chrono::{SecondsFormat, Utc};
use control_plane::*;
use host_service::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod, SslVerifyMode},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509Req, X509,
    },
};
use repository::Repository;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
};
use uuid::Uuid;
use zeroize::Zeroizing;

fn identity() -> HostIdentity {
    HostIdentity::new(Uuid::from_u128(1), Uuid::from_u128(2)).unwrap()
}
fn private_dir(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir.canonicalize().unwrap()
}
fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}
fn ca() -> (PKey<Private>, X509) {
    let key = key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Disposable Test CA")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::from_unix(Utc::now().timestamp() - 30).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (key, cert.build())
}
fn leaf(
    ca_key: &PKey<Private>,
    ca: &X509,
    public: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    server: bool,
    san: &str,
    seconds: i64,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Disposable leaf").unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(
        &BigNum::from_u32(if server { 2 } else { 3 })
            .unwrap()
            .to_asn1_integer()
            .unwrap(),
    )
    .unwrap();
    cert.set_subject_name(&name.build()).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(public).unwrap();
    cert.set_not_before(&Asn1Time::from_unix(Utc::now().timestamp() - 30).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::from_unix(Utc::now().timestamp() + seconds).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    let mut eku = ExtendedKeyUsage::new();
    if server {
        eku.server_auth();
    } else {
        eku.client_auth();
    }
    cert.append_extension(eku.build().unwrap()).unwrap();
    let mut names = SubjectAlternativeName::new();
    if server {
        names.ip("127.0.0.1");
    } else {
        names.uri(san);
    }
    let ext = names.build(&cert.x509v3_context(Some(ca), None)).unwrap();
    cert.append_extension(ext).unwrap();
    cert.sign(ca_key, MessageDigest::sha256()).unwrap();
    cert.build()
}
#[derive(Clone, Copy)]
enum Issue {
    Good,
    WrongKey,
    WrongSan,
    WrongTenant,
    Expired,
    TooLong,
    Short,
}
fn issue(csr: &str, ca_key: &PKey<Private>, ca: &X509, mode: Issue) -> Value {
    let request = X509Req::from_pem(csr.as_bytes()).unwrap();
    let public = request.public_key().unwrap();
    assert!(request.verify(&public).unwrap());
    assert_eq!(
        public.ec_key().unwrap().group().curve_name(),
        Some(Nid::X9_62_PRIME256V1)
    );
    let wrong = key();
    let wrong = PKey::public_key_from_pem(&wrong.public_key_to_pem().unwrap()).unwrap();
    let host = identity();
    let san = if matches!(mode, Issue::WrongSan) {
        "urn:bunker:tenant:wrong:host:wrong".into()
    } else {
        format!("urn:bunker:tenant:{}:host:{}", host.tenant, host.host)
    };
    let seconds = match mode {
        Issue::Expired => -1,
        Issue::TooLong => 100000,
        Issue::Short => 1800,
        _ => 86400,
    };
    let cert = leaf(
        ca_key,
        ca,
        if matches!(mode, Issue::WrongKey) {
            &wrong
        } else {
            &public
        },
        false,
        &san,
        seconds,
    );
    json!({"hostId":host.host,"tenantId":if matches!(mode,Issue::WrongTenant){Uuid::from_u128(4)}else{host.tenant},
        "transport":"mtls","certificate":String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        "trustChain":String::from_utf8(ca.to_pem().unwrap()).unwrap(),
        "expiresAt":(Utc::now()+chrono::Duration::seconds(seconds)).to_rfc3339_opts(SecondsFormat::Secs,true)})
}
#[derive(Clone)]
struct WireRequest {
    line: String,
    headers: String,
    body: Value,
    client_cert: bool,
}
fn read_http(stream: &mut impl Read, client_cert: bool) -> WireRequest {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 20000);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let length = headers
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|s| s.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    WireRequest {
        line: headers.lines().next().unwrap().into(),
        headers,
        body: if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        },
        client_cert,
    }
}
struct FixtureServer {
    origin: String,
    trust: ServerTrust,
    handle: thread::JoinHandle<()>,
}
impl FixtureServer {
    fn spawn(
        ca_key: &PKey<Private>,
        ca: &X509,
        mtls: bool,
        count: usize,
        handler: impl Fn(WireRequest) -> (u16, Value) + Send + 'static,
    ) -> Self {
        let key = key();
        let public = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();
        let cert = leaf(ca_key, ca, &public, true, "", 86400);
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_session_id_context(b"bunker-disposable-fixture")
            .unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        if mtls {
            acceptor.cert_store_mut().add_cert(ca.clone()).unwrap();
            acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        let acceptor = acceptor.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for _ in 0..count {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(8)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(8)))
                    .unwrap();
                let Ok(mut tls) = acceptor.accept(stream) else {
                    continue;
                };
                let has_client = tls.ssl().peer_certificate().is_some();
                let request = read_http(&mut tls, has_client);
                let (status, body) = handler(request);
                if status == 0 {
                    continue;
                } // Simulate accepted mutation with lost response.
                let body = serde_json::to_vec(&body).unwrap();
                write!(tls,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
                tls.write_all(&body).unwrap();
                tls.flush().unwrap();
            }
        });
        Self {
            origin,
            trust: ServerTrust::CaBundle(ca.to_pem().unwrap()),
            handle,
        }
    }
    fn finish(self) {
        self.handle.join().unwrap();
    }
}
fn enrollment(
    root: &Path,
    ca_key: &PKey<Private>,
    ca: &X509,
    mode: Issue,
) -> Result<(Credentials, CredentialStore)> {
    let ck = ca_key.clone();
    let cc = ca.clone();
    let server = FixtureServer::spawn(ca_key, ca, false, 1, move |r| {
        assert_eq!(r.line, "POST /api/enroll HTTP/1.1");
        assert!(!r.client_cert);
        assert!(!r.headers.to_ascii_lowercase().contains("authorization:"));
        assert_eq!(r.body["token"], "disposable-token-never-production-123456");
        assert_eq!(r.body.as_object().unwrap().len(), 2);
        (201, issue(r.body["csr"].as_str().unwrap(), &ck, &cc, mode))
    });
    let token = root.join("token");
    fs::write(&token, "disposable-token-never-production-123456\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let dir = private_dir(root, "credentials");
    let store = CredentialStore::open(&dir)?;
    let result = enroll(
        HttpsOrigin::parse(&server.origin)?,
        &server.trust,
        identity().tenant,
        &EnrollmentTokenSource::File(token),
        &store,
    );
    server.finish();
    result.map(|c| (c, store))
}
#[test]
fn real_p256_enrollment_mtls_renewal_and_revocation_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let (ca_key, ca) = ca();
    let (credentials, store) = enrollment(temp.path(), &ca_key, &ca, Issue::Short).unwrap();
    assert!(credentials.renewal_due(Utc::now()));
    assert_eq!(store.load().unwrap().host_id, identity().host);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(temp.path().join("credentials/identity.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let ck = ca_key.clone();
    let cc = ca.clone();
    let calls = Arc::new(Mutex::new(0));
    let counter = calls.clone();
    let server = FixtureServer::spawn(&ca_key, &ca, true, 3, move |r| {
        assert!(r.client_cert);
        let headers = r.headers.to_ascii_lowercase();
        for forbidden in ["authorization:", "cookie:", "gateway"] {
            assert!(!headers.contains(forbidden));
        }
        let mut count = counter.lock().unwrap();
        *count += 1;
        if r.line.contains("/certificate ") {
            (
                201,
                issue(r.body["csr"].as_str().unwrap(), &ck, &cc, Issue::Good),
            )
        } else if *count == 1 {
            (200, json!([]))
        } else {
            (401, json!({"error":"revoked"}))
        }
    });
    let origin = HttpsOrigin::parse(&server.origin).unwrap();
    let mut transport = MtlsTransport::new(origin.clone(), &server.trust, &credentials).unwrap();
    assert!(transport
        .request(
            Method::Get,
            "/tenants/00000000-0000-0000-0000-000000000001/policies",
            None
        )
        .is_ok());
    let next = renew(&mut transport, &credentials, &store).unwrap();
    assert!(!next.renewal_due(Utc::now()));
    let mut rotated = MtlsTransport::new(origin, &server.trust, &next).unwrap();
    assert_eq!(
        rotated.request(
            Method::Get,
            "/tenants/00000000-0000-0000-0000-000000000001/policies",
            None
        ),
        Err(TransportError::Http(401))
    );
    assert_eq!(
        rotated.request(
            Method::Get,
            "/tenants/00000000-0000-0000-0000-000000000001/policies",
            None
        ),
        Err(TransportError::Http(401))
    );
    assert_eq!(*calls.lock().unwrap(), 3);
    server.finish();
    assert!(!credentials.require_valid(credentials.expires_at).is_ok());
}
#[test]
fn enrollment_rejects_wrong_key_san_tenant_expiry_and_lifetime_without_persistence() {
    let (ca_key, ca) = ca();
    for mode in [
        Issue::WrongKey,
        Issue::WrongSan,
        Issue::WrongTenant,
        Issue::Expired,
        Issue::TooLong,
    ] {
        let temp = tempfile::tempdir().unwrap();
        assert!(enrollment(temp.path(), &ca_key, &ca, mode).is_err());
        assert!(!temp.path().join("credentials/identity.json").exists());
    }
}
#[test]
fn explicit_server_ca_is_separate_from_enrolled_client_chain() {
    let temp = tempfile::tempdir().unwrap();
    let (ca_key, ca) = ca();
    let (credentials, _) = enrollment(temp.path(), &ca_key, &ca, Issue::Good).unwrap();
    // The client identity's CA is NOT added to server trust implicitly.
    let server = FixtureServer::spawn(&ca_key, &ca, true, 1, |_| {
        panic!("untrusted TLS must not reach HTTP")
    });
    let mut transport = MtlsTransport::new(
        HttpsOrigin::parse(&server.origin).unwrap(),
        &ServerTrust::Native,
        &credentials,
    )
    .unwrap();
    assert_eq!(
        transport.request(Method::Get, "/policies", None),
        Err(TransportError::Ambiguous)
    );
    server.finish();
    let (wrong_key, wrong_ca) = self::ca();
    let server = FixtureServer::spawn(&ca_key, &ca, true, 1, |_| {
        panic!("wrong server CA must not reach HTTP")
    });
    let mut transport = MtlsTransport::new(
        HttpsOrigin::parse(&server.origin).unwrap(),
        &ServerTrust::CaBundle(wrong_ca.to_pem().unwrap()),
        &credentials,
    )
    .unwrap();
    assert!(transport.request(Method::Get, "/policies", None).is_err());
    server.finish();
    drop(wrong_key);
}
#[test]
fn no_redirects_bearer_escape_or_public_token_files() {
    assert!(HttpsOrigin::parse("http://127.0.0.1").is_err());
    assert!(HttpsOrigin::parse("https://user:password@example.test").is_err());
    for origin in [
        "http://localhost:1",
        "http://192.0.2.1",
        "https://127.0.0.1",
        "http://127.0.0.1/path",
    ] {
        assert!(
            LoopbackDevelopmentTransport::new(origin, Zeroizing::new("fixture".into()), true)
                .is_err()
        );
    }
    assert!(LoopbackDevelopmentTransport::new(
        "http://127.0.0.1",
        Zeroizing::new("fixture".into()),
        false
    )
    .is_err());
    assert!(LoopbackDevelopmentTransport::new(
        "http://[::1]",
        Zeroizing::new("fixture".into()),
        true
    )
    .is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("token");
        fs::write(&file, "fixture").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let store = CredentialStore::open(&private_dir(temp.path(), "credentials")).unwrap();
        let error = enroll(
            HttpsOrigin::parse("https://127.0.0.1:1").unwrap(),
            &ServerTrust::Native,
            identity().tenant,
            &EnrollmentTokenSource::File(file.clone()),
            &store,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("owner-only"));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let linked = temp.path().join("link");
        symlink(&file, &linked).unwrap();
        assert!(enroll(
            HttpsOrigin::parse("https://127.0.0.1:1").unwrap(),
            &ServerTrust::Native,
            identity().tenant,
            &EnrollmentTokenSource::File(linked),
            &store
        )
        .is_err());
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let req = read_http(&mut stream, false);
        assert!(req
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture"));
        write!(stream,"HTTP/1.1 307 Redirect\r\nLocation: http://192.0.2.1/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    let mut transport =
        LoopbackDevelopmentTransport::new(&origin, Zeroizing::new("fixture".into()), true).unwrap();
    assert_eq!(
        transport.request(Method::Post, "/restores", Some(&json!({}))),
        Err(TransportError::Http(307))
    );
    handle.join().unwrap();
}

#[derive(Default)]
struct RemoteState {
    calls: Vec<(String, Value)>,
    restore: Option<Value>,
    claim: Option<Value>,
    status: String,
    create_ambiguous: bool,
    claim_ambiguous: bool,
    completion_ambiguous: bool,
    completion_bad_ack: bool,
    bad_claim: bool,
    expire: bool,
    wrong_tenant: bool,
    mutate_on_claim: Option<PathBuf>,
    policy: Option<Value>,
}
#[derive(Clone)]
struct FakeTransport(Arc<Mutex<RemoteState>>);
impl FakeTransport {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(RemoteState {
            status: "approved".into(),
            ..Default::default()
        })))
    }
}
impl Transport for FakeTransport {
    fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> std::result::Result<Value, TransportError> {
        let mut s = self.0.lock().unwrap();
        s.calls
            .push((path.into(), body.cloned().unwrap_or(Value::Null)));
        if path.ends_with("/policies") {
            return Ok(s.policy.clone().unwrap_or(json!([])));
        }
        if path.ends_with("/snapshots") || path.ends_with("/evidence") {
            return Ok(json!({"id":body.unwrap()["id"]}));
        }
        if path.ends_with("/alerts") {
            return Ok(json!({"id":Uuid::from_u128(6)}));
        }
        if path.ends_with("/restores") && matches!(method, Method::Post) {
            s.restore = body.cloned();
            if s.create_ambiguous {
                return Err(TransportError::Ambiguous);
            }
            return Ok(json!({"id":Uuid::from_u128(7),"status":"pending"}));
        }
        if path.ends_with("/claim") {
            assert_eq!(
                body.unwrap()["diffDigest"],
                s.restore.as_ref().unwrap()["diffDigest"]
            );
            if let Some(path) = &s.mutate_on_claim {
                fs::write(path, "changed during claim").unwrap();
            }
            s.claim = body.cloned();
            if s.claim_ambiguous {
                return Err(TransportError::Ambiguous);
            }
            let b = s.restore.as_ref().unwrap();
            return Ok(
                json!({"id":Uuid::from_u128(7),"status":"executing","diffDigest":if s.bad_claim {json!("0".repeat(64))}else{b["diffDigest"].clone()},"manifestDigest":b["manifestDigest"],"expiresAt":Utc::now()+chrono::Duration::minutes(10)}),
            );
        }
        if path.ends_with("/complete") {
            if s.completion_ambiguous {
                return Err(TransportError::Ambiguous);
            }
            if s.completion_bad_ack {
                return Ok(json!({"id":Uuid::from_u128(99),"status":"succeeded"}));
            }
            return Ok(json!({"id":Uuid::from_u128(7),"status":body.unwrap()["status"]}));
        }
        if matches!(method, Method::Get) {
            let expiry = Utc::now() + chrono::Duration::seconds(if s.expire { -1 } else { 600 });
            return Ok(
                json!([{"id":Uuid::from_u128(7),"tenant_id":if s.wrong_tenant{Uuid::from_u128(8)}else{identity().tenant},"host_id":identity().host,"status":s.status,"body":s.restore,"expires_at":expiry}]),
            );
        }
        panic!("unexpected fixture request");
    }
}
struct RestoreFixture {
    _temp: tempfile::TempDir,
    repo: Repository,
    work: PathBuf,
    snapshot: String,
    consumed: ConsumedRequests,
}
impl RestoreFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = Repository::init(&root.join("repo"), "fixture-only-passphrase").unwrap();
        let work = root.join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("private-name.txt"), "original private content").unwrap();
        let snapshot = repo
            .snapshot(
                &work,
                &policy::Policy::default(),
                Some("codex".into()),
                Some("private-session".into()),
                "manual",
            )
            .unwrap()
            .id;
        fs::write(work.join("private-name.txt"), "changed private content").unwrap();
        let consumed = ConsumedRequests::open(&private_dir(&root, "consumed")).unwrap();
        Self {
            _temp: temp,
            repo,
            work,
            snapshot,
            consumed,
        }
    }
    fn request(&self, client: &mut HostClient<FakeTransport>) -> RequestedRestore {
        client
            .request_restore(
                &self.repo,
                &self.consumed,
                &self.snapshot,
                &self.work,
                Some("private-name.txt"),
            )
            .unwrap()
    }
    fn content(&self) -> String {
        fs::read_to_string(self.work.join("private-name.txt")).unwrap()
    }
}
#[test]
fn metadata_only_encrypted_plan_one_shot_claim_completion_and_restart_replay() {
    let f = RestoreFixture::new();
    let transport = FakeTransport::new();
    let state = transport.0.clone();
    let mut client = HostClient::new(transport, identity());
    let request = f.request(&mut client);
    let wire = serde_json::to_string(&state.lock().unwrap().calls).unwrap();
    for secret in [
        "private-name",
        "private-session",
        "private content",
        f.work.to_str().unwrap(),
        "preview",
        "confirmation",
    ] {
        assert!(!wire.contains(secret));
    }
    let local = f.repo.request(&request.local_request_id).unwrap();
    assert_eq!(
        local["server_request"],
        request.server_request_id.to_string()
    );
    assert!(local["frozen"]["plan"]["changes"][0]["preview"]
        .as_str()
        .unwrap()
        .contains("private content"));
    let frozen_preview = client
        .local_restore_preview(&f.repo, &request.local_request_id)
        .unwrap();
    fs::write(f.work.join("private-name.txt"), "newer unreviewed content").unwrap();
    assert_eq!(
        client
            .local_restore_preview(&f.repo, &request.local_request_id)
            .unwrap()
            .confirmation,
        frozen_preview.confirmation
    );
    assert_ne!(
        f.repo
            .plan(&f.snapshot, &f.work, Some("private-name.txt"))
            .unwrap()
            .confirmation,
        frozen_preview.confirmation
    );
    fs::write(f.work.join("private-name.txt"), "changed private content").unwrap();
    let encrypted = fs::read(
        f.repo
            .root()
            .join("requests")
            .join(&request.local_request_id),
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains("private content"));
    assert!(state.lock().unwrap().claim.is_none());
    assert_eq!(f.content(), "changed private content");
    client
        .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
        .unwrap();
    assert_eq!(f.content(), "original private content");
    let before = state.lock().unwrap().calls.len();
    let reopened = ConsumedRequests::open(f.consumed.path()).unwrap();
    // Put the destination back to its original before-state; replay still cannot claim or write.
    fs::write(f.work.join("private-name.txt"), "changed private content").unwrap();
    assert!(client
        .execute_restore_once(&f.repo, &reopened, &request.local_request_id)
        .is_err());
    assert_eq!(state.lock().unwrap().calls.len(), before);
    assert_eq!(f.content(), "changed private content");
    assert!(state
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|(path, body)| path.ends_with("/complete") && body["status"] == "succeeded"));
}
#[test]
fn stale_destination_manifest_and_replaced_directory_never_claim() {
    for mode in 0..3 {
        let f = RestoreFixture::new();
        let transport = FakeTransport::new();
        let state = transport.0.clone();
        let mut client = HostClient::new(transport, identity());
        let request = f.request(&mut client);
        match mode {
            0 => fs::write(f.work.join("private-name.txt"), "newer work").unwrap(),
            1 => {
                let file = f.repo.root().join("snapshots").join(&f.snapshot);
                let mut bytes = fs::read(&file).unwrap();
                bytes[0] ^= 1;
                fs::write(file, bytes).unwrap();
            }
            _ => {
                fs::rename(&f.work, f.work.with_extension("old")).unwrap();
                fs::create_dir(&f.work).unwrap();
                fs::write(f.work.join("private-name.txt"), "changed private content").unwrap();
            }
        }
        assert!(client
            .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
            .is_err());
        assert!(state.lock().unwrap().claim.is_none());
    }
}
#[test]
fn denied_expired_cross_tenant_bad_claim_and_ambiguous_claim_never_write_or_retry() {
    for mode in 0..6 {
        let f = RestoreFixture::new();
        let transport = FakeTransport::new();
        let state = transport.0.clone();
        let mut client = HostClient::new(transport, identity());
        let request = f.request(&mut client);
        {
            let mut s = state.lock().unwrap();
            match mode {
                0 => s.status = "denied".into(),
                1 => s.expire = true,
                2 => s.wrong_tenant = true,
                3 => s.bad_claim = true,
                4 => s.claim_ambiguous = true,
                _ => s.status = "pending".into(),
            }
        }
        assert!(client
            .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
            .is_err());
        assert_eq!(f.content(), "changed private content");
        let calls = state.lock().unwrap().calls.len();
        assert!(client
            .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
            .is_err());
        assert_eq!(state.lock().unwrap().calls.len(), calls);
    }
}
#[test]
fn destination_mutated_during_claim_reports_failure_and_completion_loss_never_replays() {
    for mutate in [true, false] {
        let f = RestoreFixture::new();
        let transport = FakeTransport::new();
        let state = transport.0.clone();
        let mut client = HostClient::new(transport, identity());
        let request = f.request(&mut client);
        {
            let mut s = state.lock().unwrap();
            if mutate {
                s.mutate_on_claim = Some(f.work.join("private-name.txt"));
            } else {
                s.completion_ambiguous = true;
            }
        }
        assert!(client
            .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
            .is_err());
        assert_eq!(
            f.content(),
            if mutate {
                "changed during claim"
            } else {
                "original private content"
            }
        );
        let calls = state.lock().unwrap().calls.len();
        assert!(client
            .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
            .is_err());
        assert_eq!(state.lock().unwrap().calls.len(), calls);
        let expected = if mutate { "failed" } else { "succeeded" };
        assert!(state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|(p, b)| p.ends_with("/complete") && b["status"] == expected));
    }
}
#[test]
fn ambiguous_creation_is_once_and_keeps_only_encrypted_local_intent() {
    let f = RestoreFixture::new();
    let transport = FakeTransport::new();
    let state = transport.0.clone();
    state.lock().unwrap().create_ambiguous = true;
    let mut client = HostClient::new(transport, identity());
    assert!(client
        .request_restore(&f.repo, &f.consumed, &f.snapshot, &f.work, None)
        .is_err());
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(p, _)| p.ends_with("/restores"))
            .count(),
        1
    );
    assert_eq!(f.content(), "changed private content");
    assert_eq!(
        fs::read_dir(f.repo.root().join("requests"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn stable_snapshot_ids_and_local_opaque_file_metadata() {
    let f = RestoreFixture::new();
    let first = identity().snapshot_id(&f.snapshot).unwrap();
    assert_eq!(first, identity().snapshot_id(&f.snapshot).unwrap());
    assert_eq!(first.get_version_num(), 5);
    assert_ne!(
        first,
        HostIdentity::new(Uuid::from_u128(3), identity().host)
            .unwrap()
            .snapshot_id(&f.snapshot)
            .unwrap()
    );
    assert!(identity().snapshot_id("not-a-core-id").is_err());
    let metadata =
        serde_json::to_string(&snapshot_files(&f.repo, identity(), &f.snapshot).unwrap()).unwrap();
    assert!(!metadata.contains("private-name"));
    assert!(!metadata.contains("content"));
}
fn policy_value() -> Value {
    json!([{"id":Uuid::from_u128(9),"version":1,"updated_at":Utc::now(),"body":{
        "name":"Local","hostId":identity().host,"intervalMinutes":5,"endOfSession":false,"retentionDays":30,
        "exclusions":[],"sizeCapBytes":10000000,"immutable":false,"drCopy":false,"residency":"unrestricted","storage":"local",
        "storageRef":"local-repository","keyRef":"wrapped-key","massDeleteThreshold":20,"missedBackupMinutes":10,"restoreTestIntervalHours":24,"channels":["ui"]}}])
}
#[cfg(unix)]
#[test]
fn host_publication_requires_external_replication_custody_and_reuses_receipts() {
    use bunker::host_storage::{HostStorageAdapter, HostStorageConfig};
    use std::os::unix::fs::PermissionsExt;
    let f = RestoreFixture::new();
    let root = f._temp.path().canonicalize().unwrap();
    let remote = private_dir(&root, "remote-copy");
    let reports = private_dir(&root, "replication-reports");
    let primary = root.join("storage.toml");
    let storage = bunker::storage::StorageConfig {
        service: "local".into(),
        options: [("root".into(), remote.to_str().unwrap().into())].into(),
        credential_env: Default::default(),
        immutable: false,
    };
    fs::write(&primary, toml::to_string(&storage).unwrap()).unwrap();
    fs::set_permissions(&primary, fs::Permissions::from_mode(0o600)).unwrap();
    let config = HostStorageConfig {
        primary,
        secondary: None,
        required_until: None,
        report_directory: reports.clone(),
        consumer_state: None,
    };
    let adapter = Arc::new(
        HostStorageAdapter::open(&config, &f.repo, &f.work, "local-repository", "wrapped-key")
            .unwrap(),
    );
    let bindings = LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key")
        .unwrap()
        .with_storage(adapter);
    let transport = FakeTransport::new();
    let remote_state = transport.0.clone();
    remote_state.lock().unwrap().policy = Some(policy_value());
    let mut service = HostService::new(HostClient::new(transport, identity()));
    assert!(service
        .cycle(&f.repo, &bindings, |_| {
            // A failure after capture but before durable remote custody cannot become
            // a successful snapshot POST.
            fs::remove_dir(&reports).unwrap();
            fs::write(&reports, "fixture obstruction").unwrap();
            Ok(WorkResults {
                snapshots: vec![f.snapshot.clone()],
                ..WorkResults::default()
            })
        })
        .is_err());
    assert!(!remote_state
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|(path, _)| path.ends_with("/snapshots")));
    assert!(!f.repo.root().join("checkpoints/latest").exists());
    fs::remove_file(&reports).unwrap();
    fs::create_dir(&reports).unwrap();
    fs::set_permissions(&reports, fs::Permissions::from_mode(0o700)).unwrap();
    let mut saved = None;
    for _ in 0..2 {
        let transport = FakeTransport::new();
        transport.0.lock().unwrap().policy = Some(policy_value());
        let mut service = HostService::new(HostClient::new(transport, identity()));
        let report = service
            .cycle(&f.repo, &bindings, |_| {
                Ok(WorkResults {
                    snapshots: vec![f.snapshot.clone()],
                    ..WorkResults::default()
                })
            })
            .unwrap();
        assert_eq!(report.snapshots_reported, 1);
        let checkpoint = fs::read(f.repo.root().join("checkpoints/latest")).unwrap();
        let count = fs::read_dir(&reports).unwrap().count();
        assert!(count > 0);
        if let Some((old, files)) = &saved {
            assert_eq!(&checkpoint, old);
            assert_eq!(count, *files);
        }
        saved = Some((checkpoint, count));
    }
}
#[test]
fn explicit_session_cycle_requires_both_opt_ins_and_refetches_policy() {
    let f = RestoreFixture::new();
    let disabled =
        LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key").unwrap();
    let enabled = LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key")
        .unwrap()
        .with_session_handler(true);
    let transport = FakeTransport::new();
    let state = transport.0.clone();
    let mut policy = policy_value();
    policy[0]["body"]["endOfSession"] = json!(true);
    state.lock().unwrap().policy = Some(policy.clone());
    let mut service = HostService::new(HostClient::new(transport, identity()));
    assert!(service
        .session_cycle(&f.repo, &disabled, |_| panic!("disabled local handler"))
        .is_err());
    service
        .cycle(&f.repo, &enabled, |_| Ok(WorkResults::default()))
        .unwrap();
    // Explicit events can follow a tick immediately and each other without
    // bypassing either fresh policy authorization or ordinary tick throttling.
    for _ in 0..2 {
        service
            .session_cycle(&f.repo, &enabled, |_| Ok(WorkResults::default()))
            .unwrap();
    }
    policy[0]["body"]["endOfSession"] = json!(false);
    state.lock().unwrap().policy = Some(policy);
    assert!(service
        .session_cycle(&f.repo, &enabled, |_| panic!("remote policy disabled"))
        .is_err());
    assert!(service
        .cycle(&f.repo, &enabled, |_| panic!("tick still throttled"))
        .is_err());
}
#[test]
fn unsupported_policy_capabilities_and_unbound_references_fail_before_work() {
    let f = RestoreFixture::new();
    let bindings =
        LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key").unwrap();
    for (field, value) in [
        ("immutable", json!(true)),
        ("drCopy", json!(true)),
        ("residency", json!("AU")),
        ("storage", json!("s3")),
        ("storageRef", json!("unbound")),
        ("keyRef", json!("other-key")),
        ("endOfSession", json!(true)),
    ] {
        let transport = FakeTransport::new();
        let mut policy = policy_value();
        policy[0]["body"][field] = value;
        transport.0.lock().unwrap().policy = Some(policy);
        let mut service = HostService::new(HostClient::new(transport, identity()));
        assert!(service
            .cycle(&f.repo, &bindings, |_| panic!(
                "unsupported policy must not run work"
            ))
            .is_err());
    }
    let mut service = HostService::new(HostClient::new(FakeTransport::new(), identity()));
    assert!(service
        .cycle(&f.repo, &bindings, |_| panic!(
            "empty policy must not run work"
        ))
        .is_err());
}
#[test]
fn cycle_publishes_real_results_and_records_not_run_without_fabricated_evidence() {
    let f = RestoreFixture::new();
    let bindings =
        LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key").unwrap();
    let transport = FakeTransport::new();
    let state = transport.0.clone();
    state.lock().unwrap().policy = Some(policy_value());
    let mut service = HostService::new(HostClient::new(transport, identity()));
    let evidence = |outcome| RestoreEvidence {
        id: Uuid::new_v4(),
        snapshot: f.snapshot.clone(),
        finished_at: Utc::now(),
        sandbox: EvidenceSandbox::ContainerFileContent,
        agents: vec![AgentProbe {
            agent: "codex".into(),
            outcome,
        }],
        mcps: vec![],
    };
    let report = service
        .cycle(&f.repo, &bindings, |policy| {
            assert_eq!(policy.interval_seconds, 300);
            Ok(WorkResults {
                snapshots: vec![f.snapshot.clone()],
                evidence: vec![
                    evidence(ProbeOutcome::NotRun),
                    evidence(ProbeOutcome::Failed),
                ],
                alerts: vec![ObservedAlert {
                    event_id: Uuid::new_v4(),
                    kind: AlertKind::MassDelete,
                    critical: true,
                    snapshot: Some(f.snapshot.clone()),
                    count: 22,
                }],
            })
        })
        .unwrap();
    assert_eq!(report.snapshots_reported, 1);
    assert_eq!(report.probes_not_run, 1);
    assert_eq!(report.evidence_reported, 2);
    let s = state.lock().unwrap();
    let evidence: Vec<_> = s
        .calls
        .iter()
        .filter(|(p, _)| p.ends_with("/evidence"))
        .collect();
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].1["scope"], "file-content");
    assert_eq!(evidence[0].1["sandbox"], "container");
    assert_eq!(evidence[0].1["agents"][0]["outcome"], "not_run");
    assert_eq!(evidence[0].1["agents"][0]["reasonCode"], "not_configured");
    assert_eq!(evidence[1].1["agents"][0]["outcome"], "failed");
    assert!(evidence[0].1["agents"][0].get("passed").is_none());
}

#[test]
fn production_cycle_rotates_expiring_identity_before_authenticated_policy_fetch() {
    let f = RestoreFixture::new();
    let (ca_key, ca) = ca();
    let (_, store) = enrollment(f._temp.path(), &ca_key, &ca, Issue::Short).unwrap();
    let ck = ca_key.clone();
    let cc = ca.clone();
    let order = Arc::new(Mutex::new(Vec::new()));
    let observed = order.clone();
    let server = FixtureServer::spawn(&ca_key, &ca, true, 2, move |request| {
        assert!(request.client_cert);
        observed.lock().unwrap().push(request.line.clone());
        if request.line.contains("/certificate ") {
            (
                201,
                issue(request.body["csr"].as_str().unwrap(), &ck, &cc, Issue::Good),
            )
        } else {
            assert!(request.line.contains("/policies "));
            (200, policy_value())
        }
    });
    let mut host = ProductionHost::open(
        store,
        HttpsOrigin::parse(&server.origin).unwrap(),
        server.trust.clone(),
    )
    .unwrap();
    let bindings =
        LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key").unwrap();
    host.cycle(&f.repo, &bindings, |_| Ok(WorkResults::default()))
        .unwrap();
    assert!(order.lock().unwrap()[0].contains("/certificate "));
    assert_eq!(host.identity(), identity());
    assert!(host
        .cycle(&f.repo, &bindings, |_| panic!(
            "must not rerun before policy tick"
        ))
        .is_err());
    server.finish();
}

#[test]
fn real_mtls_requires_client_certificate_and_dropped_claim_is_ambiguous() {
    let temp = tempfile::tempdir().unwrap();
    let (ca_key, ca) = ca();
    let (credentials, _) = enrollment(temp.path(), &ca_key, &ca, Issue::Good).unwrap();
    let server = FixtureServer::spawn(&ca_key, &ca, true, 1, |_| {
        panic!("missing client certificate reached HTTP")
    });
    let public_client = reqwest::blocking::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca.to_pem().unwrap()).unwrap())
        .build()
        .unwrap();
    assert!(public_client
        .get(format!("{}/api/policies", server.origin))
        .send()
        .is_err());
    server.finish();
    let seen = Arc::new(Mutex::new(0));
    let counter = seen.clone();
    let server = FixtureServer::spawn(&ca_key, &ca, true, 1, move |request| {
        assert!(request.client_cert);
        assert!(request.line.contains("/claim "));
        *counter.lock().unwrap() += 1;
        (0, Value::Null)
    });
    let mut transport = MtlsTransport::new(
        HttpsOrigin::parse(&server.origin).unwrap(),
        &server.trust,
        &credentials,
    )
    .unwrap();
    assert_eq!(transport.request(Method::Post, "/tenants/00000000-0000-0000-0000-000000000001/restores/00000000-0000-0000-0000-000000000007/claim", Some(&json!({"diffDigest":"a".repeat(64)}))), Err(TransportError::Ambiguous));
    assert_eq!(*seen.lock().unwrap(), 1);
    server.finish();
}

#[test]
fn concurrent_executors_have_exactly_one_durable_claim_winner() {
    let f = RestoreFixture::new();
    let transport = FakeTransport::new();
    let state = transport.0.clone();
    let mut client = HostClient::new(transport.clone(), identity());
    let request = f.request(&mut client);
    let barrier = std::sync::Barrier::new(2);
    let successes = thread::scope(|scope| {
        let run = || {
            let mut client = HostClient::new(transport.clone(), identity());
            barrier.wait();
            client
                .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
                .is_ok()
        };
        let left = scope.spawn(run);
        let right = scope.spawn(run);
        usize::from(left.join().unwrap()) + usize::from(right.join().unwrap())
    });
    assert_eq!(successes, 1);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(path, _)| path.ends_with("/claim"))
            .count(),
        1
    );
    assert_eq!(f.content(), "original private content");
}

#[test]
fn invalid_completion_ack_does_not_report_success_or_allow_execution_replay() {
    let f = RestoreFixture::new();
    let transport = FakeTransport::new();
    let state = transport.0.clone();
    let mut client = HostClient::new(transport, identity());
    let request = f.request(&mut client);
    state.lock().unwrap().completion_bad_ack = true;
    let error = client
        .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
        .unwrap_err();
    assert!(error.to_string().contains("acknowledgement mismatch"));
    assert_eq!(f.content(), "original private content");
    let calls = state.lock().unwrap().calls.len();
    fs::write(f.work.join("private-name.txt"), "changed private content").unwrap();
    assert!(client
        .execute_restore_once(&f.repo, &f.consumed, &request.local_request_id)
        .is_err());
    assert_eq!(state.lock().unwrap().calls.len(), calls);
}

#[cfg(unix)]
#[test]
fn protected_token_fifo_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("token.fifo");
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // Disposable FIFO exercises descriptor validation before any token read or network request.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let store = CredentialStore::open(&private_dir(temp.path(), "credentials")).unwrap();
    let error = enroll(
        HttpsOrigin::parse("https://127.0.0.1:1").unwrap(),
        &ServerTrust::Native,
        identity().tenant,
        &EnrollmentTokenSource::File(fifo),
        &store,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("regular"));
}

#[test]
fn policy_binding_detects_actual_key_header_change_before_scheduler_work() {
    let f = RestoreFixture::new();
    let bindings =
        LocalBindings::local_repository(&f.repo, "local-repository", "wrapped-key").unwrap();
    f.repo
        .rewrap_passphrase("changed-fixture-only-passphrase")
        .unwrap();
    let transport = FakeTransport::new();
    transport.0.lock().unwrap().policy = Some(policy_value());
    let mut service = HostService::new(HostClient::new(transport, identity()));
    let error = service
        .cycle(&f.repo, &bindings, |_| {
            panic!("changed key binding must not run work")
        })
        .err()
        .unwrap();
    assert!(error.to_string().contains("binding changed"));
}
