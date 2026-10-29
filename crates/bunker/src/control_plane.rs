//! Host-only control-plane transport. Never accepts human sessions or gateway proofs.
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{store::X509StoreBuilder, X509PurposeId, X509Req, X509StoreContext, X509},
};
use reqwest::{blocking::Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const POLICY_POLL_INTERVAL: Duration = Duration::from_secs(30);
pub const RENEW_BEFORE: i64 = 60 * 60;
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;
const MAX_CREDENTIAL: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Method {
    Get,
    Post,
}
#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    Http(u16),
    Ambiguous,
    InvalidResponse,
    InvalidRequest,
    Expired,
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(n) => write!(f, "control plane returned HTTP {n}"),
            Self::Ambiguous => {
                f.write_str("control plane response uncertain; do not replay mutation")
            }
            Self::InvalidResponse => f.write_str("invalid control plane response"),
            Self::InvalidRequest => f.write_str("invalid control plane request"),
            Self::Expired => f.write_str("host certificate expired; re-enrollment required"),
        }
    }
}
impl std::error::Error for TransportError {}
/// Implementations must make one attempt, never automatically retry POSTs, and must not log bodies.
pub trait Transport {
    fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> std::result::Result<Value, TransportError>;
}

#[derive(Clone)]
pub enum ServerTrust {
    /// The operating system's configured roots, not enrollment's client-identity chain.
    Native,
    /// A separately provisioned PEM CA bundle. Replaces native roots.
    CaBundle(Vec<u8>),
}
#[derive(Clone)]
pub struct HttpsOrigin(Url);
impl HttpsOrigin {
    pub fn parse(origin: &str) -> Result<Self> {
        let url = Url::parse(origin).context("invalid HTTPS origin")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "expected HTTPS origin without credentials, path, query or fragment"
        );
        Ok(Self(url))
    }
}
fn builder(trust: &ServerTrust) -> Result<reqwest::blocking::ClientBuilder> {
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20));
    if let ServerTrust::CaBundle(pem) = trust {
        builder = builder.tls_built_in_root_certs(false);
        let certs =
            reqwest::Certificate::from_pem_bundle(pem).context("invalid server CA bundle")?;
        ensure!(!certs.is_empty(), "empty server CA bundle");
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    Ok(builder)
}

/// No Debug implementation: private key is deliberately excluded from diagnostics.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub tenant_id: Uuid,
    pub host_id: Uuid,
    pub expires_at: DateTime<Utc>,
    certificate: String,
    client_chain: String,
    private_key: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
impl Credentials {
    pub fn renewal_due(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.signed_duration_since(now).num_seconds() <= RENEW_BEFORE
    }
    pub fn require_valid(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            now < self.expires_at,
            "host certificate expired; re-enrollment required"
        );
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        validate_certificate(
            &self.private_key,
            &self.certificate,
            &self.client_chain,
            self.tenant_id,
            self.host_id,
            self.expires_at,
        )
    }
}

/// Private, owner-only directory; credentials are replaced as one fsynced atomic file.
/// Unix permissions are enforced. Other platforms fail closed pending an ACL implementation.
pub struct CredentialStore {
    dir: PathBuf,
}
impl CredentialStore {
    pub fn open(directory: &Path) -> Result<Self> {
        Ok(Self {
            dir: private_directory(directory)?,
        })
    }
    pub fn directory(&self) -> &Path {
        &self.dir
    }
    pub fn load(&self) -> Result<Credentials> {
        let bytes = read_private(&self.dir.join("identity.json"), MAX_CREDENTIAL)?;
        let credentials: Credentials =
            serde_json::from_slice(&bytes).context("invalid host credential state")?;
        credentials.validate()?;
        Ok(credentials)
    }
    pub fn save(&self, credentials: &Credentials) -> Result<()> {
        credentials.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(credentials)?);
        ensure!(
            bytes.len() as u64 <= MAX_CREDENTIAL,
            "credential state too large"
        );
        let mut temporary = tempfile::NamedTempFile::new_in(&self.dir)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(self.dir.join("identity.json"))
            .map_err(|_| anyhow::anyhow!("persist host credential state"))?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

/// Read the one-time token through an owner-only file or a protected process environment.
/// The caller must arrange environment protection before process launch. Never use a CLI value.
pub enum EnrollmentTokenSource {
    File(PathBuf),
    Environment(String),
}
impl EnrollmentTokenSource {
    fn read(&self) -> Result<Zeroizing<String>> {
        let raw =
            match self {
                Self::File(path) => Zeroizing::new(
                    String::from_utf8(read_private(path, 256)?.to_vec())
                        .context("invalid enrollment token encoding")?,
                ),
                Self::Environment(name) => {
                    ensure!(
                        !name.is_empty(),
                        "missing enrollment environment variable name"
                    );
                    Zeroizing::new(std::env::var(name).map_err(|_| {
                        anyhow::anyhow!("enrollment environment variable unavailable")
                    })?)
                }
            };
        let token = Zeroizing::new(raw.trim().to_owned());
        ensure!(
            (32..=128).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid enrollment token"
        );
        Ok(token)
    }
}

struct SigningRequest {
    key: PKey<Private>,
    csr: String,
}
fn signing_request() -> Result<SigningRequest> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut request = X509Req::builder()?;
    request.set_version(0)?;
    request.set_pubkey(&key)?;
    let mut subject = openssl::x509::X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", "Bunker host")?;
    request.set_subject_name(&subject.build())?;
    request.sign(&key, MessageDigest::sha256())?;
    Ok(SigningRequest {
        key,
        csr: String::from_utf8(request.build().to_pem()?)?,
    })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssuedIdentity {
    tenant_id: Uuid,
    host_id: Uuid,
    transport: String,
    certificate: String,
    trust_chain: String,
    expires_at: DateTime<Utc>,
}
fn issued(
    value: Value,
    request: SigningRequest,
    expected_tenant: Uuid,
    expected_host: Option<Uuid>,
) -> Result<Credentials> {
    let response: IssuedIdentity =
        serde_json::from_value(value).context("invalid enrollment response")?;
    ensure!(
        response.transport == "mtls"
            && response.tenant_id == expected_tenant
            && expected_host.is_none_or(|host| host == response.host_id),
        "issued identity binding mismatch"
    );
    let credentials = Credentials {
        tenant_id: response.tenant_id,
        host_id: response.host_id,
        expires_at: response.expires_at,
        certificate: response.certificate,
        client_chain: response.trust_chain,
        private_key: String::from_utf8(request.key.private_key_to_pem_pkcs8()?)?,
    };
    credentials.validate()?;
    Ok(credentials)
}
fn validate_certificate(
    key: &str,
    leaf: &str,
    chain: &str,
    tenant: Uuid,
    host: Uuid,
    expiry: DateTime<Utc>,
) -> Result<()> {
    ensure!(!tenant.is_nil() && !host.is_nil(), "nil host identity");
    let key = PKey::private_key_from_pem(key.as_bytes())?;
    ensure!(
        key.ec_key()?.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
        "host key must be P-256"
    );
    let leaves = X509::stack_from_pem(leaf.as_bytes())?;
    ensure!(leaves.len() == 1, "expected one client leaf");
    let cert = &leaves[0];
    ensure!(
        cert.public_key()?.public_eq(&key),
        "issued certificate does not match local key"
    );
    let san = cert.subject_alt_names().context("missing host SAN")?;
    let expected = format!("urn:bunker:tenant:{tenant}:host:{host}");
    ensure!(
        san.len() == 1 && san[0].uri() == Some(expected.as_str()),
        "issued certificate SAN mismatch"
    );
    let now = Asn1Time::from_unix(Utc::now().timestamp())?;
    let expires = Asn1Time::from_unix(expiry.timestamp())?;
    ensure!(
        cert.not_before() <= now.as_ref()
            && cert.not_after() > now.as_ref()
            && cert.not_after() == expires.as_ref(),
        "issued certificate validity mismatch or expired"
    );
    let lifetime = cert.not_before().diff(cert.not_after())?;
    ensure!(
        i64::from(lifetime.days) * 86400 + i64::from(lifetime.secs) <= 86430
            && expiry.signed_duration_since(Utc::now()).num_seconds() <= 86400,
        "client certificate exceeds 24-hour expiry plus server 30-second backdating"
    );
    let roots = X509::stack_from_pem(chain.as_bytes())?;
    ensure!(!roots.is_empty(), "missing client issuer chain");
    let mut store = X509StoreBuilder::new()?;
    store.set_purpose(X509PurposeId::SSL_CLIENT)?;
    // These roots validate only the client leaf. They NEVER enter the HTTPS client trust store.
    for root in &roots {
        store.add_cert(root.clone())?;
    }
    let mut intermediates = Stack::new()?;
    for root in roots {
        intermediates.push(root)?;
    }
    let valid = X509StoreContext::new()?.init(&store.build(), cert, &intermediates, |ctx| {
        ctx.verify_cert()
    })?;
    ensure!(
        valid,
        "invalid client certificate chain or clientAuth purpose"
    );
    Ok(())
}

pub fn enroll(
    origin: HttpsOrigin,
    trust: &ServerTrust,
    expected_tenant: Uuid,
    token_source: &EnrollmentTokenSource,
    store: &CredentialStore,
) -> Result<Credentials> {
    let request = signing_request()?;
    let token = token_source.read()?;
    // Serialize directly into a zeroizing buffer; avoid keeping token in a serde_json::Value.
    #[derive(Serialize)]
    struct Enrollment<'a> {
        token: &'a str,
        csr: &'a str,
    }
    let body = Zeroizing::new(serde_json::to_vec(&Enrollment {
        token: &token,
        csr: &request.csr,
    })?);
    let client = builder(trust)?
        .build()
        .context("build enrollment HTTPS client")?;
    let value = send(
        &client,
        &origin.0,
        Method::Post,
        "/enroll",
        Some(body.as_slice()),
        None,
    )?;
    let credentials = issued(value, request, expected_tenant, None)?;
    store.save(&credentials)?;
    Ok(credentials)
}

pub struct MtlsTransport {
    client: Client,
    origin: HttpsOrigin,
    expires_at: DateTime<Utc>,
    rejected: bool,
}
impl MtlsTransport {
    pub fn new(
        origin: HttpsOrigin,
        trust: &ServerTrust,
        credentials: &Credentials,
    ) -> Result<Self> {
        credentials.validate()?;
        let mut pem = Zeroizing::new(credentials.private_key.clone());
        pem.push_str(&credentials.certificate);
        pem.push_str(&credentials.client_chain);
        let identity =
            reqwest::Identity::from_pem(pem.as_bytes()).context("invalid mTLS identity")?;
        let client = builder(trust)?
            .identity(identity)
            .build()
            .context("build mTLS HTTPS client")?;
        Ok(Self {
            client,
            origin,
            expires_at: credentials.expires_at,
            rejected: false,
        })
    }
}
impl Transport for MtlsTransport {
    fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> std::result::Result<Value, TransportError> {
        if self.rejected {
            return Err(TransportError::Http(401));
        }
        if Utc::now() >= self.expires_at {
            return Err(TransportError::Expired);
        }
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| TransportError::InvalidRequest)?;
        let result = send(
            &self.client,
            &self.origin.0,
            method,
            path,
            body.as_deref(),
            None,
        );
        if matches!(result, Err(TransportError::Http(401 | 403))) {
            self.rejected = true;
        }
        result
    }
}
/// Renewal rotates the local key, persists the complete validated identity, and returns it.
/// Rebuild MtlsTransport after success. Failure must stop the host cycle; never fall back to bearer.
pub fn renew(
    transport: &mut impl Transport,
    current: &Credentials,
    store: &CredentialStore,
) -> Result<Credentials> {
    current.require_valid(Utc::now())?;
    let request = signing_request()?;
    let value = transport.request(
        Method::Post,
        &format!(
            "/tenants/{}/hosts/{}/certificate",
            current.tenant_id, current.host_id
        ),
        Some(&serde_json::json!({"csr":request.csr})),
    )?;
    let credentials = issued(value, request, current.tenant_id, Some(current.host_id))?;
    store.save(&credentials)?;
    Ok(credentials)
}

/// Explicit development/test opt-in. This type cannot connect to HTTPS or non-loopback hosts.
/// The bearer must come from protected local configuration, never a human session.
pub struct LoopbackDevelopmentTransport {
    client: Client,
    origin: Url,
    bearer: Zeroizing<String>,
}
impl LoopbackDevelopmentTransport {
    pub fn new(origin: &str, bearer: Zeroizing<String>, explicit_opt_in: bool) -> Result<Self> {
        let url = Url::parse(origin)?;
        let loopback = url
            .host_str()
            .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        ensure!(
            explicit_opt_in
                && loopback
                && url.scheme() == "http"
                && url.path() == "/"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "development bearer requires explicit opt-in and literal HTTP loopback origin"
        );
        ensure!(
            !bearer.is_empty() && bearer.bytes().all(|b| b.is_ascii_graphic()),
            "invalid development bearer"
        );
        Ok(Self {
            client: builder(&ServerTrust::Native)?.build()?,
            origin: url,
            bearer,
        })
    }
}
impl Transport for LoopbackDevelopmentTransport {
    fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> std::result::Result<Value, TransportError> {
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| TransportError::InvalidRequest)?;
        send(
            &self.client,
            &self.origin,
            method,
            path,
            body.as_deref(),
            Some(&self.bearer),
        )
    }
}
fn send(
    client: &Client,
    origin: &Url,
    method: Method,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
) -> std::result::Result<Value, TransportError> {
    if !path.starts_with('/')
        || path.contains("..")
        || path
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b"/-".contains(&b)))
    {
        return Err(TransportError::InvalidRequest);
    }
    if body.is_some_and(|b| b.len() > 256_000) {
        return Err(TransportError::InvalidRequest);
    }
    let url = origin
        .join(&format!("/api{path}"))
        .map_err(|_| TransportError::InvalidRequest)?;
    let method = match method {
        Method::Get => reqwest::Method::GET,
        Method::Post => reqwest::Method::POST,
    };
    let mut request = client
        .request(method, url)
        .header("Accept", "application/json");
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    let response = request.send().map_err(|_| TransportError::Ambiguous)?;
    if !response.status().is_success() {
        return Err(TransportError::Http(response.status().as_u16()));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TransportError::Ambiguous)?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(TransportError::InvalidResponse);
    }
    serde_json::from_slice(&bytes).map_err(|_| TransportError::InvalidResponse)
}

pub(crate) fn private_directory(path: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let absolute = std::path::absolute(path)?;
        match fs::DirBuilder::new().mode(0o700).create(&absolute) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() },
            "host state directory must be owner-only and not a symlink"
        );
        // Reject symlinked parents too, so a directory alias cannot silently change state roots.
        let canonical = path.canonicalize()?;
        ensure!(
            absolute == canonical,
            "host state path must be canonical without symlinks"
        );
        // Also flush when a previous create succeeded but its parent sync failed.
        // An existing name alone does not establish durable directory linkage.
        if let Some(parent) = canonical.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(canonical)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        anyhow::bail!("host credential ACL enforcement is not implemented on this platform")
    }
}
pub(crate) fn read_private(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = OpenOptions::new()
            .read(true)
            // Open first without following links, but do not block on a FIFO/device
            // before we can inspect the descriptor and reject non-regular files.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() },
            "credential/token file must be owner-only, regular, and not linked"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= limit,
            "protected file exceeds size limit"
        );
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        anyhow::bail!("protected file ACL enforcement unavailable")
    }
}
