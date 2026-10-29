//! Version-bound provider retention. No delete, governance bypass, or provisioning API.
//! See docs/immutable-storage.md for the trust boundary and saved evidence requirement.
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;
use zeroize::Zeroizing;

const MAX_OBJECT: u64 = 64 * 1024 * 1024;
const MAX_CONTROL: u64 = 64 * 1024;
const ATTEMPTS: usize = 3;
const API_VERSION: &str = "2023-11-03";

/// Intentionally no Debug: requests contain credentials and object ciphertext.
pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub maximum_response: u64,
}
/// A transport must honor maximum_response without buffering an unbounded body.
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}
/// Transport errors are deliberately opaque and never include URL/header/body details.
#[derive(Debug)]
pub struct TransportError;
pub trait Transport: Send + Sync {
    fn send(&self, request: Request) -> std::result::Result<Response, TransportError>;
}
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

struct HttpsTransport(reqwest::blocking::Client);
impl HttpsTransport {
    fn new() -> Result<Self> {
        Ok(Self(
            reqwest::blocking::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(60))
                .build()
                .map_err(|_| anyhow!("protected HTTPS client initialization failed"))?,
        ))
    }
}
impl Transport for HttpsTransport {
    fn send(&self, request: Request) -> std::result::Result<Response, TransportError> {
        let response = self
            .0
            .request(request.method, request.url)
            .headers(request.headers)
            .body(request.body)
            .send()
            .map_err(|_| TransportError)?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        if headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum::<usize>()
            > 65536
        {
            return Err(TransportError);
        }
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

enum Provider {
    S3 {
        region: String,
        access: Zeroizing<String>,
        secret: Zeroizing<String>,
        token: Option<Zeroizing<String>>,
    },
    Azure {
        account: String,
        key: Zeroizing<Vec<u8>>,
    },
}
struct Inner {
    provider: Provider,
    base: Url,
    root: String,
    required_until: DateTime<Utc>,
    identity: BackendIdentity,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
    proofs: Mutex<Proofs>,
    recovery_only: bool,
}
#[derive(Clone)]
pub struct ProtectedBackend(Arc<Inner>);

#[derive(Default)]
struct Proofs {
    objects: BTreeMap<String, ObjectProof>,
    estimated_bytes: usize,
}
fn proof_size(path: &str, proof: &ObjectProof) -> usize {
    path.len() + proof.version.len() + 256
}

/// Opaque identifiers exclude credentials. Different IDs do not prove separate cloud
/// principals or administrative fault domains; deployment policy must establish that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    pub backend: String,
    pub credential: String,
    /// Exact configured origin/container/root binding, separate from DR independence.
    pub location: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectProof {
    pub version: String,
    pub retain_until: DateTime<Utc>,
    pub mode: String,
    pub bytes: u64,
    pub blake3: String,
}
/// Save this outside the remote backend, alongside the existing checkpoint locator.
/// It is evidence from a provider response, not an independent provider attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionEvidence {
    pub identity: BackendIdentity,
    pub required_until: DateTime<Utc>,
    pub objects: BTreeMap<String, ObjectProof>,
}

impl ProtectedBackend {
    /// Production constructor. Credentials are read ONLY from configured env references.
    pub fn new(
        config: &crate::storage::StorageConfig,
        required_until: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_transport(
            config,
            required_until,
            Arc::new(HttpsTransport::new()?),
            Arc::new(SystemClock),
            |name| std::env::var(name).ok(),
        )
    }
    /// Injectable transport, clock, and explicit-name credential resolver for offline tests.
    /// Resolver is invoked only with names present in config. There is no fallback chain.
    pub fn with_transport(
        config: &crate::storage::StorageConfig,
        required_until: DateTime<Utc>,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        resolve: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        Self::build(config, required_until, transport, clock, resolve, false)
    }
    /// Read-only recovery pins exact versions from an externally saved locator. Expired
    /// retention does not prevent byte recovery and is never reported as current protection.
    pub fn for_recovery(
        config: &crate::storage::StorageConfig,
        evidence: &ProtectionEvidence,
    ) -> Result<Self> {
        Self::for_recovery_with_transport(
            config,
            evidence,
            Arc::new(HttpsTransport::new()?),
            Arc::new(SystemClock),
            |name| std::env::var(name).ok(),
        )
    }
    pub fn for_recovery_with_transport(
        config: &crate::storage::StorageConfig,
        evidence: &ProtectionEvidence,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        resolve: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let backend = Self::build(
            config,
            evidence.required_until,
            transport,
            clock,
            resolve,
            true,
        )?;
        backend.load_evidence(evidence)?;
        Ok(backend)
    }
    fn build(
        config: &crate::storage::StorageConfig,
        required_until: DateTime<Utc>,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        resolve: impl Fn(&str) -> Option<String>,
        recovery_only: bool,
    ) -> Result<Self> {
        ensure!(
            config.immutable,
            "protected backend requires explicit immutable configuration"
        );
        ensure!(
            recovery_only || required_until > clock.now(),
            "retention deadline must be in the future"
        );
        ensure!(
            required_until.timestamp_subsec_nanos() == 0,
            "retention deadline must use whole seconds"
        );
        ensure!(matches!(config.service.as_str(), "s3" | "azure"), "protected storage supports S3 Object Lock and Azure version immutability only; R2 is unsupported");
        let allowed = if config.service == "s3" {
            vec!["endpoint", "bucket", "root", "region"]
        } else {
            vec!["endpoint", "container", "root", "account_name"]
        };
        ensure!(
            config.options.keys().all(|k| allowed.contains(&k.as_str())),
            "unsupported protected backend option"
        );
        let allowed_secrets = if config.service == "s3" {
            vec!["access_key_id", "secret_access_key", "session_token"]
        } else {
            vec!["account_key"]
        };
        ensure!(
            config
                .credential_env
                .keys()
                .all(|k| allowed_secrets.contains(&k.as_str())),
            "unsupported protected credential reference (Azure requires explicit SharedKey)"
        );
        let option = |name: &str| -> Result<String> {
            config
                .options
                .get(name)
                .filter(|v| !v.is_empty())
                .cloned()
                .context("required protected backend option is missing")
        };
        let credential = |name: &str| -> Result<Zeroizing<String>> {
            let reference = config
                .credential_env
                .get(name)
                .context("required credential environment reference is missing")?;
            ensure!(
                !reference.is_empty()
                    && reference.len() <= 256
                    && reference
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "invalid credential environment reference"
            );
            resolve(reference)
                .filter(|v| !v.is_empty())
                .map(Zeroizing::new)
                .context("required explicit credential is unavailable")
        };
        let mut base = Url::parse(&option("endpoint")?)
            .map_err(|_| anyhow!("invalid protected HTTPS endpoint"))?;
        ensure!(
            base.scheme() == "https"
                && base.host_str().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none()
                && base.path() == "/",
            "protected endpoint must be an HTTPS origin without credentials, query, or path"
        );
        // Do not accept R2 hidden behind its S3 service alias.
        ensure!(
            !base
                .host_str()
                .unwrap_or_default()
                .ends_with("r2.cloudflarestorage.com"),
            "R2 does not expose required version-retention APIs"
        );
        let root = config
            .options
            .get("root")
            .cloned()
            .unwrap_or_default()
            .trim_matches('/')
            .to_owned();
        if !root.is_empty() {
            validate_path(&root)?;
        }
        let (provider, backend, identity_credential, container) = if config.service == "s3" {
            let bucket = option("bucket")?;
            validate_container(&bucket)?;
            let region = option("region")?;
            ensure!(
                region
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "invalid S3 region"
            );
            let access = credential("access_key_id")?;
            let identity = blake3::hash(access.as_bytes()).to_hex().to_string();
            let secret = credential("secret_access_key")?;
            let token = config
                .credential_env
                .contains_key("session_token")
                .then(|| credential("session_token"))
                .transpose()?;
            // Conservatively identify a bucket across regional/alias endpoints and roots.
            (
                Provider::S3 {
                    region,
                    access,
                    secret,
                    token,
                },
                format!("s3:{bucket}"),
                identity,
                bucket,
            )
        } else {
            let container = option("container")?;
            validate_container(&container)?;
            let account = option("account_name")?;
            ensure!(
                !account.is_empty()
                    && account
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "invalid Azure account name"
            );
            let key = Zeroizing::new(
                STANDARD
                    .decode(credential("account_key")?.as_bytes())
                    .map_err(|_| anyhow!("invalid Azure SharedKey encoding"))?,
            );
            ensure!(key.len() >= 32, "invalid Azure SharedKey length");
            let identity = blake3::hash(account.as_bytes()).to_hex().to_string();
            (
                Provider::Azure {
                    account: account.clone(),
                    key,
                },
                format!("azure:{account}:{container}"),
                identity,
                container,
            )
        };
        base.set_path(&format!("/{container}/"));
        let location = blake3::hash(format!("{}|{root}", base.as_str()).as_bytes())
            .to_hex()
            .to_string();
        Ok(Self(Arc::new(Inner {
            provider,
            base,
            root,
            required_until,
            identity: BackendIdentity {
                backend,
                credential: identity_credential,
                location,
            },
            transport,
            clock,
            proofs: Mutex::new(Proofs::default()),
            recovery_only,
        })))
    }
    pub fn identity(&self) -> &BackendIdentity {
        &self.0.identity
    }
    pub fn required_until(&self) -> DateTime<Utc> {
        self.0.required_until
    }
    pub fn ensure_independent(&self, other: &Self) -> Result<()> {
        ensure!(
            self.identity().backend != other.identity().backend,
            "DR requires a distinct explicit backend, not another prefix or endpoint alias"
        );
        ensure!(
            self.identity().credential != other.identity().credential,
            "DR requires a distinct explicit credential identity"
        );
        Ok(())
    }
    pub fn evidence(&self) -> Result<ProtectionEvidence> {
        ensure!(
            !self.0.recovery_only,
            "recovery-only backend cannot report current protection"
        );
        let objects = self
            .0
            .proofs
            .lock()
            .map_err(|_| anyhow!("protected evidence lock failed"))?
            .objects
            .clone();
        ensure!(
            self.0.required_until > self.0.clock.now()
                && objects
                    .values()
                    .all(|p| p.retain_until >= self.0.required_until),
            "cannot report current protection from expired or insufficient evidence"
        );
        Ok(ProtectionEvidence {
            identity: self.identity().clone(),
            required_until: self.0.required_until,
            objects,
        })
    }
    /// Load externally saved evidence for version-pinned recovery. This cannot create a
    /// protection claim: imports are read-only and every read rechecks bytes and version.
    pub fn load_evidence(&self, evidence: &ProtectionEvidence) -> Result<()> {
        ensure!(
            self.0.recovery_only,
            "saved evidence can only be imported into a recovery-only backend"
        );
        ensure!(
            evidence.identity.backend == self.identity().backend
                && evidence.identity.location == self.identity().location,
            "saved evidence backend mismatch"
        );
        ensure!(
            evidence.objects.len() <= 100_000,
            "saved evidence exceeds object limit"
        );
        for (path, proof) in &evidence.objects {
            validate_path(path)?;
            validate_version(&proof.version)?;
            ensure!(
                proof.bytes <= MAX_OBJECT
                    && proof.blake3.len() == 64
                    && proof.blake3.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid saved object evidence"
            );
            ensure!(
                self.strong_mode(&proof.mode),
                "saved evidence has an unsupported retention mode"
            );
            ensure!(
                proof.retain_until >= evidence.required_until,
                "saved evidence retention is shorter than its declared minimum"
            );
        }
        let estimated_bytes = evidence
            .objects
            .iter()
            .map(|(p, v)| proof_size(p, v))
            .sum::<usize>();
        ensure!(
            estimated_bytes <= 32 * 1024 * 1024,
            "saved evidence exceeds byte limit"
        );
        *self
            .0
            .proofs
            .lock()
            .map_err(|_| anyhow!("protected evidence lock failed"))? = Proofs {
            objects: evidence.objects.clone(),
            estimated_bytes,
        };
        Ok(())
    }
    fn version_header(&self) -> &'static str {
        match self.0.provider {
            Provider::S3 { .. } => "x-amz-version-id",
            Provider::Azure { .. } => "x-ms-version-id",
        }
    }
    fn strong_mode(&self, mode: &str) -> bool {
        match self.0.provider {
            Provider::S3 { .. } => mode == "COMPLIANCE",
            Provider::Azure { .. } => mode.eq_ignore_ascii_case("locked"),
        }
    }
    fn object_url(&self, path: &str, version: Option<&str>, retention: bool) -> Result<Url> {
        validate_path(path)?;
        let mut url = self.0.base.clone();
        {
            let mut parts = url
                .path_segments_mut()
                .map_err(|_| anyhow!("invalid backend URL"))?;
            parts.pop_if_empty();
            if !self.0.root.is_empty() {
                parts.extend(self.0.root.split('/'));
            }
            parts.extend(path.split('/'));
        }
        let mut query = BTreeMap::new();
        if let Some(version) = version {
            validate_version(version)?;
            query.insert(
                if matches!(self.0.provider, Provider::S3 { .. }) {
                    "versionId"
                } else {
                    "versionid"
                },
                version,
            );
        }
        if retention {
            query.insert(
                if matches!(self.0.provider, Provider::S3 { .. }) {
                    "retention"
                } else {
                    "comp"
                },
                if matches!(self.0.provider, Provider::S3 { .. }) {
                    ""
                } else {
                    "immutabilityPolicies"
                },
            );
        }
        if !query.is_empty() {
            // AWS uses RFC3986, never form-urlencoded '+' for spaces.
            url.set_query(Some(
                &query
                    .iter()
                    .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                    .collect::<Vec<_>>()
                    .join("&"),
            ));
        }
        Ok(url)
    }
    fn request(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
        maximum: u64,
    ) -> Result<Response> {
        ensure!(
            maximum <= MAX_OBJECT,
            "protected response limit exceeds safety cap"
        );
        for attempt in 0..ATTEMPTS {
            let now = self.0.clock.now();
            let mut request = Request {
                method: method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                body: body.clone(),
                maximum_response: maximum,
            };
            sign(&self.0.provider, &mut request, now)?;
            match self.0.transport.send(request) {
                Ok(response) => {
                    ensure!(
                        response.body.len() as u64 <= maximum
                            && response
                                .headers
                                .iter()
                                .map(|(k, v)| k.as_str().len() + v.len())
                                .sum::<usize>()
                                <= 65536,
                        "protected response exceeds safety limit"
                    );
                    if matches!(response.status, 429 | 500 | 502 | 503 | 504)
                        && attempt + 1 < ATTEMPTS
                    {
                        std::thread::sleep(Duration::from_millis(50 << attempt));
                        continue;
                    }
                    // Provider clock binds retention checks; absent/stale Date is never proof.
                    if (200..300).contains(&response.status) {
                        let server = response_time(&response)?;
                        ensure!(
                            (server - now).num_seconds().abs() <= 300,
                            "provider clock skew exceeds five minutes"
                        );
                    }
                    return Ok(response);
                }
                Err(_) if attempt + 1 < ATTEMPTS => {
                    std::thread::sleep(Duration::from_millis(50 << attempt))
                }
                Err(_) => bail!("protected storage transport failed after bounded retries"),
            }
        }
        bail!("protected storage retry limit reached")
    }
    fn head(&self, path: &str, version: Option<&str>) -> Result<Response> {
        self.request(
            Method::HEAD,
            self.object_url(path, version, false)?,
            HeaderMap::new(),
            vec![],
            MAX_CONTROL,
        )
    }
    fn version(&self, response: &Response) -> Result<String> {
        let value = header(&response.headers, self.version_header())?
            .context("provider did not return a version ID; versioned storage is required")?;
        validate_version(value)?;
        Ok(value.to_owned())
    }
    fn retention(&self, response: &Response) -> Result<Option<(String, DateTime<Utc>)>> {
        let (mode_name, until_name) = match self.0.provider {
            Provider::S3 { .. } => (
                "x-amz-object-lock-mode",
                "x-amz-object-lock-retain-until-date",
            ),
            Provider::Azure { .. } => (
                "x-ms-immutability-policy-mode",
                "x-ms-immutability-policy-until-date",
            ),
        };
        let mode = header(&response.headers, mode_name)?;
        let until = header(&response.headers, until_name)?;
        match (mode, until) {
            (None, None) => Ok(None),
            (Some(mode), Some(until)) => {
                let date = if matches!(self.0.provider, Provider::S3 { .. }) {
                    DateTime::parse_from_rfc3339(until)
                        .map(|t| t.with_timezone(&Utc))
                        .map_err(|_| anyhow!("invalid provider retention date"))?
                } else {
                    httpdate::parse_http_date(until)
                        .map(DateTime::<Utc>::from)
                        .map_err(|_| anyhow!("invalid provider retention date"))?
                };
                ensure!(self.strong_mode(mode), "provider retention is not COMPLIANCE/locked; governance and unlocked policies are refused");
                Ok(Some((mode.to_owned(), date)))
            }
            _ => bail!("incomplete provider retention response"),
        }
    }
    fn protection_headers(&self, headers: &mut HeaderMap) -> Result<()> {
        match self.0.provider {
            Provider::S3 { .. } => {
                put(headers, "x-amz-object-lock-mode", "COMPLIANCE")?;
                put(
                    headers,
                    "x-amz-object-lock-retain-until-date",
                    &iso(self.0.required_until),
                )?;
            }
            Provider::Azure { .. } => {
                put(headers, "x-ms-immutability-policy-mode", "Locked")?;
                put(
                    headers,
                    "x-ms-immutability-policy-until-date",
                    &httpdate::fmt_http_date(self.0.required_until.into()),
                )?;
            }
        }
        Ok(())
    }
    fn apply_retention(&self, path: &str, version: &str) -> Result<()> {
        let mut headers = HeaderMap::new();
        let body = match self.0.provider {
            Provider::S3 { .. } => {
                put(&mut headers, "content-type", "application/xml")?;
                format!("<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>COMPLIANCE</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>", iso(self.0.required_until)).into_bytes()
            }
            Provider::Azure { .. } => {
                self.protection_headers(&mut headers)?;
                vec![]
            }
        };
        checksum(&mut headers, &body)?;
        let response = self.request(
            Method::PUT,
            self.object_url(path, Some(version), true)?,
            headers,
            body,
            MAX_CONTROL,
        )?;
        ensure!(
            (200..300).contains(&response.status),
            "provider refused retention application (HTTP {})",
            response.status
        );
        Ok(())
    }
    fn read_version(&self, path: &str, version: &str, maximum: u64) -> Result<Response> {
        let response = self.request(
            Method::GET,
            self.object_url(path, Some(version), false)?,
            HeaderMap::new(),
            vec![],
            maximum,
        )?;
        ensure!(
            response.status == 200,
            "protected object version unavailable (HTTP {})",
            response.status
        );
        ensure!(
            self.version(&response)? == version,
            "provider returned a different object version"
        );
        Ok(response)
    }
    /// Atomically create with retention or validate/extend an identical existing version.
    /// Success requires exact-version byte readback, strong retention, and unchanged latest.
    pub fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        ensure!(!self.0.recovery_only, "recovery-only backend cannot write");
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_OBJECT,
            "protected object size is outside safety limits"
        );
        ensure!(
            self.0.required_until > self.0.clock.now(),
            "required retention deadline has expired"
        );
        let mut initial = self.head(path, None)?;
        if initial.status == 404 {
            let mut headers = HeaderMap::new();
            put(&mut headers, "if-none-match", "*")?;
            self.protection_headers(&mut headers)?;
            if matches!(self.0.provider, Provider::Azure { .. }) {
                put(&mut headers, "x-ms-blob-type", "BlockBlob")?;
            }
            checksum(&mut headers, &bytes)?;
            let created = self.request(
                Method::PUT,
                self.object_url(path, None, false)?,
                headers,
                bytes.clone(),
                MAX_CONTROL,
            )?;
            ensure!(
                (200..300).contains(&created.status)
                    || created.status == 412
                    || created.status == 409,
                "conditional protected creation failed (HTTP {})",
                created.status
            );
            initial = self.head(path, None)?;
            if (200..300).contains(&created.status) {
                ensure!(
                    self.version(&created)? == self.version(&initial)?,
                    "latest version changed after conditional creation"
                );
            }
        }
        ensure!(
            initial.status == 200,
            "protected object metadata unavailable (HTTP {})",
            initial.status
        );
        let version = self.version(&initial)?;
        let readback = self.read_version(path, &version, bytes.len() as u64)?;
        ensure!(
            readback.body == bytes,
            "existing protected object ciphertext differs; overwrite refused"
        );
        // Do not infer retention from a successful write or from config. HEAD this version.
        let before = self.head(path, Some(&version))?;
        ensure!(
            before.status == 200 && self.version(&before)? == version,
            "version metadata binding failed"
        );
        let retention = self.retention(&before)?;
        if retention
            .as_ref()
            .is_none_or(|(_, date)| *date < self.0.required_until)
        {
            self.apply_retention(path, &version)?;
        }
        let verified = self.head(path, Some(&version))?;
        ensure!(
            verified.status == 200 && self.version(&verified)? == version,
            "retention verification version mismatch"
        );
        let (mode, until) = self
            .retention(&verified)?
            .context("provider retention is missing after application")?;
        ensure!(
            until >= self.0.required_until
                && until > self.0.clock.now()
                && until > response_time(&verified)?,
            "provider retention does not cover required minimum"
        );
        let latest = self.head(path, None)?;
        ensure!(
            latest.status == 200 && self.version(&latest)? == version,
            "latest pointer changed during protection verification; refusing publication"
        );
        ensure!(
            until > response_time(&latest)? && self.0.required_until > self.0.clock.now(),
            "retention deadline expired during verification"
        );
        let proof = ObjectProof {
            version,
            retain_until: until,
            mode,
            bytes: bytes.len() as u64,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
        };
        let mut proofs = self
            .0
            .proofs
            .lock()
            .map_err(|_| anyhow!("protected evidence lock failed"))?;
        ensure!(
            proofs.objects.len() < 100_000 || proofs.objects.contains_key(path),
            "protected evidence exceeds object limit"
        );
        let estimated_bytes = proofs.estimated_bytes
            - proofs
                .objects
                .get(path)
                .map(|p| proof_size(path, p))
                .unwrap_or(0)
            + proof_size(path, &proof);
        ensure!(
            estimated_bytes <= 32 * 1024 * 1024,
            "protected evidence exceeds byte limit"
        );
        proofs.estimated_bytes = estimated_bytes;
        proofs.objects.insert(path.to_owned(), proof);
        Ok(())
    }
    /// Saved evidence pins versions across delete markers and replacement latest versions.
    /// Without saved evidence the current version must itself prove strong retention.
    pub fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        ensure!(
            maximum <= MAX_OBJECT,
            "protected read limit exceeds safety cap"
        );
        let saved = self
            .0
            .proofs
            .lock()
            .map_err(|_| anyhow!("protected evidence lock failed"))?
            .objects
            .get(path)
            .cloned();
        ensure!(
            !self.0.recovery_only || saved.is_some(),
            "recovery requires saved evidence for every object"
        );
        let version = if let Some(proof) = &saved {
            proof.version.clone()
        } else {
            let head = self.head(path, None)?;
            ensure!(head.status == 200, "protected object unavailable");
            self.version(&head)?
        };
        let response = self.read_version(path, &version, maximum)?;
        if self.0.recovery_only {
            let proof = saved.context("recovery evidence missing")?;
            ensure!(
                response.body.len() as u64 == proof.bytes
                    && blake3::hash(&response.body).to_hex().as_str() == proof.blake3,
                "saved protected object evidence mismatch"
            );
            return Ok(response.body);
        }
        let metadata = self.head(path, Some(&version))?;
        ensure!(
            metadata.status == 200 && self.version(&metadata)? == version,
            "protected read metadata version mismatch"
        );
        let (_, until) = self
            .retention(&metadata)?
            .context("protected read has no retention evidence")?;
        ensure!(
            until > self.0.clock.now() && until > response_time(&metadata)?,
            "protected read retention has expired; use saved evidence with recovery-only mode"
        );
        if let Some(proof) = &saved {
            ensure!(
                until >= proof.retain_until
                    && response.body.len() as u64 == proof.bytes
                    && blake3::hash(&response.body).to_hex().as_str() == proof.blake3,
                "saved protected object evidence mismatch"
            );
        } else {
            ensure!(
                until >= self.0.required_until,
                "current object retention does not meet required minimum"
            );
        }
        Ok(response.body)
    }
}

impl crate::checkpoint::RemoteStore for ProtectedBackend {
    async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        let backend = self.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            ProtectedBackend::read_bounded(&backend, &path, maximum)
        })
        .await
        .map_err(|_| anyhow!("protected read task failed"))?
    }
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        let backend = self.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            ProtectedBackend::create_verified(&backend, &path, bytes)
        })
        .await
        .map_err(|_| anyhow!("protected write task failed"))?
    }
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 2048
            && path.split('/').all(|s| !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))),
        "invalid protected object path"
    );
    Ok(())
}
fn validate_container(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
            && value != "."
            && value != "..",
        "invalid protected bucket/container"
    );
    Ok(())
}
fn validate_version(version: &str) -> Result<()> {
    ensure!(
        !version.is_empty()
            && version != "null"
            && version.len() <= 1024
            && !version.chars().any(char::is_control),
        "provider version ID is missing or invalid"
    );
    Ok(())
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    ensure!(
        headers.get_all(name).iter().count() <= 1,
        "duplicate provider evidence header"
    );
    headers
        .get(name)
        .map(|v| {
            v.to_str()
                .map_err(|_| anyhow!("invalid provider evidence header"))
        })
        .transpose()
}
fn response_time(response: &Response) -> Result<DateTime<Utc>> {
    let date = header(&response.headers, "date")?.context("provider Date header missing")?;
    httpdate::parse_http_date(date)
        .map(DateTime::<Utc>::from)
        .map_err(|_| anyhow!("invalid provider Date header"))
}
fn put(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let mut value =
        HeaderValue::from_str(value).map_err(|_| anyhow!("invalid protected request header"))?;
    if matches!(name, "authorization" | "x-amz-security-token") {
        value.set_sensitive(true);
    }
    headers.insert(name, value);
    Ok(())
}
fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn checksum(headers: &mut HeaderMap, bytes: &[u8]) -> Result<()> {
    let md5 = openssl::hash::hash(openssl::hash::MessageDigest::md5(), bytes)
        .map_err(|_| anyhow!("request checksum computation failed"))?;
    put(headers, "content-md5", &STANDARD.encode(md5))
}
fn encode(value: &str) -> String {
    let mut result = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            result.push(char::from(b));
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}
fn hmac(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| anyhow!("request signature initialization failed"))?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}
fn sign(provider: &Provider, request: &mut Request, now: DateTime<Utc>) -> Result<()> {
    let host = match request.url.port() {
        Some(port) => format!(
            "{}:{port}",
            request.url.host_str().context("request host missing")?
        ),
        None => request
            .url
            .host_str()
            .context("request host missing")?
            .to_owned(),
    };
    put(&mut request.headers, "host", &host)?;
    put(
        &mut request.headers,
        "content-length",
        &request.body.len().to_string(),
    )?;
    match provider {
        Provider::S3 {
            region,
            access,
            secret,
            token,
        } => {
            put(
                &mut request.headers,
                "x-amz-date",
                &now.format("%Y%m%dT%H%M%SZ").to_string(),
            )?;
            let payload = hex::encode(Sha256::digest(&request.body));
            put(&mut request.headers, "x-amz-content-sha256", &payload)?;
            if let Some(token) = token {
                put(&mut request.headers, "x-amz-security-token", token)?;
            }
            let canonical: BTreeMap<_, _> = request
                .headers
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.as_str().to_owned(),
                        v.to_str()
                            .map_err(|_| anyhow!("invalid signing header"))?
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                })
                .collect::<Result<_>>()?;
            let header_names = canonical.keys().cloned().collect::<Vec<_>>().join(";");
            let canonical_headers = canonical
                .iter()
                .map(|(k, v)| format!("{k}:{v}\n"))
                .collect::<String>();
            let canonical_request = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                request.method,
                request.url.path(),
                request.url.query().unwrap_or_default(),
                canonical_headers,
                header_names,
                payload
            );
            let date = now.format("%Y%m%d").to_string();
            let scope = format!("{date}/{region}/s3/aws4_request");
            let to_sign = format!(
                "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
                now.format("%Y%m%dT%H%M%SZ"),
                hex::encode(Sha256::digest(canonical_request.as_bytes()))
            );
            let initial = Zeroizing::new(format!("AWS4{}", secret.as_str()));
            let date_key = Zeroizing::new(hmac(initial.as_bytes(), date.as_bytes())?);
            let region_key = Zeroizing::new(hmac(&date_key, region.as_bytes())?);
            let service_key = Zeroizing::new(hmac(&region_key, b"s3")?);
            let signing_key = Zeroizing::new(hmac(&service_key, b"aws4_request")?);
            let signature = hex::encode(hmac(&signing_key, to_sign.as_bytes())?);
            put(&mut request.headers, "authorization", &format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={header_names}, Signature={signature}", access.as_str()))?;
        }
        Provider::Azure { account, key } => {
            put(
                &mut request.headers,
                "x-ms-date",
                &httpdate::fmt_http_date(now.into()),
            )?;
            put(&mut request.headers, "x-ms-version", API_VERSION)?;
            let mut fields = vec![request.method.as_str().to_owned()];
            for name in [
                "content-encoding",
                "content-language",
                "content-length",
                "content-md5",
                "content-type",
                "date",
                "if-modified-since",
                "if-match",
                "if-none-match",
                "if-unmodified-since",
                "range",
            ] {
                let value = header(&request.headers, name)?.unwrap_or_default();
                fields.push(if name == "content-length" && value == "0" {
                    String::new()
                } else {
                    value.to_owned()
                });
            }
            let canonical: BTreeMap<_, _> = request
                .headers
                .iter()
                .filter(|(k, _)| k.as_str().starts_with("x-ms-"))
                .map(|(k, v)| {
                    Ok((
                        k.as_str(),
                        v.to_str()
                            .map_err(|_| anyhow!("invalid Azure signing header"))?
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                })
                .collect::<Result<_>>()?;
            let mut to_sign = fields.join("\n") + "\n";
            for (k, v) in canonical {
                to_sign.push_str(&format!("{k}:{v}\n"));
            }
            to_sign.push_str(&format!("/{account}{}", request.url.path()));
            let query: BTreeMap<_, _> = request
                .url
                .query_pairs()
                .map(|(k, v)| (k.to_lowercase(), v.into_owned()))
                .collect();
            for (k, v) in query {
                to_sign.push_str(&format!("\n{k}:{v}"));
            }
            put(
                &mut request.headers,
                "authorization",
                &format!(
                    "SharedKey {account}:{}",
                    STANDARD.encode(hmac(key, to_sign.as_bytes())?)
                ),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use reqsign_core::{ProvideCredential, SignRequest};

    /// Compare the custom wire signatures against the existing independently maintained
    /// signers, with no HTTP, environment, metadata, certificate or profile provider.
    #[test]
    fn s3_and_azure_rest_signatures_match_reqsign_offline() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let context = reqsign_core::Context::new();
            for azure in [false, true] {
                let provider = if azure {
                    Provider::Azure { account: "fixture".into(), key: Zeroizing::new(vec![0;32]) }
                } else {
                    Provider::S3 { region: "us-east-1".into(), access: Zeroizing::new("AKIDEXAMPLE".into()), secret: Zeroizing::new("fixture-only-secret".into()), token: Some(Zeroizing::new("fixture-session-token".into())) }
                };
                for method in [Method::GET, Method::HEAD, Method::PUT] {
                    let url = Url::parse(if azure { "https://fixture.blob.core.windows.net/backup/repo/chunks/key?comp=immutabilityPolicies&versionid=v%2B%2F%3D%20one" } else { "https://s3.us-east-1.amazonaws.com/backup/repo/chunks/key?retention=&versionId=v%2B%2F%3D%20one" }).unwrap();
                    let mut request = Request { method, url, headers: HeaderMap::new(), body: b"encrypted fixture".to_vec(), maximum_response: MAX_CONTROL };
                    checksum(&mut request.headers, &request.body).unwrap();
                    put(&mut request.headers, "if-none-match", "*").unwrap();
                    if azure { put(&mut request.headers, "x-ms-immutability-policy-mode", "Locked").unwrap(); }
                    else { put(&mut request.headers, "x-amz-object-lock-mode", "COMPLIANCE").unwrap(); }
                    sign(&provider,&mut request,Utc::now()).unwrap();
                    let mut native = http::Request::builder().method(request.method.clone()).uri(request.url.as_str()).body(()).unwrap().into_parts().0;
                    native.headers = request.headers.clone(); native.headers.remove("authorization");
                    let signed_at = if azure {
                        let credentials = reqsign_azure_storage::StaticCredentialProvider::new_shared_key("fixture",&STANDARD.encode([0;32])).provide_credential(&context).await.unwrap().unwrap();
                        reqsign_azure_storage::RequestSigner::new().sign_request(&context,&mut native,Some(&credentials),None).await.unwrap();
                        DateTime::<Utc>::from(httpdate::parse_http_date(native.headers["x-ms-date"].to_str().unwrap()).unwrap())
                    } else {
                        let credentials = reqsign_aws_v4::StaticCredentialProvider::new("AKIDEXAMPLE","fixture-only-secret").with_session_token("fixture-session-token").provide_credential(&context).await.unwrap().unwrap();
                        reqsign_aws_v4::RequestSigner::new("s3","us-east-1").sign_request(&context,&mut native,Some(&credentials),None).await.unwrap();
                        chrono::NaiveDateTime::parse_from_str(native.headers["x-amz-date"].to_str().unwrap(),"%Y%m%dT%H%M%SZ").unwrap().and_utc()
                    };
                    // Copy the reference signer's timestamp to eliminate second-boundary races.
                    request.headers.remove("authorization");
                    sign(&provider,&mut request,signed_at).unwrap();
                    assert_eq!(request.headers["authorization"],native.headers["authorization"],"provider {} method {}",if azure {"Azure"} else {"S3"},request.method);
                }
            }
        });
    }
}
