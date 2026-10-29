//! Exact-ID encrypted object storage for Google Drive and OneDrive.
//! See docs/consumer-storage.md: these services provide no WORM/retention guarantee.
use anyhow::{anyhow, bail, ensure, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use http::{HeaderMap, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;
use zeroize::Zeroizing;

pub const MAX_OBJECT: u64 = 64 * 1024 * 1024;
pub const MAX_EVIDENCE: usize = 16 * 1024 * 1024;
pub const MAX_PROOFS: usize = 10_000;
const MAX_CONTROL: u64 = 64 * 1024;

/// No Debug: URLs, headers and bodies may contain credentials or ciphertext.
pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub maximum_response: u64,
}
pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}
#[derive(Debug)]
pub struct TransportError;
/// Implementations must bound streaming bodies before allocation, verify TLS, disable
/// redirects and never log requests/responses. Production uses fixed provider origins.
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
#[derive(Debug)]
pub struct PersistenceError;
/// Success means the complete replacement token is durably stored privately (including
/// fsync/atomic replacement where applicable), and available on restart. Never log it.
/// `reference` is the configured refresh-token environment variable NAME.
pub trait RefreshTokenSink: Send + Sync {
    /// Durably guard this attempt before network access. Fail if an attempt is
    /// already pending; `load` must fail while guarded, including after restart.
    /// Store only a hash of the attempted token in the private pending marker.
    fn begin_refresh(
        &self,
        reference: &str,
        token: &str,
    ) -> std::result::Result<(), PersistenceError>;
    /// Durably clear a guard after a known safe outcome. Must support retry after
    /// a failed cleanup (including removal followed by a directory-sync failure).
    fn finish_refresh(&self, reference: &str) -> std::result::Result<(), PersistenceError>;
    /// Read the last durably saved rotation for this explicit reference. A read error
    /// MUST be returned, never disguised as absence: stale env fallback is unsafe.
    /// Bind the sink to provider location and client identity outside this adapter.
    /// Production sinks must override this to reject pending refresh guards,
    /// even when no replacement credential has ever been saved.
    fn load(
        &self,
        _reference: &str,
    ) -> std::result::Result<Option<Zeroizing<String>>, PersistenceError> {
        Ok(None)
    }
    fn persist(&self, reference: &str, token: &str) -> std::result::Result<(), PersistenceError>;
}
/// Success means this entire map is durably saved outside the consumer backend.
/// Serialize concurrent writers at the caller; use one evidence store per location.
pub trait EvidenceSink: Send + Sync {
    fn persist(&self, evidence: &ConsumerEvidence) -> std::result::Result<(), PersistenceError>;
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
                .map_err(|_| anyhow!("consumer HTTPS initialization failed"))?,
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
            .take(request.maximum_response.saturating_add(1))
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerLocation {
    pub service: String,
    pub drive_id: Option<String>,
    /// Existing folder ID, never a name/path to resolve by listing.
    pub root: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Revision {
    /// Exact retained binary revision; keepForever is not an administrative lock.
    Google { revision_id: String },
    /// Exact observed item revision tags, NOT a Graph historical version ID.
    /// Recovery fails closed if these change; historical recovery is not promised.
    OneDrive { etag: String, ctag: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectProof {
    pub file_id: String,
    pub revision: Revision,
    pub bytes: u64,
    pub blake3: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerEvidence {
    pub version: u32,
    pub location: ConsumerLocation,
    pub objects: BTreeMap<String, ObjectProof>,
}
impl ConsumerEvidence {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EVIDENCE,
            "consumer evidence exceeds limit"
        );
        let evidence: Self =
            serde_json::from_slice(bytes).map_err(|_| anyhow!("invalid consumer evidence"))?;
        evidence.validate()?;
        Ok(evidence)
    }
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| anyhow!("consumer evidence encoding failed"))?;
        ensure!(
            bytes.len() <= MAX_EVIDENCE,
            "consumer evidence exceeds limit"
        );
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.objects.len() <= MAX_PROOFS,
            "invalid consumer evidence version or count"
        );
        validate_location(&self.location)?;
        for (path, proof) in &self.objects {
            validate_path(path)?;
            validate_id(&proof.file_id)?;
            ensure!(
                proof.bytes > 0 && proof.bytes <= MAX_OBJECT && is_hash(&proof.blake3),
                "invalid consumer object proof"
            );
            match &proof.revision {
                Revision::Google { revision_id } => {
                    ensure!(
                        self.location.service == "gdrive",
                        "consumer evidence provider mismatch"
                    );
                    validate_id(revision_id)?;
                }
                Revision::OneDrive { etag, ctag } => {
                    ensure!(
                        self.location.service == "onedrive",
                        "consumer evidence provider mismatch"
                    );
                    validate_tag(etag)?;
                    validate_tag(ctag)?;
                }
            }
        }
        let encoded =
            serde_json::to_vec(self).map_err(|_| anyhow!("consumer evidence encoding failed"))?;
        ensure!(
            encoded.len() <= MAX_EVIDENCE,
            "consumer evidence exceeds limit"
        );
        Ok(())
    }
}

struct OAuth {
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
    refresh: Zeroizing<String>,
    reference: String,
    access: Option<(Zeroizing<String>, DateTime<Utc>)>,
    pending_rotation: bool,
    pending_finish: bool,
    refresh_uncertain: bool,
}
struct Inner {
    location: ConsumerLocation,
    oauth: Mutex<OAuth>,
    evidence: Mutex<ConsumerEvidence>,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
    tokens: Arc<dyn RefreshTokenSink>,
    sink: Arc<dyn EvidenceSink>,
    recovery_only: bool,
}
pub(crate) fn validated_location(
    config: &crate::storage::StorageConfig,
) -> Result<ConsumerLocation> {
    ensure!(
        !config.immutable,
        "consumer storage cannot provide verified retention or WORM"
    );
    ensure!(
        config
            .options
            .keys()
            .all(|k| matches!(k.as_str(), "root" | "drive_id")),
        "unsupported consumer option"
    );
    let location = ConsumerLocation {
        service: config.service.clone(),
        drive_id: config.options.get("drive_id").cloned(),
        root: config
            .options
            .get("root")
            .cloned()
            .ok_or_else(|| anyhow!("explicit folder ID root is required"))?,
    };
    validate_location(&location)?;
    ensure!(config.credential_env.len() == 3 && config.credential_env.keys().all(|k| matches!(k.as_str(), "client_id" | "client_secret" | "refresh_token")),
        "consumer OAuth requires exactly client_id, client_secret and refresh_token environment references");
    for reference in config.credential_env.values() {
        ensure!(
            !reference.is_empty()
                && reference.len() <= 256
                && reference
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            "invalid OAuth environment reference"
        );
    }
    Ok(location)
}

#[derive(Clone)]
pub struct ConsumerBackend(Arc<Inner>);
impl ConsumerBackend {
    /// Fresh publication session. Resume using saved evidence to reuse exact IDs.
    pub fn new(
        config: &crate::storage::StorageConfig,
        tokens: Arc<dyn RefreshTokenSink>,
        sink: Arc<dyn EvidenceSink>,
    ) -> Result<Self> {
        Self::with_transport(
            config,
            None,
            false,
            Arc::new(HttpsTransport::new()?),
            Arc::new(SystemClock),
            |name| std::env::var(name).ok(),
            tokens,
            sink,
        )
    }
    /// Saved evidence is mandatory for recovery; `recovery_only` forbids publication.
    pub fn from_evidence(
        config: &crate::storage::StorageConfig,
        evidence: &ConsumerEvidence,
        recovery_only: bool,
        tokens: Arc<dyn RefreshTokenSink>,
        sink: Arc<dyn EvidenceSink>,
    ) -> Result<Self> {
        Self::with_transport(
            config,
            Some(evidence),
            recovery_only,
            Arc::new(HttpsTransport::new()?),
            Arc::new(SystemClock),
            |name| std::env::var(name).ok(),
            tokens,
            sink,
        )
    }
    /// Production verified HTTPS with explicit-reference resolution. A persisted
    /// refresh token from the sink takes precedence over this resolver too.
    pub fn with_resolver(
        config: &crate::storage::StorageConfig,
        evidence: Option<&ConsumerEvidence>,
        recovery_only: bool,
        resolve: impl Fn(&str) -> Option<String>,
        tokens: Arc<dyn RefreshTokenSink>,
        sink: Arc<dyn EvidenceSink>,
    ) -> Result<Self> {
        Self::with_transport(
            config,
            evidence,
            recovery_only,
            Arc::new(HttpsTransport::new()?),
            Arc::new(SystemClock),
            resolve,
            tokens,
            sink,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn with_transport(
        config: &crate::storage::StorageConfig,
        evidence: Option<&ConsumerEvidence>,
        recovery_only: bool,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        resolve: impl Fn(&str) -> Option<String>,
        tokens: Arc<dyn RefreshTokenSink>,
        sink: Arc<dyn EvidenceSink>,
    ) -> Result<Self> {
        let location = validated_location(config)?;
        let credential = |key: &str| -> Result<Zeroizing<String>> {
            let reference = config
                .credential_env
                .get(key)
                .ok_or_else(|| anyhow!("explicit OAuth reference missing"))?;
            ensure!(
                !reference.is_empty()
                    && reference.len() <= 256
                    && reference
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "invalid OAuth environment reference"
            );
            let stored = if key == "refresh_token" {
                tokens.load(reference).map_err(|_| anyhow!("private OAuth token-store read failed; refusing stale environment fallback"))?
            } else {
                None
            };
            let value = match stored {
                Some(value) => value,
                None => Zeroizing::new(
                    resolve(reference)
                        .ok_or_else(|| anyhow!("explicit OAuth credential unavailable"))?,
                ),
            };
            ensure!(
                !value.is_empty() && value.len() <= 16384 && !value.chars().any(char::is_control),
                "invalid explicit OAuth credential"
            );
            Ok(value)
        };
        ensure!(
            !recovery_only || evidence.is_some(),
            "recovery requires saved external consumer evidence"
        );
        let evidence = match evidence {
            Some(saved) => {
                saved.validate()?;
                ensure!(
                    saved.location == location,
                    "consumer evidence location mismatch"
                );
                saved.clone()
            }
            None => ConsumerEvidence {
                version: 1,
                location: location.clone(),
                objects: BTreeMap::new(),
            },
        };
        Ok(Self(Arc::new(Inner {
            location,
            oauth: Mutex::new(OAuth {
                client_id: credential("client_id")?,
                client_secret: credential("client_secret")?,
                refresh: credential("refresh_token")?,
                reference: config.credential_env["refresh_token"].clone(),
                access: None,
                pending_rotation: false,
                pending_finish: false,
                refresh_uncertain: false,
            }),
            evidence: Mutex::new(evidence),
            transport,
            clock,
            tokens,
            sink,
            recovery_only,
        })))
    }
    /// Export includes a pending verified proof if its durable sink previously failed.
    /// A successful create_verified, not this accessor, acknowledges durable persistence.
    pub fn evidence(&self) -> Result<ConsumerEvidence> {
        Ok(self
            .0
            .evidence
            .lock()
            .map_err(|_| anyhow!("consumer evidence lock failed"))?
            .clone())
    }
    fn send(&self, request: Request) -> Result<Response> {
        let max = request.maximum_response;
        let result = self
            .0
            .transport
            .send(request)
            .map_err(|_| anyhow!("consumer HTTPS request failed; outcome may be unknown"))?;
        ensure!(
            result.body.len() as u64 <= max
                && result
                    .headers
                    .iter()
                    .map(|(k, v)| k.as_str().len() + v.len())
                    .sum::<usize>()
                    <= 65536,
            "consumer response exceeds limit"
        );
        ensure!(
            !(300..400).contains(&result.status),
            "consumer redirects are forbidden"
        );
        Ok(result)
    }
    fn access_token(&self) -> Result<Zeroizing<String>> {
        let mut oauth = self
            .0
            .oauth
            .lock()
            .map_err(|_| anyhow!("consumer OAuth lock failed"))?;
        if oauth.pending_rotation {
            self.0.tokens.persist(&oauth.reference, &oauth.refresh).map_err(|_| anyhow!("rotated OAuth credential requires durable private token-store persistence or operator rebinding; session retained it for retry"))?;
            oauth.pending_rotation = false;
            oauth.pending_finish = true;
        }
        if oauth.pending_finish {
            self.finish_refresh(&mut oauth)?;
        }
        ensure!(!oauth.refresh_uncertain, "OAuth refresh outcome uncertain; rebind from private token store or reauthorize before retrying");
        let now = self.0.clock.now();
        if let Some((token, expires)) = &oauth.access {
            if *expires > now + ChronoDuration::seconds(30) {
                return Ok(token.clone());
            }
        }
        oauth.access = None;
        self.0.tokens.begin_refresh(&oauth.reference, &oauth.refresh).map_err(|_| anyhow!("OAuth refresh requires durable private token-store intent or operator rebinding"))?;
        // Never retry a refresh automatically: a lost response may contain a rotated token.
        oauth.refresh_uncertain = true;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", &oauth.client_id)
            .append_pair("client_secret", &oauth.client_secret)
            .append_pair("refresh_token", &oauth.refresh)
            .finish();
        let endpoint = if self.google() {
            "https://oauth2.googleapis.com/token"
        } else {
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        };
        let response = self.send(Request {
            method: Method::POST,
            url: fixed_url(endpoint)?,
            headers: HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )]),
            body: body.into_bytes(),
            maximum_response: MAX_CONTROL,
        })?;
        ensure!(
            response.status == 200,
            "OAuth refresh rejected; operator rebinding or reauthorization required"
        );
        #[derive(Deserialize)]
        struct Token {
            refresh_token: Option<String>,
            access_token: Option<serde_json::Value>,
            token_type: Option<serde_json::Value>,
            expires_in: Option<serde_json::Value>,
        }
        let token: Token = serde_json::from_slice(&response.body).map_err(|_| {
            anyhow!("invalid OAuth response; operator credential recovery may be required")
        })?;
        if let Some(rotated) = token.refresh_token {
            let rotated = Zeroizing::new(rotated);
            ensure!(
                valid_secret(&rotated),
                "invalid rotated OAuth credential; operator rebinding required"
            );
            if *rotated != *oauth.refresh {
                oauth.refresh = rotated;
                oauth.pending_rotation = true;
                // Keep the guard until the replacement is durably saved, even
                // when the rest of the response is malformed.
                self.0.tokens.persist(&oauth.reference, &oauth.refresh).map_err(|_| anyhow!("rotated OAuth credential requires durable private token-store persistence or operator rebinding; session retained it for retry"))?;
                oauth.pending_rotation = false;
                oauth.pending_finish = true;
                self.finish_refresh(&mut oauth)?;
            }
        }
        let access = Zeroizing::new(token.access_token.and_then(|v| match v {
            serde_json::Value::String(value) => Some(value), _ => None,
        }).ok_or_else(|| anyhow!("OAuth access token missing or invalid; credential rebinding may be required"))?);
        ensure!(
            valid_secret(&access)
                && token
                    .token_type
                    .as_ref()
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| s.eq_ignore_ascii_case("Bearer")),
            "invalid OAuth access token response"
        );
        let lifetime = token
            .expires_in
            .as_ref()
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow!("OAuth expiry missing"))?;
        ensure!((60..=86400).contains(&lifetime), "invalid OAuth expiry");
        oauth.access = Some((access.clone(), now + ChronoDuration::seconds(lifetime)));
        if oauth.refresh_uncertain {
            oauth.pending_finish = true;
            self.finish_refresh(&mut oauth)?;
        }
        Ok(access)
    }
    fn finish_refresh(&self, oauth: &mut OAuth) -> Result<()> {
        self.0.tokens.finish_refresh(&oauth.reference).map_err(|_| anyhow!("OAuth refresh requires durable private token-store completion or operator rebinding; session retained completion for retry"))?;
        oauth.pending_finish = false;
        oauth.refresh_uncertain = false;
        Ok(())
    }
    fn api(
        &self,
        method: Method,
        url: Url,
        mut headers: HeaderMap,
        body: Vec<u8>,
        maximum_response: u64,
    ) -> Result<Response> {
        let token = self.access_token()?;
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
            .map_err(|_| anyhow!("invalid OAuth authorization"))?;
        value.set_sensitive(true);
        headers.insert(http::header::AUTHORIZATION, value);
        self.send(Request {
            method,
            url,
            headers,
            body,
            maximum_response,
        })
    }
    fn google(&self) -> bool {
        self.0.location.service == "gdrive"
    }
    fn google_file(&self, id: &str) -> Result<Url> {
        let mut url = fixed_url("https://www.googleapis.com/drive/v3/files/")?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("invalid provider URL"))?
            .pop_if_empty()
            .push(id);
        url.query_pairs_mut()
            .append_pair("supportsAllDrives", "true");
        Ok(url)
    }
    fn graph_item(&self, id: &str) -> Result<Url> {
        let mut url = fixed_url("https://graph.microsoft.com/v1.0/drives/")?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("invalid provider URL"))?
            .pop_if_empty()
            .push(
                self.0
                    .location
                    .drive_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("drive ID missing"))?,
            )
            .push("items")
            .push(id);
        Ok(url)
    }
    fn google_revision(&self, id: &str, revision: &str) -> Result<Url> {
        let mut url = self.google_file(id)?;
        url.set_query(None);
        url.path_segments_mut()
            .map_err(|_| anyhow!("invalid provider URL"))?
            .push("revisions")
            .push(revision);
        Ok(url)
    }
    fn google_metadata(&self, id: &str) -> Result<GoogleFile> {
        let mut url = self.google_file(id)?;
        url.query_pairs_mut().append_pair(
            "fields",
            "id,mimeType,parents,driveId,trashed,size,headRevisionId",
        );
        let response = self.api(Method::GET, url, HeaderMap::new(), vec![], MAX_CONTROL)?;
        decode_ok(response, &[200])
    }
    fn graph_metadata(&self, id: &str) -> Result<DriveItem> {
        let response = self.api(
            Method::GET,
            self.graph_item(id)?,
            HeaderMap::new(),
            vec![],
            MAX_CONTROL,
        )?;
        decode_ok(response, &[200])
    }
    fn check_google(&self, metadata: &GoogleFile, id: &str) -> Result<()> {
        ensure!(
            metadata.id == id
                && metadata.trashed == Some(false)
                && metadata.mime_type == "application/octet-stream"
                && metadata
                    .parents
                    .as_ref()
                    .is_some_and(|p| p == std::slice::from_ref(&self.0.location.root))
                && metadata.drive_id == self.0.location.drive_id,
            "Google object identity or location mismatch"
        );
        Ok(())
    }
    fn check_graph(&self, metadata: &DriveItem, id: &str) -> Result<()> {
        ensure!(
            metadata.id == id
                && metadata.file.is_some()
                && metadata.folder.is_none()
                && metadata.deleted.is_none()
                && metadata.remote_item.is_none()
                && metadata
                    .parent_reference
                    .as_ref()
                    .is_some_and(|p| Some(&p.drive_id) == self.0.location.drive_id.as_ref()
                        && p.id == self.0.location.root),
            "OneDrive object identity or location mismatch"
        );
        validate_tag(&metadata.etag)?;
        validate_tag(&metadata.ctag)?;
        Ok(())
    }
    fn read_proof(&self, proof: &ObjectProof, maximum: u64) -> Result<Vec<u8>> {
        ensure!(
            proof.bytes <= maximum.min(MAX_OBJECT),
            "consumer object exceeds read limit"
        );
        let bytes = match &proof.revision {
            Revision::Google { revision_id } => {
                let metadata = self.google_metadata(&proof.file_id)?;
                self.check_google(&metadata, &proof.file_id)?;
                let mut url = self.google_revision(&proof.file_id, revision_id)?;
                url.query_pairs_mut()
                    .append_pair("fields", "id,keepForever,size,mimeType");
                let revision: GoogleRevision = decode_ok(
                    self.api(Method::GET, url, HeaderMap::new(), vec![], MAX_CONTROL)?,
                    &[200],
                )?;
                ensure!(
                    revision.id == *revision_id
                        && revision.keep_forever
                        && revision.size.parse::<u64>().ok() == Some(proof.bytes)
                        && revision.mime_type == "application/octet-stream",
                    "Google revision proof mismatch"
                );
                let mut url = self.google_revision(&proof.file_id, revision_id)?;
                url.query_pairs_mut().append_pair("alt", "media");
                let response = self.api(Method::GET, url, HeaderMap::new(), vec![], proof.bytes)?;
                ensure!(response.status == 200, "Google revision download failed");
                response.body
            }
            Revision::OneDrive { etag, ctag } => {
                let metadata = self.graph_metadata(&proof.file_id)?;
                self.check_graph(&metadata, &proof.file_id)?;
                ensure!(
                    metadata.etag == *etag
                        && metadata.ctag == *ctag
                        && metadata.size == proof.bytes,
                    "OneDrive saved revision no longer current"
                );
                let url = capability_url(
                    metadata
                        .download_url
                        .as_deref()
                        .ok_or_else(|| anyhow!("OneDrive download URL missing"))?,
                    false,
                )?;
                // This URL is a short-lived bearer capability. Do not forward OAuth headers.
                let response = self.send(Request {
                    method: Method::GET,
                    url,
                    headers: HeaderMap::new(),
                    body: vec![],
                    maximum_response: proof.bytes,
                })?;
                ensure!(response.status == 200, "OneDrive direct download failed");
                let after = self.graph_metadata(&proof.file_id)?;
                self.check_graph(&after, &proof.file_id)?;
                ensure!(
                    after.etag == *etag && after.ctag == *ctag && after.size == proof.bytes,
                    "OneDrive revision changed during read"
                );
                response.body
            }
        };
        ensure!(
            bytes.len() as u64 == proof.bytes
                && blake3::hash(&bytes).to_hex().as_str() == proof.blake3,
            "consumer ciphertext integrity mismatch"
        );
        Ok(bytes)
    }
    fn verify_root(&self) -> Result<()> {
        if self.google() {
            let root = self.google_metadata(&self.0.location.root)?;
            ensure!(
                root.id == self.0.location.root
                    && root.mime_type == "application/vnd.google-apps.folder"
                    && root.trashed == Some(false)
                    && root.drive_id == self.0.location.drive_id,
                "Google root is not the configured folder"
            );
        } else {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Folder {
                id: String,
                folder: Option<serde_json::Value>,
                remote_item: Option<serde_json::Value>,
                deleted: Option<serde_json::Value>,
                parent_reference: Option<ParentReference>,
            }
            let response = self.api(
                Method::GET,
                self.graph_item(&self.0.location.root)?,
                HeaderMap::new(),
                vec![],
                MAX_CONTROL,
            )?;
            let root: Folder = decode_ok(response, &[200])?;
            ensure!(
                root.id == self.0.location.root
                    && root.folder.is_some()
                    && root.remote_item.is_none()
                    && root.deleted.is_none()
                    && root
                        .parent_reference
                        .as_ref()
                        .is_some_and(|p| Some(&p.drive_id) == self.0.location.drive_id.as_ref()),
                "OneDrive root is not the configured folder"
            );
        }
        Ok(())
    }
    fn upload_google(&self, bytes: &[u8]) -> Result<ObjectProof> {
        // Initiate a new file (no existing ID in the request), then upload the body
        // once to the exact session URL. Resumable upload also supports >5 MiB objects.
        let metadata = serde_json::json!({"name": format!("bunker-{}", uuid::Uuid::new_v4().simple()),
            "parents": [self.0.location.root], "mimeType": "application/octet-stream"});
        let mut url = fixed_url("https://www.googleapis.com/upload/drive/v3/files")?;
        url.query_pairs_mut()
            .append_pair("uploadType", "resumable")
            .append_pair("supportsAllDrives", "true")
            .append_pair(
                "fields",
                "id,mimeType,parents,driveId,trashed,size,headRevisionId",
            );
        let mut headers = json_headers();
        headers.insert(
            "x-upload-content-type",
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            "x-upload-content-length",
            HeaderValue::from_str(&bytes.len().to_string())
                .map_err(|_| anyhow!("invalid Google object size"))?,
        );
        let session = self.api(
            Method::POST,
            url,
            headers,
            serde_json::to_vec(&metadata)?,
            MAX_CONTROL,
        )?;
        ensure!(session.status == 200, "Google upload session rejected");
        let location = session
            .headers
            .get(http::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| anyhow!("Google upload session URL missing"))?;
        let upload_url = google_upload_url(location)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&bytes.len().to_string())
                .map_err(|_| anyhow!("invalid Google object size"))?,
        );
        let created: GoogleFile = decode_ok(
            self.api(
                Method::PUT,
                upload_url,
                headers,
                bytes.to_vec(),
                MAX_CONTROL,
            )?,
            &[200, 201],
        )?;
        validate_id(&created.id)?;
        self.check_google(&created, &created.id)?;
        ensure!(
            created.size.as_deref().and_then(|s| s.parse::<u64>().ok()) == Some(bytes.len() as u64),
            "Google upload size mismatch"
        );
        let revision_id = created
            .head_revision_id
            .ok_or_else(|| anyhow!("Google binary revision ID missing"))?;
        validate_id(&revision_id)?;
        let mut url = self.google_revision(&created.id, &revision_id)?;
        url.query_pairs_mut()
            .append_pair("fields", "id,keepForever,size,mimeType");
        let revision: GoogleRevision = decode_ok(
            self.api(
                Method::PATCH,
                url,
                json_headers(),
                br#"{"keepForever":true}"#.to_vec(),
                MAX_CONTROL,
            )?,
            &[200],
        )?;
        ensure!(
            revision.id == revision_id
                && revision.keep_forever
                && revision.size.parse::<u64>().ok() == Some(bytes.len() as u64)
                && revision.mime_type == "application/octet-stream",
            "Google retained revision verification failed"
        );
        Ok(ObjectProof {
            file_id: created.id,
            revision: Revision::Google { revision_id },
            bytes: bytes.len() as u64,
            blake3: blake3::hash(bytes).to_hex().to_string(),
        })
    }
    fn upload_graph(&self, bytes: &[u8]) -> Result<ObjectProof> {
        // Upload sessions explicitly enforce conflictBehavior=fail at final commit.
        // Never PUT an existing item or retry/redirect a failed commit.
        let name = format!("bunker-{}", uuid::Uuid::new_v4().simple());
        let mut url = self.graph_item(&self.0.location.root)?;
        url.set_path(&format!("{}:/{name}:/createUploadSession", url.path()));
        let body = serde_json::to_vec(&serde_json::json!({"item": {
            "name": name, "@microsoft.graph.conflictBehavior": "fail"
        }, "deferCommit": false}))?;
        let session: UploadSession = decode_ok(
            self.api(Method::POST, url, json_headers(), body, MAX_CONTROL)?,
            &[200],
        )?;
        let upload_url = capability_url(&session.upload_url, true)?;
        validate_expiry(session.expiration_date_time, self.0.clock.now())?;
        const FRAGMENT: usize = 10 * 1024 * 1024; // multiple of 320 KiB, less than 60 MiB
        for (index, fragment) in bytes.chunks(FRAGMENT).enumerate() {
            let offset = index * FRAGMENT;
            let end = offset + fragment.len();
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&fragment.len().to_string())
                    .map_err(|_| anyhow!("invalid fragment size"))?,
            );
            headers.insert(
                http::header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{}", offset, end - 1, bytes.len()))
                    .map_err(|_| anyhow!("invalid fragment range"))?,
            );
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            let response = self.send(Request {
                method: Method::PUT,
                url: upload_url.clone(),
                headers,
                body: fragment.to_vec(),
                maximum_response: MAX_CONTROL,
            })?;
            if end < bytes.len() {
                let progress: UploadProgress = decode_ok(response, &[202])?;
                ensure!(
                    progress.next_expected_ranges == [format!("{end}-")],
                    "unexpected OneDrive upload progress"
                );
                validate_expiry(progress.expiration_date_time, self.0.clock.now())?;
            } else {
                let uploaded: DriveItem = decode_ok(response, &[200, 201])?;
                validate_id(&uploaded.id)?;
                self.check_graph(&uploaded, &uploaded.id)?;
                ensure!(
                    uploaded.size == bytes.len() as u64,
                    "OneDrive upload size mismatch"
                );
                return Ok(ObjectProof {
                    file_id: uploaded.id,
                    revision: Revision::OneDrive {
                        etag: uploaded.etag,
                        ctag: uploaded.ctag,
                    },
                    bytes: bytes.len() as u64,
                    blake3: blake3::hash(bytes).to_hex().to_string(),
                });
            }
        }
        bail!("empty ciphertext cannot be uploaded")
    }
}
impl ConsumerBackend {
    fn read_sync(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        validate_path(path)?;
        let proof = self
            .0
            .evidence
            .lock()
            .map_err(|_| anyhow!("consumer evidence lock failed"))?
            .objects
            .get(path)
            .cloned()
            .ok_or_else(|| {
                anyhow!("saved exact-ID consumer evidence required; remote discovery is forbidden")
            })?;
        self.read_proof(&proof, maximum)
    }
    fn create_sync(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            !self.0.recovery_only,
            "consumer recovery backend is read-only"
        );
        validate_path(path)?;
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_OBJECT,
            "consumer ciphertext is empty or exceeds limit"
        );
        let mut evidence = self
            .0
            .evidence
            .lock()
            .map_err(|_| anyhow!("consumer evidence lock failed"))?;
        if let Some(proof) = evidence.objects.get(path) {
            ensure!(
                proof.bytes == bytes.len() as u64
                    && proof.blake3 == blake3::hash(&bytes).to_hex().as_str(),
                "consumer object conflicts with saved ciphertext"
            );
            self.read_proof(proof, bytes.len() as u64)?;
        } else {
            ensure!(
                evidence.objects.len() < MAX_PROOFS,
                "consumer proof count limit reached"
            );
            // Reserve worst-case proof budget BEFORE any upload, including maximum ID lengths.
            ensure!(
                evidence.to_vec()?.len() + 16384 <= MAX_EVIDENCE,
                "consumer proof budget exhausted"
            );
            self.verify_root()?;
            let proof = if self.google() {
                self.upload_google(&bytes)?
            } else {
                self.upload_graph(&bytes)?
            };
            self.read_proof(&proof, bytes.len() as u64)?;
            evidence.objects.insert(path.to_owned(), proof);
        }
        evidence.validate()?;
        self.0.sink.persist(&evidence).map_err(|_| {
            anyhow!(
                "consumer evidence persistence failed; do not acknowledge checkpoint publication"
            )
        })?;
        Ok(())
    }
}

impl crate::checkpoint::RemoteStore for ConsumerBackend {
    async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        validate_path(path)?;
        let backend = self.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || backend.read_sync(&path, maximum))
            .await
            .map_err(|_| anyhow!("consumer read worker failed"))?
    }
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        validate_path(path)?;
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_OBJECT,
            "consumer ciphertext is empty or exceeds limit"
        );
        let backend = self.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || backend.create_sync(&path, bytes))
            .await
            .map_err(|_| anyhow!("consumer publication worker failed"))?
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleFile {
    id: String,
    mime_type: String,
    parents: Option<Vec<String>>,
    drive_id: Option<String>,
    trashed: Option<bool>,
    size: Option<String>,
    head_revision_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleRevision {
    id: String,
    keep_forever: bool,
    size: String,
    mime_type: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParentReference {
    id: String,
    drive_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveItem {
    id: String,
    #[serde(rename = "eTag")]
    etag: String,
    #[serde(rename = "cTag")]
    ctag: String,
    size: u64,
    file: Option<serde_json::Value>,
    folder: Option<serde_json::Value>,
    deleted: Option<serde_json::Value>,
    remote_item: Option<serde_json::Value>,
    parent_reference: Option<ParentReference>,
    #[serde(rename = "@microsoft.graph.downloadUrl")]
    download_url: Option<String>,
}
fn decode_ok<T: serde::de::DeserializeOwned>(response: Response, accepted: &[u16]) -> Result<T> {
    ensure!(
        accepted.contains(&response.status),
        "consumer provider request rejected"
    );
    serde_json::from_slice(&response.body)
        .map_err(|_| anyhow!("invalid consumer provider response"))
}
fn fixed_url(value: &str) -> Result<Url> {
    Url::parse(value).map_err(|_| anyhow!("invalid consumer provider URL"))
}
fn json_headers() -> HeaderMap {
    HeaderMap::from_iter([(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    )])
}
fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16384 && !value.chars().any(char::is_control)
}
fn validate_location(value: &ConsumerLocation) -> Result<()> {
    ensure!(
        matches!(value.service.as_str(), "gdrive" | "onedrive"),
        "unsupported consumer provider"
    );
    validate_id(&value.root)?;
    // Root aliases are mutable account pointers. Require real folder/item IDs.
    ensure!(
        value.root != "root" && value.root != "me",
        "root must be an explicit folder item ID"
    );
    if let Some(drive) = &value.drive_id {
        validate_id(drive)?;
    }
    ensure!(
        value.service != "onedrive" || value.drive_id.is_some(),
        "OneDrive requires explicit drive_id"
    );
    Ok(())
}
fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-!.".contains(&b)),
        "invalid consumer provider ID"
    );
    Ok(())
}
fn validate_tag(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value.is_ascii()
            && !value.bytes().any(|b| b.is_ascii_control())
            && value != "*"
            && !value.starts_with("W/"),
        "invalid consumer revision tag"
    );
    Ok(())
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_path(value: &str) -> Result<()> {
    ensure!(value.len() <= 256, "consumer object address exceeds limit");
    let parts: Vec<_> = value.split('/').collect();
    ensure!(
        parts.len() == 3
            && is_hash(parts[0])
            && is_hash(parts[2])
            && matches!(parts[1], "headers" | "chunks" | "snapshots" | "checkpoints"),
        "consumer path must be an immutable checkpoint object address"
    );
    Ok(())
}
fn capability_url(value: &str, upload: bool) -> Result<Url> {
    ensure!(
        value.len() <= 16384,
        "OneDrive capability URL exceeds limit"
    );
    let url = fixed_url(value)?;
    let host = url.host_str().unwrap_or_default();
    let suffixes: &[&str] = if upload {
        &[".up.1drv.com", ".sharepoint.com"]
    } else {
        &[".files.1drv.com", ".storage.live.com", ".sharepoint.com"]
    };
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443)
            && suffixes.iter().any(|suffix| host.ends_with(suffix)),
        "OneDrive capability origin is outside supported public Microsoft hosts"
    );
    Ok(url)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadSession {
    upload_url: String,
    expiration_date_time: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadProgress {
    expiration_date_time: DateTime<Utc>,
    next_expected_ranges: Vec<String>,
}
fn validate_expiry(expires: DateTime<Utc>, now: DateTime<Utc>) -> Result<()> {
    ensure!(
        expires > now && expires <= now + ChronoDuration::days(1),
        "invalid OneDrive upload session expiry"
    );
    Ok(())
}

fn google_upload_url(value: &str) -> Result<Url> {
    ensure!(value.len() <= 16384, "Google upload URL exceeds limit");
    let url = fixed_url(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("www.googleapis.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path() == "/upload/drive/v3/files"
            && url
                .query_pairs()
                .filter(|(k, v)| k == "upload_id" && !v.is_empty())
                .count()
                == 1,
        "Google upload session origin or path mismatch"
    );
    Ok(url)
}
