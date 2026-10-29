//! Metadata-only host orchestration and one-shot independently approved restores.
//! No human approval API, backup deletion, executable agent probing, or automatic claim retry.
use crate::{
    control_plane::{private_directory, Method, Transport, POLICY_POLL_INTERVAL},
    policy::Policy,
    repository::{Manifest, Repository, RestorePlan},
};
use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use uuid::Uuid;

const ID_NAMESPACE: Uuid = Uuid::from_u128(0xf63ebba0_dad7_536a_9bb7_9e44f8eff60f);
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}
fn protected_digest(
    repo: &impl RestoreRepository,
    domain: &str,
    value: &impl Serialize,
) -> Result<String> {
    repo.metadata_token(domain, &serde_json::to_vec(value)?)
}
fn valid_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected lowercase 64-hex digest"
    );
    Ok(())
}
fn timestamp(seconds: u64) -> Result<String> {
    Ok(DateTime::from_timestamp(i64::try_from(seconds)?, 0)
        .context("invalid timestamp")?
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    pub tenant: Uuid,
    pub host: Uuid,
}
impl HostIdentity {
    pub fn new(tenant: Uuid, host: Uuid) -> Result<Self> {
        ensure!(!tenant.is_nil() && !host.is_nil(), "nil host identity");
        Ok(Self { tenant, host })
    }
    fn scoped_id(&self, domain: &str, id: &str) -> Uuid {
        Uuid::new_v5(
            &ID_NAMESPACE,
            format!("{}:{}:{domain}:{id}", self.tenant, self.host).as_bytes(),
        )
    }
    pub fn snapshot_id(&self, core_id: &str) -> Result<Uuid> {
        valid_digest(core_id)?;
        Ok(self.scoped_id("snapshot", core_id))
    }
    fn file_id(&self, core_id: &str, path: &str) -> Result<String> {
        digest(&(self, "file-v1", core_id, path))
    }
    fn route(&self, suffix: &str) -> String {
        format!("/tenants/{}{suffix}", self.tenant)
    }
}
fn agent(value: Option<&str>) -> Result<&str> {
    match value {
        Some("claude_code" | "claude-code") => Ok("claude-code"),
        Some("github_copilot" | "copilot") => Ok("copilot"),
        Some(v @ ("cursor" | "codex" | "kiro")) => Ok(v),
        _ => bail!("snapshot has no supported agent identity"),
    }
}

/// Local selectors only: never upload paths, previews, secret references, or chunk identifiers.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotFileMetadata {
    pub file_id: String,
    pub digest: String,
    pub bytes: u64,
    pub executable: bool,
}
pub fn snapshot_files(
    repo: &Repository,
    identity: HostIdentity,
    snapshot: &str,
) -> Result<Vec<SnapshotFileMetadata>> {
    let manifest = repo.manifest(snapshot)?;
    manifest
        .files
        .iter()
        .map(|f| {
            Ok(SnapshotFileMetadata {
                file_id: repo
                    .metadata_token("file-id", identity.file_id(snapshot, &f.path)?.as_bytes())?,
                digest: repo.metadata_token("file-content", f.hash.as_bytes())?,
                bytes: f.size,
                executable: f.executable,
            })
        })
        .collect()
}

/// Abstraction keeps transport/state-machine tests independent of real keys and destinations.
/// Implementations must persist requests encrypted, fsync their state, and execute only the exact
/// plan confirmation with stale-state checks. The production implementation is Repository below.
pub trait RestoreRepository {
    fn metadata_token(&self, domain: &str, bytes: &[u8]) -> Result<String>;
    fn manifest(&self, snapshot: &str) -> Result<Manifest>;
    fn verify(&self, snapshot: &str) -> Result<()>;
    fn plan(
        &self,
        snapshot: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RestorePlan>;
    fn save_request(&self, request: &Value) -> Result<String>;
    fn request(&self, id: &str) -> Result<Value>;
    fn audit(&self, event: &str, detail: Value) -> Result<()>;
    fn execute(&self, plan: &RestorePlan, selection: Option<&str>) -> Result<()>;
    fn execute_before(
        &self,
        plan: &RestorePlan,
        selection: Option<&str>,
        deadline: DateTime<Utc>,
    ) -> Result<()> {
        ensure!(Utc::now() < deadline, "restore authorization expired");
        self.execute(plan, selection)
    }
}
impl RestoreRepository for Repository {
    fn execute_before(
        &self,
        plan: &RestorePlan,
        selection: Option<&str>,
        deadline: DateTime<Utc>,
    ) -> Result<()> {
        let destination = Path::new(&plan.destination);
        let identity = destination_identity(destination)?;
        self.restore_with_authorization(
            &plan.snapshot,
            destination,
            selection,
            &plan.confirmation,
            false,
            || {
                ensure!(
                    Utc::now() < deadline,
                    "restore authorization expired before mutation"
                );
                ensure!(
                    destination_identity(destination)? == identity,
                    "restore destination identity changed"
                );
                Ok(())
            },
        )
        .map(|_| ())
    }
    fn metadata_token(&self, domain: &str, bytes: &[u8]) -> Result<String> {
        self.metadata_token(domain, bytes)
    }
    fn manifest(&self, snapshot: &str) -> Result<Manifest> {
        self.manifest(snapshot)
    }
    fn verify(&self, snapshot: &str) -> Result<()> {
        self.verify(snapshot).map(|_| ())
    }
    fn plan(
        &self,
        snapshot: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RestorePlan> {
        self.plan(snapshot, destination, selection)
    }
    fn save_request(&self, request: &Value) -> Result<String> {
        self.save_request(request)
    }
    fn request(&self, id: &str) -> Result<Value> {
        self.request(id)
    }
    fn audit(&self, event: &str, detail: Value) -> Result<()> {
        self.audit(event, detail)
    }
    fn execute(&self, plan: &RestorePlan, selection: Option<&str>) -> Result<()> {
        // Core re-plans and compares confirmation again, then uses capability-safe filesystem access.
        self.restore_with_options(
            &plan.snapshot,
            Path::new(&plan.destination),
            selection,
            &plan.confirmation,
            false,
        )
        .map(|_| ())
    }
}

/// This directory is durable safety state, not a cache. Use one stable directory per host.
/// Any existence (including a partial/corrupt marker) consumes the request permanently.
pub struct ConsumedRequests {
    directory: PathBuf,
}
impl ConsumedRequests {
    pub fn open(directory: &Path) -> Result<Self> {
        Ok(Self {
            directory: private_directory(directory)?,
        })
    }
    pub fn path(&self) -> &Path {
        &self.directory
    }
    fn consume(&self, identity: HostIdentity, request: Uuid) -> Result<()> {
        let name = identity
            .scoped_id("consumed-restore", &request.to_string())
            .to_string();
        let path = self.directory.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(path)
            .context("restore already consumed or durable claim state unavailable")?;
        file.write_all(b"consumed-before-claim-v1\n")?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DestinationIdentity {
    device: u64,
    inode: u64,
}
fn destination_identity(path: &Path) -> Result<DestinationIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            path.canonicalize()? == path,
            "restore destination must remain canonical"
        );
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "restore destination changed"
        );
        Ok(DestinationIdentity {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("destination identity validation not supported on this platform")
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenPlan {
    version: u32,
    identity: HostIdentity,
    manifest_digest: String,
    destination_identity: DestinationIdentity,
    selection: Option<String>,
    consumed_directory: PathBuf,
    plan: RestorePlan,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRequest {
    frozen: FrozenPlan,
    server_request: Uuid,
    diff_digest: String,
    // Conservative local deadline starts before POST, never extends the server's 15-minute TTL.
    expires_at: DateTime<Utc>,
}
#[derive(Debug, Serialize)]
pub struct RequestedRestore {
    pub local_request_id: String,
    pub server_request_id: Uuid,
    pub diff_digest: String,
    pub expires_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatedRequest {
    id: Uuid,
    status: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimedRequest {
    id: Uuid,
    status: String,
    diff_digest: String,
    manifest_digest: String,
    expires_at: DateTime<Utc>,
}

pub struct HostClient<T: Transport> {
    transport: T,
    identity: HostIdentity,
}
impl<T: Transport> HostClient<T> {
    pub fn new(transport: T, identity: HostIdentity) -> Self {
        Self {
            transport,
            identity,
        }
    }
    pub fn identity(&self) -> HostIdentity {
        self.identity
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn into_transport(self) -> T {
        self.transport
    }
    /// LOCAL HUMAN UI ONLY. Returns the exact saved redacted preview, not a newly
    /// computed plan. Never serialize this value into a control-plane/MCP response.
    pub fn local_restore_preview(
        &self,
        repo: &impl RestoreRepository,
        local_request_id: &str,
    ) -> Result<RestorePlan> {
        let saved: SavedRequest = serde_json::from_value(repo.request(local_request_id)?)
            .context("invalid encrypted bridge request")?;
        ensure!(
            saved.frozen.version == 1
                && saved.frozen.identity == self.identity
                && saved.diff_digest == protected_digest(repo, "restore-plan", &saved.frozen)?,
            "saved restore preview binding mismatch"
        );
        Ok(saved.frozen.plan)
    }
    fn get(&mut self, suffix: &str) -> Result<Value> {
        Ok(self
            .transport
            .request(Method::Get, &self.identity.route(suffix), None)?)
    }
    fn post(&mut self, suffix: &str, body: &Value) -> Result<Value> {
        Ok(self
            .transport
            .request(Method::Post, &self.identity.route(suffix), Some(body))?)
    }

    pub fn publish_snapshot(
        &mut self,
        repo: &impl RestoreRepository,
        snapshot: &str,
    ) -> Result<Uuid> {
        repo.verify(snapshot)?;
        let manifest = repo.manifest(snapshot)?;
        ensure!(
            manifest.id == snapshot,
            "snapshot manifest identity mismatch"
        );
        let id = self.identity.snapshot_id(snapshot)?;
        let agent = agent(manifest.agent.as_deref())?;
        let session = self
            .identity
            .scoped_id("session", manifest.session.as_deref().unwrap_or(snapshot));
        let acknowledgement = self.post("/snapshots", &json!({"id":id,"agent":agent,"sessionId":session,
            "manifestDigest":protected_digest(repo, "manifest", &manifest)?,"fileCount":manifest.files.len(),"totalBytes":manifest.bytes,
            "capturedAt":timestamp(manifest.created_at)?,"status":"succeeded"}))?;
        ensure!(
            acknowledgement["id"] == id.to_string(),
            "snapshot acknowledgement mismatch"
        );
        Ok(id)
    }

    /// MCP/CLI adapter: creates a remote human-review request, never approves or executes it.
    /// Only single-file or entire-snapshot-in-place scope is supported. A full snapshot is sent
    /// as workspace; session remapping and deletes are intentionally not exposed.
    /// Display local_restore_preview after creation to review this exact frozen diff locally.
    pub fn request_restore(
        &mut self,
        repo: &impl RestoreRepository,
        consumed: &ConsumedRequests,
        snapshot: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RequestedRestore> {
        let manifest = repo.manifest(snapshot)?;
        ensure!(
            manifest.id == snapshot,
            "snapshot manifest identity mismatch"
        );
        let plan = repo.plan(snapshot, destination, selection)?;
        ensure!(
            plan.snapshot == snapshot && !plan.changes.is_empty(),
            "invalid restore plan"
        );
        ensure!(
            !Path::new(&plan.destination).starts_with(consumed.path())
                && !consumed.path().starts_with(&plan.destination),
            "restore destination overlaps durable claim state"
        );
        ensure!(
            !plan
                .changes
                .iter()
                .any(|c| c.requires_rebind && c.before.is_some() && c.action != "unchanged"),
            "remote restore cannot overwrite configuration requiring secret rebinding"
        );
        let frozen = FrozenPlan {
            version: 1,
            identity: self.identity,
            manifest_digest: protected_digest(repo, "manifest", &manifest)?,
            destination_identity: destination_identity(Path::new(&plan.destination))?,
            selection: selection.map(str::to_owned),
            consumed_directory: consumed.directory.clone(),
            plan,
        };
        let changes = metadata_changes(repo, &frozen)?;
        let diff_digest = protected_digest(repo, "restore-plan", &frozen)?;
        let expires_at = Utc::now() + chrono::Duration::minutes(15);
        // Save the exact plan before any network mutation; an ambiguous POST is never retried.
        let intent = repo.save_request(
            &json!({"bridge_intent":&frozen,"diff_digest":&diff_digest,"expires_at":expires_at}),
        )?;
        repo.audit(
            "remote_restore_create_attempt",
            json!({"intent":intent,"diff_digest":diff_digest}),
        )?;
        self.publish_snapshot(repo, snapshot)?;
        let value = self.post(
            "/restores",
            &json!({"snapshotId":self.identity.snapshot_id(snapshot)?,
            "kind":if selection.is_some(){"file"}else{"workspace"},
            "manifestDigest":frozen.manifest_digest,"diffDigest":diff_digest,"changes":changes}),
        )?;
        let created: CreatedRequest = serde_json::from_value(value)
            .context("ambiguous restore creation response; do not retry")?;
        ensure!(
            created.status == "pending" && !created.id.is_nil(),
            "invalid restore creation response; do not retry"
        );
        let saved = SavedRequest {
            frozen,
            server_request: created.id,
            diff_digest: diff_digest.clone(),
            expires_at,
        };
        let local_request_id = repo.save_request(&serde_json::to_value(&saved)?)?;
        repo.audit("remote_restore_requested", json!({"request":created.id,"local_request":local_request_id,"diff_digest":diff_digest}))?;
        Ok(RequestedRestore {
            local_request_id,
            server_request_id: created.id,
            diff_digest,
            expires_at,
        })
    }

    /// Explicit operator/daemon step for a particular locally persisted request. Polling approved
    /// metadata alone MUST NOT call this automatically without the matching local request handle.
    /// Consumes durable local state BEFORE the single fetch and claim. Any failure thereafter
    /// requires a new request, including pending status, stale state, timeout, or process crash.
    pub fn execute_restore_once(
        &mut self,
        repo: &impl RestoreRepository,
        consumed: &ConsumedRequests,
        local_request_id: &str,
    ) -> Result<()> {
        let saved: SavedRequest = serde_json::from_value(repo.request(local_request_id)?)
            .context("invalid encrypted bridge request")?;
        ensure!(
            saved.frozen.version == 1
                && saved.frozen.identity == self.identity
                && saved.frozen.consumed_directory == consumed.directory
                && !saved.server_request.is_nil(),
            "restore identity/state binding mismatch"
        );
        ensure!(
            saved.diff_digest == protected_digest(repo, "restore-plan", &saved.frozen)?,
            "frozen restore digest mismatch"
        );
        self.validate_current(repo, &saved)?;
        consumed.consume(self.identity, saved.server_request)?;
        repo.audit(
            "remote_restore_consumed",
            json!({"request":saved.server_request,"diff_digest":saved.diff_digest}),
        )?;
        let response = self.get(&format!("/restores/{}", saved.server_request))?;
        validate_remote(repo, &response, &saved)?;
        // GET may take time: validate all local state immediately before claiming.
        self.validate_current(repo, &saved)?;
        let response = self.post(
            &format!("/restores/{}/claim", saved.server_request),
            &json!({"diffDigest":saved.diff_digest}),
        )?;
        let claim: ClaimedRequest = serde_json::from_value(response)
            .context("ambiguous claim; execution permanently disabled for this request")?;
        ensure!(
            claim.id == saved.server_request
                && claim.status == "executing"
                && claim.diff_digest == saved.diff_digest
                && claim.manifest_digest == saved.frozen.manifest_digest
                && Utc::now() < claim.expires_at,
            "claim binding or expiry invalid; execution disabled"
        );
        // Claim is not sufficient if destination/manifest changed while HTTP was in flight.
        let result = (|| {
            self.validate_current(repo, &saved)?;
            repo.audit(
                "remote_restore_execution_started",
                json!({"request":saved.server_request,"diff_digest":saved.diff_digest}),
            )?;
            ensure!(
                Utc::now() < claim.expires_at && Utc::now() < saved.expires_at,
                "restore expired before execution"
            );
            repo.execute_before(
                &saved.frozen.plan,
                saved.frozen.selection.as_deref(),
                claim.expires_at.min(saved.expires_at),
            )
        })();
        let status = if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        };
        // Save local outcome even if completion delivery fails. Never replay file writes.
        let audit = repo.audit(
            "remote_restore_execution_finished",
            json!({"request":saved.server_request,"status":status,"diff_digest":saved.diff_digest}),
        );
        let completion = self.post(
            &format!("/restores/{}/complete", saved.server_request),
            &json!({"status":status,"diffDigest":saved.diff_digest}),
        );
        result?;
        audit?;
        let completion = completion
            .context("restore executed once; completion delivery uncertain; do not re-execute")?;
        ensure!(
            completion["id"] == saved.server_request.to_string() && completion["status"] == status,
            "restore executed once; completion acknowledgement mismatch; do not re-execute"
        );
        Ok(())
    }
    fn validate_current(&self, repo: &impl RestoreRepository, saved: &SavedRequest) -> Result<()> {
        ensure!(
            Utc::now() < saved.expires_at,
            "local restore request expired"
        );
        let frozen = &saved.frozen;
        ensure!(
            destination_identity(Path::new(&frozen.plan.destination))?
                == frozen.destination_identity,
            "destination directory identity changed"
        );
        ensure!(
            protected_digest(repo, "manifest", &repo.manifest(&frozen.plan.snapshot)?)?
                == frozen.manifest_digest,
            "snapshot manifest changed"
        );
        repo.verify(&frozen.plan.snapshot)?;
        let current = repo.plan(
            &frozen.plan.snapshot,
            Path::new(&frozen.plan.destination),
            frozen.selection.as_deref(),
        )?;
        ensure!(
            serde_json::to_vec(&current)? == serde_json::to_vec(&frozen.plan)?,
            "restore plan or destination is stale"
        );
        Ok(())
    }
}
fn metadata_changes(repo: &impl RestoreRepository, frozen: &FrozenPlan) -> Result<Vec<Value>> {
    let mut changes = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for change in &frozen.plan.changes {
        if change.action == "unchanged" {
            continue;
        }
        valid_digest(&change.after)?;
        if let Some(before) = &change.before {
            valid_digest(before)?;
        }
        let action = match (change.action.as_str(), change.before.is_some()) {
            ("create", false) => "create",
            ("overwrite", true) => "replace",
            _ => bail!("unsupported restore change"),
        };
        let id = repo.metadata_token(
            "file-id",
            frozen
                .identity
                .file_id(&frozen.plan.snapshot, &change.path)?
                .as_bytes(),
        )?;
        let before = change
            .before
            .as_deref()
            .map(|hash| repo.metadata_token("file-content", hash.as_bytes()))
            .transpose()?;
        let after = repo.metadata_token("file-content", change.after.as_bytes())?;
        ensure!(seen.insert(id.clone()), "duplicate file in plan");
        changes.push(json!({"fileId":id,"action":action,"beforeDigest":before,
            "afterDigest":after,"bytes":change.after_size}));
    }
    if let Some(git) = &frozen.plan.git {
        ensure!(
            frozen.selection.is_none(),
            "single-file request cannot mutate Git state"
        );
        let id = repo.metadata_token("git-state-id", frozen.plan.snapshot.as_bytes())?;
        ensure!(seen.insert(id.clone()), "duplicate Git state identifier");
        changes.push(json!({"fileId":id,"action":"replace",
            "beforeDigest":repo.metadata_token("git-state", git.prior_state_fingerprint.as_bytes())?,
            "afterDigest":repo.metadata_token("git-state", git.capture_fingerprint.as_bytes())?,"bytes":0}));
    }
    ensure!(
        !changes.is_empty()
            && changes.len() <= 1000
            && (frozen.selection.is_none() || changes.len() == 1),
        "restore needs 1..1000 changes (exactly one for a file)"
    );
    Ok(changes)
}
fn validate_remote(
    repo: &impl RestoreRepository,
    value: &Value,
    saved: &SavedRequest,
) -> Result<()> {
    let rows = value.as_array().context("invalid restore lookup")?;
    ensure!(rows.len() == 1, "remote restore missing or ambiguous");
    let row = &rows[0];
    ensure!(
        row["id"] == saved.server_request.to_string()
            && row["tenant_id"] == saved.frozen.identity.tenant.to_string()
            && row["host_id"] == saved.frozen.identity.host.to_string()
            && row["status"] == "approved",
        "remote restore is not approved for this identity"
    );
    let body = &row["body"];
    ensure!(
        body["diffDigest"] == saved.diff_digest
            && body["manifestDigest"] == saved.frozen.manifest_digest
            && body["snapshotId"]
                == saved
                    .frozen
                    .identity
                    .snapshot_id(&saved.frozen.plan.snapshot)?
                    .to_string()
            && body["kind"]
                == if saved.frozen.selection.is_some() {
                    "file"
                } else {
                    "workspace"
                }
            && body["changes"] == serde_json::to_value(metadata_changes(repo, &saved.frozen)?)?,
        "remote restore plan binding mismatch"
    );
    let expires = DateTime::parse_from_rfc3339(
        row["expires_at"]
            .as_str()
            .context("missing remote expiry")?,
    )?;
    ensure!(Utc::now() < expires, "remote restore request expired");
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemotePolicy {
    pub name: String,
    pub host_id: Option<Uuid>,
    pub interval_minutes: u64,
    pub end_of_session: bool,
    pub retention_days: u32,
    pub exclusions: Vec<String>,
    pub size_cap_bytes: u64,
    pub immutable: bool,
    pub dr_copy: bool,
    pub residency: String,
    pub storage: String,
    pub storage_ref: String,
    pub key_ref: String,
    pub mass_delete_threshold: usize,
    pub missed_backup_minutes: u64,
    pub restore_test_interval_hours: u64,
    pub channels: Vec<String>,
}
/// Pins labels to the actual open local repository and its wrapped-key header. Remote providers,
/// managed keys, and location attestations need separate verified adapters; labels alone prove none.
pub struct LocalBindings {
    repository: PathBuf,
    header_digest: String,
    storage_ref: String,
    key_ref: String,
    session_handler: bool,
    storage: Option<Arc<crate::host_storage::HostStorageAdapter>>,
}
impl LocalBindings {
    pub fn local_repository(repo: &Repository, storage_ref: &str, key_ref: &str) -> Result<Self> {
        ensure!(
            !storage_ref.is_empty() && !key_ref.is_empty(),
            "storage/key references required"
        );
        Ok(Self {
            repository: repo.root().canonicalize()?,
            header_digest: blake3::hash(&repo.encrypted_object("repository.json")?)
                .to_hex()
                .to_string(),
            storage_ref: storage_ref.into(),
            key_ref: key_ref.into(),
            session_handler: false,
            storage: None,
        })
    }
    /// Explicit operator opt-in for the durable authenticated session handler.
    pub fn with_session_handler(mut self, enabled: bool) -> Self {
        self.session_handler = enabled;
        self
    }
    /// Bind verified replication; cycle publication cannot bypass this adapter.
    pub fn with_storage(mut self, adapter: Arc<crate::host_storage::HostStorageAdapter>) -> Self {
        self.storage = Some(adapter);
        self
    }
    fn validate(
        &self,
        repo: &Repository,
        remote: &RemotePolicy,
        identity: HostIdentity,
    ) -> Result<Policy> {
        ensure!(
            repo.root().canonicalize()? == self.repository
                && blake3::hash(&repo.encrypted_object("repository.json")?)
                    .to_hex()
                    .as_str()
                    == self.header_digest,
            "local repository/key binding changed"
        );
        ensure!(
            (self.storage.is_some() || remote.storage == "local")
                && remote.storage_ref == self.storage_ref
                && remote.key_ref == self.key_ref,
            "policy storage/key references do not match active local configuration"
        );
        ensure!(
            remote.host_id.is_none_or(|h| h == identity.host),
            "policy belongs to another host"
        );
        ensure!(
            self.storage.is_some() || (!remote.immutable && !remote.dr_copy),
            "immutable or DR policy cannot be enforced by this host"
        );
        ensure!(
            remote.residency == "unrestricted",
            "local storage residency cannot be attested"
        );
        if let Some(storage) = &self.storage {
            storage.binding().validate(repo, remote)?;
        }
        ensure!(
            !remote.end_of_session || self.session_handler,
            "end-of-session event capture is not integrated"
        );
        ensure!(
            remote.channels == ["ui"] || remote.channels == ["ui", "webhook"],
            "unsupported notification channel"
        );
        ensure!(
            (5..=10080).contains(&remote.interval_minutes)
                && (1..=3650).contains(&remote.retention_days)
                && (1..=1_000_000_000_000).contains(&remote.size_cap_bytes)
                && (10..=43200).contains(&remote.missed_backup_minutes)
                && (1..=8760).contains(&remote.restore_test_interval_hours)
                && (1..=1_000_000).contains(&remote.mass_delete_threshold)
                && remote.exclusions.len() <= 100,
            "invalid policy limits"
        );
        let policy = Policy {
            interval_seconds: remote.interval_minutes * 60,
            size_cap_bytes: remote.size_cap_bytes,
            max_file_bytes: remote.size_cap_bytes.min(64 * 1024 * 1024),
            exclusions: remote.exclusions.clone(),
            retention_days: remote.retention_days,
            restore_test_interval_seconds: remote.restore_test_interval_hours * 3600,
            mass_delete_threshold: remote.mass_delete_threshold,
            ..Policy::default()
        };
        policy.validate()?;
        Ok(policy)
    }
}
#[derive(Deserialize)]
struct PolicyEnvelope {
    id: Uuid,
    body: RemotePolicy,
    version: u64,
}
/// Bounded metadata only: never send command lines, output, paths or secrets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFailure {
    RestoreFailed,
    Timeout,
    OutputLimit,
    ProcessFailed,
    InvalidBootResponse,
    InvalidMcpHandshake,
    CleanupFailed,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSkip {
    NotConfigured,
    RuntimeUnavailable,
    NetworkUnavailable,
    CredentialsUnavailable,
    UnsupportedSnapshot,
    ResourceLimit,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Passed,
    Failed,
    NotRun,
    FailedWithReason(ProbeFailure),
    NotRunWithReason(ProbeSkip),
}
impl ProbeOutcome {
    pub fn status(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed | Self::FailedWithReason(_) => "failed",
            Self::NotRun | Self::NotRunWithReason(_) => "not_run",
        }
    }
    pub fn reason(self) -> Option<serde_json::Value> {
        match self {
            Self::Passed => None,
            Self::Failed => Some(json!(ProbeFailure::ProcessFailed)),
            Self::NotRun => Some(json!(ProbeSkip::NotConfigured)),
            Self::FailedWithReason(reason) => Some(json!(reason)),
            Self::NotRunWithReason(reason) => Some(json!(reason)),
        }
    }
    pub fn is_not_run(self) -> bool {
        self.status() == "not_run"
    }
}
fn probe_metadata(key: &str, label: &str, outcome: ProbeOutcome) -> serde_json::Value {
    let mut value = json!({key: label, "outcome": outcome.status()});
    if let Some(reason) = outcome.reason() {
        value["reasonCode"] = reason;
    }
    value
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProbe {
    pub agent: String,
    pub outcome: ProbeOutcome,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpProbe {
    pub name: String,
    pub outcome: ProbeOutcome,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEvidence {
    pub id: Uuid,
    pub snapshot: String,
    pub finished_at: DateTime<Utc>,
    pub sandbox: EvidenceSandbox,
    pub agents: Vec<AgentProbe>,
    pub mcps: Vec<McpProbe>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSandbox {
    TempDirectory,
    Container,
    /// Container probe of verified file contents, not Git refs/config or native setup restoration.
    ContainerFileContent,
}
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlertKind {
    MassDelete,
    ForcePush,
    HistoryRewrite,
    McpChange,
    SkillChange,
    BackupFailed,
    BackupMissed,
    RestoreTestFailed,
}
pub struct ObservedAlert {
    pub event_id: Uuid,
    pub kind: AlertKind,
    pub critical: bool,
    pub snapshot: Option<String>,
    pub count: u64,
}
/// Actual outcomes from a trusted local scheduler; this bridge never runs agent/MCP code.
#[derive(Default)]
pub struct WorkResults {
    pub snapshots: Vec<String>,
    pub alerts: Vec<ObservedAlert>,
    pub evidence: Vec<RestoreEvidence>,
}
pub struct CycleReport {
    pub snapshots_reported: usize,
    pub evidence_reported: usize,
    pub probes_not_run: usize,
}
pub struct HostService<T: Transport> {
    pub client: HostClient<T>,
    last_policy_poll: Option<Instant>,
}
impl<T: Transport> HostService<T> {
    pub fn new(client: HostClient<T>) -> Self {
        Self {
            client,
            last_policy_poll: None,
        }
    }
    /// Invoke on a 30-second daemon tick. The callback is the existing trusted scheduler; it must
    /// honor interval/exclusions/cap and return only actual results. Errors invalidate the cycle.
    /// Retention is desired metadata only; no deletion or retention compliance is claimed.
    pub fn cycle(
        &mut self,
        repo: &Repository,
        bindings: &LocalBindings,
        work: impl FnOnce(&Policy) -> Result<WorkResults>,
    ) -> Result<CycleReport> {
        self.cycle_inner(repo, bindings, false, work)
    }
    /// Explicit session events require a freshly fetched policy enabling them.
    pub fn session_cycle(
        &mut self,
        repo: &Repository,
        bindings: &LocalBindings,
        work: impl FnOnce(&Policy) -> Result<WorkResults>,
    ) -> Result<CycleReport> {
        self.cycle_inner(repo, bindings, true, work)
    }
    fn cycle_inner(
        &mut self,
        repo: &Repository,
        bindings: &LocalBindings,
        session: bool,
        work: impl FnOnce(&Policy) -> Result<WorkResults>,
    ) -> Result<CycleReport> {
        let now = Instant::now();
        ensure!(
            session
                || self
                    .last_policy_poll
                    .is_none_or(|last| now.duration_since(last) >= POLICY_POLL_INTERVAL),
            "host cycle called before 30-second policy tick"
        );
        // Keep no executable cached policy: every eligible tick authenticates and fetches anew.
        let value = self.client.get("/policies")?;
        let mut policies: Vec<PolicyEnvelope> =
            serde_json::from_value(value).context("invalid effective policy response")?;
        ensure!(
            policies.len() == 1,
            "host has no single effective policy; work disabled"
        );
        let remote = policies.remove(0);
        ensure!(
            !remote.id.is_nil() && remote.version > 0,
            "invalid policy identity/version"
        );
        let local = bindings.validate(repo, &remote.body, self.client.identity)?;
        ensure!(
            !session || (bindings.session_handler && remote.body.end_of_session),
            "end-of-session policy or local handler disabled"
        );
        repo.audit(
            "host_policy_loaded",
            json!({"policy":remote.id,"version":remote.version,
            "retention_enforced":false,"session_event":session}),
        )?;
        if !session {
            self.last_policy_poll = Some(Instant::now());
        }
        let results = match work(&local).and_then(|results| {
            if let Some(storage) = &bindings.storage {
                storage.replicate_snapshots(repo, &remote.body, &results.snapshots)?;
            }
            Ok(results)
        }) {
            Ok(results) => results,
            Err(error) => {
                let report = self.client.publish_alert(&ObservedAlert {
                    event_id: Uuid::new_v4(),
                    kind: AlertKind::BackupFailed,
                    critical: true,
                    snapshot: None,
                    count: 1,
                });
                repo.audit(
                    "host_cycle_failed",
                    json!({"alert_delivered":report.is_ok()}),
                )?;
                return Err(error.context("host work failed; no success evidence fabricated"));
            }
        };
        let mut report = CycleReport {
            snapshots_reported: 0,
            evidence_reported: 0,
            probes_not_run: 0,
        };
        for snapshot in results.snapshots {
            self.client.publish_snapshot(repo, &snapshot)?;
            report.snapshots_reported += 1;
        }
        for alert in results.alerts {
            self.client.publish_alert(&alert)?;
        }
        for evidence in results.evidence {
            let not_run = evidence
                .agents
                .iter()
                .filter(|p| p.outcome.is_not_run())
                .count()
                + evidence
                    .mcps
                    .iter()
                    .filter(|p| p.outcome.is_not_run())
                    .count();
            report.probes_not_run += not_run;
            repo.audit("host_restore_probe_results", json!({"id":evidence.id,"snapshot":evidence.snapshot,
                "agents":evidence.agents.iter().map(|p|probe_metadata("agent", &p.agent, p.outcome)).collect::<Vec<_>>(),
                "mcps":evidence.mcps.iter().map(|p|probe_metadata("name", &p.name, p.outcome)).collect::<Vec<_>>()}))?;
            self.client.publish_evidence(evidence)?;
            report.evidence_reported += 1;
        }
        Ok(report)
    }
}
impl<T: Transport> HostClient<T> {
    pub fn publish_alert(&mut self, alert: &ObservedAlert) -> Result<()> {
        ensure!(
            !alert.event_id.is_nil() && alert.count <= 10_000_000,
            "invalid alert metadata"
        );
        let acknowledgement = self.post("/alerts", &json!({"eventId":alert.event_id,"type":alert.kind,
            "severity":if alert.critical {"critical"} else {"warning"},
            "snapshotId":alert.snapshot.as_deref().map(|s|self.identity.snapshot_id(s)).transpose()?,"count":alert.count}))?;
        let id: Uuid = serde_json::from_value(acknowledgement["id"].clone())
            .context("invalid alert acknowledgement")?;
        ensure!(!id.is_nil(), "invalid alert acknowledgement");
        Ok(())
    }
    fn publish_evidence(&mut self, evidence: RestoreEvidence) -> Result<()> {
        ensure!(
            !evidence.id.is_nil()
                && (1..=5).contains(&evidence.agents.len())
                && evidence.mcps.len() <= 100,
            "invalid evidence metadata"
        );
        let agents = evidence
            .agents
            .iter()
            .map(|p| Ok(probe_metadata("agent", agent(Some(&p.agent))?, p.outcome)))
            .collect::<Result<Vec<_>>>()?;
        // Labels must be caller-approved non-secret names, not command lines or process output.
        ensure!(
            evidence.mcps.iter().all(|p| !p.name.is_empty()
                && p.name.len() <= 100
                && p.name
                    .chars()
                    .all(|c| c.is_alphanumeric() || " _@.()+-".contains(c))),
            "invalid MCP metadata label"
        );
        let mut payload = json!({"id":evidence.id,"snapshotId":self.identity.snapshot_id(&evidence.snapshot)?,
            "finishedAt":evidence.finished_at.to_rfc3339_opts(SecondsFormat::Secs,true),
            "sandbox":match evidence.sandbox { EvidenceSandbox::TempDirectory=>"temp-directory",EvidenceSandbox::Container | EvidenceSandbox::ContainerFileContent=>"container" },
            "agents":agents,"mcps":evidence.mcps.iter().map(|p|probe_metadata("name", &p.name, p.outcome)).collect::<Vec<_>>()});
        if matches!(evidence.sandbox, EvidenceSandbox::ContainerFileContent) {
            payload["scope"] = json!("file-content");
        }
        let acknowledgement = self.post("/evidence", &payload)?;
        ensure!(
            acknowledgement["id"] == evidence.id.to_string(),
            "evidence acknowledgement mismatch"
        );
        Ok(())
    }
}

/// Production entrypoint: owns the active identity and refreshes it before every host operation.
/// Use this from CLI/daemon integration; HostClient remains available for injected test transports.
/// Construct from protected persisted credentials, never from human credentials or gateway proof.
pub struct ProductionHost {
    credentials: crate::control_plane::Credentials,
    store: crate::control_plane::CredentialStore,
    origin: crate::control_plane::HttpsOrigin,
    trust: crate::control_plane::ServerTrust,
    service: HostService<crate::control_plane::MtlsTransport>,
}
impl ProductionHost {
    pub fn open(
        store: crate::control_plane::CredentialStore,
        origin: crate::control_plane::HttpsOrigin,
        trust: crate::control_plane::ServerTrust,
    ) -> Result<Self> {
        let credentials = store.load()?;
        let identity = HostIdentity::new(credentials.tenant_id, credentials.host_id)?;
        let transport =
            crate::control_plane::MtlsTransport::new(origin.clone(), &trust, &credentials)?;
        Ok(Self {
            credentials,
            store,
            origin,
            trust,
            service: HostService::new(HostClient::new(transport, identity)),
        })
    }
    pub fn identity(&self) -> HostIdentity {
        self.service.client.identity()
    }
    /// Human CLI only: the frozen redacted preview stays local, even when current files changed.
    pub fn local_restore_preview(
        &self,
        repo: &Repository,
        local_request_id: &str,
    ) -> Result<RestorePlan> {
        self.service
            .client
            .local_restore_preview(repo, local_request_id)
    }
    fn refresh(&mut self) -> Result<()> {
        self.credentials.require_valid(Utc::now())?;
        if self.credentials.renewal_due(Utc::now()) {
            let next = crate::control_plane::renew(
                self.service.client.transport_mut(),
                &self.credentials,
                &self.store,
            )?;
            // A nearly expired issuing CA can return a short leaf. Pause operations until the
            // administrator repairs CA validity; don't spin renewal or silently accept expiry.
            ensure!(
                !next.renewal_due(Utc::now()),
                "renewed identity has less than one hour remaining"
            );
            let transport =
                crate::control_plane::MtlsTransport::new(self.origin.clone(), &self.trust, &next)?;
            self.service.client = HostClient::new(transport, self.identity());
            self.credentials = next;
        }
        Ok(())
    }
    pub fn cycle(
        &mut self,
        repo: &Repository,
        bindings: &LocalBindings,
        work: impl FnOnce(&Policy) -> Result<WorkResults>,
    ) -> Result<CycleReport> {
        self.refresh()?;
        self.service.cycle(repo, bindings, work)
    }
    pub fn session_cycle(
        &mut self,
        repo: &Repository,
        bindings: &LocalBindings,
        work: impl FnOnce(&Policy) -> Result<WorkResults>,
    ) -> Result<CycleReport> {
        self.refresh()?;
        self.service.session_cycle(repo, bindings, work)
    }
    pub fn request_restore(
        &mut self,
        repo: &Repository,
        consumed: &ConsumedRequests,
        snapshot: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RequestedRestore> {
        self.refresh()?;
        let destination = destination.canonicalize()?;
        ensure!(
            !destination.starts_with(self.store.directory())
                && !self.store.directory().starts_with(&destination),
            "restore destination overlaps host credential state"
        );
        self.service
            .client
            .request_restore(repo, consumed, snapshot, &destination, selection)
    }
    pub fn execute_restore_once(
        &mut self,
        repo: &Repository,
        consumed: &ConsumedRequests,
        local_request_id: &str,
    ) -> Result<()> {
        self.refresh()?;
        // Refuse requests prepared by a different integration with a destination around credentials.
        let saved: SavedRequest = serde_json::from_value(repo.request(local_request_id)?)?;
        let destination = Path::new(&saved.frozen.plan.destination).canonicalize()?;
        ensure!(
            !destination.starts_with(self.store.directory())
                && !self.store.directory().starts_with(&destination),
            "restore destination overlaps host credential state"
        );
        self.service
            .client
            .execute_restore_once(repo, consumed, local_request_id)
    }
}
