//! Operator-bound host replication and externally retained, authenticated receipts.
use crate::{
    checkpoint::{self, RemoteStore},
    consumer_replication::ConsumerReport,
    consumer_state::ConsumerState,
    consumer_storage::ConsumerBackend,
    host_service::RemotePolicy,
    protected_replication::{PairedStore, ProtectedReport},
    protected_storage::ProtectedBackend,
    repository::Repository,
    storage::StorageConfig,
};
use anyhow::{ensure, Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

const MAX_REPORT: u64 = 64 * 1024 * 1024;
const RECEIPT_DOMAIN: &[u8] = b"bunker-host-storage-receipt-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStorageConfig {
    pub primary: PathBuf,
    #[serde(default)]
    pub secondary: Option<PathBuf>,
    /// Explicit UTC deadline, not a claim inferred from old recovery evidence.
    #[serde(default)]
    pub required_until: Option<DateTime<Utc>>,
    pub report_directory: PathBuf,
    #[serde(default)]
    pub consumer_state: Option<PathBuf>,
}

impl HostStorageConfig {
    /// Read-only preflight. Call before creating any host or OAuth state.
    pub fn validate_paths(&self, repository: &Path, workspace: &Path) -> Result<()> {
        let repository = checked_path(repository, false)?;
        let workspace = checked_path(workspace, false)?;
        let mut paths = vec![(&self.primary, false), (&self.report_directory, true)];
        if let Some(path) = &self.secondary {
            paths.push((path, false));
        }
        if let Some(path) = &self.consumer_state {
            paths.push((path, true));
        }
        for (path, directory) in &paths {
            let path = checked_path(path, *directory)?;
            ensure!(
                !overlaps(&path, &repository) && !overlaps(&path, &workspace),
                "host storage configuration/state must be disjoint from repository and workspace"
            );
            if path.exists() {
                private_metadata(&fs::symlink_metadata(&path)?, *directory)?;
            }
        }
        for (i, (a, _)) in paths.iter().enumerate() {
            for (b, _) in &paths[i + 1..] {
                ensure!(
                    !overlaps(a, b),
                    "host storage configuration/state paths must be disjoint"
                );
            }
        }
        for path in std::iter::once(&self.primary).chain(self.secondary.iter()) {
            let config = load_config(path)?;
            if config.service == "local" {
                let root = Path::new(
                    config
                        .options
                        .get("root")
                        .context("explicit local storage root required")?,
                );
                let root = checked_path(root, false)?;
                ensure!(
                    !overlaps(&root, &repository) && !overlaps(&root, &workspace),
                    "local replication destination must be disjoint from repository and workspace"
                );
                for (path, _) in &paths {
                    ensure!(
                        !overlaps(&root, path),
                        "local replication destination overlaps host storage state"
                    );
                }
                if root.exists() {
                    private_metadata(&fs::symlink_metadata(&root)?, true)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct HostStorageBinding {
    config: HostStorageConfig,
    repository: PathBuf,
    workspace: PathBuf,
    header: String,
    fingerprint: String,
    service: String,
    immutable: bool,
    storage_ref: String,
    key_ref: String,
}

impl HostStorageBinding {
    pub fn validate(&self, repo: &Repository, policy: &RemotePolicy) -> Result<()> {
        self.config.validate_paths(repo.root(), &self.workspace)?;
        ensure!(
            repo.root().canonicalize()? == self.repository
                && digest(&repo.encrypted_object("repository.json")?) == self.header,
            "host storage repository/key binding changed"
        );
        ensure!(
            fingerprint(&self.config)? == self.fingerprint,
            "host storage configuration or credential binding changed"
        );
        ensure!(
            policy.storage == self.service
                && policy.storage_ref == self.storage_ref
                && policy.key_ref == self.key_ref,
            "remote storage/key references do not match operator binding"
        );
        ensure!(
            policy.residency == "unrestricted",
            "host storage has no residency attestation"
        );
        ensure!(
            policy.immutable == self.immutable && policy.dr_copy == self.config.secondary.is_some(),
            "remote immutable/DR policy does not match configured capability"
        );
        ensure!(
            (1..=3650).contains(&policy.retention_days),
            "invalid remote retention horizon"
        );
        if self.immutable {
            ensure!(
                self.config
                    .required_until
                    .context("explicit retention deadline required")?
                    > Utc::now(),
                "configured retention deadline expired"
            );
        }
        Ok(())
    }
}

pub struct HostStorageAdapter {
    binding: HostStorageBinding,
}

impl HostStorageAdapter {
    /// No state writes or network requests. The worker also isolates blocking HTTP constructors
    /// from a caller's Tokio runtime.
    pub fn open(
        config: &HostStorageConfig,
        repo: &Repository,
        workspace: &Path,
        storage_ref: &str,
        key_ref: &str,
    ) -> Result<Self> {
        config.validate_paths(repo.root(), workspace)?;
        ensure!(
            !storage_ref.is_empty() && !key_ref.is_empty(),
            "storage/key references required"
        );
        let initial_fingerprint = fingerprint(config)?;
        let primary = load_config(&config.primary)?;
        std::thread::scope(|scope| {
            scope
                .spawn(|| preflight(config))
                .join()
                .map_err(|_| anyhow::anyhow!("host storage validation worker failed"))?
        })?;
        ensure!(
            fingerprint(config)? == initial_fingerprint,
            "host storage configuration changed during binding"
        );
        Ok(Self {
            binding: HostStorageBinding {
                config: config.clone(),
                repository: repo.root().canonicalize()?,
                workspace: workspace.canonicalize()?,
                header: digest(&repo.encrypted_object("repository.json")?),
                fingerprint: initial_fingerprint,
                service: primary.service,
                immutable: primary.immutable,
                storage_ref: storage_ref.into(),
                key_ref: key_ref.into(),
            },
        })
    }

    pub fn binding(&self) -> HostStorageBinding {
        self.binding.clone()
    }

    /// Call after the durable work outbox is saved and before publishing any snapshot success.
    /// Errors leave the caller's outbox untouched. Safe from synchronous and async callers.
    pub fn replicate_snapshots(
        &self,
        repo: &Repository,
        policy: &RemotePolicy,
        snapshots: &[String],
    ) -> Result<()> {
        self.binding.validate(repo, policy)?;
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.replicate_worker(repo, policy, snapshots))
                .join()
                .map_err(|_| anyhow::anyhow!("host storage replication worker failed"))?
        })
    }

    fn replicate_worker(
        &self,
        repo: &Repository,
        policy: &RemotePolicy,
        snapshots: &[String],
    ) -> Result<()> {
        self.binding.validate(repo, policy)?;
        let config = &self.binding.config;
        preflight(config)?;
        // Validate every selected snapshot and retention horizon before state writes or uploads.
        for snapshot in snapshots {
            let manifest = repo.verify(snapshot)?;
            if let Some(until) = config.required_until {
                let created = i64::try_from(manifest.created_at)?;
                let horizon = DateTime::from_timestamp(created, 0)
                    .context("invalid snapshot timestamp")?
                    .checked_add_signed(Duration::days(i64::from(policy.retention_days)))
                    .context("retention overflow")?;
                ensure!(
                    until >= horizon,
                    "explicit retention deadline does not cover snapshot policy horizon"
                );
            }
        }
        if snapshots.is_empty() {
            return Ok(());
        }
        let custody = Custody::open(&config.report_directory)?;
        let policy_hash = policy_digest(policy)?;
        for snapshot in snapshots {
            self.binding
                .config
                .validate_paths(repo.root(), &self.binding.workspace)?;
            ensure!(
                fingerprint(config)? == self.binding.fingerprint,
                "storage configuration changed during replication"
            );
            let key = digest(&serde_json::to_vec(&(
                &self.binding.fingerprint,
                &self.binding.header,
                &policy_hash,
                snapshot,
            ))?);
            let receipt = custody
                .read(&format!("{key}.receipt"))?
                .map(|bytes| -> Result<Receipt> {
                    Ok(serde_json::from_slice(
                        &repo.open_metadata(RECEIPT_DOMAIN, &bytes)?,
                    )?)
                })
                .transpose()?;
            let context = Publication {
                repo,
                custody: &custody,
                key: &key,
                binding: &self.binding,
                snapshot,
                policy: &policy_hash,
            };
            let primary = load_config(&config.primary)?;
            if primary.immutable {
                let until = config
                    .required_until
                    .context("explicit retention deadline required")?;
                let primary = ProtectedBackend::new(&primary, until)?;
                let secondary = config
                    .secondary
                    .as_ref()
                    .map(|path| ProtectedBackend::new(&load_config(path)?, until))
                    .transpose()?;
                if let Some(secondary) = &secondary {
                    primary.ensure_independent(secondary)?;
                }
                let runtime = tokio::runtime::Runtime::new()?;
                runtime.block_on(async {
                    if let Some(receipt) = receipt {
                        context.validate_receipt(&receipt)?;
                        let reports = context.reports(&receipt)?;
                        ensure!(
                            reports.len() == 1 + usize::from(secondary.is_some()),
                            "protected custody backend count mismatch"
                        );
                        for (backend, bytes) in std::iter::once(&primary)
                            .chain(secondary.iter())
                            .zip(reports)
                        {
                            let report: ProtectedReport = serde_json::from_slice(&bytes)?;
                            report.validate()?;
                            ensure!(
                                report.backends.len() == 1
                                    && report.namespace == receipt.namespace
                                    && report.sequence == receipt.sequence,
                                "protected recovery report binding mismatch"
                            );
                            let evidence = &report.backends[0];
                            ensure!(
                                &evidence.identity == backend.identity()
                                    && evidence.required_until == until,
                                "protected recovery report backend mismatch"
                            );
                            ensure!(
                                evidence.objects.len() == receipt.inventory.len(),
                                "protected inventory mismatch"
                            );
                            // Fresh write-capable backend performs current provider version/retention checks.
                            // Recovery-only imported evidence is never used to claim current protection.
                            for (path, proof) in &receipt.inventory {
                                let saved = evidence
                                    .objects
                                    .get(path)
                                    .context("missing protected object proof")?;
                                ensure!(
                                    saved.blake3 == proof.blake3 && saved.bytes == proof.bytes,
                                    "protected object binding mismatch"
                                );
                                let bytes = local_object(repo, path, &receipt)?;
                                verify_bytes(&bytes, proof)?;
                                RemoteStore::create_verified(backend, path, bytes).await?;
                            }
                            let current = backend.evidence()?;
                            for (path, saved) in &evidence.objects {
                                ensure!(
                                    current.objects[path].version == saved.version,
                                    "protected receipt version changed"
                                );
                            }
                        }
                        Ok(())
                    } else {
                        if let Some(secondary) = &secondary {
                            publish(
                                &context,
                                &PairedStore {
                                    primary: &primary,
                                    secondary,
                                },
                                |result| protected_reports(repo, result, &primary, Some(secondary)),
                            )
                            .await
                        } else {
                            publish(&context, &primary, |result| {
                                protected_reports(repo, result, &primary, None)
                            })
                            .await
                        }
                    }
                })?;
            } else if matches!(primary.service.as_str(), "gdrive" | "onedrive") {
                let state = Arc::new(ConsumerState::open(
                    config
                        .consumer_state
                        .as_ref()
                        .context("consumer state required")?,
                    &primary,
                )?);
                let saved = if let Some(receipt) = &receipt {
                    context.validate_receipt(receipt)?;
                    let reports = context.reports(receipt)?;
                    ensure!(
                        reports.len() == 1,
                        "consumer recovery report count mismatch"
                    );
                    let report = ConsumerReport::from_slice(&reports[0])?;
                    ensure!(
                        report.namespace == receipt.namespace
                            && report.sequence == receipt.sequence,
                        "consumer report binding mismatch"
                    );
                    Some(report.evidence)
                } else {
                    state.evidence()?
                };
                let backend = if let Some(saved) = &saved {
                    ConsumerBackend::from_evidence(
                        &primary,
                        saved,
                        false,
                        state.clone(),
                        state.clone(),
                    )?
                } else {
                    ConsumerBackend::new(&primary, state.clone(), state.clone())?
                };
                let runtime = tokio::runtime::Runtime::new()?;
                runtime.block_on(async {
                    if let Some(receipt) = receipt {
                        verify_inventory(&backend, &receipt.inventory).await
                    } else {
                        publish(&context, &backend, |result| {
                            let report = ConsumerReport {
                                version: 1,
                                namespace: result.namespace.clone(),
                                sequence: result.sequence,
                                evidence: backend.evidence()?,
                            };
                            state.save_report(&report)?;
                            Ok(vec![report.to_vec()?])
                        })
                        .await
                    }
                })?;
            } else {
                let backend = primary.operator()?;
                let runtime = tokio::runtime::Runtime::new()?;
                runtime.block_on(async {
                    if let Some(receipt) = receipt {
                        context.validate_receipt(&receipt)?;
                        let reports = context.reports(&receipt)?;
                        ensure!(reports.len() == 1, "plain recovery report count mismatch");
                        let report: PlainReport = serde_json::from_slice(&reports[0])?;
                        ensure!(
                            report.version == 1
                                && report.namespace == receipt.namespace
                                && report.sequence == receipt.sequence
                                && report.snapshot == snapshot.as_str(),
                            "plain recovery report binding mismatch"
                        );
                        verify_inventory(&backend, &receipt.inventory).await
                    } else {
                        publish(&context, &backend, |result| {
                            Ok(vec![serde_json::to_vec(&PlainReport {
                                version: 1,
                                namespace: result.namespace.clone(),
                                sequence: result.sequence,
                                snapshot: snapshot.clone(),
                            })?])
                        })
                        .await
                    }
                })?;
            }
            // Retry visible files after an earlier directory-fsync failure must finish
            // the durability barrier before authorizing host success.
            custody.sync()?;
            self.binding.validate(repo, policy)?;
        }
        Ok(())
    }
}

fn preflight(config: &HostStorageConfig) -> Result<()> {
    let primary = load_config(&config.primary)?;
    if primary.immutable {
        ensure!(
            config.consumer_state.is_none(),
            "immutable consumer storage is unsupported"
        );
        let until = config
            .required_until
            .context("immutable storage requires explicit required_until")?;
        let backend = ProtectedBackend::new(&primary, until)?;
        if let Some(path) = &config.secondary {
            let secondary = ProtectedBackend::new(&load_config(path)?, until)?;
            backend.ensure_independent(&secondary)?;
        }
    } else {
        ensure!(
            config.secondary.is_none(),
            "DR requires two verified immutable S3/Azure backends"
        );
        ensure!(
            config.required_until.is_none(),
            "retention deadline requires immutable storage"
        );
        if matches!(primary.service.as_str(), "gdrive" | "onedrive") {
            crate::consumer_storage::validated_location(&primary)?;
            ensure!(
                config.consumer_state.is_some(),
                "consumer storage requires durable external OAuth state"
            );
            for (name, reference) in &primary.credential_env {
                if name == "refresh_token" {
                    continue;
                }
                let value = Zeroizing::new(
                    std::env::var(reference).context("explicit OAuth credential unavailable")?,
                );
                ensure!(
                    !value.is_empty()
                        && value.len() <= 16384
                        && !value.chars().any(char::is_control),
                    "invalid explicit OAuth credential"
                );
            }
            // Persisted refresh rotation is authoritative. Do not require the obsolete
            // bootstrap credential to remain in the environment after first use.
            let state = config
                .consumer_state
                .as_ref()
                .context("consumer state required")?;
            ensure!(
                matches!(fs::symlink_metadata(state.join("refresh-pending")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "uncertain OAuth refresh requires explicit rebinding"
            );
            let saved = state.join("credentials.json");
            let token = match fs::symlink_metadata(&saved) {
                Ok(_) => crate::control_plane::read_private(&saved, 16384)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Zeroizing::new(
                    std::env::var(&primary.credential_env["refresh_token"])
                        .context("explicit bootstrap OAuth credential unavailable")?
                        .into_bytes(),
                ),
                Err(e) => return Err(e.into()),
            };
            let token = std::str::from_utf8(&token).context("invalid saved OAuth credential")?;
            ensure!(
                !token.is_empty() && token.len() <= 16384 && !token.chars().any(char::is_control),
                "invalid explicit OAuth credential"
            );
        } else {
            ensure!(
                config.consumer_state.is_none(),
                "consumer state only supported for Drive/OneDrive"
            );
            // Constructor validates explicit credentials and prevents ambient provider discovery.
            primary.operator()?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainReport {
    version: u32,
    namespace: String,
    sequence: u64,
    snapshot: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectDigest {
    bytes: u64,
    blake3: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    binding: String,
    header: String,
    policy: String,
    snapshot: String,
    namespace: String,
    sequence: u64,
    reports: Vec<String>,
    inventory: BTreeMap<String, ObjectDigest>,
    // Retain the exact published ciphertext even if the process stops before the
    // checkpoint module saves its local copy. This is authenticated by the receipt.
    checkpoint: Vec<u8>,
}

struct Publication<'a> {
    repo: &'a Repository,
    custody: &'a Custody,
    key: &'a str,
    binding: &'a HostStorageBinding,
    snapshot: &'a str,
    policy: &'a str,
}
impl Publication<'_> {
    fn validate_receipt(&self, receipt: &Receipt) -> Result<()> {
        ensure!(
            receipt.version == 1
                && receipt.binding == self.binding.fingerprint
                && receipt.header == self.binding.header
                && receipt.policy == self.policy
                && receipt.snapshot == self.snapshot
                && receipt.sequence > 0,
            "host storage receipt binding mismatch"
        );
        let parts: Vec<_> = receipt.namespace.split(':').collect();
        ensure!(
            parts.len() == 3 && parts[0] == self.repo.identity() && parts[1] == self.binding.header,
            "receipt recovery locator mismatch"
        );
        for part in &parts {
            crate::repository::valid_id(part)?;
        }
        ensure!(
            digest(&receipt.checkpoint) == parts[2],
            "receipt checkpoint digest mismatch"
        );
        let index: serde_json::Value = serde_json::from_slice(
            &self
                .repo
                .open_metadata(b"bunker-replication-index-v1", &receipt.checkpoint)?,
        )?;
        ensure!(
            index["version"] == 1
                && index["repository"] == parts[0]
                && index["header"] == parts[1]
                && index["sequence"] == receipt.sequence
                && index["snapshots"] == serde_json::json!([self.snapshot]),
            "receipt checkpoint does not bind the exact selected snapshot"
        );
        ensure!(
            !receipt.inventory.is_empty() && receipt.inventory.len() <= 100_000,
            "invalid receipt inventory"
        );
        for path in [
            format!("{}/headers/{}", parts[0], parts[1]),
            format!("{}/checkpoints/{}", parts[0], parts[2]),
            format!("{}/snapshots/{}", parts[0], self.snapshot),
        ] {
            let proof = receipt
                .inventory
                .get(&path)
                .context("receipt missing selected snapshot/header/checkpoint")?;
            let bytes = local_object(self.repo, &path, receipt)?;
            verify_bytes(&bytes, proof)?;
        }
        Ok(())
    }
    fn reports(&self, receipt: &Receipt) -> Result<Vec<Vec<u8>>> {
        ensure!(
            (1..=2).contains(&receipt.reports.len()),
            "invalid custody report count"
        );
        receipt
            .reports
            .iter()
            .enumerate()
            .map(|(index, hash)| {
                let bytes = self
                    .custody
                    .read(&format!("{}-{index}.json", self.key))?
                    .context("external recovery report missing")?;
                ensure!(digest(&bytes) == *hash, "external recovery report changed");
                Ok(bytes)
            })
            .collect()
    }
}

struct RecordingStore<'a, S> {
    store: &'a S,
    inventory: Mutex<BTreeMap<String, ObjectDigest>>,
    checkpoint: Mutex<Vec<u8>>,
}
impl<S: RemoteStore> RemoteStore for RecordingStore<'_, S> {
    async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        self.store.read_bounded(path, maximum).await
    }
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        let proof = ObjectDigest {
            bytes: bytes.len() as u64,
            blake3: digest(&bytes),
        };
        if path.contains("/checkpoints/") {
            *self
                .checkpoint
                .lock()
                .map_err(|_| anyhow::anyhow!("checkpoint lock failed"))? = bytes.clone();
        }
        self.store.create_verified(path, bytes).await?;
        let mut inventory = self
            .inventory
            .lock()
            .map_err(|_| anyhow::anyhow!("inventory lock failed"))?;
        ensure!(
            inventory.len() < 100_000 || inventory.contains_key(path),
            "host receipt inventory exceeds limit"
        );
        inventory.insert(path.to_owned(), proof);
        Ok(())
    }
}

async fn publish<S: RemoteStore>(
    context: &Publication<'_>,
    store: &S,
    reports: impl FnOnce(&checkpoint::ReplicationReport) -> Result<Vec<Vec<u8>>>,
) -> Result<()> {
    let recording = RecordingStore {
        store,
        inventory: Mutex::new(BTreeMap::new()),
        checkpoint: Mutex::new(Vec::new()),
    };
    checkpoint::replicate_with_publication(
        context.repo,
        &recording,
        Some(context.snapshot),
        |result| {
            context
                .binding
                .config
                .validate_paths(context.repo.root(), &context.binding.workspace)?;
            ensure!(
                fingerprint(&context.binding.config)? == context.binding.fingerprint,
                "storage configuration changed during publication"
            );
            let reports = reports(result)?;
            ensure!(
                (1..=2).contains(&reports.len()),
                "invalid recovery report count"
            );
            let mut hashes = Vec::new();
            for (index, report) in reports.iter().enumerate() {
                context
                    .custody
                    .write(&format!("{}-{index}.json", context.key), report)?;
                hashes.push(digest(report));
            }
            let receipt = Receipt {
                version: 1,
                binding: context.binding.fingerprint.clone(),
                header: context.binding.header.clone(),
                policy: context.policy.to_owned(),
                snapshot: context.snapshot.to_owned(),
                namespace: result.namespace.clone(),
                sequence: result.sequence,
                reports: hashes,
                inventory: recording
                    .inventory
                    .lock()
                    .map_err(|_| anyhow::anyhow!("inventory lock failed"))?
                    .clone(),
                checkpoint: recording
                    .checkpoint
                    .lock()
                    .map_err(|_| anyhow::anyhow!("checkpoint lock failed"))?
                    .clone(),
            };
            let bytes = serde_json::to_vec(&receipt)?;
            context.custody.write(
                &format!("{}.receipt", context.key),
                &context.repo.seal_metadata(RECEIPT_DOMAIN, &bytes)?,
            )?;
            Ok(())
        },
    )
    .await?;
    Ok(())
}

fn protected_reports(
    repo: &Repository,
    result: &checkpoint::ReplicationReport,
    primary: &ProtectedBackend,
    secondary: Option<&ProtectedBackend>,
) -> Result<Vec<Vec<u8>>> {
    let mut backends = vec![primary.evidence()?];
    if let Some(secondary) = secondary {
        backends.push(secondary.evidence()?);
    }
    let report = ProtectedReport {
        version: 1,
        namespace: result.namespace.clone(),
        sequence: result.sequence,
        objects_per_backend: result.objects_verified,
        backends,
    };
    report.validate()?;
    report.persist_local(repo)?;
    report
        .backends
        .into_iter()
        .map(|backend| {
            Ok(serde_json::to_vec(&ProtectedReport {
                version: 1,
                namespace: result.namespace.clone(),
                sequence: result.sequence,
                objects_per_backend: result.objects_verified,
                backends: vec![backend],
            })?)
        })
        .collect()
}

async fn verify_inventory<S: RemoteStore>(
    store: &S,
    inventory: &BTreeMap<String, ObjectDigest>,
) -> Result<()> {
    for (path, proof) in inventory {
        let bytes = store.read_bounded(path, proof.bytes).await?;
        verify_bytes(&bytes, proof)?;
    }
    Ok(())
}
fn verify_bytes(bytes: &[u8], proof: &ObjectDigest) -> Result<()> {
    ensure!(
        bytes.len() as u64 == proof.bytes && digest(bytes) == proof.blake3,
        "replication receipt object differs"
    );
    Ok(())
}
fn local_object(repo: &Repository, path: &str, receipt: &Receipt) -> Result<Vec<u8>> {
    let prefix = format!("{}/", repo.identity());
    let path = path
        .strip_prefix(&prefix)
        .context("receipt object repository mismatch")?;
    crate::repository::safe_path(path)?;
    if path.starts_with("headers/") {
        return repo.encrypted_object("repository.json");
    }
    if let Some(id) = path.strip_prefix("checkpoints/") {
        crate::repository::valid_id(id)?;
        if receipt.namespace.rsplit(':').next() == Some(id) {
            return Ok(receipt.checkpoint.clone());
        }
        return repo
            .read_private_metadata(&format!("checkpoints/{id}"), MAX_REPORT)?
            .with_context(|| {
                "receipt checkpoint missing locally; do not regenerate an authenticated receipt"
            });
    }
    ensure!(
        path.starts_with("snapshots/") || path.starts_with("chunks/"),
        "invalid receipt object path"
    );
    repo.encrypted_object(path)
}

/// Exclusive custody directory lock prevents concurrent receipt/report replacement.
struct Custody {
    dir: Dir,
    _lock: fs::File,
}
impl Custody {
    fn open(path: &Path) -> Result<Self> {
        let directory = crate::control_plane::private_directory(path)?;
        let dir = Dir::open_ambient_dir(&directory, ambient_authority())?;
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NONBLOCK);
        }
        let lock = dir.open_with("lock", &options)?.into_std();
        private_metadata(&lock.metadata()?, false)?;
        lock.try_lock_exclusive()
            .context("host storage custody is busy")?;
        Ok(Self { dir, _lock: lock })
    }
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = match self.dir.open_with(name, &options) {
            Ok(file) => file.into_std(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        private_metadata(&file.metadata()?, false)?;
        ensure!(
            file.metadata()?.len() <= MAX_REPORT,
            "custody file exceeds limit"
        );
        file.sync_all()?;
        let mut bytes = Vec::new();
        file.take(MAX_REPORT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_REPORT,
            "custody file exceeds limit"
        );
        Ok(Some(bytes))
    }
    fn sync(&self) -> Result<()> {
        self.dir.try_clone()?.into_std_file().sync_all()?;
        Ok(())
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() as u64 <= MAX_REPORT,
            "custody file exceeds limit"
        );
        // Existing partial publication may be retried, but unsafe paths are never replaced.
        self.read(name)?;
        crate::repository::atomic_write(&self.dir, name, bytes, true)?;
        ensure!(
            self.read(name)?.as_deref() == Some(bytes),
            "custody readback failed"
        );
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn load_config(path: &Path) -> Result<StorageConfig> {
    let bytes = crate::control_plane::read_private(path, 1024 * 1024)?;
    toml::from_str(std::str::from_utf8(&bytes)?)
        .map_err(|_| anyhow::anyhow!("invalid host storage configuration"))
}
fn fingerprint(config: &HostStorageConfig) -> Result<String> {
    let mut hash = blake3::Hasher::new();
    hash.update(&serde_json::to_vec(config)?);
    for path in std::iter::once(&config.primary).chain(config.secondary.iter()) {
        let storage = load_config(path)?;
        let value = serde_json::to_vec(&storage)?;
        hash.update(&(value.len() as u64).to_le_bytes());
        hash.update(&value);
        for (name, reference) in &storage.credential_env {
            if matches!(storage.service.as_str(), "gdrive" | "onedrive") && name == "refresh_token"
            {
                // Bind the named state/provider/client, not a rotating OAuth secret.
                continue;
            }
            let value = Zeroizing::new(
                std::env::var(reference).context("explicit storage credential unavailable")?,
            );
            hash.update(&(value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}
fn policy_digest(policy: &RemotePolicy) -> Result<String> {
    // RemotePolicy is deserialize-only. Bind all authenticated fields, including scheduling
    // and exclusions, so receipts cannot silently cross policy revisions.
    Ok(digest(&serde_json::to_vec(&serde_json::json!({
        "name":policy.name,"hostId":policy.host_id,"intervalMinutes":policy.interval_minutes,
        "endOfSession":policy.end_of_session,"retentionDays":policy.retention_days,
        "exclusions":policy.exclusions,"sizeCapBytes":policy.size_cap_bytes,"immutable":policy.immutable,
        "drCopy":policy.dr_copy,"residency":policy.residency,"storage":policy.storage,
        "storageRef":policy.storage_ref,"keyRef":policy.key_ref,"massDeleteThreshold":policy.mass_delete_threshold,
        "missedBackupMinutes":policy.missed_backup_minutes,"restoreTestIntervalHours":policy.restore_test_interval_hours,
        "channels":policy.channels
    }))?))
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn checked_path(path: &Path, may_create: bool) -> Result<PathBuf> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
        "host storage paths must be normalized absolute paths"
    );
    if path.exists() {
        ensure!(
            path.canonicalize()? == path,
            "host storage path contains a symlink"
        );
    } else {
        ensure!(may_create, "host storage path does not exist");
        ensure!(
            fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "unsafe host storage path"
        );
        let parent = path.parent().context("host storage parent required")?;
        ensure!(
            parent.canonicalize()? == parent,
            "host storage parent contains a symlink"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for parent in path.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir()
                    && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0),
                "host storage ancestor is writable by other users"
            );
        }
    }
    Ok(path.to_owned())
}
fn private_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            (if directory {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.nlink() == 1
            }) && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "host storage files/directories must be owner-only, regular and not linked"
        );
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, directory);
        anyhow::bail!("host storage ACL validation is not implemented on this platform")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        _temp: tempfile::TempDir,
        repo: Repository,
        snapshot: String,
        adapter: HostStorageAdapter,
        custody: Custody,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let work = base.join("work");
            fs::create_dir(&work).unwrap();
            fs::write(work.join("file"), "publication fixture").unwrap();
            let remote = base.join("remote");
            fs::create_dir(&remote).unwrap();
            fs::set_permissions(&remote, fs::Permissions::from_mode(0o700)).unwrap();
            let primary = base.join("storage.toml");
            fs::write(
                &primary,
                format!("service='local'\n[options]\nroot='{}'\n", remote.display()),
            )
            .unwrap();
            fs::set_permissions(&primary, fs::Permissions::from_mode(0o600)).unwrap();
            let repo = Repository::init(&base.join("repo"), "publication-fixture").unwrap();
            let snapshot = repo
                .snapshot(&work, &Policy::default(), None, None, "fixture")
                .unwrap()
                .id;
            let config = HostStorageConfig {
                primary,
                secondary: None,
                required_until: None,
                report_directory: base.join("reports"),
                consumer_state: None,
            };
            let adapter =
                HostStorageAdapter::open(&config, &repo, &work, "archive", "wrapped").unwrap();
            let custody = Custody::open(&config.report_directory).unwrap();
            Self {
                _temp: temp,
                repo,
                snapshot,
                adapter,
                custody,
            }
        }
        fn context(&self) -> Publication<'_> {
            Publication {
                repo: &self.repo,
                custody: &self.custody,
                key: "fixture",
                binding: &self.adapter.binding,
                snapshot: &self.snapshot,
                policy: "fixture-policy",
            }
        }
    }

    struct FailCheckpoint(opendal::Operator);
    impl RemoteStore for FailCheckpoint {
        async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
            self.0.read_bounded(path, maximum).await
        }
        async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
            ensure!(
                !path.contains("/checkpoints/"),
                "injected secondary publication failure"
            );
            self.0.create_verified(path, bytes).await
        }
    }
    fn memory() -> opendal::Operator {
        opendal::Operator::new(opendal::services::Memory::default()).unwrap()
    }

    #[test]
    fn partial_dr_failure_never_creates_receipt_or_advances_latest() {
        let fixture = Fixture::new();
        let primary = memory();
        let secondary = FailCheckpoint(memory());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(publish(
            &fixture.context(),
            &PairedStore {
                primary: &primary,
                secondary: &secondary,
            },
            |_| panic!("report callback must not run on partial replication"),
        ));
        assert!(result.is_err());
        assert!(fixture.custody.read("fixture.receipt").unwrap().is_none());
        assert!(!fixture.repo.root().join("checkpoints/latest").exists());
        runtime
            .block_on(publish(
                &fixture.context(),
                &PairedStore {
                    primary: &primary,
                    secondary: &secondary.0,
                },
                |result| {
                    Ok(vec![
                        serde_json::to_vec(result)?,
                        serde_json::to_vec(result)?,
                    ])
                },
            ))
            .unwrap();
        let bytes = fixture.custody.read("fixture.receipt").unwrap().unwrap();
        let receipt: Receipt =
            serde_json::from_slice(&fixture.repo.open_metadata(RECEIPT_DOMAIN, &bytes).unwrap())
                .unwrap();
        assert_eq!(receipt.sequence, 1);
        assert_eq!(fixture.context().reports(&receipt).unwrap().len(), 2);
        fixture.context().validate_receipt(&receipt).unwrap();
        runtime
            .block_on(verify_inventory(&primary, &receipt.inventory))
            .unwrap();
        runtime
            .block_on(verify_inventory(&secondary.0, &receipt.inventory))
            .unwrap();
    }

    #[test]
    fn external_report_failure_after_upload_does_not_advance_checkpoint() {
        let fixture = Fixture::new();
        let backend = memory();
        fixture.custody.dir.create_dir("fixture-0.json").unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(publish(&fixture.context(), &backend, |report| {
            Ok(vec![serde_json::to_vec(report)?])
        }));
        assert!(result.is_err());
        assert!(!fixture.repo.root().join("checkpoints/latest").exists());
        assert!(fixture.custody.read("fixture.receipt").unwrap().is_none());
        fixture.custody.dir.remove_dir("fixture-0.json").unwrap();
        runtime
            .block_on(publish(&fixture.context(), &backend, |report| {
                Ok(vec![serde_json::to_vec(report)?])
            }))
            .unwrap();
        let receipt: Receipt = serde_json::from_slice(
            &fixture
                .repo
                .open_metadata(
                    RECEIPT_DOMAIN,
                    &fixture.custody.read("fixture.receipt").unwrap().unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.sequence, 1);
    }

    #[test]
    fn report_success_without_durable_receipt_is_not_publication_success() {
        let fixture = Fixture::new();
        let backend = memory();
        fixture.custody.dir.create_dir("fixture.receipt").unwrap();
        let result = tokio::runtime::Runtime::new().unwrap().block_on(publish(
            &fixture.context(),
            &backend,
            |report| Ok(vec![serde_json::to_vec(report)?]),
        ));
        assert!(result.is_err());
        assert!(fixture.custody.read("fixture-0.json").unwrap().is_some());
        assert!(!fixture.repo.root().join("checkpoints/latest").exists());
    }

    #[test]
    fn authenticated_receipt_still_requires_exact_snapshot_and_policy_binding() {
        let fixture = Fixture::new();
        let backend = memory();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(publish(&fixture.context(), &backend, |report| {
                Ok(vec![serde_json::to_vec(report)?])
            }))
            .unwrap();
        let bytes = fixture.custody.read("fixture.receipt").unwrap().unwrap();
        let mut receipt: Receipt =
            serde_json::from_slice(&fixture.repo.open_metadata(RECEIPT_DOMAIN, &bytes).unwrap())
                .unwrap();
        receipt.snapshot = "0".repeat(64);
        assert!(fixture.context().validate_receipt(&receipt).is_err());
        receipt.snapshot = fixture.snapshot.clone();
        receipt.policy = "old-policy".into();
        assert!(fixture.context().validate_receipt(&receipt).is_err());
        receipt.policy = "fixture-policy".into();
        receipt.checkpoint[0] ^= 1;
        assert!(fixture.context().validate_receipt(&receipt).is_err());
    }
}
