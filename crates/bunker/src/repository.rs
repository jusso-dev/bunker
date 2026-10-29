use crate::{crypto, policy::Policy};
use anyhow::{anyhow, bail, ensure, Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const FORMAT_VERSION: u32 = 1;
const MAX_MANIFEST: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    salt: [u8; 16],
    wrapped_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_key: Option<bunker_keys::WrappedKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authentication: Option<String>,
}

#[path = "repository_keys.rs"]
mod keys;
pub use keys::KeySource;
#[path = "repository_maintenance.rs"]
mod maintenance;
pub use maintenance::{MaintenancePlan, MaintenanceReport};
#[path = "repository_setup.rs"]
mod setup;
pub use setup::{SetupScope, SetupSnapshot};

#[path = "repository_git.rs"]
mod git;
pub use git::{GitArtifact, GitPart, RecoveryPlan};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub hash: String,
    pub chunks: Vec<String>,
    pub executable: bool,
    #[serde(default)]
    pub secret_references: Vec<bunker_discovery::SecretReference>,
    #[serde(default)]
    pub sanitized: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub id: String,
    pub created_at: u64,
    pub agent: Option<String>,
    pub session: Option<String>,
    pub trigger: String,
    pub region: Option<String>,
    pub files: Vec<FileEntry>,
    pub skipped: Vec<String>,
    #[serde(default)]
    pub diagnostics: Vec<FileDiagnostic>,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<SetupScope>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiagnostic {
    pub path: String,
    pub reason: String,
    pub attempts: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub action: String,
    pub before: Option<String>,
    pub after: String,
    pub before_size: Option<u64>,
    pub after_size: u64,
    pub before_executable: Option<bool>,
    pub after_executable: bool,
    pub requires_rebind: bool,
    pub preview: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePlan {
    pub snapshot: String,
    pub destination: String,
    pub changes: Vec<Change>,
    pub confirmation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<bunker_git::RestorePlan>,
}

pub struct Repository {
    root: PathBuf,
    dir: Dir,
    key: Zeroizing<[u8; 32]>,
    header_digest: std::sync::RwLock<[u8; 32]>,
    _lock: fs::File,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn valid_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid object identifier"
    );
    Ok(())
}
pub fn safe_path(path: &str) -> Result<()> {
    bunker_discovery::validate_relative_path(Path::new(path))?;
    ensure!(
        !path.is_empty() && !path.contains('\\') && !path.contains(':') && !path.contains('\0'),
        "invalid relative path"
    );
    ensure!(
        Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "path must be relative with no traversal"
    );
    ensure!(
        path.split('/')
            .all(|c| !c.is_empty() && !c.ends_with('.') && !c.ends_with(' ')),
        "non-portable path"
    );
    Ok(())
}
fn read_bounded(dir: &Dir, path: &str, maximum: u64) -> Result<Vec<u8>> {
    safe_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = dir.open_with(path, &options)?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "expected a regular file");
    ensure!(before.len() <= maximum, "file exceeds safety limit");
    let mut data = Vec::new();
    Read::take(&mut file, maximum + 1).read_to_end(&mut data)?;
    let after = file.metadata()?;
    ensure!(
        data.len() as u64 <= maximum,
        "file grew beyond safety limit"
    );
    ensure!(
        before.len() == after.len()
            && before.modified()? == after.modified()?
            && data.len() as u64 == after.len(),
        "file changed while being read; retry snapshot"
    );
    Ok(data)
}
pub(crate) fn atomic_write(dir: &Dir, path: &str, bytes: &[u8], replace: bool) -> Result<()> {
    atomic_write_inner(dir, path, bytes, replace, true)
}
fn atomic_write_inner(
    dir: &Dir,
    path: &str,
    bytes: &[u8],
    replace: bool,
    sync_directory: bool,
) -> Result<()> {
    safe_path(path)?;
    if !replace && dir.try_exists(path)? {
        bail!("destination already exists");
    }
    let parent = Path::new(path).parent().unwrap_or(Path::new(""));
    if !parent.as_os_str().is_empty() {
        dir.create_dir_all(parent)?;
    }
    let temp = parent.join(format!(
        ".bunker-{}.tmp",
        hex::encode(crypto::random::<16>())
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = dir.open_with(&temp, &options)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            dir.rename(&temp, dir, path)?;
        } else {
            // Atomic no-clobber publication; an existence check plus rename races.
            dir.hard_link(&temp, dir, path)?;
            dir.remove_file(&temp)?;
        }
        if sync_directory {
            sync_parents(dir, parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = dir.remove_file(&temp);
    }
    result
}

impl Repository {
    pub fn init(path: &Path, passphrase: &str) -> Result<Self> {
        Self::init_with_key_source(path, &KeySource::passphrase(passphrase))
    }
    pub fn open(path: &Path, passphrase: &str) -> Result<Self> {
        Self::open_with_key_source(path, &KeySource::passphrase(passphrase))
    }
    pub fn rewrap_passphrase(&self, new_passphrase: &str) -> Result<()> {
        self.rewrap_key(&KeySource::passphrase(new_passphrase))
    }
    /// Compatibility alias: this rewraps the existing data key, it does not rotate it.
    pub fn rotate_passphrase(&self, new_passphrase: &str) -> Result<()> {
        self.rewrap_passphrase(new_passphrase)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn encrypted_object(&self, path: &str) -> Result<Vec<u8>> {
        if path == "repository.json" {
            let bytes = read_bounded(&self.dir, path, 8192)?;
            ensure!(
                *blake3::hash(&bytes).as_bytes()
                    == *self
                        .header_digest
                        .read()
                        .map_err(|_| anyhow!("header lock poisoned"))?,
                "repository header changed since unlock"
            );
            return Ok(bytes);
        }
        if let Some(id) = path.strip_prefix("chunks/") {
            valid_id(id)?;
            let bytes = read_bounded(&self.dir, path, 8 * 1024 * 1024 + 40)?;
            self.decode_chunk(id, &bytes)?;
            return Ok(bytes);
        }
        if let Some(id) = path.strip_prefix("snapshots/") {
            valid_id(id)?;
            let bytes = read_bounded(&self.dir, path, MAX_MANIFEST)?;
            self.decode_manifest(id, &bytes)?;
            return Ok(bytes);
        }
        bail!("only encrypted repository objects can be exported")
    }
    fn put_chunk(&self, bytes: &[u8]) -> Result<String> {
        let id = blake3::keyed_hash(&self.key, bytes).to_hex().to_string();
        let path = format!("chunks/{id}");
        if self.dir.try_exists(&path)? {
            ensure!(*self.chunk(&id)? == bytes, "existing chunk is corrupt");
        } else {
            atomic_write_inner(
                &self.dir,
                &path,
                &crypto::seal(&self.key, bytes, id.as_bytes())?,
                false,
                false,
            )?;
        }
        Ok(id)
    }
    fn chunk(&self, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        valid_id(id)?;
        let encrypted = read_bounded(&self.dir, &format!("chunks/{id}"), 8 * 1024 * 1024 + 40)?;
        self.decode_chunk(id, &encrypted)
    }
    fn decode_chunk(&self, id: &str, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = crypto::open(&self.key, encrypted, id.as_bytes())?;
        ensure!(
            blake3::keyed_hash(&self.key, &bytes).to_hex().as_str() == id,
            "chunk digest mismatch"
        );
        Ok(bytes)
    }
    pub fn manifest(&self, id: &str) -> Result<Manifest> {
        valid_id(id)?;
        let bytes = read_bounded(&self.dir, &format!("snapshots/{id}"), MAX_MANIFEST)?;
        self.decode_manifest(id, &bytes)
    }
    fn decode_manifest(&self, id: &str, bytes: &[u8]) -> Result<Manifest> {
        let plain = crypto::open(&self.key, bytes, id.as_bytes())?;
        let manifest: Manifest = serde_json::from_slice(&plain)?;
        if let Some(scope) = &manifest.setup {
            scope.validate()?;
            ensure!(
                manifest.git.is_none(),
                "setup snapshots cannot include workspace Git state"
            );
        }
        ensure!(
            manifest.version == FORMAT_VERSION && manifest.id == id,
            "invalid snapshot manifest"
        );
        let mut paths = HashSet::new();
        let mut identities = bunker_discovery::PathIdentitySet::default();
        let mut total = 0u64;
        for file in &manifest.files {
            safe_path(&file.path)?;
            ensure!(
                paths.insert(file.path.clone()) && identities.insert(Path::new(&file.path)),
                "duplicate or case-colliding snapshot path"
            );
            ensure!(
                file.size <= 1024 * 1024 * 1024 && file.chunks.len() <= 262144,
                "manifest file exceeds safety limit"
            );
            valid_id(&file.hash)?;
            for chunk in &file.chunks {
                valid_id(chunk)?;
            }
            total = total
                .checked_add(file.size)
                .context("manifest size overflow")?;
        }
        ensure!(total == manifest.bytes, "manifest size mismatch");
        if let Some(git) = &manifest.git {
            git.validate()?;
        }
        Ok(manifest)
    }
    pub fn list(&self) -> Result<Vec<Manifest>> {
        let mut manifests = vec![];
        let mut inventory_bytes = 0u64;
        for entry in self.dir.read_dir("snapshots")? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("invalid snapshot name"))?;
            if name.starts_with('.') {
                continue;
            }
            ensure!(
                manifests.len() < 10000,
                "inventory exceeds 10000 snapshots; select a snapshot"
            );
            inventory_bytes = inventory_bytes
                .checked_add(entry.metadata()?.len())
                .context("inventory size overflow")?;
            ensure!(
                inventory_bytes <= MAX_MANIFEST,
                "inventory exceeds 64 MiB; select a snapshot"
            );
            manifests.push(self.manifest(&name)?);
        }
        manifests.sort_by_key(|m| (m.created_at, m.id.clone()));
        Ok(manifests)
    }
    pub fn snapshot(
        &self,
        workspace: &Path,
        policy: &Policy,
        agent: Option<String>,
        session: Option<String>,
        trigger: &str,
    ) -> Result<Manifest> {
        self.snapshot_with_previous(workspace, policy, agent, session, trigger, None)
    }
    /// A caller-bound previous capture enables authenticated Git history comparison.
    /// Do not infer a workspace baseline from unrelated repository-wide snapshots.
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot_with_previous(
        &self,
        workspace: &Path,
        policy: &Policy,
        agent: Option<String>,
        session: Option<String>,
        trigger: &str,
        previous: Option<&Manifest>,
    ) -> Result<Manifest> {
        policy.validate()?;
        let workspace = workspace.canonicalize()?;
        ensure!(
            !self.root.starts_with(&workspace) && !workspace.starts_with(&self.root),
            "repository and workspace must be disjoint"
        );
        let source = Dir::open_ambient_dir(&workspace, ambient_authority())?;
        let exclusions = bunker_discovery::ExclusionPolicy::new(&bunker_discovery::SafetyPolicy {
            extra_excludes: policy.exclusions.clone(),
            default_includes: policy.default_includes.clone(),
            ..Default::default()
        })?;
        let mut manifest = Manifest {
            version: FORMAT_VERSION,
            id: hex::encode(crypto::random::<32>()),
            created_at: now(),
            agent,
            session,
            trigger: trigger.into(),
            region: policy.region.clone(),
            files: vec![],
            skipped: vec![],
            diagnostics: vec![],
            bytes: 0,
            git: None,
            setup: None,
        };
        // Hold cooperative exclusion through both Git and workspace capture.
        let _git_access = match git::ExclusiveAccess::optional(&workspace) {
            Ok(access) => {
                if access.is_some() {
                    let captured = match previous {
                        Some(previous) => {
                            self.capture_git_with_previous(&workspace, policy, Some(previous))
                        }
                        None => self.capture_git(&workspace, policy),
                    };
                    match captured {
                        Ok(artifact) => manifest.git = Some(artifact),
                        Err(_) => manifest.diagnostics.push(git::capture_diagnostic()),
                    }
                }
                access
            }
            Err(_) => {
                manifest.diagnostics.push(git::capture_diagnostic());
                None
            }
        };
        let mut candidates = vec![];
        let mut identities = bunker_discovery::PathIdentitySet::default();
        let mut total = 0u64;
        let mut walker = walkdir::WalkDir::new(&workspace)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter();
        let mut visited = 0usize;
        while let Some(entry) = walker.next() {
            visited += 1;
            ensure!(
                visited <= 100000,
                "snapshot exceeds 100000 visited entries; narrow workspace or policy"
            );
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    manifest.diagnostics.push(FileDiagnostic {
                        path: error
                            .path()
                            .and_then(|p| p.strip_prefix(&workspace).ok())
                            .map(|p| p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
                            .unwrap_or_default(),
                        reason: "directory_read_failed".into(),
                        attempts: 1,
                    });
                    continue;
                }
            };
            if entry.depth() == 0 {
                continue;
            }
            let relative_path = entry.path().strip_prefix(&workspace)?;
            let relative = relative_path
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            let reason = exclusions.reason(relative_path);
            let reason = match reason {
                Ok(reason) => reason,
                Err(_) => {
                    manifest.diagnostics.push(FileDiagnostic {
                        path: relative.clone(),
                        reason: "unsupported_path".into(),
                        attempts: 0,
                    });
                    if entry.file_type().is_dir() {
                        walker.skip_current_dir();
                    }
                    continue;
                }
            };
            if let Some(reason) = reason {
                // An include may target a descendant of a default-excluded directory.
                if entry.file_type().is_dir()
                    && !policy.default_includes.is_empty()
                    && bunker_discovery::is_default_artifact(&reason)
                {
                    continue;
                }
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                manifest.skipped.push(relative.clone());
                let reason = match reason {
                    bunker_discovery::ExclusionReason::Policy => "policy_exclusion".to_owned(),
                    bunker_discovery::ExclusionReason::Credentials => "credential_path".to_owned(),
                    bunker_discovery::ExclusionReason::Environment => "environment_file".to_owned(),
                    bunker_discovery::ExclusionReason::Transcript => {
                        "agent_private_data".to_owned()
                    }
                    other => format!("excluded_{other:?}").to_ascii_lowercase(),
                };
                manifest.diagnostics.push(FileDiagnostic {
                    path: relative,
                    reason,
                    attempts: 0,
                });
                continue;
            }
            if !entry.file_type().is_file() {
                if !entry.file_type().is_dir() {
                    manifest.skipped.push(relative.clone());
                    manifest.diagnostics.push(FileDiagnostic {
                        path: relative,
                        reason: "not_regular_file".into(),
                        attempts: 0,
                    });
                }
                continue;
            }
            if relative_path.to_str().is_none() || safe_path(&relative).is_err() {
                manifest.skipped.push(relative.clone());
                manifest.diagnostics.push(FileDiagnostic {
                    path: relative,
                    reason: "unsupported_path".into(),
                    attempts: 0,
                });
                continue;
            }
            if !identities.insert(relative_path) {
                manifest.skipped.push(relative.clone());
                manifest.diagnostics.push(FileDiagnostic {
                    path: relative,
                    reason: "case_collision".into(),
                    attempts: 0,
                });
                continue;
            }
            let size = match entry.metadata() {
                Ok(meta) => meta.len(),
                Err(_) => {
                    manifest.skipped.push(relative.clone());
                    manifest.diagnostics.push(FileDiagnostic {
                        path: relative,
                        reason: "metadata_failed".into(),
                        attempts: 1,
                    });
                    continue;
                }
            };
            let cap = if agent_config(&relative) {
                policy.max_file_bytes.min(MAX_CONFIG)
            } else {
                policy.max_file_bytes
            };
            if size > cap {
                manifest.skipped.push(relative.clone());
                manifest.diagnostics.push(FileDiagnostic {
                    path: relative,
                    reason: "file_size_cap".into(),
                    attempts: 0,
                });
                continue;
            }
            total = total.checked_add(size).context("workspace size overflow")?;
            ensure!(
                total <= policy.size_cap_bytes,
                "workspace exceeds size_cap_bytes; no snapshot published"
            );
            ensure!(
                candidates.len() < 100000,
                "snapshot exceeds 100000 files; narrow workspace or policy"
            );
            candidates.push(relative);
        }
        for relative in candidates {
            let mut captured = None;
            for attempt in 1..=3 {
                let result = (|| -> Result<_> {
                    reject_symlinks(&source, &relative).context("unsafe_source_path")?;
                    let cap = if agent_config(&relative) {
                        policy.max_file_bytes.min(MAX_CONFIG)
                    } else {
                        policy.max_file_bytes
                    };
                    let original = Zeroizing::new(
                        read_bounded(&source, &relative, cap).context("source_read_failed")?,
                    );
                    let content = sanitize(&relative, &original)
                        .map_err(|error| anyhow!("configuration_sanitization_failed: {error}"))?;
                    let executable =
                        executable(&source, &relative).context("source_metadata_failed")?;
                    Ok((content, executable))
                })();
                match result {
                    Ok(value) => {
                        if attempt > 1 {
                            manifest.diagnostics.push(FileDiagnostic {
                                path: relative.clone(),
                                reason: "read_retry_succeeded".into(),
                                attempts: attempt,
                            });
                        }
                        captured = Some(value);
                        break;
                    }
                    Err(_) if attempt < 3 => {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(error) => {
                        manifest.skipped.push(relative.clone());
                        manifest.diagnostics.push(FileDiagnostic {
                            path: relative.clone(),
                            reason: error.to_string(),
                            attempts: attempt,
                        });
                    }
                }
            }
            let Some((content, executable)) = captured else {
                continue;
            };
            let bytes = Zeroizing::new(content.bytes);
            manifest.bytes = manifest
                .bytes
                .checked_add(bytes.len() as u64)
                .context("size overflow")?;
            ensure!(
                manifest.bytes <= policy.size_cap_bytes,
                "workspace exceeds size_cap_bytes; no snapshot published"
            );
            let mut chunks = vec![];
            for chunk in fastcdc::v2020::FastCDC::new(&bytes, 64 * 1024, 256 * 1024, 1024 * 1024) {
                chunks.push(self.put_chunk(&bytes[chunk.offset..chunk.offset + chunk.length])?);
            }
            manifest.files.push(FileEntry {
                path: relative,
                size: bytes.len() as u64,
                hash: blake3::hash(&bytes).to_hex().to_string(),
                chunks,
                executable,
                sanitized: content.modified,
                secret_references: content.secret_references,
            });
        }
        if manifest.git.as_ref().is_some_and(|git| {
            manifest
                .bytes
                .saturating_add(git.metadata.size)
                .saturating_add(git.pack.size)
                > policy.size_cap_bytes
        }) {
            manifest.git = None;
            manifest.diagnostics.push(FileDiagnostic {
                path: ".git".into(),
                reason: "git_capture_size_cap".into(),
                attempts: 1,
            });
        }
        // Each new chunk has synced file data; publish the directory once before
        // any manifest can reference those chunks.
        #[cfg(unix)]
        self.dir.open_dir("chunks")?.into_std_file().sync_all()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&manifest)?);
        ensure!(
            plaintext.len() as u64 + 40 <= MAX_MANIFEST,
            "snapshot has too many files"
        );
        atomic_write(
            &self.dir,
            &format!("snapshots/{}", manifest.id),
            &crypto::seal(&self.key, &plaintext, manifest.id.as_bytes())?,
            false,
        )?;
        Ok(manifest)
    }
    pub fn file_bytes(&self, file: &FileEntry) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        for id in &file.chunks {
            let chunk = self.chunk(id)?;
            ensure!(
                bytes.len() as u64 + chunk.len() as u64 <= file.size,
                "file size mismatch"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            bytes.len() as u64 == file.size && blake3::hash(&bytes).to_hex().as_str() == file.hash,
            "file integrity check failed"
        );
        Ok(bytes)
    }
    pub fn verify(&self, id: &str) -> Result<Manifest> {
        let manifest = self.manifest(id)?;
        for file in &manifest.files {
            self.file_bytes(file)?;
        }
        if let Some(git) = &manifest.git {
            self.git_capture(git)?;
        }
        Ok(manifest)
    }
    pub fn plan(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RestorePlan> {
        let _access = if selection.is_none() && self.manifest(id)?.git.is_some() {
            Some(git::ExclusiveAccess::required(
                &destination.canonicalize()?,
            )?)
        } else {
            None
        };
        self.plan_locked(id, destination, selection)
    }
    fn plan_locked(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RestorePlan> {
        let manifest = self.manifest(id)?;
        let destination = destination
            .canonicalize()
            .context("restore destination must exist")?;
        ensure!(
            !destination.starts_with(&self.root) && !self.root.starts_with(&destination),
            "cannot restore into or around the repository"
        );
        let dir = Dir::open_ambient_dir(&destination, ambient_authority())?;
        let mut changes = vec![];
        let mut preview_bytes = 0usize;
        let mut found = selection.is_none();
        for file in &manifest.files {
            if selection.is_some_and(|s| s != file.path) {
                continue;
            }
            found = true;
            reject_symlinks(&dir, &file.path)?;
            let before_state = destination_state(&dir, &file.path)?;
            let before = before_state.as_ref().map(|s| s.0.clone());
            let unchanged = before_state
                .as_ref()
                .is_some_and(|s| s.0 == file.hash && s.2 == file.executable);
            let requires_rebind = file.sanitized
                || file
                    .secret_references
                    .iter()
                    .any(|r| r.kind == bunker_discovery::ReferenceKind::RebindRequired)
                || (file.secret_references.is_empty()
                    && agent_config(&file.path)
                    && (file.size > MAX_CONFIG
                        || self
                            .file_bytes(file)?
                            .windows(b"BUNKER_SECRET_".len())
                            .any(|w| w == b"BUNKER_SECRET_")));
            // Legacy manifests did not persist references. Their generated
            // placeholders still require explicit rebind-overwrite consent.
            let preview = if unchanged {
                "No content or executable-mode changes.".into()
            } else {
                self.preview(&dir, file, before_state.is_some())?
            };
            preview_bytes += preview.len();
            ensure!(
                preview_bytes <= 4 * 1024 * 1024,
                "preview exceeds 4 MiB; select a file"
            );
            ensure!(
                changes.len() < 10000,
                "preview exceeds 10000 files; select a file"
            );
            changes.push(Change {
                path: file.path.clone(),
                action: if unchanged {
                    "unchanged"
                } else if before.is_some() {
                    "overwrite"
                } else {
                    "create"
                }
                .into(),
                before_size: before_state.as_ref().map(|s| s.1),
                before_executable: before_state.as_ref().map(|s| s.2),
                after_size: file.size,
                after_executable: file.executable,
                requires_rebind,
                preview,
                before,
                after: file.hash.clone(),
            });
        }
        ensure!(found, "selected file is not in snapshot");
        let mut plan = RestorePlan {
            snapshot: id.into(),
            destination: destination.to_string_lossy().into_owned(),
            changes,
            confirmation: String::new(),
            git: if selection.is_none() {
                manifest
                    .git
                    .as_ref()
                    .map(|artifact| {
                        bunker_git::GitBackup::default()
                            .plan_restore(&destination, &self.git_capture(artifact)?)
                    })
                    .transpose()?
            } else {
                None
            },
        };
        plan.confirmation = blake3::hash(&serde_json::to_vec(&plan)?)
            .to_hex()
            .to_string();
        Ok(plan)
    }
    fn preview(&self, dir: &Dir, file: &FileEntry, exists: bool) -> Result<String> {
        const LIMIT: u64 = 16 * 1024;
        if file.size > LIMIT || (exists && dir.metadata(&file.path)?.len() > LIMIT) {
            return Ok(
                "Content preview omitted (larger than 16 KiB); see size and executable mode."
                    .into(),
            );
        }
        let before = if exists {
            Zeroizing::new(read_bounded(dir, &file.path, LIMIT)?)
        } else {
            Zeroizing::new(vec![])
        };
        let after = self.file_bytes(file)?;
        let redact = |bytes: &[u8]| -> String {
            match bunker_discovery::sanitize(bytes, bunker_discovery::FileFormat::Text) {
                Ok(content) => String::from_utf8_lossy(&content.bytes).into_owned(),
                Err(_) => "[binary or sensitive content omitted]".into(),
            }
        };
        // Complete small-file views are deliberately simple, bounded, and redacted.
        let mut preview = String::from("--- current (redacted)\n+++ snapshot (redacted)\n");
        for line in redact(&before).lines() {
            preview.push_str(&format!("- {line}\n"));
        }
        for line in redact(&after).lines() {
            preview.push_str(&format!("+ {line}\n"));
        }
        Ok(preview)
    }
    pub fn restore(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
        confirmation: &str,
    ) -> Result<RestorePlan> {
        self.restore_with_options(id, destination, selection, confirmation, false)
    }
    /// Local operator action, NOT independent human authentication. An agent with
    /// the same OS identity can call this too; MCP requests never route here.
    pub fn restore_with_options(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
        confirmation: &str,
        allow_rebind_overwrite: bool,
    ) -> Result<RestorePlan> {
        self.restore_with_authorization(
            id,
            destination,
            selection,
            confirmation,
            allow_rebind_overwrite,
            || Ok(()),
        )
    }
    /// Revalidate independent authorization after staging and at mutation boundaries.
    /// An authorization failure retains the encrypted transaction for recovery.
    pub fn restore_with_authorization(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
        confirmation: &str,
        allow_rebind_overwrite: bool,
        mut authorize: impl FnMut() -> Result<()>,
    ) -> Result<RestorePlan> {
        authorize()?;
        let _access = if selection.is_none() && self.manifest(id)?.git.is_some() {
            Some(git::ExclusiveAccess::required(
                &destination.canonicalize()?,
            )?)
        } else {
            None
        };
        let plan = self.plan_locked(id, destination, selection)?;
        ensure!(
            confirmation == plan.confirmation,
            "restore confirmation missing or stale; review fresh diff"
        );
        ensure!(allow_rebind_overwrite || !plan.changes.iter().any(|c| c.requires_rebind && c.before.is_some() && c.action != "unchanged"),
            "sanitized configuration would overwrite existing settings with unbound secret placeholders; explicitly opt in with --allow-rebind-overwrite");
        let manifest = self.manifest(id)?;
        for file in &manifest.files {
            if selection.is_none_or(|selected| selected == file.path) {
                self.file_bytes(file)?;
            }
        }
        if let Some(artifact) = manifest.git.as_ref().filter(|_| selection.is_none()) {
            self.git_capture(artifact)?;
        }
        let dir = Dir::open_ambient_dir(&plan.destination, ambient_authority())?;
        let entries: BTreeMap<_, _> = manifest
            .files
            .iter()
            .map(|f| (f.path.as_str(), f))
            .collect();
        ensure!(
            plan.changes.len() <= 10000,
            "restore exceeds 10000-file transaction limit; select a file"
        );
        let transaction = hex::encode(crypto::random::<32>());
        let base = format!("transactions/{transaction}");
        let mut journal = serde_json::json!({"id":transaction,"plan":plan,"status":"staging","applied":[],"preimages":[]});
        let save_journal = |value: &serde_json::Value| -> Result<()> {
            atomic_write(
                &self.dir,
                &format!("{base}/journal"),
                &crypto::seal(
                    &self.key,
                    &serde_json::to_vec(value)?,
                    transaction.as_bytes(),
                )?,
                true,
            )
        };
        save_journal(&journal)?;
        let result = (|| -> Result<()> {
            let mut staged_bytes = 0u64;
            for (index, change) in plan.changes.iter().enumerate() {
                if change.action == "unchanged" {
                    continue;
                }
                reject_symlinks(&dir, &change.path)?;
                let current = destination_state(&dir, &change.path)?;
                ensure!(
                    current.as_ref().map(|s| &s.0) == change.before.as_ref()
                        && current.as_ref().map(|s| s.2) == change.before_executable,
                    "destination changed since preview"
                );
                staged_bytes = staged_bytes
                    .checked_add(change.before_size.unwrap_or(0))
                    .and_then(|n| n.checked_add(change.after_size))
                    .context("restore size overflow")?;
                ensure!(
                    staged_bytes <= 2 * 1024 * 1024 * 1024,
                    "restore staging exceeds 2 GiB; select a file"
                );
                if change.before.is_some() {
                    let original =
                        Zeroizing::new(read_bounded(&dir, &change.path, 1024 * 1024 * 1024)?);
                    ensure!(
                        Some(blake3::hash(&original).to_hex().to_string()) == change.before,
                        "destination changed while staging"
                    );
                    atomic_write(
                        &self.dir,
                        &format!("{base}/{index}.before"),
                        &crypto::seal(&self.key, &original, transaction.as_bytes())?,
                        false,
                    )?;
                }
                let bytes = self.file_bytes(entries[change.path.as_str()])?;
                atomic_write(
                    &self.dir,
                    &format!("{base}/{index}.after"),
                    &crypto::seal(&self.key, &bytes, transaction.as_bytes())?,
                    false,
                )?;
                journal["preimages"].as_array_mut().unwrap().push(serde_json::json!({"index":index,"path":change.path,"existed":change.before.is_some(),"executable":change.before_executable}));
                save_journal(&journal)?;
            }
            // Audit and persist intent before changing any destination file.
            self.audit(
                "restore_started",
                serde_json::json!({"transaction":transaction,"snapshot":id}),
            )?;
            journal["status"] = serde_json::json!("applying");
            save_journal(&journal)?;
            authorize()?;
            if let Some(git_plan) = &plan.git {
                let capture =
                    self.git_capture(manifest.git.as_ref().context("missing Git artifact")?)?;
                bunker_git::GitBackup::default().apply_restore_with_authorization(
                    git_plan,
                    &capture,
                    |git_journal| {
                        self.save_git_journal(&transaction, git_journal)?;
                        journal["git_started"] = serde_json::json!(true);
                        save_journal(&journal)
                    },
                    &mut authorize,
                )?;
                journal["git_applied"] = serde_json::json!(true);
                save_journal(&journal)?;
            }
            for (index, change) in plan.changes.iter().enumerate() {
                if change.action == "unchanged" {
                    continue;
                }
                reject_symlinks(&dir, &change.path)?;
                let current = destination_state(&dir, &change.path)?;
                ensure!(
                    current.as_ref().map(|s| &s.0) == change.before.as_ref()
                        && current.as_ref().map(|s| s.2) == change.before_executable,
                    "destination changed before write"
                );
                journal["in_flight"] = serde_json::json!(index);
                save_journal(&journal)?;
                let encrypted = read_bounded(
                    &self.dir,
                    &format!("{base}/{index}.after"),
                    1024 * 1024 * 1024 + 40,
                )?;
                let bytes = crypto::open(&self.key, &encrypted, transaction.as_bytes())?;
                authorize()?;
                atomic_write(&dir, &change.path, &bytes, change.before.is_some())?;
                #[cfg(unix)]
                {
                    use cap_std::fs::PermissionsExt;
                    authorize()?;
                    dir.set_permissions(
                        &change.path,
                        cap_std::fs::Permissions::from_mode(if change.after_executable {
                            0o700
                        } else {
                            0o600
                        }),
                    )?;
                    dir.open(&change.path)?.sync_all()?;
                }
                journal["applied"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!(index));
                journal["in_flight"] = serde_json::Value::Null;
                save_journal(&journal)?;
            }
            journal["status"] = serde_json::json!("completed");
            save_journal(&journal)?;
            for (index, change) in plan.changes.iter().enumerate() {
                if change.action != "unchanged" {
                    self.dir.remove_file(format!("{base}/{index}.after"))?;
                }
            }
            sync_parents(&self.dir, Path::new(&base))?;
            self.audit(
                "restore_completed",
                serde_json::json!({"transaction":transaction,"snapshot":id}),
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            // Never erase evidence: a crash or failed write leaves encrypted
            // preimages, staged files and durable in-flight/progress metadata.
            let outcome = if journal["status"] == "completed" {
                "completed_audit_failed"
            } else {
                "interrupted"
            };
            journal["status"] = serde_json::json!(outcome);
            let _ = save_journal(&journal);
            return Err(error.context(format!("restore {outcome}; inspect encrypted transaction {transaction}; preimages retained")));
        }
        Ok(plan)
    }
    pub fn restore_journal(&self, id: &str) -> Result<serde_json::Value> {
        valid_id(id)?;
        let bytes = read_bounded(
            &self.dir,
            &format!("transactions/{id}/journal"),
            MAX_MANIFEST,
        )?;
        Ok(serde_json::from_slice(&crypto::open(
            &self.key,
            &bytes,
            id.as_bytes(),
        )?)?)
    }
    pub fn audit(&self, event: &str, detail: serde_json::Value) -> Result<()> {
        let id = hex::encode(crypto::random::<32>());
        let bytes =
            serde_json::to_vec(&serde_json::json!({"at":now(),"event":event,"detail":detail}))?;
        atomic_write(
            &self.dir,
            &format!("audit/{id}"),
            &crypto::seal(&self.key, &bytes, id.as_bytes())?,
            false,
        )
    }
    pub fn save_request(&self, value: &serde_json::Value) -> Result<String> {
        ensure!(
            self.dir.read_dir("requests")?.take(1024).count() < 1024,
            "request quota reached (1024); operator maintenance required"
        );
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        ensure!(
            bytes.len() <= 1024 * 1024,
            "request exceeds 1 MiB; select a file"
        );
        let id = hex::encode(crypto::random::<32>());
        atomic_write(
            &self.dir,
            &format!("requests/{id}"),
            &crypto::seal(&self.key, &bytes, id.as_bytes())?,
            false,
        )?;
        self.audit(
            "restore_requested",
            serde_json::json!({"request":id,"execution":"disabled_pending_independent_human_auth"}),
        )?;
        Ok(id)
    }
    pub fn request(&self, id: &str) -> Result<serde_json::Value> {
        valid_id(id)?;
        let encrypted = read_bounded(&self.dir, &format!("requests/{id}"), 1024 * 1024 + 40)?;
        Ok(serde_json::from_slice(&crypto::open(
            &self.key,
            &encrypted,
            id.as_bytes(),
        )?)?)
    }
    /// Operator-only maintenance, deliberately absent from MCP. Removes only
    /// authenticated decided or expired records; active pending requests survive.
    /// A bounded batch and audit-before-delete keep retries safe and reviewable.
    pub fn prune_requests(&self, limit: usize) -> Result<usize> {
        ensure!((1..=1024).contains(&limit), "prune limit must be 1..1024");
        let mut selected = vec![];
        for entry in self.dir.read_dir("requests")?.take(1024) {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if valid_id(&id).is_err() || !entry.file_type()?.is_file() {
                continue;
            }
            let request = match self.request(&id) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let decided = matches!(
                request["status"].as_str(),
                Some("denied" | "expired" | "approved")
            );
            let expired = request["status"] == "pending"
                && request["expires_at"]
                    .as_u64()
                    .is_some_and(|expiry| expiry <= now());
            if decided || expired {
                selected.push(id);
                if selected.len() == limit {
                    break;
                }
            }
        }
        if selected.is_empty() {
            return Ok(0);
        }
        self.audit(
            "restore_requests_prune",
            serde_json::json!({"requests": selected}),
        )?;
        for id in &selected {
            self.dir.remove_file(format!("requests/{id}"))?;
        }
        sync_parents(&self.dir, Path::new("requests"))?;
        Ok(selected.len())
    }
    pub fn decide_request(
        &self,
        id: &str,
        approve: bool,
        confirmation: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut request = self.request(id)?;
        ensure!(
            request["status"] == "pending",
            "request has already been decided"
        );
        let expired = request["expires_at"]
            .as_u64()
            .context("invalid request expiry")?
            <= now();
        let status = if expired {
            "expired"
        } else if approve {
            "approved"
        } else {
            "denied"
        };
        if approve && !expired {
            let _ = confirmation;
            bail!("request execution disabled: independent human authorization is not implemented; the repository passphrase, confirmation digest and TTY are not independent authority");
        }
        request["status"] = serde_json::json!(status);
        atomic_write(
            &self.dir,
            &format!("requests/{id}"),
            &crypto::seal(&self.key, &serde_json::to_vec(&request)?, id.as_bytes())?,
            true,
        )?;
        self.audit(
            "restore_request_decided",
            serde_json::json!({"request":id,"status":request["status"]}),
        )?;
        if expired {
            bail!("request expired; request a fresh preview");
        }
        Ok(request)
    }
}

fn reject_symlinks(dir: &Dir, path: &str) -> Result<()> {
    safe_path(path)?;
    let mut current = PathBuf::new();
    for component in Path::new(path).components() {
        current.push(component);
        match dir.symlink_metadata(&current) {
            Ok(meta) => ensure!(
                !meta.is_symlink(),
                "symlinks are not allowed in restore/source paths"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

const MAX_CONFIG: u64 = 1024 * 1024;

/// Only known structured agent setup targets are sanitized. Ordinary workspace
/// documents and code (including binaries) are always preserved byte-for-byte.
pub fn agent_config(path: &str) -> bool {
    bunker_discovery::agent_config(Path::new(path))
}
pub fn default_excluded(path: &Path) -> bool {
    bunker_discovery::ExclusionPolicy::new(&bunker_discovery::SafetyPolicy::default())
        .and_then(|p| p.reason(path))
        .map_or(true, |r| r.is_some())
}
fn sanitize(path: &str, input: &[u8]) -> Result<bunker_discovery::SanitizedContent> {
    if agent_config(path) {
        ensure!(
            input.len() as u64 <= MAX_CONFIG,
            "configuration exceeds sanitizer cap"
        );
        bunker_discovery::sanitize(
            input,
            bunker_discovery::FileFormat::for_path(Path::new(path)),
        )
    } else {
        Ok(bunker_discovery::SanitizedContent {
            bytes: input.to_vec(),
            modified: false,
            secret_references: vec![],
        })
    }
}
fn executable(dir: &Dir, path: &str) -> Result<bool> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        Ok(dir.metadata(path)?.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, path);
        Ok(false)
    }
}
fn sync_parents(dir: &Dir, parent: &Path) -> Result<()> {
    let mut current = parent.to_path_buf();
    loop {
        let target = if current.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &current
        };
        dir.open_dir(target)?.into_std_file().sync_all()?;
        if !current.pop() {
            break;
        }
    }
    Ok(())
}
pub(crate) fn durable_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing parent")?;
    let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
    atomic_write(
        &dir,
        path.file_name()
            .and_then(|p| p.to_str())
            .context("invalid name")?,
        bytes,
        true,
    )
}

/// Hash destination content with constant memory, checking for concurrent changes.
fn destination_state(dir: &Dir, path: &str) -> Result<Option<(String, u64, bool)>> {
    if !dir.try_exists(path)? {
        return Ok(None);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = dir.open_with(path, &options)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= 1024 * 1024 * 1024,
        "destination is not a regular file within 1 GiB cap"
    );
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(count <= 1024 * 1024 * 1024, "destination exceeds size cap");
        hasher.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    ensure!(
        count == before.len()
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "destination changed while hashing"
    );
    Ok(Some((
        hasher.finalize().to_hex().to_string(),
        count,
        executable(dir, path)?,
    )))
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn legacy_manifest_without_reference_metadata_still_requires_rebind_opt_in() {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(
            work.join(".mcp.json"),
            br#"{"env":{"API_KEY":"fixture-literal"}}"#,
        )
        .unwrap();
        let repo = Repository::init(&root.path().join("repo"), "fixture-passphrase-only").unwrap();
        let manifest = repo
            .snapshot(&work, &Policy::default(), None, None, "test")
            .unwrap();
        let mut legacy = serde_json::to_value(&manifest).unwrap();
        for file in legacy["files"].as_array_mut().unwrap() {
            file.as_object_mut().unwrap().remove("secret_references");
            file.as_object_mut().unwrap().remove("sanitized");
        }
        atomic_write(
            &repo.dir,
            &format!("snapshots/{}", manifest.id),
            &crypto::seal(
                &repo.key,
                &serde_json::to_vec(&legacy).unwrap(),
                manifest.id.as_bytes(),
            )
            .unwrap(),
            true,
        )
        .unwrap();
        let plan = repo.plan(&manifest.id, &work, None).unwrap();
        assert!(plan.changes[0].requires_rebind);
        assert!(repo
            .restore(&manifest.id, &work, None, &plan.confirmation)
            .is_err());
        assert!(fs::read_to_string(work.join(".mcp.json"))
            .unwrap()
            .contains("fixture-literal"));
    }
}
