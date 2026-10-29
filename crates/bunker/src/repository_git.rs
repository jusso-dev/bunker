//! Authenticated Git artifacts and the outer workspace/Git recovery transaction.
use super::*;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPart {
    pub size: u64,
    pub hash: String,
    pub chunks: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitArtifact {
    pub version: u32,
    pub metadata: GitPart,
    pub pack: GitPart,
}
impl GitArtifact {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported Git artifact version");
        let limits = bunker_git::Limits::default();
        for (part, cap) in [
            (&self.metadata, limits.max_metadata_bytes),
            (&self.pack, limits.max_pack_bytes),
        ] {
            ensure!(
                part.size <= cap as u64 && part.chunks.len() <= 8192,
                "Git artifact exceeds limit"
            );
            valid_id(&part.hash)?;
            for chunk in &part.chunks {
                valid_id(chunk)?;
            }
        }
        Ok(())
    }
}

/// This only excludes other Bunker operations. The operator/host MUST quiesce
/// other Git and filesystem writers; Git has no universal exclusive-access lock.
pub(super) struct ExclusiveAccess {
    path: PathBuf,
}
impl ExclusiveAccess {
    pub(super) fn optional(root: &Path) -> Result<Option<Self>> {
        match fs::symlink_metadata(root.join(".git")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => Self::required(root).map(Some),
        }
    }
    pub(super) fn required(root: &Path) -> Result<Self> {
        let canonical = root.canonicalize()?;
        // Refuse aliases before creating any lock; library repeats stricter checks.
        ensure!(
            root.is_absolute() && canonical == root,
            "Git root must be canonical and absolute"
        );
        let metadata = fs::symlink_metadata(root.join(".git"))?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Git requires an ordinary .git directory"
        );
        let path = root.join(".git/bunker-capture.lock");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .context(
                "exclusive Git access unavailable; stop writers and inspect abandoned locks",
            )?;
        let guard = Self { path };
        file.sync_all()?;
        Ok(guard)
    }
}
impl Drop for ExclusiveAccess {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
pub(super) fn capture_diagnostic() -> FileDiagnostic {
    FileDiagnostic {
        path: ".git".into(),
        reason: "git_capture_failed_or_unsupported".into(),
        attempts: 1,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    pub transaction: String,
    pub destination: String,
    pub paths: Vec<String>,
    pub restores_git: bool,
    pub confirmation: String,
}

impl Repository {
    /// Complete deduplicated dependency inventory for checkpoints and legacy exports.
    /// Call with an authenticated manifest returned by `manifest`/`verify`.
    pub fn snapshot_chunks(&self, manifest: &Manifest) -> Result<Vec<String>> {
        if let Some(git) = &manifest.git {
            git.validate()?;
        }
        for file in &manifest.files {
            safe_path(&file.path)?;
            valid_id(&file.hash)?;
            for chunk in &file.chunks {
                valid_id(chunk)?;
            }
        }
        let mut chunks: BTreeSet<_> = manifest
            .files
            .iter()
            .flat_map(|f| f.chunks.iter().cloned())
            .collect();
        if let Some(git) = &manifest.git {
            chunks.extend(git.metadata.chunks.iter().cloned());
            chunks.extend(git.pack.chunks.iter().cloned());
        }
        Ok(chunks.into_iter().collect())
    }
    fn store_git_part(&self, bytes: &[u8]) -> Result<GitPart> {
        let mut chunks = vec![];
        for chunk in fastcdc::v2020::FastCDC::new(bytes, 64 * 1024, 256 * 1024, 1024 * 1024) {
            chunks.push(self.put_chunk(&bytes[chunk.offset..chunk.offset + chunk.length])?);
        }
        Ok(GitPart {
            size: bytes.len() as u64,
            hash: blake3::keyed_hash(&self.key, bytes).to_hex().to_string(),
            chunks,
        })
    }
    pub(super) fn capture_git(&self, root: &Path, policy: &Policy) -> Result<GitArtifact> {
        let capture = bunker_git::GitBackup::default().capture(
            root,
            &bunker_git::CapturePolicy {
                extra_excludes: policy.exclusions.clone(),
            },
        )?;
        let metadata = Zeroizing::new(serde_json::to_vec(&capture.metadata)?);
        Ok(GitArtifact {
            version: 1,
            metadata: self.store_git_part(&metadata)?,
            pack: self.store_git_part(&capture.pack)?,
        })
    }
    /// Capture an authenticated comparison while the caller holds exclusive Git
    /// access. Previous metadata and all tracking tips remain encrypted locally.
    pub(super) fn capture_git_with_previous(
        &self,
        root: &Path,
        policy: &Policy,
        previous: Option<&Manifest>,
    ) -> Result<GitArtifact> {
        let previous = previous
            .and_then(|manifest| manifest.git.as_ref())
            .map(|artifact| self.git_capture(artifact))
            .transpose()
            // Prior damage makes comparison unavailable, not the current backup.
            // A capture without a baseline cannot claim a rewrite.
            .unwrap_or(None);
        let capture = bunker_git::GitBackup::default().capture_with_previous(
            root,
            &bunker_git::CapturePolicy {
                extra_excludes: policy.exclusions.clone(),
            },
            previous.as_ref().map(|capture| &capture.metadata),
        )?;
        let metadata = Zeroizing::new(serde_json::to_vec(&capture.metadata)?);
        Ok(GitArtifact {
            version: 1,
            metadata: self.store_git_part(&metadata)?,
            pack: self.store_git_part(&capture.pack)?,
        })
    }
    /// Content-free Git effects between authenticated snapshots; no live source
    /// or Git process is needed. Never forward artifact/decryption error chains.
    pub fn git_alerts(
        &self,
        previous: &Manifest,
        current: &Manifest,
    ) -> Result<bunker_git::GitAlerts> {
        let (Some(previous), Some(current)) = (&previous.git, &current.git) else {
            return Ok(bunker_git::GitAlerts::unavailable(
                bunker_git::GitDiagnostic::CaptureUnavailable,
            ));
        };
        let compare = || -> Result<bunker_git::GitAlerts> {
            let current = self.git_capture(current)?;
            let Ok(previous) = self.git_capture(previous) else {
                return Ok(bunker_git::GitAlerts::unavailable(
                    bunker_git::GitDiagnostic::ObservationUnavailable,
                ));
            };
            bunker_git::git_alerts(&previous.metadata, &current.metadata)
        };
        compare().map_err(|_| anyhow::anyhow!("Git observation unavailable"))
    }
    fn git_part(&self, part: &GitPart) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        for id in &part.chunks {
            let chunk = self.chunk(id)?;
            ensure!(
                bytes.len() as u64 + chunk.len() as u64 <= part.size,
                "Git artifact size mismatch"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            bytes.len() as u64 == part.size
                && blake3::keyed_hash(&self.key, &bytes).to_hex().as_str() == part.hash,
            "Git artifact integrity failure"
        );
        Ok(bytes)
    }
    pub(super) fn git_capture(&self, artifact: &GitArtifact) -> Result<bunker_git::Capture> {
        artifact.validate()?;
        let metadata = self.git_part(&artifact.metadata)?;
        let pack = self.git_part(&artifact.pack)?;
        bunker_git::Capture::from_parts(&metadata, pack.to_vec(), &bunker_git::Limits::default())
    }
    pub(super) fn save_git_journal(&self, id: &str, journal: &bunker_git::Journal) -> Result<()> {
        valid_id(id)?;
        let bytes = Zeroizing::new(serde_json::to_vec(journal)?);
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST,
            "Git journal exceeds limit"
        );
        atomic_write(
            &self.dir,
            &format!("transactions/{id}/git-journal"),
            &crypto::seal(&self.key, &bytes, id.as_bytes())?,
            false,
        )
    }
    fn load_git_journal(&self, id: &str) -> Result<Option<bunker_git::Journal>> {
        let path = format!("transactions/{id}/git-journal");
        if !self.dir.try_exists(&path)? {
            return Ok(None);
        }
        let encrypted = read_bounded(&self.dir, &path, MAX_MANIFEST + 40)?;
        Ok(Some(serde_json::from_slice(&crypto::open(
            &self.key,
            &encrypted,
            id.as_bytes(),
        )?)?))
    }
    fn recovery_state(
        &self,
        id: &str,
    ) -> Result<(RecoveryPlan, serde_json::Value, RestorePlan, Vec<usize>)> {
        let journal = self.restore_journal(id)?;
        ensure!(journal["id"] == id, "transaction identity mismatch");
        let plan: RestorePlan = serde_json::from_value(journal["plan"].clone())?;
        let destination = Path::new(&plan.destination);
        ensure!(
            destination.canonicalize()? == destination
                && !destination.starts_with(&self.root)
                && !self.root.starts_with(destination),
            "unsafe recovery destination"
        );
        let dir = Dir::open_ambient_dir(destination, ambient_authority())?;
        let mut indices = BTreeSet::new();
        for value in journal["applied"]
            .as_array()
            .context("invalid transaction progress")?
        {
            indices.insert(value.as_u64().context("invalid applied index")? as usize);
        }
        if let Some(index) = journal["in_flight"].as_u64() {
            indices.insert(index as usize);
        }
        let mut paths = vec![];
        let mut states = vec![];
        for &index in &indices {
            let change = plan
                .changes
                .get(index)
                .context("invalid transaction index")?;
            ensure!(change.action != "unchanged", "invalid recovery entry");
            reject_symlinks(&dir, &change.path)?;
            let current = destination_state(&dir, &change.path)?;
            let before = current.as_ref().map(|s| &s.0) == change.before.as_ref()
                && current.as_ref().map(|s| s.2) == change.before_executable;
            // A crash can occur between rename and chmod. The private temp is
            // nonexecutable; only that mode or the intended mode is known.
            let after = current.as_ref().is_some_and(|s| {
                s.0 == change.after && s.1 == change.after_size && (!s.2 || change.after_executable)
            });
            let recovering_before = journal["status"] == "recovering"
                && current
                    .as_ref()
                    .is_some_and(|s| Some(&s.0) == change.before.as_ref() && !s.2);
            ensure!(
                before || after || recovering_before,
                "recovery refused: workspace changed after restore"
            );
            if change.before.is_some() {
                let bytes = read_bounded(
                    &self.dir,
                    &format!("transactions/{id}/{index}.before"),
                    1024 * 1024 * 1024 + 40,
                )?;
                let plain = crypto::open(&self.key, &bytes, id.as_bytes())?;
                ensure!(
                    Some(blake3::hash(&plain).to_hex().to_string()) == change.before
                        && Some(plain.len() as u64) == change.before_size,
                    "invalid recovery preimage"
                );
            }
            paths.push(change.path.clone());
            states.push(current);
        }
        let git = self.load_git_journal(id)?;
        let mut git_state = BTreeMap::new();
        let mut git_metadata_bytes = 0u64;
        let mut fingerprint = |path: &str| -> Result<String> {
            let bytes = Zeroizing::new(read_bounded(&dir, path, MAX_MANIFEST)?);
            git_metadata_bytes = git_metadata_bytes
                .checked_add(bytes.len() as u64)
                .context("Git recovery metadata overflow")?;
            ensure!(
                git_metadata_bytes <= MAX_MANIFEST,
                "Git recovery metadata exceeds limit"
            );
            Ok(blake3::keyed_hash(&self.key, &bytes).to_hex().to_string())
        };
        if let Some(git) = &git {
            ensure!(
                git.target() == destination
                    && plan
                        .git
                        .as_ref()
                        .map(|g| g.confirmation_digest())
                        .transpose()?
                        .as_deref()
                        == Some(git.plan_fingerprint()),
                "Git journal does not match transaction"
            );
            // Bind recovery consent to current refs/index/reflog without exposing
            // names or contents in the public recovery preview.
            for path in [
                ".git/HEAD",
                ".git/config",
                ".git/index",
                ".git/packed-refs",
                ".git/logs/refs/stash",
            ] {
                reject_symlinks(&dir, path)?;
                if dir.try_exists(path)? {
                    git_state.insert(path.to_owned(), fingerprint(path)?);
                }
            }
            for entry in walkdir::WalkDir::new(destination.join(".git/refs"))
                .follow_links(false)
                .into_iter()
            {
                let entry = entry?;
                ensure!(!entry.file_type().is_symlink(), "unsafe Git recovery path");
                if !entry.file_type().is_file() {
                    continue;
                }
                ensure!(git_state.len() < 100000, "recovery ref limit");
                let path = entry
                    .path()
                    .strip_prefix(destination)?
                    .to_str()
                    .context("invalid ref path")?;
                git_state.insert(path.to_owned(), fingerprint(path)?);
            }
        }
        let confirmation = blake3::keyed_hash(
            &self.key,
            &serde_json::to_vec(&(&journal, &states, &git_state))?,
        )
        .to_hex()
        .to_string();
        Ok((
            RecoveryPlan {
                transaction: id.into(),
                destination: plan.destination.clone(),
                paths,
                restores_git: git.is_some(),
                confirmation,
            },
            journal,
            plan,
            indices.into_iter().collect(),
        ))
    }
    /// Local operator preview. Stop all writers before preview and recovery.
    pub fn plan_recovery(&self, id: &str) -> Result<RecoveryPlan> {
        let journal = self.restore_journal(id)?;
        let destination = journal["plan"]["destination"]
            .as_str()
            .context("missing destination")?;
        let _access = if self.load_git_journal(id)?.is_some() {
            Some(ExclusiveAccess::required(Path::new(destination))?)
        } else {
            None
        };
        Ok(self.recovery_state(id)?.0)
    }
    /// Guarded, restartable rollback of the combined Git/workspace transaction.
    /// Added objects and empty directories remain; later user edits are refused.
    pub fn recover_transaction(&self, id: &str, confirmation: &str) -> Result<RecoveryPlan> {
        let journal = self.restore_journal(id)?;
        let destination = journal["plan"]["destination"]
            .as_str()
            .context("missing destination")?;
        let _access = if self.load_git_journal(id)?.is_some() {
            Some(ExclusiveAccess::required(Path::new(destination))?)
        } else {
            None
        };
        let (preview, mut journal, plan, indices) = self.recovery_state(id)?;
        ensure!(
            preview.confirmation == confirmation,
            "recovery confirmation missing or stale"
        );
        let save = |journal: &serde_json::Value| -> Result<()> {
            atomic_write(
                &self.dir,
                &format!("transactions/{id}/journal"),
                &crypto::seal(&self.key, &serde_json::to_vec(journal)?, id.as_bytes())?,
                true,
            )
        };
        journal["status"] = serde_json::json!("recovering");
        save(&journal)?;
        // All file preimages and guards were checked before Git can mutate.
        if let Some(git) = self.load_git_journal(id)? {
            bunker_git::GitBackup::default().recover(&git)?;
        }
        let dir = Dir::open_ambient_dir(&plan.destination, ambient_authority())?;
        for index in indices.into_iter().rev() {
            let change = &plan.changes[index];
            reject_symlinks(&dir, &change.path)?;
            let current = destination_state(&dir, &change.path)?;
            let before = current.as_ref().map(|s| &s.0) == change.before.as_ref()
                && current.as_ref().map(|s| s.2) == change.before_executable;
            if before {
                continue;
            }
            ensure!(
                current.as_ref().is_some_and(|s| (s.0 == change.after
                    && (!s.2 || change.after_executable))
                    || (Some(&s.0) == change.before.as_ref()
                        && (!s.2 || change.before_executable == Some(true)))),
                "recovery refused: workspace changed"
            );
            if change.before.is_some() {
                let bytes = read_bounded(
                    &self.dir,
                    &format!("transactions/{id}/{index}.before"),
                    1024 * 1024 * 1024 + 40,
                )?;
                let plain = crypto::open(&self.key, &bytes, id.as_bytes())?;
                atomic_write(&dir, &change.path, &plain, true)?;
                #[cfg(unix)]
                {
                    use cap_std::fs::PermissionsExt;
                    dir.set_permissions(
                        &change.path,
                        cap_std::fs::Permissions::from_mode(
                            if change.before_executable == Some(true) {
                                0o700
                            } else {
                                0o600
                            },
                        ),
                    )?;
                    dir.open(&change.path)?.sync_all()?;
                }
            } else {
                dir.remove_file(&change.path)?;
                sync_parents(
                    &dir,
                    Path::new(&change.path).parent().unwrap_or(Path::new("")),
                )?;
            }
        }
        journal["status"] = serde_json::json!("rolled_back");
        save(&journal)?;
        self.audit("restore_rolled_back", serde_json::json!({"transaction":id}))?;
        Ok(preview)
    }
}
