//! Existing global setup capture; no provisioning, agent execution, or origin-directed restore.
use super::*;
use bunker_discovery::{
    discover, prepare_files, AgentId, DiscoveryContext, FileRequest, SafetyPolicy,
};
use std::collections::BTreeSet;

pub type SetupSnapshot = Vec<Manifest>;

/// Stored only inside the authenticated, encrypted manifest and replicated with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupScope {
    pub version: u32,
    pub source_root: PathBuf,
    pub agents: Vec<AgentId>,
    pub capture_id: String,
    pub scope_index: u32,
    pub scope_count: u32,
    /// Keyed session identity, never a command, credential, or source path.
    pub session_event: Option<String>,
}
impl SetupScope {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported setup scope version");
        // Origins are inert metadata: accept absolute Windows origins after DR
        // onto Unix as well. Never resolve or write this path during restore.
        let origin = self.source_root.to_str().context("invalid setup origin")?;
        let portable = origin.replace('\\', "/");
        let windows_absolute = portable.as_bytes().get(1) == Some(&b':')
            && portable
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && portable.as_bytes().get(2) == Some(&b'/');
        ensure!(
            portable.starts_with('/') || windows_absolute,
            "setup origin must be absolute"
        );
        ensure!(
            !portable.split('/').any(|part| part == "." || part == ".."),
            "setup origin must be normalized"
        );
        ensure!(
            self.source_root
                .to_str()
                .is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control)),
            "invalid setup origin"
        );
        ensure!(
            !self
                .source_root
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "setup origin must be normalized"
        );
        ensure!(
            !self.agents.is_empty()
                && self.agents.len() <= 5
                && self.agents.iter().copied().collect::<BTreeSet<_>>().len() == self.agents.len(),
            "invalid setup agents"
        );
        ensure!(
            self.scope_count > 0 && self.scope_count <= 64 && self.scope_index < self.scope_count,
            "invalid setup scope count"
        );
        valid_id(&self.capture_id)?;
        if let Some(event) = &self.session_event {
            valid_id(event)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Candidates {
    agents: BTreeSet<AgentId>,
    requests: BTreeMap<PathBuf, FileRequest>,
    diagnostics: BTreeMap<String, FileDiagnostic>,
}

impl Repository {
    /// Capture global roots supplied by the operator. Workspace roots in `context`
    /// are deliberately ignored: ordinary workspace capture remains `snapshot`.
    /// Every eligible byte comes from `prepare_files`, never a second path read.
    /// All roots are prepared and aggregate caps checked before any publication.
    pub fn snapshot_setup(
        &self,
        context: &DiscoveryContext,
        policy: &Policy,
        session: Option<String>,
        trigger: &str,
    ) -> Result<SetupSnapshot> {
        self.capture_setup(context, policy, session, trigger, None, None)
    }

    /// A successful complete capture is deduplicated across processes/restarts.
    /// Incomplete groups (e.g. crash during publication) are retried as a new group.
    /// No arbitrary agent hook or command is executed here.
    pub fn snapshot_setup_for_session(
        &self,
        context: &DiscoveryContext,
        policy: &Policy,
        event: &crate::session_hooks::SessionEnd,
    ) -> Result<SetupSnapshot> {
        event.validate()?;
        let identity = serde_json::to_vec(event)?;
        self.capture_setup_once(
            context,
            policy,
            Some(event.session_id.clone()),
            "session_end",
            &identity,
            None,
        )
    }

    /// Stable scheduled trigger identity comes from the already-persisted workspace
    /// snapshot, not the current clock. Retry never creates a second complete group.
    pub fn snapshot_setup_for_schedule(
        &self,
        context: &DiscoveryContext,
        policy: &Policy,
        workspace_snapshot: &str,
    ) -> Result<SetupSnapshot> {
        self.snapshot_setup_for_schedule_filtered(context, policy, workspace_snapshot, None)
    }

    pub fn snapshot_setup_for_schedule_filtered(
        &self,
        context: &DiscoveryContext,
        policy: &Policy,
        workspace_snapshot: &str,
        agent: Option<AgentId>,
    ) -> Result<SetupSnapshot> {
        valid_id(workspace_snapshot)?;
        self.capture_setup_once(
            context,
            policy,
            None,
            "schedule_setup",
            workspace_snapshot.as_bytes(),
            agent,
        )
    }

    fn capture_setup_once(
        &self,
        context: &DiscoveryContext,
        policy: &Policy,
        session: Option<String>,
        trigger: &str,
        identity: &[u8],
        agent: Option<AgentId>,
    ) -> Result<SetupSnapshot> {
        policy.validate()?;
        let mut global_context = context.clone();
        global_context.workspace_roots.clear();
        let event_bytes = Zeroizing::new(serde_json::to_vec(&(
            trigger,
            &global_context,
            identity,
            agent,
        ))?);
        let event_key = blake3::keyed_hash(&self.key, &event_bytes)
            .to_hex()
            .to_string();
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = self
            .dir
            .open_with("setup-session.lock", &options)?
            .into_std();
        lock.lock_exclusive()?;
        let mut groups: BTreeMap<String, Vec<Manifest>> = BTreeMap::new();
        for manifest in self.list()? {
            if let Some(scope) = &manifest.setup {
                scope.validate()?;
                if scope.session_event.as_deref() == Some(&event_key) {
                    groups
                        .entry(scope.capture_id.clone())
                        .or_default()
                        .push(manifest);
                }
            }
        }
        for (_, mut group) in groups.into_iter().rev() {
            group.sort_by_key(|m| m.setup.as_ref().unwrap().scope_index);
            let count = group[0].setup.as_ref().unwrap().scope_count;
            if group.len() == count as usize
                && group.iter().enumerate().all(|(index, m)| {
                    m.setup
                        .as_ref()
                        .is_some_and(|s| s.scope_count == count && s.scope_index == index as u32)
                })
            {
                for manifest in &group {
                    self.verify(&manifest.id)?;
                }
                return Ok(group);
            }
        }
        self.capture_setup(context, policy, session, trigger, Some(event_key), agent)
    }

    fn capture_setup(
        &self,
        context: &DiscoveryContext,
        policy: &Policy,
        session: Option<String>,
        trigger: &str,
        session_event: Option<String>,
        agent: Option<AgentId>,
    ) -> Result<SetupSnapshot> {
        policy.validate()?;
        ensure!(
            session
                .as_ref()
                .is_none_or(|s| s.len() <= 256 && !s.chars().any(char::is_control)),
            "invalid setup session metadata"
        );
        ensure!(
            !trigger.is_empty() && trigger.len() <= 128 && !trigger.chars().any(char::is_control),
            "invalid setup trigger"
        );
        let mut context = context.clone();
        context.workspace_roots.clear();
        let safety = SafetyPolicy {
            max_file_bytes: policy.max_file_bytes,
            max_repo_bytes: policy.size_cap_bytes,
            extra_excludes: policy.exclusions.clone(),
            default_includes: policy.default_includes.clone(),
        };
        let mut roots: BTreeMap<PathBuf, Candidates> = BTreeMap::new();
        for result in discover(&context, &safety)? {
            if agent.is_some_and(|agent| result.agent != agent) {
                continue;
            }
            for item in result.items {
                let request = item.request();
                let inside_repository = item.path().starts_with(&self.root);
                let candidate = roots.entry(item.root).or_default();
                candidate.agents.insert(result.agent);
                if inside_repository {
                    let path = request.relative_path.to_string_lossy().into_owned();
                    candidate.diagnostics.insert(
                        path.clone(),
                        FileDiagnostic {
                            path,
                            reason: "setup_repository_excluded".into(),
                            attempts: 0,
                        },
                    );
                    continue;
                }
                candidate
                    .requests
                    .entry(request.relative_path.clone())
                    .or_insert(request);
            }
            for excluded in result.excluded {
                let candidate = roots.entry(excluded.root).or_default();
                candidate.agents.insert(result.agent);
                let path = excluded.relative_path.to_string_lossy().into_owned();
                candidate
                    .diagnostics
                    .entry(path.clone())
                    .or_insert(FileDiagnostic {
                        path,
                        reason: format!("setup_{:?}", excluded.reason),
                        attempts: 0,
                    });
            }
        }
        ensure!(roots.len() <= 64, "too many setup roots");
        let scope_count = roots.len() as u32;
        let capture_id = hex::encode(crypto::random::<32>());
        let mut pending = vec![];
        let mut source_total = 0u64;
        let mut output_total = 0u64;
        for (scope_index, (root, mut candidate)) in roots.into_iter().enumerate() {
            let scope = SetupScope {
                version: 1,
                source_root: root.clone(),
                agents: candidate.agents.into_iter().collect(),
                capture_id: capture_id.clone(),
                scope_index: scope_index as u32,
                scope_count,
                session_event: session_event.clone(),
            };
            scope.validate()?;
            let prepared = prepare_files(
                &root,
                &candidate.requests.into_values().collect::<Vec<_>>(),
                &safety,
            )?;
            source_total = source_total
                .checked_add(prepared.source_bytes)
                .context("setup size overflow")?;
            output_total = output_total
                .checked_add(prepared.sanitized_bytes)
                .context("setup size overflow")?;
            ensure!(
                source_total <= policy.size_cap_bytes && output_total <= policy.size_cap_bytes,
                "global setup exceeds size_cap_bytes; no setup manifests published"
            );
            for (path, reason) in prepared.excluded {
                let path = path.to_string_lossy().into_owned();
                candidate.diagnostics.insert(
                    path.clone(),
                    FileDiagnostic {
                        path,
                        reason: format!("setup_{reason:?}"),
                        attempts: 1,
                    },
                );
            }
            ensure!(
                prepared.files.len() <= 10000,
                "setup scope exceeds file limit"
            );
            pending.push((
                scope,
                prepared.files,
                candidate.diagnostics.into_values().collect::<Vec<_>>(),
            ));
        }
        let mut manifests = vec![];
        for (scope, files, diagnostics) in pending {
            let mut manifest = Manifest {
                version: FORMAT_VERSION,
                id: hex::encode(crypto::random::<32>()),
                created_at: now(),
                agent: Some(
                    if scope.agents.len() == 1 {
                        scope.agents[0].as_str()
                    } else {
                        "global_setup"
                    }
                    .into(),
                ),
                session: session.clone(),
                trigger: trigger.into(),
                region: policy.region.clone(),
                files: vec![],
                skipped: diagnostics.iter().map(|d| d.path.clone()).collect(),
                diagnostics,
                bytes: 0,
                git: None,
                setup: Some(scope),
            };
            for file in files {
                let bytes = Zeroizing::new(file.bytes);
                let path = file.relative_path.to_string_lossy().into_owned();
                if file.relative_path.to_str().is_none() || safe_path(&path).is_err() {
                    manifest.skipped.push(path.clone());
                    manifest.diagnostics.push(FileDiagnostic {
                        path,
                        reason: "setup_nonportable_path".into(),
                        attempts: 1,
                    });
                    continue;
                }
                let mut chunks = vec![];
                for chunk in
                    fastcdc::v2020::FastCDC::new(&bytes, 64 * 1024, 256 * 1024, 1024 * 1024)
                {
                    chunks.push(self.put_chunk(&bytes[chunk.offset..chunk.offset + chunk.length])?);
                }
                manifest.bytes += bytes.len() as u64;
                manifest.files.push(FileEntry {
                    path,
                    size: bytes.len() as u64,
                    hash: blake3::hash(&bytes).to_hex().to_string(),
                    chunks,
                    executable: file.executable,
                    secret_references: file.secret_references,
                    sanitized: file.sanitized,
                });
            }
            // Serialize every manifest before publishing any: metadata/cap errors do
            // not leave a subset looking like a successful complete capture.
            let plaintext = Zeroizing::new(serde_json::to_vec(&manifest)?);
            ensure!(
                plaintext.len() as u64 + 40 <= MAX_MANIFEST,
                "setup manifest exceeds limit"
            );
            manifests.push((manifest, plaintext));
        }
        #[cfg(unix)]
        self.dir.open_dir("chunks")?.into_std_file().sync_all()?;
        for (manifest, plaintext) in &manifests {
            atomic_write(
                &self.dir,
                &format!("snapshots/{}", manifest.id),
                &crypto::seal(&self.key, plaintext, manifest.id.as_bytes())?,
                false,
            )?;
        }
        Ok(manifests
            .into_iter()
            .map(|(manifest, _)| manifest)
            .collect())
    }

    /// Scope metadata is informational. Only the explicit destination controls writes.
    pub fn plan_setup(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
    ) -> Result<RestorePlan> {
        let manifest = self.manifest(id)?;
        manifest
            .setup
            .as_ref()
            .context("snapshot is not a global setup snapshot")?
            .validate()?;
        ensure!(
            manifest.git.is_none(),
            "setup snapshot cannot contain workspace Git state"
        );
        // Require an existing real directory, including every ancestor, before core
        // canonicalization; no silent destination symlink redirection.
        crate::session_hooks::open_existing_root(destination)?;
        self.plan(id, destination, selection)
    }

    pub fn restore_setup(
        &self,
        id: &str,
        destination: &Path,
        selection: Option<&str>,
        confirmation: &str,
        allow_rebind_overwrite: bool,
    ) -> Result<RestorePlan> {
        self.plan_setup(id, destination, selection)?;
        self.restore_with_options(
            id,
            destination,
            selection,
            confirmation,
            allow_rebind_overwrite,
        )
    }
}
