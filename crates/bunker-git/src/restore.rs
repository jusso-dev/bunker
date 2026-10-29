use super::*;
use std::io::Write;

/// Serialize and bind this entire value into Bunker's independently authorized confirmation.
/// Apply recomputes it; callers cannot change the desired state by editing a plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub version: u32,
    pub target: PathBuf,
    pub capture_fingerprint: String,
    pub prior_state_fingerprint: String,
    pub prior_config_fingerprint: String,
    pub prior_index_fingerprint: Option<String>,
    pub desired_index_fingerprint: String,
    pub prior_refs: BTreeMap<String, Option<String>>,
    pub desired_refs: BTreeMap<String, String>,
    pub head_ref: String,
    pub index: Vec<IndexEntry>,
    pub stash_oldest_first: Vec<String>,
    pub prerequisite_count: usize,
    pub imported_object_count: usize,
    pub warnings: Vec<String>,
}
impl RestorePlan {
    pub fn confirmation_digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
    pub fn readable(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
/// Durable preimages. The caller MUST encrypt, atomically persist, and fsync this
/// value (and its parent directory) in the callback before it returns success.
/// Retain until apply/recovery completes. Object imports are additive and not undone.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    version: u32,
    target: PathBuf,
    plan_fingerprint: String,
    prior_refs: BTreeMap<String, Option<String>>,
    desired_refs: BTreeMap<String, String>,
    prior_config: ConfigState,
    prior_index: Option<Vec<u8>>,
    desired_index: Vec<u8>,
    prior_stash_log: Option<Vec<u8>>,
    desired_stash_log: Option<Vec<u8>>,
    transitional_stash_log: Option<Vec<u8>>,
}
impl Journal {
    pub fn target(&self) -> &Path {
        &self.target
    }
    pub fn plan_fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }
}
// Git has no switch to skip repository-local config. Mutating plumbing runs
// only after this generated config is installed under config.lock. The caller's
// encrypted journal protects the original bytes/mode across crashes.
const ISOLATED_CONFIG: &[u8] = b"[core]\nrepositoryformatversion = 0\nbare = true\n";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigState {
    bytes: Option<Vec<u8>>,
    mode: Option<u32>,
}
impl ConfigState {
    fn read(root: &Path, limit: usize) -> Result<Self> {
        let path = root.join(".git/config");
        let bytes = git::optional(&path, limit)?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            if bytes.is_some() {
                Some(fs::metadata(&path)?.permissions().mode() & 0o777)
            } else {
                None
            }
        };
        #[cfg(not(unix))]
        let mode = None;
        Ok(Self { bytes, mode })
    }
    fn fingerprint(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
    fn validate(&self, limit: usize) -> Result<()> {
        ensure!(
            self.bytes.as_ref().is_none_or(|b| b.len() <= limit),
            "config preimage exceeds cap"
        );
        ensure!(
            self.bytes.is_some() == self.mode.is_some()
                && self.mode.is_none_or(|mode| mode <= 0o777),
            "invalid config preimage mode"
        );
        Ok(())
    }
    fn install(&self, root: &Path) -> Result<()> {
        self.validate(usize::MAX)?;
        let path = root.join(".git/config");
        install_file(&path, self.bytes.as_deref())?;
        #[cfg(unix)]
        if let Some(mode) = self.mode {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            fs::File::open(&path)?.sync_all()?;
        }
        Ok(())
    }
    fn isolated() -> Self {
        Self {
            bytes: Some(ISOLATED_CONFIG.to_vec()),
            mode: Some(0o600),
        }
    }
    fn permits_recovery(&self, current: &Self) -> bool {
        current == self || current == &Self::isolated()
            // Crash after original bytes were renamed, before original mode.
            || (current.bytes == self.bytes && current.mode == Some(0o600))
    }
}
#[derive(Debug)]
pub struct ApplyFailure {
    pub message: String,
    pub journal: Option<Box<Journal>>,
    /// False means the caller must retain the journal and arrange explicit recovery.
    pub rollback_completed: bool,
    pub recovery_error: Option<String>,
}
impl std::fmt::Display for ApplyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (rollback_completed={})",
            self.message, self.rollback_completed
        )
    }
}
impl std::error::Error for ApplyFailure {}
struct Locks {
    paths: Vec<PathBuf>,
}
impl Locks {
    fn new(root: &Path) -> Result<Self> {
        git::regular_path(&root.join(".git"))?;
        ensure!(
            root.join(".git").is_dir(),
            "restore target is not an ordinary Git worktree"
        );
        let mut locks = Self { paths: vec![] };
        for name in ["bunker-git.lock", "index.lock", "config.lock"] {
            let path = root.join(".git").join(name);
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .context("restore lock already held")?;
            locks.paths.push(path);
            file.sync_all()?;
        }
        Ok(locks)
    }
}
impl Drop for Locks {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}
impl GitBackup {
    fn validate_capture(&self, view: &View, capture: &Capture) -> Result<()> {
        let m = &capture.metadata;
        ensure!(
            m.version == 1 && m.object_format == "sha1",
            "unsupported Git backup version/object format"
        );
        ensure!(
            serde_json::to_vec(m)?.len() <= self.limits.max_metadata_bytes,
            "metadata cap exceeded"
        );
        ensure!(
            m.packed_objects.len() + m.prerequisites.len() <= self.limits.max_objects,
            "object count cap exceeded"
        );
        valid_ref(&m.head_ref)?;
        ensure!(m.head_ref.starts_with("refs/heads/"), "invalid HEAD branch");
        validate_ref_namespace(
            m.heads
                .keys()
                .map(String::as_str)
                .chain([m.head_ref.as_str()]),
        )?;
        for (r, id) in &m.heads {
            valid_ref(r)?;
            ensure!(r.starts_with("refs/heads/"), "invalid head ref");
            valid_oid(id)?;
        }
        for id in m
            .packed_objects
            .iter()
            .chain(&m.prerequisites)
            .chain(&m.stash)
        {
            valid_oid(id)?;
        }
        ensure!(
            m.packed_objects.is_disjoint(&m.prerequisites),
            "pack and prerequisite sets overlap"
        );
        index::encode(&m.index)?;
        ensure!(
            m.index.len() <= self.limits.max_files,
            "index entry cap exceeded"
        );
        let objects = pack::decode(&capture.pack, &self.limits)?;
        ensure!(
            objects.keys().cloned().collect::<BTreeSet<_>>() == m.packed_objects,
            "pack object inventory mismatch"
        );
        // Check prerequisites against ONLY the target before importing any captured object.
        for id in &m.prerequisites {
            view.git(self)
                .run(&["cat-file", "-e", id], &[])
                .map_err(|_| {
                    anyhow::anyhow!(
                        "missing remote prerequisite {id}; supply an appropriate clone offline"
                    )
                })?;
        }
        for (id, object) in &objects {
            let got = view.git(self).text(
                &["hash-object", "-w", "-t", &object.kind, "--stdin"],
                &object.bytes,
            )?;
            ensure!(got.trim() == id, "imported object identity mismatch");
        }
        let roots: BTreeSet<_> = m
            .heads
            .values()
            .chain(&m.stash)
            .chain(m.index.iter().map(|e| &e.oid))
            .cloned()
            .collect();
        let required = self.graph(view, &roots)?;
        ensure!(
            required == m.packed_objects.union(&m.prerequisites).cloned().collect(),
            "backup object closure mismatch"
        );
        for id in m.heads.values().chain(&m.stash) {
            ensure!(
                view.git(self).text(&["cat-file", "-t", id], &[])?.trim() == "commit",
                "head/stash is not a commit"
            );
        }
        for id in &m.stash {
            let commit = self.object(view, id)?;
            let headers = commit
                .bytes
                .split(|b| *b == b'\n')
                .take_while(|l| !l.is_empty());
            let count = headers.filter(|l| l.starts_with(b"parent ")).count();
            ensure!(
                (2..=3).contains(&count),
                "stash entry lacks expected parent structure"
            );
        }
        // Git validates tree ordering, object structure and graph links in the isolated view.
        if !roots.is_empty() {
            let args = vec![
                "fsck",
                "--strict",
                "--no-reflogs",
                "--no-dangling",
                "--no-progress",
            ];
            view.git(self).run(&args, &[])?;
        }
        let policy = CapturePolicy::default();
        let mut checked = BTreeSet::new();
        for entry in &m.index {
            ensure!(
                view.git(self)
                    .text(&["cat-file", "-t", &entry.oid], &[])?
                    .trim()
                    == "blob",
                "index entry is not a blob"
            );
            self.check_path(view, entry, &policy)?;
        }
        for (id, object) in &objects {
            if object.kind == "commit" {
                for entry in self.tree_entries(view, id)? {
                    if checked.insert((entry.path.clone(), entry.oid.clone(), entry.mode.clone())) {
                        self.check_path(view, &entry, &policy)?;
                    }
                }
            }
        }
        Ok(())
    }
    fn clean(
        &self,
        root: &Path,
        view: &View,
        refs: &BTreeMap<String, String>,
        head: &str,
    ) -> Result<()> {
        let entries = view
            .state
            .get("index")
            .map(|b| index::decode(b, self.limits.max_files))
            .transpose()?
            .unwrap_or_default();
        let head_entries = refs
            .get(head)
            .map(|id| self.tree_entries(view, id))
            .transpose()?
            .unwrap_or_default();
        ensure!(
            entries == head_entries,
            "target index is not clean relative to HEAD"
        );
        for entry in &entries {
            safe_path(&entry.path)?;
            ensure!(
                entry.mode == "100644" || entry.mode == "100755",
                "unsupported target index mode"
            );
            let path = root.join(&entry.path);
            let bytes = git::read(&path, self.limits.max_object_bytes)?;
            ensure!(
                pack::oid("blob", &bytes) == entry.oid,
                "target worktree is dirty (or requires checkout filters)"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    (fs::metadata(path)?.permissions().mode() & 0o111 != 0)
                        == (entry.mode == "100755"),
                    "target worktree executable mode differs"
                );
            }
        }
        // Untracked files are not modified; plan states this explicitly.
        Ok(())
    }
    pub fn plan_restore(&self, root: &Path, capture: &Capture) -> Result<RestorePlan> {
        let config = ConfigState::read(root, self.limits.max_metadata_bytes)?;
        let view = self.view(root)?;
        let refs = self.refs(&view)?;
        let head = self.head(&view)?;
        ensure!(
            head == capture.metadata.head_ref,
            "target HEAD branch differs; select the captured branch explicitly before planning"
        );
        self.clean(root, &view, &refs, &head)?;
        self.validate_capture(&view, capture)?;
        let mut desired_refs = capture.metadata.heads.clone();
        if let Some(tip) = capture.metadata.stash.last() {
            desired_refs.insert("refs/stash".into(), tip.clone());
        }
        // Validate the final namespace while retaining all extra target refs.
        validate_ref_namespace(
            refs.keys()
                .chain(desired_refs.keys())
                .map(String::as_str)
                .chain([head.as_str()]),
        )?;
        let prior_refs = desired_refs
            .keys()
            .map(|r| (r.clone(), refs.get(r).cloned()))
            .collect();
        ensure!(
            self.state(root)?.digest()? == view.state.digest()?
                && ConfigState::read(root, self.limits.max_metadata_bytes)? == config,
            "target changed during restore planning"
        );
        Ok(RestorePlan { version: 1, target: root.into(), capture_fingerprint: capture.fingerprint()?,
            prior_state_fingerprint: view.state.digest()?, prior_config_fingerprint: config.fingerprint()?, prior_index_fingerprint: view.state.get("index").map(digest),
            desired_index_fingerprint: digest(&index::encode(&capture.metadata.index)?), prior_refs, desired_refs,
            head_ref: head, index: capture.metadata.index.clone(), stash_oldest_first: capture.metadata.stash.clone(),
            prerequisite_count: capture.metadata.prerequisites.len(), imported_object_count: capture.metadata.packed_objects.len(),
            warnings: vec!["Worktree files and HEAD are unchanged; coordinate workspace restoration separately. Restored refs/index may make the worktree dirty.".into(),
                "Extra target refs and untracked files are retained. Empty captured stash leaves any target stash unchanged.".into(),
                "Stash commit order is preserved; reflog messages, identities and timestamps are replaced with neutral metadata.".into(),
                "Exclusive repository access is required through apply/recovery; the journal spans refs, index and stash log.".into()] })
    }
    /// No authority is inferred from this API. Bunker must authorize the exact plan
    /// independently and encrypt/durably persist the supplied journal before success.
    pub fn apply_restore<F>(
        &self,
        plan: &RestorePlan,
        capture: &Capture,
        persist_journal: F,
    ) -> std::result::Result<Journal, ApplyFailure>
    where
        F: FnOnce(&Journal) -> Result<()>,
    {
        self.apply_restore_with_authorization(plan, capture, persist_journal, || Ok(()))
    }
    /// Revalidate authority at each forward mutation boundary. Rollback remains
    /// allowed after expiry so an interrupted apply can restore its preimages.
    pub fn apply_restore_with_authorization<F, A>(
        &self,
        plan: &RestorePlan,
        capture: &Capture,
        persist_journal: F,
        mut authorize: A,
    ) -> std::result::Result<Journal, ApplyFailure>
    where
        F: FnOnce(&Journal) -> Result<()>,
        A: FnMut() -> Result<()>,
    {
        let mut journal = None;
        let mut locks = None;
        let mut mutation_started = false;
        let result = (|| -> Result<Journal> {
            ensure!(
                self.plan_restore(&plan.target, capture)? == *plan,
                "stale or modified restore plan"
            );
            locks = Some(Locks::new(&plan.target)?);
            let state = self.state(&plan.target)?;
            let prior_config = ConfigState::read(&plan.target, self.limits.max_metadata_bytes)?;
            ensure!(
                state.digest()? == plan.prior_state_fingerprint
                    && prior_config.fingerprint()? == plan.prior_config_fingerprint,
                "stale restore plan after locking"
            );
            // Validate every path Git may write, including existing branch reflogs/config.
            self.check_write_paths(&plan.target)?;
            let desired_stash_log = if capture.metadata.stash.is_empty() {
                None
            } else {
                Some(stash_log(&capture.metadata.stash))
            };
            let prior_stash_log = state.get("logs/refs/stash").map(<[u8]>::to_vec);
            let transitional_stash_log = desired_stash_log.as_ref().map(|_| {
                let mut bytes = prior_stash_log.clone().unwrap_or_default();
                let old = plan
                    .prior_refs
                    .get("refs/stash")
                    .and_then(Option::as_deref)
                    .unwrap_or(ZERO);
                let new = plan
                    .desired_refs
                    .get("refs/stash")
                    .map(String::as_str)
                    .unwrap_or(ZERO);
                // update-ref leaves the reflog unchanged for a no-op update.
                if old != new {
                    bytes.extend(
                        format!(
                            "{old} {new} Bunker <restore@bunker.invalid> 1 +0000\tbunker restore\n"
                        )
                        .as_bytes(),
                    );
                }
                bytes
            });
            let j = Journal {
                version: 2,
                target: plan.target.clone(),
                plan_fingerprint: plan.confirmation_digest()?,
                prior_refs: plan.prior_refs.clone(),
                desired_refs: plan.desired_refs.clone(),
                prior_config,
                prior_index: state.get("index").map(<[u8]>::to_vec),
                desired_index: index::encode(&capture.metadata.index)?,
                prior_stash_log,
                desired_stash_log,
                transitional_stash_log,
            };
            ensure!(
                serde_json::to_vec(&j)?.len() <= self.limits.max_metadata_bytes.saturating_mul(4),
                "journal cap exceeded before restore"
            );
            persist_journal(&j).context("journal persistence failed; restore not started")?;
            journal = Some(j.clone());
            // Pack was verified in an isolated repository by plan_restore. Import using
            // hash-object: no pack delta bases, checkout filters, hooks or external helpers.
            let objects = pack::decode(&capture.pack, &self.limits)?;
            authorize()?;
            mutation_started = true;
            ConfigState::isolated().install(&plan.target)?;
            let dir = plan.target.join(".git");
            let git = git::Git {
                exe: &self.git_executable,
                dir: &dir,
                limits: &self.limits,
                alternate: None,
            };
            for (id, object) in objects {
                authorize()?;
                ensure!(
                    git.text(
                        &["hash-object", "-w", "-t", &object.kind, "--stdin"],
                        &object.bytes
                    )?
                    .trim()
                        == id,
                    "object import mismatch"
                );
            }
            authorize()?;
            self.ref_transaction(
                &j.target,
                &j.prior_refs,
                &j.desired_refs
                    .iter()
                    .map(|(k, v)| (k.clone(), Some(v.clone())))
                    .collect(),
            )?;
            authorize()?;
            install_index(&j.target, Some(&j.desired_index))?;
            if let Some(bytes) = &j.desired_stash_log {
                authorize()?;
                install_file(&j.target.join(".git/logs/refs/stash"), Some(bytes))?;
            }
            authorize()?;
            j.prior_config.install(&j.target)?;
            Ok(j)
        })();
        match result {
            Ok(j) => Ok(j),
            Err(error) => {
                let recovery_error = if mutation_started {
                    journal
                        .as_ref()
                        .and_then(|j| self.rollback_locked(j).err())
                        .map(|e| format!("{e:#}"))
                } else {
                    None
                };
                let rollback_completed = recovery_error.is_none();
                Err(ApplyFailure {
                    message: format!("Git restore failed: {error:#}"),
                    journal: journal.map(Box::new),
                    rollback_completed,
                    recovery_error,
                })
            }
        }
    }
    fn check_write_paths(&self, root: &Path) -> Result<()> {
        let dir = root.join(".git");
        for name in ["config", "logs", "refs", "objects"] {
            let path = dir.join(name);
            if fs::symlink_metadata(&path).is_ok() {
                git::regular_path(&path)?;
                if path.is_dir() {
                    walk(&path, &dir, &mut Vec::new(), self.limits.max_files)?;
                } else {
                    ensure!(path.is_file(), "nonregular Git write path");
                }
            }
        }
        Ok(())
    }
    fn ref_transaction(
        &self,
        root: &Path,
        old: &BTreeMap<String, Option<String>>,
        new: &BTreeMap<String, Option<String>>,
    ) -> Result<()> {
        ensure!(old.keys().eq(new.keys()), "ref transaction key mismatch");
        let mut input = String::from("start\n");
        for (name, desired) in new {
            valid_ref(name)?;
            let prior = old.get(name).and_then(Option::as_deref).unwrap_or(ZERO);
            valid_oid(prior)?;
            match desired {
                Some(id) => {
                    valid_oid(id)?;
                    input.push_str(&format!("update {name} {id} {prior}\n"));
                }
                None if prior != ZERO => input.push_str(&format!("delete {name} {prior}\n")),
                None => input.push_str(&format!("verify {name} {ZERO}\n")),
            }
        }
        input.push_str("prepare\ncommit\n");
        let dir = root.join(".git");
        git::Git {
            exe: &self.git_executable,
            dir: &dir,
            limits: &self.limits,
            alternate: None,
        }
        .run(
            &[
                "update-ref",
                "--no-deref",
                "-m",
                "bunker restore",
                "--stdin",
            ],
            input.as_bytes(),
        )?;
        Ok(())
    }
    /// Roll back completed or interrupted apply, guarded against subsequent edits.
    /// If a process crashed, the operator must first establish exclusive access and
    /// remove abandoned bunker-git.lock/index.lock/config.lock files. Never remove live locks.
    pub fn recover(&self, journal: &Journal) -> Result<()> {
        let _locks = Locks::new(&journal.target)?;
        self.rollback_locked(journal)
    }
    fn rollback_locked(&self, j: &Journal) -> Result<()> {
        ensure!(
            j.version == 2,
            "unsupported journal version (config preimage required)"
        );
        ensure!(
            serde_json::to_vec(j)?.len() <= self.limits.max_metadata_bytes.saturating_mul(4),
            "journal cap exceeded"
        );
        j.prior_config.validate(self.limits.max_metadata_bytes)?;
        ensure!(
            j.prior_config.permits_recovery(&ConfigState::read(
                &j.target,
                self.limits.max_metadata_bytes
            )?),
            "recovery refused: config changed after restore"
        );
        // Config cleanup must survive a failed ref guard/transaction, malformed
        // index, or unsafe ref write path. Recheck its independent guard even on
        // failure so a later config edit is never replaced with the preimage.
        let rollback = self.rollback_state_locked(j);
        let cleanup = (|| -> Result<()> {
            let current = ConfigState::read(&j.target, self.limits.max_metadata_bytes)?;
            ensure!(
                j.prior_config.permits_recovery(&current),
                "recovery refused: config changed after restore"
            );
            if current != j.prior_config {
                j.prior_config.install(&j.target)?;
            }
            Ok(())
        })();
        match (rollback, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
                "{error:#}; config cleanup failed: {cleanup:#}"
            )),
        }
    }
    fn rollback_state_locked(&self, j: &Journal) -> Result<()> {
        self.check_write_paths(&j.target)?;
        index::decode(&j.desired_index, self.limits.max_files)?;
        if let Some(bytes) = &j.prior_index {
            index::decode(bytes, self.limits.max_files)?;
        }
        // Build a view directly because our own index.lock is held.
        let view = self.view_locked(&j.target)?;
        let refs = self.refs(&view)?;
        let mut current = BTreeMap::new();
        ensure!(
            j.prior_refs.keys().eq(j.desired_refs.keys()),
            "journal ref keys mismatch"
        );
        validate_ref_namespace(refs.keys().chain(j.desired_refs.keys()).map(String::as_str))?;
        for (name, desired) in &j.desired_refs {
            valid_ref(name)?;
            valid_oid(desired)?;
            let now = refs.get(name).cloned();
            ensure!(
                now == j.prior_refs[name] || now.as_ref() == Some(desired),
                "recovery refused: refs changed after restore"
            );
            current.insert(name.clone(), now);
        }
        let now_index = view.state.get("index");
        ensure!(
            now_index == j.prior_index.as_deref() || now_index == Some(j.desired_index.as_slice()),
            "recovery refused: index changed after restore"
        );
        if j.desired_stash_log.is_some() {
            let now = view.state.get("logs/refs/stash");
            let mut allowed = vec![
                j.prior_stash_log.clone(),
                j.desired_stash_log.clone(),
                j.transitional_stash_log.clone(),
            ];
            // A previous recovery may itself have crashed after restoring refs and
            // appending Git's rollback reflog line, before replacing the stash log.
            if let Some(Some(prior)) = j.prior_refs.get("refs/stash") {
                let desired = j
                    .desired_refs
                    .get("refs/stash")
                    .context("journal missing stash ref")?;
                if prior != desired {
                    let suffix = format!("{desired} {prior} Bunker <restore@bunker.invalid> 1 +0000\tbunker restore\n");
                    for mut bytes in allowed.clone().into_iter().flatten() {
                        bytes.extend(suffix.as_bytes());
                        allowed.push(Some(bytes));
                    }
                }
            }
            ensure!(
                allowed.iter().any(|bytes| bytes.as_deref() == now),
                "recovery refused: stash log changed after restore"
            );
        }
        // No target Git command occurs until all recovery guards have passed and
        // its arbitrary configuration (including includes) has been isolated.
        ConfigState::isolated().install(&j.target)?;
        self.ref_transaction(&j.target, &current, &j.prior_refs)?;
        install_index(&j.target, j.prior_index.as_deref())?;
        if j.desired_stash_log.is_some() {
            install_file(
                &j.target.join(".git/logs/refs/stash"),
                j.prior_stash_log.as_deref(),
            )?;
        }
        Ok(())
    }
}
const ZERO: &str = "0000000000000000000000000000000000000000";
fn stash_log(stack: &[String]) -> Vec<u8> {
    let mut out = String::new();
    let mut prior = ZERO;
    for id in stack {
        out.push_str(&format!(
            "{prior} {id} Bunker <restore@bunker.invalid> 1 +0000\tbunker preserved stash\n"
        ));
        prior = id;
    }
    out.into_bytes()
}
fn install_index(root: &Path, bytes: Option<&[u8]>) -> Result<()> {
    // Keep index.lock present for the whole transaction; use a separate atomic file.
    install_file(&root.join(".git/index"), bytes)
}
fn install_file(path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    let parent = path.parent().context("missing metadata parent")?;
    fs::create_dir_all(parent)?;
    git::regular_path(parent)?;
    if let Some(bytes) = bytes {
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| e.error)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
