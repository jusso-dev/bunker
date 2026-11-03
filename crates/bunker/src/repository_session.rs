//! Session rollback: restore files changed during one agent session to their
//! pre-session state. The baseline is the explicit `session-start` capture bound to
//! the same session ID and workspace, never an inferred repository-wide predecessor.
use super::*;

pub const SESSION_START: &str = "session-start";
pub const SESSION_END: &str = "session-end";
pub const SESSION_ROLLBACK: &str = "session-rollback";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRollback {
    pub session: String,
    pub baseline_snapshot: String,
    pub session_end_snapshot: String,
    /// Derived restore point: the pre-session version of every changed file.
    pub rollback_snapshot: String,
    pub restored_paths: Vec<String>,
    /// Restore never deletes; files created during the session need manual review.
    pub created_during_session: Vec<String>,
}

impl Repository {
    /// Builds (or reuses) a deterministic encrypted rollback manifest for `workspace`,
    /// the restore destination. Start and end captures must both be of that workspace,
    /// in that order. Plan and restore it like any snapshot; the reviewed confirmation
    /// binds its exact ID, and planning refuses any other destination.
    pub fn session_rollback(&self, session: &str, workspace: &Path) -> Result<SessionRollback> {
        ensure!(
            !session.is_empty() && session.len() <= 256,
            "invalid session identifier"
        );
        let workspace = self.workspace_identity(
            &workspace
                .canonicalize()
                .context("session rollback workspace must exist")?,
        )?;
        let manifests: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|m| {
                m.setup.is_none()
                    && m.session.as_deref() == Some(session)
                    && (m.trigger == SESSION_START || m.trigger == SESSION_END)
            })
            .collect();
        ensure!(
            manifests
                .iter()
                .all(|m| m.workspace.is_some() && m.created_at_nanos.is_some()),
            "session has captures without a workspace binding (taken by an older Bunker); session rollback refused, restore a specific snapshot ID instead"
        );
        let pick = |trigger: &str| -> Result<Manifest> {
            let mut found = manifests
                .iter()
                .filter(|m| m.trigger == trigger && m.workspace.as_deref() == Some(&workspace));
            let manifest = found.next().with_context(|| {
                format!("session has no {trigger} snapshot of this workspace; rollback needs both a {SESSION_START} capture before the session and a {SESSION_END} capture after it, of the same workspace and session ID (standalone session-run takes both; otherwise run `bunker snapshot --workspace PATH --agent NAME --session ID --trigger {SESSION_START}` before the session). Host-mode session-run does not record a {SESSION_START} capture")
            })?;
            ensure!(
                found.next().is_none(),
                "session has several {trigger} captures of this workspace; rollback is ambiguous"
            );
            Ok(manifest.clone())
        };
        let start = pick(SESSION_START)?;
        let end = pick(SESSION_END)?;
        ensure!(
            start.workspace.is_some() && start.workspace == end.workspace,
            "session start and end captures are of different workspaces"
        );
        ensure!(
            start.created_at <= end.created_at && start.created_at_nanos < end.created_at_nanos,
            "session-start capture is not before the session-end capture; rollback refused"
        );
        ensure!(
            start.agent == end.agent,
            "session agent binding changed between captures"
        );
        let after: BTreeMap<_, _> = end.files.iter().map(|f| (f.path.as_str(), f)).collect();
        let files: Vec<FileEntry> = start
            .files
            .iter()
            .filter(|f| {
                after
                    .get(f.path.as_str())
                    .is_none_or(|e| e.hash != f.hash || e.executable != f.executable)
            })
            .cloned()
            .collect();
        let before: HashSet<_> = start.files.iter().map(|f| f.path.as_str()).collect();
        let created_during_session = end
            .files
            .iter()
            .filter(|f| !before.contains(f.path.as_str()))
            .map(|f| f.path.clone())
            .collect();
        ensure!(
            !files.is_empty(),
            "session changed or removed no previously captured files"
        );
        let id = blake3::keyed_hash(
            &self.key,
            &serde_json::to_vec(&("bunker-session-rollback-v1", &start.id, &end.id))?,
        )
        .to_hex()
        .to_string();
        let restored_paths = files.iter().map(|f| f.path.clone()).collect();
        let manifest = Manifest {
            version: FORMAT_VERSION,
            id: id.clone(),
            created_at: end.created_at,
            agent: end.agent.clone(),
            session: Some(session.into()),
            trigger: SESSION_ROLLBACK.into(),
            region: start.region.clone(),
            bytes: files.iter().map(|f| f.size).sum(),
            files,
            skipped: vec![],
            diagnostics: vec![],
            git: None,
            setup: None,
            workspace: start.workspace.clone(),
            created_at_nanos: end.created_at_nanos,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&manifest)?);
        if self.dir.try_exists(format!("snapshots/{id}"))? {
            ensure!(
                *serde_json::to_vec(&self.manifest(&id)?)? == *plaintext,
                "existing session rollback manifest does not match its captures"
            );
        } else {
            atomic_write(
                &self.dir,
                &format!("snapshots/{id}"),
                &crypto::seal(&self.key, &plaintext, id.as_bytes())?,
                false,
            )?;
            self.audit(
                "session_rollback_prepared",
                serde_json::json!({"rollback_snapshot":id,"baseline_snapshot":start.id,"session_end_snapshot":end.id}),
            )?;
        }
        Ok(SessionRollback {
            session: session.into(),
            baseline_snapshot: start.id,
            session_end_snapshot: end.id,
            rollback_snapshot: id,
            restored_paths,
            created_during_session,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temp: tempfile::TempDir,
        repo: Repository,
        a: PathBuf,
        b: PathBuf,
    }
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = Repository::init(&root.join("repo"), "session-binding-fixture").unwrap();
        let (a, b) = (root.join("a"), root.join("b"));
        for (dir, content) in [(&a, "workspace a"), (&b, "workspace b")] {
            fs::create_dir(dir).unwrap();
            fs::write(dir.join("shared.txt"), content).unwrap();
        }
        Fixture {
            _temp: temp,
            repo,
            a,
            b,
        }
    }
    impl Fixture {
        fn capture(&self, workspace: &Path, session: &str, trigger: &str) -> Manifest {
            self.repo
                .snapshot(
                    workspace,
                    &Policy::default(),
                    Some("codex".into()),
                    Some(session.into()),
                    trigger,
                )
                .unwrap()
        }
        /// Rewrites a manifest as an older Bunker stored it, without a workspace binding.
        fn strip_binding(&self, id: &str) {
            let mut manifest = self.repo.manifest(id).unwrap();
            manifest.workspace = None;
            manifest.created_at_nanos = None;
            let plaintext = serde_json::to_vec(&manifest).unwrap();
            atomic_write(
                &self.repo.dir,
                &format!("snapshots/{id}"),
                &crypto::seal(&self.repo.key, &plaintext, id.as_bytes()).unwrap(),
                true,
            )
            .unwrap();
        }
    }

    #[test]
    fn start_and_end_on_different_workspaces_never_roll_back() {
        let f = fixture();
        f.capture(&f.a, "crossed", SESSION_START);
        fs::write(f.b.join("shared.txt"), "agent edit in b").unwrap();
        f.capture(&f.b, "crossed", SESSION_END);
        // Rolling back B would otherwise overwrite it with A's files.
        let error = f.repo.session_rollback("crossed", &f.b).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no session-start snapshot of this workspace"),
            "{error}"
        );
        let error = f.repo.session_rollback("crossed", &f.a).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no session-end snapshot of this workspace"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(f.b.join("shared.txt")).unwrap(),
            "agent edit in b"
        );
    }

    #[test]
    fn rollback_plans_only_into_its_own_workspace() {
        let f = fixture();
        f.capture(&f.a, "bound", SESSION_START);
        fs::write(f.a.join("shared.txt"), "agent edit").unwrap();
        f.capture(&f.a, "bound", SESSION_END);
        let rollback = f.repo.session_rollback("bound", &f.a).unwrap();
        assert_eq!(rollback.restored_paths, ["shared.txt"]);
        let error = f
            .repo
            .plan(&rollback.rollback_snapshot, &f.b, None)
            .unwrap_err();
        assert!(error.to_string().contains("another workspace"), "{error}");
        let plan = f
            .repo
            .plan(&rollback.rollback_snapshot, &f.a, None)
            .unwrap();
        assert_eq!(plan.changes[0].action, "overwrite");
    }

    #[test]
    fn session_end_before_start_is_refused() {
        let f = fixture();
        f.capture(&f.a, "reversed", SESSION_END);
        fs::write(f.a.join("shared.txt"), "later").unwrap();
        f.capture(&f.a, "reversed", SESSION_START);
        let error = f.repo.session_rollback("reversed", &f.a).unwrap_err();
        assert!(error.to_string().contains("not before"), "{error}");
    }

    #[test]
    fn legacy_captures_without_workspace_binding_are_refused() {
        let f = fixture();
        let start = f.capture(&f.a, "legacy", SESSION_START);
        fs::write(f.a.join("shared.txt"), "agent edit").unwrap();
        let end = f.capture(&f.a, "legacy", SESSION_END);
        f.strip_binding(&start.id);
        f.strip_binding(&end.id);
        assert!(f.repo.manifest(&start.id).unwrap().workspace.is_none());
        let error = f.repo.session_rollback("legacy", &f.a).unwrap_err();
        assert!(
            error.to_string().contains("without a workspace binding"),
            "{error}"
        );
    }
}
