//! Session rollback: restore files changed during one agent session to their
//! pre-session state. The baseline is the explicit `session-start` capture bound to
//! the same session ID, never an inferred repository-wide predecessor.
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
    /// Builds (or reuses) a deterministic encrypted rollback manifest. Plan and
    /// restore it like any snapshot; the reviewed confirmation binds its exact ID.
    pub fn session_rollback(&self, session: &str) -> Result<SessionRollback> {
        ensure!(
            !session.is_empty() && session.len() <= 256,
            "invalid session identifier"
        );
        let manifests: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|m| m.setup.is_none() && m.session.as_deref() == Some(session))
            .collect();
        let pick = |trigger: &str| -> Result<Manifest> {
            let mut found = manifests.iter().filter(|m| m.trigger == trigger);
            let manifest = found.next().with_context(|| {
                format!("session has no {trigger} workspace snapshot; rollback needs a pre-session capture from session-run or session-start")
            })?;
            ensure!(
                found.next().is_none(),
                "session captured several workspaces; rollback is ambiguous"
            );
            Ok(manifest.clone())
        };
        let start = pick(SESSION_START)?;
        let end = pick(SESSION_END)?;
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
