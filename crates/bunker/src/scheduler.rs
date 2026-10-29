use crate::{
    policy::Policy,
    repository::{durable_write, now, KeySource, Manifest, Repository},
};
use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::io::Write;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScheduleState {
    pub workspace: Option<PathBuf>,
    pub last_success: u64,
    pub next_run: u64,
    pub last_snapshot: Option<String>,
    pub last_good_policy: Option<Policy>,
    pub pending_detection: Option<(Option<String>, String)>,
    pub pending_setup: Option<PendingSetup>,
    pub setup_failures: u32,
    pub setup_retry_after: u64,
    pub last_setup_error: Option<String>,
    pub setup_diagnostics: Vec<SetupDiagnostic>,
    pub pending_missed_backup: Option<u64>,
    pub failures: u32,
    pub last_error: Option<String>,
    pub retry_after: u64,
    pub failure_audited: bool,
    pub pending_schedule_recovery: Option<String>,
    pub next_probe: u64,
    pub probe_failures: u32,
    pub probe_retry_after: u64,
    pub last_probe_error: Option<String>,
}
/// One bounded pending setup job. New workspace captures coalesce old unfinished
/// work with an explicit diagnostic; setup outages do not block workspace cadence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupDiagnostic {
    pub workspace_snapshot: String,
    pub reason: String,
    pub at: u64,
}
/// Frozen policy allows stale jobs to be cancelled before a changed policy runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSetup {
    pub workspace_snapshot: String,
    pub policy: Policy,
}
impl PendingSetup {
    fn validate(&self) -> Result<()> {
        crate::repository::valid_id(&self.workspace_snapshot)?;
        self.policy.validate()?;
        anyhow::ensure!(
            self.policy.setup_home.is_some(),
            "pending setup has no configured root"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub kind: String,
    pub fingerprint: String,
    pub detected_at: u64,
    pub snapshot: Option<String>,
    pub count: usize,
}
pub fn detect(previous: &Manifest, current: &Manifest, threshold: usize) -> Vec<Alert> {
    let before: BTreeSet<_> = previous.files.iter().map(|f| &f.path).collect();
    let after: BTreeSet<_> = current.files.iter().map(|f| &f.path).collect();
    // Unreadable/excluded paths are not evidence of deletion.
    let deleted = before
        .difference(&after)
        .filter(|path| {
            !current.diagnostics.iter().any(|d| {
                d.reason != "read_retry_succeeded"
                    && (d.path.is_empty()
                        || path.as_str() == d.path
                        || path.starts_with(&format!("{}/", d.path)))
            })
        })
        .count();
    let mut alerts = vec![];
    let mut add = |kind: &str, count| {
        alerts.push(Alert {
            kind: kind.into(),
            fingerprint: blake3::hash(format!("{}:{kind}", current.id).as_bytes())
                .to_hex()
                .to_string(),
            detected_at: now(),
            snapshot: Some(current.id.clone()),
            count,
        })
    };
    if deleted > 0 && deleted >= threshold {
        add("mass_delete", deleted);
    }
    let changed = current
        .files
        .iter()
        .filter(|f| {
            let path = f.path.to_lowercase();
            (path.contains("mcp")
                || path.contains("/skills/")
                || path.ends_with("agents.md")
                || path.ends_with("claude.md"))
                && previous
                    .files
                    .iter()
                    .find(|old| old.path == f.path)
                    .is_none_or(|old| old.hash != f.hash)
        })
        .count();
    if changed > 0 {
        add("agent_config_changed", changed);
    }
    alerts
}

/// File and authenticated stored Git observations; no live repository or raw refs
/// are needed when retrying a persisted comparison after interruption.
pub fn detect_repository(
    repo: &Repository,
    previous: &Manifest,
    current: &Manifest,
    threshold: usize,
) -> Result<Vec<Alert>> {
    let mut alerts = detect(previous, current, threshold);
    if previous.git.is_some() || current.git.is_some() {
        match repo.git_alerts(previous, current) {
            Ok(summary) => {
                repo.audit("git_observation", serde_json::json!({"snapshot":current.id,"summary":summary}))?;
                for (kind, count) in [("history_rewrite", summary.local_branch_rewrites), ("force_push", summary.remote_tracking_rewrites)] {
                    if count > 0 {
                        alerts.push(Alert { kind: kind.into(), fingerprint: blake3::hash(format!("{}:{kind}",current.id).as_bytes()).to_hex().to_string(), detected_at: now(), snapshot: Some(current.id.clone()), count: usize::try_from(count).unwrap_or(usize::MAX) });
                    }
                }
            }
            Err(_) => repo.audit("git_observation_unavailable", serde_json::json!({"snapshot":current.id,"reason":"authenticated_observation_unavailable"}))?,
        }
    }
    Ok(alerts)
}

/// Backward-compatible passphrase entry points.
pub fn daemon(
    repo_path: &Path,
    passphrase: &str,
    workspace: &Path,
    policy_path: Option<&Path>,
    once: bool,
) -> Result<()> {
    daemon_with_key_source(
        repo_path,
        &KeySource::passphrase(passphrase),
        workspace,
        policy_path,
        once,
    )
}
pub fn tick(
    repo_path: &Path,
    passphrase: &str,
    workspace: &Path,
    policy_path: Option<&Path>,
    state: &mut ScheduleState,
    force: bool,
) -> Result<()> {
    tick_with_key_source(
        repo_path,
        &KeySource::passphrase(passphrase),
        workspace,
        policy_path,
        state,
        force,
    )
}
pub fn load_schedule(repo_path: &Path, passphrase: &str) -> Result<ScheduleState> {
    load_schedule_with_key_source(repo_path, &KeySource::passphrase(passphrase))
}
pub fn daemon_with_key_source(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    policy_path: Option<&Path>,
    once: bool,
) -> Result<()> {
    daemon_with_probes(repo_path, key_source, workspace, policy_path, once, None)
}

/// Run operator-configured restore probes independently of workspace retry state.
pub fn daemon_with_probes(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    policy_path: Option<&Path>,
    once: bool,
    probe_config: Option<&Path>,
) -> Result<()> {
    let repo_path = repo_path.canonicalize()?;
    let mut lock_options = fs::OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let daemon_lock = lock_options.open(repo_path.join("daemon.lock"))?;
    fs2::FileExt::try_lock_exclusive(&daemon_lock).context("daemon already running")?;
    #[cfg(unix)]
    let listener = {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        let socket = repo_path.join("daemon.sock");
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        listener
    };
    let state_path = repo_path.join("schedule.json");
    let mut state = load_schedule_with_key_source(&repo_path, key_source)?;
    durable_write(
        &repo_path.join("daemon.json"),
        &serde_json::to_vec(
            &serde_json::json!({"transport": if cfg!(unix) { "unix" } else { "disabled" }, "pid":std::process::id()}),
        )?,
    )?;
    loop {
        let started = Instant::now();
        if let Err(error) = tick_with_key_source(
            &repo_path,
            key_source,
            workspace,
            policy_path,
            &mut state,
            once,
        ) {
            eprintln!(
                "{}",
                serde_json::json!({"level":"error","event":"daemon_retry","retry_at":state.retry_after,"message":"scheduling step failed"})
            );
            // No parser diagnostics or config values enter logs/status.
            let _ = persist(&state_path, &state);
            if once {
                return Err(error);
            }
        }
        if let Some(config) = probe_config {
            if let Err(error) =
                scheduled_probe_tick(&repo_path, key_source, workspace, &mut state, config)
            {
                eprintln!(
                    "{}",
                    serde_json::json!({"level":"error","event":"restore_probe_retry","message":"scheduled restore probe unavailable"})
                );
                if once {
                    return Err(error);
                }
            }
        }
        if once {
            break;
        }
        // Bound each service pass even under a flood of local status clients.
        #[cfg(unix)]
        for _ in 0..16 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            if stream
                .set_write_timeout(Some(Duration::from_millis(100)))
                .is_ok()
            {
                let _ = stream.write_all(&serde_json::to_vec(
                    &serde_json::json!({"running":true,"state":state}),
                )?);
            }
        }
        thread::sleep(Duration::from_secs(1).saturating_sub(started.elapsed()));
    }
    Ok(())
}
fn persist(path: &Path, state: &ScheduleState) -> Result<()> {
    durable_write(path, &serde_json::to_vec(state)?)
}

fn scheduled_probe_tick(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    state: &mut ScheduleState,
    config: &Path,
) -> Result<()> {
    if now() < state.next_probe || now() < state.probe_retry_after || state.last_snapshot.is_none()
    {
        return Ok(());
    }
    let workspace = workspace.canonicalize()?;
    anyhow::ensure!(
        state.workspace.as_ref() == Some(&workspace),
        "probe schedule is bound to another workspace"
    );
    let repo = match Repository::open_with_key_source(repo_path, key_source) {
        Ok(repo) => repo,
        Err(error) => {
            let interval = state
                .last_good_policy
                .as_ref()
                .map_or(3600, |p| p.restore_test_interval_seconds);
            probe_unavailable(state, interval);
            persist(&repo_path.join("schedule.json"), state)?;
            return Err(error);
        }
    };
    scheduled_probe_work(&repo, state, |snapshot| {
        let manifest = repo.manifest(snapshot)?;
        let agent = manifest.agent.as_deref().unwrap_or("codex");
        crate::host_runtime::run_configured_probes(&repo, &workspace, agent, snapshot, Some(config))
    })
}

fn scheduled_probe_work(
    repo: &Repository,
    state: &mut ScheduleState,
    run: impl FnOnce(&str) -> Result<crate::host_service::RestoreEvidence>,
) -> Result<()> {
    if now() < state.next_probe || now() < state.probe_retry_after {
        return Ok(());
    }
    let Some(snapshot) = state.last_snapshot.clone() else {
        return Ok(());
    };
    let Some(policy) = &state.last_good_policy else {
        return Ok(());
    };
    let interval = policy.restore_test_interval_seconds;
    let result = run(&snapshot).and_then(|evidence| {
        anyhow::ensure!(
            evidence.snapshot == snapshot && !evidence.id.is_nil(),
            "probe evidence binding mismatch"
        );
        // Evidence is durable before the next due time advances. A crash between
        // these writes may repeat a probe, but cannot lose its recorded outcome.
        repo.audit("scheduled_restore_probe", serde_json::to_value(evidence)?)
    });
    match &result {
        Ok(()) => {
            state.next_probe = now().saturating_add(interval);
            state.probe_failures = 0;
            state.probe_retry_after = 0;
            state.last_probe_error = None;
        }
        Err(_) => {
            probe_unavailable(state, interval);
        }
    }
    persist(&repo.root().join("schedule.json"), state)?;
    result
}

fn probe_unavailable(state: &mut ScheduleState, interval: u64) {
    state.probe_failures = state.probe_failures.saturating_add(1);
    state.probe_retry_after = now().saturating_add(retry_delay(state.probe_failures, interval));
    state.last_probe_error = Some("restore probe unavailable".into());
}
/// Corruption never prevents backups. Preserve the exact bad file, then audit
/// recovery without putting parser output or file contents in logs.
pub fn load_schedule_with_key_source(
    repo_path: &Path,
    key_source: &KeySource,
) -> Result<ScheduleState> {
    let path = repo_path.join("schedule.json");
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ScheduleState::default())
        }
        Err(error) => return Err(error.into()),
    };
    use std::io::Read;
    let mut bytes = vec![];
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() <= 1024 * 1024 {
        if let Ok(state) = serde_json::from_slice::<ScheduleState>(&bytes) {
            if state
                .last_good_policy
                .as_ref()
                .is_none_or(|policy| policy.validate().is_ok())
                && state
                    .pending_setup
                    .as_ref()
                    .is_none_or(|pending| pending.validate().is_ok())
                && state.setup_diagnostics.len() <= 64
                && state.setup_diagnostics.iter().all(|entry| {
                    crate::repository::valid_id(&entry.workspace_snapshot).is_ok()
                        && entry.reason.len() <= 128
                })
            {
                return Ok(state);
            }
        }
    }
    let preserved = format!(
        "schedule.corrupt-{}.json",
        hex::encode(crate::crypto::random::<16>())
    );
    // No-clobber preservation precedes replacing the corrupt schedule.
    fs::hard_link(&path, repo_path.join(&preserved))?;
    #[cfg(unix)]
    fs::File::open(repo_path)?.sync_all()?;
    let mut state = ScheduleState {
        pending_schedule_recovery: Some(preserved),
        ..ScheduleState::default()
    };
    persist(&path, &state)?;
    // An audit outage must not turn a recoverable corrupt schedule into a
    // permanent startup failure. Persist the pending event for the retry loop.
    if let Ok(repo) = Repository::open_with_key_source(repo_path, key_source) {
        if finish_schedule_recovery(&repo, &mut state).is_ok() {
            persist(&path, &state)?;
        }
    }
    Ok(state)
}

pub fn retry_delay(failures: u32, interval_seconds: u64) -> u64 {
    2u64.saturating_pow(failures.min(63))
        .min(interval_seconds.max(1))
}

/// Failed steps back off durably, including after restart. A failure streak is
/// audited once; successful recovery clears it. Force is reserved for operators.
pub fn tick_with_key_source(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    policy_path: Option<&Path>,
    state: &mut ScheduleState,
    force: bool,
) -> Result<()> {
    if !force && now() < state.retry_after {
        return Ok(());
    }
    match tick_inner(repo_path, key_source, workspace, policy_path, state, force) {
        Ok(()) => {
            if state.failures > 0 {
                state.failures = 0;
                state.last_error = None;
                state.retry_after = 0;
                state.failure_audited = false;
                persist(&repo_path.join("schedule.json"), state)?;
            }
            Ok(())
        }
        Err(error) => {
            state.failures = state.failures.saturating_add(1);
            state.last_error = Some("scheduling step failed".into());
            let interval = state
                .last_good_policy
                .as_ref()
                .map_or(3600, |p| p.interval_seconds);
            state.retry_after = now().saturating_add(retry_delay(state.failures, interval));
            if !state.failure_audited {
                if let Ok(repo) = Repository::open_with_key_source(repo_path, key_source) {
                    state.failure_audited = repo.audit("backup_failed", serde_json::json!({"message":"scheduling step failed; retries use exponential backoff"})).is_ok();
                }
            }
            let _ = persist(&repo_path.join("schedule.json"), state);
            Err(error)
        }
    }
}
/// One retryable scheduling step, also used by regression tests. Last-good policy
/// survives partial edits and restarts; durable progress precedes detection/audit.
fn tick_inner(
    repo_path: &Path,
    key_source: &KeySource,
    workspace: &Path,
    policy_path: Option<&Path>,
    state: &mut ScheduleState,
    force: bool,
) -> Result<()> {
    let state_path = repo_path.join("schedule.json");
    let workspace = workspace.canonicalize()?;
    match &state.workspace {
        Some(bound) => anyhow::ensure!(
            *bound == workspace,
            "schedule is bound to another workspace; use a separate repository/schedule"
        ),
        None => {
            // Legacy schedules have no authenticated source identity. Preserve
            // queued historical work, but never use its latest snapshot as the
            // baseline of a newly bound source.
            state.workspace = Some(workspace.clone());
            state.last_snapshot = None;
            state.last_success = 0;
            state.next_run = 0;
            state.next_probe = 0;
            persist(&state_path, state)?;
        }
    }
    match Policy::load(policy_path) {
        Ok(policy) => {
            if state
                .last_good_policy
                .as_ref()
                .is_some_and(|p| p.interval_seconds != policy.interval_seconds)
            {
                state.next_run = state.last_success.saturating_add(policy.interval_seconds);
            }
            state.last_good_policy = Some(policy);
        }
        Err(_) if state.last_good_policy.is_some() => {
            eprintln!(
                "{}",
                serde_json::json!({"level":"warn","event":"policy_reload_failed","message":"using last good policy"})
            );
        }
        Err(error) => return Err(error.context("no valid policy available; will retry")),
    }
    let policy = state.last_good_policy.clone().context("no policy")?;
    if state.pending_detection.is_some() {
        // Re-persist before retrying detection if the previous state write failed.
        persist(&state_path, state)?;
        let repo = Repository::open_with_key_source(repo_path, key_source)?;
        finish_detection(&repo, state, &policy)?;
        persist(&state_path, state)?;
        finish_setup_step(&repo, state, &policy, force)?;
        persist(&state_path, state)?;
        return Ok(());
    }
    // A forced retry of unfinished setup does not force a duplicate workspace
    // snapshot before its cadence. Once due, workspace capture proceeds regardless.
    if now() < state.next_run && (!force || state.pending_setup.is_some()) {
        if state.pending_setup.is_some() {
            let repo = Repository::open_with_key_source(repo_path, key_source)?;
            finish_setup_step(&repo, state, &policy, force)?;
            persist(&state_path, state)?;
        }
        return Ok(());
    }
    let repo = Repository::open_with_key_source(repo_path, key_source)?;
    let previous = state.last_snapshot.clone();
    let baseline = previous.as_ref().and_then(|id| repo.manifest(id).ok());
    let manifest = repo.snapshot_with_previous(
        &workspace,
        &policy,
        None,
        None,
        "schedule",
        baseline.as_ref(),
    )?;
    if state.last_success > 0
        && now()
            > state
                .last_success
                .saturating_add(policy.interval_seconds)
                .saturating_add(policy.jitter_seconds)
                .saturating_add(60)
    {
        state.pending_missed_backup = Some(state.last_success);
    }
    state.last_success = now();
    state.last_snapshot = Some(manifest.id.clone());
    state.next_run = now()
        .saturating_add(policy.interval_seconds)
        .saturating_add(rand::thread_rng().gen_range(0..=policy.jitter_seconds));
    if let Some(pending) = state.pending_setup.take() {
        setup_diagnostic(
            state,
            pending.workspace_snapshot,
            "superseded_pending_setup",
        );
    }
    if policy.setup_home.is_some() {
        state.pending_setup = Some(PendingSetup {
            workspace_snapshot: manifest.id.clone(),
            policy: policy.clone(),
        });
    }
    state.pending_detection = Some((previous, manifest.id));
    persist(&state_path, state)?;
    finish_detection(&repo, state, &policy)?;
    persist(&state_path, state)?;
    finish_setup_step(&repo, state, &policy, force)?;
    persist(&state_path, state)?;
    Ok(())
}
fn setup_diagnostic(state: &mut ScheduleState, workspace_snapshot: String, reason: &str) {
    // Bounded local diagnostics; paths and exception/config contents never enter
    // these records. A newer pending job replaces at most one unfinished job.
    if state.setup_diagnostics.len() >= 64 {
        state.setup_diagnostics.remove(0);
    }
    state.setup_diagnostics.push(SetupDiagnostic {
        workspace_snapshot,
        reason: reason.into(),
        at: now(),
    });
}
fn finish_setup_step(
    repo: &Repository,
    state: &mut ScheduleState,
    policy: &Policy,
    force: bool,
) -> Result<()> {
    let Some(pending) = state.pending_setup.clone() else {
        return Ok(());
    };
    pending.validate()?;
    if serde_json::to_value(&pending.policy)? != serde_json::to_value(policy)? {
        setup_diagnostic(state, pending.workspace_snapshot, "setup_policy_changed");
        state.pending_setup = None;
        state.setup_failures = 0;
        state.setup_retry_after = 0;
        state.last_setup_error =
            Some("pending setup cancelled because operator policy changed".into());
        return Ok(());
    }
    if !force && now() < state.setup_retry_after {
        return Ok(());
    }
    let result = (|| -> Result<()> {
        let home = pending
            .policy
            .setup_home
            .as_ref()
            .context("setup root missing")?;
        crate::session_hooks::open_existing_root(home)?;
        let context = bunker_discovery::DiscoveryContext::new(
            bunker_discovery::Platform::current(),
            home,
            vec![],
        );
        let manifests = repo.snapshot_setup_for_schedule(
            &context,
            &pending.policy,
            &pending.workspace_snapshot,
        )?;
        repo.audit("setup_backup_completed", serde_json::json!({"workspace_snapshot":pending.workspace_snapshot,"snapshots":manifests.iter().map(|m| &m.id).collect::<Vec<_>>()}))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            state.pending_setup = None;
            state.setup_failures = 0;
            state.setup_retry_after = 0;
            state.last_setup_error = None;
        }
        Err(_) => {
            state.setup_failures = state.setup_failures.saturating_add(1);
            state.setup_retry_after =
                now().saturating_add(retry_delay(state.setup_failures, policy.interval_seconds));
            state.last_setup_error = Some("global setup capture or completion audit failed".into());
            setup_diagnostic(state, pending.workspace_snapshot, "setup_capture_failed");
        }
    }
    Ok(())
}
fn finish_schedule_recovery(repo: &Repository, state: &mut ScheduleState) -> Result<()> {
    if let Some(preserved) = &state.pending_schedule_recovery {
        repo.audit(
            "schedule_recovered",
            serde_json::json!({"preserved":preserved}),
        )?;
        state.pending_schedule_recovery = None;
    }
    Ok(())
}
fn finish_detection(repo: &Repository, state: &mut ScheduleState, policy: &Policy) -> Result<()> {
    finish_schedule_recovery(repo, state)?;
    if let Some(last_success) = state.pending_missed_backup {
        repo.audit(
            "missed_backup",
            serde_json::json!({"last_success":last_success}),
        )?;
        state.pending_missed_backup = None;
    }
    if let Some((previous, current)) = &state.pending_detection {
        let current = match repo.manifest(current) {
            Ok(manifest) => manifest,
            Err(_) => {
                repo.audit("detection_gap", serde_json::json!({"snapshot":current,"reason":"current manifest unavailable or damaged"}))?;
                state.last_snapshot = None;
                state.next_run = now();
                state.pending_detection = None;
                return Ok(());
            }
        };
        if let Some(id) = previous {
            match repo.manifest(id) {
                Ok(previous) => {
                    for alert in detect_repository(repo, &previous, &current, policy.mass_delete_threshold)? {
                        repo.audit("alert", serde_json::to_value(alert)?)?;
                    }
                }
                Err(_) => repo.audit("detection_gap", serde_json::json!({"prior_snapshot":id,"reason":"prior manifest unavailable or damaged"}))?,
            }
        }
        repo.audit(
            "backup_completed",
            serde_json::json!({"snapshot":current.id}),
        )?;
        state.pending_detection = None;
    }
    Ok(())
}
#[cfg(unix)]
pub fn status(repo_path: &Path) -> Result<serde_json::Value> {
    use std::{io::Read, os::unix::net::UnixStream};
    let stream =
        UnixStream::connect(repo_path.join("daemon.sock")).context("daemon is not running")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = vec![];
    stream.take(65536).read_to_end(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(not(unix))]
pub fn status(_repo_path: &Path) -> Result<serde_json::Value> {
    anyhow::bail!(
        "local daemon status requires a permission-restricted Unix socket on this platform"
    )
}

#[cfg(test)]
mod probe_schedule_tests {
    use super::*;
    use crate::host_service::{AgentProbe, EvidenceSandbox, ProbeOutcome, RestoreEvidence};
    use uuid::Uuid;

    #[test]
    fn probe_results_persist_without_changing_backup_cadence() {
        let temp = tempfile::tempdir().unwrap();
        let repo = Repository::init(&temp.path().join("repo"), "probe-fixture").unwrap();
        let workspace = temp.path().join("work");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("file"), "fixture").unwrap();
        let policy = Policy::default();
        let snapshot = repo
            .snapshot(&workspace, &policy, None, None, "fixture")
            .unwrap();
        let mut state = ScheduleState {
            last_snapshot: Some(snapshot.id.clone()),
            last_good_policy: Some(policy),
            next_run: 12345,
            failures: 3,
            retry_after: u64::MAX,
            ..ScheduleState::default()
        };
        scheduled_probe_work(&repo, &mut state, |_| {
            anyhow::bail!("private path must not enter status")
        })
        .unwrap_err();
        assert_eq!(state.next_run, 12345);
        assert_eq!(state.failures, 3);
        assert_eq!(
            state.last_probe_error.as_deref(),
            Some("restore probe unavailable")
        );
        scheduled_probe_work(&repo, &mut state, |_| panic!("probe backoff ignored")).unwrap();
        state.probe_retry_after = 0;
        scheduled_probe_work(&repo, &mut state, |id| {
            Ok(RestoreEvidence {
                id: Uuid::new_v4(),
                snapshot: id.into(),
                finished_at: chrono::Utc::now(),
                sandbox: EvidenceSandbox::ContainerFileContent,
                agents: vec![AgentProbe {
                    agent: "codex".into(),
                    outcome: ProbeOutcome::Failed,
                }],
                mcps: vec![],
            })
        })
        .unwrap();
        assert!(state.next_probe > now());
        assert_eq!(state.probe_failures, 0);
        assert!(state.last_probe_error.is_none());
        assert_eq!(state.next_run, 12345);
        let saved: ScheduleState =
            serde_json::from_slice(&fs::read(repo.root().join("schedule.json")).unwrap()).unwrap();
        assert_eq!(saved.next_probe, state.next_probe);
        assert_eq!(saved.retry_after, u64::MAX);
        scheduled_probe_work(&repo, &mut state, |_| panic!("probe interval ignored")).unwrap();
        state.next_probe = 0;
        scheduled_probe_work(&repo, &mut state, |_| {
            Ok(RestoreEvidence {
                id: Uuid::new_v4(),
                snapshot: "another-snapshot".into(),
                finished_at: chrono::Utc::now(),
                sandbox: EvidenceSandbox::ContainerFileContent,
                agents: vec![],
                mcps: vec![],
            })
        })
        .unwrap_err();
        assert_eq!(state.next_probe, 0);
    }
}
