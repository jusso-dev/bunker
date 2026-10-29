//! Local configuration and durable scheduling for the independently authenticated host bridge.
use crate::{
    control_plane::{self, CredentialStore, EnrollmentTokenSource, HttpsOrigin, ServerTrust},
    host_service::{
        AlertKind, ConsumedRequests, LocalBindings, ObservedAlert, ProductionHost, WorkResults,
    },
    policy::Policy,
    repository::{now, KeySource, Repository},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub public_origin: String,
    pub host_origin: String,
    pub tenant: Uuid,
    pub credential_directory: PathBuf,
    pub consumed_directory: PathBuf,
    pub server_ca_file: Option<PathBuf>,
    pub storage_ref: String,
    pub key_ref: String,
    #[serde(default)]
    pub setup_home: Option<PathBuf>,
    #[serde(default)]
    pub probe_config: Option<PathBuf>,
    #[serde(default)]
    pub storage: Option<crate::host_storage::HostStorageConfig>,
    /// Operator attests that a local wrapper or native handler routes session events here.
    #[serde(default)]
    pub session_handler: bool,
}
impl HostConfig {
    fn validate_storage_paths(&self, repo: &Path, workspace: &Path) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.validate_paths(repo, workspace)?;
        }
        Ok(())
    }
    fn bindings(&self, repo: &Repository, workspace: &Path) -> Result<LocalBindings> {
        let mut bindings = LocalBindings::local_repository(repo, &self.storage_ref, &self.key_ref)?
            .with_session_handler(self.session_handler);
        if let Some(config) = &self.storage {
            let adapter = crate::host_storage::HostStorageAdapter::open(
                config,
                repo,
                workspace,
                &self.storage_ref,
                &self.key_ref,
            )?;
            bindings = bindings.with_storage(std::sync::Arc::new(adapter));
        }
        Ok(bindings)
    }
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = String::new();
        fs::File::open(path)?
            .take(16385)
            .read_to_string(&mut bytes)?;
        ensure!(bytes.len() <= 16384, "host configuration exceeds limit");
        let config: Self = toml::from_str(&bytes).context("invalid host configuration")?;
        HttpsOrigin::parse(&config.public_origin)?;
        HttpsOrigin::parse(&config.host_origin)?;
        ensure!(!config.tenant.is_nil(), "host tenant is required");
        ensure!(
            config.credential_directory.is_absolute() && config.consumed_directory.is_absolute(),
            "host state directories must be absolute"
        );
        ensure!(
            !config.storage_ref.is_empty() && !config.key_ref.is_empty(),
            "host storage/key references are required"
        );
        Policy {
            setup_home: config.setup_home.clone(),
            ..Policy::default()
        }
        .validate()?;
        Ok(config)
    }
    fn trust(&self) -> Result<ServerTrust> {
        match &self.server_ca_file {
            None => Ok(ServerTrust::Native),
            Some(path) => {
                let mut bytes = vec![];
                fs::File::open(path)?
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 1024 * 1024, "server CA bundle exceeds limit");
                Ok(ServerTrust::CaBundle(bytes))
            }
        }
    }
    pub fn enroll(&self, token: &EnrollmentTokenSource) -> Result<serde_json::Value> {
        let store = CredentialStore::open(&self.credential_directory)?;
        ensure!(!store.directory().join("identity.json").try_exists()?, "host identity already exists; use its automatic renewal or a new explicit state directory");
        let credentials = control_plane::enroll(
            HttpsOrigin::parse(&self.public_origin)?,
            &self.trust()?,
            self.tenant,
            token,
            &store,
        )?;
        Ok(
            serde_json::json!({"enrolled":true,"tenant":credentials.tenant_id,"host":credentials.host_id,"expires_at":credentials.expires_at}),
        )
    }
    pub fn open(&self) -> Result<(ProductionHost, ConsumedRequests)> {
        let store = CredentialStore::open(&self.credential_directory)?;
        let consumed = ConsumedRequests::open(&self.consumed_directory)?;
        let credentials = store.load()?;
        ensure!(
            credentials.tenant_id == self.tenant,
            "configured tenant does not match host identity"
        );
        let host =
            ProductionHost::open(store, HttpsOrigin::parse(&self.host_origin)?, self.trust()?)?;
        Ok((host, consumed))
    }
    pub fn validate_workspace(&self, workspace: &Path) -> Result<PathBuf> {
        let work = workspace.canonicalize()?;
        for path in [&self.credential_directory, &self.consumed_directory] {
            let state = path.canonicalize()?;
            ensure!(
                !state.starts_with(&work) && !work.starts_with(&state),
                "workspace overlaps protected host state"
            );
        }
        Ok(work)
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    workspace: PathBuf,
    host: Option<Uuid>,
    last_snapshot: Option<String>,
    next_run: u64,
    pending: Vec<String>,
    pending_alerts: Vec<crate::scheduler::Alert>,
    #[serde(default)]
    pending_evidence: Vec<crate::host_service::RestoreEvidence>,
    #[serde(default)]
    next_probe: u64,
    #[serde(default)]
    pending_detection: Option<PendingDetection>,
    #[serde(default)]
    pending_setup: Option<String>,
    #[serde(default)]
    setup_binding: Option<SetupBinding>,
    #[serde(default)]
    setup_failures: u32,
    #[serde(default)]
    setup_retry_after: u64,
    #[serde(default)]
    last_setup_error: Option<String>,
    #[serde(default)]
    diagnostics: Vec<RuntimeDiagnostic>,
    #[serde(default)]
    sessions: Vec<PendingSession>,
    #[serde(default)]
    session_receipts: Vec<SessionReceipt>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSession {
    key: String,
    agent: bunker_discovery::AgentId,
    policy: Policy,
    home: Option<PathBuf>,
    before: Option<String>,
    workspace_snapshot: Option<String>,
    setup_snapshots: Vec<String>,
    capture_complete: bool,
    last_error: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReceipt {
    key: String,
    workspace_snapshot: String,
    setup_snapshots: Vec<String>,
}
const MAX_ACTIVE_SESSIONS: usize = 16;
const MAX_SESSION_RECEIPTS: usize = 4096;
const MAX_SETUP_SCOPES: usize = 64;
const MAX_SCHEDULE_BYTES: usize = 1024 * 1024 - 40;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingDetection {
    before: Option<String>,
    after: String,
    threshold: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBinding {
    home: PathBuf,
    policy: Policy,
    agent: bunker_discovery::AgentId,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDiagnostic {
    snapshot: Option<String>,
    reason: String,
    at: u64,
}
const MAX_OUTBOX: usize = 256;
const MAX_ALERTS: usize = 512;
const MAX_DIAGNOSTICS: usize = 64;
const MAX_EVIDENCE_OUTBOX: usize = 16;
const STATE: &str = "host/schedule";
const DOMAIN: &[u8] = b"bunker-host-schedule-v1";
fn load_schedule(repo: &Repository, workspace: &Path, host: Uuid) -> Result<Schedule> {
    let mut state: Schedule = match repo.read_private_metadata(STATE, 1024 * 1024)? {
        Some(bytes) => serde_json::from_slice(&repo.open_metadata(DOMAIN, &bytes)?)?,
        None => Schedule::default(),
    };
    validate_schedule(&state)?;
    if state.host.is_some() {
        ensure!(
            state.host == Some(host) && state.workspace == workspace,
            "host schedule is bound to another host/workspace"
        );
    } else {
        state.host = Some(host);
        state.workspace = workspace.into();
    }
    Ok(state)
}
fn validate_schedule(state: &Schedule) -> Result<()> {
    ensure!(
        state.sessions.len() <= MAX_ACTIVE_SESSIONS
            && state.sessions.len() + state.session_receipts.len() <= MAX_SESSION_RECEIPTS,
        "host session ledger is full"
    );
    let mut keys = std::collections::BTreeSet::new();
    for session in &state.sessions {
        crate::repository::valid_id(&session.key)?;
        ensure!(keys.insert(&session.key), "duplicate host session identity");
        session.policy.validate()?;
        Policy {
            setup_home: session.home.clone(),
            ..Policy::default()
        }
        .validate()?;
        ensure!(
            session.setup_snapshots.len() <= MAX_SETUP_SCOPES,
            "too many session setup snapshots"
        );
        ensure!(
            !session.capture_complete || session.workspace_snapshot.is_some(),
            "completed session missing workspace snapshot"
        );
        for id in session
            .before
            .iter()
            .chain(session.workspace_snapshot.iter())
            .chain(&session.setup_snapshots)
        {
            crate::repository::valid_id(id)?;
        }
    }
    for receipt in &state.session_receipts {
        crate::repository::valid_id(&receipt.key)?;
        ensure!(keys.insert(&receipt.key), "duplicate host session identity");
        ensure!(
            receipt.setup_snapshots.len() <= MAX_SETUP_SCOPES,
            "too many session setup snapshots"
        );
        for id in std::iter::once(&receipt.workspace_snapshot).chain(&receipt.setup_snapshots) {
            crate::repository::valid_id(id)?;
        }
    }
    if let Some(pending) = &state.pending_detection {
        ensure!(
            (1..=1_000_000).contains(&pending.threshold),
            "invalid detection threshold"
        );
        for id in pending.before.iter().chain(std::iter::once(&pending.after)) {
            crate::repository::valid_id(id)?;
        }
    }
    ensure!(
        state.pending.len() <= MAX_OUTBOX
            && state.pending_alerts.len() <= MAX_ALERTS
            && state.diagnostics.len() <= MAX_DIAGNOSTICS,
        "host schedule exceeds bounded outbox limits"
    );
    ensure!(
        state.pending_evidence.len() <= MAX_EVIDENCE_OUTBOX,
        "host evidence outbox exceeds limit"
    );
    for evidence in &state.pending_evidence {
        crate::repository::valid_id(&evidence.snapshot)?;
        ensure!(
            !evidence.id.is_nil()
                && (1..=5).contains(&evidence.agents.len())
                && evidence.mcps.len() <= 100,
            "invalid saved restore evidence"
        );
    }
    for id in &state.pending {
        crate::repository::valid_id(id)?;
    }
    if let Some(id) = &state.pending_setup {
        crate::repository::valid_id(id)?;
    }
    if let Some(binding) = &state.setup_binding {
        binding.policy.validate()?;
        Policy {
            setup_home: Some(binding.home.clone()),
            ..Policy::default()
        }
        .validate()?;
    }
    for id in state.last_snapshot.iter().chain(
        state
            .pending_alerts
            .iter()
            .filter_map(|a| a.snapshot.as_ref()),
    ) {
        crate::repository::valid_id(id)?;
    }
    Ok(())
}
/// Maintenance shares the runtime schema and bounds before deriving deletion roots.
pub(crate) fn maintenance_pins(plaintext: &[u8]) -> Result<std::collections::BTreeSet<String>> {
    let state: Schedule = serde_json::from_slice(plaintext)?;
    validate_schedule(&state)?;
    // A crash may publish a manifest before the ledger records its ID. Refuse
    // deletion until a same-ID session retry reconciles that authenticated manifest.
    ensure!(
        state.sessions.iter().all(|s| s.capture_complete),
        "unfinished host session must be retried before maintenance"
    );
    let session_pins = state.sessions.into_iter().flat_map(|s| {
        s.before
            .into_iter()
            .chain(s.workspace_snapshot)
            .chain(s.setup_snapshots)
    });
    let receipt_pins = state
        .session_receipts
        .into_iter()
        .flat_map(|s| std::iter::once(s.workspace_snapshot).chain(s.setup_snapshots));
    let detection = state
        .pending_detection
        .into_iter()
        .flat_map(|d| d.before.into_iter().chain(std::iter::once(d.after)));
    Ok(state
        .pending
        .into_iter()
        .chain(detection)
        .chain(state.last_snapshot)
        .chain(state.pending_setup)
        .chain(state.pending_evidence.into_iter().map(|e| e.snapshot))
        .chain(state.pending_alerts.into_iter().filter_map(|a| a.snapshot))
        .chain(session_pins)
        .chain(receipt_pins)
        .collect())
}

fn save_schedule(repo: &Repository, state: &Schedule) -> Result<()> {
    validate_schedule(state)?;
    let plaintext = serde_json::to_vec(state)?;
    ensure!(
        plaintext.len() <= MAX_SCHEDULE_BYTES,
        "host schedule exceeds durable state capacity"
    );
    repo.write_private_metadata(STATE, &repo.seal_metadata(DOMAIN, &plaintext)?, true)
}
fn diagnostic(state: &mut Schedule, snapshot: Option<String>, reason: &str) {
    if state.diagnostics.len() >= MAX_DIAGNOSTICS {
        state.diagnostics.remove(0);
    }
    state.diagnostics.push(RuntimeDiagnostic {
        snapshot,
        reason: reason.into(),
        at: now(),
    });
}
fn agent_id(agent: &str) -> Result<bunker_discovery::AgentId> {
    use bunker_discovery::AgentId::*;
    match agent {
        "claude-code" | "claude_code" => Ok(ClaudeCode),
        "cursor" => Ok(Cursor),
        "codex" => Ok(Codex),
        "copilot" | "github_copilot" => Ok(GitHubCopilot),
        "kiro" => Ok(Kiro),
        _ => anyhow::bail!("unsupported agent"),
    }
}
fn attempt_setup(
    repo: &Repository,
    policy: &Policy,
    state: &mut Schedule,
    home: Option<&Path>,
    agent: bunker_discovery::AgentId,
) -> Result<()> {
    let Some(snapshot) = state.pending_setup.clone() else {
        return Ok(());
    };
    let binding = state.setup_binding.clone();
    let current = binding
        .as_ref()
        .is_some_and(|binding| home == Some(binding.home.as_path()) && binding.agent == agent)
        && binding
            .as_ref()
            .map(|binding| serde_json::to_value(&binding.policy))
            .transpose()?
            == Some(serde_json::to_value(policy)?);
    if !current {
        diagnostic(state, Some(snapshot), "setup_policy_or_home_changed");
        state.pending_setup = None;
        state.setup_binding = None;
        state.setup_failures = 0;
        state.setup_retry_after = 0;
        state.last_setup_error =
            Some("pending setup cancelled: policy, agent, or home changed".into());
        return save_schedule(repo, state);
    }
    if now() < state.setup_retry_after {
        return Ok(());
    }
    let binding = binding.context("missing setup binding")?;
    let result = (|| -> Result<Vec<String>> {
        crate::session_hooks::open_existing_root(&binding.home)?;
        let context = bunker_discovery::DiscoveryContext::new(
            bunker_discovery::Platform::current(),
            &binding.home,
            vec![],
        );
        let setup = repo.snapshot_setup_for_schedule_filtered(
            &context,
            &binding.policy,
            &snapshot,
            Some(binding.agent),
        )?;
        let ids: Vec<_> = setup
            .into_iter()
            .map(|manifest| manifest.id)
            .filter(|id| !state.pending.contains(id))
            .collect();
        ensure!(
            state.pending.len() + ids.len() <= MAX_OUTBOX,
            "host delivery outbox is full"
        );
        Ok(ids)
    })();
    match result {
        Ok(ids) => {
            state.pending.extend(ids);
            state.pending_setup = None;
            state.setup_binding = None;
            state.setup_failures = 0;
            state.setup_retry_after = 0;
            state.last_setup_error = None;
        }
        Err(_) => {
            state.setup_failures = state.setup_failures.saturating_add(1);
            state.setup_retry_after = now().saturating_add(crate::scheduler::retry_delay(
                state.setup_failures,
                policy.interval_seconds,
            ));
            state.last_setup_error = Some("setup capture or delivery queue capacity failed".into());
            diagnostic(state, Some(snapshot), "setup_capture_or_queue_failed");
        }
    }
    // Persist setup retry state independently. A capture error must not hide the
    // already-persisted workspace outbox from the delivery callback below.
    save_schedule(repo, state)
}
fn finish_detection(repo: &Repository, state: &mut Schedule) -> Result<()> {
    if state.pending_alerts.len() > MAX_ALERTS - 4 {
        return Ok(());
    }
    if let Some(pending) = &state.pending_detection {
        let current = repo.manifest(&pending.after)?;
        if let Some(before) = &pending.before {
            match repo.manifest(before) {
                Ok(previous) => state
                    .pending_alerts
                    .extend(crate::scheduler::detect_repository(
                        repo,
                        &previous,
                        &current,
                        pending.threshold,
                    )?),
                Err(_) => diagnostic(state, Some(before.clone()), "previous_manifest_unreadable"),
            }
        }
        state.pending_detection = None;
        save_schedule(repo, state)?;
    }
    Ok(())
}
fn scheduled_work(
    repo: &Repository,
    workspace: &Path,
    agent: &str,
    policy: &Policy,
    state: &mut Schedule,
    setup_home: Option<&Path>,
) -> Result<WorkResults> {
    policy.validate()?;
    let setup_agent = agent_id(agent)?;
    finish_detection(repo, state)?;
    let reconciled = reconcile_session_captures(repo, state)?;
    if state.pending_detection.is_none() && reconciled && now() >= state.next_run {
        if state.pending.len() >= MAX_OUTBOX || state.pending_alerts.len() > MAX_ALERTS - 4 {
            // Backpressure is explicit and preserves every pending delivery. It
            // pauses new capture only after bounded capacity is exhausted; the
            // existing outbox is still returned so successful delivery can drain it.
            diagnostic(
                state,
                state.last_snapshot.clone(),
                "delivery_outbox_full_capture_deferred",
            );
            save_schedule(repo, state)?;
        } else {
            let previous = state.last_snapshot.clone();
            let baseline = previous.as_ref().and_then(|id| repo.manifest(id).ok());
            let snapshot = repo.snapshot_with_previous(
                workspace,
                policy,
                Some(agent.into()),
                None,
                "host-schedule",
                baseline.as_ref(),
            )?;
            state.next_run = now().saturating_add(policy.interval_seconds);
            state.last_snapshot = Some(snapshot.id.clone());
            state.pending.push(snapshot.id.clone());
            if let Some(previous_setup) = state.pending_setup.take() {
                diagnostic(state, Some(previous_setup), "superseded_pending_setup");
            }
            state.setup_binding = setup_home.map(|home| SetupBinding {
                home: home.into(),
                policy: policy.clone(),
                agent: setup_agent,
            });
            state.pending_setup = setup_home.map(|_| snapshot.id.clone());
            state.pending_detection = Some(PendingDetection {
                before: previous,
                after: snapshot.id.clone(),
                threshold: policy.mass_delete_threshold,
            });
            // Commit successful capture before detection, setup, or delivery.
            save_schedule(repo, state)?;
            finish_detection(repo, state)?;
        }
    }
    attempt_setup(repo, policy, state, setup_home, setup_agent)?;
    Ok(outbox(state))
}

fn outbox(state: &Schedule) -> WorkResults {
    let alerts = state
        .pending_alerts
        .iter()
        .map(|alert| ObservedAlert {
            event_id: Uuid::new_v5(&Uuid::NAMESPACE_OID, alert.fingerprint.as_bytes()),
            kind: match alert.kind.as_str() {
                "mass_delete" => AlertKind::MassDelete,
                "history_rewrite" => AlertKind::HistoryRewrite,
                "force_push" => AlertKind::ForcePush,
                _ => AlertKind::McpChange,
            },
            critical: alert.kind == "mass_delete",
            snapshot: alert.snapshot.clone(),
            count: alert.count as u64,
        })
        .collect();
    WorkResults {
        snapshots: state.pending.clone(),
        alerts,
        evidence: state.pending_evidence.clone(),
    }
}

fn skipped_probe(
    snapshot: &str,
    agent: &str,
    reason: crate::host_service::ProbeSkip,
) -> crate::host_service::RestoreEvidence {
    crate::host_service::RestoreEvidence {
        id: Uuid::new_v4(),
        snapshot: snapshot.into(),
        finished_at: chrono::Utc::now(),
        sandbox: crate::host_service::EvidenceSandbox::Container,
        agents: vec![crate::host_service::AgentProbe {
            agent: agent.into(),
            outcome: crate::host_service::ProbeOutcome::NotRunWithReason(reason),
        }],
        mcps: vec![],
    }
}
fn scheduled_probes(
    repo: &Repository,
    policy: &Policy,
    state: &mut Schedule,
    agent: &str,
    run: impl FnOnce(&str) -> Result<crate::host_service::RestoreEvidence>,
) -> Result<()> {
    if now() < state.next_probe || state.pending_evidence.len() >= MAX_EVIDENCE_OUTBOX {
        return Ok(());
    }
    let Some(snapshot) = state.last_snapshot.clone() else {
        return Ok(());
    };
    let evidence = match run(&snapshot) {
        Ok(evidence) => evidence,
        Err(_) => {
            diagnostic(
                state,
                Some(snapshot.clone()),
                "probe_configuration_or_runtime_unavailable",
            );
            skipped_probe(
                &snapshot,
                agent,
                crate::host_service::ProbeSkip::RuntimeUnavailable,
            )
        }
    };
    ensure!(
        evidence.snapshot == snapshot && !evidence.id.is_nil(),
        "probe evidence binding mismatch"
    );
    state.pending_evidence.push(evidence);
    state.next_probe = now().saturating_add(policy.restore_test_interval_seconds);
    validate_schedule(state)?;
    save_schedule(repo, state)
}
pub(crate) fn run_configured_probes(
    repo: &Repository,
    workspace: &Path,
    agent: &str,
    snapshot: &str,
    path: Option<&Path>,
) -> Result<crate::host_service::RestoreEvidence> {
    let Some(path) = path else {
        return Ok(skipped_probe(
            snapshot,
            agent,
            crate::host_service::ProbeSkip::NotConfigured,
        ));
    };
    let resolved = path.canonicalize()?;
    ensure!(
        !resolved.starts_with(repo.root()) && !resolved.starts_with(workspace),
        "trusted probe config overlaps captured data"
    );
    let config = crate::restore_probes::TrustedProbeConfig::load(path)?;
    for trusted in [&config.docker_executable, &config.docker_config] {
        let resolved = trusted.canonicalize()?;
        ensure!(
            !resolved.starts_with(repo.root()) && !resolved.starts_with(workspace),
            "trusted Docker runtime overlaps captured data"
        );
    }
    let mut executor = crate::restore_probes::DockerExecutor::new(&config)?;
    crate::restore_probes::run_restore_probes(repo, snapshot, &config, &mut executor)
}
/// No raw session ID, command, payload path, or transport error is exposed.
#[derive(Debug, Serialize)]
pub struct HostSessionReport {
    pub session_key: String,
    pub workspace_snapshot: Option<String>,
    pub capture_complete: bool,
    pub delivery_complete: bool,
    pub retry_required: bool,
    pub error: Option<String>,
}

fn session_key(host: Uuid, event: &crate::session_hooks::SessionEnd) -> Result<String> {
    event.validate()?;
    Ok(blake3::hash(&serde_json::to_vec(&(host, event))?)
        .to_hex()
        .to_string())
}

fn acknowledge_sessions(state: &mut Schedule) {
    let mut unfinished = vec![];
    for session in state.sessions.drain(..) {
        if session.capture_complete {
            state.session_receipts.push(SessionReceipt {
                key: session.key,
                workspace_snapshot: session.workspace_snapshot.expect("validated session"),
                setup_snapshots: session.setup_snapshots,
            });
        } else {
            unfinished.push(session);
        }
    }
    state.sessions = unfinished;
}

fn published_session(
    repo: &Repository,
    session: &PendingSession,
) -> Result<Option<crate::repository::Manifest>> {
    let mut recovered = repo
        .list()?
        .into_iter()
        .filter(|manifest| {
            manifest.trigger == "host-session-end"
                && manifest.session.as_deref() == Some(session.key.as_str())
                && manifest.setup.is_none()
        })
        .collect::<Vec<_>>();
    ensure!(recovered.len() <= 1, "ambiguous session capture");
    if let Some(manifest) = recovered.pop() {
        ensure!(
            manifest.agent.as_deref() == Some(session.agent.as_str()),
            "session agent binding changed"
        );
        repo.verify(&manifest.id)?;
        Ok(Some(manifest))
    } else {
        Ok(None)
    }
}

fn record_session_capture(
    repo: &Repository,
    state: &mut Schedule,
    index: usize,
    snapshot: crate::repository::Manifest,
) -> Result<()> {
    ensure!(
        state.pending.len() < MAX_OUTBOX && state.pending_detection.is_none(),
        "session delivery or comparison backpressure"
    );
    state.sessions[index].workspace_snapshot = Some(snapshot.id.clone());
    state.last_snapshot = Some(snapshot.id.clone());
    if !state.pending.contains(&snapshot.id) {
        state.pending.push(snapshot.id.clone());
    }
    state.pending_detection = Some(PendingDetection {
        before: state.sessions[index].before.clone(),
        after: snapshot.id,
        threshold: state.sessions[index].policy.mass_delete_threshold,
    });
    save_schedule(repo, state)?;
    finish_detection(repo, state)
}

/// Recover published results before any new periodic capture advances the shared
/// baseline. An intent with no published result does not pause periodic work.
/// This never initiates session capture under a daemon policy that may disable it.
fn reconcile_session_captures(repo: &Repository, state: &mut Schedule) -> Result<bool> {
    for index in 0..state.sessions.len() {
        if state.sessions[index].workspace_snapshot.is_some() {
            continue;
        }
        if let Some(snapshot) = published_session(repo, &state.sessions[index])? {
            if state.pending.len() >= MAX_OUTBOX
                || state.pending_detection.is_some()
                || state.pending_alerts.len() > MAX_ALERTS - 4
            {
                return Ok(false);
            }
            record_session_capture(repo, state, index, snapshot)?;
            if state.sessions[index].home.is_none() {
                state.sessions[index].capture_complete = true;
                state.sessions[index].last_error = None;
                save_schedule(repo, state)?;
            }
        }
    }
    Ok(true)
}

fn capture_host_session(
    repo: &Repository,
    workspace: &Path,
    policy: &Policy,
    state: &mut Schedule,
    index: usize,
    home: Option<&Path>,
) -> Result<()> {
    let session = state.sessions[index].clone();
    if session.capture_complete {
        return Ok(());
    }
    ensure!(
        session.home.as_deref() == home
            && serde_json::to_value(&session.policy)? == serde_json::to_value(policy)?,
        "session policy or setup home changed; retry original binding"
    );
    finish_detection(repo, state)?;
    ensure!(
        state.pending_detection.is_none(),
        "session comparison backpressure"
    );
    ensure!(
        state.pending_alerts.len() <= MAX_ALERTS - 4,
        "session alert outbox is full"
    );
    if session.workspace_snapshot.is_none() {
        ensure!(
            state.pending.len() < MAX_OUTBOX,
            "session delivery outbox is full"
        );
        // Reconcile a manifest published before the schedule replacement. The
        // durable intent binds the key, agent, host/workspace and policy first.
        let snapshot = if let Some(manifest) = published_session(repo, &session)? {
            manifest
        } else {
            // A failed intent may span successful periodic captures. Bind the
            // actual current baseline durably before publishing a new snapshot.
            state.sessions[index].before = state.last_snapshot.clone();
            save_schedule(repo, state)?;
            let previous = state.sessions[index]
                .before
                .as_ref()
                .map(|id| repo.manifest(id))
                .transpose()?;
            repo.snapshot_with_previous(
                workspace,
                policy,
                Some(session.agent.as_str().into()),
                Some(session.key.clone()),
                "host-session-end",
                previous.as_ref(),
            )?
        };
        record_session_capture(repo, state, index, snapshot)?;
    }
    if let Some(home) = home {
        // Reserve the discovery maximum before any setup manifests are published.
        ensure!(
            state.pending.len() + MAX_SETUP_SCOPES <= MAX_OUTBOX,
            "session setup delivery outbox is full"
        );
        crate::session_hooks::open_existing_root(home)?;
        let context = bunker_discovery::DiscoveryContext::new(
            bunker_discovery::Platform::current(),
            home,
            vec![],
        );
        let snapshots = repo.snapshot_setup_for_schedule_filtered(
            &context,
            policy,
            state.sessions[index]
                .workspace_snapshot
                .as_deref()
                .context("session capture missing")?,
            Some(session.agent),
        )?;
        let ids = snapshots.into_iter().map(|s| s.id).collect::<Vec<_>>();
        ensure!(
            ids.len() <= MAX_SETUP_SCOPES,
            "too many session setup snapshots"
        );
        for id in &ids {
            if !state.pending.contains(id) {
                state.pending.push(id.clone());
            }
        }
        state.sessions[index].setup_snapshots = ids;
    }
    state.sessions[index].capture_complete = true;
    state.sessions[index].last_error = None;
    save_schedule(repo, state)
}

fn session_work(
    repo: &Repository,
    workspace: &Path,
    policy: &Policy,
    state: &mut Schedule,
    home: Option<&Path>,
    event: &crate::session_hooks::SessionEnd,
) -> Result<WorkResults> {
    policy.validate()?;
    let key = session_key(state.host.context("host identity missing")?, event)?;
    if state
        .session_receipts
        .iter()
        .any(|receipt| receipt.key == key)
    {
        return Ok(outbox(state));
    }
    let index = match state.sessions.iter().position(|session| session.key == key) {
        Some(index) => index,
        None => {
            ensure!(
                state.sessions.len() < MAX_ACTIVE_SESSIONS
                    && state.sessions.len() + state.session_receipts.len() < MAX_SESSION_RECEIPTS,
                "host session ledger is full; receipts are never evicted"
            );
            ensure!(
                !state
                    .sessions
                    .iter()
                    .any(|s| s.workspace_snapshot.is_none()),
                "retry interrupted host session before admitting another"
            );
            ensure!(
                state.pending.len() < MAX_OUTBOX,
                "host delivery outbox is full"
            );
            let index = state.sessions.len();
            state.sessions.push(PendingSession {
                key,
                agent: event.agent,
                policy: policy.clone(),
                home: home.map(Path::to_path_buf),
                before: state.last_snapshot.clone(),
                workspace_snapshot: None,
                setup_snapshots: vec![],
                capture_complete: false,
                last_error: None,
            });
            // Leave room for IDs and failure state before accepting this event.
            ensure!(
                serde_json::to_vec(state)?.len() + 16 * 1024 <= MAX_SCHEDULE_BYTES,
                "host session ledger byte capacity exhausted"
            );
            save_schedule(repo, state)?;
            index
        }
    };
    if capture_host_session(repo, workspace, policy, state, index, home).is_err() {
        state.sessions[index].last_error = Some("session_capture_or_resume_failed".into());
        save_schedule(repo, state)?;
    }
    Ok(outbox(state))
}

/// Explicit local handler: fresh mTLS policy fetch precedes all new capture.
/// Repository exclusion is held only for this invocation, coexisting with daemon ticks.
/// The caller must treat `retry_required` as failure even when a report is returned.
pub fn session_end(
    repo_path: &Path,
    key: &KeySource,
    config: &HostConfig,
    workspace: &Path,
    event: &crate::session_hooks::SessionEnd,
) -> Result<HostSessionReport> {
    event.validate()?;
    ensure!(
        config.session_handler,
        "host session handler is not explicitly enabled"
    );
    config.validate_storage_paths(repo_path, workspace)?;
    let (mut host, _) = config.open()?;
    let workspace = config.validate_workspace(workspace)?;
    let repo = Repository::open_with_key_source(repo_path, key)?;
    let bindings = config.bindings(&repo, &workspace)?;
    let mut state = load_schedule(&repo, &workspace, host.identity().host)?;
    let event_key = session_key(host.identity().host, event)?;
    let mut invoked = false;
    let delivery = host.session_cycle(&repo, &bindings, |policy| {
        invoked = true;
        session_work(
            &repo,
            &workspace,
            policy,
            &mut state,
            config.setup_home.as_deref(),
            event,
        )
    });
    if !invoked {
        // Authentication/policy errors must not appear as accepted events.
        return Err(delivery
            .err()
            .context("session policy callback was not invoked")?);
    }
    let delivered = delivery.is_ok();
    if delivered {
        state.pending.clear();
        state.pending_alerts.clear();
        state.pending_evidence.clear();
        acknowledge_sessions(&mut state);
        save_schedule(&repo, &state)?;
    }
    let receipt = state.session_receipts.iter().find(|r| r.key == event_key);
    let pending = state.sessions.iter().find(|r| r.key == event_key);
    let captured = receipt.is_some() || pending.is_some_and(|s| s.capture_complete);
    let workspace_snapshot = receipt
        .map(|r| r.workspace_snapshot.clone())
        .or_else(|| pending.and_then(|s| s.workspace_snapshot.clone()));
    let error = if !captured {
        Some(
            pending
                .and_then(|s| s.last_error.clone())
                .unwrap_or_else(|| "session_not_accepted".into()),
        )
    } else if !delivered {
        Some("session_delivery_failed".into())
    } else {
        None
    };
    Ok(HostSessionReport {
        session_key: event_key,
        workspace_snapshot,
        capture_complete: captured,
        delivery_complete: delivered,
        retry_required: !captured || !delivered,
        error,
    })
}

pub fn run(
    repo_path: &Path,
    key: &KeySource,
    config: &HostConfig,
    workspace: &Path,
    agent: &str,
    once: bool,
) -> Result<()> {
    ensure!(
        ["claude-code", "cursor", "codex", "copilot", "kiro"].contains(&agent),
        "unsupported agent identifier"
    );
    config.validate_storage_paths(repo_path, workspace)?;
    let (mut host, _) = config.open()?;
    let workspace = config.validate_workspace(workspace)?;
    let mut failures = 0u32;
    loop {
        let result = (|| -> Result<_> {
            let repo = Repository::open_with_key_source(repo_path, key)?;
            let bindings = config.bindings(&repo, &workspace)?;
            let mut state = load_schedule(&repo, &workspace, host.identity().host)?;
            let report = host.cycle(&repo, &bindings, |policy| {
                let mut work = scheduled_work(
                    &repo,
                    &workspace,
                    agent,
                    policy,
                    &mut state,
                    config.setup_home.as_deref(),
                )?;
                scheduled_probes(&repo, policy, &mut state, agent, |snapshot| {
                    run_configured_probes(
                        &repo,
                        &workspace,
                        agent,
                        snapshot,
                        config.probe_config.as_deref(),
                    )
                })?;
                work.evidence = state.pending_evidence.clone();
                Ok(work)
            })?;
            state.pending.clear();
            state.pending_alerts.clear();
            state.pending_evidence.clear();
            acknowledge_sessions(&mut state);
            save_schedule(&repo, &state)?;
            Ok(
                serde_json::json!({"snapshots_reported":report.snapshots_reported,"evidence_reported":report.evidence_reported,"probes_not_run":report.probes_not_run,"setup_pending":state.pending_setup.is_some(),"setup_error":state.last_setup_error,"sessions_pending":state.sessions.len(),"session_errors":state.sessions.iter().filter(|s|s.last_error.is_some()).count(),"local_diagnostics":state.diagnostics.len()}),
            )
        })();
        match result {
            Ok(report) => {
                failures = 0;
                println!("{report}");
            }
            Err(error) if once => return Err(error),
            Err(_) => {
                failures = failures.saturating_add(1);
                eprintln!("{{\"event\":\"host_cycle_failed\",\"retry\":true}}");
            }
        }
        if once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(
            30u64
                .saturating_mul(2u64.saturating_pow(failures.min(7)))
                .min(3600),
        ));
    }
}

pub fn serve_mcp(
    repo_path: &Path,
    key: &KeySource,
    config: &HostConfig,
    workspace: &Path,
    input: impl std::io::BufRead,
    output: impl std::io::Write,
) -> Result<()> {
    let (mut host, consumed) = config.open()?;
    let workspace = config.validate_workspace(workspace)?;
    let mut requester = |repo: &Repository, work: &Path, args: &serde_json::Value| {
        let snapshot = args["snapshot"].as_str().context("missing snapshot")?;
        let file = args
            .get("file")
            .map(|v| v.as_str().context("file must be a string"))
            .transpose()?;
        Ok(serde_json::to_value(
            host.request_restore(repo, &consumed, snapshot, work, file)?,
        )?)
    };
    crate::mcp::serve_with_requester(
        repo_path,
        key,
        &workspace,
        input,
        output,
        Some(&mut requester),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_delivery_survives_restart_and_prevents_duplicate_capture() {
        let lab = tempfile::tempdir().unwrap();
        let work = lab.path().join("work");
        fs::create_dir(&work).unwrap();
        let work = work.canonicalize().unwrap();
        fs::write(work.join("file"), "original").unwrap();
        let path = lab.path().join("repo");
        let host = Uuid::new_v4();
        let repo = Repository::init(&path, "disposable-host-runtime-passphrase").unwrap();
        let mut state = load_schedule(&repo, &work, host).unwrap();
        let first =
            scheduled_work(&repo, &work, "codex", &Policy::default(), &mut state, None).unwrap();
        assert_eq!(first.snapshots.len(), 1);
        drop(repo);
        let repo = Repository::open(&path, "disposable-host-runtime-passphrase").unwrap();
        let mut state = load_schedule(&repo, &work, host).unwrap();
        fs::write(work.join("file"), "changed").unwrap();
        let retry =
            scheduled_work(&repo, &work, "codex", &Policy::default(), &mut state, None).unwrap();
        assert_eq!(first.snapshots, retry.snapshots);
        assert_eq!(repo.list().unwrap().len(), 1);
        assert!(load_schedule(&repo, &work, Uuid::new_v4()).is_err());
    }
    fn runtime_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Repository, Schedule) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("file"), b"fixture").unwrap();
        let home = root.join("home");
        let repo = Repository::init(&root.join("repo"), "runtime-fixture-passphrase").unwrap();
        let state = load_schedule(&repo, &workspace, Uuid::new_v4()).unwrap();
        (temp, workspace, home, repo, state)
    }

    #[test]
    fn setup_outage_returns_workspace_delivery_and_allows_next_due_capture() {
        let (_temp, workspace, missing_home, repo, mut state) = runtime_fixture();
        let first = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&missing_home),
        )
        .unwrap();
        assert_eq!(first.snapshots.len(), 1);
        assert!(state.pending_setup.is_some() && state.last_setup_error.is_some());
        assert_eq!(state.setup_failures, 1);
        let mut restarted = load_schedule(&repo, &workspace, state.host.unwrap()).unwrap();
        restarted.next_run = 0;
        restarted.setup_retry_after = now() + 3600;
        let next = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut restarted,
            Some(&missing_home),
        )
        .unwrap();
        assert_eq!(next.snapshots.len(), 2);
        assert_eq!(repo.list().unwrap().len(), 2);
        assert!(next.snapshots.contains(&first.snapshots[0]));
        assert!(restarted
            .diagnostics
            .iter()
            .any(|d| d.reason == "superseded_pending_setup"));
        // Delivery failure would leave both IDs durable, rather than losing the
        // successful workspace just because setup is still unavailable.
        let durable = load_schedule(&repo, &workspace, restarted.host.unwrap()).unwrap();
        assert_eq!(durable.pending, next.snapshots);
    }

    #[test]
    fn setup_scope_change_cancels_retry_without_scanning_new_home() {
        let (_temp, workspace, home, repo, mut state) = runtime_fixture();
        let first = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&home),
        )
        .unwrap();
        let new_home = home.with_file_name("other-home");
        fs::create_dir_all(new_home.join(".codex")).unwrap();
        fs::write(new_home.join(".codex/config.toml"), "model = 'fixture'\n").unwrap();
        state.setup_retry_after = now() + 3600;
        let retry = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&new_home),
        )
        .unwrap();
        assert_eq!(retry.snapshots, first.snapshots);
        assert!(state.pending_setup.is_none() && state.setup_binding.is_none());
        assert!(state
            .diagnostics
            .iter()
            .any(|d| d.reason == "setup_policy_or_home_changed"));
        assert_eq!(repo.list().unwrap().len(), 1);
    }

    #[test]
    fn filtered_setup_delivery_is_durable_and_not_duplicated() {
        let (_temp, workspace, home, repo, mut state) = runtime_fixture();
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(home.join(".codex/config.toml"), "model = 'fixture'\n").unwrap();
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        let first = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&home),
        )
        .unwrap();
        assert_eq!(first.snapshots.len(), 2);
        assert!(state.pending_setup.is_none());
        let setup = repo.manifest(&first.snapshots[1]).unwrap();
        assert_eq!(setup.agent.as_deref(), Some("codex"));
        assert_eq!(
            setup.setup.unwrap().agents,
            vec![bunker_discovery::AgentId::Codex]
        );
        assert!(setup.files.iter().all(|f| f.path.starts_with(".codex/")));
        let mut restarted = load_schedule(&repo, &workspace, state.host.unwrap()).unwrap();
        let retry = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut restarted,
            Some(&home),
        )
        .unwrap();
        assert_eq!(retry.snapshots, first.snapshots);
        assert_eq!(repo.list().unwrap().len(), 2);
    }

    #[test]
    fn full_delivery_outbox_defers_capture_explicitly_and_loses_nothing() {
        let (_temp, workspace, _home, repo, mut state) = runtime_fixture();
        state.pending = (0..MAX_OUTBOX).map(|id| format!("{id:064x}")).collect();
        let original = state.pending.clone();
        let result = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            None,
        )
        .unwrap();
        assert_eq!(result.snapshots, original);
        assert!(repo.list().unwrap().is_empty());
        assert!(state
            .diagnostics
            .iter()
            .any(|d| d.reason == "delivery_outbox_full_capture_deferred"));
        assert_eq!(
            load_schedule(&repo, &workspace, state.host.unwrap())
                .unwrap()
                .pending,
            original
        );
        // A successful delivery drains the outbox; the deferred due capture runs.
        state.pending.clear();
        let after = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            None,
        )
        .unwrap();
        assert_eq!(after.snapshots.len(), 1);
    }

    #[test]
    fn setup_completion_waits_for_outbox_capacity_without_republishing() {
        let (_temp, workspace, home, repo, mut state) = runtime_fixture();
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(home.join(".codex/config.toml"), "model = 'fixture'\n").unwrap();
        let workspace_snapshot = repo
            .snapshot(
                &workspace,
                &Policy::default(),
                Some("codex".into()),
                None,
                "fixture",
            )
            .unwrap();
        state.next_run = now() + 3600;
        state.pending_setup = Some(workspace_snapshot.id.clone());
        state.setup_binding = Some(SetupBinding {
            home: home.clone(),
            policy: Policy::default(),
            agent: bunker_discovery::AgentId::Codex,
        });
        state.pending = (0..MAX_OUTBOX).map(|id| format!("{id:064x}")).collect();
        let result = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&home),
        )
        .unwrap();
        assert_eq!(result.snapshots.len(), MAX_OUTBOX);
        assert!(state.pending_setup.is_some());
        let ids: std::collections::BTreeSet<_> =
            repo.list().unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(ids.len(), 2);
        state.pending.clear(); // Simulated successful delivery acknowledgment.
        state.setup_retry_after = 0;
        let delivered = scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&home),
        )
        .unwrap();
        assert_eq!(delivered.snapshots.len(), 1);
        assert_eq!(
            ids,
            repo.list().unwrap().into_iter().map(|m| m.id).collect()
        );
        assert!(state.pending_setup.is_none());
    }

    #[test]
    fn legacy_unbound_setup_request_is_cancelled_not_redirected() {
        let (_temp, workspace, home, repo, mut state) = runtime_fixture();
        state.next_run = now() + 3600;
        state.pending_setup = Some("a".repeat(64));
        scheduled_work(
            &repo,
            &workspace,
            "codex",
            &Policy::default(),
            &mut state,
            Some(&home),
        )
        .unwrap();
        assert!(state.pending_setup.is_none());
        assert!(repo.list().unwrap().is_empty());
        assert!(state
            .diagnostics
            .iter()
            .any(|d| d.reason == "setup_policy_or_home_changed"));
    }
    #[test]
    fn interrupted_capture_replays_durable_detection_once_with_original_threshold() {
        let (_temp, work, _home, repo, mut state) = runtime_fixture();
        let first =
            scheduled_work(&repo, &work, "codex", &Policy::default(), &mut state, None).unwrap();
        fs::remove_file(work.join("file")).unwrap();
        let after = repo
            .snapshot(
                &work,
                &Policy::default(),
                Some("codex".into()),
                None,
                "interruption-fixture",
            )
            .unwrap();
        state.last_snapshot = Some(after.id.clone());
        state.next_run = now() + 3600;
        state.pending.push(after.id.clone());
        state.pending_detection = Some(PendingDetection {
            before: Some(first.snapshots[0].clone()),
            after: after.id.clone(),
            threshold: 1,
        });
        save_schedule(&repo, &state).unwrap();
        let pins = maintenance_pins(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(pins.contains(&first.snapshots[0]) && pins.contains(&after.id));
        let path = repo.root().to_path_buf();
        let host = state.host.unwrap();
        drop(repo);
        let repo = Repository::open(&path, "runtime-fixture-passphrase").unwrap();
        let mut restarted = load_schedule(&repo, &work, host).unwrap();
        let result = scheduled_work(
            &repo,
            &work,
            "codex",
            &Policy::default(),
            &mut restarted,
            None,
        )
        .unwrap();
        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.alerts[0].count, 1);
        assert!(restarted.pending_detection.is_none());
        let mut again = load_schedule(&repo, &work, host).unwrap();
        let repeated =
            scheduled_work(&repo, &work, "codex", &Policy::default(), &mut again, None).unwrap();
        assert_eq!(repeated.alerts.len(), 1);
        assert_eq!(repeated.alerts[0].event_id, result.alerts[0].event_id);
        assert_eq!(repo.list().unwrap().len(), 2);
    }
    #[test]
    fn scheduled_probe_evidence_survives_restart_and_pins_snapshot_without_rerun() {
        let (_temp, work, _home, repo, mut state) = runtime_fixture();
        scheduled_work(&repo, &work, "codex", &Policy::default(), &mut state, None).unwrap();
        scheduled_probes(&repo, &Policy::default(), &mut state, "codex", |snapshot| {
            Ok(skipped_probe(
                snapshot,
                "codex",
                crate::host_service::ProbeSkip::NotConfigured,
            ))
        })
        .unwrap();
        let saved = state.pending_evidence[0].clone();
        let pins = maintenance_pins(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(pins.contains(&saved.snapshot));
        let mut again = load_schedule(&repo, &work, state.host.unwrap()).unwrap();
        scheduled_probes(&repo, &Policy::default(), &mut again, "codex", |_| {
            panic!("probe reran before due")
        })
        .unwrap();
        assert_eq!(again.pending_evidence.len(), 1);
        assert_eq!(again.pending_evidence[0].id, saved.id);
        again.next_probe = 0;
        scheduled_probes(&repo, &Policy::default(), &mut again, "codex", |_| {
            anyhow::bail!("fixture runtime unavailable")
        })
        .unwrap();
        assert_eq!(again.pending_evidence.len(), 2);
        assert_eq!(
            again.pending_evidence[1].agents[0].outcome.status(),
            "not_run"
        );
        let results =
            scheduled_work(&repo, &work, "codex", &Policy::default(), &mut again, None).unwrap();
        assert!(!results.snapshots.is_empty());
        assert_eq!(results.evidence.len(), 2);
        again.pending_evidence.resize(MAX_EVIDENCE_OUTBOX, saved);
        again.next_probe = 0;
        scheduled_probes(&repo, &Policy::default(), &mut again, "codex", |_| {
            panic!("full outbox must not execute")
        })
        .unwrap();
        assert_eq!(again.pending_evidence.len(), MAX_EVIDENCE_OUTBOX);
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use bunker_discovery::AgentId;

    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        Repository,
        Schedule,
        crate::session_hooks::SessionEnd,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("file"), "original").unwrap();
        let repo = Repository::init(&root.join("repo"), "session-runtime-fixture").unwrap();
        let mut state = load_schedule(&repo, &workspace, Uuid::new_v4()).unwrap();
        state.next_run = now() + 3600;
        let event = crate::session_hooks::SessionEnd {
            agent: AgentId::Codex,
            session_id: "session-1".into(),
        };
        (temp, workspace, repo, state, event)
    }

    fn acknowledged(repo: &Repository, state: &mut Schedule) {
        state.pending.clear();
        state.pending_alerts.clear();
        acknowledge_sessions(state);
        save_schedule(repo, state).unwrap();
    }

    #[test]
    fn session_replay_and_receipt_survive_restart_without_resetting_timer() {
        let (_temp, workspace, repo, mut state, event) = fixture();
        let timer = state.next_run;
        let first = session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event,
        )
        .unwrap();
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(state.next_run, timer);
        let path = repo.root().to_path_buf();
        let host = state.host.unwrap();
        drop(repo);
        let repo = Repository::open(&path, "session-runtime-fixture").unwrap();
        let mut state = load_schedule(&repo, &workspace, host).unwrap();
        fs::write(workspace.join("file"), "changed after session").unwrap();
        let retry = session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event,
        )
        .unwrap();
        assert_eq!(retry.snapshots, first.snapshots);
        acknowledged(&repo, &mut state);
        let mut state = load_schedule(&repo, &workspace, host).unwrap();
        let duplicate = session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event,
        )
        .unwrap();
        assert!(duplicate.snapshots.is_empty());
        assert_eq!(state.session_receipts.len(), 1);
        assert_eq!(repo.list().unwrap().len(), 1);
        assert_eq!(state.next_run, timer);
        assert!(maintenance_pins(&serde_json::to_vec(&state).unwrap())
            .unwrap()
            .contains(&first.snapshots[0]));
    }

    #[test]
    fn published_manifest_is_reconciled_after_crash_before_ledger_update() {
        let (_temp, workspace, repo, mut state, event) = fixture();
        let key = session_key(state.host.unwrap(), &event).unwrap();
        // A missing source leaves a durable intent but no invented success.
        let missing = workspace.join("missing");
        session_work(
            &repo,
            &missing,
            &Policy::default(),
            &mut state,
            None,
            &event,
        )
        .unwrap();
        assert!(state.sessions[0].workspace_snapshot.is_none());
        assert!(maintenance_pins(&serde_json::to_vec(&state).unwrap()).is_err());
        let snapshot = repo
            .snapshot(
                &workspace,
                &Policy::default(),
                Some("codex".into()),
                Some(key),
                "host-session-end",
            )
            .unwrap();
        fs::write(workspace.join("file"), "must not recapture").unwrap();
        let mut state = load_schedule(&repo, &workspace, state.host.unwrap()).unwrap();
        let work = session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event,
        )
        .unwrap();
        assert_eq!(work.snapshots, vec![snapshot.id]);
        assert_eq!(repo.list().unwrap().len(), 1);
        assert!(state.sessions[0].capture_complete);
    }

    #[test]
    fn setup_failure_delivers_workspace_then_same_id_retry_completes_filtered_setup() {
        let (temp, workspace, repo, mut state, event) = fixture();
        let home = temp.path().canonicalize().unwrap().join("home");
        let work = session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            Some(&home),
            &event,
        )
        .unwrap();
        assert_eq!(work.snapshots.len(), 1);
        assert!(!state.sessions[0].capture_complete);
        assert!(state.sessions[0].last_error.is_some());
        acknowledged(&repo, &mut state);
        assert!(state.session_receipts.is_empty());
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(home.join(".codex/config.toml"), "model = 'fixture'\n").unwrap();
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        let mut state = load_schedule(&repo, &workspace, state.host.unwrap()).unwrap();
        let mut different_policy = Policy::default();
        different_policy.exclusions.push("file".into());
        let rejected = session_work(
            &repo,
            &workspace,
            &different_policy,
            &mut state,
            Some(&home),
            &event,
        )
        .unwrap();
        assert!(rejected.snapshots.is_empty());
        assert!(!state.sessions[0].capture_complete);
        assert_eq!(repo.list().unwrap().len(), 1);
        let retry = session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            Some(&home),
            &event,
        )
        .unwrap();
        assert_eq!(retry.snapshots.len(), 1);
        let setup = repo.manifest(&retry.snapshots[0]).unwrap();
        assert_eq!(setup.setup.unwrap().agents, vec![AgentId::Codex]);
        assert_eq!(repo.list().unwrap().len(), 2);
        acknowledged(&repo, &mut state);
        let pins = maintenance_pins(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(pins.contains(&work.snapshots[0]) && pins.contains(&retry.snapshots[0]));
        assert_eq!(state.session_receipts[0].setup_snapshots, retry.snapshots);
    }

    #[test]
    fn session_queue_backpressure_never_evicts_receipts_or_publishes_unqueued_capture() {
        let (_temp, workspace, repo, mut state, event) = fixture();
        state.pending = (0..MAX_OUTBOX).map(|i| format!("{i:064x}")).collect();
        save_schedule(&repo, &state).unwrap();
        assert!(session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event
        )
        .is_err());
        assert!(state.sessions.is_empty());
        assert!(repo.list().unwrap().is_empty());
        assert_eq!(
            load_schedule(&repo, &workspace, state.host.unwrap())
                .unwrap()
                .pending,
            state.pending
        );
        state.pending.clear();
        state.session_receipts = (0..MAX_SESSION_RECEIPTS)
            .map(|i| SessionReceipt {
                key: format!("{i:064x}"),
                workspace_snapshot: "a".repeat(64),
                setup_snapshots: vec![],
            })
            .collect();
        save_schedule(&repo, &state).unwrap();
        assert!(session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event
        )
        .is_err());
        assert_eq!(state.session_receipts.len(), MAX_SESSION_RECEIPTS);
        assert!(repo.list().unwrap().is_empty());
    }

    #[test]
    fn session_capture_uses_existing_comparison_and_preserves_alert_identity_on_retry() {
        let (_temp, workspace, repo, mut state, mut event) = fixture();
        let policy = Policy {
            mass_delete_threshold: 1,
            ..Policy::default()
        };
        session_work(&repo, &workspace, &policy, &mut state, None, &event).unwrap();
        acknowledged(&repo, &mut state);
        fs::remove_file(workspace.join("file")).unwrap();
        event.session_id = "session-2".into();
        let work = session_work(&repo, &workspace, &policy, &mut state, None, &event).unwrap();
        assert_eq!(work.alerts.len(), 1);
        assert_eq!(work.alerts[0].count, 1);
        let mut state = load_schedule(&repo, &workspace, state.host.unwrap()).unwrap();
        let retry = session_work(&repo, &workspace, &policy, &mut state, None, &event).unwrap();
        assert_eq!(work.snapshots, retry.snapshots);
        assert_eq!(work.alerts[0].event_id, retry.alerts[0].event_id);
        assert_eq!(repo.list().unwrap().len(), 2);
    }

    #[test]
    fn invalid_ledger_is_rejected_by_maintenance_and_runtime_identically() {
        let (_temp, workspace, repo, mut state, event) = fixture();
        session_work(
            &repo,
            &workspace,
            &Policy::default(),
            &mut state,
            None,
            &event,
        )
        .unwrap();
        acknowledged(&repo, &mut state);
        state.session_receipts[0]
            .setup_snapshots
            .push("../invalid".into());
        let plaintext = serde_json::to_vec(&state).unwrap();
        assert!(maintenance_pins(&plaintext).is_err());
        repo.write_private_metadata(
            STATE,
            &repo.seal_metadata(DOMAIN, &plaintext).unwrap(),
            true,
        )
        .unwrap();
        assert!(load_schedule(&repo, &workspace, state.host.unwrap()).is_err());
    }

    #[test]
    fn authenticated_session_cycle_keeps_outbox_on_ambiguous_delivery_and_refetches_policy() {
        use crate::control_plane::{Method, Transport, TransportError};
        use crate::host_service::{HostClient, HostIdentity, HostService};
        use serde_json::{json, Value};
        struct Server {
            host: Uuid,
            fail: bool,
            enabled: bool,
            policy_reads: usize,
            snapshot_posts: Vec<Value>,
        }
        impl Transport for Server {
            fn request(
                &mut self,
                _method: Method,
                path: &str,
                body: Option<&Value>,
            ) -> std::result::Result<Value, TransportError> {
                if path.ends_with("/policies") {
                    self.policy_reads += 1;
                    return Ok(json!([{"id":Uuid::from_u128(9),"version":1,"body":{
                        "name":"Fixture","hostId":self.host,"intervalMinutes":5,
                        "endOfSession":self.enabled,"retentionDays":30,"exclusions":[],
                        "sizeCapBytes":10000000,"immutable":false,"drCopy":false,
                        "residency":"unrestricted","storage":"local","storageRef":"local",
                        "keyRef":"key","massDeleteThreshold":20,"missedBackupMinutes":10,
                        "restoreTestIntervalHours":24,"channels":["ui"]}}]));
                }
                if path.ends_with("/snapshots") {
                    self.snapshot_posts.push(body.unwrap().clone());
                    if self.fail {
                        return Err(TransportError::Ambiguous);
                    }
                    return Ok(json!({"id": body.unwrap()["id"]}));
                }
                panic!("unexpected host request");
            }
        }
        let (_temp, workspace, repo, mut state, event) = fixture();
        let identity = HostIdentity::new(Uuid::new_v4(), state.host.unwrap()).unwrap();
        let server = Server {
            host: identity.host,
            fail: true,
            enabled: true,
            policy_reads: 0,
            snapshot_posts: vec![],
        };
        let mut service = HostService::new(HostClient::new(server, identity));
        let bindings = LocalBindings::local_repository(&repo, "local", "key")
            .unwrap()
            .with_session_handler(true);
        assert!(service
            .session_cycle(&repo, &bindings, |policy| session_work(
                &repo, &workspace, policy, &mut state, None, &event
            ))
            .is_err());
        assert!(state.sessions[0].capture_complete);
        let mut state = load_schedule(&repo, &workspace, identity.host).unwrap();
        assert_eq!(state.pending.len(), 1);
        let original = repo.read_private_metadata(STATE, 1024 * 1024).unwrap();
        service.client.transport_mut().enabled = false;
        assert!(service
            .session_cycle(&repo, &bindings, |_| panic!("revoked policy executed"))
            .is_err());
        assert_eq!(
            repo.read_private_metadata(STATE, 1024 * 1024).unwrap(),
            original
        );
        let server = service.client.transport_mut();
        server.enabled = true;
        server.fail = false;
        let report = service
            .session_cycle(&repo, &bindings, |policy| {
                session_work(&repo, &workspace, policy, &mut state, None, &event)
            })
            .unwrap();
        assert_eq!(report.snapshots_reported, 1);
        let server = service.client.transport_mut();
        assert_eq!(server.policy_reads, 3);
        assert_eq!(server.snapshot_posts.len(), 2);
        assert_eq!(server.snapshot_posts[0], server.snapshot_posts[1]);
        assert_eq!(repo.list().unwrap().len(), 1);
        acknowledged(&repo, &mut state);
        assert_eq!(
            load_schedule(&repo, &workspace, identity.host)
                .unwrap()
                .session_receipts
                .len(),
            1
        );
    }

    #[test]
    fn unpublished_session_intent_does_not_block_periodic_capture_and_retry_rebinds_baseline() {
        let (_temp, workspace, repo, mut state, event) = fixture();
        let policy = Policy::default();
        session_work(
            &repo,
            &workspace.join("missing"),
            &policy,
            &mut state,
            None,
            &event,
        )
        .unwrap();
        assert!(state.sessions[0].workspace_snapshot.is_none());
        state.next_run = 0;
        let periodic =
            scheduled_work(&repo, &workspace, "codex", &policy, &mut state, None).unwrap();
        assert_eq!(periodic.snapshots.len(), 1);
        assert!(state.sessions[0].workspace_snapshot.is_none());
        let timer = state.next_run;
        session_work(&repo, &workspace, &policy, &mut state, None, &event).unwrap();
        assert_eq!(
            state.sessions[0].before.as_ref(),
            Some(&periodic.snapshots[0])
        );
        assert!(state.sessions[0].capture_complete);
        assert_eq!(state.next_run, timer);
        assert_eq!(repo.list().unwrap().len(), 2);
    }

    #[test]
    fn daemon_recovers_published_session_before_advancing_periodic_comparison() {
        let (_temp, workspace, repo, mut state, event) = fixture();
        let policy = Policy {
            mass_delete_threshold: 1,
            ..Policy::default()
        };
        session_work(
            &repo,
            &workspace.join("missing"),
            &policy,
            &mut state,
            None,
            &event,
        )
        .unwrap();
        let recovered = repo
            .snapshot(
                &workspace,
                &policy,
                Some("codex".into()),
                Some(session_key(state.host.unwrap(), &event).unwrap()),
                "host-session-end",
            )
            .unwrap();
        fs::remove_file(workspace.join("file")).unwrap();
        let mut state = load_schedule(&repo, &workspace, state.host.unwrap()).unwrap();
        state.next_run = 0;
        let periodic =
            scheduled_work(&repo, &workspace, "codex", &policy, &mut state, None).unwrap();
        assert_eq!(periodic.snapshots.len(), 2);
        assert_eq!(periodic.snapshots[0], recovered.id);
        assert_eq!(state.last_snapshot.as_ref(), Some(&periodic.snapshots[1]));
        assert_eq!(
            state.sessions[0].workspace_snapshot.as_ref(),
            Some(&recovered.id)
        );
        assert!(state.sessions[0].capture_complete);
        assert_eq!(periodic.alerts.len(), 1);
        assert_eq!(
            periodic.alerts[0].snapshot.as_ref(),
            Some(&periodic.snapshots[1])
        );
        assert_eq!(repo.list().unwrap().len(), 2);
    }
}
