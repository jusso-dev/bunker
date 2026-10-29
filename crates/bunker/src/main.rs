use anyhow::{Context, Result};
use bunker::{
    mcp,
    policy::Policy,
    repository::{KeySource, Repository},
    scheduler,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Encrypted backup and reviewed restore for AI coding workspaces"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".bunker-repository")]
    repo: PathBuf,
    #[arg(long, global = true)]
    policy: Option<PathBuf>,
    /// Explicit AWS KMS, Azure Key Vault or GCP KMS provider configuration.
    #[arg(long, global = true)]
    key_config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init,
    SnapshotSetup {
        #[arg(long)]
        home: PathBuf,
        #[arg(long)]
        session: Option<String>,
    },
    SessionEnd {
        #[arg(long)]
        agent: String,
        #[arg(long, required_unless_present = "host_config")]
        home: Option<PathBuf>,
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        workspace: Vec<PathBuf>,
        #[arg(long)]
        session_id: Option<String>,
    },
    SessionRun {
        #[arg(long)]
        agent: String,
        #[arg(long, required_unless_present = "host_config")]
        home: Option<PathBuf>,
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        workspace: Vec<PathBuf>,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
    },
    HookClaude {
        #[arg(long)]
        home: PathBuf,
        #[arg(long)]
        workspace: Vec<PathBuf>,
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        disable: bool,
        #[arg(long)]
        confirm: Option<String>,
    },
    Host {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        action: HostAction,
    },
    /// Operator-only cleanup of expired or decided requests. Never exposed by MCP.
    PruneRequests {
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    MaintenancePlan {
        #[arg(long)]
        output: PathBuf,
    },
    MaintenanceExecute {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        confirm: String,
    },
    Discover {
        #[arg(long)]
        workspace: Vec<PathBuf>,
        #[arg(long)]
        home: Option<PathBuf>,
    },
    Snapshot {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long, default_value = "manual")]
        trigger: String,
    },
    List,
    Diff {
        snapshot: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        file: Option<String>,
    },
    Restore {
        snapshot: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        confirm: Option<String>,
        /// Permit overwriting settings with unbound secret placeholders (local operator action).
        #[arg(long)]
        allow_rebind_overwrite: bool,
    },
    Verify {
        snapshot: String,
    },
    RestoreTest {
        snapshot: String,
        /// Source workspace boundary for trusted executable/configuration exclusions.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Protected operator-defined container/boot/MCP probes; never snapshot commands.
        #[arg(long, requires = "workspace")]
        probe_config: Option<PathBuf>,
    },
    /// Rewrap the SAME data key; stable remote chunk namespace is unchanged.
    #[command(visible_alias = "rotate-key")]
    RewrapPassphrase,
    /// Rewrap the same data key under an explicitly configured managed key.
    RewrapKey {
        #[arg(long)]
        new_key_config: PathBuf,
    },
    /// Export an encrypted recovery envelope; BUNKER_RECOVERY_KEY holds 64 hex digits.
    Escrow {
        #[arg(long)]
        output: PathBuf,
    },
    /// Unlock with an escrow envelope and replace the key wrapper with --key-config or BUNKER_PASSPHRASE.
    EscrowUnlock {
        #[arg(long)]
        input: PathBuf,
    },
    RestoreJournal {
        id: String,
    },
    RestoreRecover {
        id: String,
        #[arg(long)]
        confirm: Option<String>,
    },
    Request {
        id: String,
    },
    Approve {
        id: String,
        #[arg(long)]
        confirm: String,
    },
    Deny {
        id: String,
    },
    Replicate {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        snapshot: Option<String>,
        /// Independent immutable disaster-recovery backend with separate credentials.
        #[arg(long)]
        dr_storage: Option<PathBuf>,
        /// Required retention period for verified immutable versions.
        #[arg(long)]
        retain_days: Option<u32>,
        /// Durable external exact-version report, required for immutable replication.
        #[arg(long)]
        report: Option<PathBuf>,
        /// Private durable OAuth rotation and exact-ID evidence directory for Drive/OneDrive.
        #[arg(long)]
        consumer_state: Option<PathBuf>,
    },
    /// Re-export the encrypted local fallback after an external report-write failure.
    ProtectionReport {
        checkpoint: String,
        #[arg(long)]
        output: PathBuf,
    },
    ConsumerReport {
        checkpoint: String,
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        consumer_state: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Rebind uncertain OAuth state from the configured private environment reference.
    ConsumerRebind {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        consumer_state: PathBuf,
    },
    Recover {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        snapshot: Option<String>,
        /// Explicitly recover old single-hash, unindexed backups; inventory completeness is unproven.
        #[arg(long)]
        legacy_unindexed: bool,
        /// Recover remote ciphertext using a separately held escrow envelope.
        #[arg(long)]
        escrow: Option<PathBuf>,
        /// Saved immutable replication report; uses pinned versions, including after expiry.
        #[arg(long, conflicts_with = "legacy_unindexed")]
        protection_report: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["legacy_unindexed", "protection_report"])]
        consumer_report: Option<PathBuf>,
        #[arg(long)]
        consumer_state: Option<PathBuf>,
    },
    Daemon {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        host_config: Option<PathBuf>,
        /// Trusted container probe configuration for the standalone daemon.
        #[arg(long, conflicts_with = "host_config")]
        probe_config: Option<PathBuf>,
        #[arg(long, default_value = "codex")]
        agent: String,
    },
    Status,
    Mcp {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        host_config: Option<PathBuf>,
    },
    PolicyDefaults,
}
#[derive(Subcommand)]
enum HostAction {
    Enroll {
        #[arg(long, conflicts_with = "token_env")]
        token_file: Option<PathBuf>,
        /// Environment variable NAME containing a one-use token, never the token value.
        #[arg(long, conflicts_with = "token_file")]
        token_env: Option<String>,
    },
    RequestRestore {
        snapshot: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        file: Option<String>,
    },
    ReviewRestore {
        id: String,
    },
    ExecuteRestore {
        id: String,
    },
    Run {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, default_value = "codex")]
        agent: String,
        #[arg(long)]
        once: bool,
    },
}
fn print(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn recovery_key() -> Result<Zeroizing<[u8; 32]>> {
    let encoded = Zeroizing::new(std::env::var("BUNKER_RECOVERY_KEY")
        .context("set BUNKER_RECOVERY_KEY through your secret manager (32 random bytes encoded as 64 hex digits)")?);
    let mut key = Zeroizing::new([0; 32]);
    hex::decode_to_slice(encoded.as_str(), key.as_mut())
        .map_err(|_| anyhow::anyhow!("invalid BUNKER_RECOVERY_KEY encoding"))?;
    Ok(key)
}
fn read_escrow(path: &std::path::Path) -> Result<bunker_keys::Escrow> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8193)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 8192, "escrow envelope exceeds limit");
    Ok(serde_json::from_slice(&bytes)?)
}
fn external_report_destination(repo: &Repository, output: &std::path::Path) -> Result<()> {
    anyhow::ensure!(!output.try_exists()?, "report destination already exists");
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."))
        .canonicalize()?;
    anyhow::ensure!(
        !parent.starts_with(repo.root().canonicalize()?),
        "keep recovery reports outside the repository"
    );
    Ok(())
}
fn external_consumer_state(repository: &std::path::Path, state: &std::path::Path) -> Result<()> {
    fn resolve(path: &std::path::Path) -> Result<PathBuf> {
        if path.try_exists()? {
            return Ok(path.canonicalize()?);
        }
        let path = std::path::absolute(path)?;
        Ok(path
            .parent()
            .context("state/repository parent required")?
            .canonicalize()?
            .join(path.file_name().context("state/repository name required")?))
    }
    let repository = resolve(repository)?;
    let state = resolve(state)?;
    anyhow::ensure!(
        !state.starts_with(&repository) && !repository.starts_with(&state),
        "consumer private state must be disjoint from the repository"
    );
    Ok(())
}
fn write_review_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("review document destination exists or cannot be written"))?;
    cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?
        .into_std_file()
        .sync_all()?;
    Ok(())
}
fn parse_agent(value: &str) -> Result<bunker_discovery::AgentId> {
    let name = match value {
        "claude-code" => "claude_code",
        "copilot" => "github_copilot",
        name => name,
    };
    serde_json::from_value(serde_json::Value::String(name.into()))
        .context("unsupported agent identifier")
}
fn capture_session(
    repo: &Repository,
    home: &std::path::Path,
    workspaces: &[PathBuf],
    policy: &Policy,
    event: &bunker::session_hooks::SessionEnd,
) -> Result<serde_json::Value> {
    event.validate()?;
    let context = bunker_discovery::DiscoveryContext::new(
        bunker_discovery::Platform::current(),
        home.canonicalize()?,
        vec![],
    );
    let mut snapshots = vec![];
    let mut failed = 0usize;
    for workspace in workspaces {
        match repo.snapshot(
            workspace,
            policy,
            Some(event.agent.as_str().into()),
            Some(event.session_id.clone()),
            "session-end",
        ) {
            Ok(snapshot) => snapshots.push(snapshot.id),
            Err(_) => failed += 1,
        }
    }
    let setup = repo.snapshot_setup_for_session(&context, policy, event)?;
    repo.audit("session_end_captured", serde_json::json!({"workspace_snapshots":snapshots,"setup_snapshots":setup.iter().map(|m|&m.id).collect::<Vec<_>>(),"failed_scopes":failed}))?;
    anyhow::ensure!(failed == 0, "one or more configured workspace snapshots failed; successful setup/workspace snapshots were retained");
    Ok(
        serde_json::json!({"workspace_snapshots":snapshots,"setup_snapshots":setup.iter().map(|m|&m.id).collect::<Vec<_>>() }),
    )
}
#[derive(Debug)]
struct SessionExit(i32);
impl std::fmt::Display for SessionExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "session command exited with status {}", self.0)
    }
}
impl std::error::Error for SessionExit {}
fn run() -> Result<()> {
    let cli = Cli::parse();
    if let Command::ConsumerRebind {
        storage,
        consumer_state,
    } = &cli.command
    {
        let config = bunker::storage::StorageConfig::load(storage)?;
        external_consumer_state(&cli.repo, consumer_state)?;
        let reference = config
            .credential_env
            .get("refresh_token")
            .context("configured refresh token reference missing")?;
        let token = Zeroizing::new(std::env::var(reference).context(
            "replacement refresh credential unavailable in configured secret reference",
        )?);
        let state = bunker::consumer_state::ConsumerState::open_for_rebind(
            consumer_state,
            &config,
            &token,
        )?;
        state.rebind_refresh(&token)?;
        return print(serde_json::json!({"consumer_credential_rebound":true}));
    }
    if let Command::Host {
        config,
        action: HostAction::Enroll {
            token_file,
            token_env,
        },
    } = &cli.command
    {
        let config = bunker::host_runtime::HostConfig::load(config)?;
        let token = match token_file {
            Some(path) => bunker::control_plane::EnrollmentTokenSource::File(path.clone()),
            None => bunker::control_plane::EnrollmentTokenSource::Environment(
                token_env
                    .clone()
                    .unwrap_or_else(|| "BUNKER_ENROLLMENT_TOKEN".into()),
            ),
        };
        return print(config.enroll(&token)?);
    }
    if matches!(cli.command, Command::PolicyDefaults) {
        println!("# retention_days is enforced by explicit operator maintenance; scheduled agent/MCP probes require a trusted probe configuration.");
        println!("{}", toml::to_string_pretty(&Policy::default())?);
        return Ok(());
    }
    if matches!(cli.command, Command::Status) {
        return print(scheduler::status(&cli.repo)?);
    }
    if let Command::Discover { workspace, home } = &cli.command {
        let home = home
            .clone()
            .or_else(|| {
                std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                    .map(PathBuf::from)
            })
            .context("pass --home to locate user agent configuration")?;
        let context = bunker_discovery::DiscoveryContext::new(
            bunker_discovery::Platform::current(),
            home,
            workspace.clone(),
        );
        return print(bunker_discovery::discover(
            &context,
            &bunker_discovery::SafetyPolicy::default(),
        )?);
    }
    let key_source = if let Command::Recover {
        escrow: Some(path), ..
    } = &cli.command
    {
        KeySource::Escrow {
            envelope: read_escrow(path)?,
            recovery_key: recovery_key()?,
        }
    } else {
        match &cli.key_config {
            Some(path) => KeySource::managed_config(path)?,
            None => {
                KeySource::Passphrase(Zeroizing::new(std::env::var("BUNKER_PASSPHRASE").context(
                    "set BUNKER_PASSPHRASE through your secret manager or pass --key-config",
                )?))
            }
        }
    };
    if let Command::EscrowUnlock { input } = &cli.command {
        let escrow = read_escrow(input)?;
        let repo = Repository::open_with_escrow(&cli.repo, &escrow, &*recovery_key()?)?;
        repo.rewrap_key(&key_source)?;
        return print(serde_json::json!({"escrow_recovered":true,"data_key_changed":false}));
    }
    if matches!(cli.command, Command::Init) {
        Repository::init_with_key_source(&cli.repo, &key_source)?;
        return print(serde_json::json!({"initialized":true,"key_format":2}));
    }
    if let Command::Recover {
        storage,
        namespace,
        snapshot,
        legacy_unindexed,
        protection_report,
        consumer_report,
        consumer_state,
        ..
    } = &cli.command
    {
        let config = bunker::storage::StorageConfig::load(storage)?;
        if let Some(path) = consumer_report {
            use std::{io::Read, sync::Arc};
            let state_path = consumer_state
                .as_ref()
                .context("consumer recovery requires --consumer-state")?;
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take((bunker::consumer_storage::MAX_EVIDENCE + 4097) as u64)
                .read_to_end(&mut bytes)?;
            let report = bunker::consumer_replication::ConsumerReport::from_slice(&bytes)?;
            anyhow::ensure!(
                report.namespace == *namespace,
                "consumer report locator mismatch"
            );
            external_consumer_state(&cli.repo, state_path)?;
            let state = Arc::new(bunker::consumer_state::ConsumerState::open(
                state_path, &config,
            )?);
            let backend = bunker::consumer_storage::ConsumerBackend::from_evidence(
                &config,
                &report.evidence,
                true,
                state.clone(),
                state.clone(),
            )?;
            let count = tokio::runtime::Runtime::new()?.block_on(bunker::checkpoint::recover(
                &backend,
                namespace,
                &cli.repo,
                &key_source,
                snapshot.as_deref(),
            ))?;
            return print(
                serde_json::json!({"verified_snapshots":count,"inventory_completeness":"authenticated_inventory_and_saved_object_ids","immutable":false,"escrow_unlock_required":matches!(key_source,KeySource::Escrow{..})}),
            );
        }
        anyhow::ensure!(
            consumer_state.is_none(),
            "--consumer-state requires --consumer-report during recovery"
        );
        if let Some(path) = protection_report {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() <= 64 * 1024 * 1024,
                "protected report exceeds limit"
            );
            let report: bunker::protected_replication::ProtectedReport =
                serde_json::from_slice(&bytes)?;
            report.validate()?;
            anyhow::ensure!(
                report.namespace == *namespace,
                "protected report locator mismatch"
            );
            let backend = report
                .backends
                .iter()
                .find_map(|evidence| {
                    bunker::protected_storage::ProtectedBackend::for_recovery(&config, evidence)
                        .ok()
                })
                .context("no saved evidence matches configured protected backend")?;
            let count = tokio::runtime::Runtime::new()?.block_on(bunker::checkpoint::recover(
                &backend,
                namespace,
                &cli.repo,
                &key_source,
                snapshot.as_deref(),
            ))?;
            return print(
                serde_json::json!({"verified_snapshots":count,"inventory_completeness":"authenticated_inventory_and_saved_versions","current_retention_verified":false,"escrow_unlock_required":matches!(key_source,KeySource::Escrow{..})}),
            );
        }
        let operator = config.operator()?;
        let count = tokio::runtime::Runtime::new()?.block_on(async {
            if *legacy_unindexed {
                bunker::storage::recover_legacy_with_key_source(
                    &operator,
                    namespace,
                    &cli.repo,
                    &key_source,
                    snapshot.as_deref(),
                )
                .await
            } else {
                bunker::checkpoint::recover(
                    &operator,
                    namespace,
                    &cli.repo,
                    &key_source,
                    snapshot.as_deref(),
                )
                .await
            }
        })?;
        return print(
            serde_json::json!({"verified_snapshots":count,"inventory_completeness":if *legacy_unindexed {"unproven_legacy_listing"} else {"authenticated_inventory_pinned_by_saved_locator"},"selected_snapshot":snapshot,"escrow_unlock_required":matches!(key_source,KeySource::Escrow{..})}),
        );
    }
    if let Command::Host {
        config,
        action:
            HostAction::Run {
                workspace,
                agent,
                once,
            },
    } = &cli.command
    {
        return bunker::host_runtime::run(
            &cli.repo,
            &key_source,
            &bunker::host_runtime::HostConfig::load(config)?,
            workspace,
            agent,
            *once,
        );
    }
    if let Command::Daemon {
        workspace,
        once,
        host_config,
        probe_config,
        agent,
    } = &cli.command
    {
        if let Some(config) = host_config {
            return bunker::host_runtime::run(
                &cli.repo,
                &key_source,
                &bunker::host_runtime::HostConfig::load(config)?,
                workspace,
                agent,
                *once,
            );
        }
        return scheduler::daemon_with_probes(
            &cli.repo,
            &key_source,
            workspace,
            cli.policy.as_deref(),
            *once,
            probe_config.as_deref(),
        );
    }
    if let Command::Mcp {
        workspace,
        host_config,
    } = &cli.command
    {
        if let Some(config) = host_config {
            return bunker::host_runtime::serve_mcp(
                &cli.repo,
                &key_source,
                &bunker::host_runtime::HostConfig::load(config)?,
                workspace,
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            );
        }
        return mcp::serve_with_key_source(
            &cli.repo,
            &key_source,
            workspace,
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        );
    }
    if let Command::SessionRun {
        agent,
        home,
        host_config,
        workspace,
        session_id,
        command,
    } = &cli.command
    {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let event = bunker::session_hooks::SessionEnd {
            agent: parse_agent(agent)?,
            session_id: session_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        };
        event.validate()?;
        let host_config = host_config
            .as_ref()
            .map(|p| bunker::host_runtime::HostConfig::load(p))
            .transpose()?;
        if host_config.is_some() {
            anyhow::ensure!(workspace.len() == 1 && cli.policy.is_none(), "host sessions require exactly one --workspace; policy and setup home come from authenticated host configuration");
            anyhow::ensure!(session_id.is_some(), "host session-run requires --session-id so pending capture/delivery can be retried with the same event");
        }
        let policy = Policy::load(cli.policy.as_deref())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal_flag = Arc::clone(&cancelled);
        ctrlc::set_handler(move || signal_flag.store(true, Ordering::SeqCst))?;
        let mut process =
            std::process::Command::new(command.first().context("session executable required")?);
        process.args(&command[1..]);
        let outcome = bunker::session_hooks::run_session(&mut process, &cancelled, || {
            if let Some(config) = &host_config {
                let report = bunker::host_runtime::session_end(
                    &cli.repo,
                    &key_source,
                    config,
                    &workspace[0],
                    &event,
                )?;
                return Ok((serde_json::to_value(&report)?, report.retry_required));
            }
            let repo = Repository::open_with_key_source(&cli.repo, &key_source)?;
            Ok((
                capture_session(
                    &repo,
                    home.as_deref()
                        .context("standalone session requires --home")?,
                    workspace,
                    &policy,
                    &event,
                )?,
                false,
            ))
        })?;
        use bunker::session_hooks::ProcessEnd;
        let exit = match outcome.process {
            ProcessEnd::Exited(code) => code,
            ProcessEnd::Signaled(signal) => 128 + signal,
            ProcessEnd::Cancelled => 130,
            ProcessEnd::SpawnFailed | ProcessEnd::WaitFailed => 1,
        };
        let snapshot_result = match outcome.snapshot {
            Ok((snapshot, retry)) => print(snapshot).and_then(|()| {
                anyhow::ensure!(
                    !retry,
                    "host session capture or delivery remains pending; retry the same session ID"
                );
                Ok(())
            }),
            Err(error) => {
                eprintln!("Session backup failed: {error:#}");
                Err(error)
            }
        };
        if exit != 0 {
            return Err(SessionExit(exit).into());
        }
        return snapshot_result;
    }
    if let Command::SessionEnd {
        agent,
        workspace,
        session_id,
        host_config: Some(path),
        ..
    } = &cli.command
    {
        anyhow::ensure!(
            workspace.len() == 1 && cli.policy.is_none(),
            "host sessions require exactly one --workspace and no local --policy"
        );
        let agent = parse_agent(agent)?;
        let event = if let Some(session_id) = session_id {
            bunker::session_hooks::SessionEnd {
                agent,
                session_id: session_id.clone(),
            }
        } else {
            anyhow::ensure!(
                agent == bunker_discovery::AgentId::ClaudeCode,
                "non-Claude native events require an explicit --session-id or session-run wrapper"
            );
            bunker::session_hooks::SessionEnd::from_claude_input(std::io::stdin().lock())?
        };
        let report = bunker::host_runtime::session_end(
            &cli.repo,
            &key_source,
            &bunker::host_runtime::HostConfig::load(path)?,
            &workspace[0],
            &event,
        )?;
        print(&report)?;
        anyhow::ensure!(
            !report.retry_required,
            "host session capture or delivery remains pending; retry the same session ID"
        );
        return Ok(());
    }
    let repo = Repository::open_with_key_source(&cli.repo, &key_source)?;
    match cli.command {
        Command::Host { config, action } => {
            let config = bunker::host_runtime::HostConfig::load(&config)?;
            let (mut host, consumed) = config.open()?;
            match action {
                HostAction::RequestRestore {
                    snapshot,
                    workspace,
                    file,
                } => {
                    let workspace = config.validate_workspace(&workspace)?;
                    let request = host.request_restore(
                        &repo,
                        &consumed,
                        &snapshot,
                        &workspace,
                        file.as_deref(),
                    )?;
                    print(host.local_restore_preview(&repo, &request.local_request_id)?)?;
                    print(request)
                }
                HostAction::ReviewRestore { id } => print(host.local_restore_preview(&repo, &id)?),
                HostAction::ExecuteRestore { id } => {
                    host.execute_restore_once(&repo, &consumed, &id)?;
                    print(serde_json::json!({"restored_once":true}))
                }
                HostAction::Enroll { .. } | HostAction::Run { .. } => unreachable!(),
            }
        }
        Command::PruneRequests { limit } => {
            print(serde_json::json!({"pruned_requests":repo.prune_requests(limit)?}))
        }
        Command::SnapshotSetup { home, session } => {
            let context = bunker_discovery::DiscoveryContext::new(
                bunker_discovery::Platform::current(),
                home.canonicalize()?,
                vec![],
            );
            print(repo.snapshot_setup(
                &context,
                &Policy::load(cli.policy.as_deref())?,
                session,
                "manual-setup",
            )?)
        }
        Command::SessionEnd {
            agent,
            home,
            workspace,
            session_id,
            host_config: _,
        } => {
            let agent = parse_agent(&agent)?;
            let event = if let Some(session_id) = session_id {
                bunker::session_hooks::SessionEnd { agent, session_id }
            } else {
                anyhow::ensure!(agent == bunker_discovery::AgentId::ClaudeCode, "non-Claude native events require an explicit --session-id or session-run wrapper");
                bunker::session_hooks::SessionEnd::from_claude_input(std::io::stdin().lock())?
            };
            print(capture_session(
                &repo,
                home.as_deref()
                    .context("standalone session requires --home")?,
                &workspace,
                &Policy::load(cli.policy.as_deref())?,
                &event,
            )?)
        }
        Command::HookClaude {
            home,
            workspace,
            host_config,
            disable,
            confirm,
        } => {
            let invocation = bunker::session_hooks::HookInvocation {
                executable: std::env::current_exe()?.canonicalize()?,
                repository: cli.repo.canonicalize()?,
                home: home.canonicalize()?,
                workspaces: workspace
                    .iter()
                    .map(|p| p.canonicalize())
                    .collect::<std::io::Result<Vec<_>>>()?,
                policy: cli.policy.as_ref().map(|p| p.canonicalize()).transpose()?,
                key_config: cli
                    .key_config
                    .as_ref()
                    .map(|p| p.canonicalize())
                    .transpose()?,
            };
            let plan = if let Some(config) = host_config {
                anyhow::ensure!(
                    workspace.len() == 1 && cli.policy.is_none(),
                    "host hook requires exactly one --workspace and no local --policy"
                );
                bunker::session_hooks::plan_claude_host_hook(
                    &bunker::session_hooks::HostHookInvocation {
                        executable: invocation.executable,
                        repository: invocation.repository,
                        home: invocation.home,
                        key_config: invocation.key_config,
                        host_config: config.canonicalize()?,
                        workspace: invocation.workspaces[0].clone(),
                    },
                    !disable,
                )?
            } else {
                bunker::session_hooks::plan_claude_hook(&invocation, !disable)?
            };
            print(
                serde_json::json!({"destination":plan.destination,"enable":plan.enable,"changed":plan.changed,"handler":plan.handler,"confirmation":plan.confirmation}),
            )?;
            if let Some(confirmation) = confirm {
                bunker::session_hooks::apply_claude_hook(&plan, &confirmation)?;
            }
            Ok(())
        }
        Command::MaintenancePlan { output } => {
            let plan = repo.maintenance_plan(&Policy::load(cli.policy.as_deref())?)?;
            write_review_file(&output, &serde_json::to_vec_pretty(&plan)?)?;
            print(plan)
        }
        Command::MaintenanceExecute { plan, confirm } => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(plan)?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(
                bytes.len() <= 64 * 1024 * 1024,
                "maintenance plan exceeds limit"
            );
            let plan: bunker::repository::MaintenancePlan = serde_json::from_slice(&bytes)?;
            let policy = Policy::load(cli.policy.as_deref())?;
            anyhow::ensure!(
                plan.retention_days == policy.retention_days,
                "retention policy changed; obtain a new plan"
            );
            print(repo.maintenance_execute(&plan, &confirm)?)
        }
        Command::RestoreRecover { id, confirm } => {
            let plan = repo.plan_recovery(&id)?;
            print(&plan)?;
            if let Some(confirmation) = confirm {
                print(repo.recover_transaction(&id, &confirmation)?)?;
            }
            Ok(())
        }
        Command::Snapshot {
            workspace,
            agent,
            session,
            trigger,
        } => print(repo.snapshot(
            &workspace,
            &Policy::load(cli.policy.as_deref())?,
            agent,
            session,
            &trigger,
        )?),
        Command::List => print(repo.list()?),
        Command::Diff {
            snapshot,
            workspace,
            file,
        } => print(repo.plan(&snapshot, &workspace, file.as_deref())?),
        Command::Restore {
            snapshot,
            workspace,
            file,
            confirm,
            allow_rebind_overwrite,
        } => {
            let plan = repo.plan(&snapshot, &workspace, file.as_deref())?;
            print(&plan)?;
            match confirm {
                Some(token) => {
                    repo.restore_with_options(
                        &snapshot,
                        &workspace,
                        file.as_deref(),
                        &token,
                        allow_rebind_overwrite,
                    )?;
                    print(serde_json::json!({"restored":true}))
                }
                None => {
                    eprintln!("Review this diff, then repeat with --confirm <confirmation>.");
                    Ok(())
                }
            }
        }
        Command::Verify { snapshot } => {
            let m = repo.verify(&snapshot)?;
            print(serde_json::json!({"verified":true,"snapshot":snapshot,"files":m.files.len()}))
        }
        Command::RestoreTest {
            snapshot,
            probe_config,
            workspace,
        } => {
            if let Some(path) = probe_config {
                let workspace = workspace
                    .context("--probe-config requires the source --workspace boundary")?
                    .canonicalize()?;
                let config = bunker::restore_probes::TrustedProbeConfig::load(&path)?;
                let manifest = repo.manifest(&snapshot)?;
                for trusted in [&path, &config.docker_executable, &config.docker_config] {
                    let resolved = trusted.canonicalize()?;
                    anyhow::ensure!(
                        !resolved.starts_with(repo.root())
                            && !resolved.starts_with(&workspace)
                            && manifest
                                .setup
                                .as_ref()
                                .is_none_or(|scope| !resolved.starts_with(&scope.source_root)),
                        "trusted probe runtime/configuration overlaps captured data"
                    );
                }
                let mut executor = bunker::restore_probes::DockerExecutor::new(&config)?;
                let evidence = bunker::restore_probes::run_restore_probes(
                    &repo,
                    &snapshot,
                    &config,
                    &mut executor,
                )?;
                repo.audit("restore_probe_evidence", serde_json::to_value(&evidence)?)?;
                return print(evidence);
            }
            let sandbox = tempfile::tempdir()?;
            let plan = repo.plan(&snapshot, sandbox.path(), None)?;
            repo.restore(&snapshot, sandbox.path(), None, &plan.confirmation)?;
            let report = serde_json::json!({"snapshot":snapshot,"file_integrity":"passed","agent_boot":"not_run","mcp_connectivity":"not_run","sandbox_removed_on_exit":true});
            repo.audit("restore_test", report.clone())?;
            print(report)
        }
        Command::RewrapPassphrase => {
            let new = Zeroizing::new(
                std::env::var("BUNKER_NEW_PASSPHRASE")
                    .context("set BUNKER_NEW_PASSPHRASE through your secret manager")?,
            );
            repo.rewrap_passphrase(&new)?;
            print(
                serde_json::json!({"passphrase_rewrapped":true,"data_key_changed":false,"replication_namespace_changed":false}),
            )
        }
        Command::RewrapKey { new_key_config } => {
            repo.rewrap_key(&KeySource::managed_config(&new_key_config)?)?;
            print(serde_json::json!({"key_rewrapped":true,"data_key_changed":false}))
        }
        Command::Escrow { output } => {
            repo.export_escrow_to(&output, &*recovery_key()?)?;
            print(serde_json::json!({"escrow_exported":true,"repository_id":repo.identity()}))
        }
        Command::RestoreJournal { id } => print(repo.restore_journal(&id)?),
        Command::Request { id } => print(repo.request(&id)?),
        Command::Approve { id, confirm } => {
            print(repo.decide_request(&id, true, Some(&confirm))?)
        }
        Command::Deny { id } => print(repo.decide_request(&id, false, None)?),
        Command::ProtectionReport { checkpoint, output } => {
            external_report_destination(&repo, &output)?;
            let report =
                bunker::protected_replication::ProtectedReport::load_local(&repo, &checkpoint)?;
            write_review_file(&output, &serde_json::to_vec(&report)?)?;
            print(serde_json::json!({"report_saved":true,"namespace":report.namespace}))
        }
        Command::ConsumerReport {
            checkpoint,
            storage,
            consumer_state,
            output,
        } => {
            external_report_destination(&repo, &output)?;
            let config = bunker::storage::StorageConfig::load(&storage)?;
            external_consumer_state(repo.root(), &consumer_state)?;
            let state = bunker::consumer_state::ConsumerState::open(&consumer_state, &config)?;
            let report = state.load_report(&checkpoint)?;
            write_review_file(&output, &report.to_vec()?)?;
            print(serde_json::json!({"report_saved":true,"namespace":report.namespace}))
        }
        Command::Replicate {
            storage,
            snapshot,
            dr_storage,
            retain_days,
            report,
            consumer_state,
        } => {
            let config = bunker::storage::StorageConfig::load(&storage)?;
            if matches!(config.service.as_str(), "gdrive" | "onedrive") {
                use std::sync::Arc;
                anyhow::ensure!(
                    dr_storage.is_none() && retain_days.is_none() && !config.immutable,
                    "consumer providers cannot enforce immutable retention or protected DR"
                );
                let output = report.context("consumer replication requires --report")?;
                external_report_destination(&repo, &output)?;
                let path =
                    consumer_state.context("consumer replication requires --consumer-state")?;
                external_consumer_state(repo.root(), &path)?;
                let state = Arc::new(bunker::consumer_state::ConsumerState::open(&path, &config)?);
                anyhow::ensure!(
                    !state.directory().starts_with(repo.root()),
                    "consumer credentials must remain outside the repository"
                );
                let backend = match state.evidence()? {
                    Some(evidence) => bunker::consumer_storage::ConsumerBackend::from_evidence(
                        &config,
                        &evidence,
                        false,
                        state.clone(),
                        state.clone(),
                    )?,
                    None => bunker::consumer_storage::ConsumerBackend::new(
                        &config,
                        state.clone(),
                        state.clone(),
                    )?,
                };
                let report = tokio::runtime::Runtime::new()?.block_on(
                    bunker::consumer_replication::replicate(
                        &repo,
                        &backend,
                        &state,
                        snapshot.as_deref(),
                    ),
                )?;
                write_review_file(&output, &report.to_vec()?)?;
                return print(
                    serde_json::json!({"namespace":report.namespace,"sequence":report.sequence,"report_saved":true,"immutable":false}),
                );
            }
            anyhow::ensure!(
                consumer_state.is_none(),
                "consumer state is only supported for Drive/OneDrive"
            );
            if config.immutable {
                let days = retain_days.context("immutable replication requires --retain-days")?;
                anyhow::ensure!((1..=36500).contains(&days), "retain-days must be 1..36500");
                let output = report
                    .context("immutable replication requires --report outside the repository")?;
                external_report_destination(&repo, &output)?;
                let until = chrono::DateTime::from_timestamp(bunker::repository::now() as i64, 0)
                    .context("invalid clock")?
                    .checked_add_signed(chrono::Duration::days(i64::from(days)))
                    .context("retention deadline overflow")?;
                let primary = bunker::protected_storage::ProtectedBackend::new(&config, until)?;
                let secondary = dr_storage
                    .as_ref()
                    .map(|path| -> Result<_> {
                        bunker::protected_storage::ProtectedBackend::new(
                            &bunker::storage::StorageConfig::load(path)?,
                            until,
                        )
                    })
                    .transpose()?;
                let report = tokio::runtime::Runtime::new()?.block_on(
                    bunker::protected_replication::replicate(
                        &repo,
                        &primary,
                        secondary.as_ref(),
                        snapshot.as_deref(),
                    ),
                )?;
                let bytes = serde_json::to_vec(&report)?;
                anyhow::ensure!(
                    bytes.len() <= 64 * 1024 * 1024,
                    "protected report exceeds limit"
                );
                write_review_file(&output, &bytes)?;
                return print(
                    serde_json::json!({"namespace":report.namespace,"sequence":report.sequence,"objects_per_backend":report.objects_per_backend,"protected_backends":report.backends.len(),"report_saved":true,"retain_until":until}),
                );
            }
            anyhow::ensure!(
                dr_storage.is_none() && retain_days.is_none() && report.is_none(),
                "protected options require immutable storage configuration"
            );
            let operator = config.operator()?;
            let report = tokio::runtime::Runtime::new()?.block_on(
                bunker::checkpoint::replicate(&repo, &operator, snapshot.as_deref()),
            )?;
            print(report)
        }
        Command::Init
        | Command::SessionRun { .. }
        | Command::ConsumerRebind { .. }
        | Command::EscrowUnlock { .. }
        | Command::Status
        | Command::PolicyDefaults
        | Command::Recover { .. }
        | Command::Discover { .. }
        | Command::Daemon { .. }
        | Command::Mcp { .. } => unreachable!(),
    }
}
fn main() {
    if let Err(error) = run() {
        if let Some(exit) = error.downcast_ref::<SessionExit>() {
            std::process::exit(exit.0);
        }
        eprintln!(
            "{}",
            serde_json::json!({"level":"error","message":error.to_string()})
        );
        std::process::exit(1);
    }
}
