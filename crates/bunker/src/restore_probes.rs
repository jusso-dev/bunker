//! Trusted, operator-provisioned restore probes. Snapshot content is data, never a command source.
//! The scheduler owns cadence; this module owns one bounded disposable probe attempt.
use crate::{
    host_service::{
        AgentProbe, EvidenceSandbox, McpProbe, ProbeFailure, ProbeOutcome, ProbeSkip,
        RestoreEvidence,
    },
    repository::{safe_path, Repository},
};
use anyhow::{ensure, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const MAX_CONFIG: u64 = 64 * 1024;
const MAX_FILES: usize = 1000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROBES: usize = 16;
const PROTOCOL: &str = "2024-11-05";
const REQUEST_ID: &str = "bunker-restore-probe";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCommand {
    /// An absolute executable *inside the pinned image*, never a captured workspace path.
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub requires_network: bool,
    #[serde(default)]
    pub requires_credentials: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedAgentProbe {
    pub agent: String,
    pub command: TrustedCommand,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMcpProbe {
    pub name: String,
    pub command: TrustedCommand,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProbeConfig {
    /// Absolute path to a trusted Docker CLI. Never resolved from ambient PATH.
    pub docker_executable: PathBuf,
    /// Explicit context is mandatory, including on a machine with a default context.
    pub docker_context: String,
    /// Explicit operator-provisioned Docker transport configuration. Never mounted in containers.
    pub docker_config: PathBuf,
    /// Registry/repository@sha256:<64 lowercase hex>; pre-pulled by the operator.
    pub image: String,
    pub timeout_seconds: u64,
    pub output_limit_bytes: usize,
    pub agents: Vec<TrustedAgentProbe>,
    #[serde(default)]
    pub mcps: Vec<TrustedMcpProbe>,
}
impl TrustedProbeConfig {
    /// Only load from an operator-provisioned path outside the repository/captured workspace.
    /// Unix owner/root, no symlinks, no group/world write; unsupported platforms fail closed.
    pub fn load(path: &Path) -> Result<Self> {
        protected_path(path, false)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "probe configuration must be a regular file"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_CONFIG + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_CONFIG,
            "probe configuration exceeds limit"
        );
        let config: Self =
            serde_json::from_slice(&bytes).context("invalid trusted probe configuration")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.docker_executable.is_absolute() && self.docker_config.is_absolute(),
            "Docker paths must be absolute"
        );
        ensure!(
            label(&self.docker_context, 64),
            "explicit Docker context required"
        );
        let (repository, digest) = self
            .image
            .rsplit_once("@sha256:")
            .context("image must be digest pinned")?;
        ensure!(
            !repository.is_empty()
                && repository.len() <= 200
                && !repository.starts_with('-')
                && repository
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid pinned image"
        );
        ensure!(
            (1..=30).contains(&self.timeout_seconds)
                && (256..=65536).contains(&self.output_limit_bytes),
            "probe limits out of range"
        );
        ensure!(
            (1..=5).contains(&self.agents.len())
                && self.agents.len() + self.mcps.len() <= MAX_PROBES,
            "probe count exceeds limit"
        );
        let mut names = std::collections::HashSet::new();
        for probe in &self.agents {
            ensure!(
                ["claude-code", "cursor", "codex", "copilot", "kiro"]
                    .contains(&probe.agent.as_str())
                    && names.insert(probe.agent.as_str()),
                "invalid or duplicate agent"
            );
            validate_command(&probe.command)?;
        }
        names.clear();
        for probe in &self.mcps {
            ensure!(
                label(&probe.name, 100) && names.insert(probe.name.as_str()),
                "invalid or duplicate MCP label"
            );
            validate_command(&probe.command)?;
        }
        Ok(())
    }
}
fn label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" _@.()+-".contains(&b))
}
fn validate_command(command: &TrustedCommand) -> Result<()> {
    let path = Path::new(&command.executable);
    ensure!(
        path.is_absolute()
            && command.executable.len() <= 512
            && !command.executable.contains('\0')
            && !command.executable.contains(".."),
        "invalid image executable"
    );
    ensure!(
        !path.starts_with("/restore")
            && !path.starts_with("/tmp")
            && !path.starts_with("/proc")
            && !path.starts_with("/dev"),
        "executable must come from trusted image"
    );
    ensure!(
        command.args.len() <= 32
            && command
                .args
                .iter()
                .all(|a| a.len() <= 2048 && !a.contains('\0'))
            && command.args.iter().map(String::len).sum::<usize>() <= 8192,
        "command arguments exceed limit"
    );
    Ok(())
}
#[cfg(unix)]
fn protected_path(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(path.is_absolute(), "protected path must be absolute");
    for (index, component) in path.ancestors().enumerate() {
        let meta = fs::symlink_metadata(component)?;
        ensure!(
            !meta.file_type().is_symlink(),
            "protected path must not contain symlinks"
        );
        ensure!(
            meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() },
            "protected path has untrusted owner"
        );
        // A root-owned sticky ancestor such as /tmp cannot replace a private child directory.
        let sticky_ancestor = index > 0 && meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        ensure!(
            meta.mode() & 0o022 == 0 || sticky_ancestor,
            "protected path is writable by other users"
        );
        if index == 0 {
            ensure!(
                if directory {
                    meta.is_dir()
                } else {
                    meta.is_file()
                },
                "invalid protected path type"
            );
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn protected_path(_: &Path, _: bool) -> Result<()> {
    anyhow::bail!("protected probe configuration requires Unix ownership checks")
}

#[derive(Debug, Clone, Copy)]
pub enum ProbeKind {
    AgentBoot,
    McpInitialize,
}
pub struct ProbeRequest<'a> {
    pub kind: ProbeKind,
    pub command: &'a TrustedCommand,
    pub snapshot_id: &'a str,
}
/// Trusted implementation boundary. Fixtures implement this without starting any process.
/// Production implementations must bound all calls and clean resources even after failure.
pub trait ProbeExecutor {
    fn prepare(&mut self, root: &Path) -> std::result::Result<(), ProbeSkip>;
    fn execute(&mut self, request: ProbeRequest<'_>) -> ProbeOutcome;
    fn cleanup(&mut self) -> std::result::Result<(), ProbeFailure>;
}
/// Restore verified file bytes into a private disposable root, then run explicitly configured probes.
/// Git artifacts are authenticated but not replayed: scope is explicitly file-content only.
/// Setup snapshots require native HOME layout and remain unsupported.
/// Errors in configuration are returned; restore/runtime/probe results are reportable evidence.
pub fn run_restore_probes(
    repo: &Repository,
    snapshot_id: &str,
    config: &TrustedProbeConfig,
    executor: &mut impl ProbeExecutor,
) -> Result<RestoreEvidence> {
    config.validate()?;
    let mut evidence = RestoreEvidence {
        id: Uuid::new_v4(),
        snapshot: snapshot_id.into(),
        finished_at: Utc::now(),
        sandbox: EvidenceSandbox::ContainerFileContent,
        agents: config
            .agents
            .iter()
            .map(|p| AgentProbe {
                agent: p.agent.clone(),
                outcome: ProbeOutcome::NotRun,
            })
            .collect(),
        mcps: config
            .mcps
            .iter()
            .map(|p| McpProbe {
                name: p.name.clone(),
                outcome: ProbeOutcome::NotRun,
            })
            .collect(),
    };
    let root = tempfile::Builder::new()
        .prefix("bunker-restore-probe-")
        .tempdir()?;
    let restored_root = root.path().join("restored");
    fs::create_dir(&restored_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&restored_root, fs::Permissions::from_mode(0o755))?;
    }
    let restored = restore_files(repo, snapshot_id, &restored_root);
    let unavailable = match restored {
        Ok(()) => executor
            .prepare(&restored_root)
            .err()
            .map(ProbeOutcome::NotRunWithReason),
        Err(outcome) => Some(outcome),
    };
    let run = |command: &TrustedCommand, kind, executor: &mut dyn ProbeExecutor| {
        if let Some(outcome) = unavailable {
            return outcome;
        }
        if command.requires_network {
            return ProbeOutcome::NotRunWithReason(ProbeSkip::NetworkUnavailable);
        }
        if command.requires_credentials {
            return ProbeOutcome::NotRunWithReason(ProbeSkip::CredentialsUnavailable);
        }
        executor.execute(ProbeRequest {
            kind,
            command,
            snapshot_id,
        })
    };
    for (probe, result) in config.agents.iter().zip(&mut evidence.agents) {
        result.outcome = run(&probe.command, ProbeKind::AgentBoot, executor);
    }
    for (probe, result) in config.mcps.iter().zip(&mut evidence.mcps) {
        result.outcome = run(&probe.command, ProbeKind::McpInitialize, executor);
    }
    if let Err(reason) = executor.cleanup() {
        // Cleanup is part of the test: a leaked sandbox can never be reported as success.
        for probe in &mut evidence.agents {
            probe.outcome = ProbeOutcome::FailedWithReason(reason);
        }
        for probe in &mut evidence.mcps {
            probe.outcome = ProbeOutcome::FailedWithReason(reason);
        }
    }
    root.close().context("remove disposable restore root")?;
    evidence.finished_at = Utc::now();
    Ok(evidence)
}
fn restore_files(
    repo: &Repository,
    id: &str,
    root: &Path,
) -> std::result::Result<(), ProbeOutcome> {
    let failure = |_| ProbeOutcome::FailedWithReason(ProbeFailure::RestoreFailed);
    let manifest = repo.manifest(id).map_err(failure)?;
    if manifest.setup.is_some()
        || manifest
            .files
            .iter()
            .any(|file| file.path.split('/').any(|part| part == ".git"))
    {
        return Err(ProbeOutcome::NotRunWithReason(
            ProbeSkip::UnsupportedSnapshot,
        ));
    }
    if manifest.files.len() > MAX_FILES
        || manifest
            .files
            .iter()
            .try_fold(0u64, |n, f| n.checked_add(f.size))
            .is_none_or(|n| n > MAX_BYTES)
    {
        return Err(ProbeOutcome::NotRunWithReason(ProbeSkip::ResourceLimit));
    }
    // Verify all authenticated bytes before exposing any data to an executor.
    repo.verify(id).map_err(failure)?;
    if manifest
        .files
        .iter()
        .any(|f| !f.secret_references.is_empty())
    {
        return Err(ProbeOutcome::NotRunWithReason(
            ProbeSkip::CredentialsUnavailable,
        ));
    }
    let write = || -> Result<bool> {
        for entry in &manifest.files {
            safe_path(&entry.path)?;
            let path = root.join(&entry.path);
            let parent = path.parent().context("missing restore parent")?;
            fs::create_dir_all(parent)?;
            // The enclosing temporary directory stays private; copied directories must
            // remain readable by the fixed nonroot container UID even under umask 077.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for directory in parent.ancestors().take_while(|p| p.starts_with(root)) {
                    fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
                }
            }
            let bytes = repo.file_bytes(entry)?;
            // Legacy manifests may contain generated placeholders without reference metadata.
            if bytes
                .windows(b"BUNKER_SECRET_".len())
                .any(|part| part == b"BUNKER_SECRET_")
            {
                return Ok(false);
            }
            let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
            file.write_all(&bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o444))?;
            }
        }
        Ok(true)
    };
    if write().map_err(failure)? {
        Ok(())
    } else {
        Err(ProbeOutcome::NotRunWithReason(
            ProbeSkip::CredentialsUnavailable,
        ))
    }
}

/// Docker runtime with explicit context, sanitized CLI environment and no host bind mounts.
/// A task-owned named volume transports files even to a remote Docker context; probe mounts are RO.
pub struct DockerExecutor {
    config: TrustedProbeConfig,
    cli_home: tempfile::TempDir,
    volume: String,
    stage: String,
    containers: Vec<String>,
    volume_created: bool,
}
impl DockerExecutor {
    pub fn new(config: &TrustedProbeConfig) -> Result<Self> {
        config.validate()?;
        protected_path(&config.docker_config, true)?;
        // The executable may be an operator-installed symlink; resolve then verify its target.
        let executable = config.docker_executable.canonicalize()?;
        protected_path(&executable, false)?;
        let mut config = config.clone();
        config.docker_executable = executable;
        let name = format!("bunker-probe-{}", Uuid::new_v4());
        Ok(Self {
            config,
            cli_home: tempfile::tempdir()?,
            volume: format!("{name}-data"),
            stage: format!("{name}-stage"),
            containers: vec![],
            volume_created: false,
        })
    }
    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(&self.config.docker_executable);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("HOME", self.cli_home.path())
            .env("DOCKER_CONFIG", &self.config.docker_config)
            .arg("--context")
            .arg(&self.config.docker_context)
            .args(args);
        command
    }
    fn admin(&self, args: &[String]) -> bool {
        let mut command = self.command(args);
        matches!(
            bounded_process(
                &mut command,
                Duration::from_secs(10),
                self.config.output_limit_bytes,
                None
            ),
            ProcessResult::Exited(true, _)
        )
    }
    fn create_args(
        &self,
        name: &str,
        command: &TrustedCommand,
        snapshot: &str,
        readonly_volume: bool,
    ) -> Vec<String> {
        let mount = format!(
            "type=volume,source={},target=/restore,volume-nocopy{}",
            self.volume,
            if readonly_volume { ",readonly" } else { "" }
        );
        let mut args: Vec<String> = [
            "create",
            "--pull=never",
            "--log-driver=none",
            "--name",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--user=65532:65532",
            "--security-opt=no-new-privileges",
            "--network=none",
            "--pids-limit=64",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--ulimit=nofile=128:128",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
            "--workdir=/restore",
            "--env=HOME=/tmp",
            "--env=BUNKER_RESTORE_ROOT=/restore",
            "--interactive",
            "--mount",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        args.extend([
            mount,
            format!("--env=BUNKER_SNAPSHOT_ID={snapshot}"),
            "--entrypoint".into(),
            command.executable.clone(),
            self.config.image.clone(),
        ]);
        args.extend(command.args.clone());
        args
    }
}
impl ProbeExecutor for DockerExecutor {
    fn prepare(&mut self, root: &Path) -> std::result::Result<(), ProbeSkip> {
        // Establish runtime and pinned image availability before allocating any resource.
        if !self.admin(&[
            "image".into(),
            "inspect".into(),
            "--format={{.Id}}".into(),
            self.config.image.clone(),
        ]) {
            return Err(ProbeSkip::RuntimeUnavailable);
        }
        // Record names before attempting creation: timeout may mean Docker created the resource.
        self.volume_created = true;
        if !self.admin(&["volume".into(), "create".into(), self.volume.clone()]) {
            return Err(ProbeSkip::RuntimeUnavailable);
        }
        self.containers.push(self.stage.clone());
        if !self.admin(&self.create_args(&self.stage, &self.config.agents[0].command, "", false)) {
            return Err(ProbeSkip::RuntimeUnavailable);
        }
        // Only our restored temporary root is copied; never repository/credential directories.
        if !self.admin(&[
            "cp".into(),
            format!("{}/.", root.display()),
            format!("{}:/restore", self.stage),
        ]) {
            return Err(ProbeSkip::RuntimeUnavailable);
        }
        Ok(())
    }
    fn execute(&mut self, request: ProbeRequest<'_>) -> ProbeOutcome {
        let name = format!("bunker-probe-{}", Uuid::new_v4());
        self.containers.push(name.clone());
        if !self.admin(&self.create_args(&name, request.command, request.snapshot_id, true)) {
            return ProbeOutcome::NotRunWithReason(ProbeSkip::RuntimeUnavailable);
        }
        let mut command = self.command(&[
            "start".into(),
            "--attach".into(),
            "--interactive".into(),
            name.clone(),
        ]);
        let result = bounded_process(
            &mut command,
            Duration::from_secs(self.config.timeout_seconds),
            self.config.output_limit_bytes,
            Some(&request),
        );
        let outcome = match result {
            ProcessResult::Validated => ProbeOutcome::Passed,
            ProcessResult::InvalidResponse => {
                ProbeOutcome::FailedWithReason(ProbeFailure::InvalidMcpHandshake)
            }
            ProcessResult::Exited(success, output) => {
                if !success {
                    ProbeOutcome::FailedWithReason(ProbeFailure::ProcessFailed)
                } else {
                    validate_response(request.kind, request.snapshot_id, &output)
                        .map_or_else(ProbeOutcome::FailedWithReason, |_| ProbeOutcome::Passed)
                }
            }
            ProcessResult::Timeout => ProbeOutcome::FailedWithReason(ProbeFailure::Timeout),
            ProcessResult::OutputLimit => ProbeOutcome::FailedWithReason(ProbeFailure::OutputLimit),
            ProcessResult::Unavailable => {
                ProbeOutcome::NotRunWithReason(ProbeSkip::RuntimeUnavailable)
            }
        };
        if self.admin(&[
            "rm".into(),
            "--force".into(),
            "--volumes".into(),
            name.clone(),
        ]) {
            self.containers.retain(|n| n != &name);
            outcome
        } else {
            ProbeOutcome::FailedWithReason(ProbeFailure::CleanupFailed)
        }
    }
    fn cleanup(&mut self) -> std::result::Result<(), ProbeFailure> {
        let mut failed = false;
        for name in self.containers.clone() {
            if self.admin(&[
                "rm".into(),
                "--force".into(),
                "--volumes".into(),
                name.clone(),
            ]) {
                self.containers.retain(|n| n != &name);
            } else {
                failed = true;
            }
        }
        if self.volume_created {
            if self.admin(&["volume".into(), "rm".into(), self.volume.clone()]) {
                self.volume_created = false;
            } else {
                failed = true;
            }
        }
        if failed {
            Err(ProbeFailure::CleanupFailed)
        } else {
            Ok(())
        }
    }
}
impl Drop for DockerExecutor {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn initialize_request() -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":REQUEST_ID,"method":"initialize","params":{"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"bunker-restore-probe","version":"1"}}})).expect("static initialize request");
    bytes.push(b'\n');
    bytes
}
/// Validate actual application-level responses; exit(0) alone never establishes boot/connectivity.
/// MCP v1 foundation accepts newline-delimited stdio JSON-RPC with this exact supported version.
pub fn validate_response(
    kind: ProbeKind,
    snapshot: &str,
    bytes: &[u8],
) -> std::result::Result<(), ProbeFailure> {
    match kind {
        ProbeKind::AgentBoot => {
            let value: Value =
                serde_json::from_slice(bytes).map_err(|_| ProbeFailure::InvalidBootResponse)?;
            if value.get("bunkerRestoreProbe") == Some(&json!(1))
                && value.get("booted") == Some(&json!(true))
                && value.get("snapshot") == Some(&json!(snapshot))
            {
                Ok(())
            } else {
                Err(ProbeFailure::InvalidBootResponse)
            }
        }
        ProbeKind::McpInitialize => match validate_mcp_frames(bytes)? {
            true => Ok(()),
            false => Err(ProbeFailure::InvalidMcpHandshake),
        },
    }
}

/// Validate every supplied frame before accepting initialize, including frames
/// following the response. The streaming caller supplies only complete frames.
fn validate_mcp_frames(bytes: &[u8]) -> std::result::Result<bool, ProbeFailure> {
    let mut initialized = false;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let value: Value =
            serde_json::from_slice(line).map_err(|_| ProbeFailure::InvalidMcpHandshake)?;
        if value["jsonrpc"] != "2.0" {
            return Err(ProbeFailure::InvalidMcpHandshake);
        }
        let Some(id) = value.get("id") else {
            continue;
        };
        let result = &value["result"];
        if initialized
            || id != &json!(REQUEST_ID)
            || value.get("error").is_some()
            || result["protocolVersion"] != PROTOCOL
            || !result["capabilities"].is_object()
            || !["name", "version"].iter().all(|key| {
                result["serverInfo"][key]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 128)
            })
        {
            return Err(ProbeFailure::InvalidMcpHandshake);
        }
        initialized = true;
    }
    Ok(initialized)
}

enum ProcessResult {
    Exited(bool, Vec<u8>),
    Validated,
    InvalidResponse,
    Timeout,
    OutputLimit,
    Unavailable,
}
#[cfg(unix)]
fn bounded_process(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
    request: Option<&ProbeRequest<'_>>,
) -> ProcessResult {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let Ok(mut child) = command.spawn() else {
        return ProcessResult::Unavailable;
    };
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            kill_reap(&mut child);
            return ProcessResult::Unavailable;
        }
    }
    let mut input = child.stdin.take().expect("piped stdin");
    let mcp = request.is_some_and(|r| matches!(r.kind, ProbeKind::McpInitialize));
    if mcp && input.write_all(&initialize_request()).is_err() {
        kill_reap(&mut child);
        return ProcessResult::Exited(false, vec![]);
    }
    let started = Instant::now();
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut consumed = 0;
    let mut exited = None;
    let result = loop {
        if !drain(&mut stdout, &mut output, limit.saturating_sub(consumed))
            || !drain(&mut stderr, &mut errors, limit)
            || consumed + output.len() + errors.len() > limit
        {
            break ProcessResult::OutputLimit;
        }
        if mcp {
            if let Some(last_newline) = output.iter().rposition(|byte| *byte == b'\n') {
                let complete = last_newline + 1;
                let initialized = validate_mcp_frames(&output[..complete]);
                output.drain(..complete);
                consumed += complete;
                match initialized {
                    Ok(true) => {
                        if input
                            .write_all(
                                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
                            )
                            .is_ok()
                        {
                            break ProcessResult::Validated;
                        }
                        break ProcessResult::Exited(false, vec![]);
                    }
                    Err(_) => break ProcessResult::InvalidResponse,
                    Ok(false) => (),
                }
            }
        }
        if let Some(success) = exited {
            break ProcessResult::Exited(success && !mcp, output);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain and validate once more after exit, still bounded even if
                // a descendant holds the pipe. Keep an incomplete suffix intact.
                exited = Some(status.success());
                continue;
            }
            Err(_) => break ProcessResult::Unavailable,
            Ok(None) => (),
        }
        if started.elapsed() >= timeout {
            break ProcessResult::Timeout;
        }
        thread::sleep(Duration::from_millis(10));
    };
    drop(input);
    kill_reap(&mut child);
    result
}
#[cfg(unix)]
fn drain(input: &mut impl Read, output: &mut Vec<u8>, limit: usize) -> bool {
    let mut chunk = [0u8; 4096];
    loop {
        match input.read(&mut chunk) {
            Ok(0) => return true,
            Ok(count) => {
                if output.len().saturating_add(count) > limit {
                    return false;
                }
                output.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return true,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
}
#[cfg(not(unix))]
fn bounded_process(
    _: &mut Command,
    _: Duration,
    _: usize,
    _: Option<&ProbeRequest<'_>>,
) -> ProcessResult {
    ProcessResult::Unavailable
}
fn kill_reap(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn process_timeout_output_cap_exit_and_mcp_handshake_are_bounded() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5 & wait"]);
        let start = Instant::now();
        assert!(matches!(
            bounded_process(&mut command, Duration::from_millis(50), 256, None),
            ProcessResult::Timeout
        ));
        assert!(start.elapsed() < Duration::from_secs(2));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do printf 'too much output'; done"]);
        assert!(matches!(
            bounded_process(&mut command, Duration::from_secs(2), 256, None),
            ProcessResult::OutputLimit
        ));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        assert!(
            matches!(bounded_process(&mut command, Duration::from_secs(1), 256, None), ProcessResult::Exited(true, ref bytes) if bytes.is_empty())
        );
        let trusted = TrustedCommand {
            executable: "/fixture".into(),
            args: vec![],
            requires_network: false,
            requires_credentials: false,
        };
        let request = ProbeRequest {
            kind: ProbeKind::McpInitialize,
            command: &trusted,
            snapshot_id: "fixture",
        };
        let mut command = Command::new("/bin/sh");
        command.args(["-c", r#"read request; printf '%s\n' '{"jsonrpc":"2.0","id":"bunker-restore-probe","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}'; read notification; sleep 5"#]);
        assert!(matches!(
            bounded_process(&mut command, Duration::from_secs(1), 1024, Some(&request)),
            ProcessResult::Validated
        ));
    }
    fn mcp_process(script: &str, limit: usize) -> ProcessResult {
        let trusted = TrustedCommand {
            executable: "/fixture".into(),
            args: vec![],
            requires_network: false,
            requires_credentials: false,
        };
        let request = ProbeRequest {
            kind: ProbeKind::McpInitialize,
            command: &trusted,
            snapshot_id: "fixture",
        };
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]).env("RESPONSE", r#"{"jsonrpc":"2.0","id":"bunker-restore-probe","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}"#);
        bounded_process(&mut command, Duration::from_secs(2), limit, Some(&request))
    }

    #[test]
    fn mcp_initialize_before_incomplete_next_frame_is_accepted() {
        assert!(matches!(
            mcp_process(
                r#"read request; printf '%s\n%s' "$RESPONSE" '{"jsonrpc":'; read notification; sleep 5"#,
                1024
            ),
            ProcessResult::Validated
        ));
    }

    #[test]
    fn mcp_retains_split_frame_after_consumed_notification() {
        assert!(matches!(
            mcp_process(
                r#"read request; printf '%s\n%s' '{"jsonrpc":"2.0","method":"notifications/progress"}' '{"jsonrpc":'; sleep 0.1; printf '%s\n' '"2.0","id":"bunker-restore-probe","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}'; read notification; sleep 5"#,
                1024
            ),
            ProcessResult::Validated
        ));
    }

    #[test]
    fn mcp_complete_invalid_frames_cannot_hide_behind_partial_suffix() {
        for invalid in ["not-json", r#"{"jsonrpc":"1.0","method":"notification"}"#] {
            let script = format!(
                r#"read request; printf '%s\n%s\n%s' "$RESPONSE" '{}' '{{"jsonrpc":'; read notification; sleep 5"#,
                invalid
            );
            assert!(matches!(
                mcp_process(&script, 1024),
                ProcessResult::InvalidResponse
            ));
        }
        assert!(matches!(
            mcp_process(
                r#"read request; printf '%s\n%s\n%s' "$RESPONSE" "$RESPONSE" '{"jsonrpc":'; read notification; sleep 5"#,
                1024
            ),
            ProcessResult::InvalidResponse
        ));
    }

    #[test]
    fn mcp_consumed_frames_still_count_toward_output_limit() {
        assert!(matches!(
            mcp_process(
                r#"read request; while :; do printf '%s\n' '{"jsonrpc":"2.0","method":"notification"}'; sleep 0.02; done"#,
                128
            ),
            ProcessResult::OutputLimit
        ));
        assert!(matches!(
            mcp_process(r#"read request; printf '%s' "$RESPONSE"; sleep 5"#, 1024),
            ProcessResult::Timeout
        ));
    }

    #[test]
    fn docker_create_has_only_owned_volume_and_defense_in_depth() {
        // This test never runs the Docker CLI.
        let config: TrustedProbeConfig = serde_json::from_value(json!({
            "docker_executable":"/usr/bin/docker", "docker_context":"homelab", "docker_config":"/operator/docker",
            "image":format!("example/probe@sha256:{}", "a".repeat(64)), "timeout_seconds":1, "output_limit_bytes":1024,
            "agents":[{"agent":"codex","command":{"executable":"/usr/bin/fixture"}}], "mcps":[]
        })).unwrap();
        let executor = DockerExecutor {
            config: config.clone(),
            cli_home: tempfile::tempdir().unwrap(),
            volume: "owned-volume".into(),
            stage: "owned-stage".into(),
            containers: vec![],
            volume_created: false,
        };
        let args = executor.create_args(
            "owned-container",
            &config.agents[0].command,
            "snapshot",
            true,
        );
        for expected in [
            "--read-only",
            "--cap-drop=ALL",
            "--network=none",
            "--security-opt=no-new-privileges",
            "--user=65532:65532",
            "--pull=never",
            "type=volume,source=owned-volume,target=/restore,volume-nocopy,readonly",
        ] {
            assert!(args.iter().any(|arg| arg == expected));
        }
        assert!(!args
            .iter()
            .any(|arg| arg.contains("type=bind") || arg.contains("docker.sock")));
        let command = executor.command(&args);
        let env = command
            .get_envs()
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(env.len(), 3);
        assert!(env.contains(&"DOCKER_CONFIG".into()));
    }
}
