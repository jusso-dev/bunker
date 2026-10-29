//! Explicit opt-in lifecycle integration. Payload paths and arbitrary hooks are never executed.
use anyhow::{bail, ensure, Context, Result};
use bunker_discovery::AgentId;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_CONFIG: u64 = 1024 * 1024;
pub const WRAPPER_ACTIVE: &str = "BUNKER_SESSION_WRAPPER_ACTIVE";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionEnd {
    pub agent: AgentId,
    pub session_id: String,
}
impl SessionEnd {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.session_id.is_empty()
                && self.session_id.len() <= 128
                && self
                    .session_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid session identifier"
        );
        Ok(())
    }
    /// Ignores transcript_path/cwd and other untrusted fields. Nothing is read there.
    pub fn from_claude_input(mut input: impl Read) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        input.by_ref().take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "hook input exceeds limit");
        #[derive(Deserialize)]
        struct Payload {
            session_id: String,
            hook_event_name: String,
        }
        let payload: Payload = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid session-end payload"))?;
        ensure!(
            payload.hook_event_name == "SessionEnd",
            "expected SessionEnd event"
        );
        let event = Self {
            agent: AgentId::ClaudeCode,
            session_id: payload.session_id,
        };
        event.validate()?;
        Ok(event)
    }
}

/// Refuse every symlink component, including ancestors. No environment lookup.
pub(crate) fn open_existing_root(root: &Path) -> Result<Dir> {
    ensure!(root.is_absolute(), "explicit absolute root required");
    let mut anchor = PathBuf::new();
    let mut dir: Option<Dir> = None;
    for component in root.components() {
        match component {
            Component::Prefix(_) => anchor.push(component),
            Component::RootDir => {
                anchor.push(component);
                dir = Some(Dir::open_ambient_dir(
                    &anchor,
                    cap_std::ambient_authority(),
                )?);
            }
            Component::Normal(name) => {
                dir = Some(
                    dir.context("missing absolute root")?
                        .open_dir_nofollow(name)
                        .context("root component missing, inaccessible, or symlink")?,
                );
            }
            _ => bail!("root must not contain traversal"),
        }
    }
    dir.context("missing absolute root")
}

/// Only non-secret filesystem references and fixed Bunker arguments enter hook argv.
#[derive(Debug, Clone)]
pub struct HookInvocation {
    pub executable: PathBuf,
    pub repository: PathBuf,
    pub home: PathBuf,
    pub policy: Option<PathBuf>,
    pub key_config: Option<PathBuf>,
    /// Explicit operator-selected workspace roots; payload `cwd` is never used.
    pub workspaces: Vec<PathBuf>,
}

/// Explicit authenticated host routing. The payload cannot select any path.
#[derive(Debug, Clone)]
pub struct HostHookInvocation {
    pub executable: PathBuf,
    pub repository: PathBuf,
    pub home: PathBuf,
    pub key_config: Option<PathBuf>,
    pub host_config: PathBuf,
    pub workspace: PathBuf,
}

fn literal_path(path: &Path) -> Result<String> {
    let text = path.to_str().context("hook paths must be UTF-8")?;
    ensure!(
        path.is_absolute()
            && text.len() <= 4096
            && !text.contains("${")
            && !text.chars().any(char::is_control)
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "hook paths must be absolute, normalized, and literal"
    );
    Ok(text.to_owned())
}

pub fn plan_claude_host_hook(invocation: &HostHookInvocation, enable: bool) -> Result<HookPlan> {
    let config_path = literal_path(&invocation.host_config)?;
    if enable {
        let config = crate::host_runtime::HostConfig::load(&invocation.host_config)?;
        ensure!(
            config.session_handler,
            "host session handler is not explicitly enabled"
        );
    }
    let standalone = HookInvocation {
        executable: invocation.executable.clone(),
        repository: invocation.repository.clone(),
        home: invocation.home.clone(),
        policy: None,
        key_config: invocation.key_config.clone(),
        workspaces: vec![invocation.workspace.clone()],
    };
    let mut handler = standalone.handler()?;
    let args = handler["args"]
        .as_array_mut()
        .context("invalid native handler argv")?;
    args.push(serde_json::Value::String("--host-config".into()));
    args.push(serde_json::Value::String(config_path));
    plan_claude_handler(&invocation.home, handler, enable)
}

impl HookInvocation {
    fn handler(&self) -> Result<serde_json::Value> {
        let path_text = literal_path;
        let executable = path_text(&self.executable)?;
        ensure!(self.executable.is_file(), "Bunker executable must exist");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::metadata(&self.executable)?.permissions().mode() & 0o111 != 0,
                "Bunker executable is not executable"
            );
        }
        #[cfg(windows)]
        ensure!(
            self.executable
                .extension()
                .is_some_and(|s| s.eq_ignore_ascii_case("exe")),
            "native exec-form hook requires an .exe"
        );
        let mut args = vec!["--repo".to_owned(), path_text(&self.repository)?];
        if let Some(path) = &self.policy {
            args.extend(["--policy".to_owned(), path_text(path)?]);
        }
        if let Some(path) = &self.key_config {
            args.extend(["--key-config".to_owned(), path_text(path)?]);
        }
        args.extend([
            "session-end".to_owned(),
            "--agent".to_owned(),
            "claude_code".to_owned(),
            "--home".to_owned(),
            path_text(&self.home)?,
        ]);
        ensure!(self.workspaces.len() <= 64, "too many hook workspaces");
        let mut unique = std::collections::BTreeSet::new();
        for workspace in &self.workspaces {
            open_existing_root(workspace)?;
            ensure!(
                workspace.canonicalize()? == *workspace,
                "hook workspaces must be canonical"
            );
            ensure!(
                !workspace.starts_with(&self.repository) && !self.repository.starts_with(workspace),
                "hook workspace and repository must be disjoint"
            );
            ensure!(unique.insert(workspace), "duplicate hook workspace");
            args.extend(["--workspace".to_owned(), path_text(workspace)?]);
        }
        Ok(serde_json::json!({"type":"command", "command":executable, "args":args, "timeout":60}))
    }
}

/// Config bytes may contain existing credentials, so this type is deliberately
/// neither serializable nor content-debuggable. Keep it in memory for review/apply.
pub struct HookPlan {
    pub destination: PathBuf,
    pub enable: bool,
    pub changed: bool,
    pub confirmation: String,
    pub handler: serde_json::Value,
    before: Option<Zeroizing<Vec<u8>>>,
    after: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for HookPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookPlan")
            .field("destination", &self.destination)
            .field("enable", &self.enable)
            .field("changed", &self.changed)
            .finish_non_exhaustive()
    }
}

impl HookPlan {
    fn digest(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&(
            &self.destination,
            self.enable,
            self.changed,
            &self.handler,
            self.before
                .as_ref()
                .map(|b| blake3::hash(b).to_hex().to_string()),
            blake3::hash(&self.after).to_hex().to_string(),
        ))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

fn read_settings(dir: &Dir) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match dir.open_with("settings.json", &options) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("cannot safely read Claude settings"),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= MAX_CONFIG,
        "invalid Claude settings file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_CONFIG,
        "Claude settings exceed limit"
    );
    Ok(Some(bytes))
}

/// Review a minimal native hook edit. Does not write files or execute any hook.
/// Only Claude SessionEnd exec form is installed; other agents use `run_session`.
pub fn plan_claude_hook(invocation: &HookInvocation, enable: bool) -> Result<HookPlan> {
    plan_claude_handler(&invocation.home, invocation.handler()?, enable)
}

fn plan_claude_handler(
    home_path: &Path,
    handler: serde_json::Value,
    enable: bool,
) -> Result<HookPlan> {
    let home = open_existing_root(home_path)?;
    let before = match home.open_dir_nofollow(".claude") {
        Ok(dir) => read_settings(&dir)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => bail!("Claude config directory is inaccessible or a symlink"),
    };
    let group = serde_json::json!({"hooks":[handler.clone()]});
    let mut config: serde_json::Value = match &before {
        Some(bytes) => serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("Claude settings must be valid JSON"))?,
        None => serde_json::json!({}),
    };
    let object = config
        .as_object_mut()
        .context("Claude settings must be an object")?;
    let mut changed = false;
    if enable {
        let hooks = object
            .entry("hooks")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .context("Claude hooks must be an object")?;
        let entries = hooks
            .entry("SessionEnd")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .context("SessionEnd hooks must be an array")?;
        if !entries.contains(&group) {
            entries.push(group);
            changed = true;
        }
    } else if let Some(hooks) = object.get_mut("hooks") {
        let hooks = hooks
            .as_object_mut()
            .context("Claude hooks must be an object")?;
        if let Some(entries) = hooks.get_mut("SessionEnd") {
            let entries = entries
                .as_array_mut()
                .context("SessionEnd hooks must be an array")?;
            let length = entries.len();
            entries.retain(|entry| entry != &group);
            changed = entries.len() != length;
            if changed && entries.is_empty() {
                hooks.remove("SessionEnd");
            }
        }
        if changed && hooks.is_empty() {
            object.remove("hooks");
        }
    }
    let after = if changed {
        let mut bytes = serde_json::to_vec_pretty(&config)?;
        bytes.push(b'\n');
        Zeroizing::new(bytes)
    } else {
        Zeroizing::new(before.as_ref().map_or_else(Vec::new, |b| b.to_vec()))
    };
    ensure!(
        after.len() as u64 <= MAX_CONFIG,
        "updated Claude settings exceed limit"
    );
    let destination = home_path.join(".claude/settings.json");
    let mut plan = HookPlan {
        destination,
        enable,
        changed,
        confirmation: String::new(),
        handler,
        before,
        after,
    };
    plan.confirmation = plan.digest()?;
    Ok(plan)
}

/// Local explicit opt-in. Confirmation binds the in-memory reviewed edit, not
/// independent human authentication. A concurrent config change refuses the edit.
pub fn apply_claude_hook(plan: &HookPlan, confirmation: &str) -> Result<()> {
    ensure!(
        confirmation == plan.confirmation && confirmation == plan.digest()?,
        "hook confirmation missing or stale"
    );
    if !plan.changed {
        return Ok(());
    }
    let root = plan
        .destination
        .parent()
        .context("missing hook directory")?;
    let home = open_existing_root(root.parent().context("missing hook home")?)?;
    match home.create_dir(".claude") {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let dir = home.open_dir_nofollow(".claude")?;
    ensure!(
        read_settings(&dir)? == plan.before,
        "Claude settings changed; review a fresh hook plan"
    );
    crate::repository::atomic_write(&dir, "settings.json", &plan.after, plan.before.is_some())
}

/// Exact reversal of this edit, only while the resulting file is unchanged.
/// For later independent edits, generate a fresh disable plan instead.
pub fn rollback_claude_hook(plan: &HookPlan) -> Result<()> {
    ensure!(plan.confirmation == plan.digest()?, "hook plan changed");
    if !plan.changed {
        return Ok(());
    }
    let dir = open_existing_root(
        plan.destination
            .parent()
            .context("missing hook directory")?,
    )?;
    ensure!(
        read_settings(&dir)?.as_deref() == Some(&*plan.after),
        "Claude settings changed; use a fresh disable plan"
    );
    if let Some(before) = &plan.before {
        crate::repository::atomic_write(&dir, "settings.json", before, true)?;
    } else {
        dir.remove_file("settings.json")?;
        #[cfg(unix)]
        dir.into_std_file().sync_all()?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessEnd {
    Exited(i32),
    Signaled(i32),
    Cancelled,
    SpawnFailed,
    WaitFailed,
}
impl ProcessEnd {
    fn from_status(status: ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self::Exited(code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return Self::Signaled(signal);
            }
        }
        Self::WaitFailed
    }
}
pub struct SessionOutcome<T> {
    pub process: ProcessEnd,
    pub snapshot: Result<T>,
}

/// Launch a trusted, existing executable with arguments already separated by the
/// caller. No shell is inserted and no command/argument/environment value is logged.
/// Caller owns signal handling and sets `cancel`; the callback runs after success,
/// failure, cancellation, or spawn failure. SIGKILL/power loss cannot run callbacks.
pub fn run_session<T>(
    command: &mut Command,
    cancel: &AtomicBool,
    snapshot: impl FnOnce() -> Result<T>,
) -> Result<SessionOutcome<T>> {
    ensure!(
        std::env::var_os(WRAPPER_ACTIVE).is_none(),
        "recursive session wrapper refused"
    );
    ensure!(
        !command
            .get_envs()
            .any(|(name, value)| name == WRAPPER_ACTIVE && value.is_some()),
        "recursive session wrapper refused"
    );
    let program = Path::new(command.get_program());
    ensure!(
        program.is_absolute() && program.is_file(),
        "wrapper requires an explicit existing executable"
    );
    ensure!(
        program.canonicalize()? != std::env::current_exe()?.canonicalize()?,
        "cannot wrap Bunker itself"
    );
    command.env(WRAPPER_ACTIVE, "1");
    let process = if cancel.load(Ordering::SeqCst) {
        ProcessEnd::Cancelled
    } else {
        match command.spawn() {
            Err(_) => ProcessEnd::SpawnFailed,
            Ok(mut child) => loop {
                match child.try_wait() {
                    Ok(Some(status)) => break ProcessEnd::from_status(status),
                    Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break ProcessEnd::WaitFailed;
                    }
                    Ok(None) => (),
                }
                if cancel.load(Ordering::SeqCst) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break ProcessEnd::Cancelled;
                }
                std::thread::sleep(Duration::from_millis(20));
            },
        }
    };
    Ok(SessionOutcome {
        process,
        snapshot: snapshot(),
    })
}
