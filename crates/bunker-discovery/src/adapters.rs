use crate::{
    safety::{open_file, open_root},
    ExclusionPolicy, ExclusionReason, FileFormat, FileRequest, SafetyPolicy,
};
use anyhow::{bail, Context, Result};
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentId {
    ClaudeCode,
    Cursor,
    Codex,
    GitHubCopilot,
    Kiro,
}

impl AgentId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::GitHubCopilot => "github_copilot",
            Self::Kiro => "kiro",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// Explicit paths only. Constructing this context never consults environment variables.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryContext {
    pub platform: Platform,
    pub home: PathBuf,
    /// XDG_CONFIG_HOME on Linux, if provided; otherwise home/.config.
    pub config_dir: Option<PathBuf>,
    /// APPDATA on Windows, if provided; otherwise home/AppData/Roaming.
    pub app_data: Option<PathBuf>,
    /// Explicit repository roots. No implicit disk-wide repository discovery.
    pub workspace_roots: Vec<PathBuf>,
}

impl DiscoveryContext {
    pub fn new(
        platform: Platform,
        home: impl Into<PathBuf>,
        workspace_roots: Vec<PathBuf>,
    ) -> Self {
        Self {
            platform,
            home: home.into(),
            config_dir: None,
            app_data: None,
            workspace_roots,
        }
    }
    fn editor_base(&self) -> PathBuf {
        match self.platform {
            Platform::Linux => self
                .config_dir
                .clone()
                .unwrap_or_else(|| self.home.join(".config")),
            Platform::MacOs => self.home.join("Library/Application Support"),
            Platform::Windows => self
                .app_data
                .clone()
                .unwrap_or_else(|| self.home.join("AppData/Roaming")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemCategory {
    McpConfig,
    Skill,
    Rule,
    SubAgent,
    Hook,
    Memory,
    Settings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredItem {
    pub agent: AgentId,
    pub category: ItemCategory,
    pub root: PathBuf,
    pub relative_path: PathBuf,
    pub format: FileFormat,
    pub size_bytes: u64,
}

impl DiscoveredItem {
    pub fn request(&self) -> FileRequest {
        FileRequest {
            relative_path: self.relative_path.clone(),
            format: self.format,
        }
    }
    pub fn path(&self) -> PathBuf {
        self.root.join(&self.relative_path)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEvent {
    SessionStart,
    SessionEnd,
    TurnComplete,
    Scheduled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    NativeHook,
    ExternalLifecycle,
    ScheduledFallback,
}

/// A capability definition, not an installed hook or an observed session event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSignal {
    pub event: SessionEvent,
    pub source: SignalSource,
    pub hook_name: Option<String>,
    pub notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub agent: AgentId,
    pub items: Vec<DiscoveredItem>,
    pub workspace_roots: Vec<PathBuf>,
    pub session_signals: Vec<SessionSignal>,
    /// Excluded setup candidates, without reading their contents.
    #[serde(default)]
    pub excluded: Vec<DiscoveryExclusion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryExclusion {
    pub root: PathBuf,
    pub relative_path: PathBuf,
    pub reason: crate::ExclusionReason,
}

pub trait DiscoveryAdapter: Send + Sync {
    fn id(&self) -> AgentId;
    fn discover(
        &self,
        context: &DiscoveryContext,
        policy: &SafetyPolicy,
    ) -> Result<DiscoveryResult>;
    fn session_signals(&self) -> Vec<SessionSignal>;
}

/// Custom adapters may replace a built-in ID. Unknown IDs return None.
pub struct DiscoveryRegistry {
    adapters: Vec<Box<dyn DiscoveryAdapter>>,
}

impl Default for DiscoveryRegistry {
    fn default() -> Self {
        Self {
            adapters: [
                AgentId::ClaudeCode,
                AgentId::Cursor,
                AgentId::Codex,
                AgentId::GitHubCopilot,
                AgentId::Kiro,
            ]
            .into_iter()
            .map(|id| Box::new(BuiltinAdapter(id)) as Box<dyn DiscoveryAdapter>)
            .collect(),
        }
    }
}

impl DiscoveryRegistry {
    pub fn empty() -> Self {
        Self { adapters: vec![] }
    }
    pub fn register(&mut self, adapter: Box<dyn DiscoveryAdapter>) {
        self.adapters
            .retain(|existing| existing.id() != adapter.id());
        self.adapters.push(adapter);
    }
    pub fn get(&self, id: AgentId) -> Option<&dyn DiscoveryAdapter> {
        self.adapters
            .iter()
            .find(|a| a.id() == id)
            .map(|a| a.as_ref())
    }
    pub fn get_by_name(&self, name: &str) -> Option<&dyn DiscoveryAdapter> {
        self.adapters
            .iter()
            .find(|a| a.id().as_str() == name)
            .map(|a| a.as_ref())
    }
    /// Missing installations return no items and are omitted from this list.
    pub fn discover(
        &self,
        context: &DiscoveryContext,
        policy: &SafetyPolicy,
    ) -> Result<Vec<DiscoveryResult>> {
        let mut results = vec![];
        for adapter in &self.adapters {
            let result = adapter.discover(context, policy)?;
            if !result.items.is_empty() || !result.excluded.is_empty() {
                results.push(result);
            }
        }
        Ok(results)
    }
}

pub fn discover(context: &DiscoveryContext, policy: &SafetyPolicy) -> Result<Vec<DiscoveryResult>> {
    DiscoveryRegistry::default().discover(context, policy)
}

pub struct BuiltinAdapter(pub AgentId);

struct Candidate {
    root: PathBuf,
    relative: PathBuf,
    category: ItemCategory,
    recursive: bool,
}

fn add(
    candidates: &mut Vec<Candidate>,
    root: &Path,
    path: &str,
    category: ItemCategory,
    recursive: bool,
) {
    candidates.push(Candidate {
        root: root.to_owned(),
        relative: path.into(),
        category,
        recursive,
    });
}

fn agent_tree(candidates: &mut Vec<Candidate>, root: &Path, prefix: &str, agent: AgentId) {
    use ItemCategory::*;
    type CategorizedPaths = Vec<(&'static str, ItemCategory)>;
    let (files, dirs): (CategorizedPaths, CategorizedPaths) = match agent {
        AgentId::ClaudeCode => (
            vec![
                ("settings.json", Settings),
                ("settings.local.json", Settings),
                ("CLAUDE.md", Rule),
                ("mcp.json", McpConfig),
            ],
            vec![
                ("skills", Skill),
                ("commands", Skill),
                ("rules", Rule),
                ("agents", SubAgent),
                ("hooks", Hook),
                ("memory", Memory),
            ],
        ),
        AgentId::Cursor => (
            vec![
                ("mcp.json", McpConfig),
                ("settings.json", Settings),
                ("hooks.json", Hook),
            ],
            vec![
                ("rules", Rule),
                ("skills", Skill),
                ("agents", SubAgent),
                ("hooks", Hook),
            ],
        ),
        AgentId::Codex => (
            vec![
                ("config.toml", Settings),
                ("AGENTS.md", Rule),
                ("AGENTS.override.md", Rule),
            ],
            vec![
                ("prompts", Skill),
                ("skills", Skill),
                ("rules", Rule),
                ("agents", SubAgent),
                ("hooks", Hook),
                ("memory", Memory),
            ],
        ),
        AgentId::GitHubCopilot => (
            vec![
                ("config.json", Settings),
                ("mcp-config.json", McpConfig),
                ("copilot-instructions.md", Rule),
            ],
            vec![("skills", Skill), ("agents", SubAgent), ("hooks", Hook)],
        ),
        AgentId::Kiro => (
            vec![
                ("settings/mcp.json", McpConfig),
                ("settings/settings.json", Settings),
            ],
            vec![
                ("steering", Rule),
                ("specs", Rule),
                ("hooks", Hook),
                ("agents", SubAgent),
                ("skills", Skill),
            ],
        ),
    };
    for (path, kind) in files {
        add(candidates, root, &format!("{prefix}/{path}"), kind, false);
    }
    for (path, kind) in dirs {
        add(candidates, root, &format!("{prefix}/{path}"), kind, true);
    }
}

impl DiscoveryAdapter for BuiltinAdapter {
    fn id(&self) -> AgentId {
        self.0
    }

    fn session_signals(&self) -> Vec<SessionSignal> {
        let native = |event, hook: &str, notes: &str| SessionSignal {
            event,
            source: SignalSource::NativeHook,
            hook_name: Some(hook.into()),
            notes: notes.into(),
        };
        let mut signals = match self.0 {
            AgentId::ClaudeCode => vec![
                native(
                    SessionEvent::SessionStart,
                    "SessionStart",
                    "Requires explicit hook installation by the scheduler.",
                ),
                native(
                    SessionEvent::SessionEnd,
                    "SessionEnd",
                    "Requires explicit hook installation; a turn Stop is not session end.",
                ),
            ],
            AgentId::Codex => vec![native(
                SessionEvent::TurnComplete,
                "notify",
                "agent-turn-complete notification is not a full session end.",
            )],
            AgentId::Cursor => vec![native(
                SessionEvent::TurnComplete,
                "stop",
                "Version-dependent hook; a stopped turn is not necessarily session end.",
            )],
            AgentId::GitHubCopilot | AgentId::Kiro => vec![],
        };
        if self.0 != AgentId::ClaudeCode {
            signals.push(SessionSignal { event: SessionEvent::SessionEnd, source: SignalSource::ExternalLifecycle, hook_name: None,
                notes: "Requires a launcher/wrapper to report process exit; discovery does not infer session end from files.".into() });
        }
        signals.push(SessionSignal { event: SessionEvent::Scheduled, source: SignalSource::ScheduledFallback, hook_name: None,
            notes: "Hourly default, policy-configurable; use when lifecycle hooks are absent or unreliable.".into() });
        signals
    }

    fn discover(
        &self,
        context: &DiscoveryContext,
        policy: &SafetyPolicy,
    ) -> Result<DiscoveryResult> {
        use ItemCategory::*;
        let prefix = match self.0 {
            AgentId::ClaudeCode => ".claude",
            AgentId::Cursor => ".cursor",
            AgentId::Codex => ".codex",
            AgentId::GitHubCopilot => ".copilot",
            AgentId::Kiro => ".kiro",
        };
        let mut candidates = vec![];
        agent_tree(&mut candidates, &context.home, prefix, self.0);
        if self.0 == AgentId::ClaudeCode {
            add(&mut candidates, &context.home, "CLAUDE.md", Rule, false);
            add(
                &mut candidates,
                &context.home,
                ".claude.json",
                McpConfig,
                false,
            );
        }
        let editor = context.editor_base();
        if let Some(name) = match self.0 {
            AgentId::Cursor => Some("Cursor"),
            AgentId::GitHubCopilot => Some("Code"),
            AgentId::Kiro => Some("Kiro"),
            _ => None,
        } {
            add(
                &mut candidates,
                &editor,
                &format!("{name}/User/settings.json"),
                Settings,
                false,
            );
            add(
                &mut candidates,
                &editor,
                &format!("{name}/User/mcp.json"),
                McpConfig,
                false,
            );
        }
        for workspace in &context.workspace_roots {
            agent_tree(&mut candidates, workspace, prefix, self.0);
            match self.0 {
                AgentId::ClaudeCode => {
                    add(&mut candidates, workspace, "CLAUDE.md", Rule, false);
                    add(&mut candidates, workspace, ".mcp.json", McpConfig, false);
                }
                AgentId::Cursor => {
                    add(&mut candidates, workspace, ".cursorrules", Rule, false);
                    add(&mut candidates, workspace, "AGENTS.md", Rule, false);
                }
                AgentId::Codex => {
                    add(&mut candidates, workspace, "AGENTS.md", Rule, false);
                    add(
                        &mut candidates,
                        workspace,
                        "AGENTS.override.md",
                        Rule,
                        false,
                    );
                    agent_tree(&mut candidates, workspace, ".agents", self.0);
                }
                AgentId::GitHubCopilot => {
                    add(
                        &mut candidates,
                        workspace,
                        ".github/copilot-instructions.md",
                        Rule,
                        false,
                    );
                    add(
                        &mut candidates,
                        workspace,
                        ".github/instructions",
                        Rule,
                        true,
                    );
                    add(&mut candidates, workspace, ".github/prompts", Skill, true);
                    add(
                        &mut candidates,
                        workspace,
                        ".github/chatmodes",
                        SubAgent,
                        true,
                    );
                    add(&mut candidates, workspace, ".github/agents", SubAgent, true);
                    add(&mut candidates, workspace, ".github/skills", Skill, true);
                    add(&mut candidates, workspace, ".github/hooks", Hook, true);
                    add(
                        &mut candidates,
                        workspace,
                        ".vscode/mcp.json",
                        McpConfig,
                        false,
                    );
                    add(
                        &mut candidates,
                        workspace,
                        ".vscode/settings.json",
                        Settings,
                        false,
                    );
                }
                AgentId::Kiro => (),
            }
        }
        let exclusions = ExclusionPolicy::new(policy)?;
        let mut items = vec![];
        let mut excluded = vec![];
        let mut seen = BTreeSet::new();
        for candidate in candidates {
            // Missing roots/installations are normal. Existing but unsafe roots fail closed.
            match std::fs::symlink_metadata(&candidate.root) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                _ if open_root(&candidate.root).is_err() => {
                    excluded.push(DiscoveryExclusion {
                        root: candidate.root.clone(),
                        relative_path: candidate.relative.clone(),
                        reason: ExclusionReason::UnsafePath,
                    });
                    continue;
                }
                _ => {}
            }
            let path = candidate.root.join(&candidate.relative);
            let metadata = match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    excluded.push(DiscoveryExclusion {
                        root: candidate.root.clone(),
                        relative_path: candidate.relative.clone(),
                        reason: ExclusionReason::Unreadable,
                    });
                    continue;
                }
                Ok(metadata) => metadata,
            };
            if let Some(reason) = exclusions.reason(&candidate.relative)? {
                excluded.push(DiscoveryExclusion {
                    root: candidate.root.clone(),
                    relative_path: candidate.relative.clone(),
                    reason,
                });
                continue;
            }
            if metadata.file_type().is_symlink() {
                excluded.push(DiscoveryExclusion {
                    root: candidate.root.clone(),
                    relative_path: candidate.relative.clone(),
                    reason: ExclusionReason::UnsafePath,
                });
                continue;
            }
            if candidate.recursive {
                if !metadata.is_dir() {
                    excluded.push(DiscoveryExclusion {
                        root: candidate.root.clone(),
                        relative_path: candidate.relative.clone(),
                        reason: ExclusionReason::UnsafePath,
                    });
                    continue;
                }
                let directory = (|| -> Result<Dir> {
                    let mut directory = open_root(&candidate.root)?;
                    for part in candidate.relative.components() {
                        directory = directory.open_dir_nofollow(part.as_os_str())?;
                    }
                    Ok(directory)
                })();
                let directory = match directory {
                    Ok(directory) => directory,
                    Err(_) => {
                        excluded.push(DiscoveryExclusion {
                            root: candidate.root.clone(),
                            relative_path: candidate.relative.clone(),
                            reason: ExclusionReason::UnsafePath,
                        });
                        continue;
                    }
                };
                let mut paths = vec![];
                if collect_directory(
                    &directory,
                    &candidate.relative,
                    &exclusions,
                    &mut paths,
                    &mut (&candidate.root, &mut excluded),
                    &mut 0,
                    0,
                )
                .is_err()
                {
                    excluded.push(DiscoveryExclusion {
                        root: candidate.root.clone(),
                        relative_path: candidate.relative.clone(),
                        reason: ExclusionReason::Unreadable,
                    });
                }
                for relative in paths {
                    if collect_item(
                        &mut items,
                        &mut seen,
                        self.0,
                        &candidate,
                        &relative,
                        &exclusions,
                        policy,
                    )
                    .is_err()
                    {
                        excluded.push(DiscoveryExclusion {
                            root: candidate.root.clone(),
                            relative_path: relative.clone(),
                            reason: ExclusionReason::UnsafePath,
                        });
                    }
                }
            } else {
                if collect_item(
                    &mut items,
                    &mut seen,
                    self.0,
                    &candidate,
                    &candidate.relative,
                    &exclusions,
                    policy,
                )
                .is_err()
                {
                    excluded.push(DiscoveryExclusion {
                        root: candidate.root.clone(),
                        relative_path: candidate.relative.clone(),
                        reason: ExclusionReason::UnsafePath,
                    });
                }
            }
        }
        items.sort_by(|a, b| (&a.root, &a.relative_path).cmp(&(&b.root, &b.relative_path)));
        let mut identities: BTreeMap<PathBuf, crate::PathIdentitySet> = BTreeMap::new();
        items.retain(|item| {
            if identities
                .entry(item.root.clone())
                .or_default()
                .insert(&item.relative_path)
            {
                true
            } else {
                excluded.push(DiscoveryExclusion {
                    root: item.root.clone(),
                    relative_path: item.relative_path.clone(),
                    reason: ExclusionReason::CaseCollision,
                });
                false
            }
        });
        let workspace_roots = context
            .workspace_roots
            .iter()
            .filter(|root| items.iter().any(|item| item.root == **root))
            .cloned()
            .collect();
        Ok(DiscoveryResult {
            agent: self.0,
            items,
            workspace_roots,
            session_signals: self.session_signals(),
            excluded,
        })
    }
}

fn collect_directory(
    directory: &Dir,
    relative: &Path,
    exclusions: &ExclusionPolicy,
    paths: &mut Vec<PathBuf>,
    excluded: &mut (&Path, &mut Vec<DiscoveryExclusion>),
    visited: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        bail!("setup directory exceeds discovery depth limit")
    }
    for entry in directory
        .entries()
        .context("cannot enumerate setup directory")?
    {
        *visited += 1;
        if *visited > 100_000 {
            bail!("setup directory exceeds discovery entry limit")
        }
        let entry = entry.context("cannot enumerate setup directory entry")?;
        let path = relative.join(entry.file_name());
        let kind = entry
            .file_type()
            .context("cannot inspect setup directory entry")?;
        if let Some(reason) = exclusions.reason(&path)? {
            if !(kind.is_dir()
                && exclusions.has_default_includes()
                && crate::is_default_artifact(&reason))
            {
                excluded.1.push(DiscoveryExclusion {
                    root: excluded.0.to_owned(),
                    relative_path: path,
                    reason,
                });
                continue;
            }
        }
        if kind.is_symlink() {
            excluded.1.push(DiscoveryExclusion {
                root: excluded.0.to_owned(),
                relative_path: path,
                reason: ExclusionReason::UnsafePath,
            });
            continue;
        }
        if kind.is_dir() {
            let child = match directory.open_dir_nofollow(entry.file_name()) {
                Ok(child) => child,
                Err(_) => {
                    excluded.1.push(DiscoveryExclusion {
                        root: excluded.0.to_owned(),
                        relative_path: path,
                        reason: ExclusionReason::UnsafePath,
                    });
                    continue;
                }
            };
            if collect_directory(
                &child,
                &path,
                exclusions,
                paths,
                excluded,
                visited,
                depth + 1,
            )
            .is_err()
            {
                excluded.1.push(DiscoveryExclusion {
                    root: excluded.0.to_owned(),
                    relative_path: path,
                    reason: ExclusionReason::Unreadable,
                });
            }
        } else if kind.is_file() {
            paths.push(path);
        } else {
            excluded.1.push(DiscoveryExclusion {
                root: excluded.0.to_owned(),
                relative_path: path,
                reason: ExclusionReason::UnsafePath,
            });
        }
    }
    Ok(())
}

fn collect_item(
    items: &mut Vec<DiscoveredItem>,
    seen: &mut BTreeSet<(PathBuf, PathBuf)>,
    agent: AgentId,
    candidate: &Candidate,
    relative: &Path,
    exclusions: &ExclusionPolicy,
    policy: &SafetyPolicy,
) -> Result<()> {
    if exclusions.reason(relative)?.is_some() {
        return Ok(());
    }
    if !seen.insert((candidate.root.clone(), relative.to_owned())) {
        return Ok(());
    }
    let file = open_file(&candidate.root, relative)?;
    let size_bytes = file.metadata()?.len();
    if size_bytes > policy.max_file_bytes {
        bail!("discovered file exceeds configured size cap")
    }
    items.push(DiscoveredItem {
        agent,
        category: candidate.category,
        root: candidate.root.clone(),
        relative_path: relative.to_owned(),
        format: FileFormat::for_path(relative),
        size_bytes,
    });
    Ok(())
}
