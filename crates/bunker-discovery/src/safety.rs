use crate::{sanitize, FileFormat, SecretReference};
use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Component, Path, PathBuf},
};

/// Policy may override non-secret artifact defaults; hard exclusions always apply.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyPolicy {
    pub max_file_bytes: u64,
    pub max_repo_bytes: u64,
    pub extra_excludes: Vec<String>,
    /// Override non-secret artifact defaults only; hard exclusions always win.
    pub default_includes: Vec<String>,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_repo_bytes: 256 * 1024 * 1024,
            extra_excludes: vec![],
            default_includes: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    Environment,
    Credentials,
    Transcript,
    Browser,
    Cache,
    Build,
    ModelOrBinary,
    Policy,
    UnsafePath,
    InvalidConfiguration,
    Unreadable,
    CaseCollision,
}

pub struct ExclusionPolicy {
    extra: GlobSet,
    includes: GlobSet,
}

fn globs(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).context("invalid policy glob")?);
    }
    Ok(builder.build()?)
}
fn matches_ancestor(globs: &GlobSet, path: &Path) -> bool {
    path.ancestors().any(|p| globs.is_match(p))
}
impl ExclusionPolicy {
    pub fn new(policy: &SafetyPolicy) -> Result<Self> {
        Ok(Self {
            extra: globs(&policy.extra_excludes)?,
            includes: globs(&policy.default_includes)?,
        })
    }
    pub fn has_default_includes(&self) -> bool {
        !self.includes.is_empty()
    }
    /// Only relative paths are accepted. Includes cannot override private data or policy.
    pub fn reason(&self, relative: &Path) -> Result<Option<ExclusionReason>> {
        validate_relative_path(relative)?;
        let parts: Vec<_> = relative
            .iter()
            .map(|p| p.to_string_lossy().to_ascii_lowercase())
            .collect();
        for name in &parts {
            if name == ".env"
                || name.starts_with(".env.")
                || name.ends_with(".env")
                || name == ".envrc"
            {
                return Ok(Some(ExclusionReason::Environment));
            }
            if matches!(
                name.as_str(),
                ".ssh"
                    | ".aws"
                    | ".gnupg"
                    | ".azure"
                    | "secrets"
                    | "credentials"
                    | "keychain"
                    | "keychains"
                    | "auth.json"
                    | "oauth.json"
                    | "tokens.json"
                    | ".netrc"
                    | ".npmrc"
                    | ".pypirc"
                    | ".git-credentials"
            ) || [
                "id_rsa",
                "id_ed25519",
                "credentials.",
                "secrets.",
                "secret.",
                ".credentials",
            ]
            .iter()
            .any(|p| name.starts_with(p))
                || [".pem", ".key", ".p12", ".pfx", ".keystore"]
                    .iter()
                    .any(|s| name.ends_with(s))
            {
                return Ok(Some(ExclusionReason::Credentials));
            }
            if name.ends_with(".jsonl") {
                return Ok(Some(ExclusionReason::Transcript));
            }
            if matches!(name.as_str(), ".git" | ".hg" | ".svn") {
                return Ok(Some(ExclusionReason::Cache));
            }
        }
        for pair in parts.windows(2) {
            if is_agent_root(&pair[0])
                && (matches!(
                    pair[1].as_str(),
                    "sessions"
                        | "session"
                        | "projects"
                        | "transcripts"
                        | "history"
                        | "logs"
                        | "auth"
                        | "browser"
                        | "profiles"
                        | "globalstorage"
                        | "workspacestorage"
                ) || pair[1].starts_with("history."))
            {
                return Ok(Some(ExclusionReason::Transcript));
            }
        }
        if matches_ancestor(&self.extra, relative) {
            return Ok(Some(ExclusionReason::Policy));
        }
        if matches_ancestor(&self.includes, relative) {
            return Ok(None);
        }
        // Names such as build/chat/history are legitimate source or skill assets.
        let asset = parts.windows(2).any(|p| {
            (is_agent_root(&p[0]) || p[0] == ".github")
                && matches!(
                    p[1].as_str(),
                    "skills"
                        | "commands"
                        | "rules"
                        | "agents"
                        | "hooks"
                        | "memory"
                        | "prompts"
                        | "steering"
                        | "specs"
                )
        });
        for (index, name) in parts.iter().enumerate() {
            let source = parts[..index]
                .iter()
                .any(|p| matches!(p.as_str(), "src" | "source"));
            if !asset && !source {
                if matches!(
                    name.as_str(),
                    "node_modules"
                        | ".cache"
                        | "cache"
                        | "caches"
                        | ".npm"
                        | ".pnpm-store"
                        | ".yarn"
                        | ".venv"
                        | "venv"
                        | "__pycache__"
                        | ".mypy_cache"
                        | ".pytest_cache"
                        | ".ruff_cache"
                        | ".gradle"
                ) {
                    return Ok(Some(ExclusionReason::Cache));
                }
                if matches!(
                    name.as_str(),
                    "target" | "dist" | "build" | "out" | "coverage" | ".next" | ".nuxt" | ".turbo"
                ) {
                    return Ok(Some(ExclusionReason::Build));
                }
            }
        }
        if parts.last().is_some_and(|name| {
            [
                ".gguf",
                ".ggml",
                ".safetensors",
                ".onnx",
                ".pt",
                ".pth",
                ".sqlite",
                ".sqlite3",
                ".db",
            ]
            .iter()
            .any(|s| name.ends_with(s))
        }) {
            return Ok(Some(ExclusionReason::ModelOrBinary));
        }
        Ok(None)
    }
}
pub fn is_default_artifact(reason: &ExclusionReason) -> bool {
    matches!(
        reason,
        ExclusionReason::Cache | ExclusionReason::Build | ExclusionReason::ModelOrBinary
    )
}
fn is_agent_root(name: &str) -> bool {
    matches!(
        name,
        ".claude" | ".codex" | ".cursor" | ".copilot" | ".kiro" | ".agents"
    )
}

/// Recognize known configuration suffixes at any workspace depth.
pub fn agent_config(path: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    [
        ".mcp.json",
        ".claude.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude/mcp.json",
        ".cursor/mcp.json",
        ".cursor/settings.json",
        ".cursor/hooks.json",
        ".codex/config.toml",
        ".agents/config.toml",
        ".copilot/config.json",
        ".copilot/mcp-config.json",
        ".vscode/mcp.json",
        ".vscode/settings.json",
        ".kiro/settings/mcp.json",
        ".kiro/settings/settings.json",
        "cursor/user/settings.json",
        "cursor/user/mcp.json",
        "code/user/settings.json",
        "code/user/mcp.json",
        "kiro/user/settings.json",
        "kiro/user/mcp.json",
    ]
    .iter()
    .any(|suffix| path == *suffix || path.ends_with(&format!("/{suffix}")))
}

/// Reject case and NFC/NFD aliases for files and ancestors without renaming the
/// stored source path. This prevents canonical-equivalent destinations colliding.
#[derive(Default)]
pub struct PathIdentitySet(BTreeMap<String, PathBuf>);
impl PathIdentitySet {
    pub fn insert(&mut self, path: &Path) -> bool {
        let ancestors: Vec<_> = path
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
        if ancestors.iter().any(|p| {
            self.0
                .get(&portable_path_identity(p))
                .is_some_and(|existing| existing != *p)
        }) {
            return false;
        }
        for p in ancestors {
            self.0.insert(portable_path_identity(p), p.to_owned());
        }
        true
    }
}

fn portable_path_identity(path: &Path) -> String {
    use unicode_normalization::UnicodeNormalization;
    path.to_string_lossy()
        .nfc()
        .flat_map(char::to_lowercase)
        .nfc()
        .collect()
}

/// Reject traversal, absolute paths and Windows path syntax even on Unix hosts.
pub fn validate_relative_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("non-UTF-8 path refused")?;
    // Windows PathBuf::join emits backslashes; accept its native separator while
    // still rejecting foreign Windows syntax on Unix and traversal on both.
    #[cfg(windows)]
    let text = text.replace('\\', "/");
    if text.is_empty()
        || (!cfg!(windows) && text.contains('\\'))
        || text.contains(':')
        || text.contains('\0')
        || text
            .split('/')
            .any(|part| part == ".." || part == "." || part.is_empty())
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("path must be a normalized relative path without traversal");
    }
    Ok(())
}

/// Open every root component without following links, including ancestor links.
pub(crate) fn open_root(root: &Path) -> Result<Dir> {
    if !root.is_absolute() {
        bail!("root must be absolute")
    }
    let mut anchor = PathBuf::new();
    let mut dir: Option<Dir> = None;
    for component in root.components() {
        match component {
            Component::Prefix(_) => anchor.push(component),
            Component::RootDir => {
                anchor.push(component);
                dir = Some(
                    Dir::open_ambient_dir(&anchor, cap_std::ambient_authority())
                        .context("cannot open filesystem root")?,
                );
            }
            Component::Normal(name) => {
                dir = Some(
                    dir.context("missing absolute root")?
                        .open_dir_nofollow(name)
                        .context("root component missing, inaccessible, or a symlink")?,
                );
            }
            _ => bail!("root must not contain traversal"),
        }
    }
    dir.context("missing absolute root")
}

pub(crate) fn open_file(root: &Path, relative: &Path) -> Result<cap_std::fs::File> {
    validate_relative_path(relative)?;
    let mut dir = open_root(root)?;
    let components: Vec<_> = relative.components().collect();
    for component in &components[..components.len() - 1] {
        dir = dir
            .open_dir_nofollow(component.as_os_str())
            .context("file parent missing, inaccessible, or a symlink")?;
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    // A concurrent replacement with a FIFO must not block the snapshot process.
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = dir
        .open_with(components.last().unwrap().as_os_str(), &options)
        .context("file missing, inaccessible, or a symlink")?;
    if !file.metadata()?.is_file() {
        bail!("only regular files can be snapshotted")
    }
    Ok(file)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRequest {
    pub relative_path: PathBuf,
    pub format: FileFormat,
}

impl FileRequest {
    pub fn new(relative_path: impl Into<PathBuf>) -> Self {
        let relative_path = relative_path.into();
        Self {
            format: FileFormat::for_path(&relative_path),
            relative_path,
        }
    }
}

/// Configs are sanitized; ordinary assets are byte-exact. Diagnostics never contain contents.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedFile {
    pub relative_path: PathBuf,
    /// Executability from the same securely opened file used for content.
    #[serde(default)]
    pub executable: bool,
    pub bytes: Vec<u8>,
    pub source_bytes: u64,
    pub sanitized: bool,
    pub secret_references: Vec<SecretReference>,
}

impl std::fmt::Debug for PreparedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedFile")
            .field("relative_path", &self.relative_path)
            .field("source_bytes", &self.source_bytes)
            .field("sanitized_bytes", &self.bytes.len())
            .field("reference_count", &self.secret_references.len())
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreparedSnapshot {
    pub files: Vec<PreparedFile>,
    pub excluded: Vec<(PathBuf, ExclusionReason)>,
    pub source_bytes: u64,
    pub sanitized_bytes: u64,
}

/// Excluded files return None. All other errors fail closed, without raw contents.
pub fn prepare_file(
    root: &Path,
    request: &FileRequest,
    policy: &SafetyPolicy,
) -> Result<Option<PreparedFile>> {
    if ExclusionPolicy::new(policy)?
        .reason(&request.relative_path)?
        .is_some()
    {
        return Ok(None);
    }
    let mut file = open_file(root, &request.relative_path)?;
    let before = file.metadata()?;
    let length = before.len();
    #[cfg(unix)]
    let executable = {
        use cap_std::fs::PermissionsExt;
        before.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    let cap = policy.max_file_bytes.min(policy.max_repo_bytes);
    if length > cap {
        bail!("file exceeds configured size cap ({cap} bytes)")
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(cap.saturating_add(1))
        .read_to_end(&mut raw)
        .context("file read failed")?;
    if raw.len() as u64 > cap {
        bail!("file grew beyond configured size cap ({cap} bytes)")
    }
    let after = file.metadata()?;
    if before.len() != after.len()
        || before.modified()? != after.modified()?
        || raw.len() as u64 != after.len()
    {
        bail!("file changed while being read")
    }
    // File extensions alone must never rewrite ordinary source or binary assets.
    let sanitized = if agent_config(&request.relative_path) {
        sanitize(&raw, FileFormat::for_path(&request.relative_path))?
    } else {
        crate::SanitizedContent {
            modified: false,
            bytes: raw.clone(),
            secret_references: vec![],
        }
    };
    if sanitized.bytes.len() as u64 > cap {
        bail!("sanitized file exceeds configured size cap ({cap} bytes)")
    }
    Ok(Some(PreparedFile {
        relative_path: request.relative_path.clone(),
        executable,
        source_bytes: raw.len() as u64,
        sanitized: sanitized.modified,
        bytes: sanitized.bytes,
        secret_references: sanitized.secret_references,
    }))
}

/// Oversized repositories fail atomically. Unsafe/unreadable/config errors are diagnosed per file.
/// Both source and output byte totals must fit. Duplicate paths count only once.
pub fn prepare_files(
    root: &Path,
    requests: &[FileRequest],
    policy: &SafetyPolicy,
) -> Result<PreparedSnapshot> {
    let exclusions = ExclusionPolicy::new(policy)?;
    let mut result = PreparedSnapshot {
        files: vec![],
        excluded: vec![],
        source_bytes: 0,
        sanitized_bytes: 0,
    };
    let mut seen = BTreeSet::new();
    let mut identities = PathIdentitySet::default();
    for request in requests {
        if !seen.insert(request.relative_path.clone()) {
            continue;
        }
        if let Some(reason) = exclusions.reason(&request.relative_path)? {
            result
                .excluded
                .push((request.relative_path.clone(), reason));
            continue;
        }
        if !identities.insert(&request.relative_path) {
            result.excluded.push((
                request.relative_path.clone(),
                ExclusionReason::CaseCollision,
            ));
            continue;
        }
        let prepared = match prepare_file(root, request, policy) {
            Ok(prepared) => prepared,
            Err(_) => {
                result.excluded.push((
                    request.relative_path.clone(),
                    if agent_config(&request.relative_path) {
                        ExclusionReason::InvalidConfiguration
                    } else {
                        ExclusionReason::Unreadable
                    },
                ));
                continue;
            }
        };
        if let Some(file) = prepared {
            result.source_bytes = result
                .source_bytes
                .checked_add(file.source_bytes)
                .context("repository byte count overflow")?;
            result.sanitized_bytes = result
                .sanitized_bytes
                .checked_add(file.bytes.len() as u64)
                .context("repository byte count overflow")?;
            if result.source_bytes > policy.max_repo_bytes
                || result.sanitized_bytes > policy.max_repo_bytes
            {
                bail!(
                    "repository exceeds configured size cap ({} bytes); snapshot refused",
                    policy.max_repo_bytes
                );
            }
            result.files.push(file);
        }
    }
    Ok(result)
}
