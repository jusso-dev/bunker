//! Offline Git preservation. All returned bytes, metadata, plans and journals must be
//! encrypted by the caller. See docs/git-recovery.md for the exclusive-access contract.
mod git;
mod index;
mod observation;
mod pack;
mod restore;
use anyhow::{ensure, Context, Result};
pub use observation::{git_alerts, GitAlerts, GitDiagnostic, Observation};
pub use restore::{ApplyFailure, Journal, RestorePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_objects: usize,
    pub max_object_bytes: usize,
    pub max_total_object_bytes: usize,
    pub max_pack_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_command_bytes: usize,
    pub max_files: usize,
    pub command_timeout_secs: u64,
    pub max_observation_refs: usize,
    pub max_observation_comparisons: usize,
    pub max_ancestry_commits: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_object_bytes: 8 << 20,
            max_total_object_bytes: 256 << 20,
            max_pack_bytes: 256 << 20,
            max_metadata_bytes: 16 << 20,
            max_command_bytes: 32 << 20,
            max_files: 100_000,
            command_timeout_secs: 30,
            max_observation_refs: 1024,
            max_observation_comparisons: 64,
            max_ancestry_commits: 100_000,
        }
    }
}
/// Only known structured agent configs use discovery's sanitizer. Additional policy
/// exclusions refuse capture rather than rewriting a Git object.
#[derive(Clone, Debug, Default)]
pub struct CapturePolicy {
    pub extra_excludes: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub path: String,
    pub mode: String,
    pub oid: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub version: u32,
    pub object_format: String,
    pub head_ref: String,
    pub heads: BTreeMap<String, String>,
    /// Oldest to newest; duplicates are meaningful. Reflog messages/identities omitted.
    pub stash: Vec<String>,
    pub index: Vec<IndexEntry>,
    pub packed_objects: BTreeSet<String>,
    /// Every omitted object in the required graph, not remote names or URLs.
    pub prerequisites: BTreeSet<String>,
    pub had_remote_tracking_refs: bool,
    /// Private observation state: authenticate and encrypt with the capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub metadata: Metadata,
    pub pack: Vec<u8>,
}
impl Capture {
    /// Bounded parser for authenticated, caller-decrypted parts. Validates envelope,
    /// pack checksums, sizes, object identities and inventory without invoking Git.
    /// Graph, prerequisite, path and secret policy checks run during restore planning.
    pub fn from_parts(metadata_json: &[u8], pack: Vec<u8>, limits: &Limits) -> Result<Self> {
        ensure!(
            metadata_json.len() <= limits.max_metadata_bytes,
            "metadata cap exceeded"
        );
        let metadata: Metadata = serde_json::from_slice(metadata_json)
            .map_err(|_| anyhow::anyhow!("invalid Git backup metadata"))?;
        ensure!(
            metadata.version == 1 && metadata.object_format == "sha1",
            "unsupported Git backup version/object format"
        );
        observation::validate(&metadata, limits)?;
        let objects = pack::decode(&pack, limits)?;
        ensure!(
            objects.keys().cloned().collect::<BTreeSet<_>>() == metadata.packed_objects,
            "pack inventory mismatch"
        );
        Ok(Self { metadata, pack })
    }
    /// Bind both metadata and exact pack bytes into the caller's confirmation/encryption.
    pub fn fingerprint(&self) -> Result<String> {
        let mut h = Sha256::new();
        h.update(serde_json::to_vec(&self.metadata)?);
        h.update(&self.pack);
        Ok(format!("{:x}", h.finalize()))
    }
}
#[derive(Clone, Debug)]
pub struct GitBackup {
    pub git_executable: PathBuf,
    pub limits: Limits,
}
impl Default for GitBackup {
    fn default() -> Self {
        Self {
            git_executable: PathBuf::from("git"),
            limits: Limits::default(),
        }
    }
}
#[derive(Clone, Debug)]
struct Object {
    kind: String,
    bytes: Vec<u8>,
}
#[derive(Clone)]
struct State {
    files: BTreeMap<String, Vec<u8>>,
}
impl State {
    fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(&self.files)?))
    }
    fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }
}
struct View {
    temp: TempDir,
    objects: PathBuf,
    state: State,
}
impl View {
    fn git<'a>(&'a self, engine: &'a GitBackup) -> git::Git<'a> {
        git::Git {
            exe: &engine.git_executable,
            dir: self.temp.path(),
            limits: &engine.limits,
            alternate: Some(&self.objects),
        }
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_oid(oid: &str) -> Result<()> {
    ensure!(
        oid.len() == 40
            && oid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA-1 object ID"
    );
    Ok(())
}
fn safe_path(path: &str) -> Result<()> {
    bunker_discovery::validate_relative_path(Path::new(path))?;
    ensure!(
        !path.contains(['\n', '\r', '\t', '\0', ':', '\\']) && path.len() <= 4096,
        "unsupported Git path"
    );
    for p in path.split('/') {
        ensure!(
            !p.is_empty() && !p.eq_ignore_ascii_case(".git") && !p.ends_with(['.', ' ']),
            "unsafe Git path"
        );
    }
    Ok(())
}
fn valid_ref(name: &str) -> Result<()> {
    ensure!(
        name.starts_with("refs/heads/") || name == "refs/stash",
        "unsupported restore ref"
    );
    ensure!(
        !name.contains([' ', '~', '^', ':', '?', '*', '[', '\\', '\0'])
            && !name.contains("..")
            && !name.contains("@{"),
        "invalid ref name"
    );
    ensure!(
        name.bytes().all(|b| b >= 32 && b != 127),
        "invalid ref control character"
    );
    for part in name.split('/') {
        ensure!(
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock"),
            "invalid ref component"
        );
    }
    Ok(())
}

/// Ref files and every ancestor must have one portable spelling. Packed refs
/// can contain aliases even on a filesystem that cannot store them as loose refs.
fn validate_ref_namespace<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let names: BTreeSet<_> = names.into_iter().collect();
    let mut identities = bunker_discovery::PathIdentitySet::default();
    for name in &names {
        ensure!(
            identities.insert(Path::new(name)),
            "ref namespace has Unicode/case aliases"
        );
        let mut parent = *name;
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            ensure!(!names.contains(prefix), "ref namespace conflict");
            parent = prefix;
        }
    }
    Ok(())
}
fn walk(path: &Path, root: &Path, files: &mut Vec<PathBuf>, cap: usize) -> Result<()> {
    git::regular_path(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            !m.file_type().is_symlink(),
            "symlink in Git storage refused"
        );
        ensure!(m.is_file() || m.is_dir(), "nonregular Git storage refused");
        ensure!(files.len() < cap, "Git storage file cap exceeded");
        files.push(path.strip_prefix(root)?.to_owned());
        if m.is_dir() {
            walk(&path, root, files, cap)?;
        }
    }
    Ok(())
}
impl GitBackup {
    fn state(&self, root: &Path) -> Result<State> {
        ensure!(
            cfg!(unix),
            "unsupported platform: Git recovery currently requires Unix"
        );
        git::regular_path(root)?;
        ensure!(root.is_dir(), "repository root is not a directory");
        let dir = root.join(".git");
        ensure!(
            fs::symlink_metadata(&dir).is_ok(),
            "not a supported Git worktree: .git directory missing"
        );
        git::regular_path(&dir)?;
        ensure!(
            dir.is_dir(),
            "unsupported linked worktree/submodule (requires a .git directory)"
        );
        for unsupported in [
            "commondir",
            "reftable",
            "shallow",
            "info/grafts",
            "objects/info/alternates",
            "objects/info/http-alternates",
            "worktrees",
            "rebase-merge",
            "rebase-apply",
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "BISECT_LOG",
            "refs/replace",
            "packed-refs.lock",
            "HEAD.lock",
        ] {
            ensure!(
                fs::symlink_metadata(dir.join(unsupported))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "unsupported Git repository state: {unsupported}"
            );
        }
        // Source operations use generated config, never source includes or helpers.
        let mut object_files = Vec::new();
        walk(
            &dir.join("objects"),
            &dir,
            &mut object_files,
            self.limits.max_files,
        )?;
        ensure!(
            !object_files
                .iter()
                .any(|p| p.extension().is_some_and(|x| x == "promisor")),
            "partial/promisor repository unsupported"
        );
        let mut paths = vec![
            PathBuf::from("HEAD"),
            PathBuf::from("index"),
            PathBuf::from("packed-refs"),
            PathBuf::from("logs/refs/stash"),
        ];
        if dir.join("refs").exists() {
            walk(&dir.join("refs"), &dir, &mut paths, self.limits.max_files)?;
        }
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for p in paths {
            let full = dir.join(&p);
            if full.is_dir() {
                continue;
            }
            let name = p
                .to_str()
                .context("non-UTF-8 Git metadata path")?
                .to_owned();
            ensure!(
                !name.ends_with(".lock"),
                "Git reference transaction in progress"
            );
            if let Some(bytes) = git::optional(&full, self.limits.max_metadata_bytes)? {
                total = total
                    .checked_add(bytes.len())
                    .context("metadata size overflow")?;
                ensure!(
                    total <= self.limits.max_metadata_bytes,
                    "metadata size cap exceeded"
                );
                files.insert(name, bytes);
            }
        }
        ensure!(files.contains_key("HEAD"), "missing HEAD");
        Ok(State { files })
    }
    fn view(&self, root: &Path) -> Result<View> {
        ensure!(
            !root.join(".git/index.lock").exists(),
            "Git index transaction in progress"
        );
        self.view_locked(root)
    }
    fn view_locked(&self, root: &Path) -> Result<View> {
        let state = self.state(root)?;
        let temp = tempfile::tempdir()?;
        for p in ["objects", "refs/heads", "refs/tags"] {
            fs::create_dir_all(temp.path().join(p))?;
        }
        fs::write(
            temp.path().join("config"),
            b"[core]\nrepositoryformatversion = 0\nbare = true\n",
        )?;
        for (name, bytes) in &state.files {
            let path = temp.path().join(name);
            fs::create_dir_all(path.parent().context("missing metadata parent")?)?;
            fs::write(path, bytes)?;
        }
        let view = View {
            temp,
            objects: root.join(".git/objects"),
            state,
        };
        // Parse only the format declaration with includes disabled. Config bytes and
        // remote URLs never enter the view, artifact, fingerprints, or diagnostics.
        if let Some(config) =
            git::optional(&root.join(".git/config"), self.limits.max_metadata_bytes)?
        {
            for (key, default) in [
                ("core.repositoryformatversion", "0"),
                ("extensions.objectformat", "sha1"),
                ("extensions.refstorage", "files"),
            ] {
                let value = view.git(self).text(
                    &[
                        "config",
                        "--file",
                        "-",
                        "--no-includes",
                        "--default",
                        default,
                        "--get",
                        key,
                    ],
                    &config,
                )?;
                ensure!(value.trim() == default, "unsupported Git repository format (requires SHA-1, files refs, format version 0)");
            }
        }
        Ok(view)
    }
    fn refs(&self, view: &View) -> Result<BTreeMap<String, String>> {
        let text = view.git(self).text(
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname) %(symref)",
            ],
            &[],
        )?;
        let mut refs = BTreeMap::new();
        for line in text.lines() {
            let fields: Vec<_> = line.split(' ').collect();
            ensure!(fields.len() == 3, "invalid ref record");
            valid_oid(fields[1])?;
            if fields[0].starts_with("refs/heads/") || fields[0] == "refs/stash" {
                valid_ref(fields[0])?;
                ensure!(
                    fields[2].is_empty(),
                    "symbolic branch/stash refs unsupported"
                );
            }
            ensure!(
                !fields[0].starts_with("refs/replace/"),
                "replace refs unsupported"
            );
            refs.insert(fields[0].into(), fields[1].into());
        }
        validate_ref_namespace(refs.keys().map(String::as_str))?;
        Ok(refs)
    }
    fn head(&self, view: &View) -> Result<String> {
        let head = std::str::from_utf8(view.state.get("HEAD").context("missing HEAD")?)?.trim_end();
        let head = head
            .strip_prefix("ref: ")
            .context("detached HEAD unsupported")?;
        valid_ref(head)?;
        ensure!(head.starts_with("refs/heads/"), "HEAD must name a branch");
        Ok(head.into())
    }
    fn graph(&self, view: &View, roots: &BTreeSet<String>) -> Result<BTreeSet<String>> {
        if roots.is_empty() {
            return Ok(BTreeSet::new());
        }
        let input = roots.iter().map(|s| format!("{s}\n")).collect::<String>();
        let text = view.git(self).text(
            &["rev-list", "--objects", "--no-object-names", "--stdin"],
            input.as_bytes(),
        )?;
        let mut ids = BTreeSet::new();
        for id in text.lines() {
            valid_oid(id)?;
            ids.insert(id.to_owned());
            ensure!(
                ids.len() <= self.limits.max_objects,
                "object graph cap exceeded"
            );
        }
        Ok(ids)
    }
    fn object(&self, view: &View, id: &str) -> Result<Object> {
        valid_oid(id)?;
        let git = view.git(self);
        let size: usize = git.text(&["cat-file", "-s", id], &[])?.trim().parse()?;
        ensure!(
            size <= self.limits.max_object_bytes,
            "Git object size cap exceeded"
        );
        let kind = git.text(&["cat-file", "-t", id], &[])?.trim().to_owned();
        ensure!(
            ["commit", "tree", "blob", "tag"].contains(&kind.as_str()),
            "unsupported Git object type"
        );
        let bytes = git.run(&["cat-file", &kind, id], &[])?;
        ensure!(
            bytes.len() == size && pack::oid(&kind, &bytes) == id,
            "Git object identity mismatch"
        );
        Ok(Object { kind, bytes })
    }
    fn check_path(&self, view: &View, entry: &IndexEntry, policy: &CapturePolicy) -> Result<()> {
        safe_path(&entry.path)?;
        ensure!(
            entry.mode == "100644" || entry.mode == "100755",
            "unsafe-path: symlink/submodule or unsupported file mode"
        );
        let path = Path::new(&entry.path);
        let safety = bunker_discovery::SafetyPolicy {
            extra_excludes: policy.extra_excludes.clone(),
            ..Default::default()
        };
        let exclusions = bunker_discovery::ExclusionPolicy::new(&safety)?;
        let reason = exclusions.reason(path)?;
        // Ordinary source/build/binary bytes remain exact. Hard secret exclusions and
        // configured exclusions apply everywhere; full discovery policy applies agent roots.
        let agent =
            entry.path.split('/').next().is_some_and(|p| {
                [".claude", ".cursor", ".codex", ".copilot", ".kiro"].contains(&p)
            });
        let sensitive = matches!(
            reason,
            Some(
                bunker_discovery::ExclusionReason::Environment
                    | bunker_discovery::ExclusionReason::Credentials
                    | bunker_discovery::ExclusionReason::Transcript
                    | bunker_discovery::ExclusionReason::Browser
                    | bunker_discovery::ExclusionReason::Policy
            )
        );
        let extra_secret = path.components().any(|p| {
            if p.as_os_str()
                .to_str()
                .is_some_and(|s| s.to_ascii_lowercase().starts_with(".env"))
            {
                return true;
            }
            matches!(
                p.as_os_str()
                    .to_str()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                ".azure" | ".gnupg" | ".netrc" | ".npmrc" | ".pypirc"
            )
        });
        ensure!(
            !sensitive && !extra_secret && !(agent && reason.is_some()),
            "unsafe-path: excluded Git path {:?}; capture refused",
            entry.path
        );
        if bunker_discovery::agent_config(path) {
            let obj = self.object(view, &entry.oid)?;
            ensure!(obj.kind == "blob", "index/tree entry is not a blob");
            let result = bunker_discovery::sanitize(
                &obj.bytes,
                bunker_discovery::FileFormat::for_path(path),
            )
            .map_err(|_| anyhow::anyhow!("unsafe-path: agent config cannot be safely parsed"))?;
            ensure!(
                !result.modified,
                "unsafe-path: agent config needs literal-secret redaction; Git capture refused"
            );
        }
        Ok(())
    }
    fn tree_entries(&self, view: &View, id: &str) -> Result<Vec<IndexEntry>> {
        let bytes = view
            .git(self)
            .run(&["ls-tree", "-rz", "--full-tree", id], &[])?;
        let mut entries = Vec::new();
        for item in bytes.split(|b| *b == 0).filter(|b| !b.is_empty()) {
            let item = std::str::from_utf8(item).context("unsupported non-UTF-8 tree path")?;
            let (header, path) = item.split_once('\t').context("invalid tree record")?;
            let fields: Vec<_> = header.split(' ').collect();
            ensure!(fields.len() == 3, "invalid tree record");
            entries.push(IndexEntry {
                path: path.into(),
                mode: fields[0].into(),
                oid: fields[2].into(),
            });
            ensure!(
                entries.len() <= self.limits.max_files,
                "tree entry cap exceeded"
            );
        }
        Ok(entries)
    }
    pub fn capture(&self, root: &Path, policy: &CapturePolicy) -> Result<Capture> {
        self.capture_with_previous(root, policy, None)
    }
    /// Compare with caller-authenticated previous metadata while the isolated
    /// source view is available. No previous objects are imported or fetched.
    pub fn capture_with_previous(
        &self,
        root: &Path,
        policy: &CapturePolicy,
        previous: Option<&Metadata>,
    ) -> Result<Capture> {
        let view = self.view(root)?;
        let refs = self.refs(&view)?;
        let head_ref = self.head(&view)?;
        validate_ref_namespace(refs.keys().map(String::as_str).chain([head_ref.as_str()]))?;
        let heads: BTreeMap<_, _> = refs
            .iter()
            .filter(|(r, _)| r.starts_with("refs/heads/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let stash = stash_stack(&view.state, refs.get("refs/stash"))?;
        for id in heads.values().chain(&stash) {
            ensure!(
                view.git(self).text(&["cat-file", "-t", id], &[])?.trim() == "commit",
                "branch/stash ref must name a commit"
            );
        }
        for id in &stash {
            let object = self.object(&view, id)?;
            let parents = object
                .bytes
                .split(|b| *b == b'\n')
                .take_while(|line| !line.is_empty())
                .filter(|line| line.starts_with(b"parent "))
                .count();
            ensure!((2..=3).contains(&parents), "invalid stash commit structure");
        }
        let index = view
            .state
            .get("index")
            .map(|b| index::decode(b, self.limits.max_files))
            .transpose()?
            .unwrap_or_default();
        let mut roots: BTreeSet<_> = heads.values().chain(stash.iter()).cloned().collect();
        roots.extend(index.iter().map(|e| e.oid.clone()));
        let all = self.graph(&view, &roots)?;
        let remotes: BTreeSet<_> = refs
            .iter()
            .filter(|(r, _)| r.starts_with("refs/remotes/"))
            .map(|(_, o)| o.clone())
            .collect();
        let known = self.graph(&view, &remotes)?;
        let needed: BTreeSet<_> = all.difference(&known).cloned().collect();
        let mut objects = BTreeMap::new();
        let mut total = 0usize;
        let mut checked = BTreeSet::new();
        for entry in &index {
            ensure!(
                view.git(self)
                    .text(&["cat-file", "-t", &entry.oid], &[])?
                    .trim()
                    == "blob",
                "index entry must name a blob"
            );
            self.check_path(&view, entry, policy)?;
            checked.insert((entry.path.clone(), entry.oid.clone(), entry.mode.clone()));
        }
        for id in &needed {
            ensure!(
                checked.len() <= self.limits.max_files,
                "historical path inspection cap exceeded"
            );
            let object = self.object(&view, id)?;
            total = total
                .checked_add(object.bytes.len())
                .context("object size overflow")?;
            ensure!(
                total <= self.limits.max_total_object_bytes,
                "total Git object size cap exceeded"
            );
            if object.kind == "commit" {
                for entry in self.tree_entries(&view, id)? {
                    if checked.insert((entry.path.clone(), entry.oid.clone(), entry.mode.clone())) {
                        self.check_path(&view, &entry, policy)?;
                    }
                }
            }
            objects.insert(id.clone(), object);
        }
        let observation = self.observe(&view, &refs, previous)?;
        let metadata = Metadata {
            version: 1,
            object_format: "sha1".into(),
            head_ref,
            heads,
            stash,
            index,
            packed_objects: needed,
            prerequisites: all.intersection(&known).cloned().collect(),
            had_remote_tracking_refs: !remotes.is_empty(),
            observation: Some(observation),
        };
        ensure!(
            serde_json::to_vec(&metadata)?.len() <= self.limits.max_metadata_bytes,
            "capture metadata cap exceeded"
        );
        let pack = pack::encode(&objects, &self.limits)?;
        if !all.is_empty() {
            view.git(self).run(
                &[
                    "fsck",
                    "--strict",
                    "--no-reflogs",
                    "--no-dangling",
                    "--no-progress",
                ],
                &[],
            )?;
        }
        ensure!(
            self.state(root)?.digest()? == view.state.digest()?,
            "source changed during capture; retry with exclusive access"
        );
        Ok(Capture { metadata, pack })
    }
}
fn stash_stack(state: &State, tip: Option<&String>) -> Result<Vec<String>> {
    let mut stash = Vec::new();
    if let Some(bytes) = state.get("logs/refs/stash") {
        for line in bytes.split(|b| *b == b'\n').filter(|x| !x.is_empty()) {
            ensure!(
                line.len() >= 82 && line[40] == b' ' && line[81] == b' ',
                "invalid stash reflog"
            );
            let old = std::str::from_utf8(&line[..40])?;
            valid_oid(old)?;
            let oid = std::str::from_utf8(&line[41..81])?;
            valid_oid(oid)?;
            ensure!(
                oid != "0000000000000000000000000000000000000000",
                "invalid zero stash entry"
            );
            stash.push(oid.into());
        }
    }
    ensure!(
        stash.last() == tip,
        "stash reflog missing/inconsistent with refs/stash"
    );
    Ok(stash)
}
