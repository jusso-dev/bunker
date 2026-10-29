use bunker_git::{CapturePolicy, GitBackup};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    source: PathBuf,
    remote: PathBuf,
}
fn git(path: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env("GIT_AUTHOR_DATE", "@1234567890 +0000")
        .env("GIT_COMMITTER_DATE", "@1234567890 +0000")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fixture Git {:?}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim_end().to_owned()
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let remote = root.join("remote.git");
        git(
            &root,
            &[
                "init",
                "--bare",
                "--initial-branch=main",
                remote.to_str().unwrap(),
            ],
        );
        git(&source, &["init", "--initial-branch=main"]);
        fs::write(source.join("base.txt"), "REMOTE_KNOWN_FIXTURE_PAYLOAD\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "remote base"]);
        git(
            &source,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&source, &["push", "-u", "origin", "main"]);
        Self {
            _temp: temp,
            root,
            source,
            remote,
        }
    }
    fn clone_target(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        git(
            &self.root,
            &[
                "clone",
                self.remote.to_str().unwrap(),
                path.to_str().unwrap(),
            ],
        );
        path
    }
    fn local_changes(&self) {
        git(&self.source, &["checkout", "-b", "unpublished"]);
        fs::write(
            self.source.join("branch.rs"),
            b"const ID: &str = \"sk-fixture-not-a-real-secret\";\n",
        )
        .unwrap();
        git(&self.source, &["add", "."]);
        git(&self.source, &["commit", "-m", "local branch"]);
        git(&self.source, &["checkout", "main"]);
        for n in 0..3 {
            fs::write(self.source.join("base.txt"), format!("stash {n}\n")).unwrap();
            fs::write(
                self.source.join(format!("untracked-{n}.txt")),
                format!("stash untracked {n}"),
            )
            .unwrap();
            git(
                &self.source,
                &[
                    "stash",
                    "push",
                    "-u",
                    "-m",
                    &format!("private fixture message {n}"),
                ],
            );
        }
        fs::write(self.source.join("base.txt"), b"staged bytes\n").unwrap();
        git(&self.source, &["add", "base.txt"]);
        fs::write(
            self.source.join("base.txt"),
            b"working bytes are separate\n",
        )
        .unwrap();
        fs::write(
            self.source.join("new.rs"),
            b"// arbitrary source token=exact-id-123\n",
        )
        .unwrap();
        git(&self.source, &["add", "new.rs"]);
    }
}
#[test]
fn full_round_trip_omits_remote_payload_preserves_all_stashes_and_staging() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let refs_before = git(&f.source, &["show-ref"]);
    let index_before = fs::read(f.source.join(".git/index")).unwrap();
    let stash_log_before = fs::read(f.source.join(".git/logs/refs/stash")).unwrap();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    assert_eq!(capture.metadata.stash.len(), 3);
    assert_eq!(capture.metadata.heads.len(), 2);
    assert!(capture.metadata.had_remote_tracking_refs);
    let remote_blob = git(&f.source, &["rev-parse", "origin/main:base.txt"]);
    assert!(capture.metadata.prerequisites.contains(&remote_blob));
    assert!(!capture.metadata.packed_objects.contains(&remote_blob));
    let repeat = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    assert_eq!(
        capture.fingerprint().unwrap(),
        repeat.fingerprint().unwrap()
    );
    assert_eq!(capture.pack, repeat.pack);
    assert_eq!(git(&f.source, &["show-ref"]), refs_before);
    assert_eq!(fs::read(f.source.join(".git/index")).unwrap(), index_before);
    assert_eq!(
        fs::read(f.source.join(".git/logs/refs/stash")).unwrap(),
        stash_log_before
    );
    let metadata = serde_json::to_string(&capture.metadata).unwrap();
    assert!(
        !metadata.contains("private fixture")
            && !metadata.contains("remote.git")
            && !metadata.contains("example.invalid")
    );
    // Independently inspect pack inventory with Git, proving remote payloads are absent.
    let pack_path = f.root.join("capture.pack");
    fs::write(&pack_path, &capture.pack).unwrap();
    git(&f.root, &["index-pack", pack_path.to_str().unwrap()]);
    let inventory = git(
        &f.root,
        &[
            "verify-pack",
            "-v",
            f.root.join("capture.idx").to_str().unwrap(),
        ],
    );
    assert!(!inventory.lines().any(|l| l.starts_with(&remote_blob)));
    let target = f.clone_target("target");
    git(&target, &["branch", "keep-extra"]);
    let original_index = fs::read(target.join(".git/index")).unwrap();
    let plan = engine.plan_restore(&target, &capture).unwrap();
    assert!(plan.readable().unwrap().contains("prior_index_fingerprint"));
    let mut saved = None;
    let journal = engine
        .apply_restore(&plan, &capture, |j| {
            saved = Some(serde_json::to_vec(j)?);
            Ok(())
        })
        .unwrap();
    assert!(saved.is_some());
    assert_eq!(
        git(&target, &["rev-parse", "unpublished"]),
        capture.metadata.heads["refs/heads/unpublished"]
    );
    assert_eq!(
        git(&target, &["stash", "list", "--format=%H"])
            .lines()
            .collect::<Vec<_>>(),
        capture
            .metadata
            .stash
            .iter()
            .rev()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    assert_eq!(git(&target, &["show", ":base.txt"]), "staged bytes");
    assert_eq!(
        fs::read(target.join("base.txt")).unwrap(),
        b"REMOTE_KNOWN_FIXTURE_PAYLOAD\n"
    );
    assert_eq!(
        git(&target, &["show", "unpublished:branch.rs"]),
        "const ID: &str = \"sk-fixture-not-a-real-secret\";"
    );
    git(&target, &["rev-parse", "keep-extra"]);
    // Stash content includes the third parent for -u, and every historical stack entry.
    for n in 0..3 {
        assert!(git(
            &target,
            &["show", &format!("stash@{{{n}}}^3:untracked-{}.txt", 2 - n)]
        )
        .starts_with("stash untracked"));
    }
    engine.recover(&journal).unwrap();
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), original_index);
    assert!(!target.join(".git/refs/heads/unpublished").exists());
    assert!(!target.join(".git/refs/stash").exists());
    assert!(!target.join(".git/logs/refs/stash").exists());
    engine.recover(&journal).unwrap(); // recovery is idempotent
}
#[test]
fn missing_prerequisite_and_no_remote_fallback() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let empty = f.root.join("empty");
    fs::create_dir(&empty).unwrap();
    git(&empty, &["init", "--initial-branch=main"]);
    assert!(engine
        .plan_restore(&empty, &capture)
        .unwrap_err()
        .to_string()
        .contains("missing remote prerequisite"));
    git(&f.source, &["remote", "remove", "origin"]);
    let full = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    assert!(full.metadata.prerequisites.is_empty());
    assert!(!full.metadata.had_remote_tracking_refs);
    let remote_blob = git(&f.source, &["rev-parse", "main:base.txt"]);
    assert!(full.metadata.packed_objects.contains(&remote_blob));
    let plan = engine.plan_restore(&empty, &full).unwrap();
    engine.apply_restore(&plan, &full, |_| Ok(())).unwrap();
    assert_eq!(
        git(&empty, &["rev-parse", "main"]),
        full.metadata.heads["refs/heads/main"]
    );
}
#[test]
fn empty_and_git_absent_are_explicit() {
    let tmp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap();
    let engine = GitBackup::default();
    assert!(engine.capture(&root, &CapturePolicy::default()).is_err());
    git(&root, &["init", "--initial-branch=main"]);
    let capture = engine.capture(&root, &CapturePolicy::default()).unwrap();
    assert!(capture.metadata.heads.is_empty() && capture.metadata.index.is_empty());
    assert!(
        capture.metadata.packed_objects.is_empty() && capture.metadata.prerequisites.is_empty()
    );
    let missing = GitBackup {
        git_executable: root.join("absent-git"),
        ..Default::default()
    };
    assert!(missing
        .capture(&root, &CapturePolicy::default())
        .unwrap_err()
        .to_string()
        .contains("Git unavailable"));
}
#[test]
fn unsafe_history_staged_configs_and_paths_are_refused_without_secret_echo() {
    for name in [".env", ".env.fixture", ".npmrc", "secret.pem", ".mcp.json"] {
        let f = Fixture::new();
        fs::write(
            f.source.join(name),
            br#"{"apiKey":"fixture-literal-private-value"}"#,
        )
        .unwrap();
        git(&f.source, &["add", "."]);
        let error = GitBackup::default()
            .capture(&f.source, &CapturePolicy::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsafe-path"), "{name}: {error}");
        assert!(!error.contains("fixture-literal-private-value"));
    }
    let f = Fixture::new();
    fs::write(f.source.join(".env"), "fixture-secret-value").unwrap();
    git(&f.source, &["add", "."]);
    git(&f.source, &["commit", "-m", "historical secret"]);
    git(&f.source, &["rm", ".env"]);
    git(&f.source, &["commit", "-m", "removed secret"]);
    assert!(GitBackup::default()
        .capture(&f.source, &CapturePolicy::default())
        .unwrap_err()
        .to_string()
        .contains("unsafe-path"));
}
#[test]
fn ordinary_json_source_exact_safe_config_references_allowed_and_custom_exclusions() {
    let f = Fixture::new();
    fs::write(
        f.source.join("source.json"),
        b"{\"password\":\"fixture-exact-source-data\"}\n",
    )
    .unwrap();
    fs::write(
        f.source.join(".mcp.json"),
        b"{\"token\":\"${env:FIXTURE_TOKEN}\"}\n",
    )
    .unwrap();
    git(&f.source, &["add", "."]);
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    let plan = engine.plan_restore(&target, &capture).unwrap();
    engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    assert_eq!(
        git(&target, &["show", ":source.json"]),
        "{\"password\":\"fixture-exact-source-data\"}"
    );
    assert!(engine
        .capture(
            &f.source,
            &CapturePolicy {
                extra_excludes: vec!["source.json".into()]
            }
        )
        .unwrap_err()
        .to_string()
        .contains("unsafe-path"));
}
#[test]
fn stale_plan_dirty_target_and_journal_failure_do_not_mutate() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let before = fs::read(target.join(".git/index")).unwrap();
    let refs = git(&target, &["show-ref"]);
    let failure = engine
        .apply_restore(&plan, &capture, |_| {
            anyhow::bail!("fixture durable storage unavailable")
        })
        .unwrap_err();
    assert!(failure.rollback_completed && failure.journal.is_none());
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), before);
    assert_eq!(git(&target, &["show-ref"]), refs);
    git(&target, &["branch", "new-extra"]);
    assert!(engine
        .apply_restore(&plan, &capture, |_| panic!("must not persist stale plan"))
        .is_err());
    fs::write(target.join("base.txt"), "dirty").unwrap();
    assert!(engine
        .plan_restore(&target, &capture)
        .unwrap_err()
        .to_string()
        .contains("dirty"));
}
#[test]
fn malicious_metadata_pack_and_post_restore_edits_are_refused() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    let mut altered = capture.clone();
    altered.metadata.index[0].path = "../escape".into();
    assert!(engine.plan_restore(&target, &altered).is_err());
    let mut altered = capture.clone();
    altered
        .metadata
        .heads
        .insert("refs/heads/x\ncommit".into(), "0".repeat(40));
    assert!(engine.plan_restore(&target, &altered).is_err());
    let mut altered = capture.clone();
    altered.pack[15] ^= 1;
    assert!(engine
        .plan_restore(&target, &altered)
        .unwrap_err()
        .to_string()
        .contains("checksum"));
    let mut altered = capture.clone();
    altered.metadata.version = 99;
    assert!(engine.plan_restore(&target, &altered).is_err());
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    fs::write(target.join("new.rs"), "subsequent index bytes").unwrap();
    git(&target, &["add", "new.rs"]);
    assert!(engine
        .recover(&journal)
        .unwrap_err()
        .to_string()
        .contains("index changed"));
}
#[test]
fn limits_conflicts_and_index_flags_fail_closed() {
    let f = Fixture::new();
    f.local_changes();
    let mut engine = GitBackup::default();
    engine.limits.max_object_bytes = 5;
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .is_err());
    let mut engine = GitBackup::default();
    engine.limits.max_pack_bytes = 32;
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .is_err());
    let mut engine = GitBackup::default();
    engine.limits.max_metadata_bytes = 10;
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .is_err());
    git(
        &f.source,
        &["update-index", "--assume-unchanged", "base.txt"],
    );
    assert!(GitBackup::default()
        .capture(&f.source, &CapturePolicy::default())
        .unwrap_err()
        .to_string()
        .contains("unsupported index flags"));
}
#[cfg(unix)]
#[test]
fn symlinks_worktrees_hooks_fsmonitor_and_config_includes() {
    use std::os::unix::{fs::symlink, fs::PermissionsExt};
    let f = Fixture::new();
    let marker = f.root.join("executed");
    let script = f.root.join("fixture-hook");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &f.source,
        &["config", "core.fsmonitor", script.to_str().unwrap()],
    );
    fs::copy(&script, f.source.join(".git/hooks/reference-transaction")).unwrap();
    // Invalid include proves capture never parses/includes source .git/config.
    let bad = f.root.join("bad-config");
    fs::write(&bad, "not valid config {{{\n").unwrap();
    git(
        &f.source,
        &["config", "include.path", bad.to_str().unwrap()],
    );
    let engine = GitBackup::default();
    engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    assert!(!marker.exists());
    fs::remove_file(f.source.join(".git/config")).unwrap();
    symlink(f.source.join("base.txt"), f.source.join("link")).unwrap();
    git(&f.source, &["add", "link"]);
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .is_err());
    git(&f.source, &["reset", "--", "link"]);
    fs::remove_file(f.source.join("link")).unwrap();
    let linked = f.root.join("linked");
    git(
        &f.source,
        &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
    );
    assert!(engine.capture(&linked, &CapturePolicy::default()).is_err());
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .is_err());
    let fresh = Fixture::new();
    symlink(&fresh.source, fresh.root.join("alias")).unwrap();
    assert!(engine
        .capture(&fresh.root.join("alias"), &CapturePolicy::default())
        .is_err());
}

#[test]
fn interrupted_refs_only_recovery_and_existing_stash_preimages() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    fs::write(target.join("base.txt"), "prior target stash").unwrap();
    git(&target, &["stash", "push", "-m", "keep prior target stack"]);
    let prior_log = fs::read(target.join(".git/logs/refs/stash")).unwrap();
    let prior_index = fs::read(target.join(".git/index")).unwrap();
    let prior_tip = git(&target, &["rev-parse", "refs/stash"]);
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    // Model a crash after atomic refs commit but before index/stash-log publication.
    fs::write(target.join(".git/index"), &prior_index).unwrap();
    let raw = serde_json::to_value(&journal).unwrap();
    let transitional: Vec<u8> =
        serde_json::from_value(raw["transitional_stash_log"].clone()).unwrap();
    fs::write(target.join(".git/logs/refs/stash"), transitional).unwrap();
    engine.recover(&journal).unwrap();
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), prior_index);
    assert_eq!(
        fs::read(target.join(".git/logs/refs/stash")).unwrap(),
        prior_log
    );
    assert_eq!(git(&target, &["rev-parse", "refs/stash"]), prior_tip);
}
#[test]
fn fully_remote_history_has_empty_pack_and_staged_binary_mode_is_exact() {
    let f = Fixture::new();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    assert!(capture.metadata.packed_objects.is_empty());
    assert_eq!(capture.pack.len(), 32);
    assert!(!capture.metadata.prerequisites.is_empty());
    fs::write(f.source.join("binary.dat"), [0, 255, 42, 0, 128]).unwrap();
    git(&f.source, &["add", "binary.dat"]);
    git(&f.source, &["update-index", "--chmod=+x", "binary.dat"]);
    git(&f.source, &["rm", "--cached", "base.txt"]);
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    let plan = engine.plan_restore(&target, &capture).unwrap();
    engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    assert_eq!(
        git(&target, &["ls-files", "--stage"]),
        git(&f.source, &["ls-files", "--stage"])
    );
    let metadata = serde_json::to_vec(&capture.metadata).unwrap();
    let round =
        bunker_git::Capture::from_parts(&metadata, capture.pack.clone(), &engine.limits).unwrap();
    assert_eq!(round.fingerprint().unwrap(), capture.fingerprint().unwrap());
}
#[cfg(unix)]
#[test]
fn restore_hooks_and_fsmonitor_never_execute() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    let marker = f.root.join("restore-hook-executed");
    let hook = target.join(".git/hooks/reference-transaction");
    fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &target,
        &["config", "core.fsmonitor", hook.to_str().unwrap()],
    );
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    engine.recover(&journal).unwrap();
    assert!(!marker.exists());
}
#[cfg(unix)]
#[test]
fn source_changes_during_capture_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let marker = f.root.join("changed");
    let wrapper = f.root.join("git-wrapper");
    let real_git = "/usr/bin/git";
    fs::write(&wrapper, format!("#!/bin/sh\nif [ ! -e '{}' ]; then\n  touch '{}'\n  printf '\\n' >> '{}'\nfi\nexec {real_git} \"$@\"\n", marker.display(), marker.display(), f.source.join(".git/HEAD").display())).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let engine = GitBackup {
        git_executable: wrapper,
        ..Default::default()
    };
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap_err()
        .to_string()
        .contains("source changed"));
}
#[test]
fn unsupported_formats_and_stash_corruption_are_explicit() {
    let f = Fixture::new();
    let engine = GitBackup::default();
    git(&f.source, &["config", "core.repositoryformatversion", "1"]);
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap_err()
        .to_string()
        .contains("unsupported Git repository format"));
    git(&f.source, &["config", "core.repositoryformatversion", "0"]);
    f.local_changes();
    fs::remove_file(f.source.join(".git/logs/refs/stash")).unwrap();
    assert!(engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap_err()
        .to_string()
        .contains("stash reflog missing"));
}

#[test]
fn recovery_can_resume_after_its_own_ref_transaction() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    fs::write(target.join("base.txt"), "prior target stash").unwrap();
    git(&target, &["stash", "push"]);
    let prior_tip = git(&target, &["rev-parse", "refs/stash"]);
    let prior_log = fs::read(target.join(".git/logs/refs/stash")).unwrap();
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    let desired_log = fs::read(target.join(".git/logs/refs/stash")).unwrap();
    // Model interrupted rollback: refs were restored, index and stash log not yet.
    git(&target, &["update-ref", "refs/stash", &prior_tip]);
    git(&target, &["update-ref", "-d", "refs/heads/unpublished"]);
    let mut rollback_log = desired_log;
    rollback_log.extend(
        format!(
            "{} {prior_tip} Bunker <restore@bunker.invalid> 1 +0000\tbunker restore\n",
            capture.metadata.stash.last().unwrap()
        )
        .as_bytes(),
    );
    fs::write(target.join(".git/logs/refs/stash"), rollback_log).unwrap();
    engine.recover(&journal).unwrap();
    assert_eq!(
        fs::read(target.join(".git/logs/refs/stash")).unwrap(),
        prior_log
    );
    assert_eq!(git(&target, &["diff", "--cached", "--name-only"]), "");
}
#[test]
fn automatic_rollback_and_retained_journal_on_git_failure() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("target");
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let before_index = fs::read(target.join(".git/index")).unwrap();
    let before_config = fs::read(target.join(".git/config")).unwrap();
    // Ref namespace conflicts are rejected during preflight, before journaling.
    let mut conflicting = capture.clone();
    let tip = conflicting
        .metadata
        .heads
        .remove("refs/heads/unpublished")
        .unwrap();
    conflicting
        .metadata
        .heads
        .insert("refs/heads/main/child".into(), tip);
    assert!(engine
        .plan_restore(&target, &conflicting)
        .unwrap_err()
        .to_string()
        .contains("namespace conflict"));
    // Model another process taking a ref lock after planning. Forward transaction
    // and automatic rollback must fail explicitly and retain recovery preimages.
    let lock = target.join(".git/refs/heads/unpublished.lock");
    let failure = engine
        .apply_restore(&plan, &capture, |_| {
            fs::write(&lock, b"fixture lock")?;
            Ok(())
        })
        .unwrap_err();
    assert!(
        failure.journal.is_some()
            && !failure.rollback_completed
            && failure.recovery_error.is_some()
    );
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), before_index);
    assert_eq!(fs::read(target.join(".git/config")).unwrap(), before_config);
    assert_eq!(
        git(&target, &["rev-parse", "main"]),
        plan.prior_refs["refs/heads/main"]
            .as_ref()
            .unwrap()
            .as_str()
    );
    // Explicit recovery must leave config restored while the competing ref lock
    // continues to block recovery.
    assert!(engine.recover(failure.journal.as_ref().unwrap()).is_err());
    assert_eq!(fs::read(target.join(".git/config")).unwrap(), before_config);
    fs::remove_file(lock).unwrap();
    engine.recover(failure.journal.as_ref().unwrap()).unwrap();
}

#[test]
fn every_authorization_boundary_can_expire_and_restore_original_state() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("expiry-target");
    let original_config = fs::read(target.join(".git/config")).unwrap();
    let original_index = fs::read(target.join(".git/index")).unwrap();
    let original_head = git(&target, &["rev-parse", "HEAD"]);
    let objects = capture.metadata.packed_objects.len();
    assert!(objects > 1 && !capture.metadata.stash.is_empty());
    // config, first/last object, refs, index, reflog, original-config restoration.
    for deny_at in [
        1,
        2,
        objects + 1,
        objects + 2,
        objects + 3,
        objects + 4,
        objects + 5,
    ] {
        let plan = engine.plan_restore(&target, &capture).unwrap();
        let mut calls = 0;
        let mut persisted = None;
        let failure = engine
            .apply_restore_with_authorization(
                &plan,
                &capture,
                |j| {
                    persisted = Some(j.clone());
                    Ok(())
                },
                || {
                    calls += 1;
                    anyhow::ensure!(calls < deny_at, "approval expired");
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(calls, deny_at);
        assert!(persisted.is_some());
        assert!(failure.rollback_completed, "{failure:?}");
        assert_eq!(
            fs::read(target.join(".git/config")).unwrap(),
            original_config
        );
        assert_eq!(fs::read(target.join(".git/index")).unwrap(), original_index);
        assert_eq!(git(&target, &["rev-parse", "HEAD"]), original_head);
        assert!(!target.join(".git/logs/refs/stash").exists());
        assert!(!target.join(".git/config.lock").exists());
        engine.recover(persisted.as_ref().unwrap()).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn config_isolation_is_journaled_restartable_and_preserves_modes() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("config-target");
    let config = target.join(".git/config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
    let original = fs::read(&config).unwrap();
    let mut isolated = None;
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine
        .apply_restore_with_authorization(
            &plan,
            &capture,
            |_| Ok(()),
            || {
                let bytes = fs::read(&config)?;
                if bytes != original {
                    isolated = Some(bytes);
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(fs::read(&config).unwrap(), original);
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );
    // Model a process crash after forward state installation but before config cleanup.
    fs::write(&config, isolated.unwrap()).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    engine.recover(&journal).unwrap();
    assert_eq!(fs::read(&config).unwrap(), original);
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );
    // A rollback interrupted between original bytes and chmod is also resumable.
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    engine.recover(&journal).unwrap();
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    let index = fs::read(target.join(".git/index")).unwrap();
    let head = git(&target, &["rev-parse", "HEAD"]);
    fs::write(
        &config,
        b"[core]\nrepositoryformatversion = 0\n# later user edits\n",
    )
    .unwrap();
    assert!(engine
        .recover(&journal)
        .unwrap_err()
        .to_string()
        .contains("config changed"));
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), index);
    assert_eq!(git(&target, &["rev-parse", "HEAD"]), head);
}

#[test]
fn target_config_change_invalidates_confirmation_and_absent_config_remains_absent() {
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("config-change-target");
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let config = target.join(".git/config");
    let mut bytes = fs::read(&config).unwrap();
    bytes.extend_from_slice(b"\n# changed\n");
    fs::write(&config, &bytes).unwrap();
    let mut journaled = false;
    assert!(engine
        .apply_restore(&plan, &capture, |_| {
            journaled = true;
            Ok(())
        })
        .is_err());
    assert!(!journaled);
    assert_eq!(fs::read(&config).unwrap(), bytes);
    fs::remove_file(&config).unwrap();
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    assert!(!config.exists());
    engine.recover(&journal).unwrap();
    assert!(!config.exists());
}

#[test]
fn nested_agent_configs_in_index_and_deleted_local_history_are_refused() {
    // Include desktop/user and .agents paths that the old Git-only matcher omitted.
    for name in [
        "nested/.claude/settings.json",
        "nested/.claude/settings.local.json",
        "nested/.mcp.json",
        "nested/.codex/config.toml",
        "nested/.agents/config.toml",
        "nested/.copilot/mcp-config.json",
        "nested/.vscode/settings.json",
        "nested/.kiro/settings/mcp.json",
        "nested/Cursor/User/settings.json",
        "nested/Code/User/mcp.json",
        "nested/Kiro/User/settings.json",
    ] {
        let f = Fixture::new();
        let path = f.source.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let secret = "fixture-literal-private-value";
        let bytes = if name.ends_with(".toml") {
            format!("apiKey = \"{secret}\"\n")
        } else {
            format!(r#"{{"apiKey":"{secret}"}}"#)
        };
        fs::write(&path, bytes).unwrap();
        git(&f.source, &["add", name]);
        let engine = GitBackup::default();
        let error = engine
            .capture(&f.source, &CapturePolicy::default())
            .unwrap_err();
        assert!(error.to_string().contains("unsafe-path"), "{name}: {error}");
        assert!(!format!("{error:#}").contains(secret));
        git(&f.source, &["commit", "-m", "unsafe nested fixture"]);
        git(&f.source, &["rm", name]);
        git(&f.source, &["commit", "-m", "delete unsafe nested fixture"]);
        let error = engine
            .capture(&f.source, &CapturePolicy::default())
            .unwrap_err();
        assert!(error.to_string().contains("unsafe-path"), "{name}: {error}");
        assert!(!format!("{error:#}").contains(secret));
    }
}

#[test]
fn safe_nested_agent_config_preserves_exact_git_object_ids() {
    let f = Fixture::new();
    let name = "nested/.claude/settings.json";
    fs::create_dir_all(f.source.join("nested/.claude")).unwrap();
    fs::write(
        f.source.join(name),
        b"{\"apiKey\":\"${env:FIXTURE_KEY}\"}\n",
    )
    .unwrap();
    git(&f.source, &["add", name]);
    git(&f.source, &["commit", "-m", "safe nested reference"]);
    let commit = git(&f.source, &["rev-parse", "HEAD"]);
    let blob = git(&f.source, &["rev-parse", &format!("HEAD:{name}")]);
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    assert_eq!(capture.metadata.heads["refs/heads/main"], commit);
    assert_eq!(
        capture
            .metadata
            .index
            .iter()
            .find(|e| e.path == name)
            .unwrap()
            .oid,
        blob
    );
    let target = f.clone_target("safe-nested-target");
    let plan = engine.plan_restore(&target, &capture).unwrap();
    engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    assert_eq!(git(&target, &["rev-parse", "HEAD"]), commit);
    assert_eq!(git(&target, &["rev-parse", &format!(":{name}")]), blob);
}

fn write_packed_branches(root: &Path, names: &[&str], oid: &str) {
    // Writing packed refs is essential: loose aliases cannot coexist on macOS.
    // Retain the clone's packed remote refs so origin/HEAD stays valid.
    let path = root.join(".git/packed-refs");
    let old = fs::read_to_string(&path).unwrap_or_default();
    let mut refs: std::collections::BTreeMap<_, _> = old
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(_, name)| name.starts_with("refs/") && !name.starts_with("refs/heads/"))
        .map(|(id, name)| (name.to_owned(), id.to_owned()))
        .collect();
    for name in names {
        refs.insert(format!("refs/heads/{name}"), oid.to_owned());
    }
    let mut bytes = String::from("# pack-refs with: sorted\n");
    for (name, id) in refs {
        bytes.push_str(&format!("{id} {name}\n"));
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn packed_unicode_ref_aliases_and_ancestor_aliases_refuse_before_mutation() {
    for names in [
        ["\u{e9}", "e\u{301}"],
        ["\u{c9}", "\u{e9}"],
        ["\u{e9}/left", "e\u{301}/right"],
        ["\u{c9}/left", "\u{e9}/right"],
        ["Topic/left", "topic/right"],
    ] {
        let f = Fixture::new();
        let engine = GitBackup::default();
        let capture = engine
            .capture(&f.source, &CapturePolicy::default())
            .unwrap();
        let oid = &capture.metadata.heads["refs/heads/main"];
        let target = f.clone_target("alias-target");
        let plan = engine.plan_restore(&target, &capture).unwrap();
        let before_config = fs::read(target.join(".git/config")).unwrap();
        let before_index = fs::read(target.join(".git/index")).unwrap();
        let before_head = git(&target, &["rev-parse", "HEAD"]);

        // Actual source capture, not merely fabricated restore metadata.
        write_packed_branches(&f.source, &names, oid);
        let error = engine
            .capture(&f.source, &CapturePolicy::default())
            .unwrap_err();
        assert!(error.to_string().contains("aliases"), "{error}");

        // An authenticated artifact still needs namespace validation.
        let mut artifact = capture.clone();
        for name in names {
            artifact
                .metadata
                .heads
                .insert(format!("refs/heads/{name}"), oid.clone());
        }
        assert!(engine
            .plan_restore(&target, &artifact)
            .unwrap_err()
            .to_string()
            .contains("aliases"));
        let failure = engine
            .apply_restore(&plan, &artifact, |_| panic!("must not journal aliases"))
            .unwrap_err();
        assert!(failure.journal.is_none());

        // Validate target-only aliases, including aliases in packed refs.
        write_packed_branches(&target, &names, oid);
        let packed = fs::read(target.join(".git/packed-refs")).unwrap();
        assert!(engine
            .plan_restore(&target, &capture)
            .unwrap_err()
            .to_string()
            .contains("aliases"));
        let failure = engine
            .apply_restore(&plan, &capture, |_| panic!("must not journal aliases"))
            .unwrap_err();
        assert!(failure.journal.is_none());
        assert_eq!(fs::read(target.join(".git/packed-refs")).unwrap(), packed);

        // Each side alone is valid; their combined final namespace is not.
        write_packed_branches(&target, &names[..1], oid);
        artifact
            .metadata
            .heads
            .remove(&format!("refs/heads/{}", names[0]));
        assert!(engine
            .plan_restore(&target, &artifact)
            .unwrap_err()
            .to_string()
            .contains("aliases"));
        assert_eq!(fs::read(target.join(".git/config")).unwrap(), before_config);
        assert_eq!(fs::read(target.join(".git/index")).unwrap(), before_index);
        assert_eq!(git(&target, &["rev-parse", "HEAD"]), before_head);
        assert!(!target.join(".git/bunker-git.lock").exists());
        assert!(!target.join(".git/config.lock").exists());
        assert!(!target.join(".git/index.lock").exists());
    }
}

#[test]
fn failed_ref_guards_restore_isolated_config_but_preserve_later_config_edits() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("guard-target");
    let config = target.join(".git/config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
    let original = fs::read(&config).unwrap();
    let mut isolated = None;
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine
        .apply_restore_with_authorization(
            &plan,
            &capture,
            |_| Ok(()),
            || {
                let bytes = fs::read(&config)?;
                if bytes != original {
                    isolated = Some(bytes);
                }
                Ok(())
            },
        )
        .unwrap();
    let isolated = isolated.unwrap();
    let head = git(&target, &["rev-parse", "HEAD"]);
    let index = fs::read(target.join(".git/index")).unwrap();

    // Legacy interrupted apply with an invalid packed namespace: recover fails
    // before touching refs/index, but still restores original config and mode.
    write_packed_branches(&target, &["\u{e9}", "e\u{301}"], &head);
    fs::write(&config, &isolated).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(engine
        .recover(&journal)
        .unwrap_err()
        .to_string()
        .contains("aliases"));
    assert_eq!(fs::read(&config).unwrap(), original);
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), index);

    fs::remove_file(target.join(".git/packed-refs")).unwrap();
    git(&target, &["update-ref", "refs/heads/unpublished", &head]);
    fs::write(&config, &isolated).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(engine
        .recover(&journal)
        .unwrap_err()
        .to_string()
        .contains("refs changed"));
    assert_eq!(fs::read(&config).unwrap(), original);
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(git(&target, &["rev-parse", "unpublished"]), head);
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), index);

    // Repeating failed recovery must never overwrite a later byte or mode edit.
    for (bytes, mode) in [
        (
            b"[core]\nrepositoryformatversion = 0\n# later edit\n".as_slice(),
            0o640,
        ),
        (isolated.as_slice(), 0o644),
    ] {
        fs::write(&config, bytes).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(mode)).unwrap();
        assert!(engine
            .recover(&journal)
            .unwrap_err()
            .to_string()
            .contains("config changed"));
        assert_eq!(fs::read(&config).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            mode
        );
        assert_eq!(fs::read(target.join(".git/index")).unwrap(), index);
    }
}

#[test]
fn failed_rollback_plumbing_cleans_config_and_rechecks_for_intervening_edits() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.local_changes();
    let engine = GitBackup::default();
    let capture = engine
        .capture(&f.source, &CapturePolicy::default())
        .unwrap();
    let target = f.clone_target("rollback-plumbing-target");
    let config = target.join(".git/config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
    let original = fs::read(&config).unwrap();
    let plan = engine.plan_restore(&target, &capture).unwrap();
    let journal = engine.apply_restore(&plan, &capture, |_| Ok(())).unwrap();
    let index = fs::read(target.join(".git/index")).unwrap();
    let refs = git(&target, &["show-ref"]);
    let wrapper = f.root.join("failing-git");
    // Only target update-ref fails; all isolated-view validation still runs.
    fs::write(&wrapper, b"#!/bin/sh\nfor arg do\n if [ \"$arg\" = update-ref ]; then exit 1; fi\ndone\nexec /usr/bin/git \"$@\"\n").unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let failing = GitBackup {
        git_executable: wrapper.clone(),
        ..Default::default()
    };
    assert!(failing
        .recover(&journal)
        .unwrap_err()
        .to_string()
        .contains("Git plumbing failed"));
    assert_eq!(fs::read(&config).unwrap(), original);
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), index);
    assert_eq!(git(&target, &["show-ref"]), refs);

    // Simulate a writer violating exclusive access after the initial config guard.
    // The final cleanup guard must retain the edit and report both failures.
    fs::write(&wrapper, b"#!/bin/sh\nfor arg do\n if [ \"$arg\" = update-ref ]; then\n  printf '%s\\n' '# later fixture config edit' >> \"$3/config\"\n  exit 1\n fi\ndone\nexec /usr/bin/git \"$@\"\n").unwrap();
    let error = failing.recover(&journal).unwrap_err().to_string();
    assert!(error.contains("Git plumbing failed"));
    assert!(error.contains("config cleanup failed: recovery refused: config changed"));
    assert!(fs::read(&config)
        .unwrap()
        .ends_with(b"# later fixture config edit\n"));
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(target.join(".git/index")).unwrap(), index);

    // Once the fixture's edit is explicitly removed, the retained journal works.
    fs::write(&config, original).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
    engine.recover(&journal).unwrap();
}
