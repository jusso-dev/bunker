//! Integration fixtures never use live repositories, credentials, or network remotes.
use bunker::{policy::Policy, repository::Repository};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=always",
        ])
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
struct Fixture {
    _temp: tempfile::TempDir,
    repo: Repository,
    source: PathBuf,
    target: PathBuf,
    baseline: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        // macOS /var is a symlink; the Git contract requires canonical ancestors.
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("source");
        let target = root.join("target");
        fs::create_dir(&source).unwrap();
        git(&source, &["init", "-b", "main"]);
        fs::write(source.join("a.txt"), "remote-known base\n").unwrap();
        fs::write(source.join("b.txt"), "base b\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "base"]);
        let baseline = git(&source, &["rev-parse", "HEAD"]);
        git(
            &source,
            &["update-ref", "refs/remotes/origin/main", &baseline],
        );
        git(
            &root,
            &[
                "clone",
                "--no-hardlinks",
                source.to_str().unwrap(),
                target.to_str().unwrap(),
            ],
        );
        let repo = Repository::init(&root.join("vault"), "fixture-only").unwrap();
        Self {
            _temp: temp,
            repo,
            source,
            target,
            baseline,
        }
    }
    fn local_state(&self) {
        fs::write(self.source.join("a.txt"), "unpublished commit content\n").unwrap();
        git(&self.source, &["add", "a.txt"]);
        git(&self.source, &["commit", "-m", "unpublished fixture"]);
        git(&self.source, &["branch", "private-topic"]);
        for i in 0..3 {
            fs::write(self.source.join("a.txt"), format!("stash {i}\n")).unwrap();
            fs::write(
                self.source.join(format!("stash-{i}.txt")),
                format!("untracked stash {i}\n"),
            )
            .unwrap();
            git(&self.source, &["stash", "push", "-u", "-m", "fixture"]);
        }
        fs::write(self.source.join("a.txt"), "staged source bytes\n").unwrap();
        git(&self.source, &["add", "a.txt"]);
        fs::write(self.source.join("a.txt"), "working source bytes\n").unwrap();
        fs::write(self.source.join("b.txt"), "working b\n").unwrap();
        fs::write(self.source.join("new.txt"), "ordinary untracked\n").unwrap();
    }
    fn snapshot(&self) -> bunker::repository::Manifest {
        self.repo
            .snapshot(&self.source, &Policy::default(), None, None, "fixture")
            .unwrap()
    }
    fn transaction(&self) -> String {
        fs::read_dir(self.repo.root().join("transactions"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name()
            .into_string()
            .unwrap()
    }
}

#[test]
fn captures_encrypted_git_and_restores_branches_stash_index_and_working_bytes() {
    let f = Fixture::new();
    f.local_state();
    let snapshot = f.snapshot();
    let artifact = snapshot.git.as_ref().expect("Git artifact");
    assert!(!artifact.pack.chunks.is_empty());
    let dependencies = f.repo.snapshot_chunks(&snapshot).unwrap();
    assert!(artifact
        .metadata
        .chunks
        .iter()
        .chain(&artifact.pack.chunks)
        .all(|c| dependencies.contains(c)));
    f.repo.verify(&snapshot.id).unwrap();
    let again = f.snapshot();
    assert_eq!(artifact.pack.chunks, again.git.unwrap().pack.chunks);
    for entry in walkdir::WalkDir::new(f.repo.root())
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
    {
        let bytes = fs::read(entry.path()).unwrap();
        for marker in [
            "private-topic",
            "unpublished commit content",
            "staged source bytes",
        ] {
            assert!(!bytes.windows(marker.len()).any(|b| b == marker.as_bytes()));
        }
    }
    let plan = f.repo.plan(&snapshot.id, &f.target, None).unwrap();
    let gp = plan.git.as_ref().unwrap();
    assert!(gp.prerequisite_count > 0);
    assert!(gp.desired_refs.contains_key("refs/heads/private-topic"));
    assert_eq!(gp.stash_oldest_first.len(), 3);
    assert!(serde_json::to_string(&plan)
        .unwrap()
        .contains("desired_index_fingerprint"));
    f.repo
        .restore(&snapshot.id, &f.target, None, &plan.confirmation)
        .unwrap();
    assert_eq!(
        git(&f.target, &["rev-parse", "main"]),
        git(&f.source, &["rev-parse", "main"])
    );
    assert_eq!(
        git(&f.target, &["rev-parse", "private-topic"]),
        git(&f.source, &["rev-parse", "private-topic"])
    );
    assert_eq!(
        git(&f.target, &["stash", "list", "--format=%H"]),
        git(&f.source, &["stash", "list", "--format=%H"])
    );
    assert_eq!(git(&f.target, &["show", ":a.txt"]), "staged source bytes");
    assert_eq!(
        fs::read(f.target.join("a.txt")).unwrap(),
        b"working source bytes\n"
    );
    assert_eq!(
        fs::read(f.target.join("new.txt")).unwrap(),
        b"ordinary untracked\n"
    );
    let transaction = f.transaction();
    assert_eq!(
        f.repo.restore_journal(&transaction).unwrap()["status"],
        "completed"
    );
    let recovery = f.repo.plan_recovery(&transaction).unwrap();
    assert!(recovery.restores_git);
    f.repo
        .recover_transaction(&transaction, &recovery.confirmation)
        .unwrap();
    assert_eq!(git(&f.target, &["rev-parse", "HEAD"]), f.baseline);
    assert!(git(&f.target, &["status", "--porcelain"]).is_empty());
    assert!(!f.target.join("new.txt").exists());
    // Restartable rollback also accepts a fully rolled-back state.
    let recovery = f.repo.plan_recovery(&transaction).unwrap();
    f.repo
        .recover_transaction(&transaction, &recovery.confirmation)
        .unwrap();
}

#[test]
fn export_inventory_recovers_git_and_corrupt_git_does_not_break_file_restore() {
    let f = Fixture::new();
    f.local_state();
    let snapshot = f.snapshot();
    let exported = f.target.parent().unwrap().join("exported");
    fs::create_dir_all(exported.join("chunks")).unwrap();
    fs::create_dir(exported.join("snapshots")).unwrap();
    for dir in ["audit", "transactions", "requests"] {
        fs::create_dir(exported.join(dir)).unwrap();
    }
    let mut paths = vec![
        "repository.json".to_owned(),
        format!("snapshots/{}", snapshot.id),
    ];
    paths.extend(
        f.repo
            .snapshot_chunks(&snapshot)
            .unwrap()
            .iter()
            .map(|id| format!("chunks/{id}")),
    );
    for path in paths {
        fs::write(
            exported.join(&path),
            f.repo.encrypted_object(&path).unwrap(),
        )
        .unwrap();
    }
    let recovered = Repository::open(&exported, "fixture-only").unwrap();
    recovered.verify(&snapshot.id).unwrap();
    let plan = recovered.plan(&snapshot.id, &f.target, None).unwrap();
    assert!(plan.git.is_some());
    let pack_chunk = &snapshot.git.as_ref().unwrap().pack.chunks[0];
    fs::write(exported.join("chunks").join(pack_chunk), b"corrupt").unwrap();
    assert!(recovered.verify(&snapshot.id).is_err());
    assert!(recovered.plan(&snapshot.id, &f.target, None).is_err());
    let plan = recovered
        .plan(&snapshot.id, &f.target, Some("a.txt"))
        .unwrap();
    assert!(plan.git.is_none());
    recovered
        .restore(&snapshot.id, &f.target, Some("a.txt"), &plan.confirmation)
        .unwrap();
    assert_eq!(git(&f.target, &["rev-parse", "HEAD"]), f.baseline);
    assert_eq!(git(&f.target, &["show", ":a.txt"]), "remote-known base");
}

#[test]
fn unsupported_git_is_isolated_and_ordinary_workspaces_have_no_git_artifact() {
    let f = Fixture::new();
    fs::write(f.source.join(".env"), "PASSWORD=fixture-only\n").unwrap();
    git(&f.source, &["add", ".env"]);
    git(&f.source, &["commit", "-m", "unsafe fixture"]);
    let snapshot = f.snapshot();
    assert!(snapshot.git.is_none());
    assert!(snapshot.files.iter().any(|x| x.path == "a.txt"));
    assert!(snapshot
        .diagnostics
        .iter()
        .any(|d| d.path == ".git" && d.reason == "git_capture_failed_or_unsupported"));
    assert!(!snapshot.files.iter().any(|x| x.path == ".env"));
    let plain = f.source.parent().unwrap().join("plain");
    fs::create_dir(&plain).unwrap();
    fs::write(plain.join("a.txt"), "plain").unwrap();
    let snapshot = f
        .repo
        .snapshot(&plain, &Policy::default(), None, None, "fixture")
        .unwrap();
    assert!(snapshot.git.is_none());
    assert!(!snapshot.diagnostics.iter().any(|d| d.path == ".git"));
}

#[test]
fn dirty_missing_prerequisite_and_stale_git_plans_refuse_before_workspace_mutations() {
    let f = Fixture::new();
    f.local_state();
    let snapshot = f.snapshot();
    let plan = f.repo.plan(&snapshot.id, &f.target, None).unwrap();
    git(&f.target, &["branch", "new-local-branch"]);
    assert!(f
        .repo
        .restore(&snapshot.id, &f.target, None, &plan.confirmation)
        .is_err());
    assert_eq!(
        fs::read(f.target.join("a.txt")).unwrap(),
        b"remote-known base\n"
    );
    fs::write(f.target.join("a.txt"), "dirty").unwrap();
    assert!(f.repo.plan(&snapshot.id, &f.target, None).is_err());
    let empty = f.source.parent().unwrap().join("empty");
    fs::create_dir(&empty).unwrap();
    git(&empty, &["init", "-b", "main"]);
    assert!(f
        .repo
        .plan(&snapshot.id, &empty, None)
        .unwrap_err()
        .to_string()
        .contains("prerequisite"));
    assert!(!empty.join("a.txt").exists());
}

#[test]
fn expiry_after_staging_and_partial_apply_leave_guarded_recoverable_journals() {
    for expire_call in [2, 3, usize::MAX] {
        let f = Fixture::new();
        f.local_state();
        let snapshot = f.snapshot();
        let plan = f.repo.plan(&snapshot.id, &f.target, None).unwrap();
        let mut calls = 0;
        let result = f.repo.restore_with_authorization(
            &snapshot.id,
            &f.target,
            None,
            &plan.confirmation,
            false,
            || {
                calls += 1;
                let file_installed =
                    fs::read(f.target.join("a.txt")).unwrap() == b"working source bytes\n";
                anyhow::ensure!(calls < expire_call && !file_installed, "approval expired");
                Ok(())
            },
        );
        assert!(result.is_err());
        let transaction = f.transaction();
        assert_eq!(
            f.repo.restore_journal(&transaction).unwrap()["status"],
            "interrupted"
        );
        if expire_call == usize::MAX {
            assert_eq!(
                f.repo.restore_journal(&transaction).unwrap()["git_applied"],
                true
            );
            assert_eq!(
                fs::read(f.target.join("a.txt")).unwrap(),
                b"working source bytes\n"
            );
        }
        if expire_call <= 3 {
            assert_eq!(git(&f.target, &["rev-parse", "HEAD"]), f.baseline);
            assert_eq!(
                fs::read(f.target.join("a.txt")).unwrap(),
                b"remote-known base\n"
            );
        }
        let recovery = f.repo.plan_recovery(&transaction).unwrap();
        f.repo
            .recover_transaction(&transaction, &recovery.confirmation)
            .unwrap();
        assert_eq!(git(&f.target, &["rev-parse", "HEAD"]), f.baseline);
        assert!(git(&f.target, &["status", "--porcelain"]).is_empty());
    }
}

#[test]
fn recovery_refuses_subsequent_file_and_git_edits_and_stale_consent() {
    let f = Fixture::new();
    f.local_state();
    let snapshot = f.snapshot();
    let plan = f.repo.plan(&snapshot.id, &f.target, None).unwrap();
    f.repo
        .restore(&snapshot.id, &f.target, None, &plan.confirmation)
        .unwrap();
    let transaction = f.transaction();
    let recovery = f.repo.plan_recovery(&transaction).unwrap();
    fs::write(f.target.join("a.txt"), "new user edits").unwrap();
    assert!(f
        .repo
        .recover_transaction(&transaction, &recovery.confirmation)
        .is_err());
    assert_eq!(fs::read(f.target.join("a.txt")).unwrap(), b"new user edits");
    fs::write(f.target.join("a.txt"), "working source bytes\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(f.target.join("a.txt"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(f.repo.plan_recovery(&transaction).is_err());
        fs::set_permissions(f.target.join("a.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    git(
        &f.target,
        &["update-ref", "refs/heads/private-topic", &f.baseline],
    );
    assert!(f
        .repo
        .recover_transaction(&transaction, &recovery.confirmation)
        .is_err());
    let recovery = f.repo.plan_recovery(&transaction).unwrap();
    assert!(f
        .repo
        .recover_transaction(&transaction, &recovery.confirmation)
        .is_err());
    assert_eq!(
        fs::read(f.target.join("a.txt")).unwrap(),
        b"working source bytes\n"
    );
}

#[test]
fn cooperative_lock_and_policy_budget_fail_git_in_isolation() {
    let f = Fixture::new();
    let lock = f.source.join(".git/bunker-capture.lock");
    fs::write(&lock, "another operation").unwrap();
    let snapshot = f.snapshot();
    assert!(snapshot.git.is_none());
    assert_eq!(fs::read(&lock).unwrap(), b"another operation");
    assert!(snapshot.diagnostics.iter().any(|d| d.path == ".git"));
    fs::remove_file(lock).unwrap();
    let policy = Policy {
        size_cap_bytes: 128,
        max_file_bytes: 128,
        ..Policy::default()
    };
    let snapshot = f
        .repo
        .snapshot(&f.source, &policy, None, None, "fixture")
        .unwrap();
    assert!(snapshot.git.is_none());
    assert_eq!(snapshot.files.len(), 2);
    assert!(snapshot
        .diagnostics
        .iter()
        .any(|d| d.reason == "git_capture_size_cap"));
    let snapshot = f.snapshot();
    fs::write(
        f.target.join(".git/bunker-capture.lock"),
        "another operation",
    )
    .unwrap();
    assert!(f.repo.plan(&snapshot.id, &f.target, None).is_err());
    // File-only plans neither claim Git exclusion nor mutate Git.
    let plan = f.repo.plan(&snapshot.id, &f.target, Some("a.txt")).unwrap();
    assert!(plan.git.is_none());
    f.repo
        .restore(&snapshot.id, &f.target, Some("a.txt"), &plan.confirmation)
        .unwrap();
    assert_eq!(
        fs::read(f.target.join(".git/bunker-capture.lock")).unwrap(),
        b"another operation"
    );
}

#[test]
fn source_and_target_hooks_and_config_includes_never_run() {
    let f = Fixture::new();
    f.local_state();
    let marker = f.source.parent().unwrap().join("executed");
    for root in [&f.source, &f.target] {
        let hook = root.join(".git/hooks/reference-transaction");
        fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = root.join(".git/config");
        let mut bytes = fs::read(&config).unwrap();
        bytes.extend_from_slice(
            format!(
                "\n[include]\npath = {}\n[core]\nfsmonitor = {}\n",
                hook.display(),
                hook.display()
            )
            .as_bytes(),
        );
        fs::write(config, bytes).unwrap();
    }
    let snapshot = f.snapshot();
    assert!(snapshot.git.is_some());
    let plan = f.repo.plan(&snapshot.id, &f.target, None).unwrap();
    f.repo
        .restore(&snapshot.id, &f.target, None, &plan.confirmation)
        .unwrap();
    let id = f.transaction();
    let recovery = f.repo.plan_recovery(&id).unwrap();
    f.repo
        .recover_transaction(&id, &recovery.confirmation)
        .unwrap();
    assert!(!marker.exists());
}

#[test]
fn nested_secret_configs_and_packed_ref_aliases_never_produce_git_artifacts() {
    let f = Fixture::new();
    let name = "nested/.claude/settings.json";
    fs::create_dir_all(f.source.join("nested/.claude")).unwrap();
    fs::write(
        f.source.join(name),
        br#"{"apiKey":"fixture-only-not-a-real-key"}"#,
    )
    .unwrap();
    git(&f.source, &["add", name]);
    let assert_refused = |snapshot: bunker::repository::Manifest| {
        assert!(snapshot.git.is_none());
        assert!(snapshot
            .diagnostics
            .iter()
            .any(|d| { d.path == ".git" && d.reason == "git_capture_failed_or_unsupported" }));
    };
    assert_refused(f.snapshot());
    git(&f.source, &["commit", "-m", "nested config fixture"]);
    git(&f.source, &["rm", name]);
    git(&f.source, &["commit", "-m", "delete nested config fixture"]);
    assert_refused(f.snapshot());

    let aliases = Fixture::new();
    let oid = &aliases.baseline;
    fs::write(
        aliases.source.join(".git/packed-refs"),
        format!("# pack-refs with: sorted\n{oid} refs/heads/e\u{301}\n{oid} refs/heads/\u{e9}\n"),
    )
    .unwrap();
    assert_refused(aliases.snapshot());
}
