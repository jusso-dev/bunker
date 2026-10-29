//! Disposable offline repositories only. No fetches, pushes or user configuration.
use bunker_git::{git_alerts, Capture, CapturePolicy, GitBackup, GitDiagnostic, Limits};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}
fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "fixture Git failed");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        git(&root, &["init", "-b", "main"]);
        let fixture = Self { _temp: temp, root };
        fixture.commit("base");
        fixture
    }
    fn commit(&self, name: &str) -> String {
        git(&self.root, &["commit", "--allow-empty", "-m", name]);
        git(&self.root, &["rev-parse", "HEAD"])
    }
    fn capture(&self, previous: Option<&Capture>) -> Capture {
        GitBackup::default()
            .capture_with_previous(
                &self.root,
                &CapturePolicy::default(),
                previous.map(|c| &c.metadata),
            )
            .unwrap()
    }
}

#[test]
fn no_change_fast_forward_rewrite_and_deletion_are_distinct() {
    let f = Fixture::new();
    let a = f.capture(None);
    let same = f.capture(Some(&a));
    let summary = git_alerts(&a.metadata, &same.metadata).unwrap();
    assert_eq!(summary.unchanged_refs, 1);
    assert!(summary.diagnostics.is_empty());
    f.commit("forward");
    let forward = f.capture(Some(&same));
    assert_eq!(
        git_alerts(&same.metadata, &forward.metadata)
            .unwrap()
            .fast_forwards,
        1
    );
    git(
        &f.root,
        &[
            "update-ref",
            "refs/heads/main",
            &a.metadata.heads["refs/heads/main"],
        ],
    );
    git(&f.root, &["branch", "temporary"]);
    let rewrite = f.capture(Some(&forward));
    assert_eq!(
        git_alerts(&forward.metadata, &rewrite.metadata)
            .unwrap()
            .local_branch_rewrites,
        1
    );
    git(&f.root, &["branch", "-D", "temporary"]);
    let deleted = f.capture(Some(&rewrite));
    let summary = git_alerts(&rewrite.metadata, &deleted.metadata).unwrap();
    assert_eq!(summary.branch_deletions, 1);
    assert_eq!(summary.local_branch_rewrites, 0);
    assert!(summary.diagnostics.is_empty());
}

#[test]
fn missing_old_commit_is_unknown_even_when_previous_pack_contains_it() {
    let f = Fixture::new();
    let base = git(&f.root, &["rev-parse", "HEAD"]);
    let old = f.commit("will be garbage collected");
    let previous = f.capture(None);
    git(&f.root, &["update-ref", "refs/heads/main", &base]);
    // Remove exactly the now-unreachable loose fixture commit, as GC could do.
    fs::remove_file(f.root.join(".git/objects").join(&old[..2]).join(&old[2..])).unwrap();
    let current = f.capture(Some(&previous));
    let summary = git_alerts(&previous.metadata, &current.metadata).unwrap();
    assert_eq!(summary.local_branch_rewrites, 0);
    assert_eq!(
        summary.diagnostics[&GitDiagnostic::PreviousObjectUnavailable],
        1
    );
}

#[test]
fn tracking_rewrite_and_public_summary_do_not_expose_sensitive_names_or_oids() {
    let f = Fixture::new();
    let base = git(&f.root, &["rev-parse", "HEAD"]);
    let tip = f.commit("forward");
    let private_ref = "refs/remotes/private-sensitive-origin/private-sensitive-topic";
    git(&f.root, &["update-ref", private_ref, &tip]);
    let previous = f.capture(None);
    git(&f.root, &["update-ref", private_ref, &base]);
    let current = f.capture(Some(&previous));
    let summary = git_alerts(&previous.metadata, &current.metadata).unwrap();
    assert_eq!(summary.remote_tracking_rewrites, 1);
    assert_eq!(summary.local_branch_rewrites, 0);
    for output in [
        serde_json::to_string(&summary).unwrap(),
        format!("{summary:?}"),
    ] {
        for secret in [private_ref, base.as_str(), tip.as_str(), "sensitive"] {
            assert!(!output.contains(secret));
        }
    }
    git(&f.root, &["update-ref", "-d", private_ref]);
    let deleted = f.capture(Some(&current));
    let summary = git_alerts(&current.metadata, &deleted.metadata).unwrap();
    assert_eq!(summary.tracking_ref_deletions, 1);
    assert_eq!(summary.remote_tracking_rewrites, 0);
}

#[test]
fn old_metadata_without_observation_decodes_and_local_comparison_still_works() {
    let f = Fixture::new();
    let mut previous = f.capture(None);
    previous.metadata.observation = None;
    let bytes = serde_json::to_vec(&previous.metadata).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("observation"));
    let previous = Capture::from_parts(&bytes, previous.pack, &Limits::default()).unwrap();
    f.commit("forward");
    let current = f.capture(Some(&previous));
    let summary = git_alerts(&previous.metadata, &current.metadata).unwrap();
    assert_eq!(summary.fast_forwards, 1);
    assert_eq!(
        summary.diagnostics[&GitDiagnostic::PreviousTrackingUnavailable],
        1
    );
    assert_eq!(
        git_alerts(&current.metadata, &previous.metadata)
            .unwrap()
            .diagnostics[&GitDiagnostic::ObservationUnavailable],
        1
    );
}

#[test]
fn comparison_is_bound_to_exact_previous_metadata_and_survives_source_removal() {
    let f = Fixture::new();
    let previous = f.capture(None);
    f.commit("forward");
    let current = f.capture(Some(&previous));
    let different = f.capture(None);
    let summary = git_alerts(&different.metadata, &current.metadata).unwrap();
    assert_eq!(summary.diagnostics[&GitDiagnostic::BaselineMismatch], 1);
    assert_eq!(summary.fast_forwards, 0);
    fs::remove_dir_all(f.root.join(".git")).unwrap();
    let decoded = Capture::from_parts(
        &serde_json::to_vec(&current.metadata).unwrap(),
        current.pack,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        git_alerts(&previous.metadata, &decoded.metadata)
            .unwrap()
            .fast_forwards,
        1
    );
}

#[test]
fn ancestry_and_comparison_caps_produce_unknown_not_rewrite() {
    let f = Fixture::new();
    let previous = f.capture(None);
    f.commit("one");
    f.commit("two");
    let mut engine = GitBackup::default();
    engine.limits.max_ancestry_commits = 1;
    let current = engine
        .capture_with_previous(&f.root, &CapturePolicy::default(), Some(&previous.metadata))
        .unwrap();
    let summary = git_alerts(&previous.metadata, &current.metadata).unwrap();
    assert_eq!(summary.local_branch_rewrites, 0);
    assert_eq!(
        summary.diagnostics[&GitDiagnostic::ObservationLimitExceeded],
        1
    );
    engine.limits.max_observation_comparisons = 0;
    let current = engine
        .capture_with_previous(&f.root, &CapturePolicy::default(), Some(&previous.metadata))
        .unwrap();
    assert_eq!(
        git_alerts(&previous.metadata, &current.metadata)
            .unwrap()
            .diagnostics[&GitDiagnostic::ObservationLimitExceeded],
        1
    );
}

#[test]
fn tracking_ref_cap_is_explicit_and_does_not_invent_deletions() {
    let f = Fixture::new();
    let tip = git(&f.root, &["rev-parse", "HEAD"]);
    for name in ["refs/remotes/origin/a", "refs/remotes/origin/b"] {
        git(&f.root, &["update-ref", name, &tip]);
    }
    let mut engine = GitBackup::default();
    engine.limits.max_observation_refs = 1;
    let previous = engine.capture(&f.root, &CapturePolicy::default()).unwrap();
    let current = engine
        .capture_with_previous(&f.root, &CapturePolicy::default(), Some(&previous.metadata))
        .unwrap();
    let summary = git_alerts(&previous.metadata, &current.metadata).unwrap();
    assert_eq!(summary.tracking_ref_deletions, 0);
    assert_eq!(summary.unchanged_refs, 2);
    assert_eq!(
        summary.diagnostics[&GitDiagnostic::ObservationLimitExceeded],
        2
    );
    assert!(Capture::from_parts(
        &serde_json::to_vec(&current.metadata).unwrap(),
        current.pack,
        &engine.limits
    )
    .is_ok());
}

#[test]
fn observation_ignores_source_config_includes_hooks_and_urls() {
    let f = Fixture::new();
    let previous = f.capture(None);
    f.commit("forward");
    let config = f.root.join(".git/config");
    let before = fs::read(&config).unwrap();
    let marker = f.root.join("hook.ran");
    let script = f.root.join("hook");
    fs::write(&script, "#!/bin/sh\nprintf invoked > \"$0.ran\"\nexit 99\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let include = f.root.join("included");
    // Invalid included configuration proves it was not even parsed.
    fs::write(&include, "[invalid\nprivate-config-sentinel").unwrap();
    let extra = format!("\n[include]\npath = {}\n[core]\nfsmonitor = {}\nhooksPath = {}\n[remote \"private-origin\"]\nurl = https://private-url-sentinel.invalid\n", include.display(), script.display(), script.display());
    let contents = [before, extra.into_bytes()].concat();
    fs::write(&config, &contents).unwrap();
    let current = f.capture(Some(&previous));
    assert_eq!(
        git_alerts(&previous.metadata, &current.metadata)
            .unwrap()
            .fast_forwards,
        1
    );
    assert!(!marker.exists());
    assert_eq!(fs::read(config).unwrap(), contents);
    let metadata = serde_json::to_string(&current.metadata).unwrap();
    assert!(!metadata.contains("private-config-sentinel"));
    assert!(!metadata.contains("private-url-sentinel"));
}

#[test]
fn non_commit_tracking_tip_is_unknown_instead_of_a_rewrite() {
    let f = Fixture::new();
    let tip = git(&f.root, &["rev-parse", "HEAD"]);
    git(&f.root, &["update-ref", "refs/remotes/origin/main", &tip]);
    let previous = f.capture(None);
    fs::write(f.root.join("blob"), "fixture blob").unwrap();
    let blob = git(&f.root, &["hash-object", "-w", "blob"]);
    git(&f.root, &["update-ref", "refs/remotes/origin/main", &blob]);
    let current = f.capture(Some(&previous));
    let summary = git_alerts(&previous.metadata, &current.metadata).unwrap();
    assert_eq!(summary.remote_tracking_rewrites, 0);
    assert_eq!(summary.diagnostics[&GitDiagnostic::AncestryUnavailable], 1);
}

#[test]
fn packed_local_heads_keep_the_legacy_storage_file_cap_semantics() {
    let f = Fixture::new();
    for i in 0..16 {
        git(&f.root, &["branch", &format!("topic-{i}")]);
    }
    git(&f.root, &["pack-refs", "--all", "--prune"]);
    let mut engine = GitBackup::default();
    engine.limits.max_files = 8;
    engine.limits.max_observation_refs = 0;
    let capture = engine.capture(&f.root, &CapturePolicy::default()).unwrap();
    assert_eq!(capture.metadata.heads.len(), 17);
    Capture::from_parts(
        &serde_json::to_vec(&capture.metadata).unwrap(),
        capture.pack,
        &engine.limits,
    )
    .unwrap();
}
