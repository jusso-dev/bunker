//! Public summary/authentication regressions; fixture-only, offline Git.
use bunker::{
    policy::Policy,
    repository::{Manifest, Repository},
};
use bunker_git::GitDiagnostic;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    repo: Repository,
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
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
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
        let base = temp.path().canonicalize().unwrap();
        let root = base.join("source");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]);
        git(&root, &["commit", "--allow-empty", "-m", "base"]);
        let repo = Repository::init(&base.join("vault"), "fixture-only").unwrap();
        Self {
            _temp: temp,
            root,
            repo,
        }
    }
    fn snapshot(&self) -> Manifest {
        self.repo
            .snapshot(&self.root, &Policy::default(), None, None, "fixture")
            .unwrap()
    }
    fn snapshot_with_previous(&self, previous: &Manifest) -> Manifest {
        self.repo
            .snapshot_with_previous(
                &self.root,
                &Policy::default(),
                None,
                None,
                "fixture",
                Some(previous),
            )
            .unwrap()
    }
}

#[test]
fn stored_authenticated_comparison_survives_source_removal_and_redacts_identity() {
    let f = Fixture::new();
    let base = git(&f.root, &["rev-parse", "HEAD"]);
    git(&f.root, &["commit", "--allow-empty", "-m", "advanced"]);
    let tip = git(&f.root, &["rev-parse", "HEAD"]);
    let name = "refs/remotes/private-origin/private-topic";
    git(&f.root, &["update-ref", name, &tip]);
    let previous = f.snapshot();
    git(&f.root, &["update-ref", name, &base]);
    git(&f.root, &["update-ref", "refs/heads/main", &base]);
    let current = f.snapshot_with_previous(&previous);
    fs::remove_dir_all(&f.root).unwrap();
    let previous = f.repo.manifest(&previous.id).unwrap();
    let current = f.repo.manifest(&current.id).unwrap();
    let summary = f.repo.git_alerts(&previous, &current).unwrap();
    assert_eq!(summary.local_branch_rewrites, 1);
    assert_eq!(summary.remote_tracking_rewrites, 1);
    assert!(summary.diagnostics.is_empty());
    let alerts = bunker::scheduler::detect_repository(&f.repo, &previous, &current, 10).unwrap();
    for kind in ["history_rewrite", "force_push"] {
        let alert = alerts.iter().find(|alert| alert.kind == kind).unwrap();
        assert_eq!(alert.count, 1);
        assert_eq!(alert.snapshot.as_deref(), Some(current.id.as_str()));
    }
    let repeated = bunker::scheduler::detect_repository(&f.repo, &previous, &current, 10).unwrap();
    for alert in &alerts {
        assert_eq!(
            alert.fingerprint,
            repeated
                .iter()
                .find(|other| other.kind == alert.kind)
                .unwrap()
                .fingerprint
        );
    }
    let serialized_alerts = serde_json::to_string(&alerts).unwrap();
    let json = serde_json::to_string(&summary).unwrap();
    for secret in [
        name,
        base.as_str(),
        tip.as_str(),
        "private-origin",
        "private-topic",
    ] {
        assert!(!json.contains(secret));
        assert!(!serialized_alerts.contains(secret));
    }
    let mut tampered = current.clone();
    tampered.git.as_mut().unwrap().metadata.hash = "private-error-sentinel".into();
    let error = f.repo.git_alerts(&previous, &tampered).unwrap_err();
    assert_eq!(format!("{error:#}"), "Git observation unavailable");
    assert!(!format!("{error:?}").contains("private-error-sentinel"));
    tampered.git.as_mut().unwrap().metadata.hash = "0".repeat(64);
    assert_eq!(
        format!("{:#}", f.repo.git_alerts(&previous, &tampered).unwrap_err()),
        "Git observation unavailable"
    );
}

#[test]
fn wrong_baseline_and_absent_git_are_explicit_diagnostics() {
    let f = Fixture::new();
    let previous = f.snapshot();
    git(&f.root, &["commit", "--allow-empty", "-m", "advanced"]);
    let current = f.snapshot_with_previous(&previous);
    let standalone = f.snapshot();
    assert_eq!(
        f.repo
            .git_alerts(&current, &standalone)
            .unwrap()
            .diagnostics[&GitDiagnostic::ObservationUnavailable],
        1
    );
    let alerts = bunker::scheduler::detect_repository(&f.repo, &previous, &current, 10).unwrap();
    assert!(!alerts
        .iter()
        .any(|alert| matches!(alert.kind.as_str(), "history_rewrite" | "force_push")));
    assert_eq!(
        f.repo
            .git_alerts(&previous, &current)
            .unwrap()
            .fast_forwards,
        1
    );
    assert_eq!(
        f.repo.git_alerts(&current, &current).unwrap().diagnostics
            [&GitDiagnostic::BaselineMismatch],
        1
    );
    let mut no_git = previous.clone();
    no_git.git = None;
    assert_eq!(
        f.repo.git_alerts(&no_git, &current).unwrap().diagnostics
            [&GitDiagnostic::CaptureUnavailable],
        1
    );
}

fn damaged_previous_metadata_preserves_current_capture(corrupt: bool) {
    let f = Fixture::new();
    let base = git(&f.root, &["rev-parse", "HEAD"]);
    git(&f.root, &["commit", "--allow-empty", "-m", "advanced"]);
    let previous = f.snapshot();
    let chunk = &previous.git.as_ref().unwrap().metadata.chunks[0];
    let path = f.root.parent().unwrap().join("vault/chunks").join(chunk);
    let original = fs::read(&path).unwrap();
    if corrupt {
        fs::write(&path, b"private-damaged-metadata-sentinel").unwrap();
    } else {
        fs::remove_file(&path).unwrap();
    }
    // This really is a rewind, but unavailable evidence must not assert one.
    git(&f.root, &["update-ref", "refs/heads/main", &base]);
    let current = f.snapshot_with_previous(&previous);
    assert!(current.git.is_some());
    assert!(!current
        .diagnostics
        .iter()
        .any(|entry| entry.reason == "git_capture_failed_or_unsupported"));
    f.repo.verify(&current.id).unwrap();
    let summary = f.repo.git_alerts(&previous, &current).unwrap();
    assert_eq!(
        summary,
        bunker_git::GitAlerts::unavailable(GitDiagnostic::ObservationUnavailable)
    );
    let serialized = serde_json::to_string(&summary).unwrap();
    assert!(!serialized.contains("private-damaged-metadata-sentinel"));
    assert!(!serialized.contains(chunk));
    let mut invalid_current = current.clone();
    invalid_current.git.as_mut().unwrap().metadata.hash = "0".repeat(64);
    assert!(f.repo.git_alerts(&previous, &invalid_current).is_err());
    let alerts = bunker::scheduler::detect_repository(&f.repo, &previous, &current, 10).unwrap();
    assert!(!alerts
        .iter()
        .any(|alert| matches!(alert.kind.as_str(), "history_rewrite" | "force_push")));
    // Repairing old storage cannot manufacture a comparison that was not made.
    fs::write(&path, original).unwrap();
    assert_eq!(f.repo.git_alerts(&previous, &current).unwrap(), summary);
    // The new capture is a usable baseline for the next healthy observation.
    git(&f.root, &["commit", "--allow-empty", "-m", "next"]);
    let next = f.snapshot_with_previous(&current);
    assert_eq!(f.repo.git_alerts(&current, &next).unwrap().fast_forwards, 1);
    f.repo.verify(&next.id).unwrap();
}

#[test]
fn missing_previous_metadata_does_not_suppress_current_git_capture() {
    damaged_previous_metadata_preserves_current_capture(false);
}

#[test]
fn corrupt_previous_metadata_does_not_suppress_current_git_capture() {
    damaged_previous_metadata_preserves_current_capture(true);
}
