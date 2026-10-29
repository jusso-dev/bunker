use bunker::{
    mcp,
    policy::Policy,
    repository::{safe_path, Repository},
};
use std::{fs, path::Path};

fn repo(root: &Path) -> Repository {
    Repository::init(&root.join("repository"), "fixture-passphrase-only").unwrap()
}
fn workspace(root: &Path) -> std::path::PathBuf {
    let path = root.join("workspace");
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn encrypted_deduplicated_snapshot_and_reviewed_restore() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    fs::create_dir(work.join("src")).unwrap();
    fs::write(work.join("src/main.txt"), "unique workspace content").unwrap();
    fs::write(work.join("empty"), "").unwrap();
    let first = repository
        .snapshot(
            &work,
            &Policy::default(),
            Some("codex".into()),
            Some("session-1".into()),
            "manual",
        )
        .unwrap();
    let chunks = fs::read_dir(repository.root().join("chunks"))
        .unwrap()
        .count();
    let second = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    assert_eq!(
        chunks,
        fs::read_dir(repository.root().join("chunks"))
            .unwrap()
            .count()
    );
    assert_eq!(
        first.files.iter().map(|f| &f.chunks).collect::<Vec<_>>(),
        second.files.iter().map(|f| &f.chunks).collect::<Vec<_>>()
    );
    for entry in walkdir::WalkDir::new(repository.root())
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
    {
        let data = fs::read(entry.path()).unwrap();
        assert!(!data
            .windows(b"unique workspace content".len())
            .any(|w| w == b"unique workspace content"));
        assert!(!data
            .windows(b"src/main.txt".len())
            .any(|w| w == b"src/main.txt"));
    }
    fs::write(work.join("src/main.txt"), "damaged").unwrap();
    let plan = repository.plan(&first.id, &work, None).unwrap();
    assert!(repository.restore(&first.id, &work, None, "wrong").is_err());
    repository
        .restore(&first.id, &work, None, &plan.confirmation)
        .unwrap();
    assert_eq!(
        fs::read_to_string(work.join("src/main.txt")).unwrap(),
        "unique workspace content"
    );
    assert_eq!(repository.list().unwrap().len(), 2);
}

#[test]
fn stale_confirmation_refuses_newer_work() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    fs::write(work.join("a"), "original").unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    fs::write(work.join("a"), "edit").unwrap();
    let plan = repository.plan(&snapshot.id, &work, None).unwrap();
    fs::write(work.join("a"), "new work").unwrap();
    assert!(repository
        .restore(&snapshot.id, &work, None, &plan.confirmation)
        .is_err());
    assert_eq!(fs::read_to_string(work.join("a")).unwrap(), "new work");
}

#[test]
fn corrupted_chunk_causes_no_partial_restore() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    fs::write(work.join("a"), "first").unwrap();
    fs::write(work.join("z"), "last").unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    fs::write(work.join("a"), "new first").unwrap();
    fs::write(work.join("z"), "new last").unwrap();
    let chunk = repository
        .root()
        .join("chunks")
        .join(&snapshot.files[1].chunks[0]);
    let plan = repository.plan(&snapshot.id, &work, None).unwrap();
    fs::write(chunk, b"corrupted").unwrap();
    assert!(repository.plan(&snapshot.id, &work, None).is_err());
    assert!(repository
        .restore(&snapshot.id, &work, None, &plan.confirmation)
        .is_err());
    assert_eq!(fs::read_to_string(work.join("a")).unwrap(), "new first");
}

#[test]
fn wrong_keys_rotation_and_repository_lock() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let path = repository.root().to_owned();
    assert!(Repository::open(&path, "fixture-passphrase-only").is_err());
    repository
        .rotate_passphrase("new-fixture-passphrase")
        .unwrap();
    drop(repository);
    assert!(Repository::open(&path, "fixture-passphrase-only").is_err());
    assert!(Repository::open(&path, "new-fixture-passphrase").is_ok());
}

#[test]
fn exclusions_and_cap_apply_before_publishing() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    fs::write(work.join(".env.production"), "not-a-real-secret").unwrap();
    fs::write(work.join("auth.json"), "not-a-real-secret").unwrap();
    fs::create_dir(work.join("node_modules")).unwrap();
    fs::write(work.join("node_modules/junk"), "junk").unwrap();
    fs::write(work.join("keep.txt"), "123456").unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    assert_eq!(snapshot.files.len(), 1);
    fs::write(work.join("second.txt"), "123456").unwrap();
    let policy = Policy {
        size_cap_bytes: 10,
        max_file_bytes: 10,
        ..Policy::default()
    };
    assert!(repository
        .snapshot(&work, &policy, None, None, "manual")
        .is_err());
    assert_eq!(repository.list().unwrap().len(), 1);
}

#[test]
fn traversal_and_repository_overlap_rejected() {
    for path in [
        "../outside",
        "/absolute",
        "a/../../b",
        "C:\\windows",
        "a\\..\\b",
        "./foo",
        "x:",
        "a/",
        "",
    ] {
        assert!(safe_path(path).is_err(), "{path}");
    }
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    assert!(repository
        .snapshot(temp.path(), &Policy::default(), None, None, "manual")
        .is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_cannot_leak_or_overwrite_outside_root() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    let outside = temp.path().join("outside");
    fs::write(&outside, "outside-data").unwrap();
    symlink(&outside, work.join("leak")).unwrap();
    fs::create_dir(work.join("dir")).unwrap();
    fs::write(work.join("dir/file"), "safe").unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    assert_eq!(snapshot.files.len(), 1);
    fs::remove_file(work.join("dir/file")).unwrap();
    fs::remove_dir(work.join("dir")).unwrap();
    symlink(temp.path(), work.join("dir")).unwrap();
    assert!(repository.plan(&snapshot.id, &work, None).is_err());
    assert_eq!(fs::read_to_string(outside).unwrap(), "outside-data");
}

#[test]
fn mcp_requests_never_restore_delete_or_approve() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    fs::write(work.join("a"), "before").unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    fs::write(work.join("a"), "after").unwrap();
    let response = mcp::call(
        &repository,
        &work,
        "request_restore",
        &serde_json::json!({"snapshot":snapshot.id}),
    )
    .unwrap();
    assert_eq!(response["status"], "pending");
    assert_eq!(fs::read_to_string(work.join("a")).unwrap(), "after");
    for name in [
        "restore",
        "delete",
        "delete_snapshot",
        "approve",
        "set_retention",
    ] {
        assert!(mcp::call(&repository, &work, name, &serde_json::json!({})).is_err());
    }
    assert_eq!(repository.list().unwrap().len(), 1);
}

#[test]
fn five_agent_workspace_configs_round_trip_with_secret_references() {
    for (agent, path, content) in [
        (
            "claude-code",
            ".mcp.json",
            r#"{"mcpServers":{"test":{"env":{"API_KEY":"fixture-not-a-real-credential"}}}}"#,
        ),
        (
            "cursor",
            ".cursor/mcp.json",
            r#"{"mcpServers":{"test":{"env":{"API_KEY":"fixture-not-a-real-credential"}}}}"#,
        ),
        (
            "codex",
            ".codex/config.toml",
            "[mcp_servers.test.env]\nAPI_KEY = 'fixture-not-a-real-credential'\n",
        ),
        (
            "copilot",
            ".vscode/mcp.json",
            r#"{"servers":{"test":{"env":{"API_KEY":"fixture-not-a-real-credential"}}}}"#,
        ),
        (
            "kiro",
            ".kiro/settings/mcp.json",
            r#"{"mcpServers":{"test":{"env":{"API_KEY":"fixture-not-a-real-credential"}}}}"#,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let repository = repo(temp.path());
        let work = workspace(temp.path());
        fs::create_dir_all(work.join(path).parent().unwrap()).unwrap();
        fs::write(work.join(path), content).unwrap();
        let snapshot = repository
            .snapshot(
                &work,
                &Policy::default(),
                Some(agent.into()),
                None,
                "session-end",
            )
            .unwrap();
        assert_eq!(snapshot.files.len(), 1);
        let saved = repository.file_bytes(&snapshot.files[0]).unwrap();
        assert!(!String::from_utf8_lossy(&saved).contains("fixture-not-a-real-credential"));
        assert!(String::from_utf8_lossy(&saved).contains("BUNKER_SECRET_"));
        fs::write(work.join(path), "damaged").unwrap();
        let plan = repository.plan(&snapshot.id, &work, None).unwrap();
        assert!(repository
            .restore(&snapshot.id, &work, None, &plan.confirmation)
            .is_err());
        repository
            .restore_with_options(&snapshot.id, &work, None, &plan.confirmation, true)
            .unwrap();
        assert_eq!(fs::read(work.join(path)).unwrap(), *saved);
    }
}

#[test]
fn secret_free_structured_files_preserve_original_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    let original = b"{ \"name\": \"example\", \"version\": \"1.0.0\" }\n";
    fs::write(work.join("package.json"), original).unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    assert_eq!(
        &**repository.file_bytes(&snapshot.files[0]).unwrap(),
        original
    );
}

#[test]
fn requests_are_expiring_and_single_use() {
    let temp = tempfile::tempdir().unwrap();
    let repository = repo(temp.path());
    let work = workspace(temp.path());
    fs::write(work.join("a"), "original").unwrap();
    let snapshot = repository
        .snapshot(&work, &Policy::default(), None, None, "manual")
        .unwrap();
    fs::write(work.join("a"), "edit").unwrap();
    let plan = repository.plan(&snapshot.id, &work, None).unwrap();
    let expired = repository
        .save_request(
            &serde_json::json!({"plan":plan,"file":null,"expires_at":0,"status":"pending"}),
        )
        .unwrap();
    assert!(repository
        .decide_request(&expired, true, Some(&plan.confirmation))
        .is_err());
    assert_eq!(repository.request(&expired).unwrap()["status"], "expired");
    let request = mcp::call(
        &repository,
        &work,
        "request_restore",
        &serde_json::json!({"snapshot":snapshot.id}),
    )
    .unwrap();
    let id = request["request_id"].as_str().unwrap();
    assert!(repository.decide_request(id, true, Some("wrong")).is_err());
    let error = repository
        .decide_request(id, true, Some(&plan.confirmation))
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("independent human authorization"));
    assert_eq!(fs::read_to_string(work.join("a")).unwrap(), "edit");
    assert_eq!(
        repository.decide_request(id, false, None).unwrap()["status"],
        "denied"
    );
    assert!(repository
        .decide_request(id, true, Some(&plan.confirmation))
        .is_err());
}
