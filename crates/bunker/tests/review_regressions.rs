use bunker::{
    mcp,
    policy::Policy,
    repository::Repository,
    scheduler::{self, ScheduleState},
};
use std::{fs, path::Path};
const PASSPHRASE: &str = "fixture-passphrase-only";
fn setup(root: &Path) -> (Repository, std::path::PathBuf) {
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    (
        Repository::init(&root.join("repo"), PASSPHRASE).unwrap(),
        work,
    )
}
#[test]
fn ordinary_source_binary_jsonc_yaml_and_lockfiles_are_byte_exact() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let cases: &[(&str, &[u8])] = &[
        (
            "src/main.rs",
            b"let token = next(); // 550e8400-e29b-41d4-a716-446655440000\n",
        ),
        ("README.md", b"This is a basic example.\n"),
        (
            "Cargo.lock",
            b"checksum = \"a987654321abcdef0123456789abcdef0123456789abcdef0123456789abcdef01\"\n",
        ),
        ("image.png", b"\x89PNG\r\n\x1a\n\0\xff"),
        ("settings.jsonc", b"{ // comment\n \"x\": 1,\n}\n"),
        ("config.yaml", b"token: |\n  ordinary-example\n"),
        ("vendor/pkg.bin", b"\0\x80source fixture"),
        (
            "src/history/messages.json",
            b"{\"messages\":[\"ordinary fixture\"]}",
        ),
    ];
    for (path, bytes) in cases {
        fs::create_dir_all(work.join(path).parent().unwrap()).unwrap();
        fs::write(work.join(path), bytes).unwrap();
    }
    let snapshot = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    assert_eq!(snapshot.files.len(), cases.len());
    for (path, bytes) in cases {
        let file = snapshot.files.iter().find(|f| &f.path == path).unwrap();
        assert!(!file.sanitized);
        assert_eq!(&**repo.file_bytes(file).unwrap(), *bytes);
    }
}
#[test]
fn only_agent_private_directories_are_filtered_and_exclusions_are_recorded() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    for name in [
        "chat", "history", "logs", "profiles", "browser", "vendor", "build", "target", "sessions",
    ] {
        fs::create_dir_all(work.join("src").join(name)).unwrap();
        fs::write(work.join("src").join(name).join("code.rs"), "source").unwrap();
    }
    fs::create_dir_all(work.join(".claude/projects")).unwrap();
    fs::write(work.join(".claude/projects/transcript"), "private fixture").unwrap();
    fs::write(work.join(".env.local"), "fixture credential").unwrap();
    fs::write(work.join("excluded.txt"), "policy fixture").unwrap();
    let policy = Policy {
        exclusions: vec!["excluded.txt".into()],
        ..Policy::default()
    };
    let m = repo.snapshot(&work, &policy, None, None, "test").unwrap();
    assert_eq!(m.files.len(), 9);
    for (path, reason) in [
        (".claude/projects", "agent_private_data"),
        (".env.local", "environment_file"),
        ("excluded.txt", "policy_exclusion"),
    ] {
        assert!(m
            .diagnostics
            .iter()
            .any(|d| d.path == path && d.reason == reason));
    }
}
#[test]
fn config_history_removal_survives_wrapper_and_references_persist() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join(".claude.json"), r#"{"history":["private"],"messages":["private"],"projects":{"private":"value"},"theme":"dark"}"#).unwrap();
    fs::write(
        work.join(".mcp.json"),
        r#"{"env":{"API_KEY":"fixture-literal","URL":"${EXISTING}"}}"#,
    )
    .unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    let loaded = repo.manifest(&m.id).unwrap();
    let history = loaded
        .files
        .iter()
        .find(|f| f.path == ".claude.json")
        .unwrap();
    assert!(history.sanitized);
    assert!(history.secret_references.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&repo.file_bytes(history).unwrap()).unwrap();
    assert_eq!(value, serde_json::json!({"theme":"dark"}));
    let config = loaded.files.iter().find(|f| f.path == ".mcp.json").unwrap();
    assert_eq!(config.secret_references.len(), 2);
    assert!(config
        .secret_references
        .iter()
        .any(|r| r.kind == bunker_discovery::ReferenceKind::RebindRequired));
    let plan = repo.plan(&m.id, &work, Some(".mcp.json")).unwrap();
    assert!(plan.changes[0].requires_rebind);
    assert!(repo
        .restore(&m.id, &work, Some(".mcp.json"), &plan.confirmation)
        .is_err());
    repo.restore_with_options(&m.id, &work, Some(".mcp.json"), &plan.confirmation, true)
        .unwrap();
}
#[test]
fn unsupported_agent_config_is_skipped_with_attempts_ordinary_files_continue() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join(".mcp.json"), b"{ // JSONC not supported\n}").unwrap();
    fs::create_dir(work.join(".codex")).unwrap();
    fs::write(work.join(".codex/config.toml"), vec![b'a'; 1024 * 1024 + 1]).unwrap();
    fs::write(work.join("source.rs"), b"let token = next();").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    assert_eq!(m.files.len(), 1);
    assert!(m.diagnostics.iter().any(|d| d.path == ".mcp.json"
        && d.reason.contains("configuration_sanitization_failed")
        && d.reason.contains("JSONC")
        && d.attempts == 3));
    assert!(m
        .diagnostics
        .iter()
        .any(|d| d.path == ".codex/config.toml" && d.reason == "file_size_cap"));
}
#[test]
fn mcp_never_exports_content_confirmation_or_executes_request() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "private source prose\n").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::write(work.join("a"), "local changed source\n").unwrap();
    let args = serde_json::json!({"snapshot":m.id});
    let diff = mcp::call(&repo, &work, "diff", &args).unwrap();
    let serialized = diff.to_string();
    assert!(!serialized.contains("confirmation"));
    assert!(!serialized.contains("preview"));
    assert!(!serialized.contains("private source"));
    assert!(!serialized.contains("local changed"));
    let request = mcp::call(&repo, &work, "request_restore", &args).unwrap();
    let id = request["request_id"].as_str().unwrap();
    let local = repo.plan(&m.id, &work, None).unwrap();
    assert!(repo
        .decide_request(id, true, Some(&local.confirmation))
        .unwrap_err()
        .to_string()
        .contains("independent human authorization"));
    assert_eq!(
        fs::read_to_string(work.join("a")).unwrap(),
        "local changed source\n"
    );
    for name in ["approve", "restore", "gc", "retention", "delete"] {
        assert!(mcp::call(&repo, &work, name, &args).is_err());
    }
}
#[test]
fn local_preview_is_readable_redacted_and_reports_sizes() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(
        work.join("a"),
        "hello original\npassword = fixture-hidden-value\n",
    )
    .unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::write(work.join("a"), "hello changed\n").unwrap();
    let plan = repo.plan(&m.id, &work, None).unwrap();
    let c = &plan.changes[0];
    assert!(c.preview.contains("+ hello original"));
    assert!(c.preview.contains("- hello changed"));
    assert!(!c.preview.contains("fixture-hidden-value"));
    assert_eq!(c.before_size, Some(14));
    assert!(c.after_size > 14);
}
#[cfg(unix)]
#[test]
fn executable_only_changes_are_not_unchanged_and_restore_is_journaled() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("run"), "echo fixture\n").unwrap();
    fs::set_permissions(work.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::set_permissions(work.join("run"), fs::Permissions::from_mode(0o600)).unwrap();
    let plan = repo.plan(&m.id, &work, None).unwrap();
    assert_eq!(plan.changes[0].action, "overwrite");
    assert_eq!(plan.changes[0].before_executable, Some(false));
    assert!(plan.changes[0].after_executable);
    repo.restore(&m.id, &work, None, &plan.confirmation)
        .unwrap();
    assert_ne!(
        fs::metadata(work.join("run")).unwrap().permissions().mode() & 0o111,
        0
    );
    let transaction = fs::read_dir(repo.root().join("transactions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let id = transaction.file_name().to_string_lossy().into_owned();
    let journal = repo.restore_journal(&id).unwrap();
    assert_eq!(journal["status"], "completed");
    assert_eq!(journal["applied"], serde_json::json!([0]));
    assert!(transaction.path().join("0.before").exists());
    assert!(!transaction.path().join("0.after").exists());
    let encrypted = fs::read(transaction.path().join("0.before")).unwrap();
    assert!(!encrypted.windows(12).any(|w| w == b"echo fixture"));
}
#[test]
fn export_validates_header_and_exact_encrypted_objects() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "fixture").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    let path = format!("chunks/{}", m.files[0].chunks[0]);
    assert_eq!(
        repo.encrypted_object(&path).unwrap(),
        fs::read(repo.root().join(&path)).unwrap()
    );
    fs::write(repo.root().join(&path), b"corrupt").unwrap();
    assert!(repo.encrypted_object(&path).is_err());
    fs::write(repo.root().join("repository.json"), b"{}").unwrap();
    assert!(repo.encrypted_object("repository.json").is_err());
}
#[test]
fn request_size_is_bounded_before_persistence() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, _) = setup(temp.path());
    assert!(repo
        .save_request(&serde_json::json!({"x":"x".repeat(1024 * 1024)}))
        .is_err());
    assert_eq!(
        fs::read_dir(repo.root().join("requests")).unwrap().count(),
        0
    );
}
#[test]
fn scheduler_retries_busy_repository_and_keeps_last_good_policy() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let path = repo.root().to_owned();
    let policy = temp.path().join("policy.toml");
    fs::write(&policy, "interval_seconds = 10\njitter_seconds = 0\n").unwrap();
    fs::write(work.join("a"), "fixture").unwrap();
    let mut state = ScheduleState::default();
    assert!(scheduler::tick(&path, PASSPHRASE, &work, Some(&policy), &mut state, true).is_err());
    assert_eq!(state.last_success, 0);
    drop(repo);
    fs::write(&policy, "interval_seconds = ").unwrap();
    scheduler::tick(&path, PASSPHRASE, &work, Some(&policy), &mut state, true).unwrap();
    assert_eq!(state.last_good_policy.unwrap().interval_seconds, 10);
    assert!(state.last_success > 0);
    assert!(state.last_snapshot.is_some());
}
#[test]
fn scheduler_missing_prior_manifest_records_gap_without_losing_success() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let path = repo.root().to_owned();
    drop(repo);
    fs::write(work.join("a"), "fixture").unwrap();
    let mut state = ScheduleState {
        last_snapshot: Some("a".repeat(64)),
        workspace: Some(work.canonicalize().unwrap()),
        ..ScheduleState::default()
    };
    scheduler::tick(&path, PASSPHRASE, &work, None, &mut state, true).unwrap();
    assert!(state.pending_detection.is_none());
    assert_ne!(state.last_snapshot, Some("a".repeat(64)));
    let disk: ScheduleState =
        serde_json::from_slice(&fs::read(path.join("schedule.json")).unwrap()).unwrap();
    assert_eq!(disk.last_snapshot, state.last_snapshot);
}
#[test]
fn audit_failure_leaves_scheduler_success_durable_and_retries_detection_only() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let path = repo.root().to_owned();
    drop(repo);
    fs::write(work.join("a"), "fixture").unwrap();
    // Make the audit directory unavailable without disturbing snapshot storage.
    fs::write(path.join("audit"), "fixture obstruction").unwrap();
    let mut state = ScheduleState {
        last_success: 1,
        workspace: Some(work.canonicalize().unwrap()),
        ..ScheduleState::default()
    };
    assert!(scheduler::tick(&path, PASSPHRASE, &work, None, &mut state, true).is_err());
    let disk: ScheduleState =
        serde_json::from_slice(&fs::read(path.join("schedule.json")).unwrap()).unwrap();
    assert!(disk.last_snapshot.is_some());
    assert!(disk.pending_detection.is_some());
    assert_eq!(disk.pending_missed_backup, Some(1));
    assert_eq!(fs::read_dir(path.join("snapshots")).unwrap().count(), 1);
    fs::remove_file(path.join("audit")).unwrap();
    scheduler::tick(&path, PASSPHRASE, &work, None, &mut state, true).unwrap();
    assert!(state.pending_detection.is_none());
    assert!(state.pending_missed_backup.is_none());
    assert_eq!(fs::read_dir(path.join("snapshots")).unwrap().count(), 1);
}
#[test]
fn restore_audit_failure_retains_preimages_and_does_not_write_destination() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "original fixture").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::write(work.join("a"), "current fixture").unwrap();
    fs::write(repo.root().join("audit"), "fixture obstruction").unwrap();
    let plan = repo.plan(&m.id, &work, None).unwrap();
    let error = repo
        .restore(&m.id, &work, None, &plan.confirmation)
        .unwrap_err();
    assert!(error.to_string().contains("preimages retained"));
    assert_eq!(
        fs::read_to_string(work.join("a")).unwrap(),
        "current fixture"
    );
    let transaction = fs::read_dir(repo.root().join("transactions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let journal = repo
        .restore_journal(&transaction.file_name().to_string_lossy())
        .unwrap();
    assert_eq!(journal["status"], "interrupted");
    assert_eq!(journal["preimages"].as_array().unwrap().len(), 1);
    assert!(transaction.path().join("0.before").exists());
}
#[test]
fn mcp_stdio_rejects_oversized_input_and_protocol_never_returns_local_preview() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "private source text").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    let root = repo.root().to_owned();
    drop(repo);
    fs::write(work.join("a"), "changed private text").unwrap();
    let input = format!(
        "{}\n{}\n{}\n",
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"diff","arguments":{"snapshot":m.id}}})
    );
    let mut output = vec![];
    mcp::serve(
        &root,
        PASSPHRASE,
        &work,
        std::io::Cursor::new(input),
        &mut output,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(output.lines().count(), 3);
    assert!(!output.contains("private source text"));
    assert!(!output.contains("changed private text"));
    assert!(!output.contains("confirmation"));
    let mut output = vec![];
    assert!(mcp::serve(
        &root,
        PASSPHRASE,
        &work,
        std::io::Cursor::new(vec![b' '; 1024 * 1024 + 1]),
        &mut output
    )
    .is_err());
}
#[test]
fn rewrapping_preserves_encrypted_data_but_changes_namespace() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "fixture").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    let chunk = format!("chunks/{}", m.files[0].chunks[0]);
    let before = repo.encrypted_object(&chunk).unwrap();
    let old_header = repo.encrypted_object("repository.json").unwrap();
    repo.rewrap_passphrase("new-fixture-passphrase").unwrap();
    assert_eq!(before, repo.encrypted_object(&chunk).unwrap());
    assert_ne!(
        old_header,
        repo.encrypted_object("repository.json").unwrap()
    );
}

#[test]
fn skipped_capture_is_not_reported_as_mass_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "a").unwrap();
    let before = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::write(work.join("a"), vec![b'a'; 11]).unwrap();
    let policy = Policy {
        max_file_bytes: 10,
        mass_delete_threshold: 1,
        ..Policy::default()
    };
    let after = repo.snapshot(&work, &policy, None, None, "test").unwrap();
    assert!(scheduler::detect(&before, &after, 1).is_empty());
    fs::remove_file(work.join("a")).unwrap();
    let deleted = repo.snapshot(&work, &policy, None, None, "test").unwrap();
    assert_eq!(
        scheduler::detect(&before, &deleted, 1)[0].kind,
        "mass_delete"
    );
}

#[test]
fn r2_defaults_include_override_and_agent_assets_are_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let artifacts = [
        "target/debug/app",
        ".venv/lib/site.py",
        "dist/bundle.js",
        ".next/cache/x",
        "__pycache__/m.pyc",
        "models/llama.gguf",
        "data/app.sqlite",
        "build/out.o",
        ".pnpm-store/v3/x",
        ".gradle/caches/x",
    ];
    let assets = [
        "src/chat/history/source.rs",
        "src/build/a.rs",
        ".claude/commands/history.md",
        ".claude/skills/chat/SKILL.md",
        ".claude/skills/release/build/SKILL.md",
        ".cursor/rules/logs/rule.mdc",
        ".claude/agents/session.md",
        ".claude/skills/x/vendor/a.py",
        ".claude/skills/x/out/a.md",
    ];
    let private = [
        "apps/web/.claude/projects/a.txt",
        ".codex/sessions/a.txt",
        "nested/.env",
        ".claude/skills/x/auth.json",
        ".git/config",
    ];
    for path in artifacts.iter().chain(&assets).chain(&private) {
        fs::create_dir_all(work.join(path).parent().unwrap()).unwrap();
        fs::write(work.join(path), "fixture").unwrap();
    }
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    for path in assets {
        assert!(m.files.iter().any(|f| f.path == path), "missing {path}");
    }
    for path in artifacts.iter().chain(&private) {
        assert!(!m.files.iter().any(|f| f.path == *path), "captured {path}");
        assert!(
            m.diagnostics
                .iter()
                .any(|d| *path == d.path || path.starts_with(&format!("{}/", d.path))),
            "no diagnostic {path}"
        );
    }
    let policy = Policy {
        default_includes: vec![
            "target/debug/app".into(),
            "**/*.sqlite".into(),
            "**/.env".into(),
            "**/auth.json".into(),
            ".git/**".into(),
        ],
        ..Policy::default()
    };
    let included = repo.snapshot(&work, &policy, None, None, "test").unwrap();
    for path in ["target/debug/app", "data/app.sqlite"] {
        assert!(included.files.iter().any(|f| f.path == path));
    }
    for path in private {
        assert!(!included.files.iter().any(|f| f.path == path));
    }
}

#[test]
fn r2_nested_config_and_removal_only_overwrite_guard() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    for path in [
        "apps/web/.mcp.json",
        "apps/web/.cursor/mcp.json",
        "pkg/.vscode/mcp.json",
        "svc/.claude/settings.local.json",
    ] {
        fs::create_dir_all(work.join(path).parent().unwrap()).unwrap();
        fs::write(
            work.join(path),
            br#"{"mcpServers":{"x":{"env":{"API_KEY":"fixture-literal-only"}}}}"#,
        )
        .unwrap();
    }
    fs::create_dir_all(work.join("pkg/.codex")).unwrap();
    fs::write(
        work.join("pkg/.codex/config.toml"),
        "model = \"fixture\"\n[history]\npersistence = \"save-all\"\n",
    )
    .unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    assert_eq!(m.files.len(), 5);
    for file in &m.files {
        assert!(file.sanitized);
        assert!(!String::from_utf8_lossy(&repo.file_bytes(file).unwrap())
            .contains("fixture-literal-only"));
    }
    let file = m
        .files
        .iter()
        .find(|f| f.path.ends_with("config.toml"))
        .unwrap();
    assert!(file.secret_references.is_empty());
    let plan = repo.plan(&m.id, &work, Some(&file.path)).unwrap();
    assert!(plan.changes[0].requires_rebind);
    assert!(repo
        .restore(&m.id, &work, Some(&file.path), &plan.confirmation)
        .is_err());
    repo.restore_with_options(&m.id, &work, Some(&file.path), &plan.confirmation, true)
        .unwrap();
}

#[test]
fn r2_mcp_diff_and_persisted_request_have_no_content_hashes() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("pin.txt"), "4821").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::write(work.join("pin.txt"), "1234").unwrap();
    let args = serde_json::json!({"snapshot": m.id});
    let plan = mcp::call(&repo, &work, "diff", &args).unwrap();
    for key in ["before", "after", "preview"] {
        assert!(plan["changes"][0].get(key).is_none());
    }
    let request = mcp::call(&repo, &work, "request_restore", &args).unwrap();
    let stored = repo
        .request(request["request_id"].as_str().unwrap())
        .unwrap()
        .to_string();
    for contents in ["4821", "1234"] {
        assert!(!stored.contains(blake3::hash(contents.as_bytes()).to_hex().as_str()));
    }
}

#[test]
fn r2_unsupported_storage_fails_before_credentials_or_network() {
    for service in ["gdrive", "onedrive"] {
        let config = bunker::storage::StorageConfig {
            service: service.into(),
            options: Default::default(),
            credential_env: Default::default(),
            immutable: false,
        };
        let error = match config.operator() {
            Ok(_) => panic!("unsupported provider accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("exact-ID consumer adapter"));
    }
}

#[test]
fn r2_scheduler_failure_streak_backs_off_and_audits_once() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let path = repo.root().to_owned();
    drop(repo);
    fs::write(work.join("a"), vec![b'x'; 700]).unwrap();
    fs::write(work.join("b"), vec![b'y'; 700]).unwrap();
    let policy = temp.path().join("policy.toml");
    fs::write(&policy, "size_cap_bytes = 1024\nmax_file_bytes = 1024\n").unwrap();
    let mut state = ScheduleState::default();
    for failure in 1..=13 {
        assert!(
            scheduler::tick(&path, PASSPHRASE, &work, Some(&policy), &mut state, true).is_err()
        );
        assert_eq!(state.failures, failure);
        assert!(state.retry_after >= bunker::repository::now());
    }
    assert_eq!(scheduler::retry_delay(state.failures, 3600), 3600);
    assert_eq!(fs::read_dir(path.join("audit")).unwrap().count(), 1);
    let saved = fs::read(path.join("schedule.json")).unwrap();
    let mut restarted: ScheduleState = serde_json::from_slice(&saved).unwrap();
    scheduler::tick(
        &path,
        PASSPHRASE,
        &work,
        Some(&policy),
        &mut restarted,
        false,
    )
    .unwrap();
    assert_eq!(restarted.failures, state.failures);
    assert_eq!(saved, fs::read(path.join("schedule.json")).unwrap());
    fs::remove_file(work.join("b")).unwrap();
    scheduler::tick(
        &path,
        PASSPHRASE,
        &work,
        Some(&policy),
        &mut restarted,
        true,
    )
    .unwrap();
    assert_eq!(restarted.failures, 0);
    assert!(!restarted.failure_audited);
}

#[test]
fn r2_corrupt_schedule_preserved_and_audited_before_safe_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, _) = setup(temp.path());
    let path = repo.root().to_owned();
    drop(repo);
    let bad = b"{broken fixture schedule";
    fs::write(path.join("schedule.json"), bad).unwrap();
    let state = scheduler::load_schedule(&path, PASSPHRASE).unwrap();
    assert_eq!(state.last_success, 0);
    let preserved = fs::read_dir(&path)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("schedule.corrupt-")
        })
        .unwrap();
    assert_eq!(fs::read(preserved.path()).unwrap(), bad);
    assert_eq!(fs::read_dir(path.join("audit")).unwrap().count(), 1);
    scheduler::load_schedule(&path, PASSPHRASE).unwrap();
    assert_eq!(fs::read_dir(path.join("audit")).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn r2_status_uses_private_unix_socket_and_key_source_variants() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let path = repo.root().to_owned();
    drop(repo);
    fs::write(work.join("a"), "fixture").unwrap();
    let source = bunker::repository::KeySource::passphrase(PASSPHRASE);
    scheduler::daemon_with_key_source(&path, &source, &work, None, true).unwrap();
    let meta = fs::metadata(path.join("daemon.sock")).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("daemon.json")).unwrap()).unwrap();
    assert_eq!(metadata["transport"], "unix");
    assert!(metadata.get("address").is_none());
    let mut output = vec![];
    mcp::serve_with_key_source(&path, &source, &work, &b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"list_snapshots\"}}\n"[..], &mut output).unwrap();
    assert!(!String::from_utf8(output).unwrap().contains("isError"));
}

#[test]
fn r2_completed_restore_discards_staged_after_but_keeps_preimages_and_journal() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("a"), "snapshot fixture").unwrap();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    fs::write(work.join("a"), "live fixture").unwrap();
    let plan = repo.plan(&m.id, &work, None).unwrap();
    repo.restore(&m.id, &work, None, &plan.confirmation)
        .unwrap();
    let transaction = fs::read_dir(repo.root().join("transactions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let names: Vec<_> = fs::read_dir(transaction.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!names.iter().any(|p| p.ends_with(".after")));
    assert!(names.iter().any(|p| p.ends_with(".before")));
    assert!(names.iter().any(|p| p == "journal"));
}

#[test]
fn r2_prune_is_operator_only_and_retains_active_and_corrupt_requests() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let active = repo
        .save_request(&serde_json::json!({"status":"pending","expires_at":u64::MAX}))
        .unwrap();
    let denied = repo
        .save_request(&serde_json::json!({"status":"denied","expires_at":u64::MAX}))
        .unwrap();
    let expired = repo
        .save_request(&serde_json::json!({"status":"pending","expires_at":0}))
        .unwrap();
    let corrupt = repo
        .save_request(&serde_json::json!({"status":"denied"}))
        .unwrap();
    fs::write(
        repo.root().join("requests").join(&corrupt),
        "corrupt fixture",
    )
    .unwrap();
    assert!(mcp::call(&repo, &work, "prune_requests", &serde_json::json!({})).is_err());
    assert!(repo.prune_requests(0).is_err());
    assert_eq!(repo.prune_requests(1024).unwrap(), 2);
    assert!(repo.request(&active).is_ok());
    assert!(repo.request(&denied).is_err());
    assert!(repo.request(&expired).is_err());
    assert!(repo.root().join("requests").join(corrupt).exists());
    assert_eq!(repo.prune_requests(1024).unwrap(), 0);
}

#[test]
fn r2_thousand_tiny_files_remain_durable_and_deduplicate() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    for i in 0..1000 {
        fs::write(work.join(format!("f{i}.txt")), format!("content {i}")).unwrap();
    }
    let started = std::time::Instant::now();
    let m = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    eprintln!("1000 tiny files first snapshot: {:?}", started.elapsed());
    assert_eq!(m.files.len(), 1000);
    let chunks = fs::read_dir(repo.root().join("chunks")).unwrap().count();
    let started = std::time::Instant::now();
    let again = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    eprintln!("1000 tiny files repeated snapshot: {:?}", started.elapsed());
    assert_eq!(
        chunks,
        fs::read_dir(repo.root().join("chunks")).unwrap().count()
    );
    for f in again.files {
        assert_eq!(
            repo.file_bytes(&f).unwrap().as_slice(),
            fs::read(work.join(f.path)).unwrap()
        );
    }
}

#[test]
fn r2_case_collision_is_a_diagnostic_not_a_snapshot_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    fs::write(work.join("Name.txt"), "fixture upper").unwrap();
    // Case-insensitive filesystems cannot materialize this collision.
    if work.join("name.txt").exists() {
        return;
    }
    fs::write(work.join("name.txt"), "fixture lower").unwrap();
    fs::write(work.join("safe.txt"), "fixture safe").unwrap();
    let manifest = repo
        .snapshot(&work, &Policy::default(), None, None, "test")
        .unwrap();
    assert_eq!(manifest.files.len(), 2);
    assert!(manifest.files.iter().any(|file| file.path == "safe.txt"));
    assert_eq!(
        manifest
            .diagnostics
            .iter()
            .filter(|d| d.reason == "case_collision")
            .count(),
        1
    );
}

#[test]
fn r2_corrupt_schedule_audit_outage_retries_without_preventing_startup() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, work) = setup(temp.path());
    let path = repo.root().to_owned();
    drop(repo);
    fs::write(work.join("a"), "fixture").unwrap();
    fs::write(path.join("schedule.json"), "corrupt fixture").unwrap();
    fs::write(path.join("audit"), "fixture obstruction").unwrap();
    let mut state = scheduler::load_schedule(&path, PASSPHRASE).unwrap();
    assert!(state.pending_schedule_recovery.is_some());
    assert!(scheduler::tick(&path, PASSPHRASE, &work, None, &mut state, true).is_err());
    assert!(state.last_snapshot.is_some());
    fs::remove_file(path.join("audit")).unwrap();
    scheduler::tick(&path, PASSPHRASE, &work, None, &mut state, true).unwrap();
    assert!(state.pending_schedule_recovery.is_none());
    assert_eq!(fs::read_dir(path.join("snapshots")).unwrap().count(), 1);
}
