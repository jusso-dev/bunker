//! Disposable fixture roots only; no user HOME/configuration or agent boot probes.
use bunker::{
    policy::Policy,
    repository::{Repository, SetupScope},
    session_hooks::*,
};
use bunker_discovery::{AgentId, DiscoveryContext, Platform, ReferenceKind};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
};

const PASS: &str = "setup-fixture-passphrase";
fn put(root: &Path, relative: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn fixture() -> (tempfile::TempDir, DiscoveryContext, Repository) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    let workspace = root.join("workspace");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&workspace).unwrap();
    let mut context = DiscoveryContext::new(Platform::Linux, home.clone(), vec![workspace.clone()]);
    context.config_dir = Some(root.join("editor"));
    let layouts: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/discovery/layout.json")).unwrap();
    for (name, target) in [
        ("home", &home),
        ("workspace", &workspace),
        ("editor", context.config_dir.as_ref().unwrap()),
    ] {
        for (relative, text) in layouts[name].as_object().unwrap() {
            put(target, relative, text.as_str().unwrap());
        }
    }
    let repo = Repository::init(&root.join("repo"), PASS).unwrap();
    (temp, context, repo)
}

#[test]
fn five_agents_capture_restore_and_replication_keep_encrypted_scopes() {
    let (temp, context, repo) = fixture();
    let opaque = b"\x00\xfffixture-uuid-123-ABC\r\n";
    put(&context.home, ".codex/skills/tool/vendor/asset.bin", opaque);
    put(
        &context.home,
        ".claude/skills/tool/ordinary.json",
        b"{ definitely not valid JSON }",
    );
    let snapshots = repo
        .snapshot_setup(&context, &Policy::default(), None, "manual")
        .unwrap();
    assert_eq!(snapshots.len(), 2);
    let mut agents = BTreeSet::new();
    for snapshot in &snapshots {
        let scope = snapshot.setup.as_ref().unwrap();
        scope.validate().unwrap();
        agents.extend(scope.agents.iter().copied());
        assert_eq!(scope.scope_count, 2);
        assert!(!snapshot
            .files
            .iter()
            .any(|f| f.path.starts_with(".github/")));
        repo.verify(&snapshot.id).unwrap();
        let destination = temp
            .path()
            .canonicalize()
            .unwrap()
            .join(format!("restore-{}", scope.scope_index));
        fs::create_dir(&destination).unwrap();
        let plan = repo.plan_setup(&snapshot.id, &destination, None).unwrap();
        repo.restore_setup(&snapshot.id, &destination, None, &plan.confirmation, false)
            .unwrap();
        if scope.source_root == context.home {
            assert_eq!(
                fs::read(destination.join(".codex/skills/tool/vendor/asset.bin")).unwrap(),
                opaque
            );
            assert_eq!(
                fs::read(destination.join(".claude/skills/tool/ordinary.json")).unwrap(),
                b"{ definitely not valid JSON }"
            );
        }
        let encrypted = repo
            .encrypted_object(&format!("snapshots/{}", snapshot.id))
            .unwrap();
        assert!(!encrypted
            .windows(context.home.to_str().unwrap().len())
            .any(|b| b == context.home.to_str().unwrap().as_bytes()));
    }
    assert_eq!(agents.len(), 5);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let operator = opendal::Operator::new(opendal::services::Memory::default()).unwrap();
        bunker::storage::replicate(&repo, &operator).await.unwrap();
        let namespace = blake3::hash(&repo.encrypted_object("repository.json").unwrap())
            .to_hex()
            .to_string();
        let restored = temp.path().canonicalize().unwrap().join("dr-repository");
        assert_eq!(
            bunker::storage::recover(&operator, &namespace, &restored, PASS)
                .await
                .unwrap(),
            snapshots.len()
        );
        let dr = Repository::open(&restored, PASS).unwrap();
        for snapshot in &snapshots {
            let manifest = dr.manifest(&snapshot.id).unwrap();
            assert_eq!(
                manifest.setup.as_ref().unwrap().source_root,
                snapshot.setup.as_ref().unwrap().source_root
            );
            dr.verify(&snapshot.id).unwrap();
        }
    });
}

#[test]
fn sanitization_references_partial_errors_and_rebind_guard() {
    let (temp, context, repo) = fixture();
    put(
        &context.home,
        ".claude/settings.json",
        br#"{"apiKey":"fixture-literal-secret","env":{"BOUND":"${env:MY_KEY}"}}"#,
    );
    put(
        &context.home,
        ".cursor/settings.json",
        b"{ invalid fixture-secret-never-log }",
    );
    let snapshots = repo
        .snapshot_setup(&context, &Policy::default(), None, "manual")
        .unwrap();
    let home = snapshots
        .iter()
        .find(|m| m.setup.as_ref().unwrap().source_root == context.home)
        .unwrap();
    let config = home
        .files
        .iter()
        .find(|f| f.path == ".claude/settings.json")
        .unwrap();
    assert!(config.sanitized);
    assert!(config
        .secret_references
        .iter()
        .any(|r| r.kind == ReferenceKind::RebindRequired));
    assert!(home
        .diagnostics
        .iter()
        .any(|d| d.path == ".cursor/settings.json"));
    assert!(!format!("{:?}", home.diagnostics).contains("fixture-secret-never-log"));
    assert!(!home.files.iter().any(|f| f.path == ".cursor/settings.json"));
    let target = temp.path().canonicalize().unwrap().join("target");
    fs::create_dir(&target).unwrap();
    put(&target, ".claude/settings.json", br#"{"keep":"current"}"#);
    let plan = repo
        .plan_setup(&home.id, &target, Some(".claude/settings.json"))
        .unwrap();
    assert!(repo
        .restore_setup(
            &home.id,
            &target,
            Some(".claude/settings.json"),
            &plan.confirmation,
            false
        )
        .is_err());
    repo.restore_setup(
        &home.id,
        &target,
        Some(".claude/settings.json"),
        &plan.confirmation,
        true,
    )
    .unwrap();
    let restored = fs::read_to_string(target.join(".claude/settings.json")).unwrap();
    assert!(!restored.contains("fixture-literal-secret"));
    assert!(restored.contains("BUNKER_SECRET_") && restored.contains("${env:MY_KEY}"));
    // Capture and restore never redirected writes back to the origin.
    assert!(
        fs::read_to_string(context.home.join(".claude/settings.json"))
            .unwrap()
            .contains("fixture-literal-secret")
    );
    let ordinary = repo
        .snapshot(
            &context.workspace_roots[0],
            &Policy::default(),
            None,
            None,
            "manual",
        )
        .unwrap();
    assert!(repo.plan_setup(&ordinary.id, &target, None).is_err());
}

#[test]
fn aggregate_caps_no_partial_publication_and_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let context = DiscoveryContext::new(Platform::Linux, root.join("home"), vec![]);
    put(&context.home, ".codex/skills/tool/cache.sqlite", [1u8; 16]);
    put(&context.home, ".claude/skills/tool/.env", b"secret fixture");
    put(&context.home, ".codex/skills/tool/ordinary.txt", [2u8; 16]);
    put(&context.home, ".config/Cursor/User/settings.json", b"{}");
    let repo = Repository::init(&root.join("repo"), PASS).unwrap();
    let mut policy = Policy {
        max_file_bytes: 32,
        size_cap_bytes: 32,
        default_includes: vec!["**/*.sqlite".into(), "**/.env".into()],
        ..Policy::default()
    };
    assert!(repo
        .snapshot_setup(&context, &policy, None, "manual")
        .is_err());
    assert!(repo.list().unwrap().is_empty());
    policy.size_cap_bytes = 64;
    let snapshots = repo
        .snapshot_setup(&context, &policy, None, "manual")
        .unwrap();
    let files: Vec<_> = snapshots
        .iter()
        .flat_map(|m| m.files.iter().map(|f| f.path.as_str()))
        .collect();
    assert!(files.contains(&".codex/skills/tool/cache.sqlite"));
    assert!(!files.iter().any(|f| f.ends_with(".env")));
    policy.default_includes.clear();
    let defaults = repo
        .snapshot_setup(&context, &policy, None, "manual")
        .unwrap();
    assert!(!defaults
        .iter()
        .flat_map(|m| &m.files)
        .any(|f| f.path.ends_with("cache.sqlite")));
}

#[test]
fn session_dedupe_survives_reopen_and_distinguishes_agent_and_session() {
    let (temp, context, repo) = fixture();
    let event = SessionEnd {
        agent: AgentId::Codex,
        session_id: "fixture-session-1".into(),
    };
    let first = repo
        .snapshot_setup_for_session(&context, &Policy::default(), &event)
        .unwrap();
    let first_ids: Vec<_> = first.iter().map(|m| &m.id).collect();
    let repeated = repo
        .snapshot_setup_for_session(&context, &Policy::default(), &event)
        .unwrap();
    assert_eq!(
        first_ids,
        repeated.iter().map(|m| &m.id).collect::<Vec<_>>()
    );
    drop(repo);
    let repo = Repository::open(&temp.path().join("repo"), PASS).unwrap();
    let restarted = repo
        .snapshot_setup_for_session(&context, &Policy::default(), &event)
        .unwrap();
    assert_eq!(
        first_ids,
        restarted.iter().map(|m| &m.id).collect::<Vec<_>>()
    );
    let different = SessionEnd {
        agent: AgentId::ClaudeCode,
        ..event
    };
    let second = repo
        .snapshot_setup_for_session(&context, &Policy::default(), &different)
        .unwrap();
    assert_ne!(first[0].id, second[0].id);
    // An incomplete published group must not suppress a retry.
    fs::remove_file(repo.root().join("snapshots").join(&second[0].id)).unwrap();
    let retried = repo
        .snapshot_setup_for_session(&context, &Policy::default(), &different)
        .unwrap();
    assert!(retried
        .iter()
        .all(|m| !second.iter().any(|old| old.id == m.id)));
}

#[test]
fn source_scope_validation_and_untrusted_hook_payloads() {
    let mut scope = SetupScope {
        version: 1,
        source_root: PathBuf::from("/explicit/home"),
        agents: vec![AgentId::Codex],
        capture_id: "a".repeat(64),
        scope_index: 0,
        scope_count: 1,
        session_event: None,
    };
    scope.validate().unwrap();
    scope.source_root = PathBuf::from("C:\\Users\\fixture");
    scope.validate().unwrap();
    scope.source_root = PathBuf::from("../escape");
    assert!(scope.validate().is_err());
    scope.source_root = PathBuf::from("/explicit/home");
    scope.agents.clear();
    assert!(scope.validate().is_err());
    let event = SessionEnd::from_claude_input(br#"{"session_id":"fixture-1","hook_event_name":"SessionEnd","cwd":"/never-read","transcript_path":"/never-read"}"#.as_slice()).unwrap();
    assert_eq!(event.agent, AgentId::ClaudeCode);
    for bytes in [
        br#"{"session_id":"../escape","hook_event_name":"SessionEnd"}"#.as_slice(),
        br#"{"session_id":"fixture","hook_event_name":"Stop"}"#.as_slice(),
        b"{fixture-secret-in-invalid-json".as_slice(),
    ] {
        let error = SessionEnd::from_claude_input(bytes).unwrap_err();
        assert!(!error.to_string().contains("fixture-secret"));
    }
    assert!(SessionEnd::from_claude_input(vec![b' '; 65537].as_slice()).is_err());
}

fn hook_fixture() -> (tempfile::TempDir, HookInvocation) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    let workspace = root.join("workspace with spaces");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&workspace).unwrap();
    let executable = root.join(if cfg!(windows) {
        "bunker fixture.exe"
    } else {
        "bunker ' fixture"
    });
    fs::write(&executable, b"fixture: not executed").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let invocation = HookInvocation {
        executable,
        repository: root.join("repo"),
        home,
        policy: None,
        key_config: None,
        workspaces: vec![workspace],
    };
    (temp, invocation)
}

#[test]
fn native_hook_is_explicit_idempotent_reversible_and_preserves_other_hooks() {
    let (_temp, invocation) = hook_fixture();
    let original = br#"{ "hooks":{"Stop":[{"hooks":[{"type":"command","command":"NEVER EXECUTE FIXTURE"}]}]}, "apiKey":"fixture-existing-secret" }"#;
    put(&invocation.home, ".claude/settings.json", original);
    let plan = plan_claude_hook(&invocation, true).unwrap();
    assert!(plan.changed);
    assert!(!format!("{plan:?}").contains("fixture-existing-secret"));
    assert_eq!(fs::read(&plan.destination).unwrap(), original);
    assert!(apply_claude_hook(&plan, "not-confirmed").is_err());
    apply_claude_hook(&plan, &plan.confirmation).unwrap();
    let updated: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan.destination).unwrap()).unwrap();
    let handler = &updated["hooks"]["SessionEnd"][0]["hooks"][0];
    assert_eq!(handler["command"], invocation.executable.to_str().unwrap());
    assert_eq!(
        handler["args"].as_array().unwrap().last().unwrap(),
        invocation.workspaces[0].to_str().unwrap()
    );
    assert!(updated["hooks"]["Stop"].is_array());
    assert_eq!(updated["apiKey"], "fixture-existing-secret");
    assert!(!plan_claude_hook(&invocation, true).unwrap().changed);
    rollback_claude_hook(&plan).unwrap();
    assert_eq!(fs::read(&plan.destination).unwrap(), original);
    let plan = plan_claude_hook(&invocation, true).unwrap();
    apply_claude_hook(&plan, &plan.confirmation).unwrap();
    let remove = plan_claude_hook(&invocation, false).unwrap();
    apply_claude_hook(&remove, &remove.confirmation).unwrap();
    let updated: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan.destination).unwrap()).unwrap();
    assert!(updated["hooks"]["SessionEnd"].is_null());
    assert!(updated["hooks"]["Stop"].is_array());
}

#[test]
fn hook_review_rejects_stale_or_modified_plans_and_new_file_rolls_back() {
    let (_temp, invocation) = hook_fixture();
    let plan = plan_claude_hook(&invocation, true).unwrap();
    apply_claude_hook(&plan, &plan.confirmation).unwrap();
    rollback_claude_hook(&plan).unwrap();
    assert!(!plan.destination.exists());
    let mut plan = plan_claude_hook(&invocation, true).unwrap();
    plan.handler["timeout"] = serde_json::json!(1);
    assert!(apply_claude_hook(&plan, &plan.confirmation).is_err());
    let plan = plan_claude_hook(&invocation, true).unwrap();
    put(&invocation.home, ".claude/settings.json", b"{}");
    assert!(apply_claude_hook(&plan, &plan.confirmation).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_fifo_and_executable_modes_are_safe() {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{symlink, PermissionsExt},
    };
    let (temp, context, repo) = fixture();
    let external = temp.path().canonicalize().unwrap().join("external");
    fs::create_dir(&external).unwrap();
    put(&external, "secret", b"unread fixture secret");
    let skill = context.home.join(".codex/skills/tool");
    fs::create_dir_all(&skill).unwrap();
    symlink(external.join("secret"), skill.join("link")).unwrap();
    let fifo = std::ffi::CString::new(skill.join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    put(
        &context.home,
        ".codex/skills/tool/run",
        b"#!/bin/sh\nexit 0\n",
    );
    fs::set_permissions(skill.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
    put(
        &context.home,
        ".codex/skills/tool/nonportable.",
        b"skip only me",
    );
    let snapshots = repo
        .snapshot_setup(&context, &Policy::default(), None, "manual")
        .unwrap();
    let home = snapshots
        .iter()
        .find(|m| m.setup.as_ref().unwrap().source_root == context.home)
        .unwrap();
    assert!(
        home.files
            .iter()
            .find(|f| f.path.ends_with("/run"))
            .unwrap()
            .executable
    );
    for name in ["/link", "/fifo", "/nonportable."] {
        assert!(!home.files.iter().any(|f| f.path.ends_with(name)));
    }
    symlink(&external, temp.path().join("redirect")).unwrap();
    assert!(repo
        .plan_setup(&home.id, &temp.path().join("redirect"), None)
        .is_err());
    let (_temp2, invocation) = hook_fixture();
    symlink(&external, invocation.home.join(".claude")).unwrap();
    assert!(plan_claude_hook(&invocation, true).is_err());
}

#[cfg(unix)]
fn fixture_command(root: &Path, body: &str) -> Command {
    use std::os::unix::fs::PermissionsExt;
    let program = root.join(format!("fixture-{}", uuid::Uuid::new_v4()));
    fs::write(&program, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(root);
    command
}

#[cfg(unix)]
#[test]
fn wrapper_keeps_literal_args_and_snapshots_success_failure_signal_and_cancel() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let mut command = fixture_command(&root, "printf '%s\\n' \"$@\" > args; exit 7");
    command.args(["literal argument", "$(touch injected)", "' ; exit 99"]);
    let outcome = run_session(&mut command, &cancel, || Ok(42)).unwrap();
    assert_eq!(outcome.process, ProcessEnd::Exited(7));
    assert_eq!(outcome.snapshot.unwrap(), 42);
    assert!(!root.join("injected").exists());
    assert_eq!(
        fs::read_to_string(root.join("args")).unwrap(),
        "literal argument\n$(touch injected)\n' ; exit 99\n"
    );
    let outcome = run_session(&mut fixture_command(&root, "exit 0"), &cancel, || Ok(())).unwrap();
    assert_eq!(outcome.process, ProcessEnd::Exited(0));
    let outcome = run_session(
        &mut fixture_command(&root, "kill -TERM $$"),
        &cancel,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(outcome.process, ProcessEnd::Signaled(libc::SIGTERM));
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            cancel.store(true, Ordering::SeqCst);
        });
        let outcome = run_session(
            &mut fixture_command(&root, "exec /bin/sleep 30"),
            &cancel,
            || Ok("cancel snapshot"),
        )
        .unwrap();
        assert_eq!(outcome.process, ProcessEnd::Cancelled);
        assert_eq!(outcome.snapshot.unwrap(), "cancel snapshot");
    });
}

#[cfg(unix)]
#[test]
fn wrapper_spawn_failure_snapshot_error_and_recursion_are_explicit() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let mut command = fixture_command(&root, "exit 0");
    fs::set_permissions(command.get_program(), fs::Permissions::from_mode(0o600)).unwrap();
    let outcome = run_session(&mut command, &cancel, || Ok("spawn failure snapshot")).unwrap();
    assert_eq!(outcome.process, ProcessEnd::SpawnFailed);
    assert!(outcome.snapshot.is_ok());
    let outcome = run_session(&mut fixture_command(&root, "exit 0"), &cancel, || {
        Err::<(), _>(anyhow::anyhow!("fixture snapshot failed"))
    })
    .unwrap();
    assert_eq!(outcome.process, ProcessEnd::Exited(0));
    assert!(outcome.snapshot.is_err());
    let mut recursive = fixture_command(&root, "exit 0");
    recursive.env(WRAPPER_ACTIVE, "1");
    assert!(run_session(&mut recursive, &cancel, || Ok(())).is_err());
}

#[test]
fn filtered_schedule_capture_dedupes_without_inventing_agent_events() {
    let (_temp, context, repo) = fixture();
    let id = "a".repeat(64);
    let codex = repo
        .snapshot_setup_for_schedule_filtered(
            &context,
            &Policy::default(),
            &id,
            Some(AgentId::Codex),
        )
        .unwrap();
    assert_eq!(codex.len(), 1);
    assert_eq!(codex[0].agent.as_deref(), Some("codex"));
    assert_eq!(codex[0].trigger, "schedule_setup");
    assert!(codex[0].session.is_none());
    assert!(codex[0].files.iter().all(|f| f.path.starts_with(".codex/")));
    let retry = repo
        .snapshot_setup_for_schedule_filtered(
            &context,
            &Policy::default(),
            &id,
            Some(AgentId::Codex),
        )
        .unwrap();
    assert_eq!(codex[0].id, retry[0].id);
    let all = repo
        .snapshot_setup_for_schedule(&context, &Policy::default(), &id)
        .unwrap();
    assert!(all.iter().all(|m| m.id != codex[0].id));
}

#[test]
fn scheduler_opt_in_retries_setup_independently_without_duplicate_workspace() {
    use bunker::scheduler::{self, ScheduleState};
    let (temp, context, repo) = fixture();
    let repo_path = repo.root().to_owned();
    drop(repo);
    let root = temp.path().canonicalize().unwrap();
    let policy_path = root.join("policy.toml");
    let missing_home = root.join("missing-home");
    let policy = Policy {
        setup_home: Some(missing_home.clone()),
        ..Policy::default()
    };
    fs::write(&policy_path, toml::to_string(&policy).unwrap()).unwrap();
    let mut state = ScheduleState::default();
    scheduler::tick(
        &repo_path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut state,
        true,
    )
    .unwrap();
    assert!(state.pending_setup.is_some() && state.pending_detection.is_none());
    assert_eq!(state.failures, 0);
    assert_eq!(state.setup_failures, 1);
    let workspace_id = state.last_snapshot.clone().unwrap();
    let repo = Repository::open(&repo_path, PASS).unwrap();
    assert_eq!(repo.list().unwrap().len(), 1);
    drop(repo);
    put(
        &missing_home,
        ".codex/config.toml",
        "model = 'fixture-retry'\n",
    );
    state = scheduler::load_schedule(&repo_path, PASS).unwrap();
    scheduler::tick(
        &repo_path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut state,
        true,
    )
    .unwrap();
    assert_eq!(state.last_snapshot.as_deref(), Some(workspace_id.as_str()));
    assert!(state.pending_setup.is_none() && state.pending_detection.is_none());
    assert_eq!(state.setup_failures, 0);
    let repo = Repository::open(&repo_path, PASS).unwrap();
    let snapshots = repo.list().unwrap();
    assert_eq!(snapshots.len(), 2);
    let setup = snapshots.iter().find(|m| m.setup.is_some()).unwrap();
    assert_eq!(setup.setup.as_ref().unwrap().source_root, missing_home);
    assert_eq!(setup.trigger, "schedule_setup");
}

#[test]
fn scheduled_setup_audit_retry_reuses_complete_group() {
    use bunker::scheduler::{self, PendingSetup, ScheduleState};
    let (temp, context, repo) = fixture();
    let path = repo.root().to_owned();
    let workspace = repo
        .snapshot(
            &context.workspace_roots[0],
            &Policy::default(),
            None,
            None,
            "schedule",
        )
        .unwrap();
    let policy = Policy {
        setup_home: Some(context.home.clone()),
        ..Policy::default()
    };
    let policy_path = temp.path().join("policy.toml");
    fs::write(&policy_path, toml::to_string(&policy).unwrap()).unwrap();
    let mut state = ScheduleState {
        last_snapshot: Some(workspace.id.clone()),
        workspace: Some(context.workspace_roots[0].canonicalize().unwrap()),
        next_run: bunker::repository::now() + 3600,
        pending_setup: Some(PendingSetup {
            workspace_snapshot: workspace.id,
            policy: policy.clone(),
        }),
        ..ScheduleState::default()
    };
    fs::write(path.join("audit"), b"fixture obstruction").unwrap();
    drop(repo);
    scheduler::tick(
        &path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut state,
        true,
    )
    .unwrap();
    assert!(state.pending_setup.is_some() && state.last_setup_error.is_some());
    assert_eq!(state.failures, 0);
    let repo = Repository::open(&path, PASS).unwrap();
    let ids: BTreeSet<_> = repo.list().unwrap().into_iter().map(|m| m.id).collect();
    assert!(ids.len() > 1);
    drop(repo);
    fs::remove_file(path.join("audit")).unwrap();
    let mut restarted = scheduler::load_schedule(&path, PASS).unwrap();
    scheduler::tick(
        &path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut restarted,
        true,
    )
    .unwrap();
    let repo = Repository::open(&path, PASS).unwrap();
    assert_eq!(
        ids,
        repo.list().unwrap().into_iter().map(|m| m.id).collect()
    );
    assert!(restarted.pending_setup.is_none() && restarted.last_setup_error.is_none());
}

#[test]
fn setup_outage_never_blocks_due_workspace_and_policy_change_cancels_stale_job() {
    use bunker::scheduler::{self, ScheduleState};
    let (temp, context, repo) = fixture();
    let path = repo.root().to_owned();
    drop(repo);
    let policy_path = temp.path().join("policy.toml");
    let policy = Policy {
        setup_home: Some(temp.path().canonicalize().unwrap().join("missing")),
        ..Policy::default()
    };
    fs::write(&policy_path, toml::to_string(&policy).unwrap()).unwrap();
    let mut state = ScheduleState::default();
    scheduler::tick(
        &path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut state,
        true,
    )
    .unwrap();
    let first = state.last_snapshot.clone().unwrap();
    assert!(state.pending_setup.is_some());
    state.next_run = 0;
    state.setup_retry_after = bunker::repository::now() + 3600;
    scheduler::tick(
        &path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut state,
        false,
    )
    .unwrap();
    assert_ne!(state.last_snapshot.as_deref(), Some(first.as_str()));
    assert!(state
        .setup_diagnostics
        .iter()
        .any(|d| d.workspace_snapshot == first && d.reason == "superseded_pending_setup"));
    assert_eq!(state.failures, 0);
    let repo = Repository::open(&path, PASS).unwrap();
    assert_eq!(repo.list().unwrap().len(), 2);
    drop(repo);
    // Neither the formerly configured missing HOME nor the newly selected HOME
    // is scanned for the old job after a policy change, even during backoff.
    let changed = Policy {
        setup_home: Some(context.home.clone()),
        ..Policy::default()
    };
    fs::write(&policy_path, toml::to_string(&changed).unwrap()).unwrap();
    scheduler::tick(
        &path,
        PASS,
        &context.workspace_roots[0],
        Some(&policy_path),
        &mut state,
        false,
    )
    .unwrap();
    assert!(state.pending_setup.is_none());
    assert!(state
        .setup_diagnostics
        .iter()
        .any(|d| d.reason == "setup_policy_changed"));
    let repo = Repository::open(&path, PASS).unwrap();
    assert_eq!(repo.list().unwrap().len(), 2);
}

#[test]
fn setup_policy_is_explicit_and_optional() {
    assert!(Policy::default().setup_home.is_none());
    assert!(Policy {
        setup_home: Some("relative-home".into()),
        ..Policy::default()
    }
    .validate()
    .is_err());
    let legacy: Policy = toml::from_str("interval_seconds = 3600").unwrap();
    assert!(legacy.setup_home.is_none());
}

#[test]
fn deduplication_rejects_damaged_completed_groups() {
    let (_temp, context, repo) = fixture();
    let event = SessionEnd {
        agent: AgentId::Codex,
        session_id: "integrity-fixture".into(),
    };
    let captured = repo
        .snapshot_setup_for_session(&context, &Policy::default(), &event)
        .unwrap();
    let chunk = captured
        .iter()
        .flat_map(|m| &m.files)
        .flat_map(|f| &f.chunks)
        .next()
        .unwrap();
    fs::write(
        repo.root().join("chunks").join(chunk),
        b"fixture corruption",
    )
    .unwrap();
    assert!(repo
        .snapshot_setup_for_session(&context, &Policy::default(), &event)
        .is_err());
}
