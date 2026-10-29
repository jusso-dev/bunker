use bunker::{host_service, repository, restore_probes};
use host_service::{ProbeFailure, ProbeOutcome, ProbeSkip};
use restore_probes::*;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn command() -> TrustedCommand {
    TrustedCommand {
        executable: "/usr/local/bin/fixture-agent".into(),
        args: vec![],
        requires_network: false,
        requires_credentials: false,
    }
}
fn config() -> TrustedProbeConfig {
    TrustedProbeConfig {
        docker_executable: PathBuf::from("/usr/bin/docker"),
        docker_context: "homelab".into(),
        docker_config: PathBuf::from("/operator/docker"),
        image: format!("example.test/probes@sha256:{}", "a".repeat(64)),
        timeout_seconds: 2,
        output_limit_bytes: 4096,
        agents: vec![TrustedAgentProbe {
            agent: "codex".into(),
            command: command(),
        }],
        mcps: vec![TrustedMcpProbe {
            name: "fixture".into(),
            command: command(),
        }],
    }
}
struct Fixture {
    root: Option<PathBuf>,
    calls: usize,
    cleaned: bool,
    unavailable: bool,
    leak: bool,
}
impl Fixture {
    fn new() -> Self {
        Self {
            root: None,
            calls: 0,
            cleaned: false,
            unavailable: false,
            leak: false,
        }
    }
}
impl ProbeExecutor for Fixture {
    fn prepare(&mut self, root: &Path) -> Result<(), ProbeSkip> {
        assert_eq!(
            fs::read_to_string(root.join("data.txt")).unwrap(),
            "verified snapshot bytes"
        );
        assert!(!root.join("repository").exists());
        self.root = Some(root.to_owned());
        if self.unavailable {
            Err(ProbeSkip::RuntimeUnavailable)
        } else {
            Ok(())
        }
    }
    fn execute(&mut self, _: ProbeRequest<'_>) -> ProbeOutcome {
        self.calls += 1;
        ProbeOutcome::Passed
    }
    fn cleanup(&mut self) -> Result<(), ProbeFailure> {
        self.cleaned = true;
        if self.leak {
            Err(ProbeFailure::CleanupFailed)
        } else {
            Ok(())
        }
    }
}
fn snapshot(root: &Path) -> (repository::Repository, String) {
    let work = root.join("workspace");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("data.txt"), "verified snapshot bytes").unwrap();
    let repo = repository::Repository::init(&root.join("repository"), "fixture-only").unwrap();
    let id = repo
        .snapshot(
            &work,
            &bunker::policy::Policy::default(),
            Some("codex".into()),
            None,
            "manual",
        )
        .unwrap()
        .id;
    (repo, id)
}
#[test]
fn verified_disposable_restore_has_no_repository_mount_and_cleans_up() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, id) = snapshot(temp.path());
    let mut executor = Fixture::new();
    let result = run_restore_probes(&repo, &id, &config(), &mut executor).unwrap();
    assert_eq!(executor.calls, 2);
    assert!(executor.cleaned);
    assert!(!executor.root.unwrap().exists());
    assert_eq!(result.agents[0].outcome, ProbeOutcome::Passed);
    assert_eq!(result.mcps[0].outcome, ProbeOutcome::Passed);
}
#[test]
fn unavailable_dependencies_skip_and_cleanup_failure_cannot_pass() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, id) = snapshot(temp.path());
    let mut cfg = config();
    cfg.agents[0].command.requires_network = true;
    cfg.mcps[0].command.requires_credentials = true;
    let mut executor = Fixture::new();
    let result = run_restore_probes(&repo, &id, &cfg, &mut executor).unwrap();
    assert_eq!(executor.calls, 0);
    assert_eq!(
        result.agents[0].outcome,
        ProbeOutcome::NotRunWithReason(ProbeSkip::NetworkUnavailable)
    );
    assert_eq!(
        result.mcps[0].outcome,
        ProbeOutcome::NotRunWithReason(ProbeSkip::CredentialsUnavailable)
    );
    executor.leak = true;
    let result = run_restore_probes(&repo, &id, &config(), &mut executor).unwrap();
    assert_eq!(
        result.agents[0].outcome,
        ProbeOutcome::FailedWithReason(ProbeFailure::CleanupFailed)
    );
    executor.leak = false;
    executor.unavailable = true;
    let result = run_restore_probes(&repo, &id, &config(), &mut executor).unwrap();
    assert_eq!(
        result.agents[0].outcome,
        ProbeOutcome::NotRunWithReason(ProbeSkip::RuntimeUnavailable)
    );
}
#[test]
fn corrupt_restore_never_starts_an_executor() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, id) = snapshot(temp.path());
    let manifest = repo.manifest(&id).unwrap();
    fs::write(
        repo.root()
            .join("chunks")
            .join(&manifest.files[0].chunks[0]),
        "corrupt",
    )
    .unwrap();
    let mut executor = Fixture::new();
    let result = run_restore_probes(&repo, &id, &config(), &mut executor).unwrap();
    assert!(executor.root.is_none());
    assert_eq!(executor.calls, 0);
    assert!(executor.cleaned);
    assert_eq!(
        result.agents[0].outcome,
        ProbeOutcome::FailedWithReason(ProbeFailure::RestoreFailed)
    );
}
#[test]
fn config_requires_pinned_image_explicit_context_and_bounded_trusted_commands() {
    let cfg = config();
    cfg.validate().unwrap();
    for change in 0..7 {
        let mut cfg = cfg.clone();
        match change {
            0 => cfg.image = "untrusted:latest".into(),
            1 => cfg.docker_context.clear(),
            2 => cfg.timeout_seconds = 31,
            3 => cfg.output_limit_bytes = 65537,
            4 => cfg.agents[0].command.executable = "/restore/hook".into(),
            5 => cfg.agents[0].command.args = vec!["x".repeat(2049)],
            _ => cfg.agents.push(cfg.agents[0].clone()),
        }
        assert!(cfg.validate().is_err());
    }
}
#[test]
fn meaningful_boot_and_mcp_responses_reject_exit_zero_empty_wrong_ids_errors_and_versions() {
    let boot = serde_json::json!({"bunkerRestoreProbe":1,"booted":true,"snapshot":"snapshot"});
    assert!(validate_response(
        ProbeKind::AgentBoot,
        "snapshot",
        &serde_json::to_vec(&boot).unwrap()
    )
    .is_ok());
    assert!(validate_response(
        ProbeKind::AgentBoot,
        "other",
        &serde_json::to_vec(&boot).unwrap()
    )
    .is_err());
    assert!(validate_response(ProbeKind::AgentBoot, "snapshot", b"").is_err());
    let response = serde_json::json!({"jsonrpc":"2.0","id":"bunker-restore-probe","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}});
    assert!(validate_response(
        ProbeKind::McpInitialize,
        "",
        &serde_json::to_vec(&response).unwrap()
    )
    .is_ok());
    for change in 0..6 {
        let mut bad = response.clone();
        match change {
            0 => bad["id"] = "other".into(),
            1 => bad["error"] = serde_json::json!({"code":-1}),
            2 => bad["result"]["protocolVersion"] = "unknown".into(),
            3 => bad["result"]["capabilities"] = serde_json::Value::Null,
            4 => bad["result"]["serverInfo"]["name"] = "".into(),
            _ => bad["jsonrpc"] = "1.0".into(),
        }
        assert!(validate_response(
            ProbeKind::McpInitialize,
            "",
            &serde_json::to_vec(&bad).unwrap()
        )
        .is_err());
    }
    assert!(validate_response(ProbeKind::McpInitialize, "", b"{}").is_err());
    let request: serde_json::Value = serde_json::from_slice(&initialize_request()).unwrap();
    assert_eq!(request["method"], "initialize");
}
#[cfg(unix)]
#[test]
fn protected_configuration_rejects_writable_and_symlink_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("probes.json");
    fs::write(&path, serde_json::to_vec(&config()).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    TrustedProbeConfig::load(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(TrustedProbeConfig::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.join("link");
    symlink(&path, &link).unwrap();
    assert!(TrustedProbeConfig::load(&link).is_err());
}

/// Explicit opt-in only: fixture image/commands must be provisioned for this task, never real agents.
#[test]
#[ignore = "requires a disposable operator-provisioned fake-agent/MCP image on docker --context homelab"]
fn disposable_container_smoke() {
    let path = std::env::var_os("BUNKER_PROBE_SMOKE_CONFIG").expect("fixture config path");
    let cfg = TrustedProbeConfig::load(Path::new(&path)).unwrap();
    assert_eq!(cfg.docker_context, "homelab");
    let temp = tempfile::tempdir().unwrap();
    let (repo, id) = snapshot(temp.path());
    let mut docker = DockerExecutor::new(&cfg).unwrap();
    let evidence = run_restore_probes(&repo, &id, &cfg, &mut docker).unwrap();
    assert_eq!(evidence.agents[0].outcome, ProbeOutcome::Passed);
    assert_eq!(evidence.mcps[0].outcome, ProbeOutcome::Passed);
}

#[test]
fn durable_evidence_roundtrip_preserves_id_and_all_outcome_reasons() {
    use host_service::{AgentProbe, EvidenceSandbox, RestoreEvidence};
    for outcome in [
        ProbeOutcome::Passed,
        ProbeOutcome::Failed,
        ProbeOutcome::NotRun,
        ProbeOutcome::FailedWithReason(ProbeFailure::Timeout),
        ProbeOutcome::NotRunWithReason(ProbeSkip::CredentialsUnavailable),
    ] {
        let evidence = RestoreEvidence {
            id: uuid::Uuid::new_v4(),
            snapshot: "a".repeat(64),
            finished_at: chrono::Utc::now(),
            sandbox: EvidenceSandbox::Container,
            agents: vec![AgentProbe {
                agent: "codex".into(),
                outcome,
            }],
            mcps: vec![],
        };
        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded: RestoreEvidence = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.id, evidence.id);
        assert_eq!(decoded.finished_at, evidence.finished_at);
        assert_eq!(decoded.agents[0].outcome, outcome);
        assert_eq!(decoded.agents[0].outcome.reason(), outcome.reason());
    }
}

#[cfg(unix)]
#[test]
fn captured_hooks_are_inert_data_and_probes_use_only_operator_commands() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("workspace");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("data.txt"), "verified snapshot bytes").unwrap();
    fs::write(work.join("captured-hook.sh"), "#!/bin/sh\nexit 99\n").unwrap();
    fs::set_permissions(
        work.join("captured-hook.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(work.join("agent-config.json"), r#"{"hooks":{"boot":"/restore/captured-hook.sh"},"mcpServers":{"untrusted":{"command":"/restore/captured-hook.sh"}}}"#).unwrap();
    let repo =
        repository::Repository::init(&temp.path().join("repository"), "fixture-only").unwrap();
    let snapshot = repo
        .snapshot(
            &work,
            &bunker::policy::Policy::default(),
            None,
            None,
            "manual",
        )
        .unwrap();
    struct Inspect {
        calls: usize,
    }
    impl ProbeExecutor for Inspect {
        fn prepare(&mut self, root: &Path) -> Result<(), ProbeSkip> {
            assert!(root.join("agent-config.json").exists());
            assert_eq!(
                fs::metadata(root.join("captured-hook.sh"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o444
            );
            Ok(())
        }
        fn execute(&mut self, request: ProbeRequest<'_>) -> ProbeOutcome {
            assert_eq!(request.command.executable, "/usr/local/bin/fixture-agent");
            assert!(request.command.args.is_empty());
            self.calls += 1;
            ProbeOutcome::Passed
        }
        fn cleanup(&mut self) -> Result<(), ProbeFailure> {
            Ok(())
        }
    }
    let mut executor = Inspect { calls: 0 };
    let evidence = run_restore_probes(&repo, &snapshot.id, &config(), &mut executor).unwrap();
    assert_eq!(executor.calls, 2);
    assert_eq!(evidence.agents[0].outcome, ProbeOutcome::Passed);
}

#[test]
fn git_snapshots_probe_verified_file_content_without_replaying_refs_or_config() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let work = root.join("workspace");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("data.txt"), "verified snapshot bytes").unwrap();
    for args in [
        vec!["init", "-b", "main"],
        vec!["add", "data.txt"],
        vec!["commit", "-m", "fixture"],
    ] {
        let status = Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .env("HOME", &root)
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
                "-C",
            ])
            .arg(&work)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
    let repo = repository::Repository::init(&root.join("repository"), "fixture-only").unwrap();
    let snapshot = repo
        .snapshot(
            &work,
            &bunker::policy::Policy::default(),
            None,
            None,
            "manual",
        )
        .unwrap();
    let artifact = snapshot
        .git
        .as_ref()
        .expect("fixture captures a Git artifact");
    struct GitFixture(Fixture);
    impl ProbeExecutor for GitFixture {
        fn prepare(&mut self, root: &Path) -> Result<(), ProbeSkip> {
            assert!(!root.join(".git").exists());
            self.0.prepare(root)
        }
        fn execute(&mut self, request: ProbeRequest<'_>) -> ProbeOutcome {
            self.0.execute(request)
        }
        fn cleanup(&mut self) -> Result<(), ProbeFailure> {
            self.0.cleanup()
        }
    }
    let mut executor = GitFixture(Fixture::new());
    let evidence = run_restore_probes(&repo, &snapshot.id, &config(), &mut executor).unwrap();
    assert_eq!(evidence.agents[0].outcome, ProbeOutcome::Passed);
    assert!(matches!(
        evidence.sandbox,
        host_service::EvidenceSandbox::ContainerFileContent
    ));
    assert_eq!(executor.0.calls, 2);
    // Even though refs are not replayed, corrupt authenticated Git artifacts fail verification.
    fs::write(
        repo.root()
            .join("chunks")
            .join(&artifact.metadata.chunks[0]),
        "corrupt",
    )
    .unwrap();
    let mut executor = Fixture::new();
    let failed = run_restore_probes(&repo, &snapshot.id, &config(), &mut executor).unwrap();
    assert_eq!(
        failed.agents[0].outcome,
        ProbeOutcome::FailedWithReason(ProbeFailure::RestoreFailed)
    );
    assert_eq!(executor.calls, 0);
}

#[test]
fn history_only_sanitization_can_probe_but_references_and_placeholders_require_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("workspace");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("data.txt"), "verified snapshot bytes").unwrap();
    let repo =
        repository::Repository::init(&temp.path().join("repository"), "fixture-only").unwrap();
    for (content, expected) in [
        (
            r#"{"history":["removed conversation"],"mcpServers":{}}"#,
            ProbeOutcome::Passed,
        ),
        (
            r#"{"mcpServers":{"fixture":{"env":{"API_KEY":"fixture-sensitive-value"}}}}"#,
            ProbeOutcome::NotRunWithReason(ProbeSkip::CredentialsUnavailable),
        ),
        (
            r#"{"mcpServers":{"fixture":{"env":{"API_KEY":"${FIXTURE_KEY}"}}}}"#,
            ProbeOutcome::NotRunWithReason(ProbeSkip::CredentialsUnavailable),
        ),
    ] {
        fs::write(work.join(".mcp.json"), content).unwrap();
        let snapshot = repo
            .snapshot(
                &work,
                &bunker::policy::Policy::default(),
                None,
                None,
                "manual",
            )
            .unwrap();
        let config_entry = snapshot
            .files
            .iter()
            .find(|f| f.path == ".mcp.json")
            .unwrap();
        if expected == ProbeOutcome::Passed {
            assert!(config_entry.sanitized);
            assert!(config_entry.secret_references.is_empty());
        }
        let mut executor = Fixture::new();
        let evidence = run_restore_probes(&repo, &snapshot.id, &config(), &mut executor).unwrap();
        assert_eq!(evidence.agents[0].outcome, expected);
        assert_eq!(
            executor.calls,
            if expected == ProbeOutcome::Passed {
                2
            } else {
                0
            }
        );
    }
    fs::remove_file(work.join(".mcp.json")).unwrap();
    fs::write(
        work.join("data.txt"),
        "legacy BUNKER_SECRET_FIXTURE placeholder",
    )
    .unwrap();
    let snapshot = repo
        .snapshot(
            &work,
            &bunker::policy::Policy::default(),
            None,
            None,
            "manual",
        )
        .unwrap();
    assert!(snapshot
        .files
        .iter()
        .all(|entry| entry.secret_references.is_empty()));
    let mut executor = Fixture::new();
    let evidence = run_restore_probes(&repo, &snapshot.id, &config(), &mut executor).unwrap();
    assert_eq!(
        evidence.agents[0].outcome,
        ProbeOutcome::NotRunWithReason(ProbeSkip::CredentialsUnavailable)
    );
    assert!(executor.root.is_none());
}

#[test]
fn mcp_validation_rejects_duplicate_and_malformed_complete_frames() {
    let response = r#"{"jsonrpc":"2.0","id":"bunker-restore-probe","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}"#;
    let notification = r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#;
    assert!(validate_response(
        ProbeKind::McpInitialize,
        "",
        format!("{notification}\n{response}\n{notification}\n").as_bytes()
    )
    .is_ok());
    for invalid in [
        response,
        "not-json",
        "{}",
        r#"{"jsonrpc":"1.0","method":"notification"}"#,
        r#"{"jsonrpc":"2.0","id":"other"}"#,
    ] {
        for frames in [
            format!("{invalid}\n{response}\n"),
            format!("{response}\n{invalid}\n"),
        ] {
            assert_eq!(
                validate_response(ProbeKind::McpInitialize, "", frames.as_bytes()),
                Err(ProbeFailure::InvalidMcpHandshake)
            );
        }
    }
}

#[test]
fn cli_restore_probe_requires_workspace_before_opening_repository() {
    let temp = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bunker"))
        .arg("--repo")
        .arg(temp.path().join("missing-repository"))
        .args(["restore-test", "missing-snapshot", "--probe-config"])
        .arg(temp.path().join("missing-config"))
        .env_remove("BUNKER_PASSPHRASE")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--workspace"));
    assert!(error.contains("required"));
    assert!(!temp.path().join("missing-repository").exists());
}

#[cfg(unix)]
#[test]
fn cli_restore_probe_rejects_runtime_paths_in_all_captured_boundaries() {
    use bunker_discovery::{DiscoveryContext, Platform};
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    let home = root.join("setup-home");
    let operator = root.join("operator");
    for path in [&workspace, &home, &operator] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(workspace.join("data.txt"), "fixture").unwrap();
    fs::create_dir(home.join(".codex")).unwrap();
    fs::write(home.join(".codex/config.toml"), "model = \"fixture\"\n").unwrap();
    let repo = repository::Repository::init(&root.join("repository"), "fixture-only").unwrap();
    let snapshot = repo
        .snapshot(
            &workspace,
            &bunker::policy::Policy::default(),
            None,
            None,
            "manual",
        )
        .unwrap();
    let context = DiscoveryContext::new(Platform::Linux, home.clone(), vec![workspace.clone()]);
    let setup = repo
        .snapshot_setup(&context, &bunker::policy::Policy::default(), None, "manual")
        .unwrap();
    let setup_snapshot = setup
        .iter()
        .find(|manifest| {
            manifest
                .setup
                .as_ref()
                .is_some_and(|scope| scope.source_root == home)
        })
        .expect("fixture captures home setup");
    let repo_path = repo.root().to_path_buf();
    drop(repo); // Release the repository lock before invoking the real CLI.
    let marker = root.join("runtime-executed");
    let script = format!(
        "#!/bin/sh\nprintf executed > '{}'\nexit 1\n",
        marker.display()
    );
    for (boundary, snapshot_id) in [
        (&workspace, &snapshot.id),
        (&repo_path, &snapshot.id),
        (&home, &setup_snapshot.id),
    ] {
        for path_kind in ["config", "executable", "docker-config"] {
            let mut cfg = config();
            let config_path = if path_kind == "config" {
                boundary.join("probe.json")
            } else {
                operator.join("probe.json")
            };
            cfg.docker_executable = if path_kind == "executable" {
                boundary.join("fixture-docker")
            } else {
                operator.join("fixture-docker")
            };
            cfg.docker_config = if path_kind == "docker-config" {
                boundary.join("docker-config")
            } else {
                operator.join("docker-config")
            };
            fs::create_dir_all(&cfg.docker_config).unwrap();
            fs::set_permissions(&cfg.docker_config, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&cfg.docker_executable, &script).unwrap();
            fs::set_permissions(&cfg.docker_executable, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&config_path, serde_json::to_vec(&cfg).unwrap()).unwrap();
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
            TrustedProbeConfig::load(&config_path).expect("fixture config is protected and valid");
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_bunker"))
                .arg("--repo")
                .arg(&repo_path)
                .args(["restore-test", snapshot_id, "--workspace"])
                .arg(&workspace)
                .arg("--probe-config")
                .arg(&config_path)
                .env("BUNKER_PASSPHRASE", "fixture-only")
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "{path_kind} in {}",
                boundary.display()
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("overlaps captured data"),
                "{path_kind}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!marker.exists(), "runtime executed for {path_kind}");
        }
    }
}
