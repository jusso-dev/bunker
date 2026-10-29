use bunker::{repository::Repository, scheduler::ScheduleState};
use std::{fs, process::Command};

#[test]
fn standalone_schedule_refuses_a_different_workspace_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path, "schedule-binding-fixture").unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("file"), "first").unwrap();
    fs::write(second.join("file"), "second").unwrap();
    let mut state = ScheduleState::default();
    let key = bunker::repository::KeySource::passphrase("schedule-binding-fixture");
    bunker::scheduler::tick_with_key_source(&repo_path, &key, &first, None, &mut state, true)
        .unwrap();
    let previous = state.last_snapshot.clone();
    let mut state = bunker::scheduler::load_schedule_with_key_source(&repo_path, &key).unwrap();
    assert!(bunker::scheduler::tick_with_key_source(
        &repo_path, &key, &second, None, &mut state, true
    )
    .is_err());
    assert_eq!(state.last_snapshot, previous);
    assert_eq!(state.workspace, Some(first.canonicalize().unwrap()));
}

#[cfg(unix)]
#[test]
fn rejected_workspace_change_cannot_run_the_old_workspaces_probe_binary() {
    use bunker::restore_probes::{TrustedAgentProbe, TrustedCommand, TrustedProbeConfig};
    use std::{
        os::unix::fs::PermissionsExt,
        process::Stdio,
        time::{Duration, Instant},
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repo_path = root.join("repo");
    Repository::init(&repo_path, "probe-boundary-fixture").unwrap();
    let first = root.join("first");
    let second = root.join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    fs::write(first.join("file"), "fixture").unwrap();
    let mut state = ScheduleState::default();
    let key = bunker::repository::KeySource::passphrase("probe-boundary-fixture");
    bunker::scheduler::tick_with_key_source(&repo_path, &key, &first, None, &mut state, true)
        .unwrap();
    let docker = first.join("docker");
    fs::write(&docker, "#!/bin/sh\n: > \"$0.executed\"\nexit 1\n").unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o700)).unwrap();
    let docker_config = root.join("docker-config");
    fs::create_dir(&docker_config).unwrap();
    fs::set_permissions(&docker_config, fs::Permissions::from_mode(0o700)).unwrap();
    let config = TrustedProbeConfig {
        docker_executable: docker,
        docker_context: "homelab".into(),
        docker_config,
        image: format!("example.test/probes@sha256:{}", "a".repeat(64)),
        timeout_seconds: 2,
        output_limit_bytes: 4096,
        agents: vec![TrustedAgentProbe {
            agent: "codex".into(),
            command: TrustedCommand {
                executable: "/fixture/agent".into(),
                args: vec![],
                requires_network: false,
                requires_credentials: false,
            },
        }],
        mcps: vec![],
    };
    let config_path = root.join("probe.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    TrustedProbeConfig::load(&config_path).unwrap();
    let log_path = root.join("daemon.log");
    let marker = first.join("docker.executed");
    let mut child = Command::new(env!("CARGO_BIN_EXE_bunker"))
        .arg("--repo")
        .arg(&repo_path)
        .args(["daemon", "--workspace"])
        .arg(&second)
        .arg("--probe-config")
        .arg(config_path)
        .env("BUNKER_PASSPHRASE", "probe-boundary-fixture")
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log_path).unwrap())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let mut rejected = false;
    while started.elapsed() < Duration::from_secs(5) {
        let log = fs::read_to_string(&log_path).unwrap();
        if log.contains("daemon_retry") && log.contains("restore_probe_retry") {
            rejected = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        rejected,
        "daemon must refuse both source capture and probe execution"
    );
    assert!(
        !marker.exists(),
        "captured workspace executable ran on host"
    );
}

#[test]
fn unavailable_standalone_probe_preserves_successful_backup_and_sanitizes_status() {
    let temp = tempfile::tempdir().unwrap();
    let repo_path = temp.path().join("repo");
    let workspace = temp.path().join("work");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("file"), "fixture").unwrap();
    Repository::init(&repo_path, "scheduled-probe-fixture").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bunker"))
        .arg("--repo")
        .arg(&repo_path)
        .args(["daemon", "--once", "--workspace"])
        .arg(&workspace)
        .arg("--probe-config")
        .arg(temp.path().join("PRIVATE_UNAVAILABLE_CONFIG"))
        .env("BUNKER_PASSPHRASE", "scheduled-probe-fixture")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let bytes = fs::read(repo_path.join("schedule.json")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_UNAVAILABLE_CONFIG"));
    let state: ScheduleState = serde_json::from_slice(&bytes).unwrap();
    assert!(state.last_snapshot.is_some());
    assert_eq!(state.failures, 0);
    assert_eq!(state.probe_failures, 1);
    assert_eq!(
        state.last_probe_error.as_deref(),
        Some("restore probe unavailable")
    );
    assert_eq!(state.next_probe, 0);
    assert!(state.next_run > state.last_success);
    let repo = Repository::open(&repo_path, "scheduled-probe-fixture").unwrap();
    repo.verify(state.last_snapshot.as_deref().unwrap())
        .unwrap();
}
