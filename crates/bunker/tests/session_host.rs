//! Disposable configuration and CLI boundary fixtures; no provider/network access.
use bunker::{host_runtime::HostConfig, repository::Repository, session_hooks::*};
use std::{fs, path::PathBuf, process::Command};
use uuid::Uuid;

struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    config: PathBuf,
}
impl Fixture {
    fn new(enabled: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("home");
        let workspace = root.join("workspace");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&workspace).unwrap();
        let repo = root.join("repo");
        Repository::init(&repo, "session-host-fixture").unwrap();
        let config = root.join("host.toml");
        fs::write(
            &config,
            toml::to_string(&HostConfig {
                public_origin: "https://localhost:14443".into(),
                host_origin: "https://localhost:14444".into(),
                tenant: Uuid::new_v4(),
                credential_directory: root.join("credentials"),
                consumed_directory: root.join("consumed"),
                server_ca_file: None,
                storage_ref: "local-repository".into(),
                key_ref: "wrapped-key".into(),
                setup_home: None,
                probe_config: None,
                storage: None,
                session_handler: enabled,
            })
            .unwrap(),
        )
        .unwrap();
        Self {
            _temp: temp,
            repo,
            home,
            workspace,
            config,
        }
    }
    fn invocation(&self) -> HostHookInvocation {
        HostHookInvocation {
            executable: PathBuf::from(env!("CARGO_BIN_EXE_bunker"))
                .canonicalize()
                .unwrap(),
            repository: self.repo.clone(),
            home: self.home.clone(),
            key_config: None,
            host_config: self.config.clone(),
            workspace: self.workspace.clone(),
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bunker"));
        command
            .arg("--repo")
            .arg(&self.repo)
            .env("BUNKER_PASSPHRASE", "session-host-fixture");
        command
    }
}

#[test]
fn host_hook_is_literal_argv_preserves_config_and_can_be_removed_after_opt_out() {
    let f = Fixture::new(true);
    fs::create_dir(f.home.join(".claude")).unwrap();
    let settings = f.home.join(".claude/settings.json");
    fs::write(&settings, br#"{"theme":"fixture","hooks":{"Stop":[{"hooks":[{"type":"command","command":"untouched"}]}]}}"#).unwrap();
    let invocation = f.invocation();
    let plan = plan_claude_host_hook(&invocation, true).unwrap();
    assert_eq!(
        plan.handler["command"],
        invocation.executable.to_str().unwrap()
    );
    let args = plan.handler["args"].as_array().unwrap();
    let host_arg = args.iter().position(|v| v == "--host-config").unwrap();
    assert_eq!(args[host_arg + 1], f.config.to_str().unwrap());
    assert!(args.iter().any(|v| v == "session-end"));
    assert!(!args.iter().any(|v| v == "--policy"));
    apply_claude_hook(&plan, &plan.confirmation).unwrap();
    assert!(!plan_claude_host_hook(&invocation, true).unwrap().changed);
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    assert_eq!(saved["theme"], "fixture");
    assert_eq!(
        saved["hooks"]["Stop"][0]["hooks"][0]["command"],
        "untouched"
    );
    // Disabling an installed route does not require an active identity/config.
    fs::remove_file(&f.config).unwrap();
    let removal = plan_claude_host_hook(&invocation, false).unwrap();
    apply_claude_hook(&removal, &removal.confirmation).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    assert!(saved["hooks"].get("SessionEnd").is_none());
    assert!(saved["hooks"].get("Stop").is_some());
}

#[test]
fn host_hook_requires_explicit_local_opt_in_and_literal_config_path() {
    let f = Fixture::new(false);
    assert!(plan_claude_host_hook(&f.invocation(), true).is_err());
    assert!(!f.home.join(".claude/settings.json").exists());
    let mut invocation = f.invocation();
    invocation.host_config = PathBuf::from("relative-config");
    assert!(plan_claude_host_hook(&invocation, false).is_err());
    invocation.host_config = f.config.with_file_name("${CONFIG}.toml");
    assert!(plan_claude_host_hook(&invocation, false).is_err());
}

#[test]
fn host_cli_accepts_no_home_but_rejects_disabled_handler_before_identity_io() {
    let f = Fixture::new(false);
    let result = f
        .command()
        .args(["session-end", "--agent", "codex", "--session-id", "fixture"])
        .arg("--host-config")
        .arg(&f.config)
        .arg("--workspace")
        .arg(&f.workspace)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("host session handler is not explicitly enabled"));
    assert!(!f.config.parent().unwrap().join("credentials").exists());
    assert!(Repository::open(&f.repo, "session-host-fixture")
        .unwrap()
        .list()
        .unwrap()
        .is_empty());
}

#[test]
fn host_cli_requires_one_workspace_and_refuses_local_policy() {
    let f = Fixture::new(true);
    for count in [0, 2] {
        let mut command = f.command();
        command
            .args(["session-end", "--agent", "codex", "--session-id", "fixture"])
            .arg("--host-config")
            .arg(&f.config);
        for _ in 0..count {
            command.arg("--workspace").arg(&f.workspace);
        }
        let result = command.output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("exactly one --workspace"));
    }
    let result = f
        .command()
        .arg("--policy")
        .arg(&f.config)
        .args(["session-end", "--agent", "codex", "--session-id", "fixture"])
        .arg("--host-config")
        .arg(&f.config)
        .arg("--workspace")
        .arg(&f.workspace)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no local --policy"));
}

#[cfg(unix)]
#[test]
fn host_wrapper_executes_child_then_preserves_its_failure_when_handler_is_disabled() {
    let f = Fixture::new(false);
    for (code, expected) in [(0, 1), (7, 7)] {
        let result = f
            .command()
            .args(["session-run", "--agent", "codex", "--session-id", "fixture"])
            .arg("--host-config")
            .arg(&f.config)
            .arg("--workspace")
            .arg(&f.workspace)
            .args(["--", "/bin/sh", "-c", &format!("exit {code}")])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(expected));
        assert!(String::from_utf8_lossy(&result.stderr).contains("Session backup failed"));
    }
}

#[test]
fn legacy_host_config_defaults_to_no_handler() {
    let f = Fixture::new(false);
    let old = fs::read_to_string(&f.config)
        .unwrap()
        .replace("session_handler = false\n", "");
    fs::write(&f.config, old).unwrap();
    assert!(!HostConfig::load(&f.config).unwrap().session_handler);
}

#[cfg(unix)]
#[test]
fn host_wrapper_requires_retryable_session_id_before_spawning_child() {
    let f = Fixture::new(false);
    let marker = f.workspace.join("child-ran");
    let result = f
        .command()
        .args(["session-run", "--agent", "codex"])
        .arg("--host-config")
        .arg(&f.config)
        .arg("--workspace")
        .arg(&f.workspace)
        .args(["--", "/usr/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--session-id"));
    assert!(!marker.exists());
}
