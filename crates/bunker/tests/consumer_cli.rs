#![cfg(unix)]
use std::{fs, process::Command};

fn rebind(root: &std::path::Path, repository: &str, state: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bunker"))
        .current_dir(root)
        .args([
            "--repo",
            repository,
            "consumer-rebind",
            "--storage",
            "storage.toml",
            "--consumer-state",
            state,
        ])
        .env("FIXTURE_CLIENT", "fixture-client")
        .env("FIXTURE_SECRET", "fixture-secret")
        .env("FIXTURE_REFRESH", "fixture-replacement")
        .output()
        .unwrap()
}

#[test]
fn rebind_rejects_repository_state_before_writes_and_supports_relative_private_state() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("repo")).unwrap();
    fs::write(
        root.join("storage.toml"),
        r#"
service = "gdrive"
[options]
root = "fixture-folder"
[credential_env]
client_id = "FIXTURE_CLIENT"
client_secret = "FIXTURE_SECRET"
refresh_token = "FIXTURE_REFRESH"
"#,
    )
    .unwrap();
    assert!(!rebind(root, "repo", "repo/oauth").status.success());
    assert!(!root.join("repo/oauth").exists());
    assert!(rebind(root, "repo", "state").status.success());
    assert!(rebind(root, "repo", "state").status.success());
    assert!(root.join("state/credentials.json").exists());
}
