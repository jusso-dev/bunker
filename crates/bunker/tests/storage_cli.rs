//! Offline CLI replication output: target warnings, region and credential privacy.
use bunker::storage::StorageConfig;
use std::{collections::BTreeMap, fs, path::Path, process::Output};

const PASSPHRASE: &str = "storage-cli-fixture-passphrase";
const ACCESS: &str = "bunkersentinelaccess0123456789";
const SECRET: &str = "bunkersentinelsecret0123456789abcdef";

fn bunker(repo: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_bunker"))
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env("BUNKER_PASSPHRASE", PASSPHRASE)
        .env("FIXTURE_S3_ACCESS", ACCESS)
        .env("FIXTURE_S3_SECRET", SECRET)
        .output()
        .unwrap()
}
fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("a.txt"), "fixture").unwrap();
    assert!(bunker(&repo, &["init"]).status.success());
    assert!(
        bunker(&repo, &["snapshot", "--workspace", work.to_str().unwrap()])
            .status
            .success()
    );
    (dir, repo)
}
fn write_config(dir: &Path, service: &str, options: &[(&str, &str)]) -> std::path::PathBuf {
    let config = StorageConfig {
        service: service.into(),
        options: options
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        credential_env: if service == "s3" {
            BTreeMap::from([
                ("access_key_id".into(), "FIXTURE_S3_ACCESS".into()),
                ("secret_access_key".into(), "FIXTURE_S3_SECRET".into()),
            ])
        } else {
            BTreeMap::new()
        },
        immutable: false,
    };
    let path = dir.join(format!("{service}.toml"));
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    path
}
fn warnings(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value["level"] == "warning")
        .collect()
}

#[test]
fn local_replication_warns_about_missing_immutability_and_records_no_region() {
    let (dir, repo) = setup();
    let remote = dir.path().join("remote");
    fs::create_dir(&remote).unwrap();
    let storage = write_config(
        dir.path(),
        "local",
        &[
            ("root", remote.to_str().unwrap()),
            ("upload_bytes_per_second", "1048576"),
        ],
    );
    let output = bunker(
        &repo,
        &["replicate", "--storage", storage.to_str().unwrap()],
    );
    assert!(output.status.success());
    let warnings = warnings(&output);
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["code"], "immutability_unsupported");
    assert_eq!(warnings[0]["service"], "local");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["storage"]["service"], "local");
    assert!(value["storage"]["region"].is_null());
    assert_eq!(value["immutable"], false);
    // Warnings stay on stderr so stdout remains a single JSON document.
    let recovered = dir.path().join("recovered");
    let output = bunker(
        &recovered,
        &[
            "recover",
            "--storage",
            storage.to_str().unwrap(),
            "--namespace",
            value["namespace"].as_str().unwrap(),
        ],
    );
    assert!(output.status.success());
}

#[test]
fn consumer_replication_warns_before_any_provider_work() {
    let (dir, repo) = setup();
    let storage = dir.path().join("gdrive.toml");
    fs::write(
        &storage,
        "service = \"gdrive\"\n[options]\nroot = \"fixture-folder\"\n[credential_env]\nclient_id = \"FIXTURE_CLIENT\"\nclient_secret = \"FIXTURE_SECRET\"\nrefresh_token = \"FIXTURE_REFRESH\"\n",
    )
    .unwrap();
    // Missing --report fails before network or state access, after the warning.
    let output = bunker(
        &repo,
        &["replicate", "--storage", storage.to_str().unwrap()],
    );
    assert!(!output.status.success());
    let warnings = warnings(&output);
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["code"], "immutability_unsupported");
    assert_eq!(warnings[0]["service"], "gdrive");
}

#[test]
fn failed_s3_replication_never_echoes_configured_credentials() {
    let (dir, repo) = setup();
    // Nothing listens on port 1; every request fails after OpenDAL's retries.
    let storage = write_config(
        dir.path(),
        "s3",
        &[
            ("endpoint", "https://127.0.0.1:1"),
            ("bucket", "fixture"),
            ("region", "ap-southeast-2"),
        ],
    );
    let output = bunker(
        &repo,
        &["replicate", "--storage", storage.to_str().unwrap()],
    );
    assert!(!output.status.success());
    assert!(warnings(&output).is_empty());
    let mut checked = vec![output.stdout, output.stderr];
    for entry in walkdir::WalkDir::new(dir.path()) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            checked.push(fs::read(entry.path()).unwrap());
        }
    }
    for bytes in checked {
        for secret in [ACCESS, SECRET] {
            assert!(!bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
        }
    }
}
