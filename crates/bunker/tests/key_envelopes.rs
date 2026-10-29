use bunker::{
    crypto,
    policy::Policy,
    repository::{KeySource, Repository},
};
use serde_json::json;
use std::fs;

const OLD: &str = "disposable-old-passphrase";
const NEW: &str = "disposable-new-passphrase";

#[test]
fn failed_initialization_can_be_retried_and_escrow_export_is_no_clobber() {
    let lab = tempfile::tempdir().unwrap();
    let path = lab.path().join("repo");
    let invalid = KeySource::Managed(bunker_keys::ProviderConfig::Azure {
        key_url: "http://invalid.example/key".into(),
        token_env: "UNUSED_FIXTURE_TOKEN".into(),
    });
    assert!(Repository::init_with_key_source(&path, &invalid).is_err());
    assert!(!path.exists());
    fs::create_dir(&path).unwrap();
    assert!(Repository::init_with_key_source(&path, &invalid).is_err());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    let repo = Repository::init(&path, OLD).unwrap();
    let escrow = lab.path().join("escrow.json");
    let key = crypto::random();
    repo.export_escrow_to(&escrow, &key).unwrap();
    let bytes = fs::read(&escrow).unwrap();
    assert!(repo.export_escrow_to(&escrow, &key).is_err());
    assert_eq!(bytes, fs::read(&escrow).unwrap());
    drop(repo);
    let source = KeySource::Escrow {
        envelope: serde_json::from_slice(&bytes).unwrap(),
        recovery_key: zeroize::Zeroizing::new(key),
    };
    Repository::open_with_key_source(&path, &source).unwrap();
}

#[test]
fn rewrap_and_escrow_preserve_identity_and_encrypted_objects() {
    let lab = tempfile::tempdir().unwrap();
    let path = lab.path().join("repo");
    let workspace = lab.path().join("work");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("file"), "original").unwrap();
    let repo = Repository::init(&path, OLD).unwrap();
    let identity = repo.identity();
    let snapshot = repo
        .snapshot(&workspace, &Policy::default(), None, None, "manual")
        .unwrap();
    let manifest = repo
        .encrypted_object(&format!("snapshots/{}", snapshot.id))
        .unwrap();
    let chunk = repo
        .encrypted_object(&format!("chunks/{}", snapshot.files[0].chunks[0]))
        .unwrap();
    let recovery = crypto::random();
    let escrow = repo.export_escrow(&recovery).unwrap();
    repo.rewrap_passphrase(NEW).unwrap();
    assert_eq!(identity, repo.identity());
    assert_eq!(
        manifest,
        repo.encrypted_object(&format!("snapshots/{}", snapshot.id))
            .unwrap()
    );
    assert_eq!(
        chunk,
        repo.encrypted_object(&format!("chunks/{}", snapshot.files[0].chunks[0]))
            .unwrap()
    );
    drop(repo);
    assert!(Repository::open(&path, OLD).is_err());
    let repo = Repository::open(&path, NEW).unwrap();
    assert_eq!(identity, repo.identity());
    drop(repo);
    assert!(Repository::open_with_escrow(&path, &escrow, &[0; 32]).is_err());
    let repo = Repository::open_with_escrow(&path, &escrow, &recovery).unwrap();
    repo.verify(&snapshot.id).unwrap();
    repo.rewrap_key(&KeySource::passphrase(OLD)).unwrap();
    drop(repo);
    Repository::open(&path, OLD).unwrap();
}

#[test]
fn headers_and_escrow_are_bound_to_repository() {
    let lab = tempfile::tempdir().unwrap();
    let first = lab.path().join("first");
    let second = lab.path().join("second");
    let recovery = crypto::random();
    let repo = Repository::init(&first, OLD).unwrap();
    let escrow = repo.export_escrow(&recovery).unwrap();
    drop(repo);
    drop(Repository::init(&second, OLD).unwrap());
    assert!(Repository::open_with_escrow(&second, &escrow, &recovery).is_err());
    let original = fs::read(first.join("repository.json")).unwrap();
    for field in ["repository_id", "authentication"] {
        let mut header: serde_json::Value = serde_json::from_slice(&original).unwrap();
        header[field] = json!("0".repeat(64));
        fs::write(
            first.join("repository.json"),
            serde_json::to_vec(&header).unwrap(),
        )
        .unwrap();
        assert!(Repository::open(&first, OLD).is_err());
        assert!(Repository::open_with_escrow(&first, &escrow, &recovery).is_err());
    }
    fs::write(first.join("repository.json"), &original).unwrap();
    let repo = Repository::open(&first, OLD).unwrap();
    assert!(Repository::open(&first, OLD).is_err());
    drop(repo);
}

#[test]
fn legacy_header_upgrades_without_changing_data_key() {
    let lab = tempfile::tempdir().unwrap();
    let path = lab.path().join("repo");
    fs::create_dir(&path).unwrap();
    let salt = crypto::random();
    let key = crypto::random::<32>();
    let wrapping = crypto::derive(OLD, &salt).unwrap();
    let header = json!({"version":1,"salt":salt,"wrapped_key":crypto::seal(&wrapping, &key, b"bunker-repository-key-v1").unwrap()});
    fs::write(
        path.join("repository.json"),
        serde_json::to_vec(&header).unwrap(),
    )
    .unwrap();
    let repo = Repository::open(&path, OLD).unwrap();
    let identity = repo.identity();
    repo.rewrap_passphrase(NEW).unwrap();
    drop(repo);
    assert_eq!(identity, Repository::open(&path, NEW).unwrap().identity());
    let header: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("repository.json")).unwrap()).unwrap();
    assert_eq!(header["version"], 2);
}

#[test]
fn initializes_current_directory_and_trailing_dot_without_replacing_directory() {
    for argument in [".", "child/."] {
        let temp = tempfile::tempdir().unwrap();
        let destination = if argument == "." {
            temp.path().to_path_buf()
        } else {
            let child = temp.path().join("child");
            fs::create_dir(&child).unwrap();
            child
        };
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(&destination).unwrap().ino()
        };
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_bunker"))
            .args(["--repo", argument, "init"])
            .current_dir(temp.path())
            .env("BUNKER_PASSPHRASE", OLD)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Repository::open(&destination, OLD).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(inode, fs::metadata(&destination).unwrap().ino());
        }
    }
}
