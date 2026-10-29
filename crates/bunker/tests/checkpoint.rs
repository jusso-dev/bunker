use bunker::{
    checkpoint,
    policy::Policy,
    repository::{KeySource, Repository},
};
use opendal::{services::Memory, Operator};
use std::fs;

const OLD: &str = "checkpoint-fixture-passphrase";
const NEW: &str = "new-checkpoint-fixture-passphrase";

#[test]
fn history_at_recovery_limit_is_rejected_before_any_remote_publication() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let lab = tempfile::tempdir().unwrap();
        let work = lab.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("file"), "fixture").unwrap();
        let repo = Repository::init(&lab.path().join("repo"), OLD).unwrap();
        let snapshot = repo
            .snapshot(&work, &Policy::default(), None, None, "manual")
            .unwrap();
        let header_bytes = repo.encrypted_object("repository.json").unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        let salt: [u8; 16] = serde_json::from_value(header["salt"].clone()).unwrap();
        let wrapped: Vec<u8> = serde_json::from_value(header["wrapped_key"].clone()).unwrap();
        let wrapping = bunker::crypto::derive(OLD, &salt).unwrap();
        let plaintext =
            bunker::crypto::open(&wrapping, &wrapped, b"bunker-repository-key-v1").unwrap();
        let key: &[u8; 32] = plaintext.as_slice().try_into().unwrap();
        let mut previous = None;
        fs::create_dir(repo.root().join("checkpoints")).unwrap();
        for sequence in 1..=33 {
            let mut value = serde_json::to_vec(
                &serde_json::json!({"version":1,"repository":repo.identity(),
                "header":blake3::hash(&header_bytes).to_hex().to_string(),"sequence":sequence,
                "previous":previous,"snapshots":[snapshot.id]}),
            )
            .unwrap();
            let length = if sequence <= 31 {
                2 * 1024 * 1024
            } else if sequence == 32 {
                2 * 1024 * 1024 - 1024
            } else {
                1024
            };
            value.resize(length - 40, b' ');
            let encrypted =
                bunker::crypto::seal(key, &value, b"bunker-replication-index-v1").unwrap();
            let id = blake3::hash(&encrypted).to_hex().to_string();
            fs::write(repo.root().join("checkpoints").join(&id), &encrypted).unwrap();
            if sequence == 33 {
                fs::write(repo.root().join("checkpoints/latest"), encrypted).unwrap();
            }
            previous = Some(id);
        }
        let operator = Operator::new(Memory::default()).unwrap();
        let error = checkpoint::replicate(&repo, &operator, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("history recovery limit"));
        assert!(operator.list("/").await.unwrap().is_empty());
    });
}

#[test]
fn remote_recovery_with_escrow_needs_no_passphrase_or_provider() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let lab = tempfile::tempdir().unwrap();
        let work = lab.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("file"), "fixture").unwrap();
        let repo = Repository::init(&lab.path().join("repo"), OLD).unwrap();
        let snapshot = repo
            .snapshot(&work, &Policy::default(), None, None, "manual")
            .unwrap();
        let key = bunker::crypto::random();
        let escrow = repo.export_escrow(&key).unwrap();
        let operator = Operator::new(Memory::default()).unwrap();
        let report = checkpoint::replicate(&repo, &operator, None).await.unwrap();
        drop(repo);
        let source = KeySource::Escrow {
            envelope: escrow,
            recovery_key: zeroize::Zeroizing::new(key),
        };
        let target = lab.path().join("recovered");
        checkpoint::recover(&operator, &report.namespace, &target, &source, None)
            .await
            .unwrap();
        let repo = Repository::open_with_key_source(&target, &source).unwrap();
        repo.verify(&snapshot.id).unwrap();
        repo.rewrap_key(&KeySource::passphrase(NEW)).unwrap();
        drop(repo);
        Repository::open(&target, NEW).unwrap();
    });
}

#[test]
fn pinned_inventory_detects_omission_and_rewrap_reuses_chunk_namespace() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let lab = tempfile::tempdir().unwrap();
        let workspace = lab.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("file"), "first version").unwrap();
        let repo = Repository::init(&lab.path().join("repo"), OLD).unwrap();
        let first = repo
            .snapshot(&workspace, &Policy::default(), None, None, "manual")
            .unwrap();
        let operator = Operator::new(Memory::default()).unwrap();
        let one = checkpoint::replicate(&repo, &operator, None).await.unwrap();
        assert_eq!(one.sequence, 1);
        let identity = repo.identity();
        let chunk_path = format!("{identity}/chunks/{}", first.files[0].chunks[0]);
        let before = operator.read(&chunk_path).await.unwrap().to_vec();
        repo.rewrap_passphrase(NEW).unwrap();
        let two = checkpoint::replicate(&repo, &operator, None).await.unwrap();
        assert_eq!(two.sequence, 2);
        assert!(two.namespace.starts_with(&identity));
        assert_eq!(before, operator.read(&chunk_path).await.unwrap().to_vec());
        assert_eq!(
            operator
                .list(&format!("{identity}/chunks/"))
                .await
                .unwrap()
                .len(),
            1
        );
        let restored = lab.path().join("restored");
        assert_eq!(
            checkpoint::recover(
                &operator,
                &two.namespace,
                &restored,
                &KeySource::passphrase(NEW),
                None
            )
            .await
            .unwrap(),
            1
        );
        let reopened = Repository::open(&restored, NEW).unwrap();
        reopened.verify(&first.id).unwrap();
        assert_eq!(
            checkpoint::replicate(&reopened, &operator, None)
                .await
                .unwrap()
                .sequence,
            3
        );
        drop(reopened);
        assert!(checkpoint::recover(
            &operator,
            &two.namespace,
            &lab.path().join("wrong-key"),
            &KeySource::passphrase(OLD),
            None
        )
        .await
        .is_err());
        // The older explicitly selected locator remains usable with its old key.
        checkpoint::recover(
            &operator,
            &one.namespace,
            &lab.path().join("older"),
            &KeySource::passphrase(OLD),
            None,
        )
        .await
        .unwrap();
        operator
            .delete(&format!("{identity}/snapshots/{}", first.id))
            .await
            .unwrap();
        let omitted = lab.path().join("omitted");
        assert!(checkpoint::recover(
            &operator,
            &two.namespace,
            &omitted,
            &KeySource::passphrase(NEW),
            None
        )
        .await
        .is_err());
        assert!(!omitted.exists());
    });
}

#[test]
fn chain_omission_and_locator_tampering_fail_without_publishing_destination() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let lab = tempfile::tempdir().unwrap();
        let work = lab.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("a"), "a").unwrap();
        let repo = Repository::init(&lab.path().join("repo"), OLD).unwrap();
        let snapshot = repo
            .snapshot(&work, &Policy::default(), None, None, "manual")
            .unwrap();
        let operator = Operator::new(Memory::default()).unwrap();
        let one = checkpoint::replicate(&repo, &operator, Some(&snapshot.id))
            .await
            .unwrap();
        let two = checkpoint::replicate(&repo, &operator, None).await.unwrap();
        let first_id = one.namespace.rsplit(':').next().unwrap();
        operator
            .delete(&format!("{}/checkpoints/{first_id}", repo.identity()))
            .await
            .unwrap();
        let destination = lab.path().join("restore");
        assert!(checkpoint::recover(
            &operator,
            &two.namespace,
            &destination,
            &KeySource::passphrase(OLD),
            None
        )
        .await
        .is_err());
        assert!(!destination.exists());
        assert!(checkpoint::recover(
            &operator,
            &"a".repeat(64),
            &destination,
            &KeySource::passphrase(OLD),
            None
        )
        .await
        .is_err());
        assert!(!destination.exists());
    });
}
