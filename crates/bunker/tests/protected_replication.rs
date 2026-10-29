use anyhow::{bail, Result};
use bunker::{
    checkpoint::{self, RemoteStore},
    policy::Policy,
    protected_replication::PairedStore,
    repository::{KeySource, Repository},
};
use opendal::{services::Memory, Operator};
use std::fs;
struct FailCheckpoint(Operator);
impl RemoteStore for FailCheckpoint {
    async fn read_bounded(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        RemoteStore::read_bounded(&self.0, path, limit).await
    }
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        if path.contains("/checkpoints/") {
            bail!("injected secondary publication failure");
        }
        RemoteStore::create_verified(&self.0, path, bytes).await
    }
}
#[test]
fn paired_replication_uses_one_checkpoint_and_each_side_recovers_independently() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let repo = Repository::init(&temp.path().join("repo"), "paired-fixture").unwrap();
        let workspace = temp.path().join("work");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("file"), "retained bytes").unwrap();
        let snapshot = repo
            .snapshot(&workspace, &Policy::default(), None, None, "test")
            .unwrap();
        let a = Operator::new(Memory::default()).unwrap();
        let b = Operator::new(Memory::default()).unwrap();
        let pair = PairedStore {
            primary: &a,
            secondary: &b,
        };
        let report = checkpoint::replicate(&repo, &pair, None).await.unwrap();
        let source = KeySource::Passphrase(zeroize::Zeroizing::new("paired-fixture".into()));
        for (index, store) in [&a, &b].iter().enumerate() {
            let path = temp.path().join(format!("recovered-{index}"));
            assert_eq!(
                checkpoint::recover(*store, &report.namespace, &path, &source, None)
                    .await
                    .unwrap(),
                1
            );
            Repository::open(&path, "paired-fixture")
                .unwrap()
                .verify(&snapshot.id)
                .unwrap();
        }
        for entry in a.list("/").await.unwrap() {
            if entry.metadata().is_file() {
                assert_eq!(
                    a.read(entry.path()).await.unwrap().to_vec(),
                    b.read(entry.path()).await.unwrap().to_vec()
                );
            }
        }
    });
}
#[test]
fn failed_secondary_checkpoint_does_not_advance_local_publication() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let repo = Repository::init(&temp.path().join("repo"), "paired-fixture").unwrap();
        let work = temp.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("file"), "fixture").unwrap();
        repo.snapshot(&work, &Policy::default(), None, None, "test")
            .unwrap();
        let a = Operator::new(Memory::default()).unwrap();
        let b = FailCheckpoint(Operator::new(Memory::default()).unwrap());
        assert!(checkpoint::replicate(
            &repo,
            &PairedStore {
                primary: &a,
                secondary: &b
            },
            None
        )
        .await
        .is_err());
        assert!(!repo.root().join("checkpoints/latest").exists());
        let report = checkpoint::replicate(
            &repo,
            &PairedStore {
                primary: &a,
                secondary: &b.0,
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.sequence, 1);
    });
}
