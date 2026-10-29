//! Encrypted inventory published last, pinned by an externally retained locator.
//! An untrusted backend cannot prove freshness without that external reference.
use crate::{
    repository::{durable_write, valid_id, KeySource, Repository},
    storage,
};
use anyhow::{anyhow, ensure, Context, Result};
use opendal::Operator;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};

/// Exact-object remote operations. Implementations must never overwrite differing
/// ciphertext, and protected backends must verify retention before returning.
#[allow(async_fn_in_trait)]
pub trait RemoteStore {
    async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>>;
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()>;
}
impl RemoteStore for Operator {
    async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        storage::remote_read(self, path, maximum)
            .await
            .map_err(|_| anyhow!("remote object unavailable"))
    }
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        storage::copy_verified(self, path, bytes).await
    }
}

const DOMAIN: &[u8] = b"bunker-replication-index-v1";
const MAX_INDEX: u64 = 2 * 1024 * 1024;
const MAX_CHAIN: usize = 10000;

fn validate_history_extension(
    existing_links: usize,
    existing_bytes: u64,
    new_bytes: u64,
) -> Result<()> {
    ensure!(
        existing_links < MAX_CHAIN,
        "new checkpoint would exceed chain recovery limit"
    );
    ensure!(
        existing_bytes
            .checked_add(new_bytes)
            .is_some_and(|n| n <= 64 * 1024 * 1024),
        "new checkpoint would exceed history recovery limit"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    repository: String,
    header: String,
    sequence: u64,
    previous: Option<String>,
    snapshots: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct ReplicationReport {
    pub objects_verified: usize,
    /// Keep this outside the backup backend. All three components are pinned.
    pub namespace: String,
    pub sequence: u64,
    pub inventory_completeness: &'static str,
}
fn decode(repo: &Repository, bytes: &[u8]) -> Result<Index> {
    ensure!(bytes.len() as u64 <= MAX_INDEX, "checkpoint exceeds limit");
    let value: Index = serde_json::from_slice(&repo.open_metadata(DOMAIN, bytes)?)?;
    ensure!(
        value.version == 1 && value.repository == repo.identity(),
        "checkpoint repository mismatch"
    );
    valid_id(&value.header)?;
    ensure!(
        value.sequence > 0 && value.snapshots.len() <= 10000,
        "invalid checkpoint inventory"
    );
    ensure!(
        (value.sequence == 1) == value.previous.is_none(),
        "invalid checkpoint chain start"
    );
    if let Some(previous) = &value.previous {
        valid_id(previous)?;
    }
    let mut previous = None;
    for id in &value.snapshots {
        valid_id(id)?;
        ensure!(
            previous.is_none_or(|p| p < id),
            "checkpoint inventory is not strictly sorted"
        );
        previous = Some(id);
    }
    Ok(value)
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn parse_locator(locator: &str) -> Result<(&str, &str, &str)> {
    let parts: Vec<_> = locator.split(':').collect();
    ensure!(
        parts.len() == 3,
        "recovery requires the saved repository:header:checkpoint locator"
    );
    for part in &parts {
        valid_id(part)?;
    }
    Ok((parts[0], parts[1], parts[2]))
}

pub async fn replicate(
    repo: &Repository,
    operator: &impl RemoteStore,
    selected: Option<&str>,
) -> Result<ReplicationReport> {
    replicate_with_publication(repo, operator, selected, |_| Ok(())).await
}

/// The callback must durably commit any adapter-specific recovery evidence before
/// the local latest pointer advances. Failure leaves remote objects uncommitted locally.
pub async fn replicate_with_publication(
    repo: &Repository,
    operator: &impl RemoteStore,
    selected: Option<&str>,
    before_advance: impl FnOnce(&ReplicationReport) -> Result<()>,
) -> Result<ReplicationReport> {
    let snapshots = if let Some(id) = selected {
        vec![repo.verify(id)?]
    } else {
        repo.list()?
            .into_iter()
            .map(|m| repo.verify(&m.id))
            .collect::<Result<Vec<_>>>()?
    };
    ensure!(
        !snapshots.is_empty() && snapshots.len() <= 10000,
        "checkpoint needs 1..10000 verified snapshots"
    );
    let mut chain = vec![];
    let previous = repo.read_private_metadata("checkpoints/latest", MAX_INDEX)?;
    let mut cursor = previous.clone();
    let mut expected_sequence = None;
    let mut chain_bytes = 0u64;
    while let Some(bytes) = cursor {
        ensure!(
            chain.len() < MAX_CHAIN,
            "checkpoint chain exceeds safety limit"
        );
        chain_bytes += bytes.len() as u64;
        ensure!(
            chain_bytes <= 64 * 1024 * 1024,
            "checkpoint history exceeds 64 MiB safety limit"
        );
        let index = decode(repo, &bytes)?;
        if let Some(sequence) = expected_sequence {
            ensure!(
                index.sequence == sequence,
                "checkpoint chain sequence mismatch"
            );
        }
        expected_sequence = index.sequence.checked_sub(1);
        cursor = index
            .previous
            .as_ref()
            .map(|id| {
                let prior = repo
                    .read_private_metadata(&format!("checkpoints/{id}"), MAX_INDEX)?
                    .context("missing local checkpoint ancestor")?;
                ensure!(digest(&prior) == *id, "local checkpoint ancestor changed");
                Ok::<_, anyhow::Error>(prior)
            })
            .transpose()?;
        chain.push(bytes);
    }
    let sequence = previous
        .as_ref()
        .map(|bytes| decode(repo, bytes))
        .transpose()?
        .map(|i| i.sequence)
        .unwrap_or(0)
        .checked_add(1)
        .context("checkpoint sequence exhausted")?;
    let header = repo.encrypted_object("repository.json")?;
    let header_id = digest(&header);
    let namespace = repo.identity();
    let mut snapshot_ids: Vec<_> = snapshots.iter().map(|m| m.id.clone()).collect();
    snapshot_ids.sort();
    let index = Index {
        version: 1,
        repository: namespace.clone(),
        header: header_id.clone(),
        sequence,
        previous: previous.as_ref().map(|b| digest(b)),
        snapshots: snapshot_ids,
    };
    let index_bytes = repo.seal_metadata(DOMAIN, &serde_json::to_vec(&index)?)?;
    ensure!(
        index_bytes.len() as u64 <= MAX_INDEX,
        "checkpoint exceeds limit"
    );
    validate_history_extension(chain.len(), chain_bytes, index_bytes.len() as u64)?;
    let index_id = digest(&index_bytes);
    operator
        .create_verified(&format!("{namespace}/headers/{header_id}"), header)
        .await?;
    let mut count = 1;
    let mut chunks = BTreeSet::new();
    for snapshot in &snapshots {
        chunks.extend(repo.snapshot_chunks(snapshot)?);
    }
    for chunk in chunks {
        operator
            .create_verified(
                &format!("{namespace}/chunks/{chunk}"),
                repo.encrypted_object(&format!("chunks/{chunk}"))?,
            )
            .await?;
        count += 1;
    }
    for snapshot in &snapshots {
        operator
            .create_verified(
                &format!("{namespace}/snapshots/{}", snapshot.id),
                repo.encrypted_object(&format!("snapshots/{}", snapshot.id))?,
            )
            .await?;
        count += 1;
    }
    for bytes in chain.into_iter().rev() {
        operator
            .create_verified(
                &format!("{namespace}/checkpoints/{}", digest(&bytes)),
                bytes,
            )
            .await?;
        count += 1;
    }
    // Publication point: all dependencies have been read back and verified.
    operator
        .create_verified(
            &format!("{namespace}/checkpoints/{index_id}"),
            index_bytes.clone(),
        )
        .await?;
    count += 1;
    let report = ReplicationReport {
        objects_verified: count,
        namespace: format!("{namespace}:{header_id}:{index_id}"),
        sequence,
        inventory_completeness: "authenticated_inventory_pinned_by_saved_locator",
    };
    before_advance(&report)?;
    repo.write_private_metadata(&format!("checkpoints/{index_id}"), &index_bytes, false)?;
    repo.write_private_metadata("checkpoints/latest", &index_bytes, true)?;
    Ok(report)
}

pub async fn recover(
    operator: &impl RemoteStore,
    locator: &str,
    destination: &Path,
    source: &KeySource,
    selected: Option<&str>,
) -> Result<usize> {
    let (namespace, header_id, checkpoint_id) = parse_locator(locator)?;
    ensure!(!destination.exists(), "recovery destination must not exist");
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let header = operator
        .read_bounded(&format!("{namespace}/headers/{header_id}"), 8192)
        .await
        .map_err(|_| anyhow!("pinned key envelope unavailable"))?;
    ensure!(digest(&header) == header_id, "pinned key envelope changed");
    durable_write(&staging.path().join("repository.json"), &header)?;
    for name in ["chunks", "snapshots", "requests"] {
        fs::create_dir(staging.path().join(name))?;
    }
    let repo = Repository::open_with_key_source(staging.path(), source)?;
    ensure!(
        repo.identity() == namespace,
        "recovery namespace does not match data key"
    );
    let mut cursor = Some(checkpoint_id.to_owned());
    let mut expected_sequence = None;
    let mut current = None;
    let mut latest = None;
    let mut visited = 0;
    let mut chain_bytes = 0u64;
    while let Some(id) = cursor {
        ensure!(visited < MAX_CHAIN, "checkpoint chain exceeds safety limit");
        visited += 1;
        let bytes = operator
            .read_bounded(&format!("{namespace}/checkpoints/{id}"), MAX_INDEX)
            .await
            .map_err(|_| anyhow!("pinned checkpoint chain incomplete"))?;
        chain_bytes += bytes.len() as u64;
        ensure!(
            chain_bytes <= 64 * 1024 * 1024,
            "checkpoint history exceeds 64 MiB safety limit"
        );
        ensure!(digest(&bytes) == id, "pinned checkpoint changed");
        let index = decode(&repo, &bytes)?;
        if let Some(sequence) = expected_sequence {
            ensure!(
                index.sequence == sequence,
                "checkpoint chain sequence mismatch"
            );
        }
        expected_sequence = index.sequence.checked_sub(1);
        cursor = index.previous.clone();
        if current.is_none() {
            ensure!(
                index.header == header_id,
                "checkpoint key envelope mismatch"
            );
            latest = Some(bytes.clone());
            current = Some(index);
        }
        repo.write_private_metadata(&format!("checkpoints/{id}"), &bytes, false)?;
    }
    let index = current.context("missing checkpoint")?;
    let snapshots = if let Some(id) = selected {
        valid_id(id)?;
        ensure!(
            index.snapshots.iter().any(|s| s == id),
            "snapshot is absent from pinned inventory"
        );
        vec![id.to_owned()]
    } else {
        index.snapshots
    };
    ensure!(!snapshots.is_empty(), "pinned inventory is empty");
    let mut total_bytes = 0u64;
    for id in &snapshots {
        let bytes = operator
            .read_bounded(&format!("{namespace}/snapshots/{id}"), 64 * 1024 * 1024)
            .await
            .map_err(|_| anyhow!("pinned inventory snapshot missing or unreadable"))?;
        total_bytes += bytes.len() as u64;
        ensure!(
            total_bytes <= 4 * 1024 * 1024 * 1024,
            "recovery exceeds 4 GiB cap; select a snapshot"
        );
        durable_write(&repo.root().join("snapshots").join(id), &bytes)?;
        let manifest = repo.manifest(id)?;
        for chunk in repo.snapshot_chunks(&manifest)? {
            let path = repo.root().join("chunks").join(&chunk);
            if path.exists() {
                continue;
            }
            let bytes = operator
                .read_bounded(&format!("{namespace}/chunks/{chunk}"), 8 * 1024 * 1024 + 40)
                .await
                .map_err(|_| anyhow!("pinned inventory chunk missing or unreadable"))?;
            total_bytes += bytes.len() as u64;
            ensure!(
                total_bytes <= 4 * 1024 * 1024 * 1024,
                "recovery exceeds 4 GiB cap; select a snapshot"
            );
            durable_write(&path, &bytes)?;
        }
        repo.verify(id)?;
    }
    repo.write_private_metadata(
        "checkpoints/latest",
        &latest.context("missing checkpoint")?,
        false,
    )?;
    drop(repo);
    storage::publish_recovery(staging.path(), destination)?;
    cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?
        .into_std_file()
        .sync_all()?;
    Ok(snapshots.len())
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn publishing_an_index_never_exceeds_its_recovery_limits() {
        assert!(validate_history_extension(9999, 64 * 1024 * 1024 - 1, 1).is_ok());
        assert!(validate_history_extension(10000, 100, 1).is_err());
        assert!(validate_history_extension(33, 64 * 1024 * 1024, 1).is_err());
        assert!(validate_history_extension(33, u64::MAX, 1).is_err());
    }
}
