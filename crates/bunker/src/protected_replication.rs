//! Protected replicas share one checkpoint and retain exact-version recovery evidence.
use crate::{
    checkpoint::{self, RemoteStore},
    protected_storage::{ProtectedBackend, ProtectionEvidence},
    repository::Repository,
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// Every dependency reaches both stores before the next object is published. A
/// partial failure never advances the local checkpoint or reports paired success.
pub struct PairedStore<'a, A, B> {
    pub primary: &'a A,
    pub secondary: &'a B,
}
impl<A: RemoteStore, B: RemoteStore> RemoteStore for PairedStore<'_, A, B> {
    async fn read_bounded(&self, path: &str, maximum: u64) -> Result<Vec<u8>> {
        self.primary.read_bounded(path, maximum).await
    }
    async fn create_verified(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        self.primary.create_verified(path, bytes.clone()).await?;
        self.secondary.create_verified(path, bytes).await
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedReport {
    pub version: u32,
    pub namespace: String,
    pub sequence: u64,
    pub objects_per_backend: usize,
    pub backends: Vec<ProtectionEvidence>,
}
impl ProtectedReport {
    pub fn load_local(repo: &Repository, checkpoint: &str) -> Result<Self> {
        crate::repository::valid_id(checkpoint)?;
        let bytes = repo
            .read_private_metadata(
                &format!("checkpoints/reports/{checkpoint}"),
                64 * 1024 * 1024 + 40,
            )?
            .ok_or_else(|| anyhow::anyhow!("protected report not found"))?;
        let report: Self =
            serde_json::from_slice(&repo.open_metadata(b"bunker-protected-report-v1", &bytes)?)?;
        report.validate()?;
        ensure!(
            report.namespace.split(':').next() == Some(repo.identity().as_str())
                && report.namespace.rsplit(':').next() == Some(checkpoint),
            "protected report binding mismatch"
        );
        Ok(report)
    }
    /// Encrypted local fallback retained before exporting the external DR report.
    pub fn persist_local(&self, repo: &Repository) -> Result<()> {
        self.validate()?;
        ensure!(
            self.namespace.split(':').next() == Some(repo.identity().as_str()),
            "report repository mismatch"
        );
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "protected report exceeds limit"
        );
        let checkpoint = self.namespace.rsplit(':').next().unwrap();
        repo.write_private_metadata(
            &format!("checkpoints/reports/{checkpoint}"),
            &repo.seal_metadata(b"bunker-protected-report-v1", &bytes)?,
            false,
        )
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && (1..=2).contains(&self.backends.len()),
            "invalid protected report"
        );
        ensure!(
            self.sequence > 0 && (1..=100_000).contains(&self.objects_per_backend),
            "invalid protected inventory size"
        );
        let parts: Vec<_> = self.namespace.split(':').collect();
        ensure!(parts.len() == 3, "invalid protected checkpoint locator");
        for part in &parts {
            crate::repository::valid_id(part)?;
        }
        for evidence in &self.backends {
            ensure!(
                evidence.objects.len() == self.objects_per_backend,
                "protected evidence inventory mismatch"
            );
            ensure!(
                evidence
                    .objects
                    .contains_key(&format!("{}/headers/{}", parts[0], parts[1]))
                    && evidence
                        .objects
                        .contains_key(&format!("{}/checkpoints/{}", parts[0], parts[2])),
                "protected evidence omits checkpoint or envelope"
            );
        }
        if self.backends.len() == 2 {
            let a = &self.backends[0];
            let b = &self.backends[1];
            ensure!(
                a.identity.backend != b.identity.backend
                    && a.identity.credential != b.identity.credential,
                "protected DR requires distinct backends and credentials"
            );
            ensure!(
                a.required_until == b.required_until && a.objects.keys().eq(b.objects.keys()),
                "DR inventories differ"
            );
            for (path, proof) in &a.objects {
                let other = &b.objects[path];
                ensure!(
                    proof.blake3 == other.blake3 && proof.bytes == other.bytes,
                    "DR ciphertext differs"
                );
            }
        }
        Ok(())
    }
}

pub async fn replicate(
    repo: &Repository,
    primary: &ProtectedBackend,
    secondary: Option<&ProtectedBackend>,
    selected: Option<&str>,
) -> Result<ProtectedReport> {
    if let Some(secondary) = secondary {
        primary.ensure_independent(secondary)?;
        ensure!(
            primary.evidence()?.required_until == secondary.evidence()?.required_until,
            "DR retention deadlines must match before publication"
        );
    }
    // Fresh backend instances ensure evidence contains only this inventory.
    ensure!(
        primary.evidence()?.objects.is_empty(),
        "use a fresh protected backend for replication"
    );
    if let Some(secondary) = secondary {
        ensure!(
            secondary.evidence()?.objects.is_empty(),
            "use a fresh DR backend for replication"
        );
    }
    let mut saved = None;
    let commit_evidence = |result: &checkpoint::ReplicationReport| -> Result<()> {
        let mut backends = vec![primary.evidence()?];
        if let Some(secondary) = secondary {
            backends.push(secondary.evidence()?);
        }
        let report = ProtectedReport {
            version: 1,
            namespace: result.namespace.clone(),
            sequence: result.sequence,
            objects_per_backend: result.objects_verified,
            backends,
        };
        report.validate()?;
        report.persist_local(repo)?;
        saved = Some(report);
        Ok(())
    };
    if let Some(secondary) = secondary {
        checkpoint::replicate_with_publication(
            repo,
            &PairedStore { primary, secondary },
            selected,
            commit_evidence,
        )
        .await?;
    } else {
        checkpoint::replicate_with_publication(repo, primary, selected, commit_evidence).await?;
    }
    saved.ok_or_else(|| anyhow::anyhow!("protected evidence was not committed"))
}
