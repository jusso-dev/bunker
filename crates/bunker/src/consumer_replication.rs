//! Consumer replication publishes only after exact-object evidence is durable.
use crate::{
    checkpoint,
    consumer_state::ConsumerState,
    consumer_storage::{ConsumerBackend, ConsumerEvidence, MAX_EVIDENCE},
    repository::Repository,
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerReport {
    pub version: u32,
    pub namespace: String,
    pub sequence: u64,
    pub evidence: ConsumerEvidence,
}
impl ConsumerReport {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EVIDENCE + 4096,
            "consumer report exceeds limit"
        );
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_EVIDENCE + 4096,
            "consumer report exceeds limit"
        );
        Ok(bytes)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.sequence > 0,
            "invalid consumer report"
        );
        self.evidence.to_vec()?;
        let parts: Vec<_> = self.namespace.split(':').collect();
        ensure!(
            parts.len() == 3,
            "consumer report requires pinned checkpoint locator"
        );
        for part in &parts {
            crate::repository::valid_id(part)?;
        }
        ensure!(
            self.evidence
                .objects
                .contains_key(&format!("{}/headers/{}", parts[0], parts[1]))
                && self
                    .evidence
                    .objects
                    .contains_key(&format!("{}/checkpoints/{}", parts[0], parts[2])),
            "consumer report omits envelope or checkpoint"
        );
        Ok(())
    }
}
pub async fn replicate(
    repo: &Repository,
    backend: &ConsumerBackend,
    state: &ConsumerState,
    selected: Option<&str>,
) -> Result<ConsumerReport> {
    let mut saved = None;
    checkpoint::replicate_with_publication(repo, backend, selected, |result| {
        let report = ConsumerReport {
            version: 1,
            namespace: result.namespace.clone(),
            sequence: result.sequence,
            evidence: backend.evidence()?,
        };
        state.save_report(&report)?;
        saved = Some(report);
        Ok(())
    })
    .await?;
    saved.ok_or_else(|| anyhow::anyhow!("consumer recovery evidence not committed"))
}
