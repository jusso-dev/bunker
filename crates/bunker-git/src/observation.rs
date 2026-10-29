//! Encrypted capture observations and deliberately content-free public summaries.
use crate::{digest, valid_oid, validate_ref_namespace, GitBackup, Limits, Metadata, View};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};

/// Fixed categories only: never attach Git stderr, ref names, paths, or object IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitDiagnostic {
    CaptureUnavailable,
    ObservationUnavailable,
    PreviousTrackingUnavailable,
    BaselineMismatch,
    PreviousObjectUnavailable,
    AncestryUnavailable,
    ObservationLimitExceeded,
}

/// Safe for host/MCP metadata. A tracking rewrite does not prove a force push.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitAlerts {
    pub local_branch_rewrites: u64,
    pub remote_tracking_rewrites: u64,
    pub branch_deletions: u64,
    pub tracking_ref_deletions: u64,
    pub fast_forwards: u64,
    pub unchanged_refs: u64,
    pub diagnostics: BTreeMap<GitDiagnostic, u64>,
}
impl GitAlerts {
    pub fn unavailable(reason: GitDiagnostic) -> Self {
        let mut summary = Self::default();
        summary.diagnose(reason, 1);
        summary
    }
    fn diagnose(&mut self, reason: GitDiagnostic, count: u64) {
        if count != 0 {
            let total = self.diagnostics.entry(reason).or_default();
            *total = total.saturating_add(count);
        }
    }
}

/// PRIVATE data, persisted only inside authenticated encrypted Git metadata.
/// Kept separate from GitAlerts so callers cannot accidentally return ref tips.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    version: u32,
    tracking_refs: BTreeMap<String, String>,
    omitted_tracking_refs: u64,
    comparison_base: Option<String>,
    summary: GitAlerts,
}

pub(crate) fn validate(metadata: &Metadata, limits: &Limits) -> Result<()> {
    // Local heads already existed in v1 and are bounded by metadata bytes.
    // max_files cannot bound their count: packed-refs is a single storage file.
    for (name, oid) in &metadata.heads {
        crate::valid_ref(name)?;
        ensure!(name.starts_with("refs/heads/"), "invalid observed branch");
        valid_oid(oid)?;
    }
    validate_ref_namespace(metadata.heads.keys().map(String::as_str))?;
    let Some(observation) = &metadata.observation else {
        return Ok(());
    };
    ensure!(
        observation.version == 1,
        "unsupported Git observation version"
    );
    ensure!(
        observation.tracking_refs.len() <= limits.max_observation_refs,
        "Git observation ref cap exceeded"
    );
    for (name, oid) in &observation.tracking_refs {
        let suffix = name
            .strip_prefix("refs/remotes/")
            .ok_or_else(|| anyhow::anyhow!("invalid observed tracking ref"))?;
        crate::valid_ref(&format!("refs/heads/{suffix}"))?;
        valid_oid(oid)?;
    }
    validate_ref_namespace(
        metadata
            .heads
            .keys()
            .chain(observation.tracking_refs.keys())
            .map(String::as_str),
    )?;
    if let Some(base) = &observation.comparison_base {
        ensure!(
            base.len() == 64
                && base
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid Git observation baseline"
        );
    }
    Ok(())
}

/// Read a capture-time comparison, bound to exactly the previous metadata.
/// Both arguments must already be authenticated. No Git process or live path.
pub fn git_alerts(previous: &Metadata, current: &Metadata) -> Result<GitAlerts> {
    let Some(observation) = &current.observation else {
        return Ok(GitAlerts::unavailable(
            GitDiagnostic::ObservationUnavailable,
        ));
    };
    let Some(base) = &observation.comparison_base else {
        return Ok(GitAlerts::unavailable(
            GitDiagnostic::ObservationUnavailable,
        ));
    };
    if *base != digest(&serde_json::to_vec(previous)?) {
        return Ok(GitAlerts::unavailable(GitDiagnostic::BaselineMismatch));
    }
    Ok(observation.summary.clone())
}

impl GitBackup {
    pub(crate) fn observe(
        &self,
        view: &View,
        refs: &BTreeMap<String, String>,
        previous: Option<&Metadata>,
    ) -> Result<Observation> {
        let tracking_count = refs
            .keys()
            .filter(|r| r.starts_with("refs/remotes/"))
            .count();
        let tracking_refs: BTreeMap<_, _> = refs
            .iter()
            .filter(|(r, _)| r.starts_with("refs/remotes/"))
            .take(self.limits.max_observation_refs)
            .map(|(r, oid)| (r.clone(), oid.clone()))
            .collect();
        let mut observation = Observation {
            version: 1,
            omitted_tracking_refs: (tracking_count - tracking_refs.len()) as u64,
            tracking_refs,
            comparison_base: None,
            summary: GitAlerts::default(),
        };
        observation.summary.diagnose(
            GitDiagnostic::ObservationLimitExceeded,
            observation.omitted_tracking_refs,
        );
        let Some(previous) = previous else {
            return Ok(observation);
        };
        ensure!(
            serde_json::to_vec(previous)?.len() <= self.limits.max_metadata_bytes,
            "previous Git metadata exceeds cap"
        );
        validate(previous, &self.limits)?;
        observation.comparison_base = Some(digest(&serde_json::to_vec(previous)?));
        let previous_tracking = previous.observation.as_ref().map(|o| &o.tracking_refs);
        if let Some(old) = &previous.observation {
            observation.summary.diagnose(
                GitDiagnostic::ObservationLimitExceeded,
                old.omitted_tracking_refs,
            );
        } else {
            observation
                .summary
                .diagnose(GitDiagnostic::PreviousTrackingUnavailable, 1);
        }
        let started = Instant::now();
        let mut comparisons = 0;
        for (name, old) in previous
            .heads
            .iter()
            .chain(previous_tracking.into_iter().flatten())
        {
            let tracking = name.starts_with("refs/remotes/");
            let summary = &mut observation.summary;
            let Some(new) = refs.get(name) else {
                if tracking {
                    summary.tracking_ref_deletions += 1;
                } else {
                    summary.branch_deletions += 1;
                }
                continue;
            };
            if old == new {
                summary.unchanged_refs += 1;
                continue;
            }
            if comparisons >= self.limits.max_observation_comparisons
                || started.elapsed().as_secs() >= self.limits.command_timeout_secs
            {
                summary.diagnose(GitDiagnostic::ObservationLimitExceeded, 1);
                continue;
            }
            comparisons += 1;
            // Absence/corruption is unknown. Never import the old capture to make
            // an unavailable old object appear present in the current source.
            if !self
                .object(view, old)
                .is_ok_and(|object| object.kind == "commit")
            {
                summary.diagnose(GitDiagnostic::PreviousObjectUnavailable, 1);
                continue;
            }
            let count = format!(
                "--max-count={}",
                self.limits.max_ancestry_commits.saturating_add(1)
            );
            let ancestry = view.git(self).text(&["rev-list", &count, new, "--"], &[]);
            let Ok(ancestry) = ancestry else {
                summary.diagnose(GitDiagnostic::AncestryUnavailable, 1);
                continue;
            };
            // A tracking ref can legally name a tag/tree/blob. Only a direct
            // commit tip is evidence for this commit-history comparison.
            if ancestry.lines().next() != Some(new.as_str())
                || ancestry.lines().any(|oid| valid_oid(oid).is_err())
            {
                summary.diagnose(GitDiagnostic::AncestryUnavailable, 1);
            } else if ancestry.lines().any(|oid| oid == old) {
                summary.fast_forwards += 1;
            } else if ancestry.lines().count() > self.limits.max_ancestry_commits {
                summary.diagnose(GitDiagnostic::ObservationLimitExceeded, 1);
            } else if tracking {
                summary.remote_tracking_rewrites += 1;
            } else {
                summary.local_branch_rewrites += 1;
            }
        }
        Ok(observation)
    }
}
