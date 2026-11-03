use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Scheduler tick slack added to the latest on-time cycle before a backup counts as missed.
pub const MISSED_BACKUP_GRACE_SECONDS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Explicit opt-in to existing global agent setup capture. No ambient HOME lookup.
    pub setup_home: Option<PathBuf>,
    pub interval_seconds: u64,
    pub jitter_seconds: u64,
    pub size_cap_bytes: u64,
    pub max_file_bytes: u64,
    pub exclusions: Vec<String>,
    /// Include non-secret artifacts excluded by defaults; never overrides secret paths.
    pub default_includes: Vec<String>,
    /// Enforced by explicit operator-confirmed maintenance, never automatic deletion.
    pub retention_days: u32,
    pub immutable: bool,
    pub region: Option<String>,
    pub dr_repository: Option<String>,
    /// Interval between scheduled boot/MCP restore probes. They run only when a
    /// trusted probe configuration (`daemon --probe-config` or host mode) is supplied.
    pub restore_test_interval_seconds: u64,
    pub mass_delete_threshold: usize,
    /// No successful backup for this long is a missed backup; unset uses interval+jitter+60s.
    pub missed_backup_seconds: Option<u64>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            setup_home: None,
            interval_seconds: 3600,
            jitter_seconds: 60,
            size_cap_bytes: 1024 * 1024 * 1024,
            max_file_bytes: 64 * 1024 * 1024,
            exclusions: vec![],
            default_includes: vec![],
            retention_days: 30,
            immutable: false,
            region: None,
            dr_repository: None,
            restore_test_interval_seconds: 86400,
            mass_delete_threshold: 20,
            missed_backup_seconds: None,
        }
    }
}
impl Policy {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let policy: Self = match path {
            Some(p) => toml::from_str(&fs::read_to_string(p).context("read policy")?)?,
            None => Self::default(),
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<()> {
        if self.setup_home.as_ref().is_some_and(|path| {
            !path.is_absolute()
                || path
                    .to_str()
                    .is_none_or(|s| s.len() > 4096 || s.chars().any(char::is_control))
                || path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
        }) {
            bail!("setup_home must be an explicit normalized absolute path");
        }
        if self.interval_seconds == 0 || self.interval_seconds > 31_536_000 {
            bail!("interval_seconds must be 1..31536000");
        }
        if self.jitter_seconds > self.interval_seconds {
            bail!("jitter_seconds must not exceed interval_seconds");
        }
        if self
            .missed_backup_seconds
            .is_some_and(|s| !(60..=2_592_000).contains(&s))
        {
            bail!("missed_backup_seconds must be 60..2592000");
        }
        if self.size_cap_bytes == 0
            || self.max_file_bytes == 0
            || self.max_file_bytes > self.size_cap_bytes
            || self.max_file_bytes > 1024 * 1024 * 1024
        {
            bail!("invalid file/repository size cap (per-file maximum is 1 GiB)");
        }
        if self.retention_days == 0 {
            bail!("retention_days must be positive");
        }
        if self.immutable {
            bail!("local storage cannot enforce immutability; configure a verified object-lock backend");
        }
        if self.dr_repository.is_some() {
            bail!("immutable DR target support is not configured; refusing an unprotected policy");
        }
        for pattern in self.exclusions.iter().chain(&self.default_includes) {
            globset::Glob::new(pattern).context("invalid exclusion glob")?;
        }
        Ok(())
    }
    /// Seconds after the last success at which a backup counts as missed. Never earlier
    /// than the latest on-time cycle (interval + jitter + one minute of tick grace), so a
    /// threshold at or below the cadence cannot alert on every on-time capture.
    pub fn missed_backup_after(&self) -> u64 {
        let on_time = self
            .interval_seconds
            .saturating_add(self.jitter_seconds)
            .saturating_add(MISSED_BACKUP_GRACE_SECONDS);
        self.missed_backup_seconds.unwrap_or(0).max(on_time)
    }
}
