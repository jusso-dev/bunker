//! Explicit private OAuth rotation and exact-ID evidence state. No ambient discovery.
use crate::{
    consumer_storage::{
        ConsumerEvidence, ConsumerLocation, EvidenceSink, PersistenceError, RefreshTokenSink,
        MAX_EVIDENCE,
    },
    storage::StorageConfig,
};
use anyhow::{ensure, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use fs2::FileExt;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub struct ConsumerState {
    directory: PathBuf,
    dir: Dir,
    reference: String,
    location: ConsumerLocation,
    _lock: std::fs::File,
}
fn validate_credential(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 16384 && !value.chars().any(char::is_control),
        "invalid explicit OAuth credential"
    );
    Ok(())
}
impl ConsumerState {
    /// One canonical 0700 directory per explicit provider/folder/client binding.
    /// The exclusive lock lasts for the entire replication/recovery operation.
    pub fn open(path: &Path, config: &StorageConfig) -> Result<Self> {
        let location = crate::consumer_storage::validated_location(config)?;
        let reference = config
            .credential_env
            .get("refresh_token")
            .context("refresh token reference required")?
            .clone();
        let client_ref = config
            .credential_env
            .get("client_id")
            .context("client identity reference required")?;
        let client = Zeroizing::new(
            std::env::var(client_ref).context("configured OAuth client identity unavailable")?,
        );
        validate_credential(&client)?;
        let binding = blake3::hash(&serde_json::to_vec(&(config, client.as_str()))?)
            .to_hex()
            .to_string();
        let directory = crate::control_plane::private_directory(path)?;
        let dir = Dir::open_ambient_dir(&directory, ambient_authority())?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NONBLOCK);
        }
        let lock = dir.open_with("lock", &options)?.into_std();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = lock.metadata()?;
            ensure!(
                m.is_file()
                    && m.nlink() == 1
                    && m.uid() == unsafe { libc::geteuid() }
                    && m.mode() & 0o077 == 0,
                "unsafe consumer state lock"
            );
        }
        lock.try_lock_exclusive()
            .context("consumer state is busy")?;
        let state = Self {
            directory,
            dir,
            reference,
            location,
            _lock: lock,
        };
        match state.read("binding", 256)? {
            Some(saved) => ensure!(
                saved.as_slice() == binding.as_bytes(),
                "consumer state belongs to a different provider, folder or OAuth client"
            ),
            None => {
                for entry in state.dir.entries()? {
                    ensure!(
                        entry?.file_name() == "lock",
                        "unbound consumer state must be empty"
                    );
                }
                crate::repository::atomic_write(&state.dir, "binding", binding.as_bytes(), false)?;
            }
        }
        Ok(state)
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Validate replacement and all required OAuth inputs before binding new state.
    pub fn open_for_rebind(path: &Path, config: &StorageConfig, token: &str) -> Result<Self> {
        crate::consumer_storage::validated_location(config)?;
        validate_credential(token)?;
        let secret = Zeroizing::new(
            std::env::var(&config.credential_env["client_secret"])
                .context("configured OAuth client credential unavailable")?,
        );
        validate_credential(&secret)?;
        Self::open(path, config)
    }
    /// Explicit recovery after an uncertain refresh; never silently retry the attempted token.
    pub fn rebind_refresh(&self, token: &str) -> Result<()> {
        validate_credential(token)?;
        if let Some(pending) = self.read("refresh-pending", 64)? {
            let digest = std::str::from_utf8(&pending)?;
            crate::repository::valid_id(digest)?;
            ensure!(blake3::hash(token.as_bytes()).to_hex().as_str() != digest, "uncertain refresh requires a different privately recovered or reauthorized credential");
        }
        crate::repository::atomic_write(&self.dir, "credentials.json", token.as_bytes(), true)?;
        self.finish_refresh(&self.reference)
            .map_err(|_| anyhow::anyhow!("failed to commit OAuth rebinding"))
    }
    pub fn save_report(&self, report: &crate::consumer_replication::ConsumerReport) -> Result<()> {
        ensure!(
            report.evidence.location == self.location,
            "consumer report location mismatch"
        );
        let checkpoint = report
            .namespace
            .rsplit(':')
            .next()
            .context("missing checkpoint")?;
        crate::repository::valid_id(checkpoint)?;
        match self.dir.create_dir("reports") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let reports = self.dir.open_dir_nofollow("reports")?;
        // Persist the directory entry itself before a report can authorize local
        // checkpoint advancement. Syncing only the new child is insufficient.
        self.dir.try_clone()?.into_std_file().sync_all()?;
        crate::repository::atomic_write(
            &reports,
            &format!("{checkpoint}.json"),
            &report.to_vec()?,
            false,
        )
    }
    pub fn load_report(
        &self,
        checkpoint: &str,
    ) -> Result<crate::consumer_replication::ConsumerReport> {
        crate::repository::valid_id(checkpoint)?;
        let bytes = self
            .read(
                &format!("reports/{checkpoint}.json"),
                (MAX_EVIDENCE + 4096) as u64,
            )?
            .context("consumer report not found")?;
        let report = crate::consumer_replication::ConsumerReport::from_slice(&bytes)?;
        ensure!(
            report.evidence.location == self.location,
            "consumer report location mismatch"
        );
        ensure!(
            report.namespace.rsplit(':').next() == Some(checkpoint),
            "consumer report checkpoint mismatch"
        );
        Ok(report)
    }
    fn read(&self, name: &str, limit: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let reports;
        let (dir, name) = if let Some(file) = name.strip_prefix("reports/") {
            reports = self.dir.open_dir_nofollow("reports")?;
            ensure!(!file.contains('/'), "invalid report path");
            (&reports, file)
        } else {
            (&self.dir, name)
        };
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = match dir.open_with(name, &options) {
            Ok(file) => file.into_std(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= limit,
            "invalid private consumer state file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                meta.nlink() == 1
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o077 == 0,
                "unsafe consumer state permissions"
            );
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= limit, "consumer state exceeds limit");
        Ok(Some(bytes))
    }
    pub fn evidence(&self) -> Result<Option<ConsumerEvidence>> {
        self.read("evidence.json", MAX_EVIDENCE as u64)?
            .map(|bytes| {
                let evidence = ConsumerEvidence::from_slice(&bytes)?;
                ensure!(
                    evidence.location == self.location,
                    "consumer evidence location mismatch"
                );
                Ok(evidence)
            })
            .transpose()
    }
}
impl RefreshTokenSink for ConsumerState {
    fn begin_refresh(
        &self,
        reference: &str,
        token: &str,
    ) -> std::result::Result<(), PersistenceError> {
        (|| -> Result<()> {
            ensure!(
                reference == self.reference && !token.is_empty() && token.len() <= 16384,
                "invalid refresh intent"
            );
            let digest = blake3::hash(token.as_bytes()).to_hex().to_string();
            crate::repository::atomic_write(&self.dir, "refresh-pending", digest.as_bytes(), false)
        })()
        .map_err(|_| PersistenceError)
    }
    fn finish_refresh(&self, reference: &str) -> std::result::Result<(), PersistenceError> {
        (|| -> Result<()> {
            ensure!(reference == self.reference, "refresh reference mismatch");
            if self.read("refresh-pending", 64)?.is_some() {
                self.dir.remove_file("refresh-pending")?;
            }
            self.dir.try_clone()?.into_std_file().sync_all()?;
            Ok(())
        })()
        .map_err(|_| PersistenceError)
    }
    fn load(
        &self,
        reference: &str,
    ) -> std::result::Result<Option<Zeroizing<String>>, PersistenceError> {
        (|| -> Result<_> {
            ensure!(
                reference == self.reference,
                "refresh token reference mismatch"
            );
            ensure!(
                self.read("refresh-pending", 64)?.is_none(),
                "uncertain OAuth refresh requires explicit rebinding"
            );
            self.read("credentials.json", 16384)?
                .map(|bytes| {
                    let value = std::str::from_utf8(&bytes)?;
                    ensure!(
                        !value.is_empty() && !value.chars().any(char::is_control),
                        "invalid saved refresh credential"
                    );
                    Ok(Zeroizing::new(value.to_owned()))
                })
                .transpose()
        })()
        .map_err(|_| PersistenceError)
    }
    fn persist(&self, reference: &str, token: &str) -> std::result::Result<(), PersistenceError> {
        (|| -> Result<()> {
            ensure!(
                reference == self.reference
                    && !token.is_empty()
                    && token.len() <= 16384
                    && !token.chars().any(char::is_control),
                "invalid refresh rotation"
            );
            crate::repository::atomic_write(&self.dir, "credentials.json", token.as_bytes(), true)
        })()
        .map_err(|_| PersistenceError)
    }
}
impl EvidenceSink for ConsumerState {
    fn persist(&self, evidence: &ConsumerEvidence) -> std::result::Result<(), PersistenceError> {
        (|| -> Result<()> {
            ensure!(
                evidence.location == self.location,
                "consumer evidence location mismatch"
            );
            let bytes = evidence.to_vec()?;
            crate::repository::atomic_write(&self.dir, "evidence.json", &bytes, true)
        })()
        .map_err(|_| PersistenceError)
    }
}
