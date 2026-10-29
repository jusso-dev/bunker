//! Versioned repository key envelopes. Legacy v1 passphrase headers stay readable.
use super::*;
use bunker_keys::{Escrow, ProviderConfig};

/// Unlock material is supplied by the operator, never inferred from a repository.
/// Provider configurations contain environment variable names, not credentials.
pub enum KeySource {
    Passphrase(Zeroizing<String>),
    Managed(ProviderConfig),
    Escrow {
        envelope: Escrow,
        recovery_key: Zeroizing<[u8; 32]>,
    },
}
impl KeySource {
    pub fn passphrase(value: &str) -> Self {
        Self::Passphrase(Zeroizing::new(value.to_owned()))
    }
    pub fn managed_config(path: &Path) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        ensure!(
            file.metadata()?.len() <= 16384,
            "key configuration exceeds limit"
        );
        let mut bytes = String::new();
        Read::take(&mut file, 16385).read_to_string(&mut bytes)?;
        ensure!(bytes.len() <= 16384, "key configuration exceeds limit");
        Ok(Self::Managed(toml::from_str(&bytes).map_err(|_| {
            anyhow!("invalid key provider configuration")
        })?))
    }
    fn wrap(&self, key: &[u8; 32], identity: String) -> Result<Header> {
        let mut header = Header {
            version: 2,
            salt: [0; 16],
            wrapped_key: vec![],
            managed_key: None,
            repository_id: Some(identity),
            authentication: None,
        };
        match self {
            Self::Passphrase(value) => {
                header.salt = crypto::random();
                let wrapping_key = crypto::derive(value, &header.salt)?;
                header.wrapped_key = crypto::seal(&wrapping_key, key, b"bunker-repository-key-v1")?;
            }
            Self::Managed(config) => {
                header.managed_key = Some(provider_call(|| async {
                    bunker_keys::wrap(config.connect()?.as_ref(), key).await
                })?);
            }
            Self::Escrow { .. } => {
                bail!("escrow is an unlock method; select a passphrase or managed key for wrapping")
            }
        }
        header.authentication = Some(header.mac(key)?);
        Ok(header)
    }
    fn unwrap(&self, header: &Header) -> Result<Zeroizing<[u8; 32]>> {
        header.validate_shape()?;
        let mut key = Zeroizing::new([0; 32]);
        if let Self::Escrow {
            envelope,
            recovery_key,
        } = self
        {
            ensure!(
                header.version == 2,
                "upgrade legacy header before escrow recovery"
            );
            let recovered = bunker_keys::recover_escrow(
                envelope,
                recovery_key,
                header
                    .repository_id
                    .as_deref()
                    .context("missing repository identity")?,
            )?;
            key.copy_from_slice(recovered.as_ref());
            header.verify(&key)?;
            return Ok(key);
        }
        match (self, &header.managed_key) {
            (Self::Passphrase(value), None) => {
                let wrapping_key = crypto::derive(value, &header.salt)?;
                let bytes = crypto::open(
                    &wrapping_key,
                    &header.wrapped_key,
                    b"bunker-repository-key-v1",
                )?;
                ensure!(bytes.len() == 32, "invalid data key length");
                key.copy_from_slice(&bytes);
            }
            (Self::Managed(config), Some(envelope)) => {
                let recovered = provider_call(|| async {
                    bunker_keys::unwrap(config.connect()?.as_ref(), envelope).await
                })?;
                key.copy_from_slice(recovered.as_ref());
            }
            _ => bail!("repository key mode does not match the supplied unlock method"),
        }
        header.verify(&key)?;
        Ok(key)
    }
}
// Provider HTTP clients are constructed and dropped on their own runtime. This
// synchronous API is also safe when called by an asynchronous storage operation.
fn provider_call<T: Send, F, Fut>(operation: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = Result<T>>,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || tokio::runtime::Runtime::new()?.block_on(operation()))
            .join()
            .map_err(|_| anyhow!("managed key worker failed"))?
    })
}
impl Header {
    fn validate_shape(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2),
            "unsupported repository key format"
        );
        if self.version == 1 {
            ensure!(
                self.repository_id.is_none()
                    && self.authentication.is_none()
                    && self.managed_key.is_none(),
                "invalid legacy header"
            );
        } else {
            valid_id(
                self.repository_id
                    .as_deref()
                    .context("missing repository identity")?,
            )?;
            valid_id(
                self.authentication
                    .as_deref()
                    .context("missing header authentication")?,
            )?;
        }
        if self.managed_key.is_some() {
            ensure!(
                self.wrapped_key.is_empty() && self.salt == [0; 16],
                "ambiguous key envelope"
            );
        } else {
            ensure!(
                self.wrapped_key.len() == 72,
                "invalid passphrase envelope length"
            );
        }
        Ok(())
    }
    fn mac(&self, key: &[u8; 32]) -> Result<String> {
        let value = serde_json::json!({
            "domain": "bunker-header-v2", "version": self.version, "salt": self.salt,
            "wrapped_key": self.wrapped_key, "managed_key": self.managed_key,
            "repository_id": self.repository_id,
        });
        Ok(blake3::keyed_hash(key, &serde_json::to_vec(&value)?)
            .to_hex()
            .to_string())
    }
    fn verify(&self, key: &[u8; 32]) -> Result<()> {
        self.validate_shape()?;
        if self.version == 2 {
            ensure!(
                self.repository_id.as_deref() == Some(key_identity(key).as_str()),
                "repository key identity mismatch"
            );
            // Hash equality uses constant-time comparison on the raw MAC bytes.
            let expected = blake3::Hash::from_hex(self.mac(key)?)?;
            let actual = blake3::Hash::from_hex(self.authentication.as_deref().unwrap())?;
            ensure!(
                expected == actual,
                "repository header authentication failed"
            );
        }
        Ok(())
    }
}
fn key_identity(key: &[u8; 32]) -> String {
    blake3::keyed_hash(key, b"bunker-repository-identity-v2")
        .to_hex()
        .to_string()
}
fn open_locked(path: &Path) -> Result<(PathBuf, Dir, fs::File)> {
    let root = path.canonicalize().context("repository does not exist")?;
    let dir = Dir::open_ambient_dir(&root, ambient_authority())?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = dir.open_with("lock", &options)?.into_std();
    lock.try_lock_exclusive().context("repository is busy")?;
    Ok((root, dir, lock))
}
impl Repository {
    pub(crate) fn metadata_token(&self, domain: &str, bytes: &[u8]) -> Result<String> {
        let bound = serde_json::to_vec(&("bunker-metadata-token-v1", domain, bytes))?;
        Ok(blake3::keyed_hash(&self.key, &bound).to_hex().to_string())
    }
    pub(crate) fn seal_metadata(&self, domain: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
        crypto::seal(&self.key, bytes, domain)
    }
    pub(crate) fn open_metadata(&self, domain: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::open(&self.key, bytes, domain)
    }
    pub(crate) fn read_private_metadata(
        &self,
        path: &str,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>> {
        if !self.dir.try_exists(path)? {
            return Ok(None);
        }
        Ok(Some(read_bounded(&self.dir, path, maximum)?))
    }
    pub(crate) fn write_private_metadata(
        &self,
        path: &str,
        bytes: &[u8],
        replace: bool,
    ) -> Result<()> {
        atomic_write(&self.dir, path, bytes, replace)
    }
    pub fn init_with_key_source(path: &Path, source: &KeySource) -> Result<Self> {
        let existed = path.try_exists()?;
        if existed {
            ensure!(
                fs::symlink_metadata(path)?.is_dir() && fs::read_dir(path)?.next().is_none(),
                "repository directory must be empty and not a symlink"
            );
        }
        // Canonicalize existing targets so `.` and trailing `/.` stage beside,
        // never inside, the initialization destination.
        let resolved = if existed {
            path.canonicalize()?
        } else {
            path.to_path_buf()
        };
        let path = resolved.as_path();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        // Prepare everything in a private sibling directory. Failure, including a
        // provider/configuration error, leaves the requested destination unchanged.
        let staging = tempfile::tempdir_in(parent)?;
        let (_, dir, lock) = open_locked(staging.path())?;
        let key = Zeroizing::new(crypto::random::<32>());
        let header = source.wrap(&key, key_identity(&key))?;
        for name in ["chunks", "snapshots", "requests"] {
            dir.create_dir(name)?;
        }
        let bytes = serde_json::to_vec(&header)?;
        atomic_write(&dir, "repository.json", &bytes, false)?;
        if existed {
            // Preserve the existing directory inode, including a caller's cwd.
            // All fallible provider work completed before creating the target lock.
            ensure!(
                fs::read_dir(path)?.next().is_none(),
                "repository destination changed"
            );
            let (root, target, target_lock) = open_locked(path)?;
            for name in ["chunks", "snapshots", "requests"] {
                target.create_dir(name)?;
            }
            atomic_write(&target, "repository.json", &bytes, false)?;
            return Ok(Self {
                root,
                dir: target,
                key,
                header_digest: std::sync::RwLock::new(*blake3::hash(&bytes).as_bytes()),
                _lock: target_lock,
            });
        }
        crate::storage::publish_recovery(staging.path(), path)?;
        Dir::open_ambient_dir(parent, ambient_authority())?
            .into_std_file()
            .sync_all()?;
        let root = path.canonicalize()?;
        Ok(Self {
            root,
            dir,
            key,
            header_digest: std::sync::RwLock::new(*blake3::hash(&bytes).as_bytes()),
            _lock: lock,
        })
    }
    pub fn open_with_key_source(path: &Path, source: &KeySource) -> Result<Self> {
        let (root, dir, lock) = open_locked(path)?;
        let bytes = read_bounded(&dir, "repository.json", 8192)?;
        let header: Header = serde_json::from_slice(&bytes)?;
        let key = source.unwrap(&header)?;
        Ok(Self {
            root,
            dir,
            key,
            header_digest: std::sync::RwLock::new(*blake3::hash(&bytes).as_bytes()),
            _lock: lock,
        })
    }
    /// Rewraps the same data key. This cannot revoke old envelopes or copies.
    pub fn rewrap_key(&self, source: &KeySource) -> Result<()> {
        self.encrypted_object("repository.json")?;
        let header = source.wrap(&self.key, self.identity())?;
        let bytes = serde_json::to_vec(&header)?;
        atomic_write(&self.dir, "repository.json", &bytes, true)?;
        *self
            .header_digest
            .write()
            .map_err(|_| anyhow!("header lock poisoned"))? = *blake3::hash(&bytes).as_bytes();
        Ok(())
    }
    /// Stable identity is key-derived and survives wrapping-key changes.
    pub fn identity(&self) -> String {
        key_identity(&self.key)
    }
    pub fn export_escrow(&self, recovery_key: &[u8; 32]) -> Result<Escrow> {
        let header: Header = serde_json::from_slice(&self.encrypted_object("repository.json")?)?;
        ensure!(
            header.version == 2,
            "rewrap the legacy header before exporting escrow"
        );
        bunker_keys::escrow(&self.key, recovery_key, &self.identity())
    }
    pub fn export_escrow_to(&self, path: &Path, recovery_key: &[u8; 32]) -> Result<()> {
        let escrow = self.export_escrow(recovery_key)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid escrow filename")?;
        // Capability directory handles use the platform's directory-opening flags;
        // publication is atomic/no-clobber and shares repository durability logic.
        atomic_write(&dir, name, &serde_json::to_vec(&escrow)?, false)
    }
    pub fn open_with_escrow(path: &Path, escrow: &Escrow, recovery_key: &[u8; 32]) -> Result<Self> {
        let (root, dir, lock) = open_locked(path)?;
        let bytes = read_bounded(&dir, "repository.json", 8192)?;
        let header: Header = serde_json::from_slice(&bytes)?;
        ensure!(
            header.version == 2,
            "upgrade the legacy header before escrow recovery"
        );
        let recovered = bunker_keys::recover_escrow(
            escrow,
            recovery_key,
            header
                .repository_id
                .as_deref()
                .context("missing repository identity")?,
        )?;
        let key = Zeroizing::new(*recovered);
        header.verify(&key)?;
        Ok(Self {
            root,
            dir,
            key,
            header_digest: std::sync::RwLock::new(*blake3::hash(&bytes).as_bytes()),
            _lock: lock,
        })
    }
}
