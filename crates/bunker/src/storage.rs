//! Encrypted object replication only. No delete, retention, or plaintext upload API.
use anyhow::{bail, ensure, Context, Result};
use opendal::{layers::RetryLayer, Operator};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub service: String,
    /// Non-secret provider options (bucket, root, endpoint, region).
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    /// Provider option => environment variable NAME. Never literal credential values.
    #[serde(default)]
    pub credential_env: BTreeMap<String, String>,
    #[serde(default)]
    pub immutable: bool,
}
impl StorageConfig {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }
    pub fn operator(&self) -> Result<Operator> {
        ensure!(
            !self.immutable,
            "object lock has not been verified for this adapter; refusing immutability claim"
        );
        let service = match self.service.as_str() {
            "s3" | "r2" => "s3",
            "azure" => "azblob",
            "gdrive" | "onedrive" => bail!("Google Drive and OneDrive require the exact-ID consumer adapter: use replicate --consumer-state PATH --report PATH and recover --consumer-report PATH; this OpenDAL operator is unsupported"),
            "local" => "fs",
            _ => bail!("unsupported storage service"),
        };
        let public = [
            "bucket",
            "root",
            "endpoint",
            "region",
            "container",
            "account_name",
            "drive_id",
        ];
        ensure!(
            self.options.keys().all(|k| public.contains(&k.as_str())),
            "storage options contain an unsupported or secret-bearing field; use credential_env"
        );
        if let Some(endpoint) = self.options.get("endpoint") {
            validate_endpoint(endpoint)?;
        }
        let allowed_credentials: &[&str] = match service {
            "s3" => &["access_key_id", "secret_access_key", "session_token"],
            "azblob" => &["account_key", "sas_token"],
            "gdrive" | "onedrive" => &[
                "access_token",
                "refresh_token",
                "client_id",
                "client_secret",
            ],
            _ => &[],
        };
        let mut options = self.options.clone();
        for (key, env_name) in &self.credential_env {
            ensure!(
                allowed_credentials.contains(&key.as_str()),
                "unsupported credential option"
            );
            ensure!(
                !env_name.is_empty()
                    && env_name
                        .bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'),
                "invalid credential environment variable name"
            );
            options.insert(
                key.clone(),
                std::env::var(env_name).map_err(|_| {
                    anyhow::anyhow!("required storage credential environment variable is not set")
                })?,
            );
        }
        build_operator(service, &options).map(|operator| operator.layer(RetryLayer::new()))
    }
}
fn validate_endpoint(endpoint: &str) -> Result<()> {
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid storage endpoint"))?;
    ensure!(
        uri.scheme_str() == Some("https")
            && uri.host().is_some_and(|h| !h.is_empty())
            && uri.query().is_none()
            && !endpoint.contains('@')
            && !endpoint.contains('#'),
        "storage endpoints must use HTTPS without credentials or query parameters"
    );
    Ok(())
}
fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.trim().is_empty())
        .with_context(|| {
            format!("explicit storage {key} is required; ambient fallback is disabled")
        })
}
/// Typed S3/Azure builders replace, rather than prepend to, the default chain.
/// No environment, profile, SSO, workload identity, IMDS or certificate provider
/// is reachable from these operators. reqsign's RSA code remains linked but is
/// not selected by this application's static-only credential chains.
fn build_operator(service: &str, options: &BTreeMap<String, String>) -> Result<Operator> {
    match service {
        "s3" => {
            let endpoint = required(options, "endpoint")?;
            validate_endpoint(endpoint)?;
            let mut provider = reqsign_aws_v4::StaticCredentialProvider::new(
                required(options, "access_key_id")?,
                required(options, "secret_access_key")?,
            );
            if options.contains_key("session_token") {
                provider = provider.with_session_token(required(options, "session_token")?);
            }
            let builder = opendal::services::S3::default()
                .bucket(required(options, "bucket")?)
                .region(required(options, "region")?)
                .endpoint(endpoint)
                .root(options.get("root").map(String::as_str).unwrap_or("/"))
                .disable_config_load()
                .disable_ec2_metadata()
                .credential_provider_chain(
                    reqsign_core::ProvideCredentialChain::new().push(provider),
                );
            Operator::new(builder).map_err(|_| anyhow::anyhow!("invalid explicit S3 configuration"))
        }
        "azblob" => {
            let endpoint = required(options, "endpoint")?;
            validate_endpoint(endpoint)?;
            ensure!(
                !(options.contains_key("sas_token") && options.contains_key("account_key")),
                "configure either Azure SAS or SharedKey, not both"
            );
            let provider = if options.contains_key("sas_token") {
                reqsign_azure_storage::StaticCredentialProvider::new_sas_token(required(
                    options,
                    "sas_token",
                )?)
            } else {
                let key = required(options, "account_key")?;
                // A custom provider bypasses the builder's static-key validation.
                // Validate here without echoing the supplied key in diagnostics.
                use base64::Engine;
                ensure!(
                    base64::engine::general_purpose::STANDARD
                        .decode(key)
                        .is_ok(),
                    "invalid Azure SharedKey encoding"
                );
                reqsign_azure_storage::StaticCredentialProvider::new_shared_key(
                    required(options, "account_name")?,
                    key,
                )
            };
            let mut builder = opendal::services::Azblob::default()
                .container(required(options, "container")?)
                .endpoint(endpoint)
                .root(options.get("root").map(String::as_str).unwrap_or("/"))
                .credential_provider_chain(
                    reqsign_core::ProvideCredentialChain::new().push(provider),
                );
            if let Some(name) = options.get("account_name") {
                builder = builder.account_name(name);
            }
            Operator::new(builder)
                .map_err(|_| anyhow::anyhow!("invalid explicit Azure configuration"))
        }
        _ => Operator::via_iter(service, options.clone())
            .map_err(|_| anyhow::anyhow!("storage configuration rejected; check provider options")),
    }
}

pub async fn replicate(
    repository: &crate::repository::Repository,
    operator: &Operator,
) -> Result<usize> {
    // Authenticate every manifest/chunk before replication. Publish each manifest last.
    replicate_selected(repository, operator, None).await
}
/// A selected snapshot isolates recovery/replication from unrelated damaged manifests.
pub async fn replicate_selected(
    repository: &crate::repository::Repository,
    operator: &Operator,
    selected: Option<&str>,
) -> Result<usize> {
    let snapshots = if let Some(id) = selected {
        vec![repository.manifest(id)?]
    } else {
        repository
            .list()
            .context("some manifests are damaged; select a verified snapshot with --snapshot")?
    };

    for snapshot in &snapshots {
        repository.verify(&snapshot.id)?;
    }
    let header = repository.encrypted_object("repository.json")?;
    let namespace = blake3::hash(&header).to_hex().to_string();
    let mut count = 0;
    copy_verified(operator, &format!("{namespace}/repository.json"), header).await?;
    count += 1;
    let mut chunks = std::collections::BTreeSet::new();
    for snapshot in &snapshots {
        chunks.extend(repository.snapshot_chunks(snapshot)?);
    }
    for chunk in chunks {
        copy_verified(
            operator,
            &format!("{namespace}/chunks/{chunk}"),
            repository.encrypted_object(&format!("chunks/{chunk}"))?,
        )
        .await?;
        count += 1;
    }
    for snapshot in &snapshots {
        copy_verified(
            operator,
            &format!("{namespace}/snapshots/{}", snapshot.id),
            repository.encrypted_object(&format!("snapshots/{}", snapshot.id))?,
        )
        .await?;
        count += 1;
    }
    repository.audit(
        "replicated",
        serde_json::json!({"namespace":namespace,"objects_verified":count,"immutable":false}),
    )?;
    Ok(count)
}
pub(crate) async fn copy_verified(operator: &Operator, path: &str, bytes: Vec<u8>) -> Result<()> {
    ensure!(
        operator.info().capability().write_with_if_not_exists,
        "backend lacks conditional create; refusing overwrite-prone replication"
    );
    let expected = blake3::hash(&bytes);
    let maximum = bytes.len() as u64;
    match remote_read(operator, path, maximum).await {
        Ok(existing) => ensure!(
            blake3::hash(&existing.to_vec()) == expected,
            "remote object differs; refusing overwrite"
        ),
        Err(error) if error.kind() == opendal::ErrorKind::NotFound => {
            operator
                .write_with(path, bytes)
                .if_not_exists(true)
                .await
                .map_err(|_| anyhow::anyhow!("encrypted object upload failed"))?;
            let stored = remote_read(operator, path, maximum)
                .await
                .map_err(|_| anyhow::anyhow!("upload verification read failed"))?;
            ensure!(
                blake3::hash(&stored.to_vec()) == expected,
                "upload verification failed"
            );
        }
        Err(_) => bail!("remote object read failed"),
    }
    Ok(())
}
pub(crate) async fn remote_read(
    operator: &Operator,
    path: &str,
    maximum: u64,
) -> opendal::Result<Vec<u8>> {
    let size = operator.stat(path).await?.content_length();
    if size > maximum {
        return Err(opendal::Error::new(
            opendal::ErrorKind::Unexpected,
            "remote object exceeds safety limit",
        ));
    }
    if size == 0 {
        return Ok(vec![]);
    }
    let bytes = operator.read_with(path).range(0..size).await?.to_vec();
    if bytes.len() as u64 != size {
        return Err(opendal::Error::new(
            opendal::ErrorKind::Unexpected,
            "remote object changed while reading",
        ));
    }
    Ok(bytes)
}

pub async fn recover(
    operator: &Operator,
    namespace: &str,
    destination: &Path,
    passphrase: &str,
) -> Result<usize> {
    recover_selected(operator, namespace, destination, passphrase, None).await
}
pub async fn recover_selected(
    operator: &Operator,
    namespace: &str,
    destination: &Path,
    passphrase: &str,
    selected: Option<&str>,
) -> Result<usize> {
    recover_legacy_with_key_source(
        operator,
        namespace,
        destination,
        &crate::repository::KeySource::passphrase(passphrase),
        selected,
    )
    .await
}
/// Explicit compatibility path: inventory completeness cannot be established by listing.
pub async fn recover_legacy_with_key_source(
    operator: &Operator,
    namespace: &str,
    destination: &Path,
    source: &crate::repository::KeySource,
    selected: Option<&str>,
) -> Result<usize> {
    ensure!(
        namespace.len() == 64 && namespace.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid repository namespace"
    );
    ensure!(!destination.exists(), "recovery destination must not exist");
    let parent = destination
        .parent()
        .context("recovery destination needs a parent")?;
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let header = remote_read(operator, &format!("{namespace}/repository.json"), 8192)
        .await
        .map_err(|_| anyhow::anyhow!("repository header download failed"))?
        .to_vec();
    ensure!(
        header.len() <= 8192 && blake3::hash(&header).to_hex().as_str() == namespace,
        "repository header integrity failure"
    );
    crate::repository::durable_write(&staging.path().join("repository.json"), &header)?;
    for directory in ["chunks", "snapshots", "requests"] {
        fs::create_dir(staging.path().join(directory))?;
    }
    let repo = crate::repository::Repository::open_with_key_source(staging.path(), source)?;
    let prefix = format!("{namespace}/snapshots/");
    let paths = if let Some(id) = selected {
        crate::repository::valid_id(id)?;
        vec![format!("{prefix}{id}")]
    } else {
        // Limit streamed listing before accumulating paths. This is an observed
        // inventory, never proof that the latest snapshot has not been omitted.
        use futures_util::TryStreamExt;
        let mut lister = operator
            .lister(&prefix)
            .await
            .map_err(|_| anyhow::anyhow!("snapshot listing failed"))?;
        let mut paths = vec![];
        let mut visited = 0usize;
        while let Some(entry) = lister
            .try_next()
            .await
            .map_err(|_| anyhow::anyhow!("snapshot listing failed"))?
        {
            visited += 1;
            ensure!(
                visited <= 10000,
                "remote inventory exceeds 10000 entries; select --snapshot"
            );
            if entry.metadata().is_dir() {
                continue;
            }
            ensure!(
                paths.len() < 10000,
                "remote inventory exceeds 10000 snapshots; select --snapshot"
            );
            paths.push(entry.path().to_owned());
        }
        paths
    };
    let mut count = 0;
    let mut total_bytes = 0u64;
    for remote_path in paths {
        let id = remote_path
            .strip_prefix(&prefix)
            .context("invalid remote path")?;
        ensure!(
            id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid remote snapshot identifier"
        );
        let bytes = remote_read(operator, &remote_path, 64 * 1024 * 1024)
            .await
            .map_err(|_| anyhow::anyhow!("snapshot download failed"))?
            .to_vec();
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "snapshot exceeds size limit"
        );
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .context("recovery size overflow")?;
        ensure!(
            total_bytes <= 4 * 1024 * 1024 * 1024,
            "recovery exceeds 4 GiB cap; select a snapshot"
        );
        crate::repository::durable_write(&repo.root().join("snapshots").join(id), &bytes)?;
        let manifest = repo
            .manifest(id)
            .context("damaged remote snapshot; retry with --snapshot for an unaffected snapshot")?;
        ensure!(
            manifest.bytes <= 1024 * 1024 * 1024,
            "remote snapshot exceeds 1 GiB recovery cap"
        );
        for chunk in repo.snapshot_chunks(&manifest)? {
            let path = repo.root().join("chunks").join(&chunk);
            if path.exists() {
                continue;
            }
            let data = remote_read(
                operator,
                &format!("{namespace}/chunks/{chunk}"),
                8 * 1024 * 1024 + 40,
            )
            .await
            .map_err(|_| anyhow::anyhow!("chunk download failed"))?
            .to_vec();
            ensure!(
                data.len() <= 8 * 1024 * 1024 + 40,
                "chunk exceeds size limit"
            );
            total_bytes = total_bytes
                .checked_add(data.len() as u64)
                .context("recovery size overflow")?;
            ensure!(
                total_bytes <= 4 * 1024 * 1024 * 1024,
                "recovery exceeds 4 GiB cap; select a snapshot"
            );
            crate::repository::durable_write(&path, &data)?;
        }
        repo.verify(id)?;
        count += 1;
    }
    ensure!(count > 0, "remote repository contains no snapshots");
    drop(repo);
    publish_recovery(staging.path(), destination)?;
    cap_std::fs::Dir::open_ambient_dir(parent, cap_std::ambient_authority())?
        .into_std_file()
        .sync_all()?;
    Ok(count)
}

/// Publish the verified directory atomically without replacing an existing path.
pub(crate) fn publish_recovery(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
        let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result =
            unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        fs::rename(source, destination)?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (source, destination);
        bail!("atomic no-clobber directory publication unavailable on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_secrets_plain_http_and_unproven_lock() {
        let mut config = StorageConfig {
            service: "s3".into(),
            options: BTreeMap::new(),
            credential_env: BTreeMap::new(),
            immutable: true,
        };
        assert!(config.operator().is_err());
        config.immutable = false;
        config
            .options
            .insert("secret_access_key".into(), "fixture".into());
        assert!(config.operator().is_err());
        config.options.clear();
        config
            .options
            .insert("endpoint".into(), "http://example.com".into());
        assert!(config.operator().is_err());
    }
    #[test]
    fn encrypted_replication_and_recovery_round_trip() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let root = tempfile::tempdir().unwrap();
            let work = root.path().join("workspace");
            fs::create_dir(&work).unwrap();
            fs::write(work.join("hello.txt"), "hello").unwrap();
            let repo = crate::repository::Repository::init(
                &root.path().join("repo"),
                "fixture-passphrase-only",
            )
            .unwrap();
            let snapshot = repo
                .snapshot(
                    &work,
                    &crate::policy::Policy::default(),
                    None,
                    None,
                    "manual",
                )
                .unwrap();
            let operator = Operator::new(opendal::services::Memory::default()).unwrap();
            replicate(&repo, &operator).await.unwrap();
            replicate(&repo, &operator).await.unwrap();
            let namespace = blake3::hash(&fs::read(repo.root().join("repository.json")).unwrap())
                .to_hex()
                .to_string();
            let recovered = root.path().join("recovered");
            recover(&operator, &namespace, &recovered, "fixture-passphrase-only")
                .await
                .unwrap();
            let recovered =
                crate::repository::Repository::open(&recovered, "fixture-passphrase-only").unwrap();
            recovered.verify(&snapshot.id).unwrap();
        });
    }
    #[test]
    fn recovery_publication_never_clobbers_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join("fixture"), "new").unwrap();
        // This simulates the destination appearing after recover's initial check.
        assert!(publish_recovery(&source, &target).is_err());
        assert!(source.join("fixture").exists());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }
    #[test]
    fn selected_snapshot_isolates_damaged_local_and_remote_manifests() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let root = tempfile::tempdir().unwrap();
            let work = root.path().join("work");
            fs::create_dir(&work).unwrap();
            fs::write(work.join("a"), "fixture").unwrap();
            let repo = crate::repository::Repository::init(
                &root.path().join("repo"),
                "fixture-passphrase-only",
            )
            .unwrap();
            let snapshot = repo
                .snapshot(&work, &crate::policy::Policy::default(), None, None, "test")
                .unwrap();
            fs::write(
                repo.root().join("snapshots").join("a".repeat(64)),
                "damaged fixture",
            )
            .unwrap();
            let operator = Operator::new(opendal::services::Memory::default()).unwrap();
            assert!(replicate(&repo, &operator).await.is_err());
            replicate_selected(&repo, &operator, Some(&snapshot.id))
                .await
                .unwrap();
            let namespace = blake3::hash(&repo.encrypted_object("repository.json").unwrap())
                .to_hex()
                .to_string();
            operator
                .write(
                    &format!("{namespace}/snapshots/{}", "a".repeat(64)),
                    "damaged fixture",
                )
                .await
                .unwrap();
            let destination = root.path().join("recovered");
            assert!(recover(
                &operator,
                &namespace,
                &destination,
                "fixture-passphrase-only"
            )
            .await
            .is_err());
            assert!(!destination.exists());
            assert_eq!(
                recover_selected(
                    &operator,
                    &namespace,
                    &destination,
                    "fixture-passphrase-only",
                    Some(&snapshot.id)
                )
                .await
                .unwrap(),
                1
            );
            let recovered =
                crate::repository::Repository::open(&destination, "fixture-passphrase-only")
                    .unwrap();
            recovered.verify(&snapshot.id).unwrap();
            assert!(recover_selected(
                &operator,
                &namespace,
                &destination,
                "fixture-passphrase-only",
                Some(&snapshot.id)
            )
            .await
            .is_err());
            assert!(recover_selected(
                &operator,
                &namespace,
                &root.path().join("missing"),
                "fixture-passphrase-only",
                Some(&"b".repeat(64))
            )
            .await
            .is_err());
        });
    }
    #[test]
    fn replication_does_not_overwrite_conflicting_remote_objects() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let operator = Operator::new(opendal::services::Memory::default()).unwrap();
            operator.write("fixture", "existing").await.unwrap();
            assert!(copy_verified(&operator, "fixture", b"different".to_vec())
                .await
                .is_err());
            assert_eq!(
                operator.read("fixture").await.unwrap().to_vec(),
                b"existing"
            );
        });
    }
    #[derive(Clone)]
    struct CaptureTransport(std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>);
    impl opendal::HttpTransport for CaptureTransport {
        async fn fetch(
            &self,
            request: http::Request<opendal::Buffer>,
        ) -> opendal::Result<http::Response<opendal::HttpBody>> {
            let authorization = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            self.0
                .lock()
                .unwrap()
                .push((request.uri().to_string(), authorization));
            // Never contact a service; stop after observing the signed request.
            Err(opendal::Error::new(
                opendal::ErrorKind::PermissionDenied,
                "fixture transport refuses network",
            ))
        }
    }
    #[test]
    fn static_credentials_ignore_ambient_providers_and_endpoints() {
        // Environment tests run in an isolated process to avoid racing other
        // tests or consulting the developer's actual cloud credentials.
        if std::env::var("BUNKER_STATIC_CHAIN_TEST").ok().as_deref() != Some("1") {
            let fixture = tempfile::tempdir().unwrap();
            let ambient = fixture.path().join("ambient-fixture");
            fs::write(&ambient, "invalid fixture certificate and credential file").unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "storage::tests::static_credentials_ignore_ambient_providers_and_endpoints",
                    "--nocapture",
                ])
                .env_clear()
                .env("BUNKER_STATIC_CHAIN_TEST", "1")
                .env("BUNKER_FIXTURE_ACCESS", "fixture-explicit-access")
                .env("BUNKER_FIXTURE_SECRET", "fixture-explicit-secret")
                .env("BUNKER_FIXTURE_AZURE", "Zml4dHVyZS1leHBsaWNpdC1rZXk=")
                .env(
                    "BUNKER_FIXTURE_SAS",
                    "sv=2023-11-03&sig=fixture-explicit-sas",
                )
                .env("AWS_ENDPOINT_URL", "http://ambient.invalid")
                .env("AWS_ENDPOINT", "http://ambient.invalid")
                .env("AWS_S3_ENDPOINT", "http://ambient.invalid")
                .env("AWS_REGION", "ambient-region")
                .env("AWS_DEFAULT_REGION", "ambient-region")
                .env("AWS_ACCESS_KEY_ID", "fixture-ambient-access")
                .env("AWS_SECRET_ACCESS_KEY", "fixture-ambient-secret")
                .env("AWS_CONFIG_FILE", &ambient)
                .env("AWS_SHARED_CREDENTIALS_FILE", &ambient)
                .env("AWS_WEB_IDENTITY_TOKEN_FILE", &ambient)
                .env(
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                    "http://ambient.invalid",
                )
                .env("AZURE_STORAGE_ACCOUNT_NAME", "ambientaccount")
                .env("AZURE_STORAGE_ACCOUNT_KEY", "Zml4dHVyZS1hbWJpZW50LWtleQ==")
                .env("AZURE_TENANT_ID", "fixture-ambient-tenant")
                .env("AZURE_CLIENT_ID", "fixture-ambient-client")
                .env("AZURE_CLIENT_CERTIFICATE_PATH", &ambient)
                .env("AZURE_FEDERATED_TOKEN_FILE", &ambient)
                .env("AZURE_IMDS_ENDPOINT", "http://ambient.invalid")
                .env("AZBLOB_ENDPOINT", "http://ambient.invalid")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let captured = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
            let transport = opendal::HttpTransporter::new(CaptureTransport(captured.clone()));
            let context = opendal::OperationContext::new().with_http_transport(transport);
            let mut s3 = StorageConfig {
                service: "s3".into(),
                immutable: false,
                options: [
                    ("bucket", "fixturebucket"),
                    ("region", "us-east-1"),
                    ("endpoint", "https://explicit.invalid"),
                ]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
                credential_env: [
                    ("access_key_id", "BUNKER_FIXTURE_ACCESS"),
                    ("secret_access_key", "BUNKER_FIXTURE_SECRET"),
                ]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            };
            let operator = s3.operator().unwrap().with_context(context.clone());
            assert!(operator.stat("fixture").await.is_err());
            let requests = captured.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].0.starts_with("https://explicit.invalid/"));
            assert!(requests[0]
                .1
                .contains("Credential=fixture-explicit-access/"));
            assert!(requests[0].1.contains("/us-east-1/s3/"));
            assert!(!requests[0].1.contains("ambient"));
            s3.credential_env.remove("secret_access_key");
            assert!(s3.operator().is_err());
            s3.credential_env
                .insert("secret_access_key".into(), "BUNKER_FIXTURE_SECRET".into());
            let endpoint = s3.options.remove("endpoint").unwrap();
            assert!(s3.operator().is_err()); // Ambient HTTP endpoint is never accepted.
            s3.options.insert("endpoint".into(), endpoint);
            s3.options.remove("region");
            assert!(s3.operator().is_err());

            let mut azure = StorageConfig {
                service: "azure".into(),
                immutable: false,
                options: [
                    ("container", "fixturecontainer"),
                    ("account_name", "fixtureaccount"),
                    ("endpoint", "https://explicit.blob.core.windows.net"),
                ]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
                credential_env: [("account_key", "BUNKER_FIXTURE_AZURE")]
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            };
            captured.lock().unwrap().clear();
            assert!(azure
                .operator()
                .unwrap()
                .with_context(context.clone())
                .stat("fixture")
                .await
                .is_err());
            let requests = captured.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            assert!(requests[0]
                .0
                .starts_with("https://explicit.blob.core.windows.net/"));
            assert!(requests[0].1.starts_with("SharedKey fixtureaccount:"));
            azure.options.remove("account_name");
            assert!(azure.operator().is_err());
            azure.credential_env.clear();
            assert!(azure.operator().is_err()); // No ambient key/certificate fallback.
            azure
                .credential_env
                .insert("sas_token".into(), "BUNKER_FIXTURE_SAS".into());
            captured.lock().unwrap().clear();
            assert!(azure
                .operator()
                .unwrap()
                .with_context(context)
                .stat("fixture")
                .await
                .is_err());
            let requests = captured.lock().unwrap().clone();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].0.contains("sig=fixture-explicit-sas"));
            assert!(requests[0].1.is_empty());
        });
    }
}
