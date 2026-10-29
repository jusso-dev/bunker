//! Host-side asymmetric KMS wrapping: plaintext data keys are never sent to a
//! provider's encrypt/wrap API or to the control plane. Providers hold the RSA
//! private key and receive ciphertext only during recovery.
use anyhow::{anyhow, ensure, Context, Result};
use async_trait::async_trait;
use aws_lc_rs::{
    encoding::{AsDer, PublicKeyX509Der},
    rsa::{
        OaepPublicEncryptingKey, PublicEncryptingKey, PublicKeyComponents, OAEP_SHA256_MGF1SHA256,
    },
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use zeroize::Zeroizing;

pub struct DataKey(Zeroizing<[u8; 32]>);
impl std::ops::Deref for DataKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}
impl DataKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == 32, "data key must contain 32 bytes");
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    pub version: u32,
    pub provider: String,
    pub key_id: String,
    pub public_key_digest: String,
    pub ciphertext: Vec<u8>,
}
impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKey")
            .field("version", &self.version)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    fn provider(&self) -> &'static str;
    fn key_id(&self) -> &str;
    async fn public_key_der(&self) -> Result<Vec<u8>>;
    async fn decrypt_ciphertext(&self, ciphertext: &[u8]) -> Result<DataKey>;
}
pub fn generate_data_key() -> DataKey {
    let mut key = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(key.as_mut());
    DataKey(key)
}
pub async fn wrap(provider: &dyn KeyProvider, key: &[u8; 32]) -> Result<WrappedKey> {
    let der = provider.public_key_der().await?;
    let public =
        PublicEncryptingKey::from_der(&der).map_err(|_| anyhow!("invalid KMS RSA public key"))?;
    let public =
        OaepPublicEncryptingKey::new(public).map_err(|_| anyhow!("invalid RSA OAEP key"))?;
    ensure!(
        (2048..=4096).contains(&public.key_size_bits()),
        "KMS RSA key must be 2048..4096 bits"
    );
    let mut ciphertext = vec![0; public.ciphertext_size()];
    public
        .encrypt(&OAEP_SHA256_MGF1SHA256, key, &mut ciphertext, None)
        .map_err(|_| anyhow!("local data-key wrapping failed"))?;
    Ok(WrappedKey {
        version: 1,
        provider: provider.provider().into(),
        key_id: provider.key_id().into(),
        public_key_digest: blake3::hash(&der).to_hex().to_string(),
        ciphertext,
    })
}
pub async fn unwrap(provider: &dyn KeyProvider, envelope: &WrappedKey) -> Result<DataKey> {
    ensure!(
        envelope.version == 1
            && envelope.provider == provider.provider()
            && envelope.key_id == provider.key_id(),
        "key provider or version binding mismatch"
    );
    ensure!(
        (256..=512).contains(&envelope.ciphertext.len()),
        "invalid wrapped-key length"
    );
    let der = provider.public_key_der().await?;
    ensure!(
        blake3::hash(&der).to_hex().as_str() == envelope.public_key_digest,
        "KMS public key changed; refusing an unbound recovery"
    );
    provider.decrypt_ciphertext(&envelope.ciphertext).await
}
pub async fn rewrap(
    old: &dyn KeyProvider,
    new: &dyn KeyProvider,
    envelope: &WrappedKey,
) -> Result<WrappedKey> {
    let key = unwrap(old, envelope).await?;
    wrap(new, &key).await
}
fn key_from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<DataKey> {
    ensure!(bytes.len() == 32, "KMS returned invalid data-key length");
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(DataKey(key))
}
fn take_secret(value: &mut Value, field: &str) -> Result<Zeroizing<String>> {
    match value[field].take() {
        Value::String(text) => Ok(Zeroizing::new(text)),
        _ => Err(anyhow!("KMS response is missing key material")),
    }
}
fn env_secret(name: &str) -> Result<Zeroizing<String>> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
        "invalid credential environment variable name"
    );
    let value = Zeroizing::new(
        std::env::var(name)
            .map_err(|_| anyhow!("required KMS credential environment variable is not set"))?,
    );
    ensure!(!value.is_empty(), "empty KMS credential");
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    Aws {
        region: String,
        key_arn: String,
        access_key_env: String,
        secret_key_env: String,
        session_token_env: Option<String>,
    },
    Azure {
        key_url: String,
        token_env: String,
    },
    Gcp {
        key_version: String,
        token_env: String,
    },
}
impl ProviderConfig {
    pub fn connect(&self) -> Result<Box<dyn KeyProvider>> {
        match self {
            Self::Aws {
                region,
                key_arn,
                access_key_env,
                secret_key_env,
                session_token_env,
            } => {
                let parts: Vec<_> = key_arn.split(':').collect();
                ensure!(
                    parts.len() == 6
                        && parts[0] == "arn"
                        && ["aws", "aws-us-gov", "aws-cn"].contains(&parts[1])
                        && parts[2] == "kms"
                        && parts[3] == region
                        && parts[4].len() == 12
                        && parts[4].bytes().all(|b| b.is_ascii_digit())
                        && parts[5].starts_with("key/")
                        && !parts[5].contains(char::is_whitespace),
                    "use an explicit KMS key ARN in the configured region, not an alias"
                );
                ensure!(
                    region
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                    "invalid AWS region"
                );
                let access = env_secret(access_key_env)?;
                let secret = env_secret(secret_key_env)?;
                let session = session_token_env.as_deref().map(env_secret).transpose()?;
                let credentials = aws_sdk_kms::config::Credentials::new(
                    access.as_str(),
                    secret.as_str(),
                    session.as_ref().map(|s| s.to_string()),
                    None,
                    "bunker-explicit",
                );
                let config = aws_sdk_kms::config::Builder::new()
                    .behavior_version_latest()
                    .region(aws_sdk_kms::config::Region::new(region.clone()))
                    .credentials_provider(credentials)
                    .retry_config(
                        aws_sdk_kms::config::retry::RetryConfig::standard().with_max_attempts(3),
                    )
                    .timeout_config(
                        aws_sdk_kms::config::timeout::TimeoutConfig::builder()
                            .operation_timeout(Duration::from_secs(30))
                            .operation_attempt_timeout(Duration::from_secs(15))
                            .connect_timeout(Duration::from_secs(5))
                            .read_timeout(Duration::from_secs(15))
                            .build(),
                    )
                    .build();
                Ok(Box::new(Aws {
                    client: aws_sdk_kms::Client::from_conf(config),
                    id: key_arn.clone(),
                }))
            }
            Self::Azure { key_url, token_env } => {
                validate_azure_url(key_url)?;
                Ok(Box::new(Azure {
                    http: http_client()?,
                    id: key_url.clone(),
                    token_env: token_env.clone(),
                }))
            }
            Self::Gcp {
                key_version,
                token_env,
            } => {
                validate_gcp_version(key_version)?;
                Ok(Box::new(Gcp {
                    http: http_client()?,
                    id: key_version.clone(),
                    token_env: token_env.clone(),
                }))
            }
        }
    }
}
struct Aws {
    client: aws_sdk_kms::Client,
    id: String,
}
#[async_trait]
impl KeyProvider for Aws {
    fn provider(&self) -> &'static str {
        "aws"
    }
    fn key_id(&self) -> &str {
        &self.id
    }
    async fn public_key_der(&self) -> Result<Vec<u8>> {
        let result = self
            .client
            .get_public_key()
            .key_id(&self.id)
            .send()
            .await
            .map_err(|_| anyhow!("AWS KMS GetPublicKey failed"))?;
        ensure!(
            result.key_id.as_deref() == Some(self.id.as_str()),
            "AWS KMS key identity mismatch"
        );
        ensure!(
            result
                .encryption_algorithms()
                .contains(&aws_sdk_kms::types::EncryptionAlgorithmSpec::RsaesOaepSha256),
            "AWS key does not support RSAES_OAEP_SHA_256"
        );
        let bytes = result
            .public_key
            .context("AWS KMS returned no public key")?
            .into_inner();
        ensure!(bytes.len() <= 8192, "KMS public key exceeds limit");
        Ok(bytes)
    }
    async fn decrypt_ciphertext(&self, ciphertext: &[u8]) -> Result<DataKey> {
        let result = self
            .client
            .decrypt()
            .key_id(&self.id)
            .encryption_algorithm(aws_sdk_kms::types::EncryptionAlgorithmSpec::RsaesOaepSha256)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
            .send()
            .await
            .map_err(|_| anyhow!("AWS KMS Decrypt failed"))?;
        ensure!(
            result.key_id.as_deref() == Some(self.id.as_str()),
            "AWS KMS decrypted under an unexpected key"
        );
        key_from_bytes(Zeroizing::new(
            result
                .plaintext
                .context("AWS KMS returned no key")?
                .into_inner(),
        ))
    }
}
fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?)
}
async fn json_response(mut response: reqwest::Response) -> Result<Value> {
    ensure!(response.status().is_success(), "KMS request failed");
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("KMS response read failed"))?
    {
        ensure!(
            bytes.len() + chunk.len() <= 32768,
            "KMS response exceeds safety limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid KMS response"))
}
fn validate_azure_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).map_err(|_| anyhow!("invalid Azure key URL"))?;
    ensure!(
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|h| h.ends_with(".vault.azure.net"))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.port().is_none(),
        "use an HTTPS Azure Key Vault key-version URL"
    );
    let segments: Vec<_> = url.path().trim_start_matches('/').split('/').collect();
    ensure!(
        segments.len() == 3
            && segments[0] == "keys"
            && !segments[1].is_empty()
            && segments[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && segments[2].len() == 32
            && segments[2].bytes().all(|b| b.is_ascii_hexdigit()),
        "Azure key URL must pin a key version"
    );
    Ok(())
}
struct Azure {
    http: reqwest::Client,
    id: String,
    token_env: String,
}
#[async_trait]
impl KeyProvider for Azure {
    fn provider(&self) -> &'static str {
        "azure"
    }
    fn key_id(&self) -> &str {
        &self.id
    }
    async fn public_key_der(&self) -> Result<Vec<u8>> {
        let token = env_secret(&self.token_env)?;
        let value = json_response(
            self.http
                .get(format!("{}?api-version=7.4", self.id))
                .bearer_auth(token.as_str())
                .send()
                .await
                .map_err(|_| anyhow!("Azure public-key request failed"))?,
        )
        .await?;
        let key = &value["key"];
        ensure!(
            key["kid"].as_str() == Some(self.id.as_str())
                && matches!(key["kty"].as_str(), Some("RSA" | "RSA-HSM")),
            "Azure key identity or type mismatch"
        );
        let n = URL_SAFE_NO_PAD
            .decode(key["n"].as_str().context("missing RSA modulus")?)
            .map_err(|_| anyhow!("invalid RSA modulus"))?;
        let e = URL_SAFE_NO_PAD
            .decode(key["e"].as_str().context("missing RSA exponent")?)
            .map_err(|_| anyhow!("invalid RSA exponent"))?;
        ensure!(n.len() <= 512 && e.len() <= 8, "invalid RSA key dimensions");
        let components = PublicKeyComponents { n, e };
        let der: PublicKeyX509Der<'static> = components
            .as_der()
            .map_err(|_| anyhow!("invalid Azure RSA key"))?;
        Ok(der.as_ref().to_vec())
    }
    async fn decrypt_ciphertext(&self, ciphertext: &[u8]) -> Result<DataKey> {
        let token = env_secret(&self.token_env)?;
        let mut value = json_response(
            self.http
                .post(format!("{}/decrypt?api-version=7.4", self.id))
                .bearer_auth(token.as_str())
                .json(&json!({"alg":"RSA-OAEP-256","value":URL_SAFE_NO_PAD.encode(ciphertext)}))
                .send()
                .await
                .map_err(|_| anyhow!("Azure decrypt request failed"))?,
        )
        .await?;
        ensure!(
            value["kid"].as_str() == Some(self.id.as_str()),
            "Azure decrypted under unexpected key"
        );
        let encoded = take_secret(&mut value, "value")?;
        key_from_bytes(Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.as_str())
                .map_err(|_| anyhow!("invalid Azure key encoding"))?,
        ))
    }
}
fn validate_gcp_version(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split('/').collect();
    ensure!(
        parts.len() == 10
            && parts[0] == "projects"
            && parts[2] == "locations"
            && parts[4] == "keyRings"
            && parts[6] == "cryptoKeys"
            && parts[8] == "cryptoKeyVersions"
            && parts.iter().all(|p| !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
            && parts[9].bytes().all(|b| b.is_ascii_digit()),
        "GCP key must pin a complete cryptoKeyVersion resource name"
    );
    Ok(())
}
fn check_crc(bytes: &[u8], value: &Value) -> Result<()> {
    let expected = value
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .or_else(|| value.as_u64().and_then(|n| u32::try_from(n).ok()))
        .context("missing KMS CRC32C")?;
    ensure!(crc32c::crc32c(bytes) == expected, "KMS CRC32C mismatch");
    Ok(())
}
struct Gcp {
    http: reqwest::Client,
    id: String,
    token_env: String,
}
#[async_trait]
impl KeyProvider for Gcp {
    fn provider(&self) -> &'static str {
        "gcp"
    }
    fn key_id(&self) -> &str {
        &self.id
    }
    async fn public_key_der(&self) -> Result<Vec<u8>> {
        let token = env_secret(&self.token_env)?;
        let value = json_response(
            self.http
                .get(format!(
                    "https://cloudkms.googleapis.com/v1/{}/publicKey",
                    self.id
                ))
                .bearer_auth(token.as_str())
                .send()
                .await
                .map_err(|_| anyhow!("GCP public-key request failed"))?,
        )
        .await?;
        ensure!(
            value["name"].as_str() == Some(self.id.as_str())
                && matches!(
                    value["algorithm"].as_str(),
                    Some(
                        "RSA_DECRYPT_OAEP_2048_SHA256"
                            | "RSA_DECRYPT_OAEP_3072_SHA256"
                            | "RSA_DECRYPT_OAEP_4096_SHA256"
                    )
                ),
            "GCP key identity or algorithm mismatch"
        );
        let pem = value["pem"]
            .as_str()
            .context("GCP returned no PEM public key")?;
        check_crc(pem.as_bytes(), &value["pemCrc32c"])?;
        ensure!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----")
                && pem.trim_end().ends_with("-----END PUBLIC KEY-----"),
            "invalid GCP public-key PEM"
        );
        let payload: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        STANDARD
            .decode(payload)
            .map_err(|_| anyhow!("invalid GCP public-key encoding"))
    }
    async fn decrypt_ciphertext(&self, ciphertext: &[u8]) -> Result<DataKey> {
        let token = env_secret(&self.token_env)?;
        let mut value=json_response(self.http.post(format!("https://cloudkms.googleapis.com/v1/{}:asymmetricDecrypt",self.id)).bearer_auth(token.as_str()).json(&json!({"ciphertext":STANDARD.encode(ciphertext),"ciphertextCrc32c":crc32c::crc32c(ciphertext).to_string()})).send().await.map_err(|_|anyhow!("GCP decrypt request failed"))?).await?;
        ensure!(
            value["verifiedCiphertextCrc32c"] == true,
            "GCP did not verify ciphertext integrity"
        );
        let encoded = take_secret(&mut value, "plaintext")?;
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded.as_str())
                .map_err(|_| anyhow!("invalid GCP key encoding"))?,
        );
        check_crc(&bytes, &value["plaintextCrc32c"])?;
        key_from_bytes(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escrow {
    pub version: u32,
    pub repository_id: String,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
pub fn escrow(key: &[u8; 32], recovery_key: &[u8; 32], repository_id: &str) -> Result<Escrow> {
    ensure!(
        !repository_id.is_empty() && repository_id.len() <= 128,
        "invalid escrow repository identity"
    );
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let context = format!("bunker-escrow-v1:{repository_id}");
    let ciphertext = XChaCha20Poly1305::new(recovery_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("escrow encryption failed"))?;
    Ok(Escrow {
        version: 1,
        repository_id: repository_id.into(),
        nonce,
        ciphertext,
    })
}
pub fn recover_escrow(
    envelope: &Escrow,
    recovery_key: &[u8; 32],
    repository_id: &str,
) -> Result<DataKey> {
    ensure!(
        envelope.version == 1
            && envelope.repository_id == repository_id
            && envelope.ciphertext.len() == 48,
        "escrow identity or format mismatch"
    );
    let context = format!("bunker-escrow-v1:{repository_id}");
    let bytes = XChaCha20Poly1305::new(recovery_key.into())
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("escrow authentication failed"))?;
    key_from_bytes(Zeroizing::new(bytes))
}
