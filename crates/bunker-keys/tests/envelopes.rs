use anyhow::Result;
use async_trait::async_trait;
use aws_lc_rs::{
    encoding::{AsDer, PublicKeyX509Der},
    rsa::{KeySize, OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA256_MGF1SHA256},
};
use bunker_keys::{
    escrow, generate_data_key, recover_escrow, rewrap, unwrap, wrap, DataKey, KeyProvider,
    ProviderConfig,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Provider {
    id: String,
    private: OaepPrivateDecryptingKey,
    public: Vec<u8>,
    decrypt_calls: AtomicUsize,
}
impl Provider {
    fn new(id: &str) -> Self {
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let der: PublicKeyX509Der<'static> = private.public_key().as_der().unwrap();
        Self {
            id: id.into(),
            private: OaepPrivateDecryptingKey::new(private).unwrap(),
            public: der.as_ref().to_vec(),
            decrypt_calls: AtomicUsize::new(0),
        }
    }
}
#[async_trait]
impl KeyProvider for Provider {
    fn provider(&self) -> &'static str {
        "fixture-kms"
    }
    fn key_id(&self) -> &str {
        &self.id
    }
    async fn public_key_der(&self) -> Result<Vec<u8>> {
        Ok(self.public.clone())
    }
    async fn decrypt_ciphertext(&self, ciphertext: &[u8]) -> Result<DataKey> {
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        let mut output = zeroize::Zeroizing::new(vec![0; self.private.min_output_size()]);
        let plaintext = self
            .private
            .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut output, None)
            .map_err(|_| anyhow::anyhow!("fixture decrypt failed"))?;
        DataKey::from_bytes(plaintext)
    }
}
#[tokio::test]
async fn local_wrapping_and_provider_rewrap_preserve_data_key() {
    let first = Provider::new("key-version-1");
    let second = Provider::new("key-version-2");
    let key = generate_data_key();
    let wrapped = wrap(&first, &key).await.unwrap();
    assert_eq!(first.decrypt_calls.load(Ordering::SeqCst), 0);
    assert!(!wrapped
        .ciphertext
        .windows(32)
        .any(|window| window == &key[..]));
    let recovered = unwrap(&first, &wrapped).await.unwrap();
    assert!(*recovered == *key);
    let changed = rewrap(&first, &second, &wrapped).await.unwrap();
    assert_eq!(changed.key_id, "key-version-2");
    assert!(*unwrap(&second, &changed).await.unwrap() == *key);
    assert!(unwrap(&first, &changed).await.is_err());
}
#[tokio::test]
async fn binding_tamper_and_key_substitution_are_rejected() {
    let provider = Provider::new("bound-key");
    let key = generate_data_key();
    let mut wrapped = wrap(&provider, &key).await.unwrap();
    wrapped.ciphertext[0] ^= 1;
    assert!(unwrap(&provider, &wrapped).await.is_err());
    let wrapped = wrap(&provider, &key).await.unwrap();
    let impostor = Provider::new("bound-key");
    assert!(unwrap(&impostor, &wrapped).await.is_err());
    assert_eq!(impostor.decrypt_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn offline_escrow_round_trip_and_failure_cases() {
    let key = generate_data_key();
    let recovery = generate_data_key();
    let mut envelope = escrow(&key, &recovery, "repository-1").unwrap();
    assert!(*recover_escrow(&envelope, &recovery, "repository-1").unwrap() == *key);
    assert!(recover_escrow(&envelope, &recovery, "repository-2").is_err());
    assert!(recover_escrow(&envelope, &generate_data_key(), "repository-1").is_err());
    envelope.ciphertext[3] ^= 1;
    assert!(recover_escrow(&envelope, &recovery, "repository-1").is_err());
    assert_eq!(format!("{key:?}"), "DataKey([REDACTED])");
}
#[test]
fn providers_reject_aliases_arbitrary_urls_and_incomplete_resource_names() {
    let azure = |url: &str| ProviderConfig::Azure {
        key_url: url.into(),
        token_env: "UNSET_FIXTURE_TOKEN".into(),
    };
    for url in [
        "http://vault.vault.azure.net/keys/key/version",
        "https://evil.example/keys/key/version",
        "https://vault.vault.azure.net/keys/key",
        "https://user:password@vault.vault.azure.net/keys/key/01234567890123456789012345678901",
    ] {
        assert!(azure(url).connect().is_err());
    }
    for key in [
        "projects/a/locations/b/keyRings/c/cryptoKeys/d",
        "projects/a/locations/b/keyRings/c/cryptoKeys/d/cryptoKeyVersions/../",
    ] {
        assert!(ProviderConfig::Gcp {
            key_version: key.into(),
            token_env: "UNSET_FIXTURE_TOKEN".into()
        }
        .connect()
        .is_err());
    }
    assert!(ProviderConfig::Aws {
        region: "ap-southeast-2".into(),
        key_arn: "alias/not-pinned".into(),
        access_key_env: "UNSET_FIXTURE_ACCESS".into(),
        secret_key_env: "UNSET_FIXTURE_SECRET".into(),
        session_token_env: None
    }
    .connect()
    .is_err());
}
