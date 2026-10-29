# Host-side key management

`crates/bunker-keys` implements asymmetric envelope wrapping for AWS KMS, Azure Key Vault, and GCP Cloud KMS, plus authenticated offline escrow. The repository, CLI, daemon and MCP accept an explicit `--key-config` file. Live provider validation remains required before issue #15 is accepted.

The host generates a random 256-bit repository data key. It obtains a pinned provider key-version's RSA public key and uses AWS-LC RSA-OAEP with SHA-256 locally. No plaintext data key is sent to a remote encrypt/wrap API or the control plane. Recovery sends the wrapped ciphertext to the provider's decrypt endpoint over verified TLS; the provider returns the data key to the host. The KMS necessarily performs the private-key operation inside its trust boundary.

Supported keys are RSA 2048–4096-bit encryption keys. AWS requires a concrete key ARN, Azure a complete versioned Key Vault URL, and GCP a `cryptoKeyVersions` resource. Provider identity and a digest of the public key are bound to the wrapped-key envelope and checked before recovery. Aliases or automatic key-version changes are not accepted. GCP requests/responses check the provider's CRC32C integrity fields.

AWS credentials are constructed exclusively from named environment references, with no profile, SSO, metadata, or credential-process discovery. Azure/GCP use explicit bearer-token environment references, a bounded HTTPS-only client, and no redirects. Provider errors deliberately omit response bodies and credential values. Long-lived credential issuance, refresh, key creation, IAM grants, and provider key deletion are outside this library.

Rewrapping decrypts the small envelope with the old provider, then wraps the same data key under the new provider locally. It does not reupload file chunks or invalidate an existing old envelope. Revocation and availability of old keys/copies require a separate operational policy.

Offline escrow encrypts the data key with a separate 256-bit recovery key using XChaCha20-Poly1305 and binds it to a repository identity. Store that recovery key in independently protected offline custody. The library never prints it, and offers no automatic escrow service or threshold-sharing claim. Loss of both provider access and recovery custody remains unrecoverable.

The tests exercise actual RSA-OAEP round trips with disposable keys, provider/key substitution rejection, tamper rejection, rewrapping, and escrow recovery/failures. They do not contact real KMS accounts. Live IAM, disabled/deleted key behavior, rate limits, audit logs, regional custody, remain separate acceptance checks. Local repository integration tests verify ciphertext preservation, legacy upgrade, escrow identity binding, and pinned remote recovery. The AWS SDK is configured with its modern HTTPS client rather than its legacy TLS feature; audit the final resolved dependency graph after integration.

## Repository and CLI integration

New repositories use authenticated v2 key headers; v1 passphrase headers remain readable and upgrade on rewrap. Snapshot/chunk format is unchanged. A header contains either a passphrase envelope or a managed envelope, never a silent passphrase fallback. The supplied provider configuration must match the envelope's provider/key binding; configuration is not inferred from backup data.

Example non-secret Azure key configuration (supply the token through your secret manager):

```toml
provider = "azure"
key_url = "https://YOUR-VAULT.vault.azure.net/keys/YOUR-KEY/PINNED-32-HEX-VERSION"
token_env = "BUNKER_AZURE_KEY_TOKEN"
```

AWS uses `provider = "aws"`, `region`, `key_arn`, `access_key_env`, `secret_key_env`, and optional `session_token_env`. GCP uses `provider = "gcp"`, `key_version`, and `token_env`.

```sh
bunker --repo "$BUNKER_REPOSITORY" --key-config keys.toml init
bunker --repo "$BUNKER_REPOSITORY" --key-config keys.toml snapshot --workspace "$WORKSPACE"
bunker --repo "$BUNKER_REPOSITORY" --key-config keys.toml rewrap-key --new-key-config next-keys.toml
```

`rewrap-passphrase` replaces the wrapper using `BUNKER_NEW_PASSPHRASE`; `rewrap-key` replaces it using another managed provider configuration. These operations preserve the data key and stable remote chunk namespace. Old wrappers still grant access to that data key. This is wrapping-key migration, not data-key revocation.

`escrow --output PATH` writes an owner-only encrypted recovery envelope without overwriting a file. `BUNKER_RECOVERY_KEY` must contain 32 independently generated random bytes encoded as 64 hex digits, supplied privately through a secret manager. Keep the envelope and recovery key in separate protected custody. `escrow-unlock --input PATH` unlocks with that recovery key and installs the wrapper selected by `--key-config` or `BUNKER_PASSPHRASE`. No plaintext key is printed. Upgrade a legacy header with a rewrap before exporting escrow.

The remote recovery locator pins repository identity, key-envelope ciphertext and an encrypted inventory checkpoint. Save each returned locator outside the storage backend. Rewrap and replicate to publish a new locator; old locators keep their old key requirements. Neither a repository nor its untrusted remote store can prove that a newer locator has not been withheld from an operator who only has an older one.
