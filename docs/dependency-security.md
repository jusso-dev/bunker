# Dependency security: RUSTSEC-2023-0071 (`rsa`)

Status as of 29-10-2026: **removed from the resolved Bunker build, without an audit ignore**. The upstream advisory remains open. Bunker now carries a small, default-compatible feature patch in `vendor/reqsign-azure-storage`: certificate credentials and their `rsa`/JWT dependencies are optional, and both Bunker and OpenDAL disable that feature. The static-only credential chains remain enforced.

`cargo check --workspace`, four upstream static-provider unit tests with the certificate feature disabled, and the resolved dependency-tree check passed. `cargo audit --no-fetch` passed against 1,381 cached advisories after updating `webpki-root-certs` to 1.0.11 for RUSTSEC-2026-0383. No live cloud request was made. See patch provenance in repository file `vendor/reqsign-azure-storage/BUNKER-PATCH.md`. The analysis below records the original upstream dependency and why the patch is necessary.

## Original finding

```
cargo audit --no-fetch
Crate:     rsa
Version:   0.9.10
ID:        RUSTSEC-2023-0071   (Marvin Attack, CVSS 5.9)
Solution:  No fixed upgrade is available!
```

The advisory has `patched = []`. It states rsa 0.9.10 (latest stable) and 0.10.0-rc.18 are still affected. Its workaround is to avoid private-key operations where an attacker can observe timing.

## Dependency path

```
bunker  -> opendal 0.59.5 feature "services-azblob"
        -> opendal-service-azblob 0.59.5
        -> reqsign-azure-storage 3.3.0   (rsa: non-optional on non-wasm32; enables reqsign-core "jwt")
        -> reqsign-core 3.3.2 feature "jwt" -> rsa 0.9.10
```

- `reqsign-azure-storage` 3.3.0 has no Cargo features (`"features":{}`); `rsa` is a hard dependency under `cfg(not(target_arch = "wasm32"))`. 3.3.0 is the latest release on crates.io (`cargo info`, 29-10-2026).
- `opendal-service-azblob` already uses `default-features = false` on reqsign crates. No feature flag in Bunker or OpenDAL removes `rsa` while keeping Azure Blob.
- No other crate in the tree depends on `rsa`. S3/R2 (`reqsign-aws-v4`, `reqsign-aws-core`), Google Drive, OneDrive and fs do not.

Experiment (temporary copy of the workspace, not committed): removing `"services-azblob"` from the `opendal` features removes `rsa` from `cargo tree` and `cargo audit --no-fetch` reports no vulnerabilities. This confirms Azure Blob is the only source.

## RSA call sites

Only two places in the dependency tree use `rsa`:

1. `reqsign-core-3.3.2/src/jwt.rs`: `encode_rs256` performs an RS256 (PKCS#1 v1.5, SHA-256) **signature** with `RsaPrivateKey`.
2. `reqsign-azure-storage-3.3.0/src/provide_credential/client_certificate.rs`: `ClientCertificateCredentialProvider` loads a PEM private key and calls `encode_rs256` to build an Entra ID client assertion, then exchanges it for a bearer token.

No RSA decryption is used anywhere in the tree. The only private-key operation is signing.

## Reachability from `crates/bunker/src/storage.rs`

`StorageConfig::operator` builds operators with `Operator::via_iter(service, options)`. Bunker never passes certificate options (`allowed_credentials` has no tenant, certificate path or password key), so the certificate provider can only be reached through OpenDAL's implicit default chain.

`opendal-service-azblob` `AzblobBuilder::build` (backend.rs, around line 377):

1. Creates `Context::new().with_file_read(TokioFileRead).with_env(OsEnv)`. This reads the real process environment and filesystem. It sets no command executor.
2. Always appends `reqsign_azure_storage::DefaultCredentialProvider::new()`.
3. Places `StaticCredentialProvider` in front only when `sas_token` is set, or when both `account_key` and an account name are present (`account_name` option, or derived from a `*.core.windows.net`/gov/China endpoint).

`ProvideCredentialChain` returns the first `Ok(Some)` and **continues past both `Ok(None)` and `Err`** (reqsign-core `api.rs`, around line 482). Static providers always return `Ok(Some)`.

Result:

| Bunker Azure configuration | Ambient chain consulted | RSA private-key operation |
|---|---|---|
| `sas_token` via `credential_env` | No | Not reached |
| `account_key` plus account name (explicit, or derivable from endpoint) | No | Not reached |
| `account_key` without a derivable account name | Yes | Reachable |
| No `credential_env` | Yes | Reachable |

When the ambient chain runs, the default order is: env, Azure CLI, client certificate, client secret, Azure Pipelines, workload identity, IMDS. The client certificate provider signs only if `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_CERTIFICATE_PATH` are all set in the process environment **and** the earlier env provider found nothing (`AZURE_STORAGE_ACCOUNT_KEY`, `AZURE_STORAGE_SAS_TOKEN`, `AZURE_STORAGE_BEARER_TOKEN`). The Azure CLI provider fails, because no command executor is configured, and the chain moves on.

Supported, documented Bunker credentials (`docs/user/storage.md`: `account_key` or `sas_token`) do not perform RSA operations.

### Exposure when reached

The signing happens locally once per token. The client assertion goes to Entra ID over TLS. An attacker cannot make Bunker sign chosen inputs on demand, and the operation is not a decryption oracle. Network-observable timing is limited to the token request. This is low practical exposure, but the code is linked and reachable under the ambient conditions above.

## Ambient credential and configuration sources (beyond `credential_env`)

These come from OpenDAL/reqsign defaults. Bunker's options allowlist cannot turn them off.

**Azure Blob** (only when no static credential applies): environment variables `AZURE_STORAGE_ACCOUNT_NAME`, `AZURE_STORAGE_ACCOUNT_KEY`, `AZURE_STORAGE_SAS_TOKEN`, `AZURE_STORAGE_BEARER_TOKEN`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_AUTHORITY_HOST`, `AZURE_CLIENT_CERTIFICATE_PATH` (arbitrary file read), `AZURE_FEDERATED_TOKEN_FILE` (file read), `SYSTEM_ACCESSTOKEN`/`SYSTEM_OIDCREQUESTURI`/`ARM_*`, `AZURE_MSI_SECRET`, `AZURE_IMDS_ENDPOINT`, `AZBLOB_ENDPOINT`, `AZURE_OBJECT_ID`, `AZURE_MSI_RESOURCE_ID`; IMDS network endpoint.

**S3/R2** (`opendal-service-s3` backend.rs, around line 929–1020; reqsign-aws-core default chain): env, profile, SSO, web identity, process, ECS, IMDSv2. With explicit `access_key_id` and `secret_access_key`, the static provider is in front and returns first. Without them, the chain reads `~/.aws/config`, `~/.aws/credentials`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`, `~/.aws/sso/cache/`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_*` and IMDS. `credential_process` is not executed because no command executor is configured. Independently of credentials:
- `region` falls back to `AWS_REGION`/`AWS_DEFAULT_REGION`.
- If `endpoint` is unset, `AWS_ENDPOINT_URL`, `AWS_ENDPOINT` or `AWS_S3_ENDPOINT` set the endpoint. **Bunker's HTTPS-only endpoint check does not see this value.**

**Google Drive, OneDrive, fs:** no ambient environment or credential-file reads found in the OpenDAL 0.59.5 service sources.

## Remediation options

| Option | Removes `rsa` from build | Keeps Azure | Notes |
|---|---|---|---|
| A. Pin static-only credential chains in Bunker | No | Yes | RSA becomes unreachable by construction. Audit still fails. |
| B. Upstream: make `rsa`/client-certificate optional in `reqsign-azure-storage` (default-on is fine, because azblob uses `default-features = false`) | Yes, once released and adopted by OpenDAL | Yes | Needs maintainer acceptance and an OpenDAL release. |
| C. `[patch.crates-io]` fork of `reqsign-azure-storage` without `client_certificate.rs` | Yes | Yes | Bunker carries a fork. Third-party source change. |
| D. Small Bunker-owned Azure Blob client (SAS or SharedKey HMAC; Put Blob with `If-None-Match: *`, Get, Head, List) and drop `services-azblob` | Yes | Yes | More code to own and test. |
| E. Drop Azure Blob | Yes | **No** | Azure Blob is a listed requirement (`docs/requirements.md`). Not acceptable. |

### Recommended bounded fix

1. **Now (option A):** In `StorageConfig::operator`, build `s3` and `azblob` operators with typed builders (`opendal::services::S3`, `opendal::services::Azblob`) and call `credential_provider_chain(...)` with only a `StaticCredentialProvider`. Require a complete explicit credential set: S3/R2 needs `access_key_id` and `secret_access_key`. Azure needs `sas_token`, or `account_key` with an explicit `account_name`. For S3, also set `disable_config_load` and `disable_ec2_metadata`, and require an explicit `region`, so `AWS_*` endpoint and region variables are ignored. This needs `reqsign-core`, `reqsign-azure-storage` and `reqsign-aws-v4` as direct dependencies at the versions in `Cargo.lock`, to name the provider types. Add tests: an Azure config without explicit credentials is rejected, and an S3 config ignores `AWS_ENDPOINT_URL`.
2. **Then (option B):** Propose the feature gate upstream in `apache/opendal-reqsign`. When a release is adopted by OpenDAL, `rsa` drops out of Bunker's tree with no Bunker code change, and the audit can pass.
3. Use option C or D only if the audit must pass before upstream moves.

Do not add an `ignore` entry for RUSTSEC-2023-0071 unless it is a documented, reviewed risk acceptance that references this analysis.

## Residual risk

- Until option B, C or D lands, `rsa` 0.9.10 stays linked and `cargo audit` keeps failing. No patched `rsa` release exists.
- With option A, the RSA code is linked but unreachable from Bunker's operator construction. With explicit credentials, static providers already short-circuit the chain today.
- Without option A, an operator running Bunker with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_CERTIFICATE_PATH` in its environment, and an Azure config lacking static credentials, will sign with the vulnerable implementation. It will also authenticate with an identity Bunker's config never named.
- None of this was verified against live cloud services. The analysis is from source reading of the locked crate versions and local `cargo tree`/`cargo audit` runs.
