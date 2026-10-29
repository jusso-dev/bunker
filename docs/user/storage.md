# Storage backends

Snapshots are created in a local encrypted repository. `replicate` copies authenticated encrypted objects through OpenDAL; `recover` downloads them into a new local repository. This is not a direct remote snapshot repository. There is no remote-delete API. Explicit S3/Azure protected replication verifies version retention and can publish a second independent copy; the authenticated host can enforce supported storage/DR policies through its explicit [storage adapter](../host-storage.md) before reporting snapshot success. Managed key wrapping is described in [key management](../key-management.md).

Storage TOML has `service`, non-secret `[options]`, credential environment-variable names under `[credential_env]`, and optional `immutable` (requires the protected workflow below when true). Supported service names are `local`, `s3`, `r2`, and `azure`. Google Drive and OneDrive use a separate exact-ID adapter and require private OAuth/evidence state plus an external recovery report. Provider options are allowlisted; endpoints must use HTTPS without user-info or query strings. Supply credentials through your secret manager without echoing values.

## Local disk or NAS

```toml
service = "local"
immutable = false
[options]
root = "/absolute/path/to/secondary-copy"
```

Use an existing, accessible absolute root. A NAS path uses the operating system's mounted filesystem; permission, rename/locking semantics, disconnection recovery and latency must be tested on your actual NAS. A second directory on the same disk is not disaster recovery.

```sh
bunker replicate --repo "$BUNKER_REPOSITORY" --storage storage.toml
bunker recover --repo "$RECOVERED_REPOSITORY" --storage storage.toml --namespace "$REPOSITORY_NAMESPACE"
```

Keep the complete `namespace` returned by replication **outside the backup backend** with your recovery records. It is a `repository:header:checkpoint` locator, pinning a versioned key envelope and an encrypted, sequenced inventory. Recovery verifies the chain and reads the exact inventory rather than trusting a remote listing; missing snapshots or chain entries fail recovery. A selected `--snapshot ID` must appear in that pinned inventory.

The recovery destination must not exist. Rewrapping publishes a new header and locator on the next replication, while existing remote chunks retain their stable namespace. Old locators still require their old passphrase/provider. Save the latest locator independently: a backend cannot prove that it has not withheld a newer checkpoint from someone who only has an old locator. Current limits are 10,000 snapshots, 10,000 checkpoint links/64 MiB checkpoint history, and 4 GiB per recovery; select a snapshot to reduce recovery volume.

## AWS S3

Use `service = "s3"`. Set an explicit HTTPS `options.endpoint`, `options.bucket`, `options.region` (for example `ap-southeast-2`) and a dedicated `options.root` prefix. Map `credential_env.access_key_id`, `credential_env.secret_access_key`, and, for temporary credentials, `credential_env.session_token` to environment-variable names supplied by your credential manager. Restrict identity permissions to the designated prefix and the required read/list/write operations; do not grant backup deletion to the agent. Provider permission policies require live testing.

## Cloudflare R2

Use `service = "r2"`, `options.bucket`, `options.region = "auto"`, and the account's HTTPS S3-compatible `options.endpoint`. Map access-key fields through `credential_env`. Account endpoint identifiers are not credentials, but avoid publishing tenant details. Location hints do not establish Australian-only storage; see [residency](../compliance/residency.md).

## Azure Blob

Use `service = "azure"`, `options.container`, `options.account_name`, and the account's HTTPS blob `options.endpoint`. Supply `account_key` or `sas_token` through `credential_env`, with the smallest required scope and lifetime. Repository key wrapping can use Azure Key Vault independently of Blob credentials. The protected adapter requires account-key authorization and version-level locked immutability; ordinary replication also supports SAS.

## Google Drive and OneDrive

These providers use verified exact file/revision IDs, not name-based OpenDAL listing. Configure an explicit folder ID in `options.root`, OneDrive `options.drive_id`, and exactly three credential environment-variable names: `client_id`, `client_secret`, and `refresh_token`. Obtain consent/initial refresh credentials through the provider's approved OAuth process; Bunker does not open an interactive authorization browser.

```sh
bunker replicate --repo "$BUNKER_REPOSITORY" --storage drive.toml --consumer-state /protected/drive-state --report /protected/recovery/drive.json
bunker recover --repo "$RECOVERED_REPOSITORY" --storage drive.toml --consumer-state /protected/drive-state --consumer-report /protected/recovery/drive.json --namespace "$REPOSITORY_NAMESPACE"
```

Use one canonical owner-only state directory per provider/folder/client. The CLI holds an exclusive lock and atomically persists refresh-token rotations before using the new credential; saved rotations take precedence over an old environment token. Preserve this private state through upgrades and keep it outside captured workspaces/repositories. Invalid, linked or permissive credential files fail closed. Windows ACL support is not implemented.

Before requesting a refresh, the state directory durably records an in-progress
marker. A lost or ambiguous response therefore blocks reuse of the old token even
after restart. Obtain a replacement through your provider's authorized consent
flow, place it in the configured environment reference, then run
`consumer-rebind --storage drive.toml --consumer-state /protected/drive-state`.
Rebinding rejects the same attempted token. Do not delete the marker to retry an
uncertain credential. Failures saving a known rotation or clearing its marker are
retried locally before another network operation.

The complete report is saved privately before advancing the local checkpoint and then exported to the required external destination. If export fails, use `consumer-report CHECKPOINT_HASH --storage drive.toml --consumer-state /protected/drive-state --output PATH` to re-export it. Keep that report independently of the cloud account. Google recovery pins retained binary revisions; OneDrive requires the saved item ETag/cTag to remain unchanged and refuses altered items. Neither service provides a Bunker WORM/retention guarantee. See [consumer provider protocol](../consumer-storage.md) for exact limits and OAuth recovery failures. Offline fixtures pass; live account behavior still needs acceptance testing.

Cloud services are wired through OpenDAL but provider smoke tests have not been run in this task. Not every allowlisted provider field is valid for every service. Rejection or successful operator construction is not proof that credentials, data residency, retention or recovery work. Keep remote-backend acceptance open until live upload/readback/recovery and failure-mode evidence exists.


## Protected versions and independent DR

Set `immutable = true` in an S3 or Azure configuration. Provision versioning and
provider immutability separately; Bunker does not create buckets, enable account
features, shorten retention, bypass governance, or delete remote objects.

```sh
bunker replicate --repo "$BUNKER_REPOSITORY" --storage primary.toml --dr-storage dr.toml --retain-days 30 --report /protected/recovery/report.json
bunker recover --repo "$RECOVERED_REPOSITORY" --storage dr.toml --namespace "$REPOSITORY_NAMESPACE" --protection-report /protected/recovery/report.json
```

`--dr-storage` is optional. When supplied, both backends must have distinct backing
bucket/container identities and credential identities. One encrypted checkpoint
and inventory goes to both; success requires verified exact-version bytes and
retention on every object in both stores. A second endpoint or prefix on the same
bucket does not establish independence. Separate administrative/failure domains
remain an operator responsibility.

The report destination must be new and outside the local repository. Preserve the
entire report independently of both storage accounts: versions can remain locked
while a delete marker hides the latest name. Recovery uses the saved versions,
checks ciphertext and the authenticated checkpoint, and can still read existing
versions after the retention period ends. Such recovery makes no current-retention
claim. An encrypted local report is retained under `checkpoints/reports/` before
external export; failure to export returns an error, not protected-replication
success. Re-export that local fallback with `protection-report CHECKPOINT_HASH
--output PATH` (use the final component of the locator). Provider fixtures are tested; live accounts and adversarial permission
settings still require validation. See [provider boundary](../immutable-storage.md).
R2 has no implemented verified-retention adapter.

## Escrow and legacy recovery

`recover --escrow /protected/escrow.json` uses the separately held
`BUNKER_RECOVERY_KEY` instead of KMS or the original passphrase. After recovery,
run `escrow-unlock` to rewrap the key for normal operation. Never put recovery-key
values in command arguments or logs.

Old single-hash unindexed backups require explicit `recover --legacy-unindexed`.
That mode cannot prove listing completeness or freshness. New protected reports
cannot be combined with legacy mode; retain the stronger pinned workflow for new
copies.
