# Automatic host storage policy binding

The authenticated host service can bind a remote policy to an operator-configured
storage adapter. `storage`, `storageRef`, and `keyRef` must match the configured
provider, local reference labels, and open repository/key header. Labels alone do
not grant capabilities. The service replicates every queued snapshot after saving
the local work outbox and before posting snapshot success. A replication or report
custody error leaves that outbox available for retry and follows the host's backup
failure handling.

Without the optional host `storage` configuration, the existing local-only policy
validation and CLI workflows remain unchanged. No credentials, accounts, buckets,
folders, retention policies, or consent grants are provisioned automatically.

## Operator configuration

Add this table to the existing host TOML configuration (which already has
`storage_ref` and `key_ref`). The referenced file uses the existing `StorageConfig`
format documented in [storage](user/storage.md), [immutable storage](immutable-storage.md),
and [consumer storage](consumer-storage.md).

```toml
[storage]
primary = "/secure/bunker/primary-storage.toml"
report_directory = "/secure/bunker/recovery-reports"
# Protected DR only:
# secondary = "/secure/bunker/dr-storage.toml"
# Immutable copies only; choose an actual operator-approved UTC deadline:
# required_until = "2027-12-31T00:00:00Z"
# Google Drive / OneDrive only:
# consumer_state = "/secure/bunker/oauth-state"
```

Paths must be normalized absolute paths without symlinks. Config files must exist,
be regular files owned by the running user, have no hard links, and have owner-only
permissions. Existing report/OAuth directories must also be owner-only. New state
directories are created with mode `0700` under an existing safe parent. Files are
written with mode `0600`, atomically published, fsynced, and read back. Ancestors
must not be writable by other users except sticky directories. Platforms without
the implemented Unix permission checks fail closed.

Both state directories and configuration files must be disjoint from the repository
and workspace, from each other, and from any local replication destination. The
local destination must already exist with owner-only permissions. Validation runs
before host/OAuth state writes. Private directory locks serialize report and token
updates. Config files contain credential **environment variable names**, never
credential values. There is no ambient credential discovery or local fallback.

Consumer OAuth bootstrap credentials are required only until a rotated credential
has been saved in the configured `ConsumerState`. The durable credential takes
precedence thereafter; rotation does not invalidate existing snapshot receipts.
An uncertain refresh still requires the existing explicit OAuth rebind workflow.

## Supported policy combinations

| Configured backend | Immutable | DR |
| --- | --- | --- |
| Local directory, S3, R2, Azure | false | false |
| Verified S3 Object Lock or Azure version immutability | true | optional second verified S3/Azure backend |
| Google Drive or OneDrive with external OAuth state | false | false |

Both protected DR copies receive the same encrypted inventory and checkpoint.
The protected adapter rejects overlapping backing identities and credentials before
uploading. These are the existing bucket/account and credential identity checks;
they are not an attestation of separate administrators, cloud accounts, or failure
domains. Operators must establish those boundaries independently.

R2 WORM, consumer immutability, unprotected DR, and consumer DR are unsupported.
Only `residency = "unrestricted"` is accepted. An AU region name or endpoint does
not establish Australian residency; AU policy remains unsupported without actual
attestations. Ordinary copies do not claim provider-enforced retention.

For immutable copies, both backends require the same explicit `required_until`.
It must remain in the future and cover **snapshot creation time + authenticated
policy retentionDays**. This is a fixed snapshot horizon: metadata retries do not
add another retention period from the retry time. Once the explicit deadline
expires, automatic publication fails closed. Updating the operator deadline changes
the configuration binding and requires new verification and custody. A policy
revision similarly requires a new receipt. Expired saved evidence can still be used
by the unchanged recovery APIs, but is never treated as current protection.

## Publication, retries, and recovery reports

The adapter publishes an encrypted checkpoint only after verifying its dependencies.
Before advancing the local checkpoint, it durably saves:

1. One external recovery report for each independent backend. Protected reports use
   the existing `ProtectedReport` format with a single backend per file; consumer
   reports use `ConsumerReport`. Plain reports contain the exact recovery namespace,
   sequence, and selected snapshot ID.
2. An encrypted, authenticated receipt binding the repository header, full policy,
   operator configuration and credential binding, exact snapshot, checkpoint
   ciphertext, object digests, and report file hashes.

Reports use `<receipt-key>-0.json` and (for DR) `<receipt-key>-1.json`; the encrypted
receipt uses `<receipt-key>.receipt`. Keep the reports and the existing recovery key
material independently recoverable. This adapter verifies durable local filesystem
custody outside the repository, not off-machine durability or survival of a lost
host. Back up that external custody directory according to the deployment's disaster
recovery requirements.

After a delivery failure or restart, the same snapshot/configuration/policy finds
the existing receipt. Every external report must still match its authenticated
hash. Plain and consumer copies re-read and verify the exact inventory; consumer
reads use saved provider IDs. Protected copies use a fresh write-capable backend
to verify current version retention and exact bytes again, and require the versions
to match the saved reports. Imported recovery-only evidence cannot authorize
current protection. With a receipt present, a missing/tampered report, invalid
receipt, changed version, stale deadline, changed binding, or unavailable object
produces an error rather than silently replacing the proof. An absent receipt
requires a fresh verified publication; retain receipts while metadata delivery
is pending to preserve retry deduplication.

Successful retries do not publish another checkpoint. The receipt retains the exact
encrypted checkpoint, so a crash after external custody but before the local
checkpoint write can still retry without regenerating it. Failures before custody
may leave unreferenced encrypted remote objects; they do not advance local `latest`
or authorize snapshot success. There is no automatic deletion or receipt cleanup.

Receipt replay does not repair or rewind the repository's local `latest` pointer.
If that pointer is absent or older after an interruption, a later new publication
can fork from that head and repeat a sequence number. Both saved locators remain
independently recoverable; sequence numbers alone do not establish global ordering
across this crash window. Preserve the exact external recovery reports and use
their pinned locators, rather than choosing a backup by its sequence number.

Recovery interfaces are unchanged: use the report's `namespace` with `recover
--storage ... --namespace ...`; add `--protection-report` for the matching protected
report or `--consumer-report` and `--consumer-state` for a consumer report. Follow
the existing repository/key-source arguments. The encrypted host receipt is a retry
artifact, not a replacement recovery key or recovery report.

The synchronous adapter runs backend construction and its Tokio runtime on a scoped
worker thread, so host calls from an existing async runtime do not create nested
blocking runtimes. No detached worker survives the method return.

## Acceptance limits

Local fixtures cover restart, interrupted publication, partial DR failure, external
report and receipt failures, path and permission rejection, configuration changes,
tampered proof/remote bytes, and recovery through the existing checkpoint API.
Provider adapters also have their existing injected HTTP fixtures. No live provider
credentials, OAuth consent, real WORM behavior, cloud disaster recovery, or residency
attestations were exercised by this implementation. Issue #26 remains deferred.
