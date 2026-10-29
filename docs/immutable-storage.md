# Verified immutable storage and a second DR copy

The v1 adapter applies provider retention to ciphertext and independently reads the
result back. `immutable = true` selects this workflow; it is never evidence that a
bucket, account, or object is protected. No live provider acceptance, cloud
provisioning, deletion, deployment, or credential access was performed during this
implementation. The tests use injected HTTP fixtures.

## Supported provider contracts

* **S3:** versioned objects with Object Lock enabled by an administrator. New
  conditional `PutObject` requests carry `COMPLIANCE` and an absolute retain-until
  date. Existing identical versions receive `PutObjectRetention` when retention is
  missing or too short. Verification uses version-specific `HeadObject` responses
  containing the version ID, `x-amz-object-lock-mode`, and retain-until date. The
  adapter never sends governance bypass and rejects GOVERNANCE evidence.
* **Azure Blob:** version-level immutability enabled by an administrator, an
  explicit account name, and an explicitly referenced SharedKey. New conditional
  `Put Blob` requests carry a locked immutable policy. Existing identical versions
  use `Set Blob Immutability Policy` with `comp=immutabilityPolicies` and a pinned
  `versionid`. Verification reads version-specific blob properties. Unlocked
  policies, absent version IDs, and incomplete policy headers are rejected.
  SAS, OAuth and ambient certificate/workload identity discovery are not part of
  this protected adapter. The legacy unprotected adapter remains separate.
* **R2:** unsupported for this protected workflow, including its normal endpoint
  under the `s3` service alias. R2 has bucket-lock management, but its S3 API does
  not supply the version-specific Object Lock contract used here. The existence
  of bucket locks does not justify claiming equivalent protection.

Official REST references checked for this implementation:
[S3 PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html),
[S3 PutObjectRetention](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html),
[S3 HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html),
[Azure Put Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob),
[Azure Set Blob Immutability Policy](https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-immutability-policy),
[Azure Get Blob Properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties),
[R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/), and
[R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/).

## Configuration and execution

Protected storage uses the existing `StorageConfig` with an explicit HTTPS origin,
provider options and credential **environment variable names**. The origin cannot
contain a path, credentials, query or fragment. Bucket/container and `root` are
separate fields. Credential values must not appear in configuration files.

```toml
service = "s3"
immutable = true
[options]
endpoint = "https://s3.us-east-1.amazonaws.com"
region = "us-east-1"
bucket = "example-primary-backup"
root = "bunker"
[credential_env]
access_key_id = "BUNKER_PRIMARY_ACCESS_ID"
secret_access_key = "BUNKER_PRIMARY_SECRET"
# session_token = "BUNKER_PRIMARY_SESSION_TOKEN"
```

```toml
service = "azure"
immutable = true
[options]
endpoint = "https://exampleaccount.blob.core.windows.net"
account_name = "exampleaccount"
container = "backup"
root = "bunker"
[credential_env]
account_key = "BUNKER_DR_ACCOUNT_KEY"
```

The integrated CLI uses `replicate --storage ... --retain-days ... --report ...`
for a protected copy, and adds `--dr-storage ...` for the second copy. Each
configuration must explicitly choose immutable storage. The protected report must
be durably retained outside the repository/backend. `recover --storage ...
--namespace ... --protection-report ...` chooses the matching backend evidence.
Follow the CLI's existing repository, key-source and destination arguments.
These commands are documentation only; they were not run against a cloud account.

No environment credential chain, profile, metadata endpoint, SSO, managed identity,
certificate discovery or implicit fallback exists. Only configured variable names
are resolved. Endpoint errors, transport errors and provider error bodies never
include credentials or raw responses. Redirects and implicit proxy discovery are
disabled. Requests use HTTPS with certificate verification, a 10-second connection
limit, 60-second request limit, and at most three attempts with bounded backoff.
Retries cover transport failures, throttling and selected server errors; access
and immutability failures do not trigger a bypass. Responses are bounded to 64 KiB
for control operations and at most 64 MiB for ciphertext. Evidence is capped at
100,000 objects and a bounded 32 MiB size estimate per backend. Provider dates must
be within five minutes of the injected/system clock.

## What verification proves

For each object, the adapter:

1. Resolves the current version, or conditionally creates an object with retention
   already present on the creation request (`If-None-Match: *`).
2. Reads that exact version and compares all ciphertext bytes before modifying any
   existing object's retention. Different ciphertext is never overwritten.
3. Reads the exact version's retention, extends only when needed, then reads the
   same version's properties again. Both mode and deadline must meet the minimum.
4. Checks that the current version is still that verified version before returning.
5. Saves its version ID, retention mode/date, byte length and BLAKE3 digest.

A successful write response, an ETag, or configuration is insufficient. Missing,
malformed, duplicate or partial evidence, unversioned objects (`null` versions),
short deadlines, governance/unlocked policies and version races fail closed.
An existing locked version with a later deadline is not shortened.

A trusted provider endpoint and TLS remain part of the security boundary. These
are verified provider responses, not a third-party signed attestation. An S3
compatible server that lies about retention cannot be independently audited by
this client. Actual cloud configuration and permissions still need provider
acceptance testing in a separately authorized environment.

## Checkpoint and DR integration

The existing encrypted checkpoint format, namespace and `namespace:header:index`
locator stay unchanged. `checkpoint::RemoteStore` delegates exact-object operations
to the protected backend. The paired coordinator encrypts one inventory and copies
identical ciphertext to both backends. Each dependency returns successfully only
after retention is independently verified at both destinations. The final
checkpoint is attempted after all dependencies; paired success and the local
checkpoint advance require both final-object verifications.

The providers do not offer a cross-cloud transaction. Failure may leave protected
orphan objects, or a final checkpoint at one destination when the other final
write fails. Such failure must not be reported as paired success. There is no
rollback/deletion API. This distinction matters: returning a durable verified
locator is publication by the application; an object may already be physically
visible while its readback is being checked.

The report contains separate backend identities and exact-version inventories,
including each final checkpoint. Independent-target validation rejects the same
bucket/container with another prefix or endpoint alias, and the same S3 access-key
ID or Azure account identity. Different credential variable names alone do not
qualify. Different access-key IDs do **not** prove different IAM principals or
administrators, and different services do not prove separate organizational fault
domains. Account/principal isolation and credential privileges must be established
by deployment policy; v1 does not claim to introspect them.

## Recovery and saved evidence

Object Lock protects a version. It does not make a name's latest pointer immutable:
new versions or delete markers can hide protected data. Keep the report with its
version IDs outside the storage target. Recovery uses those pinned versions and
checks their ciphertext length and hash, so it does not rely on listing or the
latest pointer. The report binds its exact HTTPS origin, bucket/container and root;
credential rotation is allowed without changing the storage location.

`ProtectedBackend::for_recovery` accepts an expired retention deadline. It is
strictly read-only and requires a saved proof for every requested path. Exact
version availability and byte integrity determine recovery success even after
retention expires or its policy is removed. This mode never exports a new current
protection claim. It cannot restore a version that the provider has already lost
or deleted. Treat the saved report/locator as a trusted external recovery input.

## Rust API and offline validation

* `ProtectedBackend::new(&StorageConfig, DateTime<Utc>)` creates a writer with a
  future whole-second absolute minimum. It is `Clone + Send + Sync`.
* `create_verified(path, Vec<u8>)` and `read_bounded(path, maximum)` are synchronous;
  the `RemoteStore` implementation executes them through `spawn_blocking`.
* `identity`, `ensure_independent`, `required_until`, and `evidence` supply the
  coordinator's checks and report. Importing saved evidence is recovery-only.
* `for_recovery(config, evidence)` pins externally saved versions. Both production
  constructors use a blocking HTTP client and should run outside an async runtime
  or inside `spawn_blocking`.
* `with_transport` and `for_recovery_with_transport` inject a bounded transport,
  clock and explicit-name credential resolver for fixtures.

Tests exercise S3/Azure response parsing, request signing against the existing
independent `reqsign` signers, version binding, clock skew, conditional races,
retention extension/failure, governance refusal, secret-safe diagnostics, response
and evidence bounds, deadline expiry, DR dependency failure, identical inventories
and recovery from the second copy. These fixtures establish implementation
behavior, not live service acceptance or actual cloud lock enforcement.
