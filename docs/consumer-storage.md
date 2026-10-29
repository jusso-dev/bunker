# Google Drive and OneDrive encrypted objects (v1)

`consumer_storage::ConsumerBackend` implements the existing
`checkpoint::RemoteStore::{read_bounded, create_verified}` contract using direct
verified HTTPS REST requests. It accepts the ciphertext and encrypted repository
metadata produced by the checkpoint layer. It never enumerates remote objects,
updates an existing named object, resolves `latest`, or uploads a plaintext backup.
It cannot itself determine whether arbitrary caller-supplied bytes are encrypted;
call it through the checkpoint pipeline.

This adapter provides exact-object publication and integrity verification, **not
WORM or provider-enforced retention**. `immutable = true` is rejected. Cloud
administrators can remove files/revisions, revoke access, or make recovery fail.
The saved external checkpoint locator remains the freshness trust anchor.
Issue #26 is deferred; this change does not add its workflow.

## Configuration

Only `root` and `drive_id` are accepted in `options`. `root` is an existing folder
item ID, not a slash path or the aliases `root`/`me`. Obtain the folder ID while
provisioning the account. The adapter verifies its type and drive before uploading.
It does not create folders or discover them by name.

For Google My Drive, omit `drive_id`. For a Google shared drive, set its exact
shared-drive ID; the root folder and every file must report that drive. Google
binary uploads must support revision retention. The authenticated principal needs
permission to create, read, and retain binary revisions in that folder.

```toml
service = "gdrive"
immutable = false

[options]
root = "EXISTING_GOOGLE_FOLDER_ID"
# drive_id = "EXISTING_SHARED_DRIVE_ID"  # only for a shared drive

[credential_env]
client_id = "BUNKER_DRIVE_CLIENT_ID"
client_secret = "BUNKER_DRIVE_CLIENT_SECRET"
refresh_token = "BUNKER_DRIVE_REFRESH_TOKEN"
```

For OneDrive, both the drive ID and folder item ID are mandatory. V1 uses public
Microsoft Graph and the common OAuth v2 endpoint. Sovereign clouds and arbitrary
API endpoints are not supported.

```toml
service = "onedrive"
immutable = false

[options]
drive_id = "EXISTING_ONEDRIVE_DRIVE_ID"
root = "EXISTING_ONEDRIVE_FOLDER_ITEM_ID"

[credential_env]
client_id = "BUNKER_ONEDRIVE_CLIENT_ID"
client_secret = "BUNKER_ONEDRIVE_CLIENT_SECRET"
refresh_token = "BUNKER_ONEDRIVE_REFRESH_TOKEN"
```

The three credential entries above are required **environment variable names**,
not values. No literal access token, ambient credential chain, device login,
profile search, metadata service, proxy environment, configurable token endpoint,
or insecure TLS mode is used. Only explicitly referenced names reach the resolver.
The OAuth client must support refresh with a client secret. Provision consent and
the initial refresh credential privately outside this adapter. For Google, grant
Drive access sufficient for the selected folder (for example, `drive.file` where
that folder is already accessible to the application). For delegated Microsoft
access, consent to `offline_access` and the necessary Graph file read/write scope.
The refresh request does not broaden the originally granted scopes.

## Publication and recovery

Each new logical checkpoint address gets a new opaque provider object. Addresses
must have the form `<64 lowercase hex>/<headers|chunks|snapshots|checkpoints>/<64
lowercase hex>`. Human filenames and workspace paths are not used as cloud names.

Google creates a resumable upload session for a new binary file, uploads its body
once, obtains its exact file ID and `headRevisionId`, sets that revision's
`keepForever`, and verifies the retained revision metadata and downloaded bytes.
Recovery addresses `/files/{file-id}/revisions/{revision-id}?alt=media`; it never
substitutes the file's current head. `keepForever` protects against ordinary
revision pruning, not an administrator's delete. A fresh file per publication
avoids accumulating the provider's retained-revision quota on one mutable file.

OneDrive creates an upload session under the configured folder with
`@microsoft.graph.conflictBehavior = "fail"`. It uploads sequential fragments;
conflicts at final commit fail without retry, replacement, or rename. The result
is pinned by exact item ID, ETag, cTag, size, and ciphertext hash. Reading fetches
metadata by that ID, verifies the saved tags, downloads via the metadata's
short-lived download URL, and checks metadata again and the full byte hash.

**OneDrive ETag/cTag are revision tags, not Graph historical version IDs.** V1
requires the saved item revision to remain current. A content change, metadata
change that alters its ETag, or deletion causes recovery to fail closed even if a
historical version remains available. Historical-version content APIs normally
redirect; this adapter does not follow them. It never claims historical revision
retention. This is the explicit OneDrive v1 constraint.

Graph's metadata-provided upload/download URLs are capabilities, not redirects.
The client only accepts HTTPS port 443 without userinfo or fragments, and supports
these public Microsoft hostname suffixes:

- Upload: `.up.1drv.com`, `.sharepoint.com`.
- Download: `.files.1drv.com`, `.storage.live.com`, `.sharepoint.com`.

OAuth headers are never sent to those capability URLs. Google upload sessions
must remain on `https://www.googleapis.com/upload/drive/v3/files` with an upload
session identifier. All 3xx responses, including resumable-upload intermediate
308 responses, fail; there is no automatic redirect or upload resume. New host
families require reviewed code changes. An otherwise legitimate tenant using an
unrecognized host fails closed.

Duplicate Google names, overwritten name-to-file mappings, other same-name
OneDrive objects, and remote listing omissions cannot select recovery content:
recovery uses only saved IDs. Within a backend instance, or when resumed with its
saved evidence, attempting different bytes at an existing logical address fails
before network access. Matching bytes are read back against the same saved proof.
There is no latest-pointer fallback and no listing API.

A lost response can leave an orphan upload/file. Retrying a failed unpublished
operation may create a fresh file; it never discovers/reuses an orphan by name.
V1 does not delete or garbage-collect these objects. An evidence persistence
failure retains the verified proof in memory so a caller can retry persistence
through `create_verified` without creating another object.

## Parent integration API and durability contracts

Register `pub mod consumer_storage` and route the two consumer services through
this adapter for checkpoint replication/recovery. No dependency additions or
changes to `RemoteStore` are required. The integration test includes the source
module directly so its checks also work before parent registration.

The stable production constructors are:

```rust,ignore
ConsumerBackend::new(config, token_sink, evidence_sink)
ConsumerBackend::from_evidence(config, &saved, recovery_only, token_sink, evidence_sink)
ConsumerBackend::with_resolver(
    config, saved_option, recovery_only, explicit_name_resolver,
    token_sink, evidence_sink,
)
```

`new` and `from_evidence` resolve initial credentials from explicitly named
environment variables. `with_resolver` uses the same production HTTPS client with
a caller-supplied explicit-name resolver. `with_transport` additionally accepts an
injected transport and clock for offline tests. Constructors make no network
requests. Construct the production blocking client outside an async runtime (or
on a blocking worker). `RemoteStore` operations dispatch through Tokio
`spawn_blocking`; they do not execute blocking HTTPS on runtime polling threads.
All constructors prefer `RefreshTokenSink::load` over the resolver for
the refresh credential. A saved token that cannot be read or validated fails
construction; it never falls back to a stale environment value.

Sinks use `std::result::Result` and implement `Send + Sync`:

```rust,ignore
trait RefreshTokenSink: Send + Sync {
    // Required: durably create a pending guard before any refresh request.
    fn begin_refresh(&self, reference: &str, token: &str)
        -> Result<(), PersistenceError>;
    // Required: durably remove the guard after a known safe outcome.
    fn finish_refresh(&self, reference: &str)
        -> Result<(), PersistenceError>;
    // Production must override to reject pending guards, even before any rotation.
    fn load(&self, reference: &str)
        -> Result<Option<zeroize::Zeroizing<String>>, PersistenceError>;
    fn persist(&self, reference: &str, token: &str)
        -> Result<(), PersistenceError>;
}
trait EvidenceSink: Send + Sync {
    fn persist(&self, evidence: &ConsumerEvidence)
        -> Result<(), PersistenceError>;
}
```

A successful `persist` is a durability acknowledgment, not a queue acceptance.
The parent must provide atomic replacement, file sync and directory sync where
needed, protected file creation, and exclusive locking across processes. Do not
implement production sinks as no-ops. `load` must distinguish absence from read,
permission, parse, or binding errors. Token storage must be owner-only and bound
to the provider location and OAuth client identity/reference set. Never reuse a
saved token merely because an unrelated configuration used the same variable
name. The adapter invokes sinks synchronously while holding internal locks; a
sink must not call back into the backend.

`begin_refresh` must durably create a private, create-new pending marker containing
the hash of the attempted refresh token, bound to the same identity as the token
store. An existing marker must reject another attempt. `load` must fail while
the marker exists, including after process restart; it must never fall back to
the original environment credential. `finish_refresh` removes the marker and
syncs its directory. It must support retry after a failed cleanup, including a
previous removal whose directory sync failed. The parent owns these filesystem
operations and explicit operator rebinding. Rebinding must require a credential
whose hash differs from the attempted token; reopening state alone is not recovery.

`ConsumerEvidence` contains schema version 1, service/root/drive binding, and a
map from logical checkpoint addresses to `ObjectProof` (file ID, provider revision,
length, BLAKE3 ciphertext hash). `ConsumerEvidence::from_slice` and `to_vec`
validate and bound the format. Unknown schema fields and invalid paths/IDs are
rejected. Treat the evidence as an externally trusted local recovery input,
not a provider-signed attestation. Keep it outside the backed-up repository and
outside this consumer backend, alongside the existing
`repository:header:checkpoint` locator. It contains opaque object identifiers,
not credentials or capability URLs.

The sink receives the complete replacement evidence map. Use one serialized
writer per bound location. Resume publication by passing the prior evidence to
`from_evidence(..., false, ...)`; start recovery with `true`. A successful
`create_verified` means readback verification **and** evidence durability
succeeded. The checkpoint layer publishes its checkpoint last; the parent must
also durably save its resulting locator/report before reporting whole-operation
success. Use the parent checkpoint `replicate_with_publication` callback to save
that report before the local latest pointer advances. No map traversal proves that a locator's full dependency set exists;
the checkpoint recovery layer must verify that inventory as usual.

`evidence()` returns a snapshot for export or inspection. It can include a
verified proof whose sink previously failed, so calling this accessor does not
prove durability. On recovery, `create_verified` is disabled. Recovery will not
proceed without an evidence entry for each requested address.

The parent owns CLI dispatch, the explicit `--consumer-state` directory, its exclusive
lock, private token/evidence/report files, and configuration binding. This module
does not modify Cargo, generic storage, checkpoint, or CLI wiring.

## OAuth lifecycle

Access tokens are cached only in memory and refreshed with a 30-second expiry
margin using the injected clock. Token responses and credentials are never
included in adapter errors. A replacement refresh token is retained in memory
and durably persisted **before** the returned access token is used. It is persisted
even if access-token fields are malformed. If persistence fails, all provider
operations stop; the same instance retries saving that replacement and completing
the pending guard on the next operation before it can refresh again. A guard
cleanup failure likewise blocks all network work until durable cleanup succeeds.
Errors explicitly request private-store persistence or operator rebinding without
displaying the credential.

Before sending a refresh request, the adapter requires `begin_refresh` to succeed.
An intent persistence failure sends no request. Refresh requests have no automatic
retry. A transport failure, rejection, redirect, oversized/truncated response,
or unparseable response can leave the
credential outcome uncertain. The durable pending guard remains, so both the
current session and a reopened production state fail closed on subsequent attempts;
the operator must explicitly rebind protected state to a changed credential or
reauthorize. No client can recover a rotated credential lost in transit, or
survive a crash between receipt
and durable storage without provider support. The guard makes that failure window
fail closed across restarts instead of replaying the attempted credential.
A failed sink must not prompt a user to paste the token into chat/logs.

For a response without a changed refresh token, the guard is cleared only after
validating the access token, Bearer token type, and expiry. A valid changed refresh
token is persisted before clearing the guard, even if other response fields are
malformed: the attempted old token can no longer be replayed, so the next refresh
can safely use the durably saved replacement. Malformed access fields still fail
the current operation and never authorize provider work.

Provider API errors, including 401, do not trigger hidden refresh-and-write
retries. Resume/rebind deliberately after diagnosing the account state. Access
revocation, expired consent, MFA/conditional-access policy, and app registration
changes can require private operator reauthorization.

## Bounds and validation

- Nonempty encrypted object: at most 64 MiB; recovery additionally enforces the
  caller's smaller bound and the saved exact size.
- Control/token response body: 64 KiB; returned header budget: 64 KiB. Production
  reads at most the response bound plus one byte before rejecting an oversize body.
- Evidence: at most 10,000 objects and 16 MiB serialized, whichever limits first.
  Publication reserves a conservative 16 KiB for its next proof before uploading.
- OneDrive: 10 MiB fragments (a multiple of 320 KiB), at most seven fragments per
  object, exact next-offset checks, session expiry within the next 24 hours.
- Retries: zero automatic retries. List requests/pages: zero. No remote content
  or provider error text is printed. URL, response, and request types have no
  credential-bearing `Debug` implementations.
- Production transport: verified rustls HTTPS, no proxy chain, no redirects,
  10-second connection timeout, 60-second request timeout.

Offline fixtures exercise both providers, exact-ID recovery, OAuth request
encoding/header placement, rotation persistence and restart loading, failures
before durable acknowledgment, identity/revision/hash mismatches, origin and
redirect rejection, conflict behavior, bounded bodies/proofs and fragment
progress. They use no live account, environment secrets, or network transport.
They establish the adapter contract against realistic API responses, not a live
provider/account certification. Run:

```sh
cargo test -p bunker --test consumer_storage --offline
cargo clippy -p bunker --test consumer_storage --offline -- -D warnings
```

Provider contracts used in the implementation:

- [Google upload files](https://developers.google.com/workspace/drive/api/guides/manage-uploads)
- [Google revision retention](https://developers.google.com/workspace/drive/api/guides/manage-revisions)
- [Graph upload sessions and final-commit conflicts](https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0)
- [Graph download content and preauthenticated URLs](https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0)
