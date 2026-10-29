# Local retention and maintenance

Maintenance is an explicit operator action. `Repository::maintenance_plan(&Policy)`
returns a serializable dry run; `maintenance_execute(&plan, confirmation)` requires
its exact confirmation digest and rechecks the inventory before deleting anything.
The CLI exposes these as `maintenance-plan` and `maintenance-execute --plan PATH
--confirm DIGEST`. Save the plan outside the repository, review its snapshot,
chunk, request and temporary-file lists, then supply its confirmation. The plan is
valid for 15 minutes. A changed inventory or expired plan requires a new dry run.
The plan embeds the retention policy used when it was created; execution cannot
observe edits to an external policy file, so obtain a new plan after policy changes.

Neither opening a repository nor running the daemon performs garbage collection.
There is no MCP or agent-tool deletion operation. Any future automatic scheduling
must require explicit operator enablement; this implementation does not schedule it.

## What is retained

`retention_days` is enforced against authenticated snapshot creation timestamps.
Snapshots at the cutoff or newer survive. The newest workspace snapshot for each
authenticated agent/session pair survives, even outside retention; timestamp ties
use snapshot ID order. Manifests do not currently identify workspace origins, so
this is not a per-directory guarantee. The latest complete setup capture for each
source-root/agent scope survives. Retaining any member retains its entire capture
group, including when timestamps straddle the cutoff. Incomplete published groups
remain pinned as recovery evidence and never replace the last complete capture.
These conservative scope pins can retain snapshots indefinitely.
The planner also preserves snapshots referenced by:

- Undelivered host outbox snapshots and alert references; pending setup/workspace
  detection state and the scheduler’s latest recovery point. Changes to these
  inventories invalidate existing plans; corrupt state refuses maintenance.
- Unexpired local pending restore requests.
- Frozen control-plane requests and bridge intents, even after their TTL. Their
  durable remote lifecycle cannot safely be inferred from these local records.
- Every authenticated restore transaction journal, including completed and rolled
  back transactions. Terminal transactions remain usable for explicit rollback.

Transaction preimages, staged files and journals are never removed. There is no
transaction archival policy yet; these conservative pins may keep snapshots beyond
retention indefinitely. Unknown transaction states or a directory without a valid
journal stop maintenance rather than guessing whether recovery is still possible.
Decided local requests (`approved`, `denied`, `expired`) and expired local pending
requests are eligible for removal, matching the existing `prune_requests` lifecycle.
The new API authenticates the entire managed request inventory before selecting any.
Frozen bridge records are deliberately excluded from request pruning.

The planner authenticates **all** published manifests before computing reachability,
including manifests eligible for expiry. It calls `Repository::snapshot_chunks` so
both ordinary file chunks and optional Git metadata/pack chunks participate. A chunk
referenced by any retained snapshot survives. Chunks referenced only by expired
snapshots can be removed with those snapshots. Unreferenced chunks left by failed
snapshots require at least 24 hours of age according to filesystem modification time.
Future modification times do not qualify. Future snapshot creation times stop the run
until the clock/inventory can be reconciled.

Only exact `.bunker-<32 lowercase hexadecimal characters>.tmp` regular files in
`snapshots`, `chunks` and `requests` are temporary cleanup candidates, also after
24 hours. Root-level temporary files and all transaction temporary files are kept.
Unrecognized entries in the managed object directories stop the run. Empty
repositories can reclaim old orphan chunks; no snapshot is invented or required.

## Validation and interruption

The repository holds its exclusive filesystem lock throughout planning and execution.
Callers must serialize operations through a shared `Repository` handle and quiesce
other filesystem writers. Maintenance opens managed directories with no-follow
capabilities and opens regular files without following symlinks. It never recursively
deletes directories. Symlinks, special files, missing referenced chunks, corrupt
ciphertext, invalid manifests, unknown request schemas and ambiguous journals stop
maintenance before deletion. Published chunks are authenticated too; transaction
preimages are fingerprinted, not decrypted as part of this operation.

Traversal is bounded: 200,000 object entries, 10,000 snapshots, 1,024 requests,
64 MiB of aggregate encrypted metadata read for authentication, and 64 GiB of
inventory file bytes.
Individual objects also have size limits. Reaching a limit fails closed; inventory
is never silently truncated. Large repositories may require a future paginated
maintenance design. Planning reads every managed file; execution repeats this scan.

The confirmation is keyed by the repository data key and binds the policy, fixed
cutoff time, exact deletion lists, retained snapshots and inventory fingerprint.
The fingerprint includes file contents, sizes, modification times and managed
directory presence. The header and any outstanding maintenance journal are included.
Audit history and unrelated repository namespaces are not deletion inputs and are
not scanned for reachability.

Before the first unlink, execution writes and fsyncs an authenticated encrypted
`maintenance-journal` containing the complete confirmed plan. It removes selected
manifests first and **fsyncs the snapshots directory before deleting any chunk**.
Consequently, interruption can leave extra chunks but cannot remove chunks still
referenced by a retained manifest. File removals are followed by directory fsyncs.
Completion writes an encrypted audit event, then removes and syncs the journal.

If interrupted, run another dry run. Its `interrupted` flag is true and its new
confirmation binds the remaining inventory and previous journal. Confirming that
plan safely rolls forward; the old confirmation is refused. No recovery deletion
runs on repository open. A previously referenced chunk left behind by interruption
may wait for the normal 24-hour orphan grace before a later run reclaims it. The
report counts only removals in the current run. This is crash-safe **roll-forward**
recovery, not undo: an already deleted expired snapshot cannot be recovered locally
by restoring the deletion journal. A corrupt journal requires operator diagnosis;
it is never ignored or automatically discarded.

## Security and scope

The API restriction is not filesystem protection. A process running as the same OS
identity with repository write permissions can delete repository files directly or
invoke operator code. Protect backups by deploying the backup operator/service under
a separate OS identity, with agent users denied repository write access. The lock
coordinates Bunker processes; it does not prevent malicious same-user filesystem
writes or concurrent mutation outside Bunker. Confirmation digests are not credentials
that confer OS authorization, and the library is not a separate privilege boundary.

Maintenance uses the unlocked repository data key, so passphrase and managed-key
repositories use the same implementation. It never contacts remote storage or deletes
remote backups/checkpoints. Local policy validation rejects `immutable = true` and
an unimplemented immutable DR target: local deletion cannot promise remote object-lock
retention. Existing remote copies may continue to occupy storage after local GC.
Checkpoint manifests are deliberately not treated as local retention roots; independent
remote-checkpoint recovery requires its remote objects to remain available.

Tests in `crates/bunker/tests/maintenance.rs` use disposable temporary repositories.
They exercise shared reachability, policy expiry, request/journal pins, Git references,
corruption refusal, stale confirmation, symlink refusal, orphan/temp grace, and
interrupted journal recovery. Cross-platform power-loss and hostile concurrent-writer
validation are not claimed by these process-level fixture tests.
