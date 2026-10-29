# Git capture and recovery library

`crates/bunker-git` supplies offline Git preservation. Core snapshots now capture
supported Git workspaces automatically and compose Git restore with workspace
restore. This document describes the core/library contract; host approval, CLI,
checkpoint, storage and maintenance callers must use the APIs below. It does not
claim all v1 work is complete. Fresh-machine rebuild (#26) remains deferred.

## Integration API

- `GitBackup::capture(root, &CapturePolicy)` returns `Capture { metadata, pack }`.
  Roots must be absolute, without symlink ancestors. Git is invoked as an
  executable with argument arrays; `git_executable` can select a trusted binary.
- `Capture::from_parts(metadata_json, pack, &Limits)` bounds and parses decrypted
  parts, checks the version and pack inventory/checksum/object identities. Restore
  planning additionally validates the graph, paths, object types and prerequisites.
  Use this bounded entry point rather than deserializing unbounded transport input.
- `Capture::fingerprint()` binds canonical metadata and exact pack bytes with SHA-256.
- `GitBackup::plan_restore(target, &capture)` returns a serializable `RestorePlan`:
  target path, previous refs, prior metadata/index fingerprints, desired refs and
  index fingerprint/entries, ordered stash IDs, prerequisite counts and warnings.
  `readable()` renders local JSON; `confirmation_digest()` binds the entire plan.
- `apply_restore(&plan, &capture, persist_journal)` is the local always-authorized
  compatibility wrapper. `apply_restore_with_authorization(&plan, &capture,
  persist_journal, authorize)` recomputes the plan, refuses a changed target or
  artifact, takes cooperative locks, and persists the journal before mutation.
  Authorization is checked before temporary config isolation, every object import,
  the ref transaction, index installation, stash-log installation and final config
  restoration. Errors trigger guarded rollback even after authorization expires.
- `recover(&journal)` restores prior refs/index/stash log with guards against
  subsequent edits. Recovery is idempotent and supports interruptions during both
  application and rollback. Do not use a journal from an unauthenticated source.

The journal callback receives `&Journal` and returns `anyhow::Result<()>`. It must
**encrypt, atomically persist, and fsync the journal and its directory** before
returning success. A callback error stops the restore before importing objects or
changing refs/index. A closure that merely returns `Ok(())` is useful in fixtures
but does not provide durable recovery in production. On errors after journaling,
`ApplyFailure` returns the journal, `rollback_completed`, and any `recovery_error`.
A false rollback flag requires explicit recovery; retain the encrypted journal.
Keep it until the outer Bunker workspace/Git transaction has completed durably.

All artifact bytes, metadata, plans and journals are plaintext library values.
The caller must authenticate and encrypt them before persistence or transmission.
Ref names and index paths can be sensitive. Do not expose a full plan or source
preview through MCP. Bind the Git confirmation digest, workspace plan, snapshot
identity and target to Bunker's independent human authorization mechanism. This
library neither grants authorization nor implements the confirmation UI.

## Captured state and omission rules

Capture records every `refs/heads/*` tip, the symbolic HEAD branch, every entry of
`logs/refs/stash` in oldest-to-newest order (including duplicates), and all supported
stage-zero index entries. Stash graphs include index and untracked-file parents.
Reflog messages, identities and timestamps are deliberately not exported: restored
stash logs use neutral Bunker metadata. Commit bytes, including original commit
messages/identities, are never rewritten. Dropped/expired stash entries no longer
present in the reflog cannot be recovered. Other branch reflogs and tags are not
exported. Detached HEAD is refused rather than silently omitted.

The required object graph is the union reachable from branch tips, all stash
reflog commits, and index blobs. Objects reachable from any local
`refs/remotes/*` ref are subtracted. The archive stores an explicit prerequisite
inventory for the omitted objects needed by this capture. Remote-tracking refs
are a local assertion; the library does not contact or prove the durability of
the server. A stale/deleted remote can therefore require another offline source
of prerequisite objects during recovery.

Without remote-tracking refs, all required local history is stored. An unborn
empty repository produces an explicit empty graph and valid empty pack. Missing
Git, a nonrepository root, and unsupported repository states return errors.

The pack is Git pack v2 with **no deltas**: every packed object includes its entire
canonical payload, independent of external delta bases. Objects are sorted by ID,
so repeated captures of identical state produce identical metadata and pack bytes.
Caller-side content-addressed/encrypted snapshot storage must deduplicate these
bytes; this library does not itself implement repository chunking or retention.

Staged bytes are distinct from working bytes. Index entries are reconstructed in
portable index v2 form, including executable bits and staged additions/deletions.
Stat caches and optional index extensions are discarded. Working and ordinary
untracked files belong to Bunker's workspace capture/restore, not this pack.

## History rewrite and force-push observation

`GitBackup::capture_with_previous(root, policy, previous_metadata)` accepts the
previous **authenticated** metadata and computes comparisons inside the same
isolated `View` used for capture. The optional `observation` field stores bounded
remote-tracking tips, a SHA-256 binding to the exact previous metadata, and an
aggregate comparison. It is part of the encrypted, authenticated metadata object;
ref names, object IDs and the baseline digest must never enter host/MCP metadata,
logs or error strings. Old v1 metadata without this field still decodes. It can
provide local branch baselines; tracking comparison is explicitly unavailable
until a tracking observation has been recorded.
With the same previous metadata and source state, capture is deterministic;
changing the supplied baseline changes the observation even if source tips match.

Core integration calls
`Repository::capture_git_with_previous(root, policy, Option<&Manifest>)` while
holding exclusive Git access. Public callers use
`Repository::snapshot_with_previous(workspace, policy, agent, session, trigger, previous)`
and must supply the durable previous snapshot for that workspace. The ordinary
`snapshot` method establishes an observation without comparing a baseline; it
does not infer a previous snapshot from repository-wide recency.
`Repository::git_alerts(previous, current)` loads
and authenticates both Git artifacts and returns `bunker_git::GitAlerts` without
accessing a live workspace or running Git. The library equivalent is
`bunker_git::git_alerts(&previous.metadata, &current.metadata)`. A mismatched
baseline, absent capture or absent comparison produces a fixed diagnostic,
never a guessed comparison. Artifact/decryption failures at the public repository
boundary produce only `Git observation unavailable`, without underlying errors.

For each previously observed name still present, equal tips count as unchanged.
A changed tip is a fast-forward when the old commit is in the new tip's ancestry.
A **definite non-fast-forward** requires the old commit object to be available and
identity-checked in the current source, and a complete, successful ancestry walk
of the new tip that excludes it. Local heads increment `local_branch_rewrites`;
tracking refs increment `remote_tracking_rewrites`. Branch and tracking-ref
deletions have separate counts and are not rewrite alerts. New refs establish a
baseline without a rewrite alert. Tracking aliases are counted as observed refs,
so a symbolic remote HEAD and the branch it follows can both contribute counts.

A remote-tracking rewrite means only that this local repository observed a
non-fast-forward change to that tracking name between snapshots. It **suggests**
a remote force push, but cannot prove a push occurred, who performed it, or why:
local `update-ref`, changed remote configuration and other local operations can
produce the same signal. No network, fetch, remote query or Git push is performed.
Changes and reversions entirely between snapshots are not observable. These
signals do not authorize recovery or any overwrite.

Missing/GC'd or corrupt old objects produce `previous_object_unavailable`, even
when the previous encrypted pack contains the object; observation never imports
old objects to manufacture current availability. Failed ancestry reads produce
`ancestry_unavailable`; tracking tips naming tags, trees or blobs instead of
commits are also unknown. Neither counts as a rewrite. Other fixed categories are
`capture_unavailable`, `observation_unavailable`, `previous_tracking_unavailable`,
`baseline_mismatch` and `observation_limit_exceeded`. Public summaries contain
only integer counts and these fixed categories; diagnostics mean incomplete
coverage and must not be presented as proof that no rewrite happened.

Defaults retain at most 1,024 tracking refs, inspect at most 64 changed refs and
allow 100,000 commits per ancestry result, plus one sentinel commit to detect
truncation. `Limits` exposes those three bounds;
existing subprocess output, object-size and metadata limits also apply. Reaching
an ancestry cap without finding the old tip produces unknown, never a rewrite.
Finding the old tip proves a fast-forward even before the traversal is complete.
The observation loop stops starting comparisons after `command_timeout_secs`;
individual plumbing commands retain their own deadlines. A command already in
progress is not preempted by the observation-loop deadline. Dropped tracking tips
and skipped comparisons are counted as limit diagnostics. Captures still enforce
the existing full-graph, object, policy and metadata caps independently.

Observation uses generated private configuration and the cleared process
environment. Source/target includes, hooks, replacement objects and network
protocols stay disabled. It adds no source mutation, recovery operation, config
rollback change or ref-namespace exception. Fresh-machine rebuild (#26) remains
deferred; these APIs are one detection component, not a claim that all v1 work is
complete.

`scheduler::detect_repository` maps positive local counts to `history_rewrite`
and tracking counts to `force_push` alerts. The latter name is an operational
signal with the qualification above, not proof of a remote push. Alert metadata
contains only the kind, count, snapshot identity, timestamp and a stable
snapshot/kind fingerprint. Fixed diagnostics and comparison counts are recorded
in the encrypted local `git_observation` audit. Both scheduler paths pass their
own durable `last_snapshot` as the explicit baseline.

## Secret and path safety

Every indexed path and every file tree in local-only history is inspected. Secret,
environment, transcript/browser and policy-excluded paths refuse the entire Git
capture with an `unsafe-path` diagnostic. Recognized agent directories additionally
use discovery's setup exclusions. Known structured agent configuration paths at
any workspace depth use discovery's shared path recognition (including desktop
user settings and `.agents/config.toml`) and
`bunker-discovery::sanitize` as a **check**, never to rewrite Git content. If parsing
fails or sanitization would modify anything, capture is refused: rewriting a blob
would change its tree and commit IDs. Already-safe explicit secret references are
allowed. Apply validates these rules again against the authenticated artifact.

Ordinary source files, arbitrary JSON/TOML, binaries and identifiers are not
heuristically rewritten or token-scanned. This is not a DLP guarantee: secrets
embedded in ordinary source, commit messages, names or other unrecognized content
cannot reliably be detected. Administrators must supply additional exclusions;
a match refuses capture rather than silently producing a partial Git backup.
History that contains an excluded file in a local-only commit is refused even if
its tip later deleted that file. Remote-known payloads are omitted, not sanitized.

`.git/config`, remotes/URLs, hooks, credentials and arbitrary `.git` files are never
included in an artifact. Capture uses a private temporary repository with generated
configuration and a read-only object alternate to the selected repository. Only
local format declarations are parsed from source config with includes disabled;
source config and its includes are not loaded for Git operations. During apply and
recovery, the original target config bytes and Unix mode are retained in the
encrypted journal; a generated config is atomically installed while `config.lock`
is held. Only then may plumbing run against the target. Original config is
restored after success or rollback. Recovery also attempts guarded config cleanup
when ref validation, ref rollback, or another state recovery step fails. Such a
failure still requires explicit recovery and retention of the encrypted journal;
config cleanup alone does not mean rollback completed. Cleanup rechecks the
config bytes and mode and refuses to overwrite later edits. This is necessary
because Git offers no switch to disable repository-local config includes for all
plumbing commands. Stash reflog
messages are inspected locally to recover IDs but do not enter exported metadata.
The subprocess environment is cleared, system/global configuration and attributes
are disabled, hooks/fsmonitor/replacement objects/commit graphs/automatic GC are
disabled, lazy fetch is disabled, and all network protocols are denied. Only an
explicit plumbing allowlist is used; no fetch, checkout, reset or source ref/index
mutation occurs. Git stderr is suppressed to avoid leaking object/config contents.
Temporary directories are private but contain plaintext objects/metadata while in
use; secure erasure after a crash is not promised.

## Restore contract and recovery

Capture and restore reject case and Unicode NFC/NFD aliases in ref names and
their ancestor directories, including names held only in `packed-refs`. Planning
checks artifact refs, existing target refs, and their combined namespace before
any target mutation. Names and object IDs are never rewritten to resolve aliases.

The target must already be a supported repository, with HEAD naming the captured
branch, a clean index relative to HEAD, and tracked worktree bytes/modes matching
that index. Checkout filters/EOL transformations that change bytes are refused.
Untracked files are retained. HEAD and worktree files are not changed. Restored
refs/index can consequently make the worktree dirty until the caller restores the
workspace. Empty captured stash leaves an existing target stash unchanged. Extra
target branches/tags/refs are never implicitly deleted.

Planning checks all prerequisites in the target before importing capture objects
into a private validation repository. Pack checksum, IDs, sizes, inventory and
graph closure are checked, then Git `fsck --strict` validates object structure.
Missing prerequisites cause an error naming the missing object ID. The library
never fetches; the operator must separately provide an appropriate clone/objects.

**The caller must provide exclusive access to the repository throughout capture,
apply and recovery**, including exclusion of other Git processes and filesystem
writers. Capture compares refs/HEAD/packed-refs/index/stash-log fingerprints before
and after reading. Apply recomputes the confirmed plan, checks again after taking
`bunker-git.lock`, `index.lock` and `config.lock`, and uses Git's compare-and-swap ref transaction.
The path checks reject existing symlinks and special files, including object-store
symlinks and destination reflog paths. These checks are not a capability-based
filesystem sandbox against an adversary racing path replacement. Shared-principal
hostile writers are outside the contract. Object storage must remain immutable
while reading; concurrent garbage collection is not supported.

Refs are atomically updated as a group, but refs, index and stash reflog do not
share a single filesystem transaction. The encrypted preimage journal covers the
gap. On a normal error automatic guarded rollback runs. After a process crash,
first establish exclusive access, inspect and remove only abandoned
`.git/bunker-git.lock`/`.git/index.lock`/`.git/config.lock`, and call `recover`.
A crash can leave the generated config installed; recover from the authenticated
journal before resuming ordinary Git activity. Never reconstruct or discard the
original config without its encrypted preimage. Refuse blind retries
if recovery reports subsequent edits. Recovery accepts both forward intermediate
states and its own known intermediate reflog state. Imported Git objects remain
additive on rollback; removing them could damage another ref. Ordinary branch
reflogs may gain recovery entries; exact branch reflog restoration is not modeled.
Directory/index writes are synced and Git loose-object/ref fsync is requested.

## Limits and unsupported states

Defaults: 100,000 graph objects/storage paths/index entries, 8 MiB per object,
256 MiB total packed uncompressed bytes, 256 MiB pack, 16 MiB metadata, 32 MiB per
command output, and 30 seconds per command. Caps are configurable through `Limits`.
Prerequisite inventories and remote graph traversal are bounded too; large repos
may need explicit higher limits. Limits are not an OS-level CPU/memory sandbox for
Git itself. Git processes have a deadline and bounded captured output.

V1 supports Unix, SHA-1, files refs, repository-format version 0, an ordinary
nonbare `.git` directory, symbolic branch HEAD and index v2/v3 stage-zero regular
files. It explicitly refuses linked worktrees (including main repos with attached
worktrees), submodules/gitlinks, tracked symlinks, symlinked repository ancestors or
object storage, SHA-256/reftable, shallow/partial/promisor/alternate stores,
replacement refs/grafts, in-progress merge/rebase/cherry-pick/revert/bisect,
non-UTF-8/control/traversal paths, conflicts, split/sparse/v4 indexes,
assume-unchanged/intent-to-add/skip-worktree flags, and unsupported file modes.
No Windows, hostile-filesystem-race or production remote-provider success is claimed.

## Verification and parent integration

Run independently (no root Cargo changes needed):

```sh
PATH=/Users/justinmiddler/.cargo/bin:$PATH cargo test --manifest-path crates/bunker-git/Cargo.toml
PATH=/Users/justinmiddler/.cargo/bin:$PATH cargo clippy --manifest-path crates/bunker-git/Cargo.toml --all-targets -- -D warnings
PATH=/Users/justinmiddler/.cargo/bin:$PATH cargo fmt --manifest-path crates/bunker-git/Cargo.toml -- --check
```

Fixtures use disposable repositories and bare file remotes only. They cover
unpublished branches, three stashes with untracked parents, staged/worktree
separation, deterministic captures, pack inventory inspection proving remote-known
payload omission, full-history fallback, empty repos, rollback/interrupted
recovery, stale plans, invalid packs/metadata, unsafe history/configs, hook/fsmonitor
nonexecution, symlinks/worktrees, source changes and configured caps. Tests do not
access real user repositories, configuration, secrets or cloud services.

`fuzz/` is a separate cargo-fuzz workspace with `capture_parts` and `pack_bytes`
targets. From `crates/bunker-git`, run
`cargo +nightly fuzz run <target> -- -max_total_time=10 -max_len=4096` for a smoke run.
The pack target repairs checksums to exercise deeper parsing. Short smoke runs and
a deterministic malformed-input unit corpus are useful checks, not a full audit.

## Core snapshot and restore integration

A root with a `.git` entry is offered to the Git library. Unsupported layouts,
unsafe history, unavailable Git, limits and access failures leave a generic
`git_capture_failed_or_unsupported` diagnostic at `.git`; ordinary file capture
continues. Raw Git errors are deliberately not put in snapshot diagnostics because
paths, object IDs and ref names may be sensitive. A non-Git root has no Git artifact.
Nested repositories are not independently traversed as Git repositories.

The optional authenticated manifest field `git` contains `version: 1`, `metadata`
and `pack`. Each part has `size`, a keyed BLAKE3 `hash`, and ordered encrypted
`chunks`. Metadata JSON and the binary pack are chunked independently using the
same content-defined chunk store as workspace files. Older manifests without
`git` remain readable. `verify` verifies both parts and uses the library's bounded
parser to validate pack checksum, object identities and inventory. Graph closure,
prerequisites and safe paths are validated again against the target at planning.
Git parts do not appear as ordinary workspace files or content previews.
`manifest.bytes` remains the workspace-file byte count for format compatibility;
Git part sizes are separately available. The combined workspace/Git plaintext
budget is checked before publication. If Git exceeds the remaining policy budget,
it is omitted with `git_capture_size_cap`; workspace capture still succeeds.

**Every dependency consumer must use**
`Repository::snapshot_chunks(&self, manifest: &Manifest) -> Result<Vec<String>>`.
It returns validated, sorted, deduplicated IDs for files and both Git parts.
Checkpoint upload, legacy storage export/recovery, retention and garbage collection
must not enumerate only `manifest.files[*].chunks`. `encrypted_object` exports Git
chunks through the existing authenticated chunk path. Git payloads stay encrypted
at rest and in transport.

`plan(id, destination, None)` includes a full local `git` plan: prior and desired
refs, index entries/fingerprints, stash order, prerequisites and warnings. The
whole value is bound into the core confirmation digest. The destination must be a
clean supported repository on the expected branch, already containing omitted
prerequisite objects. No clone/fetch/network operation is performed. A file
selection produces `git: None` and neither requires Git artifact chunks nor
mutates Git refs, index or stash, even if those chunks are damaged.

Restore stages and fsyncs all workspace preimages and after-images before Git
application. Git applies first, while its required baseline is still clean; then
workspace files are installed. The operation is **journaled, not filesystem-atomic**.
An error may leave a Git/workspace intermediate state, which is explicitly marked
`interrupted` and returned with its transaction ID. Git performs its own guarded
rollback on internal application errors. The outer transaction never discards
preimages on failure, and `plan_recovery`/`recover_transaction` can roll back the
combined state. No silent automatic overwrite of subsequent edits is attempted.

### Exclusive access and authorization

The core holds `.git/bunker-capture.lock` through capture, full planning, full
restore, or recovery. This is cooperative Bunker exclusion only. **The operator
or host must stop all other Git processes and filesystem writers throughout the
operation.** Git offers no universal lock that excludes all writers. Source state
is checked by the library, but these checks cannot make hostile races safe. On a
crash, establish exclusive access before manually removing abandoned Bunker/index
locks. The API never deletes a lock it did not create.

The core entry point is:

```rust
pub fn restore_with_authorization(
    &self,
    id: &str,
    destination: &Path,
    selection: Option<&str>,
    confirmation: &str,
    allow_rebind_overwrite: bool,
    authorize: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<RestorePlan>
```

`restore_with_options` delegates with an always-allow callback. The authorization
callback runs on entry, after all file staging, at each library Git mutation
boundary, and immediately before each workspace file installation and executable
mode change. Expiry leaves a durable interrupted transaction. The host bridge
must freeze the entire serialized plan, including Git, and pass its expiry check
through this API. Local confirmation is not independent human authentication.

The library rechecks before every object import, ref transaction, index write,
stash reflog write and config replacement. Rollback is allowed after expiry to
restore protected preimages. Checks do not preempt an already-started filesystem
operation or Git subprocess; commands retain the library's bounded execution
deadline. Authorization callbacks must be quick and must not mutate the target.

MCP must return only Git effect counts/booleans and warnings suitable for the
caller; do not serialize `plan.git`, source metadata, ref names, index paths,
object fingerprints or journals in an unrequested MCP response. Full plans and
journals are local operator/host-review values. A host must authorize their exact
serialized value even when the agent-facing display is sanitized.

### Durable journal format and maintenance protection

All paths below are relative to the encrypted repository. Each ciphertext uses
the repository data key and the transaction ID as AEAD associated data; transaction
IDs are 64 lowercase hexadecimal characters. Writes are atomic and fsynced along
with their parent directories before destination mutation.

- `transactions/<id>/journal`: encrypted JSON with `id`, full `plan` (including
  `plan.snapshot`, `plan.destination` and optional `plan.git`), `status`, `applied`
  file indices, `preimages`, optional `in_flight` index, and optional `git_started`
  / `git_applied` booleans. Git-journal presence is authoritative even if a crash
  occurred before the corresponding outer flag was persisted.
- `transactions/<id>/git-journal`: optional separately encrypted library `Journal`,
  bound to `plan.git` by its confirmation digest and target. Contains self-contained
  prior/desired refs, raw prior/desired index and stash reflog state, and the
  original config bytes/Unix mode; **no chunk references**. Journal version 2 is
  required because older journals lack the config preimage and cannot safely
  isolate configuration during rollback. Refuse old journals explicitly. Config
  and reflog preimages can contain credentials/identities; never display them to
  MCP or persist them unencrypted.
- `transactions/<id>/<index>.before`: encrypted original file bytes, retained.
- `transactions/<id>/<index>.after`: encrypted staged snapshot bytes; deleted only
  after the outer journal is durably `completed`.

Statuses are `staging`, `applying`, `interrupted`, `completed`,
`completed_audit_failed`, `recovering` and `rolled_back`. Pending/interrupted or
recovering transactions must retain the snapshot named by `plan.snapshot`, both
journals, and all staged/preimage files. Completion does not authorize deleting
rollback evidence automatically. Treat unknown/malformed states conservatively.
There are no Git-specific chunk references in requests or journals beyond their
referenced snapshot; pending host requests still protect their snapshot using the
host request format. Maintenance must coordinate with the repository's existing
exclusive lock and must not remove uncommitted chunks while capture is active.

`plan_recovery(id)` returns paths, a Git boolean, destination and a confirmation
bound to the authenticated journal plus live file/Git state. It validates all
file preimages and rejects unknown file content before mutation. Recovery checks
Git guards before rolling files back in reverse order. A failure leaves status
`recovering` for a fresh preview/retry. Later Git edits are refused by library
recovery; a preview alone does not prove all Git guards will pass. Known rename /
mode-update intermediate states are accepted. Recovery can also undo a completed
transaction and can be repeated after successful rollback. New empty directories,
imported Git objects and ordinary branch reflog entries can remain. Do not promise
byte-for-byte restoration of the entire `.git` directory.

Core integration fixtures are in `crates/bunker/tests/git_integration.rs`; run
`cargo test -p bunker --test git_integration`. The parent must wire the chunk helper into all dependency consumers, sanitize MCP
Git summaries/errors, expose local recovery commands, and route host expiry
checks through `restore_with_authorization`. The full frozen plan must include
`prior_config_fingerprint` as well as the refs/index effects.
