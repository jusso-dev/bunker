# Authenticated host session routing

Authenticated host routing is an explicit local opt-in. It uses the enrolled host's
mTLS identity, fetches effective policy for every invocation, and requires both
`session_handler = true` in the host TOML configuration and `endOfSession: true`
in the authenticated policy. A policy requiring session capture also fails the
ordinary host cycle when no local handler binding is configured. Setting the flag
attests that the operator has arranged a wrapper or handler; it does not install
an agent hook or prove that the agent invokes it.

The existing standalone `session-end`, `session-run`, and `hook-claude` routes
remain available. To route through the host, pass `--host-config` and exactly one
`--workspace`; do not pass `--policy`. The repository must be the daemon's
repository for that host/workspace. The authenticated host scheduler remains
bound to one host and one canonical workspace per repository.

```sh
bunker --repo /absolute/repository session-end \
  --host-config /absolute/host.toml --workspace /absolute/workspace \
  --agent codex --session-id session-unique-id

bunker --repo /absolute/repository session-run \
  --host-config /absolute/host.toml --workspace /absolute/workspace \
  --agent codex --session-id session-unique-id -- /absolute/agent argument

bunker --repo /absolute/repository hook-claude \
  --host-config /absolute/host.toml --workspace /absolute/workspace \
  --home /absolute/home
```

The wrapper launches a trusted absolute executable with separate arguments. It
inserts no shell. It acquires the repository only when the child finishes, then
calls the authenticated session handler; the daemon acquires it only during a
cycle. Concurrent access uses repository exclusion. The wrapper preserves a
failed child's exit status or cancellation status even if backup also fails.
A successful child with failed/pending backup exits unsuccessfully.

The hook command produces a reviewable plan; apply it with its `--confirm` value.
Host hook plans contain only fixed Bunker arguments and explicit filesystem
references. Claude input supplies only a validated session ID and SessionEnd
event; transcript paths, payload working directories, and other fields never
select capture roots or commands. `--home` selects where to edit Claude settings.
Host setup capture uses only `setup_home` from the host configuration, when set,
and filters it to the event's agent. Native Claude exec-form acceptance remains
unverified; the local wrapper is the tested lifecycle path. Other agents use the
wrapper or explicit session-end invocation. SIGKILL or power loss cannot run an
exit callback. Host wrappers require an explicit `--session-id` before spawning
the child so a failed event can always be retried with the same ID. Standalone
wrappers retain their generated-ID behavior.

## Durability and retry behavior

The encrypted `host/schedule` stores an intent before workspace capture. Identity
is derived from host, agent, and session ID within the repository's fixed
workspace binding. Raw session IDs are not copied into host manifests or reports.
The workspace manifest records the derived identity. If the process stops after
publishing that manifest but before updating the ledger, a same-ID retry verifies
and reuses it. A completed event is never recaptured, even if workspace files
later change. Different agents have distinct session identities.

Workspace capture, comparison, and delivery state are persisted before optional
setup capture. A setup failure does not hide a successful workspace snapshot
from delivery. Setup retries reuse the persisted workspace identity and original
policy/home binding. A changed policy or setup home leaves the session incomplete;
restore the original binding and retry the same ID. No pending session is silently
cancelled, superseded, or redirected to a different home. New capture always
requires a fresh policy fetch; revocation, invalid policy, and fetch failures
fail closed.

Session captures do not reset the periodic workspace timer, pending periodic
setup work, or probe schedule. They advance the shared authenticated comparison
baseline and use its durable comparison/alert outbox. Existing probe evidence is
included in shared delivery and retained if delivery fails. The daemon can drain
already captured session results and acknowledge complete sessions; incomplete
session capture/setup requires an explicit same-ID retry. Before periodic capture,
the daemon reconciles any already-published session workspace manifest and its
original comparison baseline. An intent that has not published a manifest leaves
periodic capture independent; a later session retry durably binds the then-current
baseline before capturing. Daemon reports include pending-session and error counts.

The outbox survives restarts and ambiguous responses. Snapshot, session, alert,
and evidence identities remain stable on replay. Only a successful acknowledgement
of the complete returned outbox clears it; partial delivery can be repeated.
Local reports distinguish `capture_complete`, `delivery_complete`, and
`retry_required`. Errors are sanitized. `delivery_complete` describes the current
outbox attempt, not proof that incomplete capture succeeded. The CLI prints the
report and fails when retry is required. Policy/authentication failures before
the callback return an error without an accepted-event report.

## Bounds and maintenance

The shared outboxes remain bounded at 256 snapshots, 512 alerts, and 16 evidence
records. Session admission additionally allows at most 16 active events and 4096
active events plus completed receipts, within the schedule's 1 MiB encrypted-file
limit. Byte capacity can be reached before record count. Setup reserves capacity
for discovery's maximum 64 scopes before publishing. Capacity exhaustion is an
explicit failure/backpressure condition; it never evicts a receipt or pending
delivery. Retry after delivery drains the outbox. A full permanent receipt ledger
requires operator archival and a new repository; there is no automatic receipt
expiry or reset command in this implementation.

Maintenance validates the same typed state as the runtime and pins all recorded
session workspace/setup snapshots, including completed receipts. Unfinished
sessions fail maintenance closed because a crash may have published an as-yet
unrecorded workspace or setup manifest. Retry those sessions first. Permanent
receipt pins intentionally limit reclamation; retention compliance is not claimed.
Normal daemon captures, authenticated Git comparisons, setup scheduling, and
restore-probe evidence continue to use their existing paths. No live provider
acceptance or whole-v1 completion is claimed; issue #26 remains deferred.
