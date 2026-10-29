# Existing global setup capture and session integration

This captures existing, explicitly selected agent configuration and assets. It
covers the five discovery adapters (Claude Code, Cursor, Codex, GitHub Copilot,
and Kiro), using their fixture-backed known paths. It does not install agents,
provision a new machine, rebuild MCP services, authenticate providers, or boot
agents. **Issue #26 remains explicitly deferred.**

## Capture and encrypted scope mapping

`Repository::snapshot_setup(context, policy, session, trigger)` returns one
`Manifest` per discovered source root. It intentionally ignores
`context.workspace_roots`: regular workspace capture remains `snapshot`.
Callers supply an explicit HOME and optional editor config/app-data roots through
`DiscoveryContext`; the library never reads ambient HOME or runs discovered code.
Custom `CODEX_HOME`/`COPILOT_HOME`, remote editor profiles, and arbitrary managed
configuration locations outside the current adapters are not inferred.

Candidates from all adapters are grouped and deduplicated per root, then passed
to `prepare_files` once per root. Only the resulting bytes are chunked. There is
no plaintext staging directory. Known configuration paths are structurally
sanitized; other files, including binary skill assets and scripts, retain their
bytes. Executable status comes from the same securely opened file descriptor.
`FileEntry.sanitized` and `secret_references` survive capture and replication.
These are references/placeholders, not stored credential values or automatic
secret-vault lookups. Unrecognized secrets in ordinary prose/assets cannot be
reliably identified: choose policy exclusions for additional sensitive assets.

Discovery hard exclusions, explicit exclusions, default artifact exclusions and
`default_includes` apply. Includes cannot override credential exclusions. The
core policy supplies per-file and aggregate byte caps; known-config parsing also
has its independent 1 MiB limit. Source and sanitized totals across *all* roots
must fit the aggregate cap. Each root has at most 10,000 captured files. There
are at most 64 roots. Unsafe, malformed, unreadable, nonportable, or excluded files
produce per-file diagnostics; valid siblings remain eligible. Repository files
are excluded from setup candidates. Symlink components, traversal, case aliases,
and canonical Unicode aliases are refused by the preparation layer. Changes
observed during a read are skipped. This is a best-effort file capture, not a
filesystem-wide atomic read transaction; quiesce writers when consistency matters.

`Manifest.setup: Option<SetupScope>` contains the source root, adapter IDs, a
capture-group ID, group index/count, and optional keyed trigger identity. It is
inside the authenticated encrypted manifest and therefore travels with existing
replication/recovery. No sidecar with plaintext origin paths is required. Origin
metadata accepts absolute foreign-platform paths as inert metadata after DR.
It never controls restore writes. Local CLI output may show operator-selected
paths, but host/control-plane publishing must use its metadata allowlist and must
not upload `setup`, source paths, file content, or secret references.

All roots and all manifest encodings are prepared before any manifest publication.
Publication of multiple manifests is not an atomic filesystem transaction: an
I/O failure/crash can leave an incomplete group. Group index/count make that
partial capture visible. Retry accepts only a complete matching group; an
incomplete group is captured again under a new group ID. Earlier partial
manifests remain visible for maintenance. The returned manifests and diagnostics
are the evidence of capture; an empty result is not evidence of an agent install.

## Explicit restore review

`plan_setup(id, destination, selection)` requires a setup manifest and an existing
explicit destination with no symlink components. It rejects ordinary workspace
snapshots and setup manifests containing Git state. `restore_setup` requires the
fresh local plan confirmation and delegates to core transactional restore.
Neither API chooses the source root as a destination. Files remain relative to
the captured scope; for example a HOME-scope manifest restores `.codex/config.toml`
under the explicit target HOME, while an editor-scope manifest restores
`Cursor/User/settings.json` under the explicit target editor directory.

Existing sanitized settings cannot be overwritten without the existing
`allow_rebind_overwrite` opt-in. New placeholders still need deliberate rebinding
or reauthentication before use. Restored scripts/hooks are never executed by
capture or restore. Review/confirmation is a local operator workflow, not an
independent security boundary against another process running as the same user.

## Session-end triggers and deduplication

`SessionEnd { agent, session_id }` accepts a bounded ASCII identifier.
`SessionEnd::from_claude_input(reader)` reads at most 64 KiB and requires
`hook_event_name: "SessionEnd"`. It ignores payload `cwd`, transcript paths,
commands, and other fields. Parsing errors omit source content. A local event is
not proof of provider authentication or permission to restore.

`Repository::snapshot_setup_for_session(context, policy, event)` derives a keyed
identity from the agent/session and explicit global context. Complete groups are
reused across retries, process restarts, and encrypted DR recovery; a repository
lock serializes competing Bunker calls. Different agents/sessions do not collide.
Workspace session snapshots remain the caller's responsibility.

For scheduled work,
`snapshot_setup_for_schedule(context, policy, workspace_snapshot_id)` uses a
separate trigger domain and the already-published workspace snapshot ID. It does
not fabricate an agent session event. The `_filtered` variant takes an additional
`Option<AgentId>` and captures only that adapter when supplied. Filtered
manifests identify that adapter in `manifest.agent`; roots shared by multiple
adapters use `global_setup` with the precise list in encrypted `setup.agents`.
The filter is part of the deduplication identity.

## Explicit native Claude hook

`HookInvocation` carries an existing Bunker executable, repository, HOME,
optional policy/key-provider config paths, and explicit workspace roots. Workspace
roots must be unique canonical existing directories, disjoint from the repository.
No secret value enters generated arguments. Key-provider config paths are
references, not key material; the host must supply the supported unlock source.
The handler uses the documented **exec form** (`command` plus `args`) and a
`SessionEnd` entry, with a 60-second timeout. There is no generated shell command.
Each workspace becomes a separate `--workspace` argument; payload `cwd` is never
trusted. Deploy only to a Claude version supporting that documented format.

`plan_claude_hook(invocation, enable)` returns a local review plan without writing
or running anything. It preserves unrelated JSON values and hooks.
`apply_claude_hook(plan, confirmation)` refuses stale settings or modified plans.
Enabling twice is idempotent. Disabling with the same invocation removes only the
exact generated entry, preserving other hooks. `rollback_claude_hook(plan)` can
restore the original bytes (or remove the newly created settings file) while the
result is unchanged. Empty directories may remain. After independent settings
edits, use a fresh disable plan instead of rollback. Removing a hook after changing
its executable/repository/workspace options requires its original invocation.

Plans retain original configuration only in memory, do not serialize it, and
redact it from Debug output. Do not print private configuration buffers. Settings
may be reformatted when an edit is applied; immediate rollback restores original
bytes. Installation never executes existing hook entries. Quiesce other settings
writers during review/apply: the freshness comparison is not an OS-wide writer
lock. Timeout, SIGKILL, and power loss can interrupt a native callback; scheduled
capture remains the fallback. Installing a hook does not verify actual agent
launch or callback delivery.

The current documented native format was verified on 2026-10-29 against
[Claude Code's hooks reference](https://code.claude.com/docs/en/hooks), specifically
SessionEnd, exec form, command arguments, and timeout behavior. No native
session-end hook is installed for Cursor, Codex, Copilot, or Kiro by this module.
This is a bounded implementation choice, not a claim that those products lack
all lifecycle hooks. Turn-complete notifications are not treated as session ends.

## Wrapper fallback

`run_session(&mut Command, &AtomicBool, snapshot_callback)` runs a trusted existing
absolute executable, with arguments supplied separately. The library adds no
shell, reads no agent hook files, and logs no command/argument/environment values.
Pass credentials through the supported private environment/key-provider channel,
not command-line arguments. The executable must not be Bunker itself; a child
environment marker also rejects recursive Bunker wrappers.

The callback is attempted after success, nonzero exit, signal exit, spawn failure,
or cancellation. `SessionOutcome` reports process outcome and snapshot result
separately, so a failed backup does not hide a failed agent. The caller installs
signal handling and sets the cancellation flag. Cancellation kills and reaps the
direct child; detached descendants are not guaranteed to stop. The child retains
the terminal process group so interactive stdin still works. Uncatchable SIGKILL,
power loss, and process abort cannot run an exit callback. Arguments are trusted
operator input; this API is not a sandbox for untrusted executables.

## Hourly daemon opt-in

The existing default interval is one hour. Add an explicit absolute path to the
operator's policy to opt in:

```toml
setup_home = "/explicit/existing/home"
```

No field means no global scan. A successful workspace snapshot first persists its
ID and a `pending_setup` record holding the policy/root selected for that capture.
Workspace detection completes independently. Setup capture and its completion
audit have separate durable retry counters/backoff and do not block later due
workspace snapshots. Before the next workspace is due, retrying setup does not
take another workspace snapshot. Setup groups deduplicate against the workspace
ID even if publication succeeded before an audit failure. The pending queue is a
single coalescing slot: a newer workspace replaces unfinished setup work with a
`superseded_pending_setup` diagnostic identifying the old workspace snapshot.
Local diagnostics retain the latest 64 records. A changed operator policy cancels
a stale pending job with a `setup_policy_changed` diagnostic before any scan;
subsequent workspace captures use the new policy. A missing/aliased configured HOME fails explicitly; it is
not reported as successful empty capture. The local schedule file contains
operator policy paths and must stay local; it is not a replicated source-scope
artifact or a control-plane payload.

## Host bridge scheduling

The host bridge's explicit `setup_home` configuration uses the same schedule
capture API, filtered to its configured agent. A stored setup job is bound to the
HOME, agent, and effective policy. Changes cancel that job before scanning; legacy
unbound pending jobs are cancelled rather than assigned a new root. Setup failures
have independent durable backoff and do not prevent a successfully captured
workspace from being returned for delivery. New due workspace captures continue
while outbox capacity remains, even if older snapshots are awaiting delivery.

The encrypted host outbox holds at most 256 snapshot IDs and 512 alerts. A full
outbox records `delivery_outbox_full_capture_deferred` and returns the existing
deliveries; new capture resumes after delivery frees capacity. Queued IDs/alerts
are never dropped to make room. Setup groups that cannot yet fit remain retryable
and deduplicate from their existing encrypted manifests. One pending setup slot
coalesces at each new workspace capture, recording the superseded workspace ID.
The latest 64 local scheduling diagnostics are retained. Host output reports
pending setup/error status without publishing source paths or scope metadata.
Filesystem/persistence failures still fail the cycle; this does not claim delivery
can succeed when durable local state cannot be written.

## Configuration references and verification limits

The discovery path matrix remains in [discovery.md](discovery.md). Configuration
references checked against current provider documentation on 2026-10-29:

- [Claude settings](https://code.claude.com/docs/en/hooks): user settings and hook configuration.
- [Cursor MCP](https://cursor.com/docs/mcp): MCP configuration.
- [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference): user `config.toml` and notification configuration.
- [Copilot CLI MCP](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers): `~/.copilot/mcp-config.json`; VS Code MCP configuration is separate.
- [Kiro MCP configuration](https://kiro.dev/docs/mcp/configuration/): user/workspace `.kiro/settings/mcp.json`.

`tests/setup_hooks.rs` uses disposable HOME/workspace/repository roots and the
five-agent discovery fixture, a memory storage backend, and fixed fixture
executables. It checks encrypted scope recovery, byte preservation, skips, caps,
secret rebinding, explicit destinations, dedupe, scheduler retry, and hook
installation/reversal. The scoped `host_runtime` unit tests exercise durable
outbox/retry/cancellation behavior without enrollment or network requests. No live
configuration is inspected or changed. No
real-agent boot, MCP connectivity, installed-version capability, Windows runtime,
or independent authorization probe is claimed by these fixtures.
