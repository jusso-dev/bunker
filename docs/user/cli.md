# CLI reference

Run `bunker --help` and `bunker COMMAND --help` for the installed revision. A test (`cli_reference_documents_every_subcommand_and_long_flag`) walks the built command tree and fails when a subcommand has no row on this page or a long flag is missing from that command's row.

## Global flags

| Flag | Behavior |
| --- | --- |
| `--repo PATH` | Repository location (default `.bunker-repository`). Always pass an explicit repository outside the workspace. |
| `--policy PATH` | Optional local policy TOML. Host mode takes policy from the authenticated host configuration instead. |
| `--key-config PATH` | Explicit AWS KMS, Azure Key Vault or GCP KMS configuration instead of `BUNKER_PASSPHRASE`. See [key management](../key-management.md). |
| `--log-level LEVEL` | `error`, `warn`, `info` (default) or `debug`; overrides `BUNKER_LOG`. Invalid levels are rejected. |
| `--help`, `--version` | Help and version; neither opens a repository. |

Most operations need `BUNKER_PASSPHRASE` or `--key-config`; `discover`, `status`, `policy-defaults`, `consumer-rebind`, `host enroll` and help do not.

## Repository and snapshots

| Command | Arguments and behavior |
| --- | --- |
| `init` | Creates a local repository at `--repo`; refuses an existing repository. |
| `discover` | Optional `--workspace PATH` (repeatable) and `--home PATH` overrides; reports discovered configuration using platform defaults otherwise. Each agent result keeps `items`, `workspace_roots`, `session_signals` and `excluded`, plus `by_category`: item paths grouped by type (`mcp_config`, `skill`, `rule`, `sub_agent`, `hook`, `memory`, `settings`). Does not create a snapshot. |
| `snapshot` | Required `--workspace PATH`; optional `--agent NAME`, `--session LABEL`, `--trigger LABEL` (default `manual`). Captures eligible files under the workspace with the local policy. `--trigger session-start --session ID` records a manual pre-session baseline for session rollback. |
| `snapshot-setup` | Required `--home PATH`; optional `--session LABEL`. Captures existing discovered global agent roots with encrypted scope mapping. |
| `list` | Lists decrypted snapshot metadata. Treat output as sensitive. |
| `verify SNAPSHOT` | Authenticates referenced objects and verifies file hashes. |
| `policy-defaults` | Prints current local-policy defaults in TOML. |
| `status` | Queries the running standalone or host daemon through its local Unix status socket; not an end-to-end cloud health or restore-readiness check. |
| `help [COMMAND]` | Shows command help without opening a repository. |

## Review and restore

| Command | Arguments and behavior |
| --- | --- |
| `diff SNAPSHOT` | Required `--workspace PATH`; optional `--file RELATIVE_PATH`. Prints planned creates/replacements and a confirmation bound to the plan. |
| `diff --session ID` | Session rollback preview (instead of `SNAPSHOT`). Prints the rollback summary (`baseline_snapshot`, `session_end_snapshot`, `rollback_snapshot`, `restored_paths`, `created_during_session`) and then the plan. |
| `restore SNAPSHOT` | Required `--workspace PATH`; optional `--file RELATIVE_PATH` (as for `diff`); without `--confirm TOKEN`, only previews. With the reviewed token, applies the plan. Before overwriting current files or Git state, captures a safety snapshot with trigger `pre-restore` and reports its ID as `pre_restore_snapshot`; skips it when there is no existing state to replace. Replacing settings containing unbound secret placeholders also requires explicit `--allow-rebind-overwrite`. |
| `restore --session ID` | Rolls back files changed or removed during that agent session to their pre-session content, with the same preview, `--confirm TOKEN` and stale-token refusal as any restore. |
| `restore-test SNAPSHOT` | Restores into a disposable directory and records file-integrity evidence. Add `--workspace SOURCE --probe-config PATH` to run explicitly configured isolated boot/MCP probes; runtime/configuration paths must be outside the source workspace and repository. |
| `restore-journal ID` | Inspects the encrypted transaction journal for an interrupted or completed restore. Preserve interrupted transaction data before attempting recovery. |
| `restore-recover ID` | Previews guarded rollback of an interrupted restore transaction; apply with `--confirm TOKEN`. |

Session rollback needs a pre-session baseline bound to the same session ID: a `session-start` workspace snapshot (taken automatically by standalone `session-run`, or manually with `snapshot --trigger session-start`) and a `session-end` snapshot. Bunker never infers a baseline from unrelated snapshots. The rollback is stored as a derived `session-rollback` snapshot that references existing encrypted chunks, so its ID (and the confirmation) is stable between `diff` and `restore`. Restore never deletes: files created during the session are listed in `created_during_session` for manual review. Sessions that captured several workspaces are refused as ambiguous. Host-mode sessions do not yet record a pre-session baseline.

## Requests and MCP

| Command | Arguments and behavior |
| --- | --- |
| `mcp` | Required `--workspace PATH`. Serves the JSON-RPC tools `list_snapshots`, `diff` and `request_restore` on standard input/output. Nothing exposed through MCP deletes or alters backups. With `--host-config PATH`, requests use the production approval bridge. |
| `request ID` | Shows a stored MCP restore request for human review. |
| `approve ID` | Requires `--confirm TOKEN` and still refuses execution: independent human authorization is not integrated locally. A local preview digest is not proof of human identity. |
| `deny ID` | Records a denial of the stored request. |
| `prune-requests` | Optional `--limit N` (default 1000). Operator-only cleanup of decided/expired requests; never exposed by MCP. |

## Session capture and hooks

| Command | Arguments and behavior |
| --- | --- |
| `session-end` | Required `--agent NAME` and `--home PATH` (unless `--host-config PATH`); `--workspace PATH` (repeatable); optional `--session-id ID`. Captures configured roots after a session. Without `--session-id`, Claude Code's native `SessionEnd` hook payload is read from standard input; its untrusted `cwd` and transcript path are ignored. |
| `session-run` | Same `--agent`, `--home`, `--host-config`, `--workspace` and `--session-id` flags, then `-- /absolute/program args`. Trusted wrapper fallback: in standalone mode it takes a `session-start` snapshot of each workspace, runs the program, captures after exit or cancellation, and exits with the program's status. The report names the `session` ID (generated when `--session-id` is omitted) for `restore --session`. Host mode requires `--session-id`. |
| `hook-claude` | Required `--home PATH`; `--workspace PATH` (repeatable); optional `--host-config PATH`. Previews a reversible Claude `SessionEnd` hook; apply with its `--confirm TOKEN`, remove with `--disable`. |

## Maintenance and keys

| Command | Arguments and behavior |
| --- | --- |
| `maintenance-plan` | Required `--output PATH`. Writes a reviewed local retention/orphan cleanup plan; unavailable through MCP. |
| `maintenance-execute` | Required `--plan PATH --confirm TOKEN`. Executes the reviewed plan if policy retention is unchanged. |
| `rewrap-passphrase` | Re-wraps the same repository data key using `BUNKER_NEW_PASSPHRASE`; also needs the old `BUNKER_PASSPHRASE`. `rotate-key` remains a compatibility alias. This does not rotate the data key or revoke old copies; the stable remote chunk namespace is unchanged, but the next replication returns a new recovery locator. |
| `rewrap-key` | Required `--new-key-config PATH`. Rewraps the same data key under a managed key. |
| `escrow` | Required `--output PATH`. Exports an encrypted recovery envelope; `BUNKER_RECOVERY_KEY` holds 64 hex digits. |
| `escrow-unlock` | Required `--input PATH`. Unlocks with an escrow envelope and replaces the key wrapper with `--key-config` or `BUNKER_PASSPHRASE`. |

## Replication and recovery

| Command | Arguments and behavior |
| --- | --- |
| `replicate` | Required `--storage PATH`; optional `--snapshot ID`. Uploads encrypted repository objects using a TOML storage configuration, verifies readback, and returns a pinned recovery locator. Immutable S3/Azure require `--retain-days N --report PATH`; optional `--dr-storage PATH` creates the same protected inventory on an independent backend. Drive/OneDrive require `--report PATH` and `--consumer-state DIR` (private OAuth rotation and exact-ID evidence, outside the repository). |
| `protection-report CHECKPOINT` | Required `--output PATH`. Re-exports the encrypted local protected-replication report after an external report-write failure. |
| `consumer-report CHECKPOINT` | Required `--storage PATH --consumer-state DIR --output PATH`. Re-exports a Drive/OneDrive recovery report from private consumer state. |
| `consumer-rebind` | Required `--storage PATH --consumer-state DIR`. Rebinds uncertain OAuth state from the configured private environment reference. |
| `recover` | Required `--storage PATH --namespace ID`; downloads and verifies a remote repository into the non-existent destination `--repo PATH`. Optional `--snapshot ID` isolates one snapshot; `--legacy-unindexed` recovers old unindexed backups (inventory completeness unproven); `--escrow PATH` supplies the recovery envelope; `--protection-report PATH` uses pinned protected versions; `--consumer-report PATH` with `--consumer-state DIR` recovers Drive/OneDrive copies by saved object IDs. This recovers the repository; use `restore` for workspace files. |

## Scheduling and host integration

| Command | Arguments and behavior |
| --- | --- |
| `daemon` | Required `--workspace PATH`. Runs scheduled local snapshots; `--once` performs one cycle and exits. `--probe-config PATH` enables standalone scheduled restore probes. `--host-config PATH` runs the authenticated host runtime instead, with `--agent NAME` (default `codex`) labelling captures. |
| `host` | Required `--config PATH` for every host action below. See [host integration](../host-integration.md). |
| `host enroll` | One-use enrollment token from `--token-file PATH` or the environment variable named by `--token-env NAME` (default `BUNKER_ENROLLMENT_TOKEN`); never pass the token value itself. |
| `host run` | Required `--workspace PATH`; optional `--agent NAME` (default `codex`) and `--once`. Authenticated host cycle against the control plane. |
| `host request-restore` | `SNAPSHOT` or `--session ID`, required `--workspace PATH`, optional `--file RELATIVE_PATH`. Creates a remote human-review request (kind `file`, `workspace` or `session`) and prints the local preview; never approves or executes. |
| `host review-restore ID` | Shows the saved local preview of a bridge request. |
| `host execute-restore ID` | Executes an approved request once after rechecking authorization, expiry and destination state. |

See the [agent guide](agents.md) for discovery coverage. Seeing an agent in discovery does not mean its entire home-directory setup has been included in a workspace snapshot.

Commands return a nonzero exit code on errors. Restore without confirmation is a successful preview, not a completed restore. Review the output before reporting completion. Repository operations can contend with a running daemon; stop the service before maintenance if the CLI reports a lock conflict.

Each standalone schedule binds to one canonical workspace. Reusing that schedule
with another workspace is refused, including restore-probe execution. Legacy
unbound schedules start a new comparison baseline when first bound, while keeping
queued historical work. Use a separate repository/schedule for another source.

Legacy local `approve` remains disabled. With `mcp --host-config PATH --workspace PATH`,
requests use the production bridge; a separately authenticated human approves the
saved plan in the UI, and the host rechecks authorization at mutation boundaries.

Daemon and host diagnostics are JSON lines on stderr with `time`, `level`, `message`, and event fields. Set global `--log-level error|warn|info|debug` or `BUNKER_LOG`; the flag takes precedence and the default is `info`. Invalid levels are rejected. Debug scheduler/cycle records are emitted only at `debug`.

Host-approved `execute-restore` also captures and reports `pre_restore_snapshot` before destructive restore. Safety snapshots use the local snapshot exclusions, sanitization, and size limits (the default local policy for host-approved restores). Snapshot failure stops the restore before writes. Secret rebindings still require separate custody; safety snapshots do not retain excluded secrets.
