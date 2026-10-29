# CLI reference

Run `bunker --help` and `bunker COMMAND --help` for the installed revision. Global flags are `--repo PATH` (default `.bunker-repository`), `--policy PATH` (optional TOML), `--help`, and `--version`. Always pass an explicit repository outside the workspace. Most operations need `BUNKER_PASSPHRASE`; `discover`, `status`, `policy-defaults`, and help do not.

| Command | Arguments and behavior |
| --- | --- |
| `init` | Creates a local repository at `--repo`; refuses an existing repository. |
| `discover` | Optional `--workspace PATH` and `--home PATH` overrides; reports discovered configuration using platform defaults otherwise. Does not create a snapshot. |
| `snapshot` | Required `--workspace PATH`; optional `--agent NAME`, `--session LABEL`, `--trigger LABEL` (default `manual`). Captures eligible files under the workspace with the local policy. |
| `list` | Lists decrypted snapshot metadata. Treat output as sensitive. |
| `diff SNAPSHOT` | Required `--workspace PATH`; optional `--file RELATIVE_PATH`. Prints planned creates/replacements and a confirmation bound to the plan. |
| `restore SNAPSHOT` | Same destination and file flags as `diff`; without `--confirm TOKEN`, only previews. With the reviewed token, applies the plan. Replacing settings containing unbound secret placeholders also requires explicit `--allow-rebind-overwrite`. |
| `verify SNAPSHOT` | Authenticates referenced objects and verifies file hashes. |
| `restore-test SNAPSHOT` | Restores into a disposable directory and records file-integrity evidence. Add `--workspace SOURCE --probe-config PATH` to run explicitly configured isolated boot/MCP probes; runtime/configuration paths must be outside the source workspace and repository. |
| `rewrap-passphrase` | Re-wraps the same repository data key using `BUNKER_NEW_PASSPHRASE`; also needs the old `BUNKER_PASSPHRASE`. `rotate-key` remains a compatibility alias. This does not rotate the data key or revoke old copies; the stable remote chunk namespace is unchanged, but the next replication returns a new recovery locator. |
| `restore-journal ID` | Inspects the encrypted transaction journal for an interrupted or completed restore. Preserve interrupted transaction data before attempting recovery. |
| `request ID` | Shows a stored MCP restore request for human review. |
| `approve ID --confirm TOKEN` | Refuses execution: independent human authorization is not integrated. A local preview digest is not proof of human identity. |
| `deny ID` | Records a denial of the stored request. |
| `replicate --storage PATH` | Uploads encrypted repository objects using a TOML storage configuration, verifies readback, and returns a pinned repository/header/checkpoint recovery locator. For immutable S3/Azure require `--retain-days N --report PATH`; optional `--dr-storage PATH` creates the same protected inventory on an independent backend. |
| `recover --storage PATH --namespace ID` | Downloads and verifies a remote repository into the non-existent destination `--repo PATH`. For version-pinned protected copies add `--protection-report PATH`; optional `--escrow PATH` supplies the recovery envelope. This recovers the repository; use `restore` for workspace files. |
| `daemon --workspace PATH` | Runs scheduled local snapshots; `--once` performs one cycle and exits. Reads local `--policy` if supplied. `--probe-config PATH` enables standalone scheduled restore probes; authenticated host mode uses its host configuration instead. |
| `status` | Reads local scheduler status; not an end-to-end cloud health or restore-readiness check. |
| `mcp --workspace PATH` | Serves the implemented JSON-RPC tool interface on standard input/output. Keep diagnostics and passphrases out of protocol output. |
| `policy-defaults` | Prints current local-policy defaults in TOML. |
| `help [COMMAND]` | Shows command help without opening a repository. |

See the [agent guide](agents.md) for discovery coverage. Seeing an agent in discovery does not mean its entire home-directory setup has been included in a workspace snapshot.

Commands return a nonzero exit code on errors. Restore without confirmation is a successful preview, not a completed restore. Review the output before reporting completion. Repository operations can contend with a running daemon; stop the service before maintenance if the CLI reports a lock conflict.

Each standalone schedule binds to one canonical workspace. Reusing that schedule
with another workspace is refused, including restore-probe execution. Legacy
unbound schedules start a new comparison baseline when first bound, while keeping
queued historical work. Use a separate repository/schedule for another source.

Managed repositories use global `--key-config PATH` instead of `BUNKER_PASSPHRASE`. `rewrap-key --new-key-config PATH` changes the managed wrapper; `escrow --output PATH` and `escrow-unlock --input PATH` provide explicit recovery-envelope operations. Both escrow commands obtain the separate recovery key privately from `BUNKER_RECOVERY_KEY`. See [key management](../key-management.md) for formats and custody requirements.


Additional integrated commands:

- `snapshot-setup --home PATH`: capture existing discovered global roots with encrypted scope mapping.
- `session-end --agent NAME --home PATH --workspace PATH`: capture explicitly configured roots after a session; native Claude input ignores untrusted cwd.
- `session-run --agent NAME --home PATH --workspace PATH -- /absolute/program args`: trusted wrapper fallback with capture after process exit/cancellation.
- `hook-claude --home PATH --workspace PATH`: preview a reversible hook; apply with its `--confirm` token, optionally `--disable`.
- `restore-recover ID`: preview guarded transaction rollback; apply with `--confirm`.
- `maintenance-plan --output PATH` and `maintenance-execute --plan PATH --confirm TOKEN`: reviewed local retention/orphan cleanup, unavailable through MCP.
- `prune-requests --limit N`: operator-only decided/expired request cleanup.
- `host --config PATH enroll`, `run`, `request-restore`, `review-restore`, and `execute-restore`: independently authenticated control-plane workflow. See [host integration](../host-integration.md).

Legacy local `approve` remains disabled. With `mcp --host-config PATH --workspace PATH`,
requests use the production bridge; a separately authenticated human approves the
saved plan in the UI, and the host rechecks authorization at mutation boundaries.
