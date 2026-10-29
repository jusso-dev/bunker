# Restore and disaster recovery runbook

## Prepare and preview

1. Stop agent edits and pause the daemon. Identify the repository, affected workspace and desired snapshot using `bunker list --repo PATH`. Preserve a separate copy of the current workspace if needed for investigation.
2. Supply the repository passphrase through your secret manager. Run `bunker verify SNAPSHOT --repo PATH`; stop on corruption, missing objects or authentication failure.
3. Prefer restoring into a new, empty directory first. Run `bunker diff SNAPSHOT --repo PATH --workspace DESTINATION`. For one file, add `--file RELATIVE_PATH` to both preview and restore.
4. Inspect the destination, snapshot, every path and action, content preview where available, before/after hashes, and secret-rebinding warnings. Content previews are redacted and may be truncated; inspect a separately restored copy where the preview is insufficient. The restore is additive/replacing: extra destination files are not automatically deleted.
5. Run `bunker restore SNAPSHOT --repo PATH --workspace DESTINATION` without confirmation. This is a preview and must not change files.

## Approve and verify

After human review, run the same restore with `--confirm TOKEN`, using the exact `confirmation` from the current plan. Changing the destination content or selected file invalidates an earlier approval; preview again rather than reusing a stale token.

Verify file content, expected executable permissions and application behavior. File integrity alone is not agent readiness. Review restored hooks, rules, MCP command lines and dependencies before executing them. Re-link secret references through the target vault. Test agent startup and each intended MCP in an isolated environment with restricted credentials; record the results without secrets or customer data.

Settings with unbound secret placeholders are flagged in the plan. Overwriting live settings with these placeholders is refused unless you explicitly supply `--allow-rebind-overwrite` after reviewing the impact and arranging reauthentication. This option does not recover original secret values. If a restore is interrupted, retain its transaction ID and inspect `bunker restore-journal ID --repo PATH`; preserve the journal and staged preimages before retrying or manually repairing the workspace.

Run `bunker restore-test SNAPSHOT --repo PATH` to exercise a temporary-directory file restore. The report deliberately marks agent boot and MCP connectivity as `not_run`. Archive the report, snapshot ID, reviewed plan, operator identity, scope, timestamp and measured recovery time as evidence. Treat paths and metadata as sensitive.

For MCP requests, inspect `bunker request ID --repo PATH` or deny with `bunker deny ID --repo PATH`. **Request execution is unavailable:** `bunker approve` refuses execution until independently authenticated human authorization is integrated. MCP exposes request creation rather than a restore or delete operation. Its responses do not grant an execution capability. A process running as the repository owner still has that owner's filesystem privileges; see [security](security.md).

## Recover after losing the repository

Use a separately stored passphrase, storage configuration and recorded replication namespace. Supply provider credentials via environment references. Run `bunker recover --repo NEW_PATH --storage storage.toml --namespace NAMESPACE`. `NEW_PATH` must not exist. Recovery verifies downloaded snapshots and chunks before publishing the local repository. Then follow the preview-and-restore steps above using the recovered repository.

Keep complete encrypted repository copies, including the encrypted header and all referenced objects. Replication does not currently copy local audit logs, pending requests or scheduler state. Back those up separately if required. No immutable DR copy, provider-side retention or escrow is guaranteed. Test recovery from the intended secondary storage, using the exact recovery credentials available during an outage.

If credentials are lost, seek your approved credential recovery process; Bunker cannot decrypt the repository without the passphrase. If tampering is detected, preserve the affected copy and use an independently verified copy. Do not silently skip damaged files or overwrite corrupt remote objects.

## Repeatable lab check

Run `python3 packaging/scripts/smoke_restore.py --binary target/debug/bunker` after building the CLI. It uses a temporary workspace and a freshly generated passphrase, checks preview without writes, stale-confirmation refusal, restored bytes, verification, and local-filesystem replication/recovery. It deletes its disposable lab on exit. Windows uses `target/debug/bunker.exe`.

The packaging/documentation member ran this check independently of the core implementation on 2026-10-29; results are recorded in the [evidence matrix](../issue-evidence.md). A separate person who did not author this runbook must still perform and sign off the procedure to meet issue #25's exact acceptance criterion. No such sign-off is asserted here.
