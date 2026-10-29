# Local quick start

Use Rust 1.91 or newer. From a checkout, run `cargo build --locked --package bunker` and use `target/debug/bunker` (Windows: `target\debug\bunker.exe`), or [install a locally built package](install.md). The commands below assume `bunker` is on `PATH` and a POSIX shell.

Create a disposable workspace and a separate repository. Repositories must be outside the workspace. Do not place a repository under the directory being backed up.

```sh
mkdir -p "$HOME/bunker-lab/workspace"
printf 'first version\n' > "$HOME/bunker-lab/workspace/notes.txt"
```

Set `BUNKER_PASSPHRASE` from your secret manager, with at least 12 bytes. Do not type its value into shell history, save it in a policy, or pass it on the command line. For a Bash interactive lab, use a hidden prompt:

```bash
read -r -s -p 'Repository passphrase: ' BUNKER_PASSPHRASE
printf '\n'
export BUNKER_PASSPHRASE
```

Store the passphrase separately from the repository using your normal credential recovery process. Losing it makes the encrypted repository unrecoverable; no KMS recovery or escrow is implemented.

```sh
bunker init --repo "$HOME/bunker-lab/repository"
bunker snapshot --repo "$HOME/bunker-lab/repository" --workspace "$HOME/bunker-lab/workspace"
bunker list --repo "$HOME/bunker-lab/repository"
```

Save the snapshot's `id` as `SNAPSHOT_ID`. Snapshot output can contain sensitive filenames and metadata; avoid public logs. Change the example file, then preview:

```sh
printf 'changed version\n' > "$HOME/bunker-lab/workspace/notes.txt"
bunker diff "$SNAPSHOT_ID" --repo "$HOME/bunker-lab/repository" --workspace "$HOME/bunker-lab/workspace"
bunker restore "$SNAPSHOT_ID" --repo "$HOME/bunker-lab/repository" --workspace "$HOME/bunker-lab/workspace"
```

The second command prints the plan without changing files. Read every path and action. Only after reviewing it, set `CONFIRMATION` to the plan's `confirmation` and apply that exact plan:

```sh
bunker restore "$SNAPSHOT_ID" --repo "$HOME/bunker-lab/repository" --workspace "$HOME/bunker-lab/workspace" --confirm "$CONFIRMATION"
cat "$HOME/bunker-lab/workspace/notes.txt"
bunker verify "$SNAPSHOT_ID" --repo "$HOME/bunker-lab/repository"
bunker restore-test "$SNAPSHOT_ID" --repo "$HOME/bunker-lab/repository"
unset BUNKER_PASSPHRASE CONFIRMATION
```

Expected file content: `first version`. The restore-test report checks file restoration; agent boot and MCP connectivity are explicitly `not_run`. Follow the [full runbook](restore.md) for production recovery decisions and acceptance gaps.
