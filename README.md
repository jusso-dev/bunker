# Bunker

Backup, rollback and disaster recovery for AI coding agents.

Bunker snapshots eligible workspace files and explicitly configured global agent setup, with encrypted Git branch/stash/index recovery and reviewed restores. Setup capture uses per-root encrypted scope metadata; it never automatically writes back to source locations.

> **Status: experimental implementation, not a completed v1.** Local encrypted snapshots, reviewed file restores, discovery adapters, encrypted replication, and a development control plane are implemented. Production identity, managed keys, Git recovery and version-protected S3/Azure replication are implemented with fixture coverage. Live-provider, native-agent, cross-platform and several workflow acceptance requirements remain incomplete. See [the acceptance evidence](docs/issue-evidence.md) before relying on a backup.

Start with the [local quick start](docs/user/quickstart.md), [restore runbook](docs/user/restore.md), and [security model](docs/user/security.md). Run `cargo test --workspace` and `pnpm test` from this checkout; use Rust 1.91+ and the pnpm version pinned in `package.json`.

## Why

Coding agents now edit files, run commands and rewrite config on their own. Git covers committed work, but it doesn't cover untracked files, stashes, local branches, or the agent setup itself. When an agent deletes a folder, force pushes, or quietly changes its own MCP config, you want a clean point to go back to.

## Who it's for

- Solo developers
- Development teams
- MSPs backing up client environments
- Government and enterprise

## Target scope for v1

- **Agents:** Claude Code, Cursor, Codex, GitHub Copilot and Kiro
- **Runs on:** laptops, servers and cloud VMs, CI runners, and containers
- **Backs up:** agent setup plus workspace, including untracked files, stashes and local branches. Committed git history is skipped because the remote already has it. Secrets are stored as references only.
- **Schedule:** hourly and at the end of each agent session by default, configurable in the control plane
- **Storage:** Cloudflare R2, Azure Blob, AWS S3, Google Drive, OneDrive, and local disk or NAS
- **Protection:** optional immutability per policy, a second immutable copy for DR, org keys in a KMS or Azure Key Vault with optional recovery key escrow
- **Restore:** single file, agent session, or whole workspace, always with a diff before overwrite
- **Restore testing:** scheduled sandbox restores that check the agent boots and its MCPs connect
- **Alerts:** mass deletes, force pushes and history rewrites, MCP config or skill changes, failed or missed backups
- **Compliance:** Australian data residency, Essential Eight backup mapping and ISM alignment

Rebuilding an agent from scratch on a new machine is planned for a later release.

## Planned architecture

```
 ┌───────────────────────────── host (laptop, VM, CI runner, container) ─┐
 │  bunker CLI / daemon (Rust)                                           │
 │   ├─ discovery adapters: Claude Code, Cursor, Codex, Copilot, Kiro    │
 │   ├─ snapshot engine (content-defined chunking, dedup, encryption)    │
 │   ├─ scheduler + session hooks                                        │
 │   ├─ watchers for alerts (mass delete, force push, config change)     │
 │   └─ MCP server: list, diff, restore (restore needs human approval)   │
 └──────────────┬───────────────────────────────────┬────────────────────┘
                │ encrypted chunks                  │ metadata, events
                ▼                                   ▼
   storage backends                       control plane (web UI + API)
   R2, Azure Blob, S3, Google Drive,      onboarding, policies, timeline,
   OneDrive, local disk or NAS            restore with diff, alerts,
   (+ immutable DR copy)                  restore test reports
                                                    │
                                          KMS / Azure Key Vault
```

Key points:

- Data is encrypted on the host before it leaves. The control plane never sees plaintext file contents.
- The MCP interface exposes listing, preview, and restore-request operations, with no backup-delete operation. The production host bridge executes only independently approved, saved plans; legacy local request execution remains disabled. A process with filesystem access under the same OS identity can still alter or delete repository files.
- See [docs/adr/0001-stack.md](docs/adr/0001-stack.md) for the stack choice.

## Contributing

The epic lists the build order. Features are complete only when their acceptance criteria have evidence; scaffolding or a passing local test does not establish cloud, signing, or cross-platform readiness.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
