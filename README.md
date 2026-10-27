# Bunker

Backup, rollback and disaster recovery for AI coding agents.

Think of it as Veeam for your agents. Bunker snapshots each agent's full setup (MCP configs, skills, rules, sub-agents, hooks, memory and settings) and the workspace it works in, so you can undo a bad file edit, roll back a whole agent session, or recover a workspace after something goes wrong.

> **Status: planning.** Nothing here is ready to use yet. See [docs/requirements.md](docs/requirements.md) and the epic issue for the build plan.

## Why

Coding agents now edit files, run commands and rewrite config on their own. Git covers committed work, but it doesn't cover untracked files, stashes, local branches, or the agent setup itself. When an agent deletes a folder, force pushes, or quietly changes its own MCP config, you want a clean point to go back to.

## Who it's for

- Solo developers
- Development teams
- MSPs backing up client environments
- Government and enterprise

## Scope for v1

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
- Agents can request a restore through MCP, but a human approves it. Agents can never delete backups.
- See [docs/adr/0001-stack.md](docs/adr/0001-stack.md) for the stack choice.

## Contributing

Early days. Issues and discussion are welcome, and the epic lists the build order.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
