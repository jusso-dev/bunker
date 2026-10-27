# Bunker v1 requirements

Confirmed requirements for the first release.

## Audience

Solo developers, development teams, MSPs backing up client environments, and government and enterprise.

## Agents

Claude Code, Cursor, Codex, GitHub Copilot and Kiro.

## Where agents run

Laptops, servers and cloud VMs, CI runners, and containers.

## What gets backed up

- Each agent's full setup: MCP configs, skills, rules files (such as `CLAUDE.md`, `AGENTS.md` and `.cursor/rules`), sub-agents, hooks, memory and settings.
- The workspace, including untracked files, stashes and local branches.
- Committed git history is not backed up, since the remote has it.
- Secrets are stored as references only, never as values.

## Excluded by default

- `.env` files and secrets
- Transcripts containing customer data
- Browser sessions and cookies
- `node_modules` and package caches
- Build output
- Model weights and large binaries
- Anything over a per-repo size cap

## Schedule

Hourly and at the end of each agent session by default. All of it is configurable in a user-friendly control plane UI.

## Retention

Set per policy in the UI.

## Storage backends

Cloudflare R2, Azure Blob, AWS S3, Google Drive, OneDrive, and local disk or NAS.

## Immutability

Optional per policy (object lock), plus a second immutable copy for disaster recovery.

## Encryption

An org key held in a KMS or Azure Key Vault, with an optional recovery key escrow.

## Compliance

Australian data residency, Essential Eight backup mapping and ISM alignment.

## Restore

- Undo a single file
- Roll back an agent session
- Restore a whole workspace
- Always show a diff before overwriting

Rebuilding an agent on a new machine is out of scope for v1 and tracked as later scope.

## Who can restore

- Humans, in the UI or the CLI
- Agents, through MCP, only with human approval
- Agents must never be able to delete backups

## Restore testing

Scheduled sandbox restores that confirm the agent boots and its MCPs connect, with a restore test report in the UI.

## Alerts

- Mass file deletes
- Force pushes and history rewrites
- Changes to MCP configs or skills
- Failed or missed backups

## Product shape

A CLI and agent daemon plus a control plane UI from day one. Open source under Apache-2.0, with no pricing.
