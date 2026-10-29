# Agent setup guides

Discovery targets Claude Code, Cursor, Codex, GitHub Copilot, and Kiro. Back up the relevant workspace and inspect discovery output before relying on coverage. Paths vary across operating systems and editor versions; inspect the installed agent configuration as well as Bunker's adapter fixtures.

| Agent | Workspace configuration to review | Home/global configuration to review |
| --- | --- | --- |
| Claude Code | `CLAUDE.md`, `.claude/`, `.mcp.json`, skills and hooks | `~/.claude/` and configured external skill roots |
| Cursor | `.cursor/rules/`, `.cursor/mcp.json`, project settings | `~/.cursor/`, user-level settings and MCP references |
| Codex | `AGENTS.md`, `.codex/`, local skills | `~/.codex/config.toml`, skills, rules and configured references |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/instructions/`, `.vscode/mcp.json` | Editor user settings and profile-specific files |
| Kiro | `.kiro/steering/`, `.kiro/settings/`, hooks and agent rules | `~/.kiro/` and user MCP settings |

For each agent:

1. Use a disposable workspace to confirm the adapter detects the intended configuration. Read warnings about missing or inaccessible files.
2. Inspect exclusions and sanitizer output. Secret-bearing configurations may be sanitized or skipped; a snapshot is not a universal secret scanner. Keep credentials as vault/environment references.
3. Snapshot the workspace with `--agent` set to its adapter name (`claude-code`, `cursor`, `codex`, `copilot`, or `kiro`) when manually labeling a backup.
4. Review `list` and restore to a separate directory. Verify the expected rules, skills, hooks and MCP references are present without executing restored hooks.
5. Re-link secrets yourself and test agent startup/MCP connections in a restricted environment. Record those checks separately from `restore-test`, which checks files only.

Transcripts, browser state, caches, model weights and secret files are excluded by intent. A global configuration file outside `--workspace` is not automatically covered merely because discovery found it. Verify the final CLI's discovery/snapshot integration before declaring full agent-setup coverage. Rebuilding a machine is [proposed later scope](../adr/0002-agent-rebuild.md).
