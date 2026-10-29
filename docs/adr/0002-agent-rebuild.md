# ADR 0002: New-machine agent rebuild design proposal

- Status: **proposed; not agreed**
- Date: 2026-10-29
- Issue: #26
- Scope: design only, later than v1; explicitly deferred by the user

## Decision gate

Issue #26 explicitly requires a design note to be written and agreed before implementation. This proposal records options and acceptance gates only. No rebuild command, agent installer, vault reconnection, MCP execution or guided rebuild UI is implemented by this work. Agreement must identify the approving maintainers and the accepted revision in the issue/decision record; none is recorded yet.

## Problem and boundaries

A file restore is not a runnable agent on a clean machine. Recovery may need an agent binary, platform-specific configuration, skills/plugins, executable hooks, secret references, MCP dependencies and explicit network permissions. Automatically executing a backed-up hook or MCP command can execute attacker-controlled code. Installing arbitrary binaries and resolving customer secrets requires a separate human-authorized workflow.

The proposal supports Claude Code, Cursor, Codex, GitHub Copilot and Kiro through adapter-specific, versioned capabilities. It should keep ordinary workspace restore available without installing any agent or contacting a vault. Cross-platform compatibility is a declared capability, never inferred from a successful file copy.

## Proposed workflow

1. **Assess:** read an authenticated snapshot and the target OS/architecture. Produce a non-executing inventory of agent versions, configuration, required dependencies, secret references, MCPs and unsupported items. Mark missing installation provenance and unavailable sources explicitly.
2. **Plan:** show proposed installs, paths/overwrites, commands, permissions, vault reference names and network destinations. Bind the plan to snapshot digest, target identity, adapter versions and expiration. The UI must show exactly what the host will execute.
3. **Approve:** require a human with an appropriate role to approve the complete plan. Keep approval out of agent-accessible tools; same-user shell access remains an environmental limitation unless an enforced broker boundary is introduced.
4. **Stage:** fetch allowlisted installation artifacts using authenticated sources, verify signatures/digests, and stage configuration in an isolated directory. Prefer a supported installed agent version when compatible. Do not blindly run recovered scripts or interpolate backup strings into a shell.
5. **Bind:** resolve secret references on the target using least-privilege vault credentials and explicit scope. Never export plaintext credentials into backups, reports or command arguments. Unresolved references block dependent readiness checks.
6. **Validate:** run adapter-declared startup and MCP connectivity checks in a restricted sandbox. Deny network by default and allow reviewed destinations only. Capture sanitized results with `passed`, `failed`, `not_run` and reasons rather than inventing successful checks.
7. **Apply:** revalidate approval, target state and installed versions, then atomically activate supported configuration changes. Do not claim atomicity for third-party installers. Preserve a recovery journal and a human-readable rollback plan.
8. **Report:** record versions, artifact provenance, file changes, approvals, sanitized checks, failures and unresolved items. Mark a machine usable only when all required readiness checks actually pass.

## Proposed contracts

An adapter would describe supported OS/agent versions, inventory and install detection, an allowlisted installation strategy, path relocation, configuration validation and bounded readiness checks. A rebuild plan would contain immutable inputs and typed operations, not arbitrary shell text from the backup. Vault integration would exchange reference identifiers and short-lived capabilities; secret material would remain target-local.

The control plane would store metadata and signed/attested results, not plaintext snapshots or keys. A host-side privileged broker, if needed, would accept a constrained approved plan and reject replay, stale digests, unknown operations and changed target state. This requires a threat-model and authorization design review before choosing an implementation.

## Failure behavior and alternatives

Missing signatures, unsupported versions/OS, unavailable vault access or incompatible configuration should stop the affected stage with a recoverable report. Network retries must be bounded and resumable without repeating destructive installs. Partial third-party installation cannot be advertised as a full rollback; document manual remediation.

Alternatives are a documentation-only manual rebuild, a downloadable plan executed by an operator, or a fully managed installer. Prefer the manual/plan path initially until unattended installation, approval boundaries and vault scopes can be demonstrated safely. Existing package managers may install agents, but their feeds and update behavior become explicit dependencies.

## Acceptance gates after agreement

- Approved design revision and threat model, with named human sign-off.
- Clean-VM tests for every supported agent on each claimed OS; independently repeatable setup and cleanup.
- Real install provenance/signature checks; missing/revoked artifact and version incompatibility tests.
- Vault-reference rebinding without literal secret persistence, including denied/expired/missing credentials.
- MCP success, timeout, revoked access, malicious configuration and unavailable network tests.
- Approval replay/staleness, target drift, path traversal, privilege separation and interrupted-stage recovery tests.
- Evidence export that distinguishes file restoration, installed agent startup and actual MCP connectivity.
- An operator who did not author the procedure completes the runbook and records measured recovery results.

## Open decisions for agreement

Choose the supported initial OS/agent-version matrix, permissible installers and trust roots, vault providers, broker privilege model, sandbox/network controls, report attestation format, retention of rollback journals, and ownership of manual recovery when an installer cannot roll back. None of these choices is silently resolved by this proposal.
