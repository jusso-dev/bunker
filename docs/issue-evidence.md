# Implementation and acceptance evidence

Assessment date: 2026-11-04, PR #42 (v1 completion). Each row separates what automated CI now proves on Linux, macOS and Windows from acceptance that needs resources CI cannot hold: live cloud accounts, signing identities, native agent installs and a non-author operator. Those residuals are listed, never inferred from offline fixtures. Earlier dated sections below are historical.

| Issue | Implementation and automated evidence | Residual external acceptance |
| --- | --- | --- |
| #1 CI/test harness | Rust fmt, clippy `-D warnings` and `--no-fail-fast` tests on Ubuntu, macOS and Windows; control-plane lint/typecheck/unit/PostgreSQL/built-gateway tests; MinIO/Azurite TLS emulator job; OpenAPI/TS client drift check; docs, packaging and action tests; fuzz smoke; checked-in five-agent discovery fixtures | None. |
| #2 CLI/daemon | `bunker daemon` and host runtime answer `bunker status` over an owner-only socket (`running_daemon_answers_status_and_stops_cleanly`, `host_runtime_answers_local_status_and_stops_cleanly`); offline local policy; enrolment identity stored owner-only on Unix and under protected owner-only DACLs on Windows; JSON logs with `--log-level`/`BUNKER_LOG` | Status socket is Unix-only; native service lifecycle (launchd/systemd/WinSW) not executed in CI. |
| #3 Snapshot engine | FastCDC/BLAKE3 dedup, per-repository data key, versioned encrypted format fuzzed; local branches, stashes and index round-trip; committed remote objects not stored | Git-aware capture is Unix-only in v1 (Windows records a diagnostic). Independent cryptographic review not performed. |
| #4 Exclusions/secrets/caps | Defaults with no config; MCP/config secrets become references (including inline `--password`/`--api-key` command flags); size-cap refusal states actual bytes, cap and policy field | Heuristic secret detection, not a universal detector. |
| #5 Discovery framework | Adapter trait/registry; `discover` groups items by category; missing/unknown agents and unreadable managed files are skipped | None beyond #6–#10. |
| #6 Claude Code | Every category on Linux/macOS/Windows layouts; SessionEnd hook payload creates a listed snapshot | Validation against a live Claude Code install. |
| #7 Cursor | Every category including `.cursor/environment.json`; schedule fallback for sessions | Live Cursor profile validation. |
| #8 Codex | Every category; `session-run` captures start/end and preserves exit status | Live Codex install validation. |
| #9 Copilot | Every category including JetBrains/user prompt locations; org-managed unreadable settings never fail discovery | Live VS Code/JetBrains org-managed validation. |
| #10 Kiro | Every category; wrapper session capture | Kiro native hook delivery not available; wrapper fallback documented. |
| #11 Scheduler/hooks | Hourly default with jitter (standalone and host); policy interval changes reschedule without restart; durable missed-run records and deterministic `BackupMissed` alerts with a threshold above interval plus jitter | Native-agent hook delivery on real installs. |
| #12 Object storage | OpenDAL S3/R2/Azure; MinIO and Azurite TLS round trips in CI; region in outputs/reports/audit; credentials never in objects, reports or CLI output; upload pacing and multipart chunk options | Live AWS/R2/Azure accounts and IAM permission tests. |
| #13 Consumer/local storage | Drive/OneDrive exact-ID adapter with durable OAuth rotation; local/NAS replication and recovery; explicit no-object-lock warning | OAuth tokens remain in owner-only (Windows: protected-DACL) state files, not the OS keychain: keyring's Linux native backend loses tokens on reboot and persistent backends need D-Bus. Live accounts not tested. |
| #14 Immutability/DR | S3/Azure protected versions with exact-version reports and paired independent DR; MinIO object-lock test proves locked versions cannot be deleted; MCP exposes no delete path | Live provider lock enforcement; DR copy runs with replication rather than on a separate schedule. |
| #15 Key management | Passphrase and AWS KMS/Azure Key Vault/GCP envelopes; rewrap without re-upload; escrow export/unlock tested | Live KMS providers. |
| #16 Control-plane foundation | Enrolment and snapshot reporting; tenant isolation; admin/operator/viewer/approver roles; OIDC and local accounts; generated TS client with drift check; image, Compose and Helm | Rust client is hand-written against the spec. |
| #17 Onboarding/policies | Live-state checklist with exact, internally consistent CLI commands; validated policy editor; policy updates reach hosts on their next 30 s poll with a bumped version | Timed zero-to-first-backup trial with a new user; per-agent policy assignment not offered (tenant or host). |
| #18 Timeline/restore | File, workspace and session-rollback restores from CLI and host bridge, always previewed and confirmed; pre-restore safety snapshot under the host policy; audited | UI initiates approval, host executes. |
| #19 MCP approval | `tools/list` is exactly `list_snapshots`, `diff`, `request_restore`; human approval; denied and expired requests audited | Slack/Teams/email approval notifications (webhook only). |
| #20 Detection/alerting | Mass delete, force push/history rewrite, MCP config and skill changes as separate alerts, failed and missed backups, each tested; dedupe and acknowledge; per-policy thresholds; pre-restore auto-snapshot | Email/Slack/Teams channels (UI and signed webhook only). |
| #21 Restore testing | Scheduled probes; failures alert; per-agent and per-MCP pass rate and history | Container probes are Unix-only; real agent images and credentials. |
| #22 Alerts UI | Status/type/host/severity filters; acknowledge; reload-safe timeline deep links across paginated tenants with nearest-snapshot fallback | Browser click-through not automated in CI. |
| #23 Compliance | Mappings in `docs/compliance/`; export with backup, restore-test and alert evidence | Assessor sign-off and current-edition review. |
| #24 Packaging | Release-tag-only workflow with build provenance, SBOM attestation and keyless cosign signatures; bootstraps verify checksum and tag/workflow-bound attestation; Windows `install.ps1`; Homebrew/winget templates rendered; action post step tested; service templates | No release published; Authenticode/Apple notarisation and registry publication need signing identities. |
| #25 Documentation | Docs build strictly in CI; a test fails if any CLI subcommand or flag is undocumented; policy fields documented; runbook smoke-tested in CI on three OSes | Restore runbook walk-through by someone who did not write it. |
| #26 Fresh-machine rebuild | [Proposal only](adr/0002-agent-rebuild.md) | Out of v1 scope by design. |
| #27 v1 epic | Children above; per-agent backup, restore and restore test for all five agents with fixtures | Live per-agent runs on real installs. |

## Packaging/documentation member checks

- Actual CLI `--help` and `discover --help` inspected; references updated for current commands.
- `python3 packaging/scripts/smoke_restore.py --binary target/debug/bunker` **passed** on macOS: preview without writes, stale-confirmation refusal, restored-byte identity, verification, file-only restore test, local encrypted replication, new-repository recovery and restoration from the recovered copy. A fresh random passphrase stayed in the child environment, was not logged, and the disposable lab was removed.
- `actionlint`, ShellCheck, `helm lint` and default `helm template` **passed locally**.
- Installer adversarial tests (checksum mismatch, symlink binary, traversal-shaped unrelated members, zip and duplicate handling) and action path/subprocess-failure tests **passed locally**.
- Package-generator, CycloneDX inventory, checksum and installed-binary smoke **passed** using the existing debug binary as a disposable packaging fixture. This was not a release build or signed package test.
- Strict MkDocs build and local-link/syntax validation **passed locally**, as did launchd plist validation and Helm rendering with the optional network policy enabled. Final review corrected repository-overlap handling in the action, the container Next.js app directory, TLS trust roots in the agent image, and archive/provenance path handling. These checks do not establish remote CI or hosted provenance success.

These checks were run by the documentation author independently of the core implementer. They do not meet issue #25's separate-person/non-author wording. Agent boot, MCP connectivity, live cloud providers, signing, native services, live Kubernetes deployment and actual Australian geography verification were **not run**. Later production TLS/mTLS and Rust bridge disposable fixtures passed; those do not establish live deployment acceptance.

## Before closure

Keep issues open until every acceptance criterion has evidence tied to a reviewed commit. Record command, platform, date, result and residuals; distinguish tests run, tests skipped and tests merely configured in CI. Unsupported feature flags and local tests do not establish provider guarantees. Reconcile independent council findings before final acceptance.


## Current integration reconciliation (29 October 2026)

The earlier packaging checklist is historical evidence. Subsequent work adds
[Git recovery](git-recovery.md), [setup/session capture](setup-capture.md),
[operator maintenance](maintenance.md), [managed keys](key-management.md),
[host integration](host-integration.md), and [version-protected storage](immutable-storage.md).
Independent council rounds have reproduced and driven fixes. Round 8 accepted the
latest storage and probe boundaries without blocking findings; the focused human
cleanup review also accepted the current UI after a fresh build and real browser
race checks. No issue is closed by this matrix, and no
live-provider/native-agent acceptance is inferred from offline fixtures.


## Final local reconciliation (30 October 2026)

Implemented integrations now include exact-ID consumer storage with durable OAuth
uncertainty handling, authenticated Git rewrite observations, scheduled container
probes, durable host session capture, verified host storage-policy publication, and
human access/session/password lifecycle with composite pagination. Migration 004
is required for the new human-access workflows. No live deployment or issue
closure was performed.

Current checks passed: the complete Rust workspace suite, the additional
checkpoint-fork recovery regression, Rust 1.91 workspace/all-target checking,
workspace Clippy with warnings denied, formatting, a cached security audit, a fresh
Next production build and 46 PostgreSQL/TLS integration tests, strict MkDocs, and
syntax/local-link validation. Independent browser tests verified tenant-token
cleanup and delayed-response isolation. The opt-in real Docker probe smoke remains
ignored in the ordinary Rust suite; previous disposable fake-agent container
smoke is separate evidence.

Receipt replay preserves exact recoverability but does not repair an absent/older
local checkpoint head. Later publications may repeat sequence numbers; preserve
and use exact external locators. See [host storage](host-storage.md). Live cloud
lock/permission/rotation guarantees, actual off-machine disaster recovery,
native-agent behavior, platform runtime/service validation, power-loss behavior,
and residency/compliance attestations remain acceptance gaps. Unsupported policy
combinations fail closed. **This is not a completed-v1 or release-readiness claim;
#26 remains deferred.**

## EKS deployment evidence (30 October 2026)

The control plane was deployed to AWS `yumait-prod`, namespace `bunker`, using
application commit `0c0d4ea` and ECR digest
`sha256:6d74e9a45bb69f0062c1d7b92de5169b6551c5f45d92a979e1e38128f15efd4b`.
The console is `https://bunker.yumait.au`; hosts use
`https://hosts.bunker.yumait.au:8444`. Private encrypted RDS has seven-day backups
and deletion protection. Migrations 001–004 and initial administrator bootstrap
completed. TLS verification remained enabled throughout deployment.

Live checks passed for public TLS, console/provider readiness, administrator
login, admin tenant access, session listing, logout invalidation and rejection of
host requests without a client certificate. A live certificate-sync Job passed
and the resulting application rollout became ready. Three offline tests cover
certificate refresh, preservation of host keys/trust roots, interrupted-rollout
repair and refusal to restart before Secret projection. Helm lint, Kubernetes
server dry runs, syntax/local-link checks and diff review cover the new deployment
configuration.

Deployment fixes supplied self-signed Amazon probe trust anchors and an explicit
DNS rule for EKS Auto Mode's managed resolver. Initial database role provisioning
and schema migration now use separate Jobs. The initial failed attempts made no
committed schema change; the final migration Job completed successfully.

This is control-plane deployment evidence, not whole-product acceptance. Real
host enrollment/capture, external storage providers, native agents, database
restore drills, HA and disaster recovery remain separate acceptance work. See the
[EKS runbook](https://github.com/jusso-dev/bunker/blob/main/deploy/eks/README.md) for operations and limitations.

The [GitHub CI run for application commit 0c0d4ea](https://github.com/jusso-dev/bunker/actions/runs/40974792833)
is not green: Windows Clippy, Linux Rust tests, the macOS restore smoke and the
built-gateway fixture failed; documentation/packaging passed. These failures were
observed during deployment and remain separate follow-up work. The live checks
above do not override or resolve those CI failures.
