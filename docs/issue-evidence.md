# Implementation and acceptance evidence

Assessment date: 2026-10-30. This development matrix is not an issue-closure list. Code/template existence is separate from verified acceptance. The parent integration/council review owns final cross-component results. The packaging/documentation member did not change remote issues, releases, PRs or deployments.

| Issue | Implementation/evidence | Remaining acceptance / status |
| --- | --- | --- |
| #1 CI/test harness | PR/main workflow; Rust fmt/clippy/test/build on three OSes; pnpm checks with PostgreSQL; discovery fixtures; docs checks | Workflow lint passed locally; hosted jobs and all OS runners have not run here. **Partial.** |
| #2 CLI/daemon | Local daemon, authenticated host runtime, durable session routing and disposable CLI checks | Cross-platform service lifecycle and live deployment remain unverified. **Partial.** |
| #3 Snapshot engine | Encrypted local objects, chunking/dedup, reviewed restore; core tests; Linux format fuzz smoke (230,452 inputs in 31 seconds) | Git branches/stashes/index and guarded combined rollback are integrated and tested; independent crypto and crash/platform evidence remain. **Partial.** |
| #4 Exclusions/secrets/caps | Sanitizer, exclusions, caps and repository/discovery tests | Heuristics are not a universal secret detector; configuration coverage needs review. **Partial.** |
| #5 Discovery framework | Discovery crate, platform paths, safety filtering and fixtures | Live host/version and full integration coverage unverified. **Partial.** |
| #6 Claude Code | Adapter and fixtures; [guide](user/agents.md) | Full real-agent setup and session behavior unverified. **Partial.** |
| #7 Cursor | Adapter and fixtures; [guide](user/agents.md) | Real editor/profile behavior unverified. **Partial.** |
| #8 Codex | Adapter and fixtures; [guide](user/agents.md) | Explicit global setup capture and session/schedule integration exist; real Codex-version validation remains. **Partial.** |
| #9 Copilot | Adapter and fixtures; [guide](user/agents.md) | Editor/profile and MCP coverage unverified. **Partial.** |
| #10 Kiro | Adapter and fixtures; [guide](user/agents.md) | Real version-specific paths and session hooks unverified. **Partial.** |
| #11 Scheduler/hooks | Independent workspace/setup/probe schedules, durable host outboxes and explicit authenticated session handler; Claude exec hook and wrapper fallback | Local restart, backpressure and policy-revocation fixtures pass; native-agent delivery and platform lifecycle remain unverified. **Partial.** |
| #12 Object storage | OpenDAL S3/R2/Azure encrypted replication/recovery; configuration guards | S3/Azure version-retention implementation and offline provider fixtures added; live provider/permission tests remain. **Providers unverified.** |
| #13 Consumer/local storage | Exact-ID Drive/OneDrive adapter, durable OAuth rotation/uncertainty/rebind state, external recovery reports; local replication/recovery | Offline protocol, restart and custody fixtures pass; live accounts and NAS failure behavior remain unverified. **Partial.** |
| #14 Immutability/DR | S3/Azure protected versions, exact-version reports, paired independent DR and automatic host policy adapter | Offline provider/publication failure fixtures and independent host review pass; live lock enforcement/independence acceptance remains. **Partial.** |
| #15 Key management | Passphrase plus explicit AWS KMS/Azure Key Vault/GCP envelopes, stable identity and escrow recovery | Envelope/checkpoint/escrow fixtures pass; live providers, organisation key administration and native platform validation remain. **Partial.** |
| #16 Control-plane foundation | Next.js/PostgreSQL, tenant roles, API schemas/tests | Verified production TLS/mTLS gateway and real Rust/PostgreSQL interoperability fixtures pass; live deployment/CA/provider acceptance remains. **Partial.** |
| #17 Onboarding/policies | TLS enrollment, versioned policies, host session/storage bindings, membership/session/password lifecycle and composite pagination | Real database/browser fixtures pass; latest independent review is tracked below. AU residency and unsupported storage combinations fail closed. **Partial.** |
| #18 Timeline/restore UI | Timeline, approvals, composite cursor Load more, retained comparisons and older snapshot lookup | Real browser and Rust approval/replay fixtures pass; tenant-token cleanup passed a fresh-build independent browser retest; deployed acceptance remains. **Partial.** |
| #19 MCP approval | Restricted tools, expiring requests and denial; local execution fails closed | Production bridge integrates independent human approval and mutation-boundary expiry checks; fixture review passes. Same-user filesystem access remains outside the MCP boundary. **Partial.** |
| #20 Detection/alerting | Mass-delete/config alerts plus authenticated Git ancestry/tracking observations; signed durable webhook outbox and supervised worker | Offline Git and real PostgreSQL/worker/TLS fixtures pass. Tracking rewrites cannot prove a force-push actor; live recipients/network enforcement remain unverified. **Partial.** |
| #21 Restore testing | Scheduled trusted container boot/MCP probes, explicit passed/failed/not_run UI evidence, durable host retries | Fake-agent/MCP container and framing fixtures pass; real native agents, credentials/network-dependent checks and crash cleanup acceptance remain. **Partial.** |
| #22 Alerts UI | List/acknowledge, dedupe, evidence links | End-to-end detection-to-UI and browser acceptance pending parent review. **Partial.** |
| #23 Compliance | [Mappings](compliance/index.md), residency caveats, export API/tests | Current control-edition review, live evidence chain, browser export and assessor sign-off remain. **Partial.** |
| #24 Packaging | Unsigned archives/SBOM/provenance workflow; checksum installer; native package/service/container/action templates; Linux control-plane image build/start smoke | No signed/notarised release, registries, native service/package execution, database-backed production deployment or hosted attestation verification. **Partial.** |
| #25 Documentation | [User guides](user/index.md), CLI/policy references, restore runbook and docs workflow | Separate non-author runbook sign-off outstanding; local checks below. **Partial.** |
| #26 Fresh-machine rebuild | [Proposal only](adr/0002-agent-rebuild.md) | User explicitly deferred/excluded from v1. Design is not agreed; no implementation. **Deferred.** |
| #27 v1 epic | Development foundation above | Required acceptance gaps remain; full v1 is not delivered. **Open/partial.** |

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
[EKS runbook](../deploy/eks/README.md) for operations and limitations.

The [GitHub CI run for application commit 0c0d4ea](https://github.com/jusso-dev/bunker/actions/runs/40974792833)
is not green: Windows Clippy, Linux Rust tests, the macOS restore smoke and the
built-gateway fixture failed; documentation/packaging passed. These failures were
observed during deployment and remain separate follow-up work. The live checks
above do not override or resolve those CI failures.
