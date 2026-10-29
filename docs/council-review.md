# Council review — 29 October 2026

Scope: the initial Bunker implementation, developed from the planning-only repository. The user confirmed that issue #26 remains deferred and the work should focus on v1.

This record distinguishes defects in implemented behavior from unfinished v1 acceptance criteria. A passing review does not establish production readiness or close the epic.

## Round 1

An independent Claude Opus reviewer examined the Rust engine, discovery integration, scheduler, MCP, and encrypted storage. An independent Codex reviewer examined the control plane, authentication, tenant boundaries, approvals, UI, API contract, and deployment templates. Both reproduced defects using disposable test data; no live agent configuration or cloud credentials were used.

Core findings included workspace corruption from overbroad secret sanitization, overly broad source exclusions, loss of embedded transcript filtering, missing rebind warnings, ineffective local human-approval separation, daemon exits on transient failures, non-durable schedule writes, unjournaled partial restores, and limitations in recovery, resource limits, and key-rotation claims.

Control-plane findings included the container starting from the wrong application directory, enrollment expiry using transaction-start time, evidence insertion rolling back on an alert deduplication collision, snapshot comparison crashing after polling evicted a selected row, and expired sessions leaving the UI unable to sign out.

## Fixes and verification

Remediation and independent re-review are in progress. Final results and remaining acceptance gaps must be recorded before this change is presented as complete.

## Acceptance boundaries

The v1 backlog includes requirements beyond the initial functional implementation: real agent setup capture and lifecycle integration; local Git history recovery; production host enrollment and identity; cloud integration and immutability enforcement; managed keys and escrow; authenticated UI-to-host restore execution; sandbox agent/MCP boot checks; external alert delivery; signed platform distribution; and native cross-platform verification. Consult the issue evidence matrix for the precise state of each issue. These requirements must not be marked complete based on scaffolding, mocks, or metadata-only demonstrations.

## Later independent rounds and integration fixes

Round 2 found incomplete exclusions, nested config leaks, removal-only restore
warnings, discovery aborts, scheduler backoff/status issues and unsupported Drive
claims. Fixes were implemented and exercised by regression fixtures. Round 3
then reproduced nested secret leakage through Git history and normalized ref
aliases leaving target config replaced; both were fixed, with 25 Git-library and
9 core Git tests passing. Round 4 reproduced wrapper exit-status loss and a host
alert lost between capture and detection persistence. New CLI failure/cancellation
and restart/durable-comparison regressions pass after their fixes.

Independent keys reviews drove cumulative checkpoint-limit enforcement, staged
initialization, portable escrow export and current-directory initialization fixes.
Maintenance review drove per-agent/session and whole-setup-group retention,
incomplete-group preservation, host/scheduler queue pins, and shared typed host
state validation. Twenty maintenance and five envelope tests passed after those
fixes; the later narrow review found no additional initialization/GC defect.

Protected-storage review reproduced local checkpoint advancement before version
proofs were durable and report re-export inside the repository. Publication now
invokes a durable evidence callback before advancing the local checkpoint;
re-export uses the same external-destination guard. Their regression suite and
independent re-review are tracked separately from live provider acceptance.

The integrated workspace/all-target check passed on declared MSRV Rust 1.91.
The cached advisory audit passed against 1,381 advisories without ignores or
excluding yanked checks. These results apply to the dependency tree checked at
that point; additions require renewed checks. Strict documentation/link validation
passed. Notification deployment has passed disposable image/TLS/worker smoke and
32 production integration tests including real Rust host enrollment/approval/
restore/denial/replay; independent notification/deployment review remains in progress.

Consumer-storage OAuth and scheduled sandbox probe implementations remain in
progress. No full-v1 acceptance, native/live-agent success, provider permission
assurance, signing/notarisation, residency certification or external deployment is
claimed. Issue #26 stays deferred.
