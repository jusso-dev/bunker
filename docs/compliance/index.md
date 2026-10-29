# Compliance scope and evidence

Bunker can contribute technical evidence to a backup/recovery assessment. It does not certify Essential Eight maturity, ISM compliance, Australian data residency or any organisation's operating effectiveness. The mappings here are an implementation-oriented assessment aid, not a substitute for the current ASD publication and an assessor's control register.

Assessment date: 2026-10-29. No specific current ISM publication revision or control identifiers have been independently verified in this task. Before relying on this mapping, record the exact authoritative edition, control wording, applicability, responsible owner and acceptance criteria. A source link is not evidence that its latest contents were reviewed.

| Evidence category | Available source | Limits |
| --- | --- | --- |
| Backup configuration | [Local/UI policy reference](../user/policies.md) | Saved intent does not prove a daemon applied it or a cloud service enforces it. |
| Local backup/recovery | [Restore runbook](../user/restore.md), [repository tests](https://github.com/jusso-dev/bunker/blob/main/crates/bunker/tests/repository.rs), [runbook smoke test](https://github.com/jusso-dev/bunker/blob/main/packaging/scripts/smoke_restore.py) | Local file restoration; not agent boot, MCP readiness, live provider recovery, RPO/RTO certification or independent-reader sign-off. |
| Remote copies | [Storage implementation/tests](https://github.com/jusso-dev/bunker/blob/main/crates/bunker/src/storage.rs), [backend guide](../user/storage.md) | In-memory and local-filesystem replication evidence; provider verification and immutable DR remain outstanding. |
| Access and approvals | [Security model](../user/security.md), [API tests](https://github.com/jusso-dev/bunker/blob/main/control-plane/tests/api.test.ts) | Development test identities are not production mTLS or platform privilege separation. |
| UI report export | [Team guide](../user/teams.md), [export API and tests](https://github.com/jusso-dev/bunker/blob/main/control-plane/tests/api.test.ts) | Host-reported metadata, bounded query results and ordinary audit rows; not independently signed/attested evidence. |

Source links target `main` for published documentation and may not resolve until this implementation is merged. Assess the exact reviewed commit, not whichever revision later appears at that branch.

## Export an assessment record

Sign in to the intended tenant and use the control-plane evidence export. Check its tenant ID, generated timestamp, reporting interval/completeness, snapshots, restore-test records, policy versions, audit records and assurance disclaimer. Keep the original JSON with a locally recorded hash and your assessor's signed notes. Do not publish customer metadata in CI logs.

Attach independent evidence for provider retention/object lock, storage/account geography, key custody, privileged-access reviews, service operation, failed/missed backup handling, and actual incident recovery exercises. Record unmet controls as gaps, including evidence whose source is unavailable or whose test did not run. Do not replace `not_run` agent/MCP results with successful claims in an export.

See the [Essential Eight mapping](essential-eight.md), [ISM mapping](ism.md), [residency guide](residency.md) and [issue evidence matrix](../issue-evidence.md). No issue is closed by these documents.
