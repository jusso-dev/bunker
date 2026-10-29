# Teams and MSPs

The control plane provides tenant-scoped metadata, policies, snapshot timelines, restore requests, alerts, and evidence export. Local repository operations remain separate. Follow the [deployment guide](deployment.md) to migrate the database and bootstrap the first administrator.

Use distinct tenants for customer environments and grant only needed roles: `admin`, `operator`, `viewer`, or `approver`. A tenant boundary in the database is not a substitute for separate storage permissions, repository passphrases, host identities and customer-specific recovery procedures. Test isolation using real deployment identities before onboarding customer data. Production enrollment and host reporting use the verified TLS/mTLS gateway. Real Rust/PostgreSQL interoperability fixtures pass; production CA operations and live deployment still require acceptance.

Policies entered in the UI express intent. They do not establish that a host received the policy or that a provider applied retention, immutability, residency or key-management controls. Inventory hosts and record who is responsible for applying the corresponding local policy. Keep a separate operator responsible for reviewing restores, and preserve an audit trail of that review.

For each customer, record the repository location, separately protected credentials, recovery namespace, storage account/region, backup schedule, recovery objectives, and the date/result of the latest full recovery exercise. Test restoration under the same access constraints an incident responder would face.

The UI's evidence export downloads JSON from the tenant's `export` endpoint. It includes snapshot metadata, restore-test evidence, policy records and audit entries, with an assurance disclaimer. Treat it as host-reported evidence, not a signed compliance certification or proof of current storage settings. Exports may be limited to the most recent records; check the current API limit and completeness for your assessment period. Restrict and encrypt exported metadata according to customer policy. See [compliance evidence](../compliance/index.md).

Account settings support current-password changes and self-service session
revocation. Tenant administrators can remove memberships with a concurrency-safe
last-admin guard. Local password recovery is an explicit instance-operator CLI
flow that creates a short-lived, one-use token in a protected file; there is no
public token-issuance or email-reset endpoint. Apply migration 004 before using
these workflows. Identity-provider links and credentials remain separately managed.

Collections use composite cursors and Load more. Filtering applies to loaded rows;
exports retain their documented limits. Tenant switches, lost access and logout
clear the displayed enrollment token along with tenant data.
