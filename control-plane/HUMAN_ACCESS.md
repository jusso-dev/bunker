# Human access and pagination

Apply migrations with `pnpm db:migrate` before starting this version. Migration 004 is incremental and keeps existing users, identity links, memberships and sessions. It gives sessions independent public management handles, adds one-use recovery records and indexes list boundaries. Historical sessions, tenants and memberships receive the migration time as their new paging/creation timestamp; original creation times were not stored.

## Memberships

Tenant administrators can list members and remove access in Administration, or use `GET /api/tenants/{tenantId}/members` and `POST /api/tenants/{tenantId}/members/{userId}/revoke`. A matching Origin and a live human session are required for mutations. Removal affects only that tenant. It does not delete the global account, federation links, or other tenant memberships. The user may still open Account with no tenant membership.

Membership grants, role changes and removal share an exclusive tenant transaction lock. Other human tenant requests take the shared lock and recheck membership while holding it. Removal waits for already authorized requests to finish; after its commit, subsequent or queued requests cannot retain the removed role. Concurrent mutual removal/demotion cannot remove the last admin. Removing yourself is allowed only if another admin remains; the existing prohibition on changing your own role remains.

## Passwords and sessions

Account lists only the signed-in human's active sessions, with creation/expiry times and a current-session flag. `handle` is a random management handle unrelated to the bearer cookie or stored authentication hash. No token, token hash or internal authentication identifier is returned. Tenant administrators cannot inspect/revoke another global user's sessions.

- `GET /api/auth/sessions`: own active sessions, paginated.
- `POST /api/auth/sessions/{handle}/revoke`: revoke one of your sessions.
- `POST /api/auth/sessions/revoke-others`: retain the current session and remove the others.
- `POST /api/auth/password`: `{currentPassword,newPassword}`; verifies the current local credential, rate limits failed verification, replaces the password and revokes **all** sessions, including the current one. Sign in again afterward.

All mutations require exact matching Origin. User row locks serialize login/session creation, password changes, recovery, session revocation and the existing federation identity-link operations. A revoked session is rechecked after lock waits. Existing OIDC/GitHub identity links are preserved; these operations do not reset provider credentials. A user with a local credential and linked federation can change/recover that existing local credential. An account without a valid local credential cannot gain one through these flows.

## Operator recovery without email

Issuance is an explicit instance-operator CLI operation, like identity linking. There is no tenant-admin or public issuance endpoint and no email delivery. The operator must verify the person's identity through the organization's established process before issuing or handing over a recovery token. Possessing a tenant admin session is insufficient to issue one.

With the operator's normal database access, from `control-plane/`:

```sh
pnpm password:recover --confirm-local-recovery USER_UUID /absolute/private-directory/new-token-file
```

The directory must be owned by that operator, mode 0700, and canonical with no symlink components. The output file must not exist. The command creates it exclusively with mode 0600 and never prints the token. No command arguments or logs contain its value. Issuance stores only a SHA-256 hash, invalidates previously issued recovery tokens for that user, and records an audit event in their current tenants. Issuance does not change the password or sign out sessions.

The person uses **Use an operator-issued recovery token** on the sign-in screen, or submits `{token,newPassword}` to `POST /api/auth/recovery` with matching Origin. The token expires after 15 minutes, including time spent waiting for database locks. Successful consumption is atomic, permits one caller under concurrency, replaces only the existing local credential, removes all sessions and outstanding recovery tokens, and clears the local login throttle. It creates no session; sign in afterward. Delete the protected handover file when it is no longer needed. Do not paste it into logs, URLs, tickets or chat.

There is no automatic identity proof, email reset, provider reset, MFA addition, global account deletion or expired-row cleanup service in this increment. Audit records remain application metadata, not independent tamper-proof attestation.

## List compatibility

Existing list response arrays are unchanged; `/me` keeps its object with `tenants` and adds `localPassword`. Lists now default to at most 200 rows. Use `limit=1..200`. If there are more rows, the response includes `X-Next-Cursor`; pass its exact value as `cursor` on the next request. The absence of the header means the end of that page sequence. Hosts, human policies, snapshots, restores, alerts, evidence, audit, notification summaries, members, own sessions and `/me` tenants support this protocol. Configured provider discovery and the host's single effective policy are not paged collections. Evidence export keeps its documented 10,000/category cap.

Cursors use descending time plus ID and preserve all six PostgreSQL fractional-second digits; equal timestamps and bigint audit IDs are not rounded or skipped. They are bounded, strictly parsed and bound to the route, tenant and caller identity. They are not credentials. SQL still enforces tenant and host scope independently of cursor content. Legacy `before` remains an exclusive timestamp filter; it cannot be combined with `cursor` and cannot by itself distinguish equal-time boundaries. Use the returned cursor for subsequent pages.

This is keyset pagination over live data, not a frozen database snapshot. New rows and policy updates appear on a fresh traversal. The console refreshes its loaded prefix, appends older pages with Load more, retains comparison/approval selections separately, clears tenant data on access loss, and resolves alert snapshot links by ID. Filters apply to loaded rows; load more to search older data. Each page is bounded; manually loading many pages increases browser memory and refresh work. Clients that previously assumed `/me`, hosts or policies were unbounded must now follow the header.

## Reproducible checks

`pnpm test:integration` initializes a private disposable PostgreSQL server with no TCP listener and runs existing API, lifecycle/pagination, production identity and notification suites. The lifecycle suite includes real blocked locks, concurrent removals/demotions, session scoping and invalidation, password/recovery races, recovery expiry after a lock wait, operator CLI file protection, all paged routes, equal timestamps, microseconds, bigint IDs, malformed cursors and cross-tenant/actor/resource cursors. Successful responses are checked against their OpenAPI-bound schemas.

For the actual rendered console, run `pnpm build`, then `sh scripts/test-human-browser.sh`. Open its loopback URL in T3 preview and evaluate the default function from `tests/human.browser.js`, passing only that disposable run's protected `fixture.json` object. This exercises real HTTP, the built Next app and disposable PostgreSQL without replacing fetch or using live providers/accounts. Stop the harness afterward to clean up its database and synthetic recovery token. `tests/console.browser.js` separately covers delayed/error/eviction UI regressions with mocked metadata.
