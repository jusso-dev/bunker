# External alert delivery (v1)

A host's effective policy can opt in with `channels: ["ui", "webhook"]`. `channels: ["ui"]` remains the default; UI is required and no historical alerts are backfilled. The policy editor exposes the opt-in. Tenant admins/operators can change the policy, but cannot submit URLs, signing keys, headers, or network exceptions through any API.

An operator first provisions `BUNKER_WEBHOOK_CONFIG_FILE` on the API and worker processes. It names an absolute, regular, non-symlink JSON file, owned by the process UID or root, mode 0600 (no group/other access), at most 64 KiB. The configuration supports one destination per tenant, at most 100 tenants per file:

```json
{
  "destinations": [
    {
      "tenantId": "REPLACE_WITH_TENANT_UUID",
      "id": "primary-v1",
      "url": "https://receiver.example.test/bunker-events",
      "secretFile": "/run/bunker/webhook-signing-key"
    }
  ]
}
```

Provide exactly one of `secretFile` or `secretEnv` (an environment variable name, never its value). Secret files have the same protection rules. Signing secrets must contain 32–4096 bytes; use at least 32 cryptographically random bytes. File bytes are used exactly, including any newline; environment values use UTF-8. Secret references are resolved only in the worker. The API only needs the configuration file. Do not use a `NEXT_PUBLIC_` variable, put configuration into client bundles, or put secrets in destination paths. URL credentials, query strings and fragments are rejected. Secrets and destination URLs are never stored in the outbox or returned through tenant APIs.

Destination IDs are operator-managed routing identities. Pending jobs retain the original ID. Changing its URL intentionally changes where pending jobs go; use a new ID when replacing a destination and investigate old pending jobs. Missing/changed IDs retry and eventually fail; they never fall through to another tenant's destination. Policy opt-in requires a provisioned destination. If configuration later disappears, new opted-in alert/evidence transactions fail with 503 and commit nothing, allowing the host to retry after repair. UI-only ingestion does not read webhook configuration.

Run migrations before deploying the new API or worker, then run the worker as a separate supervised process using the same PostgreSQL database:

```sh
pnpm --filter @bunker/control-plane db:migrate
pnpm --filter @bunker/control-plane notifications
# One due job, then exit (also suitable for operational smoke checks):
pnpm --filter @bunker/control-plane notifications --once
```

Standalone scripts require explicitly injected environment variables; they do not load Next `.env.local`. Multiple worker replicas are supported. Each claims one job with `FOR UPDATE SKIP LOCKED`, a unique lease token and a 60-second lease, then releases the transaction before network delivery. SIGTERM/SIGINT stops after the current bounded attempt. A process crash releases its job after lease expiry; stale worker completion cannot overwrite the newer claim. A crash on the eighth attempt becomes terminal after the lease expires.

New host alerts and failed restore-test evidence enqueue within the existing alert/evidence/audit transaction. Failure to enqueue rolls back all those writes. Duplicate host event IDs only increase alert occurrences, including after delivery or later policy opt-in. Duplicate evidence IDs remain 409 and do not enqueue again. Opting out affects future alerts; already queued deliveries continue. An event remains delivered or failed when acknowledged; acknowledgement does not cancel or resend it.

Delivery is **at least once**. A receiver can accept a request before the worker crashes or loses its acknowledgement. The receiver must verify signatures and atomically deduplicate `Idempotency-Key` / `X-Bunker-Delivery-Id` (both the same outbox UUID) with its own side effects. Keep deduplication records for the event's lifetime. No ordering guarantee is made between jobs or workers. A successful 2xx is recorded as delivered; redirects and permanent 4xx are terminal. Network failures, total timeout, oversized responses, 408, 429, 5xx and unavailable per-job configuration retry up to **8 total claims**. Retry delays after attempts 1–7 are 30, 60, 120, 240, 480, 960 and 1920 seconds; `Retry-After` does not override this bound. There is no automatic/manual replay endpoint, backfill, dead-letter purge or retention scheduler in v1. Operators should monitor failed/stuck rows and provision a database retention policy separately; do not delete idempotency records while alert ingestion retries remain possible.

Each attempt has a 10-second total deadline (DNS through full response) and 16 KiB response-body and header limits. HTTPS certificate/hostname verification is mandatory. There are no redirects, cookies, authorization headers, response-body storage or error-detail logging. DNS answers are all checked against non-public address ranges and one validated address is pinned for the socket; TLS still verifies the configured hostname. Private, loopback, link-local, multicast, reserved/documentation and transition endpoints are refused. Use egress firewall rules as an additional operator-controlled boundary. A destination should acknowledge quickly, then process asynchronously. Native Slack/Teams/email adapters are not included; a trusted receiver may translate the signed event.

The JSON body has only these fields:

```json
{
  "version": 1,
  "deliveryId": "OUTBOX_UUID",
  "tenantId": "TENANT_UUID",
  "hostId": "HOST_UUID",
  "alertId": "ALERT_UUID",
  "occurredAt": "2026-10-29T00:00:00.000Z",
  "type": "backup-failed",
  "severity": "critical",
  "snapshotId": null,
  "count": 1
}
```

No host names, file paths, file contents, MCP labels, keys or digests are included. `X-Bunker-Timestamp` is the attempt time in Unix seconds. `X-Bunker-Signature` is `v1=` followed by lowercase hex HMAC-SHA256 of `timestamp + "." + raw_request_body`, using the provisioned secret. Verify the raw bytes before parsing, compare signatures in constant time, reject timestamps outside a small clock-skew/replay window (for example five minutes), validate the version/schema and expected tenant, require both ID headers to equal the signed `deliveryId`, and atomically deduplicate that delivery ID. Retry bodies and IDs are stable; timestamps/signatures may change. Rotate secrets with receiver overlap for in-flight attempts.

`GET /api/tenants/{tenantId}/notifications` is human-only and returns the latest 200 rows with alert/delivery IDs, state, attempt count, timestamps, last HTTP status and a fixed error category. It exposes no payload, URL, signing reference or lease token. The Alerts UI shows these states alongside alerts; older rows may fall outside the latest-200 window. A failed delivery is visible here, not proof the receiver never processed an earlier attempt.

## Parent deployment integration

Production wiring is implemented in `deploy/compose.notifications.yml` and the Helm chart's `notifications` values/templates; both are opt-in and disabled by default. See [deployment instructions](../docs/user/deployment.md#external-notifications-opt-in) for mount layout, mandatory approved worker egress and rotation. #26 remains deferred.

The full runtime image includes migration `003_notifications.sql`, `tsx`, notification scripts/sources and shared dependencies. Run migrations once before updated API/worker startup. The separate supervised worker invokes `scripts/notification-entrypoint.ts`, materializes protected files, then runs the existing worker in-process so signals reach it directly. Compose and Helm grant 60 seconds for termination. The API calls the same bootstrap in API mode before starting its existing supervised numeric-loopback Next upstream, public TLS gateway and mandatory mTLS host listener.

The deployment accepts `BUNKER_NOTIFICATIONS_ENABLED=true` only as explicit opt-in. It uses separate config-only and signing-only mounts: `config.json` references `/run/bunker/notifications/signing/<filename>` via `secretFile` (no `secretEnv` in this deployment). Kubernetes projected symlinks are materialized into owned regular `0600` files inside private `0700` runtime directories. Strict application validators remain unchanged. The API receives configuration only; only the worker receives signing material. The worker receives database credentials but no gateway, CA or federation keys and has no inbound listener/Service. Helm always installs a deny-inbound, approved DNS/database/HTTPS egress policy with the worker. Compose requires a pre-provisioned firewall-controlled external network; its YAML alone cannot enforce that firewall.

CI explicitly runs bootstrap deployment tests and PostgreSQL notification integration tests after migrations, including 003. `deploy/smoke-notifications.mts` exercises the production worker image on disposable internal Docker resources without real secrets or external receivers. Never configure `BUNKER_WEBHOOK_TEST_TRANSPORT_FILE` in deployment; the deployed bootstrap rejects it. The existing test-only transport remains available only to the notification implementation's isolated `NODE_ENV=test` integration suite.
