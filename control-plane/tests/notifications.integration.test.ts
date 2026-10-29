import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, randomBytes } from "node:crypto";
import { createServer } from "node:https";
import { fixtures, listen, close } from "./identity-fixtures";
import { database } from "../src/lib/db";
import { digest } from "../src/lib/security";
import { handle } from "../src/lib/api";
import {
  claimDelivery,
  finishDelivery,
  runOnce,
  MAX_ATTEMPTS,
} from "../src/notifications/worker";
import { notificationsResponse } from "../src/lib/responses";

const enabled = !!process.env.BUNKER_TEST_DATABASE_URL;
test(
  "PostgreSQL outbox: atomic ingestion, isolation, concurrent leases and delivery failures",
  { skip: !enabled },
  async (t) => {
    process.env.DATABASE_URL = process.env.BUNKER_TEST_DATABASE_URL;
    process.env.BUNKER_ORIGIN = "http://localhost:3000";
    process.env.BUNKER_ALLOW_INSECURE_LOOPBACK = "true";
    (process.env as Record<string, string | undefined>).NODE_ENV = "test";
    const db = database(),
      f = fixtures();
    const org = randomUUID(),
      tenant = randomUUID(),
      other = randomUUID(),
      host = randomUUID(),
      otherHost = randomUUID();
    const user = randomUUID(),
      otherUser = randomUUID();
    const humanToken = randomUUID(),
      otherHumanToken = randomUUID(),
      hostToken = randomUUID(),
      otherHostToken = randomUUID();
    const snapshotId = randomUUID();
    let status = 204;
    const received: { id: string; tenant: string; path: string }[] = [];
    const server = createServer(
      { key: f.read("server.key"), cert: f.read("server.pem") },
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (chunk) => chunks.push(chunk));
        req.on("end", () => {
          const payload = JSON.parse(Buffer.concat(chunks).toString());
          received.push({
            id: payload.deliveryId,
            tenant: payload.tenantId,
            path: req.url!,
          });
          res.writeHead(status);
          res.end();
        });
      },
    );
    const call = async (
      resource: string,
      body?: unknown,
      scope = tenant,
      credential = humanToken,
      machine = false,
    ) => {
      const response = await handle(
        new Request(`http://localhost:3000/api/tenants/${scope}/${resource}`, {
          method: body === undefined ? "GET" : "POST",
          headers: {
            origin: "http://localhost:3000",
            "content-type": "application/json",
            [machine ? "authorization" : "cookie"]: machine
              ? `Bearer ${credential}`
              : `bunker_session=${credential}`,
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        }),
      );
      return { status: response.status, body: await response.json() };
    };
    const event = () => ({
      eventId: randomUUID(),
      type: "backup-failed",
      severity: "critical",
      snapshotId: null,
      count: 1,
    });
    const report = (body = event(), scope = tenant, credential = hostToken) =>
      call("alerts", body, scope, credential, true);
    const rows = () =>
      db.query(
        "SELECT * FROM notification_outbox WHERE tenant_id=ANY($1::uuid[]) ORDER BY created_at",
        [[tenant, other]],
      );
    const policy = {
      name: "Test",
      hostId: null,
      intervalMinutes: 60,
      endOfSession: true,
      retentionDays: 30,
      exclusions: [],
      sizeCapBytes: 1000,
      immutable: false,
      drCopy: false,
      residency: "AU",
      storage: "local",
      storageRef: "local",
      keyRef: "key",
      massDeleteThreshold: 25,
      missedBackupMinutes: 90,
      restoreTestIntervalHours: 24,
      channels: ["ui", "webhook"],
    };
    try {
      const port = await listen(server);
      f.write("secret", randomBytes(32));
      f.write("transport.json", JSON.stringify({ caFile: f.file("ca.pem") }));
      process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE = f.file("transport.json");
      const config = {
        destinations: [tenant, other].map((tenantId) => ({
          tenantId,
          id: "primary",
          url: `https://127.0.0.1:${port}/${tenantId}`,
          secretFile: f.file("secret"),
        })),
      };
      f.write("config.json", JSON.stringify(config));
      await db.query("INSERT INTO organizations VALUES($1,'Webhook test')", [
        org,
      ]);
      await db.query(
        "INSERT INTO tenants VALUES($1,$3,'Webhook A'),($2,$3,'Webhook B')",
        [tenant, other, org],
      );
      await db.query(
        "INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused'),($3,$4,'unused')",
        [user, `${user}@example.test`, otherUser, `${otherUser}@example.test`],
      );
      await db.query(
        "INSERT INTO memberships VALUES($1,$2,'admin'),($3,$4,'admin')",
        [tenant, user, other, otherUser],
      );
      await db.query(
        "INSERT INTO sessions VALUES($1,$2,now()+interval '1 hour'),($3,$4,now()+interval '1 hour')",
        [digest(humanToken), user, digest(otherHumanToken), otherUser],
      );
      await db.query(
        "INSERT INTO hosts(id,tenant_id,name,token_hash) VALUES($1,$2,'Private host label',$3),($4,$5,'Other host',$6)",
        [
          host,
          tenant,
          digest(hostToken),
          otherHost,
          other,
          digest(otherHostToken),
        ],
      );
      await db.query(
        "INSERT INTO snapshots(id,tenant_id,host_id,body) VALUES($1,$2,$3,$4)",
        [
          snapshotId,
          tenant,
          host,
          {
            id: snapshotId,
            agent: "codex",
            sessionId: randomUUID(),
            manifestDigest: "a".repeat(64),
            fileCount: 1,
            totalBytes: 10,
            capturedAt: new Date().toISOString(),
            status: "succeeded",
          },
        ],
      );
      await t.test(
        "UI-only defaults remain stable; policy opt-in requires provisioned server config",
        async () => {
          delete process.env.BUNKER_WEBHOOK_CONFIG_FILE;
          const old = event();
          assert.equal((await report(old)).status, 201);
          assert.equal((await rows()).rowCount, 0);
          assert.equal((await call("policies", policy)).status, 503);
          process.env.BUNKER_WEBHOOK_CONFIG_FILE = f.file("config.json");
          assert.equal(
            (
              await call("policies", {
                ...policy,
                webhookUrl: "https://127.0.0.1",
              })
            ).status,
            400,
          );
          assert.equal((await call("policies", policy)).status, 201);
          assert.equal(
            (await call("policies", policy, other, otherHumanToken)).status,
            201,
          );
          assert.equal((await report(old)).status, 201);
          assert.equal(
            (await rows()).rowCount,
            0,
            "old UI-only event must not be queued after opt-in",
          );
        },
      );
      await t.test(
        "concurrent duplicate ingestion creates exactly one immutable metadata delivery",
        async () => {
          const e = event();
          const results = await Promise.all(
            Array.from({ length: 8 }, () => report(e)),
          );
          assert.ok(results.every((r) => r.status === 201));
          assert.equal(new Set(results.map((r) => r.body.id)).size, 1);
          const queued = (await rows()).rows;
          assert.equal(queued.length, 1);
          assert.equal(queued[0].attempts, 0);
          assert.deepEqual(
            Object.keys(queued[0].payload).sort(),
            [
              "version",
              "deliveryId",
              "tenantId",
              "hostId",
              "alertId",
              "occurredAt",
              "type",
              "severity",
              "snapshotId",
              "count",
            ].sort(),
          );
          assert.equal(queued[0].payload.tenantId, tenant);
          assert.equal(queued[0].payload.hostId, host);
          assert.equal(queued[0].payload.deliveryId, queued[0].id);
          assert.equal(
            (
              await db.query("SELECT occurrences FROM alerts WHERE id=$1", [
                results[0].body.id,
              ])
            ).rows[0].occurrences,
            8,
          );
        },
      );
      const evidence = () => ({
        id: randomUUID(),
        snapshotId,
        finishedAt: new Date().toISOString(),
        sandbox: "temp-directory",
        agents: [{ agent: "codex", passed: false }],
        mcps: [],
      });
      await t.test(
        "failed evidence and its alert enqueue once in the same transaction",
        async () => {
          const e = evidence();
          assert.equal(
            (await call("evidence", e, tenant, hostToken, true)).status,
            201,
          );
          assert.equal(
            (await call("evidence", e, tenant, hostToken, true)).status,
            201,
          );
          assert.equal(
            (await call("evidence", e, other, otherHostToken, true)).status,
            409,
          );
          assert.equal(
            (
              await call(
                "evidence",
                Object.fromEntries(Object.entries(e).reverse()),
                tenant,
                hostToken,
                true,
              )
            ).status,
            201,
          );
          const retries = await Promise.all(
            Array.from({ length: 4 }, () =>
              call("evidence", e, tenant, hostToken, true),
            ),
          );
          assert.ok(retries.every((result) => result.status === 201));
          assert.equal(
            (
              await call(
                "evidence",
                { ...e, agents: [{ agent: "codex", passed: true }] },
                tenant,
                hostToken,
                true,
              )
            ).status,
            409,
          );
          assert.equal((await rows()).rowCount, 2);
          assert.equal(
            (await rows()).rows[1].payload.type,
            "restore-test-failed",
          );
        },
      );
      await t.test(
        "skipped evidence never enqueues notifications for an enabled webhook policy",
        async () => {
          const skipped = {
            ...evidence(),
            agents: [
              {
                agent: "codex",
                outcome: "not_run",
                reasonCode: "credentials_unavailable",
              },
            ],
          };
          assert.equal(
            (await call("evidence", skipped, tenant, hostToken, true)).status,
            201,
          );
          assert.equal((await rows()).rowCount, 2);
          assert.equal(
            (
              await db.query(
                "SELECT id FROM alerts WHERE tenant_id=$1 AND dedupe_key=$2",
                [tenant, `evidence:${skipped.id}`],
              )
            ).rowCount,
            0,
          );
        },
      );
      await t.test(
        "outbox failure rolls back alert, evidence, and audit writes",
        async () => {
          await db.query(
            "CREATE FUNCTION reject_test_notification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$",
          );
          await db.query(
            "CREATE TRIGGER reject_test_notification BEFORE INSERT ON notification_outbox FOR EACH ROW EXECUTE FUNCTION reject_test_notification()",
          );
          try {
            const auditBefore = (
              await db.query("SELECT count(*) FROM audit WHERE tenant_id=$1", [
                tenant,
              ])
            ).rows[0].count;
            const e = event(),
              failed = evidence();
            assert.equal((await report(e)).status, 503);
            assert.equal(
              (await call("evidence", failed, tenant, hostToken, true)).status,
              503,
            );
            assert.equal(
              (
                await db.query(
                  "SELECT id FROM alerts WHERE tenant_id=$1 AND dedupe_key=ANY($2::text[])",
                  [tenant, [e.eventId, `evidence:${failed.id}`]],
                )
              ).rowCount,
              0,
            );
            assert.equal(
              (
                await db.query("SELECT id FROM evidence WHERE id=$1", [
                  failed.id,
                ])
              ).rowCount,
              0,
            );
            assert.equal(
              (
                await db.query(
                  "SELECT count(*) FROM audit WHERE tenant_id=$1",
                  [tenant],
                )
              ).rows[0].count,
              auditBefore,
            );
          } finally {
            await db.query(
              "DROP TRIGGER reject_test_notification ON notification_outbox; DROP FUNCTION reject_test_notification()",
            );
          }
        },
      );
      await t.test(
        "host overrides opt out; humans see only tenant delivery state",
        async () => {
          assert.equal(
            (
              await call("policies", {
                ...policy,
                hostId: host,
                channels: ["ui"],
              })
            ).status,
            201,
          );
          assert.equal((await report()).status, 201);
          assert.equal((await rows()).rowCount, 2);
          assert.equal(
            (await call("policies", { ...policy, hostId: host })).status,
            201,
          );
          assert.equal(
            (await report(event(), other, otherHostToken)).status,
            201,
          );
          const mine = await call("notifications"),
            theirs = await call(
              "notifications",
              undefined,
              other,
              otherHumanToken,
            );
          assert.equal(mine.status, 200);
          assert.equal(theirs.status, 200);
          assert.equal(mine.body.length, 2);
          assert.equal(theirs.body.length, 1);
          notificationsResponse.parse(mine.body);
          notificationsResponse.parse(theirs.body);
          assert.ok(
            mine.body.every(
              (n: { id: string }) =>
                !theirs.body.some((x: { id: string }) => x.id === n.id),
            ),
          );
          assert.equal(
            (await call("notifications", undefined, tenant, hostToken, true))
              .status,
            403,
          );
          assert.equal(
            (await call("notifications", undefined, other)).status,
            403,
          );
          assert.equal(
            received.length,
            0,
            "ingestion must not send network requests",
          );
        },
      );
      await t.test(
        "concurrent workers claim once and route each tenant only to its destination",
        async () => {
          await Promise.all(Array.from({ length: 6 }, () => runOnce()));
          assert.equal(received.length, 3);
          assert.equal(new Set(received.map((r) => r.id)).size, 3);
          for (const r of received) assert.equal(r.path, `/${r.tenant}`);
          assert.ok(
            (await rows()).rows.every(
              (r) => r.state === "delivered" && r.attempts === 1,
            ),
          );
          assert.equal(await runOnce(), false);
          const old = (
            await db.query(
              "SELECT body FROM alerts WHERE tenant_id=$1 AND body ? 'eventId' ORDER BY created_at DESC LIMIT 1",
              [other],
            )
          ).rows[0].body;
          assert.equal((await report(old, other, otherHostToken)).status, 201);
          assert.equal(await runOnce(), false);
        },
      );
      await t.test(
        "retry backoff is durable, bounded to eight attempts, and preserves delivery IDs",
        async () => {
          status = 503;
          const a = await report();
          const get = async () =>
            (
              await db.query(
                "SELECT * FROM notification_outbox WHERE alert_id=$1",
                [a.body.id],
              )
            ).rows[0];
          for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            assert.equal(await runOnce(), true);
            const row = await get();
            assert.equal(row.attempts, attempt);
            assert.equal(
              row.state,
              attempt === MAX_ATTEMPTS ? "failed" : "retrying",
            );
            assert.equal(row.last_status, 503);
            if (attempt < MAX_ATTEMPTS) {
              assert.ok(
                new Date(row.available_at).getTime() > Date.now() + 25_000,
              );
              assert.equal(await runOnce(), false);
              await db.query(
                "UPDATE notification_outbox SET available_at=now()-interval '1 second' WHERE id=$1",
                [row.id],
              );
            }
          }
          const last = await get();
          assert.equal(received.filter((r) => r.id === last.id).length, 8);
          assert.equal(await runOnce(), false);
          status = 204;
        },
      );
      await t.test(
        "expired leases recover; stale worker completion cannot overwrite a new lease",
        async () => {
          await report();
          const first = (await claimDelivery())!;
          assert.ok(first);
          assert.equal(await claimDelivery(), undefined);
          await db.query(
            "UPDATE notification_outbox SET lease_until=now()-interval '1 second' WHERE id=$1",
            [first.id],
          );
          const second = (await claimDelivery())!;
          assert.equal(second.id, first.id);
          assert.equal(second.attempts, 2);
          assert.notEqual(second.lease_token, first.lease_token);
          await finishDelivery(first, {
            ok: true,
            retryable: false,
            status: 204,
          });
          assert.equal(
            (
              await db.query(
                "SELECT state FROM notification_outbox WHERE id=$1",
                [first.id],
              )
            ).rows[0].state,
            "delivering",
          );
          await finishDelivery(second, {
            ok: true,
            retryable: false,
            status: 204,
          });
          await report();
          const final = (await claimDelivery())!;
          await db.query(
            "UPDATE notification_outbox SET attempts=8,lease_until=now()-interval '1 second' WHERE id=$1",
            [final.id],
          );
          assert.equal(await claimDelivery(), undefined);
          assert.equal(
            (
              await db.query(
                "SELECT state,last_error FROM notification_outbox WHERE id=$1",
                [final.id],
              )
            ).rows[0].last_error,
            "lease-expired",
          );
        },
      );
      await t.test(
        "missing or changed destination cannot cross-route; HTTP rejection is terminal",
        async () => {
          const a = await report();
          f.write(
            "config.json",
            JSON.stringify({
              destinations: config.destinations.filter(
                (d) => d.tenantId !== tenant,
              ),
            }),
          );
          const before = received.length;
          assert.equal(await runOnce(), true);
          assert.equal(received.length, before);
          assert.equal(
            (
              await db.query(
                "SELECT last_error FROM notification_outbox WHERE alert_id=$1",
                [a.body.id],
              )
            ).rows[0].last_error,
            "configuration",
          );
          f.write("config.json", JSON.stringify(config));
          await db.query(
            "UPDATE notification_outbox SET available_at=now() WHERE alert_id=$1",
            [a.body.id],
          );
          status = 400;
          await runOnce();
          assert.equal(
            (
              await db.query(
                "SELECT state FROM notification_outbox WHERE alert_id=$1",
                [a.body.id],
              )
            ).rows[0].state,
            "failed",
          );
          assert.equal(await runOnce(), false);
        },
      );
      await t.test(
        "separate worker CLI processes share the queue safely",
        async () => {
          status = 204;
          await report();
          await report(event(), other, otherHostToken);
          const before = received.length;
          await Promise.all(
            Array.from({ length: 2 }, () =>
              promisify(execFile)(
                process.execPath,
                ["--import", "tsx", "scripts/notifications.ts", "--once"],
                { cwd: new URL("..", import.meta.url), env: process.env },
              ),
            ),
          );
          assert.equal(received.length, before + 2);
          assert.equal(
            new Set(received.slice(before).map((r) => r.id)).size,
            2,
          );
          assert.equal(await runOnce(), false);
        },
      );
    } finally {
      server.closeAllConnections();
      await close(server);
      f.cleanup();
      await db.end();
    }
  },
);
