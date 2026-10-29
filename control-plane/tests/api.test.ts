import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { handle } from "../src/lib/api";
import { database } from "../src/lib/db";
import { passwordHash, digest } from "../src/lib/security";
import * as responseSchemas from "../src/lib/responses";
const contract = JSON.parse(
  await readFile(new URL("../../shared/openapi.yaml", import.meta.url), "utf8"),
);
const enabled = !!process.env.BUNKER_TEST_DATABASE_URL;
const ids = {
  org: randomUUID(),
  tenant: randomUUID(),
  other: randomUUID(),
  admin: randomUUID(),
  viewer: randomUUID(),
  approver: randomUUID(),
  operator: randomUUID(),
};
const origin = "http://localhost:3000";
const password = "integration-only-password-value";
let admin = "",
  viewer = "",
  approver = "",
  operator = "",
  hostToken = "",
  hostId = "";
const snapId = randomUUID(),
  sessionId = randomUUID(),
  manifest = "a".repeat(64),
  diff = "b".repeat(64);
const snapshot = {
  id: snapId,
  agent: "codex",
  sessionId,
  manifestDigest: manifest,
  fileCount: 3,
  totalBytes: 300,
  capturedAt: new Date().toISOString(),
  status: "succeeded",
};
const restore = {
  snapshotId: snapId,
  kind: "workspace",
  manifestDigest: manifest,
  diffDigest: diff,
  changes: [
    {
      fileId: "c".repeat(64),
      action: "replace",
      beforeDigest: "d".repeat(64),
      afterDigest: "e".repeat(64),
      bytes: 10,
    },
  ],
};
async function call(
  path: string,
  body?: unknown,
  credential = admin,
  host = false,
  originHeader: string | null = origin,
) {
  const headers: Record<string, string> = {};
  if (originHeader) headers.origin = originHeader;
  if (credential)
    headers[host ? "authorization" : "cookie"] = host
      ? `Bearer ${credential}`
      : credential;
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await handle(
    new Request(`${origin}/api/${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
  const data = await response.json();
  if (response.ok) {
    const template = Object.keys(contract.paths).find((template) =>
      new RegExp(`^${template.replace(/\{[^}]+\}/g, "[^/]+")}$`).test(
        `/${path}`,
      ),
    );
    assert.ok(template, `OpenAPI route binding for ${path}`);
    const operation =
      contract.paths[template][body === undefined ? "get" : "post"];
    const schemaRef =
      operation.responses[response.status]?.content["application/json"].schema
        .$ref;
    assert.ok(
      schemaRef,
      `OpenAPI response binding for ${path}: ${response.status}`,
    );
    const name = schemaRef.split("/").at(-1) as keyof typeof responseSchemas;
    const parsed = responseSchemas[name].safeParse(data);
    assert.ok(
      parsed.success,
      `${path}: ${JSON.stringify(parsed.error?.issues)}`,
    );
  }
  return { response, data };
}
const path = (resource: string) => `tenants/${ids.tenant}/${resource}`;
before(async () => {
  if (!enabled) return;
  process.env.DATABASE_URL = process.env.BUNKER_TEST_DATABASE_URL;
  process.env.BUNKER_ORIGIN = origin;
  process.env.BUNKER_ALLOW_INSECURE_LOOPBACK = "true";
  await database().query(
    await readFile(
      new URL("../migrations/001_initial.sql", import.meta.url),
      "utf8",
    ),
  );
  await database().query(
    await readFile(
      new URL("../migrations/002_identity.sql", import.meta.url),
      "utf8",
    ),
  );
  await database().query(
    await readFile(
      new URL("../migrations/004_human_lifecycle.sql", import.meta.url),
      "utf8",
    ),
  );
  await database().query("INSERT INTO organizations VALUES($1,$2)", [
    ids.org,
    "Test organization",
  ]);
  await database().query("INSERT INTO tenants VALUES($1,$3,$4),($2,$3,$5)", [
    ids.tenant,
    ids.other,
    ids.org,
    "Tenant A",
    "Tenant B",
  ]);
  for (const role of ["admin", "viewer", "approver", "operator"] as const) {
    await database().query("INSERT INTO users VALUES($1,$2,$3)", [
      ids[role],
      `${role}@example.test`,
      passwordHash(password),
    ]);
    await database().query("INSERT INTO memberships VALUES($1,$2,$3)", [
      ids.tenant,
      ids[role],
      role,
    ]);
  }
  const cookies: Record<string, string> = {};
  for (const role of ["admin", "viewer", "approver", "operator"]) {
    const { response } = await call(
      "auth/login",
      { email: `${role}@example.test`, password },
      "",
    );
    assert.equal(response.status, 200);
    cookies[role] = response.headers.get("set-cookie")!.split(";")[0];
    assert.match(
      response.headers.get("set-cookie")!,
      /HttpOnly; SameSite=Strict/,
    );
  }
  ({ admin, viewer, approver, operator } = cookies);
});
after(async () => {
  if (enabled) await database().end();
});
test(
  "PostgreSQL integration: authentication, isolation, approval lifecycle and evidence",
  { skip: !enabled },
  async (t) => {
    await t.test(
      "unauthenticated, expired, bad-origin and brute force requests are denied",
      async () => {
        assert.equal((await call("me", undefined, "")).response.status, 401);
        const expiredToken = "expired-session-test-fixture";
        await database().query(
          "INSERT INTO sessions VALUES($1,$2,now()-interval '1 minute')",
          [digest(expiredToken), ids.admin],
        );
        assert.equal(
          (await call("me", undefined, `bunker_session=${expiredToken}`))
            .response.status,
          401,
        );
        assert.equal(
          (await call(path("snapshots/extra/path"))).response.status,
          400,
        );
        assert.equal(
          (await call(path(`snapshots/${randomUUID()}/unknown`))).response
            .status,
          404,
        );

        assert.equal(
          (
            await call(
              "auth/login",
              { email: "admin@example.test", password },
              "",
              false,
              "https://attacker.example",
            )
          ).response.status,
          403,
        );
        assert.equal(
          (
            await call(
              "auth/login",
              { email: "admin@example.test", password },
              "",
              false,
              null,
            )
          ).response.status,
          403,
        );
        const bypass = await handle(
          new Request(`${origin}/api/auth/login`, {
            method: "POST",
            headers: {
              authorization: "Bearer irrelevant",
              "content-type": "application/json",
            },
            body: JSON.stringify({ email: "admin@example.test", password }),
          }),
        );
        assert.equal(bypass.status, 403);
        for (let i = 0; i < 10; i++)
          assert.equal(
            (
              await call(
                "auth/login",
                { email: "missing@example.test", password: "wrong" },
                "",
              )
            ).response.status,
            401,
          );
        assert.equal(
          (
            await call(
              "auth/login",
              { email: "missing@example.test", password: "wrong" },
              "",
            )
          ).response.status,
          429,
        );
        assert.equal(
          (await call(`tenants/${ids.other}/snapshots`)).response.status,
          403,
        );
        assert.equal(
          (await call(path("enrollments"), { name: "x" }, viewer)).response
            .status,
          403,
        );
      },
    );
    await t.test(
      "one-time enrollment is atomic and stores only hashes",
      async () => {
        const enrollment = await call(path("enrollments"), {
          name: "Test host",
        });
        assert.equal(enrollment.response.status, 201);
        const responses = await Promise.all([
          call("enroll", { token: enrollment.data.token }, ""),
          call("enroll", { token: enrollment.data.token }, ""),
        ]);
        assert.deepEqual(
          responses.map((r) => r.response.status).sort(),
          [201, 401],
        );
        const enrolled = responses.find((r) => r.response.status === 201)!;
        hostToken = enrolled.data.token;
        hostId = enrolled.data.hostId;
        assert.equal(enrolled.data.tenantId, ids.tenant);
        const row = (
          await database().query("SELECT token_hash FROM hosts WHERE id=$1", [
            hostId,
          ])
        ).rows[0];
        assert.equal(row.token_hash, digest(hostToken));
        assert.notEqual(row.token_hash, hostToken);
        assert.equal(
          (
            await call(
              `tenants/${ids.other}/snapshots`,
              undefined,
              hostToken,
              true,
            )
          ).response.status,
          401,
        );
      },
    );
    await t.test("enrollment expires while reading the body", async () => {
      const enrollment = await call(path("enrollments"), { name: "Slow body" });
      let releaseBody!: () => void;
      let bodyRead!: () => void;
      const reading = new Promise<void>((resolve) => {
        bodyRead = resolve;
      });
      const release = new Promise<void>((resolve) => {
        releaseBody = resolve;
      });
      const stream = new ReadableStream(
        {
          async pull(controller) {
            bodyRead();
            await release;
            controller.enqueue(
              new TextEncoder().encode(
                JSON.stringify({ token: enrollment.data.token }),
              ),
            );
            controller.close();
          },
        },
        { highWaterMark: 0 },
      );
      const pending = handle(
        new Request(`${origin}/api/enroll`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: stream,
          duplex: "half",
        } as RequestInit),
      );
      await reading;
      // The handler transaction has started and is waiting for the body.
      await database().query(
        "UPDATE enrollments SET expires_at=clock_timestamp() WHERE token_hash=$1",
        [digest(enrollment.data.token)],
      );
      releaseBody();
      assert.equal((await pending).status, 401);
      assert.equal(
        (
          await database().query(
            "SELECT used_at FROM enrollments WHERE token_hash=$1",
            [digest(enrollment.data.token)],
          )
        ).rows[0].used_at,
        null,
      );
    });
    await t.test(
      "enrollment checks expiry and records consumption after row-lock waits",
      async () => {
        for (const expiresDuringWait of [true, false]) {
          const enrollment = await call(path("enrollments"), {
            name: "Lock wait",
          });
          const key = digest(enrollment.data.token);
          const lock = await database().connect();
          let pending: ReturnType<typeof call> | undefined;
          try {
            await lock.query("BEGIN");
            const pid = (await lock.query("SELECT pg_backend_pid() AS pid"))
              .rows[0].pid;
            await lock.query(
              "SELECT id FROM enrollments WHERE token_hash=$1 FOR UPDATE",
              [key],
            );
            pending = call("enroll", { token: enrollment.data.token }, "");
            let blocked = false;
            const deadline = Date.now() + 3000;
            while (Date.now() < deadline) {
              blocked =
                (
                  await database().query(
                    "SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",
                    [pid],
                  )
                ).rowCount! > 0;
              if (blocked) break;
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
            assert.ok(
              blocked,
              "enrollment must actually wait for the row lock",
            );
            // Expiry is now later than the waiting handler's transaction start.
            if (expiresDuringWait)
              await lock.query(
                "UPDATE enrollments SET expires_at=clock_timestamp() WHERE token_hash=$1",
                [key],
              );
            const releasedAt = (
              await lock.query("SELECT clock_timestamp() AS at")
            ).rows[0].at;
            await lock.query("COMMIT");
            const result = await pending;
            assert.equal(result.response.status, expiresDuringWait ? 401 : 201);
            const row = (
              await database().query(
                "SELECT used_at FROM enrollments WHERE token_hash=$1",
                [key],
              )
            ).rows[0];
            if (expiresDuringWait) assert.equal(row.used_at, null);
            else
              assert.ok(
                row.used_at >= releasedAt,
                "used_at must reflect consumption after acquiring the lock",
              );
          } finally {
            await lock.query("ROLLBACK");
            lock.release();
            await pending;
          }
        }
      },
    );
    await t.test(
      "snapshot metadata rejects content, enforces host ownership and supports idempotent retry",
      async () => {
        assert.equal(
          (
            await call(
              path("snapshots"),
              { ...snapshot, content: "forbidden" },
              hostToken,
              true,
            )
          ).response.status,
          400,
        );
        assert.equal(
          (await call(path("snapshots"), snapshot, admin)).response.status,
          403,
        );
        assert.equal(
          (await call(path("snapshots"), snapshot, hostToken, true)).response
            .status,
          201,
        );
        assert.equal(
          (await call(path("snapshots"), snapshot, hostToken, true)).response
            .status,
          201,
        );
        assert.equal(
          (
            await call(
              path("snapshots"),
              { ...snapshot, fileCount: 5 },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        assert.equal(
          (await call(path("snapshots"), undefined, viewer)).data.length,
          1,
        );
        assert.equal(
          (
            await call(
              path("snapshots"),
              { ...snapshot, id: randomUUID(), manifestDigest: "z".repeat(64) },
              hostToken,
              true,
            )
          ).response.status,
          400,
        );
      },
    );
    await t.test(
      "policy validates, versions, and polls without exposing another host override",
      async () => {
        const policy = {
          name: "Protection",
          hostId: null,
          intervalMinutes: 60,
          endOfSession: true,
          retentionDays: 30,
          exclusions: [".env*"],
          sizeCapBytes: 1e9,
          immutable: true,
          drCopy: true,
          residency: "AU",
          storage: "local",
          storageRef: "local",
          keyRef: "kms-reference",
          massDeleteThreshold: 25,
          missedBackupMinutes: 90,
          restoreTestIntervalHours: 24,
          channels: ["ui"],
        };
        assert.equal(
          (await call(path("policies"), policy, hostToken, true)).response
            .status,
          403,
        );
        assert.equal(
          (
            await call(
              path("policies"),
              { ...policy, channels: ["slack"] },
              operator,
            )
          ).response.status,
          400,
        );
        assert.equal(
          (
            await call(
              path("policies"),
              { ...policy, hostId: randomUUID() },
              operator,
            )
          ).response.status,
          404,
        );
        assert.equal(
          (await call(path("policies"), policy, operator)).data.version,
          1,
        );
        assert.equal(
          (
            await call(
              path("policies"),
              { ...policy, intervalMinutes: 30 },
              operator,
            )
          ).data.version,
          2,
        );
        assert.equal(
          (await call(path("policies"), undefined, hostToken, true)).data[0]
            .body.intervalMinutes,
          30,
        );
        assert.equal(
          (await call(path("policies"), { ...policy, hostId }, operator))
            .response.status,
          201,
        );
        assert.equal(
          (await call(path("policies"), undefined, hostToken, true)).data[0]
            .body.hostId,
          hostId,
        );
      },
    );
    await t.test(
      "only independent humans can approve; digest match and one-use claim are required",
      async () => {
        const created = await call(path("restores"), restore, hostToken, true);
        assert.equal(created.response.status, 201);
        const id = created.data.id;
        assert.equal(
          (
            await call(
              path(`restores/${id}/claim`),
              { diffDigest: diff },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        const approval = {
          decision: "approve",
          diffDigest: diff,
          reviewedLocalDiff: true,
        };
        assert.equal(
          (
            await call(
              path(`restores/${id}/decision`),
              approval,
              hostToken,
              true,
            )
          ).response.status,
          403,
        );
        assert.equal(
          (await call(path(`restores/${id}/decision`), approval, operator))
            .response.status,
          403,
        );
        assert.equal(
          (await call(path(`restores/${id}/decision`), approval, viewer))
            .response.status,
          403,
        );
        assert.equal(
          (
            await call(
              path(`restores/${id}/decision`),
              { ...approval, reviewedLocalDiff: false },
              approver,
            )
          ).response.status,
          409,
        );
        assert.equal(
          (
            await call(
              path(`restores/${id}/decision`),
              { ...approval, diffDigest: "0".repeat(64) },
              approver,
            )
          ).response.status,
          409,
        );
        assert.equal(
          (
            await call(
              path(`restores/${id}/complete`),
              { status: "succeeded", diffDigest: diff },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        assert.equal(
          (await call(path(`restores/${id}/decision`), approval, approver))
            .response.status,
          200,
        );
        const claims = await Promise.all([
          call(
            path(`restores/${id}/claim`),
            { diffDigest: diff },
            hostToken,
            true,
          ),
          call(
            path(`restores/${id}/claim`),
            { diffDigest: diff },
            hostToken,
            true,
          ),
        ]);
        assert.deepEqual(
          claims.map((x) => x.response.status).sort(),
          [200, 409],
        );
        assert.equal(
          (
            await call(
              path(`restores/${id}/complete`),
              { status: "succeeded", diffDigest: diff },
              hostToken,
              true,
            )
          ).response.status,
          200,
        );
        assert.equal(
          (
            await call(
              path(`restores/${id}/complete`),
              { status: "succeeded", diffDigest: diff },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        assert.equal(
          (await call(path(`restores/${id}`), undefined, approver)).data[0]
            .status,
          "succeeded",
        );
        const audit = (await call(path("audit"))).data;
        for (const action of [
          "restore.requested",
          "restore.approved",
          "restore.claimed",
          "restore.succeeded",
        ])
          assert.ok(audit.some((r: { action: string }) => r.action === action));
      },
    );
    await t.test(
      "denied, stale, foreign snapshot and expired restores never become executable",
      async () => {
        assert.equal(
          (
            await call(
              path("restores"),
              { ...restore, snapshotId: randomUUID() },
              hostToken,
              true,
            )
          ).response.status,
          404,
        );
        assert.equal(
          (
            await call(
              path("restores"),
              { ...restore, manifestDigest: "f".repeat(64) },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        const denied = (await call(path("restores"), restore, hostToken, true))
          .data.id;
        assert.equal(
          (
            await call(
              path(`restores/${denied}/decision`),
              { decision: "deny", diffDigest: diff, reviewedLocalDiff: false },
              approver,
            )
          ).response.status,
          200,
        );
        assert.equal(
          (
            await call(
              path(`restores/${denied}/claim`),
              { diffDigest: diff },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        const expired = (await call(path("restores"), restore, hostToken, true))
          .data.id;
        await database().query(
          "UPDATE restores SET expires_at=now()-interval '1 minute' WHERE id=$1",
          [expired],
        );
        const queue = await call(path("restores"), undefined, hostToken, true);
        assert.equal(
          queue.data.find((r: { id: string }) => r.id === expired).status,
          "expired",
        );
        assert.equal(
          (
            await call(
              path(`restores/${expired}/claim`),
              { diffDigest: diff },
              hostToken,
              true,
            )
          ).response.status,
          409,
        );
        assert.ok(
          (await call(path("audit"))).data.some(
            (r: { action: string; resource_id: string }) =>
              r.action === "restore.expired" && r.resource_id === expired,
          ),
        );
      },
    );
    await t.test(
      "alerts deduplicate, acknowledge and link evidence; failed restore tests raise alerts",
      async () => {
        const event = {
          eventId: randomUUID(),
          type: "mass-delete",
          severity: "critical",
          snapshotId: snapId,
          count: 40,
        };
        const a = await call(path("alerts"), event, hostToken, true);
        assert.equal(a.response.status, 201);
        assert.equal(
          (await call(path("alerts"), event, hostToken, true)).data.id,
          a.data.id,
        );
        assert.equal((await call(path("alerts"))).data[0].occurrences, 2);
        assert.equal(
          (await call(path(`alerts/${a.data.id}/acknowledge`), {}, viewer))
            .response.status,
          403,
        );
        assert.equal(
          (await call(path(`alerts/${a.data.id}/acknowledge`), {}, operator))
            .response.status,
          200,
        );
        const evidence = {
          id: randomUUID(),
          snapshotId: snapId,
          finishedAt: new Date().toISOString(),
          sandbox: "temp-directory",
          agents: [{ agent: "codex", passed: true }],
          mcps: [{ name: "local-tools", passed: false }],
        };
        assert.equal(
          (await call(path("evidence"), evidence, hostToken, true)).response
            .status,
          201,
        );
        assert.ok(
          (await call(path("alerts"))).data.some(
            (a: { body: { type: string } }) =>
              a.body.type === "restore-test-failed",
          ),
        );
        const report = await call(path("export"), undefined, viewer);
        assert.equal(report.response.status, 200);
        assert.equal(report.data.tenantId, ids.tenant);
        assert.equal(report.data.evidence.length, 1);
        assert.match(report.data.assurance, /not a compliance certification/);
        assert.equal(
          (await call(path("export"), undefined, hostToken, true)).response
            .status,
          403,
        );
      },
    );
    await t.test(
      "tri-state evidence roundtrips and alerts only on real failed probes",
      async () => {
        for (const outcome of ["passed", "not_run", "failed"] as const) {
          const id = randomUUID();
          const probe =
            outcome === "passed"
              ? { name: "stdio-fixture", outcome }
              : {
                  name: "stdio-fixture",
                  outcome,
                  reasonCode:
                    outcome === "failed"
                      ? "invalid_mcp_handshake"
                      : "credentials_unavailable",
                };
          const evidence = {
            id,
            snapshotId: snapId,
            finishedAt: new Date().toISOString(),
            sandbox: "container",
            agents: [{ agent: "codex", outcome: "passed" }],
            mcps: [probe],
            scope: "file-content",
          };
          assert.equal(
            (await call(path("evidence"), evidence, hostToken, true)).response
              .status,
            201,
          );
          const saved = (await call(path(`evidence/${id}`))).data[0];
          assert.deepEqual(saved.body.mcps, [probe]);
          assert.equal(saved.body.scope, "file-content");
          const alerts = await database().query(
            "SELECT id FROM alerts WHERE tenant_id=$1 AND dedupe_key=$2",
            [ids.tenant, `evidence:${id}`],
          );
          assert.equal(alerts.rowCount, outcome === "failed" ? 1 : 0);
          assert.equal(
            (await call(path("evidence"), evidence, hostToken, true)).response
              .status,
            201,
          );
          const auditCount = await database().query(
            "SELECT id FROM audit WHERE tenant_id=$1 AND resource_id=$2 AND action='restore-test.reported'",
            [ids.tenant, id],
          );
          assert.equal(auditCount.rowCount, 1);
          const alertCount = await database().query(
            "SELECT id FROM alerts WHERE tenant_id=$1 AND dedupe_key=$2",
            [ids.tenant, `evidence:${id}`],
          );
          assert.equal(alertCount.rowCount, outcome === "failed" ? 1 : 0);
          assert.equal(
            (
              await call(
                path("evidence"),
                { ...evidence, mcps: [] },
                hostToken,
                true,
              )
            ).response.status,
            409,
          );
        }
        const contradictory = {
          id: randomUUID(),
          snapshotId: snapId,
          finishedAt: new Date().toISOString(),
          sandbox: "container",
          agents: [
            {
              agent: "codex",
              outcome: "not_run",
              passed: true,
              reasonCode: "not_configured",
            },
          ],
          mcps: [],
        };
        assert.equal(
          (await call(path("evidence"), contradictory, hostToken, true))
            .response.status,
          400,
        );
      },
    );
    await t.test(
      "host event and failed evidence IDs cannot collide in either arrival order",
      async () => {
        for (const evidenceFirst of [false, true]) {
          const id = randomUUID();
          const event = {
            eventId: id,
            type: "mass-delete",
            severity: "warning",
            snapshotId: snapId,
            count: 40,
          };
          const evidence = {
            id,
            snapshotId: snapId,
            finishedAt: new Date().toISOString(),
            sandbox: "temp-directory",
            agents: [{ agent: "codex", passed: false }],
            mcps: [],
          };
          const requests = evidenceFirst
            ? ([
                ["evidence", evidence],
                ["alerts", event],
              ] as const)
            : ([
                ["alerts", event],
                ["evidence", evidence],
              ] as const);
          for (const [resource, data] of requests)
            assert.equal(
              (await call(path(resource), data, hostToken, true)).response
                .status,
              201,
            );
          assert.equal((await call(path(`evidence/${id}`))).data.length, 1);
          const rows = (
            await database().query(
              "SELECT dedupe_key,body,occurrences FROM alerts WHERE tenant_id=$1 AND host_id=$2 AND dedupe_key=ANY($3::text[])",
              [ids.tenant, hostId, [id, `evidence:${id}`]],
            )
          ).rows;
          assert.equal(rows.length, 2);
          assert.equal(
            rows.find((r) => r.dedupe_key === id).body.type,
            "mass-delete",
          );
          assert.equal(
            rows.find((r) => r.dedupe_key === `evidence:${id}`).body.type,
            "restore-test-failed",
          );
          assert.equal(
            (await call(path("alerts"), event, hostToken, true)).response
              .status,
            201,
          );
          assert.equal(
            (
              await database().query(
                "SELECT occurrences FROM alerts WHERE dedupe_key=$1",
                [`evidence:${id}`],
              )
            ).rows[0].occurrences,
            1,
          );
          assert.equal(
            (await call(path("evidence"), evidence, hostToken, true)).response
              .status,
            201,
          );
        }
      },
    );
    await t.test(
      "logout clears expired, revoked and absent sessions while enforcing Origin",
      async () => {
        const secret = "expired-logout-session-test-fixture";
        await database().query(
          "INSERT INTO sessions VALUES($1,$2,now()-interval '1 minute')",
          [digest(secret), ids.admin],
        );
        const cookie = `bunker_session=${secret}`;
        assert.equal(
          (
            await call(
              "auth/logout",
              {},
              cookie,
              false,
              "https://attacker.example",
            )
          ).response.status,
          403,
        );
        for (const credential of [cookie, cookie, ""]) {
          const result = await call("auth/logout", {}, credential);
          assert.equal(result.response.status, 200);
          assert.match(
            result.response.headers.get("set-cookie")!,
            /bunker_session=;.*Max-Age=0/,
          );
        }
        assert.equal(
          (
            await database().query(
              "SELECT 1 FROM sessions WHERE token_hash=$1",
              [digest(secret)],
            )
          ).rowCount,
          0,
        );
        assert.equal(
          (await call("me")).response.status,
          200,
          "another session remains valid",
        );
      },
    );
    await t.test(
      "production host API refuses forwarded-certificate spoofing; logout invalidates session",
      async () => {
        process.env.BUNKER_ALLOW_INSECURE_LOOPBACK = "false";
        assert.equal(
          (await call(path("snapshots"), snapshot, hostToken, true)).response
            .status,
          503,
        );
        assert.equal(
          (await call(path("enrollments"), { name: "production" })).response
            .status,
          503,
        );
        process.env.BUNKER_ALLOW_INSECURE_LOOPBACK = "true";
        assert.equal(
          (await call("auth/logout", {}, viewer)).response.status,
          200,
        );
        assert.equal(
          (await call("me", undefined, viewer)).response.status,
          401,
        );
      },
    );
  },
);
