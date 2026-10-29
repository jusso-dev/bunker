import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, stat, chmod, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { handle } from "../src/lib/api";
import { database, transaction } from "../src/lib/db";
import { issueRecovery } from "../src/lib/human-lifecycle";
import { digest, passwordHash, passwordMatches } from "../src/lib/security";
import * as responses from "../src/lib/responses";

const enabled = !!process.env.BUNKER_TEST_DATABASE_URL;
const origin = "http://localhost:3000";
const password = "disposable-local-password";
const replacement = "new-disposable-local-password";
const contract = JSON.parse(
  await readFile(new URL("../../shared/openapi.yaml", import.meta.url), "utf8"),
);
before(() => {
  if (!enabled) return;
  process.env.DATABASE_URL = process.env.BUNKER_TEST_DATABASE_URL;
  process.env.BUNKER_ORIGIN = origin;
  process.env.BUNKER_ALLOW_INSECURE_LOOPBACK = "true";
});
after(async () => {
  if (enabled) await database().end();
});
async function call(
  path: string,
  cookie = "",
  payload?: unknown,
  originHeader: string | null = origin,
) {
  const headers: Record<string, string> = {};
  if (cookie) headers.cookie = cookie;
  if (originHeader) headers.origin = originHeader;
  if (payload !== undefined) headers["content-type"] = "application/json";
  const response = await handle(
    new Request(`${origin}/api/${path}`, {
      method: payload === undefined ? "GET" : "POST",
      headers,
      body: payload === undefined ? undefined : JSON.stringify(payload),
    }),
  );
  const data = await response.json();
  if (response.ok) {
    const pathname = "/" + path.split("?")[0];
    const template = Object.keys(contract.paths).find((p) =>
      new RegExp(`^${p.replace(/\{[^}]+\}/g, "[^/]+")}$`).test(pathname),
    );
    assert.ok(template, `contract route ${pathname}`);
    const operation =
      contract.paths[template][payload === undefined ? "get" : "post"];
    const name = operation.responses[response.status].content[
      "application/json"
    ].schema.$ref
      .split("/")
      .at(-1) as keyof typeof responses;
    const parsed = responses[name].safeParse(data);
    assert.ok(
      parsed.success,
      `response schema ${pathname}: ${JSON.stringify(parsed.error?.issues)}`,
    );
  }
  return {
    response,
    data,
    status: response.status,
    next: response.headers.get("x-next-cursor"),
  };
}
async function login(email: string, credential = password) {
  const result = await call("auth/login", "", { email, password: credential });
  assert.equal(result.status, 200);
  return result.response.headers.get("set-cookie")!.split(";")[0];
}
async function fixture() {
  const org = randomUUID(),
    tenant = randomUUID(),
    other = randomUUID();
  await database().query(
    "INSERT INTO organizations VALUES($1,'Lifecycle fixture')",
    [org],
  );
  await database().query(
    "INSERT INTO tenants(id,organization_id,name) VALUES($1,$3,'Lifecycle A'),($2,$3,'Lifecycle B')",
    [tenant, other, org],
  );
  const users = [];
  for (const role of ["admin", "admin", "viewer", "operator", "approver"]) {
    const id = randomUUID(),
      email = `${id}@example.test`;
    await database().query("INSERT INTO users VALUES($1,$2,$3)", [
      id,
      email,
      passwordHash(password),
    ]);
    await database().query(
      "INSERT INTO memberships(tenant_id,user_id,role) VALUES($1,$2,$3),($4,$2,'viewer')",
      [tenant, id, role, other],
    );
    users.push({ id, email, cookie: await login(email), role });
  }
  return {
    tenant,
    other,
    users,
    path: (resource: string) => `tenants/${tenant}/${resource}`,
  };
}

// These tests run only under the private disposable-PostgreSQL harness.
test("human lifecycle and stable pagination", { skip: !enabled }, async (t) => {
  await t.test(
    "membership removal enforces tenant role, CSRF, isolation and immediate loss without deleting global identity",
    async () => {
      const f = await fixture();
      const [admin, , viewer, operator, approver] = f.users;
      const remove = f.path(`members/${viewer.id}/revoke`);
      for (const user of [viewer, operator, approver]) {
        assert.equal((await call(remove, user.cookie, {})).status, 403);
        assert.equal((await call(f.path("members"), user.cookie)).status, 403);
      }
      assert.equal((await call(remove, admin.cookie, {}, null)).status, 403);
      assert.equal(
        (
          await call(
            `tenants/${f.other}/members/${viewer.id}/revoke`,
            admin.cookie,
            {},
          )
        ).status,
        403,
      );
      assert.equal((await call(remove, admin.cookie, {})).status, 200);
      assert.equal((await call(f.path("hosts"), viewer.cookie)).status, 403);
      assert.equal(
        (await call(`tenants/${f.other}/hosts`, viewer.cookie)).status,
        200,
      );
      const me = await call("me", viewer.cookie);
      assert.deepEqual(
        me.data.tenants.map((row: { id: string }) => row.id),
        [f.other],
      );
      assert.equal((await call(remove, admin.cookie, {})).status, 404);
      assert.equal(
        (await database().query("SELECT 1 FROM users WHERE id=$1", [viewer.id]))
          .rowCount,
        1,
      );
    },
  );
  await t.test(
    "concurrent mutual removals and demotions leave an administrator; sole admin self-removal fails",
    async () => {
      for (const demote of [false, true]) {
        const f = await fixture();
        const [a, b] = f.users;
        const blocker = await database().connect();
        await blocker.query("BEGIN");
        await blocker.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
          [`membership:${f.tenant}`],
        );
        const requests = [
          call(
            f
              .path(demote ? "members" : `members/${b.id}/revoke`)
              .replace(f.tenant, f.tenant.toUpperCase()),
            a.cookie,
            demote ? { email: b.email, role: "viewer" } : {},
          ),
          call(
            f.path(demote ? "members" : `members/${a.id}/revoke`),
            b.cookie,
            demote ? { email: a.email, role: "viewer" } : {},
          ),
        ];
        await waitForLock(2);
        await blocker.query("COMMIT");
        blocker.release();
        const results = await Promise.all(requests);
        assert.equal(
          results.filter((r) => r.status === (demote ? 201 : 200)).length,
          1,
        );
        assert.equal(results.filter((r) => r.status === 403).length, 1);
        const admins = (
          await database().query(
            "SELECT user_id FROM memberships WHERE tenant_id=$1 AND role='admin'",
            [f.tenant],
          )
        ).rows;
        assert.equal(admins.length, 1);
        const survivor = f.users.find((u) => u.id === admins[0].user_id)!;
        assert.equal(
          (
            await call(
              f.path(`members/${survivor.id}/revoke`),
              survivor.cookie,
              {},
            )
          ).status,
          409,
        );
      }
    },
  );
  await t.test(
    "queued tenant requests recheck membership after a committed revoke",
    async () => {
      const f = await fixture();
      const [admin, , viewer] = f.users;
      const blocker = await database().connect();
      await blocker.query("BEGIN");
      await blocker.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        [`membership:${f.tenant}`],
      );
      const request = call(f.path("hosts"), viewer.cookie);
      await waitForLock();
      await blocker.query(
        "DELETE FROM memberships WHERE tenant_id=$1 AND user_id=$2",
        [f.tenant, viewer.id],
      );
      await blocker.query("COMMIT");
      blocker.release();
      assert.equal((await request).status, 403);
      assert.equal((await call(f.path("hosts"), admin.cookie)).status, 200);
    },
  );
  await t.test(
    "session management discloses only public handles, scopes to self and revokes immediately",
    async () => {
      const f = await fixture();
      const [a, b] = f.users;
      const second = await login(a.email);
      const list = await call("auth/sessions?limit=1", a.cookie);
      assert.ok(list.next);
      assert.equal(list.data.length, 1);
      const next = await call(`auth/sessions?cursor=${list.next}`, a.cookie);
      const sessions = [...list.data, ...next.data];
      assert.equal(sessions.length, 2);
      assert.equal(sessions.filter((row) => row.current).length, 1);
      for (const session of sessions)
        assert.deepEqual(Object.keys(session).sort(), [
          "created_at",
          "current",
          "expires_at",
          "handle",
        ]);
      const other = sessions.find((row) => !row.current);
      assert.equal(
        (await call(`auth/sessions/${other.handle}/revoke`, b.cookie, {}))
          .status,
        404,
      );
      assert.equal(
        (await call(`auth/sessions/${other.handle}/revoke`, a.cookie, {}, null))
          .status,
        403,
      );
      assert.equal(
        (await call(`auth/sessions/${other.handle}/revoke`, a.cookie, {}))
          .status,
        200,
      );
      assert.equal((await call("me", second)).status, 401);
      const third = await login(a.email);
      assert.equal(
        (await call("auth/sessions/revoke-others", a.cookie, {})).status,
        200,
      );
      assert.equal((await call("me", third)).status, 401);
      assert.equal((await call("me", a.cookie)).status, 200);
      const current = sessions.find((row) => row.current);
      const removed = await call(
        `auth/sessions/${current.handle}/revoke`,
        a.cookie,
        {},
      );
      assert.equal(removed.status, 200);
      assert.match(removed.response.headers.get("set-cookie")!, /Max-Age=0/);
      assert.equal((await call("me", a.cookie)).status, 401);
    },
  );
  await t.test(
    "password change verifies current credential and invalidates every prior session and token without unlinking identity",
    async () => {
      const f = await fixture();
      const [a] = f.users;
      const second = await login(a.email);
      await database().query(
        "INSERT INTO external_identities VALUES('fixture','https://fixture.invalid','local-linked',$1)",
        [a.id],
      );
      const recovery = await transaction((db) => issueRecovery(db, a.id));
      assert.equal(
        (
          await call(
            "auth/password",
            a.cookie,
            { currentPassword: password, newPassword: replacement },
            null,
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await call("auth/password", a.cookie, {
            currentPassword: "wrong",
            newPassword: replacement,
          })
        ).status,
        403,
      );
      assert.equal((await call("me", second)).status, 200);
      assert.equal(
        (
          await call("auth/password", a.cookie, {
            currentPassword: password,
            newPassword: replacement,
          })
        ).status,
        200,
      );
      for (const cookie of [a.cookie, second])
        assert.equal((await call("me", cookie)).status, 401);
      assert.equal(
        (await call("auth/login", "", { email: a.email, password })).status,
        401,
      );
      await login(a.email, replacement);
      assert.equal(
        (
          await call("auth/recovery", "", {
            token: recovery,
            newPassword: password,
          })
        ).status,
        401,
      );
      assert.equal(
        (
          await database().query(
            "SELECT 1 FROM external_identities WHERE user_id=$1",
            [a.id],
          )
        ).rowCount,
        1,
      );
      const hash = (
        await database().query("SELECT password_hash FROM users WHERE id=$1", [
          a.id,
        ])
      ).rows[0].password_hash;
      assert.ok(passwordMatches(replacement, hash));
      assert.notEqual(hash, replacement);
    },
  );
  await t.test(
    "concurrent password changes cannot reuse the old session/credential after lock waits",
    async () => {
      const f = await fixture();
      const [a] = f.users;
      const results = await Promise.all([
        call("auth/password", a.cookie, {
          currentPassword: password,
          newPassword: replacement,
        }),
        call("auth/password", a.cookie, {
          currentPassword: password,
          newPassword: replacement + "second",
        }),
      ]);
      assert.deepEqual(results.map((r) => r.status).sort(), [200, 401]);
    },
  );
  await t.test(
    "waiting local login and existing-session requests cannot survive password replacement",
    async () => {
      const f = await fixture();
      const [a] = f.users;
      const blocker = await database().connect();
      await blocker.query("BEGIN");
      const pending: ReturnType<typeof call>[] = [];
      try {
        await blocker.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [
          a.id,
        ]);
        pending.push(
          call("auth/login", "", { email: a.email, password }),
          call("me", a.cookie),
        );
        await waitForLock();
        await blocker.query("UPDATE users SET password_hash=$2 WHERE id=$1", [
          a.id,
          passwordHash(replacement),
        ]);
        await blocker.query("DELETE FROM sessions WHERE user_id=$1", [a.id]);
        await blocker.query("COMMIT");
      } finally {
        await blocker.query("ROLLBACK");
        blocker.release();
      }
      assert.deepEqual(
        (await Promise.all(pending)).map((r) => r.status),
        [401, 401],
      );
      await login(a.email, replacement);
    },
  );
  await t.test(
    "recovery is bounded, one use under concurrency, superseded on reissue, CSRF guarded, and never enables federated-only login",
    async () => {
      const f = await fixture();
      const [a, b] = f.users;
      const old = await transaction((db) => issueRecovery(db, a.id));
      const secret = await transaction((db) => issueRecovery(db, a.id));
      assert.equal(
        (
          await call("auth/recovery", "", {
            token: old,
            newPassword: replacement,
          })
        ).status,
        401,
      );
      assert.equal(
        (
          await call(
            "auth/recovery",
            "",
            { token: secret, newPassword: replacement },
            null,
          )
        ).status,
        403,
      );
      await database().query(
        "INSERT INTO login_attempts VALUES($1,10,clock_timestamp()) ON CONFLICT(identity_hash) DO UPDATE SET failures=10,window_start=clock_timestamp()",
        [digest(a.email)],
      );
      const results = await Promise.all(
        [0, 1].map(() =>
          call("auth/recovery", "", {
            token: secret,
            newPassword: replacement,
          }),
        ),
      );
      assert.deepEqual(results.map((r) => r.status).sort(), [200, 401]);
      assert.equal((await call("me", a.cookie)).status, 401);
      assert.equal((await call("me", b.cookie)).status, 200);
      await login(a.email, replacement);
      await database().query(
        "UPDATE users SET password_hash='federated-only' WHERE id=$1",
        [b.id],
      );
      await assert.rejects(
        transaction((db) => issueRecovery(db, b.id)),
        /existing local credential/,
      );
      assert.equal(
        (
          await call("auth/password", b.cookie, {
            currentPassword: password,
            newPassword: replacement,
          })
        ).status,
        409,
      );
      assert.equal(
        (await call("auth/login", "", { email: b.email, password })).status,
        401,
      );
      assert.equal(
        (await call("auth/recovery/issue", a.cookie, { userId: b.id })).status,
        404,
      );
    },
  );
  await t.test(
    "recovery expiry is checked after waiting for the account lock",
    async () => {
      const f = await fixture();
      const [a] = f.users;
      const secret = await transaction((db) => issueRecovery(db, a.id));
      const blocker = await database().connect();
      await blocker.query("BEGIN");
      let request: ReturnType<typeof call> | undefined;
      try {
        await blocker.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [
          a.id,
        ]);
        request = call("auth/recovery", "", {
          token: secret,
          newPassword: replacement,
        });
        await waitForLock();
        await blocker.query(
          "UPDATE password_recoveries SET created_at=clock_timestamp()-interval '16 minutes',expires_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1",
          [a.id],
        );
        await blocker.query("COMMIT");
      } finally {
        await blocker.query("ROLLBACK");
        blocker.release();
      }
      assert.ok(request);
      assert.equal((await request).status, 401);
      await login(a.email);
    },
  );
  await t.test(
    "operator CLI requires explicit local recovery and exclusive protected output; logs contain no token",
    async (context) => {
      const f = await fixture();
      const [a] = f.users;
      const directory = await mkdtemp(join(tmpdir(), "bunker-recovery-test-"));
      context.after(() => rm(directory, { recursive: true, force: true }));
      await chmod(directory, 0o700);
      const output = join(directory, "token");
      const run = (args: string[]) =>
        new Promise<{ code: number | null; output: string }>((resolve) => {
          const child = spawn(
            process.execPath,
            ["--import", "tsx", "scripts/recover-password.ts", ...args],
            {
              cwd: new URL("..", import.meta.url),
              env: {
                ...process.env,
                DATABASE_URL: process.env.BUNKER_TEST_DATABASE_URL,
              },
            },
          );
          let logs = "";
          child.stdout.on("data", (chunk) => (logs += chunk));
          child.stderr.on("data", (chunk) => (logs += chunk));
          child.on("close", (code) => resolve({ code, output: logs }));
        });
      // macOS /var resolves to /private/var; the command intentionally requires the canonical path.
      const { realpath } = await import("node:fs/promises");
      const canonical = join(await realpath(directory), "token");
      const result = await run(["--confirm-local-recovery", a.id, canonical]);
      assert.equal(result.code, 0);
      const secret = (await readFile(output, "utf8")).trim();
      assert.match(secret, /^[A-Za-z0-9_-]{43}$/);
      assert.ok(!result.output.includes(secret));
      assert.equal((await stat(output)).mode & 0o777, 0o600);
      assert.notEqual(
        (await run(["--confirm-local-recovery", a.id, canonical])).code,
        0,
      );
      await symlink(canonical, join(directory, "link"));
      assert.notEqual(
        (
          await run([
            "--confirm-local-recovery",
            a.id,
            join(await realpath(directory), "link"),
          ])
        ).code,
        0,
      );
      assert.equal(
        (
          await call("auth/recovery", "", {
            token: secret,
            newPassword: replacement,
          })
        ).status,
        200,
      );
    },
  );
  await paginationTests(t);
});
async function waitForLock(minimum = 1) {
  for (let i = 0; i < 100; i++) {
    const found = await database().query(
      "SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'",
    );
    if ((found.rowCount ?? 0) >= minimum) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("Expected real PostgreSQL lock contention");
}
async function paginationTests(t: import("node:test").TestContext) {
  await t.test(
    "composite pages cover equal-time and sub-millisecond boundaries; reject cross-tenant/actor/resource and malformed cursors",
    async () => {
      const f = await fixture();
      const [a, b] = f.users;
      const host = randomUUID();
      await database().query(
        "INSERT INTO hosts(id,tenant_id,name,token_hash) VALUES($1,$2,'pagination',$3)",
        [host, f.tenant, digest(randomUUID())],
      );
      const ids: string[] = [];
      for (let i = 0; i < 207; i++) {
        const id = randomUUID();
        ids.push(id);
        const body = {
          id,
          agent: "codex",
          sessionId: randomUUID(),
          manifestDigest: "a".repeat(64),
          fileCount: 1,
          totalBytes: 1,
          capturedAt: "2026-01-01T00:00:00Z",
          status: "succeeded",
        };
        await database().query(
          "INSERT INTO snapshots(id,tenant_id,host_id,body,created_at) VALUES($1,$2,$3,$4,$5)",
          [
            id,
            f.tenant,
            host,
            body,
            i < 203
              ? "2026-01-01T00:00:00.123456Z"
              : "2026-01-01T00:00:00.123455Z",
          ],
        );
      }
      const first = await call(f.path("snapshots"), a.cookie);
      assert.equal(first.data.length, 200);
      assert.ok(first.next);
      const second = await call(
        f.path(`snapshots?cursor=${first.next}`),
        a.cookie,
      );
      assert.equal(second.data.length, 7);
      assert.equal(second.next, null);
      assert.deepEqual(
        [...first.data, ...second.data].map((row) => row.id).sort(),
        ids.sort(),
      );
      const cursor = JSON.parse(
        Buffer.from(first.next!, "base64url").toString(),
      );
      assert.equal(cursor.time, "2026-01-01T00:00:00.123456Z");
      for (const path of [f.path("alerts"), `tenants/${f.other}/snapshots`])
        assert.equal(
          (await call(`${path}?cursor=${first.next}`, a.cookie)).status,
          400,
        );
      assert.equal(
        (await call(f.path(`snapshots?cursor=${first.next}`), b.cookie)).status,
        400,
      );
      for (const query of [
        "limit=0",
        "limit=201",
        "limit=1.2",
        "limit=1&limit=2",
        "cursor=",
        "cursor=bad!",
        "before=bad",
        `cursor=${first.next}&before=2026-01-01T00:00:00Z`,
      ])
        assert.equal(
          (await call(f.path(`snapshots?${query}`), a.cookie)).status,
          400,
          query,
        );
      for (const invalid of [
        { ...cursor, id: "bad" },
        { ...cursor, time: "2026-02-30T00:00:00.123456Z" },
        { ...cursor, extra: true },
      ]) {
        const encoded = Buffer.from(JSON.stringify(invalid)).toString(
          "base64url",
        );
        assert.equal(
          (await call(f.path(`snapshots?cursor=${encoded}`), a.cookie)).status,
          400,
        );
      }
      const legacy = await call(
        f.path("snapshots?before=2026-01-02T00:00:00Z&limit=2"),
        a.cookie,
      );
      assert.equal(legacy.data.length, 2);
      assert.ok(legacy.next);
      const item = await call(f.path(`snapshots/${ids[0]}`), a.cookie);
      assert.equal(item.data.length, 1);
      // Audit's bigint tie-breaker must not round through a JavaScript Number.
      await database().query(
        "INSERT INTO audit(id,tenant_id,actor,action,created_at) VALUES(9007199254740993,$1,'fixture','page','2026-01-01'),(9007199254740994,$1,'fixture','page','2026-01-01')",
        [f.tenant],
      );
      const audit = await call(
        f.path("audit?before=2026-01-02T00:00:00Z&limit=1"),
        a.cookie,
      );
      assert.equal(audit.data[0].id, "9007199254740994");
      const auditNext = await call(
        f.path(`audit?cursor=${audit.next}&limit=1`),
        a.cookie,
      );
      assert.equal(auditNext.data[0].id, "9007199254740993");
      // Every remaining list uses the same bounded protocol, including mutable
      // policy timestamps and human-only notification delivery summaries.
      const policy = {
        name: "Paging",
        hostId: host,
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
        channels: ["ui"],
      };
      for (let i = 0; i < 3; i++) {
        const h = randomUUID(),
          alert = randomUUID(),
          evidence = randomUUID();
        await database().query(
          "INSERT INTO hosts(id,tenant_id,name,token_hash,created_at) VALUES($1,$2,'page',$3,'2026-01-01')",
          [h, f.tenant, digest(h)],
        );
        await database().query(
          "INSERT INTO policies(id,tenant_id,host_id,body,updated_at) VALUES($1,$2,$3,$4,'2026-01-01')",
          [randomUUID(), f.tenant, h, { ...policy, hostId: h }],
        );
        await database().query(
          "INSERT INTO restores(id,tenant_id,host_id,snapshot_id,body,status,created_at,expires_at) VALUES($1,$2,$3,$4,$5,'pending','2026-01-01',clock_timestamp()+interval '1 hour')",
          [
            randomUUID(),
            f.tenant,
            host,
            ids[0],
            {
              snapshotId: ids[0],
              kind: "workspace",
              manifestDigest: "a".repeat(64),
              diffDigest: "b".repeat(64),
              changes: [
                {
                  fileId: "c".repeat(64),
                  action: "create",
                  beforeDigest: null,
                  afterDigest: "d".repeat(64),
                  bytes: 1,
                },
              ],
            },
          ],
        );
        await database().query(
          "INSERT INTO alerts(id,tenant_id,host_id,dedupe_key,body,created_at) VALUES($1::uuid,$2,$3,$1::text,$4,'2026-01-01')",
          [
            alert,
            f.tenant,
            host,
            {
              eventId: alert,
              type: "backup-failed",
              severity: "warning",
              snapshotId: ids[0],
              count: 1,
            },
          ],
        );
        await database().query(
          "INSERT INTO evidence(id,tenant_id,host_id,snapshot_id,body,created_at) VALUES($1,$2,$3,$4,$5,'2026-01-01')",
          [
            evidence,
            f.tenant,
            host,
            ids[0],
            {
              id: evidence,
              snapshotId: ids[0],
              finishedAt: "2026-01-01T00:00:00Z",
              sandbox: "temp-directory",
              agents: [
                {
                  agent: "codex",
                  outcome: "not_run",
                  reasonCode: "not_configured",
                },
              ],
              mcps: [],
            },
          ],
        );
        await database().query(
          "INSERT INTO notification_outbox(id,tenant_id,alert_id,destination_id,payload,created_at) VALUES($1,$2,$3,'fixture','{}','2026-01-01')",
          [randomUUID(), f.tenant, alert],
        );
      }
      for (const resource of [
        "hosts",
        "policies",
        "restores",
        "alerts",
        "evidence",
        "notifications",
      ]) {
        const firstPage = await call(
          f.path(`${resource}?before=2026-01-02T00:00:00Z&limit=1`),
          a.cookie,
        );
        assert.equal(firstPage.data.length, 1, resource);
        assert.ok(firstPage.next, resource);
        const remaining = await call(
          f.path(`${resource}?cursor=${firstPage.next}&limit=2`),
          a.cookie,
        );
        assert.equal(remaining.data.length, 2, resource);
        assert.equal(remaining.next, null, resource);
        assert.equal(
          new Set([...firstPage.data, ...remaining.data].map((row) => row.id))
            .size,
          3,
          resource,
        );
      }
      const members = await call(f.path("members?limit=2"), a.cookie);
      const remainder = await call(
        f.path(`members?cursor=${members.next}`),
        a.cookie,
      );
      assert.equal(
        new Set([...members.data, ...remainder.data].map((row) => row.id)).size,
        5,
      );
      const me = await call("me?limit=1", a.cookie);
      assert.ok(me.next);
      const meNext = await call(`me?cursor=${me.next}`, a.cookie);
      assert.equal(
        new Set(
          [...me.data.tenants, ...meNext.data.tenants].map((row) => row.id),
        ).size,
        2,
      );
    },
  );
}
