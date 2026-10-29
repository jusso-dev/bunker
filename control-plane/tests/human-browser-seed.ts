// Disposable local browser fixture only; never accepts an operator DATABASE_URL.
import { readFile, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { database, transaction } from "../src/lib/db";
import { digest, passwordHash } from "../src/lib/security";
import { issueRecovery } from "../src/lib/human-lifecycle";
if (
  !process.env.BUNKER_TEST_DATABASE_URL ||
  !process.env.BUNKER_TEST_BROWSER_FIXTURE
)
  throw new Error("Use the disposable browser harness");
process.env.DATABASE_URL = process.env.BUNKER_TEST_DATABASE_URL;
for (const file of [
  "001_initial.sql",
  "002_identity.sql",
  "003_notifications.sql",
  "004_human_lifecycle.sql",
])
  await database().query(
    await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8"),
  );
const org = randomUUID(),
  tenant = randomUUID(),
  other = randomUUID(),
  admin = randomUUID(),
  viewer = randomUUID(),
  recover = randomUUID(),
  host = randomUUID();
await database().query(
  "INSERT INTO organizations VALUES($1,'Disposable browser')",
  [org],
);
await database().query(
  "INSERT INTO tenants(id,organization_id,name) VALUES($1,$3,'Browser lifecycle'),($2,$3,'Other browser tenant')",
  [tenant, other, org],
);
for (const [id, email, role] of [
  [admin, "admin@browser.example.test", "admin"],
  [viewer, "viewer@browser.example.test", "viewer"],
  [recover, "recover@browser.example.test", "viewer"],
]) {
  await database().query("INSERT INTO users VALUES($1,$2,$3)", [
    id,
    email,
    passwordHash("browser-disposable-password"),
  ]);
  await database().query(
    "INSERT INTO memberships(tenant_id,user_id,role) VALUES($1,$2,$3)",
    [tenant, id, role],
  );
}
await database().query(
  "INSERT INTO memberships(tenant_id,user_id,role) VALUES($1,$2,'admin')",
  [other, admin],
);
await database().query(
  "INSERT INTO hosts(id,tenant_id,name,token_hash) VALUES($1,$2,'Browser fixture host',$3)",
  [host, tenant, digest(randomUUID())],
);
const ids: string[] = [];
for (let i = 0; i < 205; i++) {
  const id = randomUUID();
  ids.push(id);
  const body = {
    id,
    agent: "codex",
    sessionId: randomUUID(),
    manifestDigest: "a".repeat(64),
    fileCount: i + 1,
    totalBytes: i + 1,
    capturedAt: "2026-01-01T00:00:00Z",
    status: "succeeded",
  };
  await database().query(
    "INSERT INTO snapshots(id,tenant_id,host_id,body,created_at) VALUES($1,$2,$3,$4,'2026-01-01T00:00:00.123456Z')",
    [id, tenant, host, body],
  );
}
const oldSnapshot = ids.sort()[0],
  alert = randomUUID();
await database().query(
  "INSERT INTO alerts(id,tenant_id,host_id,dedupe_key,body) VALUES($1::uuid,$2,$3,$1::text,$4)",
  [
    alert,
    tenant,
    host,
    {
      eventId: alert,
      type: "backup-failed",
      severity: "warning",
      snapshotId: oldSnapshot,
      count: 1,
    },
  ],
);
for (let i = 0; i < 201; i++)
  await database().query(
    "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')",
    [digest(randomUUID()), admin],
  );
const recoveryToken = await transaction((db) => issueRecovery(db, recover));
await writeFile(
  process.env.BUNKER_TEST_BROWSER_FIXTURE,
  JSON.stringify({ tenant, other, admin, viewer, oldSnapshot, recoveryToken }),
  { mode: 0o600 },
);
await database().end();
console.log("Disposable browser fixtures ready.");
