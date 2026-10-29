// Production bootstrap/worker smoke: disposable resources, no public receiver or keys.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const image =
  process.env.BUNKER_SMOKE_IMAGE || "bunker-control-plane:council-smoke";
const prefix = "bunker-notification-smoke-" + randomUUID().slice(0, 8);
const network = prefix + "-net",
  volume = prefix + "-fixtures";
const db = prefix + "-db",
  worker = prefix + "-worker",
  copy = prefix + "-copy";
const dir = mkdtempSync(join(tmpdir(), prefix));
const database = "postgresql://bunker_smoke@database:5432/postgres";
const tenant = randomUUID(),
  org = randomUUID(),
  host = randomUUID(),
  alert = randomUUID(),
  delivery = randomUUID();
const docker = (args: string[], input?: string) =>
  execFileSync("docker", ["--context", "homelab", ...args], {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    timeout: 120000,
  });
const sql = (query: string) =>
  docker(
    [
      "exec",
      "-i",
      db,
      "psql",
      "-U",
      "bunker_smoke",
      "-d",
      "postgres",
      "-v",
      "ON_ERROR_STOP=1",
      "-At",
    ],
    query,
  ).trim();
const pause = () => new Promise((resolve) => setTimeout(resolve, 300));
const created: string[] = [];
let networkCreated = false,
  volumeCreated = false;
try {
  for (const part of ["config", "signing"])
    mkdirSync(join(dir, part, "..data"), { recursive: true });
  writeFileSync(
    join(dir, "config", "..data", "config.json"),
    JSON.stringify({
      destinations: [
        {
          tenantId: tenant,
          id: "primary-v1",
          url: "https://127.0.0.1/never-contact",
          secretFile: "/run/bunker/notifications/signing/receiver.key",
        },
      ],
    }),
    { mode: 0o640 },
  );
  writeFileSync(
    join(dir, "signing", "..data", "receiver.key"),
    randomBytes(32),
    { mode: 0o640 },
  );
  symlinkSync("..data/config.json", join(dir, "config", "config.json"));
  symlinkSync("..data/receiver.key", join(dir, "signing", "receiver.key"));
  docker(["network", "create", "--internal", network]);
  networkCreated = true;
  docker(["volume", "create", volume]);
  volumeCreated = true;
  docker([
    "run",
    "-d",
    "--name",
    db,
    "--network",
    network,
    "--network-alias",
    "database",
    "-e",
    "POSTGRES_USER=bunker_smoke",
    "-e",
    "POSTGRES_DB=postgres",
    "-e",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "postgres:17-bookworm",
  ]);
  created.push(db);
  for (let i = 0; ; i++) {
    try {
      sql("SELECT 1");
      break;
    } catch {
      if (i === 30) throw new Error("Disposable PostgreSQL did not start");
      await pause();
    }
  }
  const run = [
    "run",
    "--rm",
    "--network",
    network,
    "-e",
    "DATABASE_URL=" + database,
  ];
  for (let i = 0; i < 2; i++)
    docker([
      ...run,
      image,
      "node",
      "--import",
      "./control-plane/node_modules/tsx/dist/loader.mjs",
      "control-plane/scripts/migrate.ts",
    ]);
  assert.equal(
    sql("SELECT count(*) FROM schema_migrations WHERE version=3"),
    "1",
  );
  sql(`INSERT INTO organizations VALUES('${org}','smoke');
    INSERT INTO tenants VALUES('${tenant}','${org}','smoke');
    INSERT INTO hosts(id,tenant_id,name,token_hash) VALUES('${host}','${tenant}','smoke','disposable');
    INSERT INTO alerts(id,tenant_id,host_id,dedupe_key,body) VALUES('${alert}','${tenant}','${host}','smoke','{}');
    INSERT INTO notification_outbox(id,tenant_id,alert_id,destination_id,payload) VALUES('${delivery}','${tenant}','${alert}','missing-route','{}');`);
  docker([
    "create",
    "--name",
    copy,
    "-v",
    volume + ":/fixtures",
    "--entrypoint",
    "true",
    image,
  ]);
  created.push(copy);
  docker(["cp", dir + "/.", copy + ":/fixtures"]);
  docker([
    "run",
    "--rm",
    "-u",
    "0",
    "-v",
    volume + ":/fixtures",
    "--entrypoint",
    "chown",
    image,
    "-R",
    "1000:1000",
    "/fixtures",
  ]);
  const mounts = [
    "--mount",
    `type=volume,src=${volume},dst=/run/secrets/notification-config,volume-subpath=config,readonly`,
  ];
  const sandbox = [
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/run/bunker:uid=1000,gid=1000,mode=0700",
  ];
  // API bootstrap gets a config-only mount and still succeeds without a signing mount.
  docker([
    ...run,
    ...sandbox,
    ...mounts,
    "-e",
    "BUNKER_NOTIFICATIONS_ENABLED=true",
    image,
    "node",
    "--import",
    "./control-plane/node_modules/tsx/dist/loader.mjs",
    "--input-type=module",
    "-e",
    "import {bootstrapNotifications} from './control-plane/scripts/notification-bootstrap.ts'; import {existsSync} from 'node:fs'; bootstrapNotifications('api'); if(existsSync('/run/bunker/notifications/signing')||existsSync('/run/secrets/notification-signing'))process.exit(1)",
  ]);
  docker([
    "create",
    "--name",
    worker,
    "--network",
    network,
    "--stop-timeout",
    "60",
    ...sandbox,
    ...mounts,
    "--mount",
    `type=volume,src=${volume},dst=/run/secrets/notification-signing,volume-subpath=signing,readonly`,
    "-e",
    "DATABASE_URL=" + database,
    "-e",
    "BUNKER_NOTIFICATIONS_ENABLED=true",
    image,
    "node",
    "--import",
    "./control-plane/node_modules/tsx/dist/loader.mjs",
    "control-plane/scripts/notification-entrypoint.ts",
  ]);
  created.push(worker);
  const waitAttempt = async (attempt: number, state: "retrying" | "failed") => {
    for (let i = 0; i < 50; i++) {
      if (
        sql(
          `SELECT state||':'||attempts||':'||last_error FROM notification_outbox WHERE id='${delivery}'`,
        ) === `${state}:${attempt}:configuration`
      )
        return;
      await pause();
    }
    throw new Error(
      "Production worker did not persist the expected configuration/SSRF result",
    );
  };
  docker(["start", worker]);
  await waitAttempt(1, "retrying");
  docker([
    "exec",
    worker,
    "node",
    "-e",
    `const fs=require('fs'); for(const p of ['/run/bunker/notifications/config.json','/run/bunker/notifications/signing/receiver.key']){const s=fs.lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||(s.mode&511)!==384||s.uid!==1000)process.exit(1)} for(const p of ['/run/secrets/bunker','/run/bunker/secrets'])if(fs.existsSync(p))process.exit(2)`,
  ]);
  docker(["stop", "-t", "60", worker]);
  assert.equal(
    docker(["inspect", "-f", "{{.State.ExitCode}}", worker]).trim(),
    "0",
  );
  sql(
    `UPDATE notification_outbox SET available_at=clock_timestamp(),destination_id='primary-v1' WHERE id='${delivery}'`,
  );
  docker(["start", worker]);
  await waitAttempt(2, "failed");
  docker(["stop", "-t", "60", worker]);
  assert.equal(
    docker(["inspect", "-f", "{{.State.ExitCode}}", worker]).trim(),
    "0",
  );
  // Disabled worker and test-only transport must fail before connecting to the database.
  for (const env of [
    [],
    [
      "-e",
      "BUNKER_NOTIFICATIONS_ENABLED=true",
      "-e",
      "BUNKER_WEBHOOK_TEST_TRANSPORT_FILE=/test",
    ],
  ]) {
    assert.throws(() =>
      docker([
        ...run,
        ...sandbox,
        ...env,
        image,
        "node",
        "--import",
        "./control-plane/node_modules/tsx/dist/loader.mjs",
        "control-plane/scripts/notification-entrypoint.ts",
      ]),
    );
  }
  console.log(
    "PASS notification image: migration 003 idempotent; projected 0600 files; API/signing separation; durable claims; production SSRF rejection; restart; graceful SIGTERM; disabled/test-transport rejection",
  );
} finally {
  for (const name of created.reverse()) {
    try {
      docker(["rm", "-f", name]);
    } catch {
      /* best-effort cleanup */
    }
  }
  if (volumeCreated) docker(["volume", "rm", volume]);
  if (networkCreated) docker(["network", "rm", network]);
  rmSync(dir, { recursive: true, force: true });
}
