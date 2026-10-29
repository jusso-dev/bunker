// Disposable test resources only. Never uses an operator DATABASE_URL or secrets.
import { execFileSync } from "node:child_process";
import { copyFileSync, symlinkSync, mkdirSync, renameSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { fixtures } from "../control-plane/tests/identity-fixtures";
const image =
  process.env.BUNKER_SMOKE_IMAGE || "bunker-control-plane:council-smoke";
const prefix = "bunker-smoke-" + randomUUID().slice(0, 8);
const network = prefix + "-net",
  volume = prefix + "-secrets",
  app = prefix + "-app",
  db = prefix + "-db";
const f = fixtures();
const docker = (args: string[], input?: string) =>
  execFileSync("docker", ["--context", "homelab", ...args], {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    timeout: 120000,
  });
const database = "postgresql://bunker_smoke@database:5432/postgres";
try {
  copyFileSync(f.file("server.key"), f.file("tls.key"));
  copyFileSync(f.file("server.pem"), f.file("tls.crt"));
  copyFileSync(f.file("ca.pem"), f.file("ca.crt"));
  copyFileSync(f.file("ca.pem"), f.file("tls-ca.crt"));
  f.write("providers.json", "[]");
  copyFileSync(
    resolve("../deploy/smoke-client.mjs"),
    f.file("image-client.mjs"),
  );
  // Model the Kubernetes Secret projection, with a symlink for a required key.
  mkdirSync(f.file("..data"));
  renameSync(f.file("tls.key"), f.file("..data/tls.key"));
  symlinkSync("..data/tls.key", f.file("tls.key"));
  docker(["network", "create", "--internal", network]);
  docker(["volume", "create", volume]);
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
  for (let i = 0; ; i++) {
    try {
      docker(["exec", db, "pg_isready", "-U", "bunker_smoke"]);
      break;
    } catch {
      if (i === 30) throw new Error("Disposable PostgreSQL did not start");
      await new Promise((r) => setTimeout(r, 500));
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
  docker([
    ...run,
    image,
    "node",
    "control-plane/node_modules/tsx/dist/cli.mjs",
    "control-plane/scripts/migrate.ts",
  ]);
  docker(
    [
      ...run,
      "-i",
      image,
      "node",
      "control-plane/node_modules/tsx/dist/cli.mjs",
      "control-plane/scripts/bootstrap.ts",
      "image-smoke@example.test",
      "Smoke",
      "Smoke",
    ],
    "disposable-image-smoke-password\n",
  );
  docker([
    "create",
    "--name",
    app,
    "--network",
    network,
    "--network-alias",
    "app",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/run/bunker:uid=1000,gid=1000,mode=0700",
    "--tmpfs",
    "/app/control-plane/.next/cache:uid=1000,gid=1000,mode=0700",
    "-v",
    volume + ":/run/secrets/bunker:ro",
    "-e",
    "DATABASE_URL=" + database,
    "-e",
    "BUNKER_ORIGIN=https://localhost:8443",
    "-e",
    "BUNKER_HOST_ORIGIN=https://localhost:8444",
    image,
  ]);
  // Populate only the newly-created disposable volume; never a host secret path.
  docker([
    "create",
    "--name",
    prefix + "-copy",
    "-v",
    volume + ":/fixtures",
    "--entrypoint",
    "true",
    image,
  ]);
  docker(["cp", f.dir + "/.", prefix + "-copy:/fixtures"]);
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
  docker(["start", app]);
  console.log(
    docker([
      ...run,
      "-v",
      volume + ":/run/secrets/bunker:ro",
      image,
      "node",
      "/run/secrets/bunker/image-client.mjs",
    ]).trim(),
  );
  docker(["exec", app, "node", "control-plane/scripts/healthcheck.mjs"]);
  docker([
    "exec",
    app,
    "node",
    "control-plane/scripts/healthcheck.mjs",
    "--live",
  ]);
  docker(["restart", app]);
  console.log(
    docker([
      ...run,
      "-v",
      volume + ":/run/secrets/bunker:ro",
      image,
      "node",
      "/run/secrets/bunker/image-client.mjs",
    ]).trim(),
  );
  // Missing identity mount must terminate, not serve HTTP as a fallback.
  docker([
    "create",
    "--name",
    prefix + "-invalid",
    "-e",
    "DATABASE_URL=" + database,
    image,
  ]);
  docker(["start", prefix + "-invalid"]);
  const exit = docker(["wait", prefix + "-invalid"]).trim();
  if (exit === "0")
    throw new Error("Missing identity configuration did not fail closed");
  // Killing Next must terminate the public gateway too.
  docker([
    "exec",
    app,
    "node",
    "-e",
    "const fs=require('fs');for(const p of fs.readdirSync('/proc').filter(x=>/^\\d+$/.test(x))){try{if(fs.readFileSync('/proc/'+p+'/comm','utf8').startsWith('next-server'))process.kill(+p,'SIGTERM')}catch{}}",
  ]);
  if (docker(["wait", app]).trim() === "0")
    throw new Error("Next failure was not propagated");
  console.log(
    "PASS image: trusted probes; projected secrets; restart; missing configuration and Next failure terminate container",
  );
} finally {
  for (const name of [app, db, prefix + "-copy", prefix + "-invalid"])
    try {
      docker(["rm", "-f", name]);
    } catch {
      /* not created */
    }
  try {
    docker(["volume", "rm", volume]);
  } catch {
    /* not created */
  }
  try {
    docker(["network", "rm", network]);
  } catch {
    /* not created */
  }
  f.cleanup();
}
