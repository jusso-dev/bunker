import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { randomUUID } from "node:crypto";
import { fixtures, listen, close, tlsCall } from "./identity-fixtures";
import { createGateway } from "../src/gateway/server";
import { database } from "../src/lib/db";
import { passwordHash } from "../src/lib/security";
import { exerciseRustHost } from "./rust-host-fixture";

test(
  "built Next server behind production TLS gateway",
  { timeout: 90000 },
  async () => {
    assert.ok(
      process.env.BUNKER_TEST_DATABASE_URL,
      "Disposable database required",
    );
    process.env.DATABASE_URL = process.env.BUNKER_TEST_DATABASE_URL;
    const f = fixtures(),
      db = database(),
      org = randomUUID(),
      tenant = randomUUID(),
      user = randomUUID();
    const reserve = createServer();
    const port = await listen(reserve);
    await close(reserve);
    const common = {
      key: f.read("server.key"),
      cert: f.read("server.pem"),
      ca: f.read("ca.pem"),
      secret: f.read("gateway.secret"),
      upstream: `http://127.0.0.1:${port}`,
    };
    const publicGateway = createGateway({
        ...common,
        origin: "https://localhost",
        clientAuth: "public",
      }),
      hostGateway = createGateway({
        ...common,
        origin: "https://localhost",
        clientAuth: "required",
      });
    const origin = `https://127.0.0.1:${await listen(publicGateway)}`,
      hostOrigin = `https://127.0.0.1:${await listen(hostGateway)}`;
    await db.query("INSERT INTO organizations VALUES($1,'next fixture')", [
      org,
    ]);
    await db.query("INSERT INTO tenants VALUES($1,$2,'next fixture')", [
      tenant,
      org,
    ]);
    await db.query("INSERT INTO users VALUES($1,$2,$3)", [
      user,
      `${user}@example.test`,
      passwordHash("disposable-next-password"),
    ]);
    await db.query("INSERT INTO memberships VALUES($1,$2,'admin')", [
      tenant,
      user,
    ]);
    const child = spawn(
      process.execPath,
      [
        "node_modules/next/dist/bin/next",
        "start",
        "--hostname",
        "127.0.0.1",
        "--port",
        String(port),
      ],
      {
        env: {
          ...process.env,
          BUNKER_ORIGIN: origin,
          BUNKER_ALLOW_INSECURE_LOOPBACK: "false",
          BUNKER_IDENTITY_PROVIDERS_FILE: "",
          BUNKER_GATEWAY_SECRET_FILE: f.file("gateway.secret"),
          BUNKER_CA_CERT_FILE: f.file("ca.pem"),
          BUNKER_CA_KEY_FILE: f.file("ca.key"),
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    // Drain output without exposing configuration or request details.
    child.stdout.resume();
    child.stderr.resume();
    try {
      let ready = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        if (child.exitCode !== null)
          throw new Error("Next exited before readiness");
        const r = await tlsCall(
          origin + "/api/auth/providers",
          f.read("ca.pem"),
        );
        if (r.status === 200) {
          ready = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.ok(ready, "built Next is ready through gateway");
      assert.equal(
        (await fetch(`http://127.0.0.1:${port}/api/auth/providers`)).status,
        401,
      );
      const login = await tlsCall(
        origin + "/api/auth/login",
        f.read("ca.pem"),
        {
          method: "POST",
          headers: { origin, "content-type": "application/json" },
          body: JSON.stringify({
            email: `${user}@example.test`,
            password: "disposable-next-password",
          }),
        },
      );
      assert.equal(login.status, 200, login.body);
      const cookie = login.headers["set-cookie"]![0].split(";")[0];
      assert.ok(cookie.startsWith("bunker_session="));
      const headers = { origin, cookie, "content-type": "application/json" };
      const created = await tlsCall(
        origin + `/api/tenants/${tenant}/enrollments`,
        f.read("ca.pem"),
        {
          method: "POST",
          headers,
          body: JSON.stringify({ name: "next mTLS fixture" }),
        },
      );
      assert.equal(created.status, 201, created.body);
      const enrolled = await tlsCall(origin + "/api/enroll", f.read("ca.pem"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: JSON.parse(created.body).token,
          csr: f.read("host.csr").toString(),
        }),
      });
      assert.equal(enrolled.status, 201, enrolled.body);
      const certificate = JSON.parse(enrolled.body).certificate;
      const policy = await tlsCall(
        hostOrigin + `/api/tenants/${tenant}/policies`,
        f.read("ca.pem"),
        { key: f.read("host.key"), cert: Buffer.from(certificate) },
      );
      assert.equal(policy.status, 200, policy.body);
      if (process.env.BUNKER_TEST_BINARY) {
        await exerciseRustHost(
          process.env.BUNKER_TEST_BINARY,
          f,
          origin,
          hostOrigin,
          tenant,
          headers,
        );
      }
      const logout = await tlsCall(
        origin + "/api/auth/logout",
        f.read("ca.pem"),
        { method: "POST", headers, body: "{}" },
      );
      assert.equal(logout.status, 200, logout.body);
      assert.equal(
        (
          await tlsCall(origin + "/api/me", f.read("ca.pem"), {
            headers: { cookie },
          })
        ).status,
        401,
      );
    } finally {
      child.kill("SIGTERM");
      if (child.exitCode === null)
        await new Promise<void>((resolve) =>
          child.once("exit", () => resolve()),
        );
      await close(publicGateway);
      await close(hostGateway);
      await db.end();
      f.cleanup();
    }
  },
);
