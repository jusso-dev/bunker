// Runs in an independent container/network namespace against the built image.
import assert from "node:assert/strict";
import https from "node:https";
import net from "node:net";
import { readFileSync } from "node:fs";
const read = (name) => readFileSync("/run/secrets/bunker/" + name);
const origin = "https://localhost:8443";
const call = (path, options = {}) =>
  new Promise((resolve, reject) => {
    const { body, ...rest } = options;
    const req = https.request(
      {
        hostname: "app",
        port: 8443,
        servername: "localhost",
        ca: read("ca.pem"),
        rejectUnauthorized: true,
        path,
        timeout: 4000,
        ...rest,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(body);
  });
let ready = false;
for (let attempt = 0; attempt < 100; attempt++) {
  try {
    if ((await call("/api/auth/providers")).status === 200) {
      ready = true;
      break;
    }
  } catch {
    /* startup */
  }
  await new Promise((resolve) => setTimeout(resolve, 200));
}
assert.ok(ready, "public gateway ready");
await assert.rejects(
  new Promise((resolve, reject) => {
    const socket = net.connect({ host: "app", port: 3000, timeout: 2000 });
    socket.on("connect", () => {
      socket.destroy();
      resolve();
    });
    socket.on("error", reject);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("timeout"));
    });
  }),
  "private Next port must be unreachable from a peer container",
);
await assert.rejects(
  call("/api/auth/providers", { port: 8444 }),
  "host listener requires a client certificate",
);
const login = await call("/api/auth/login", {
  method: "POST",
  headers: { origin, "content-type": "application/json" },
  body: JSON.stringify({
    email: "image-smoke@example.test",
    password: "disposable-image-smoke-password",
  }),
});
assert.equal(login.status, 200, "login");
const cookie = login.headers["set-cookie"][0].split(";")[0];
const headers = { origin, cookie, "content-type": "application/json" };
const me = await call("/api/me", { headers });
assert.equal(me.status, 200, "session");
const tenant = JSON.parse(me.body).tenants[0].id;
assert.ok(tenant, "bootstrap tenant");
const created = await call(`/api/tenants/${tenant}/enrollments`, {
  method: "POST",
  headers,
  body: JSON.stringify({ name: "image smoke host" }),
});
assert.equal(created.status, 201, "enrollment token");
const enrolled = await call("/api/enroll", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    token: JSON.parse(created.body).token,
    csr: read("host.csr").toString(),
  }),
});
assert.equal(enrolled.status, 201, "CSR certificate issuance");
const cert = JSON.parse(enrolled.body).certificate;
const path = `/api/tenants/${tenant}/policies`;
assert.equal(
  (await call(path, { port: 8444, key: read("host.key"), cert })).status,
  200,
  "host mTLS policies",
);
assert.equal(
  (
    await call(path, {
      headers: { "x-client-cert": cert.replaceAll("\n", "") },
    })
  ).status,
  401,
  "public certificate-header spoof rejected",
);
console.log(
  "PASS image: peer cannot reach Next; verified public TLS login/enrollment; mandatory host mTLS; spoof rejected",
);
