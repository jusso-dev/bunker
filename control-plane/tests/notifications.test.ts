import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHmac } from "node:crypto";
import { createServer } from "node:https";
import { chmodSync } from "node:fs";
import { fixtures, listen, close } from "./identity-fixtures";
import {
  destinations,
  destinationUrl,
  isPublicAddress,
  testTransport,
  signingSecret,
} from "../src/notifications/config";
import {
  deliver,
  signature,
  RESPONSE_LIMIT,
} from "../src/notifications/transport";
import { policy } from "../src/lib/schemas";

test("webhook policy requires UI and unique explicit opt-in", () => {
  const channels = policy.shape.channels;
  for (const value of [["ui"], ["ui", "webhook"]])
    assert.equal(channels.safeParse(value).success, true);
  for (const value of [[], ["webhook"], ["ui", "ui"], ["ui", "slack"]])
    assert.equal(channels.safeParse(value).success, false);
});
test("SSRF guard accepts only public unicast addresses and HTTPS URLs without credentials", () => {
  for (const ip of [
    "127.0.0.1",
    "10.0.0.2",
    "169.254.169.254",
    "192.168.0.1",
    "172.16.0.1",
    "100.64.0.1",
    "198.19.1.1",
    "192.0.0.9",
    "203.0.113.1",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "::ffff:8.8.8.8",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "2001::1",
    "2002:0808:0808::1",
    "3fff::1",
    "not-an-ip",
  ])
    assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    assert.equal(isPublicAddress(ip), true);
  for (const url of [
    "http://example.test",
    "https://user:password@example.test",
    "https://example.test/#a",
    "https://example.test/?token=value",
  ])
    assert.throws(() => destinationUrl(url));
});
test("protected configuration and disposable TLS delivery", async (t) => {
  const previous = { ...process.env };
  const f = fixtures();
  const wrongCa = fixtures();
  const secret = randomBytes(32);
  let status = 204,
    responseBytes = 0,
    hang = false,
    requests = 0;
  const bodies: string[] = [],
    headers: import("node:http").IncomingHttpHeaders[] = [];
  const server = createServer(
    { key: f.read("server.key"), cert: f.read("server.pem") },
    (req, res) => {
      requests++;
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        bodies.push(Buffer.concat(chunks).toString("utf8"));
        headers.push(req.headers);
        if (hang) return;
        res.writeHead(status, {
          location: "https://127.0.0.1/never-follow",
          "content-type": "text/plain",
        });
        res.end("x".repeat(responseBytes));
      });
    },
  );
  try {
    const port = await listen(server);
    (process.env as Record<string, string | undefined>).NODE_ENV = "test";
    f.write("signing", secret);
    f.write("transport.json", JSON.stringify({ caFile: f.file("ca.pem") }));
    process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE = f.file("transport.json");
    const d = {
      tenantId: "971122e0-dc06-4acb-8d25-e77991e8796f",
      id: "primary",
      url: `https://127.0.0.1:${port}/alerts`,
      secretFile: f.file("signing"),
    };
    f.write("destinations.json", JSON.stringify({ destinations: [d] }));
    process.env.BUNKER_WEBHOOK_CONFIG_FILE = f.file("destinations.json");
    await t.test(
      "config validates references, permissions, duplicates, environment secrets",
      () => {
        assert.equal(destinations().length, 1);
        assert.deepEqual(signingSecret(d), secret);
        process.env.BUNKER_TEST_SIGNING = "a".repeat(32);
        assert.equal(
          signingSecret({
            ...d,
            secretFile: undefined,
            secretEnv: "BUNKER_TEST_SIGNING",
          }).length,
          32,
        );
        chmodSync(f.file("destinations.json"), 0o644);
        assert.throws(
          () => destinations(),
          /Webhook configuration is unavailable/,
        );
        f.write("destinations.json", JSON.stringify({ destinations: [d, d] }));
        assert.throws(
          () => destinations(),
          /Webhook configuration is unavailable/,
        );
        f.write("destinations.json", JSON.stringify({ destinations: [d] }));
        (process.env as Record<string, string | undefined>).NODE_ENV =
          "production";
        assert.throws(() => testTransport(), /requires NODE_ENV=test/);
        (process.env as Record<string, string | undefined>).NODE_ENV = "test";
      },
    );
    const payload = { version: 1, deliveryId: "delivery-id", count: 3 };
    await t.test(
      "raw body signature and stable idempotency key across attempts",
      async () => {
        for (let i = 0; i < 2; i++)
          assert.deepEqual(await deliver(d, "delivery-id", payload), {
            ok: true,
            retryable: false,
            status: 204,
          });
        assert.equal(bodies[0], bodies[1]);
        assert.deepEqual(JSON.parse(bodies[0]), payload);
        for (const h of headers) {
          assert.equal(h["idempotency-key"], "delivery-id");
          assert.equal(h["x-bunker-delivery-id"], "delivery-id");
          const timestamp = String(h["x-bunker-timestamp"]);
          const expected = createHmac("sha256", secret)
            .update(timestamp + "." + bodies[0])
            .digest("hex");
          assert.equal(h["x-bunker-signature"], `v1=${expected}`);
          assert.notEqual(
            signature(secret, timestamp, bodies[0] + " "),
            expected,
          );
          assert.notEqual(
            signature(secret, String(Number(timestamp) + 1), bodies[0]),
            expected,
          );
          assert.equal(h.authorization, undefined);
          assert.equal(h.cookie, undefined);
        }
      },
    );
    await t.test(
      "hostname lookup pins a verified address and retains TLS hostname validation",
      async () => {
        assert.equal(
          (
            await deliver(
              { ...d, url: d.url.replace("127.0.0.1", "localhost") },
              "dns-delivery",
              payload,
            )
          ).ok,
          true,
        );
      },
    );
    await t.test(
      "redirects and permanent 4xx stop; 408, 429 and 5xx retry",
      async () => {
        for (const code of [302, 400, 401, 404, 408, 429, 500, 503]) {
          status = code;
          const before = requests;
          const result = await deliver(d, "delivery-id", payload);
          assert.equal(result.status, code);
          assert.equal(result.retryable, [408, 429, 500, 503].includes(code));
          assert.equal(requests, before + 1);
        }
      },
    );
    await t.test("oversized and stalled responses are bounded", async () => {
      status = 200;
      responseBytes = RESPONSE_LIMIT + 1;
      assert.equal(
        (await deliver(d, "delivery-id", payload)).error,
        "response-too-large",
      );
      responseBytes = 0;
      hang = true;
      assert.equal((await deliver(d, "delivery-id", payload)).error, "timeout");
      hang = false;
    });
    await t.test(
      "untrusted TLS and private production addresses never receive a message",
      async () => {
        const before = requests;
        f.write(
          "transport.json",
          JSON.stringify({ caFile: wrongCa.file("ca.pem") }),
        );
        assert.equal(
          (await deliver(d, "delivery-id", payload)).error,
          "network",
        );
        delete process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE;
        assert.equal(
          (await deliver(d, "delivery-id", payload)).error,
          "configuration",
        );
        assert.equal(requests, before);
      },
    );
  } finally {
    server.closeAllConnections();
    await close(server);
    f.cleanup();
    wrongCa.cleanup();
    for (const key of Object.keys(process.env))
      if (!(key in previous)) delete process.env[key];
    Object.assign(process.env, previous);
  }
});
