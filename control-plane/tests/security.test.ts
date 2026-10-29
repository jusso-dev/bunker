import { test } from "node:test";
import assert from "node:assert/strict";
import {
  passwordHash,
  passwordMatches,
  digest,
  requireOrigin,
  requireAgentTransport,
} from "../src/lib/security";
import * as s from "../src/lib/schemas";
test("salted password hashing verifies only correct passwords", () => {
  const a = passwordHash("a sufficiently long password"),
    b = passwordHash("a sufficiently long password");
  assert.notEqual(a, b);
  assert.equal(passwordMatches("a sufficiently long password", a), true);
  assert.equal(passwordMatches("wrong password", a), false);
  assert.equal(digest("secret").length, 64);
});
test("metadata schemas reject content, keys, malformed digests, unsupported channels", () => {
  const snapshot = {
    id: crypto.randomUUID(),
    agent: "codex",
    sessionId: crypto.randomUUID(),
    manifestDigest: "a".repeat(64),
    fileCount: 1,
    totalBytes: 3,
    capturedAt: new Date().toISOString(),
    status: "succeeded",
  };
  assert.equal(s.snapshot.safeParse(snapshot).success, true);
  for (const key of [
    "content",
    "plaintext",
    "privateKey",
    "accessToken",
    "data",
  ])
    assert.equal(
      s.snapshot.safeParse({ ...snapshot, [key]: "sensitive" }).success,
      false,
    );
  assert.equal(s.hash.safeParse("not-a-hash").success, false);
  assert.equal(
    s.snapshot.safeParse({ ...snapshot, fileCount: -1 }).success,
    false,
  );
});
test("origin and production host transport fail closed", () => {
  const saved = { ...process.env };
  try {
    process.env.BUNKER_ORIGIN = "https://bunker.example";
    delete process.env.BUNKER_ALLOW_INSECURE_LOOPBACK;
    assert.throws(() =>
      requireOrigin(
        new Request("https://bunker.example/api/auth/login", {
          headers: { origin: "https://attacker.example" },
        }),
      ),
    );
    assert.throws(() =>
      requireAgentTransport(
        new Request("https://bunker.example/api/enroll", {
          headers: { "x-client-cert-verified": "SUCCESS" },
        }),
      ),
    );
    process.env.BUNKER_ALLOW_INSECURE_LOOPBACK = "true";
    assert.throws(() =>
      requireAgentTransport(new Request("https://bunker.example/api/enroll")),
    );
  } finally {
    process.env = saved;
  }
});

test("restore evidence accepts legacy and tri-state reports but rejects false success and unbounded reasons", () => {
  const report = {
    id: crypto.randomUUID(),
    snapshotId: crypto.randomUUID(),
    finishedAt: new Date().toISOString(),
    sandbox: "container",
    agents: [{ agent: "codex", outcome: "passed" }],
    mcps: [],
  };
  for (const probe of [
    { agent: "codex", passed: true },
    { agent: "codex", passed: false },
    { agent: "codex", outcome: "passed" },
    { agent: "codex", outcome: "failed", reasonCode: "timeout" },
    { agent: "codex", outcome: "not_run", reasonCode: "network_unavailable" },
  ])
    assert.equal(
      s.evidence.safeParse({ ...report, agents: [probe] }).success,
      true,
    );
  for (const probe of [
    {
      agent: "codex",
      outcome: "not_run",
      passed: true,
      reasonCode: "not_configured",
    },
    { agent: "codex", outcome: "passed", passed: false },
    { agent: "codex", outcome: "passed", reasonCode: "timeout" },
    {
      agent: "codex",
      outcome: "failed",
      reasonCode: "credentials_unavailable",
    },
    { agent: "codex", outcome: "not_run", reasonCode: "timeout" },
    { agent: "codex", outcome: "not_run" },
    { agent: "codex", outcome: "failed", reasonCode: "raw command and secret" },
  ])
    assert.equal(
      s.evidence.safeParse({ ...report, agents: [probe] }).success,
      false,
    );
});
