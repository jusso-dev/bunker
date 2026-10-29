import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  chmodSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { protectedFile, gatewayKey } from "../src/identity/files";
import { providers } from "../src/identity/federation";
import { createGateway } from "../src/gateway/server";
test("identity configuration fails closed on unsafe files, redirects, issuers, and remote upstreams", () => {
  const dir = mkdtempSync(join(tmpdir(), "bunker-config-")),
    path = join(dir, "config");
  const prior = {
    origin: process.env.BUNKER_ORIGIN,
    providers: process.env.BUNKER_IDENTITY_PROVIDERS_FILE,
    key: process.env.BUNKER_GATEWAY_SECRET_FILE,
  };
  try {
    writeFileSync(path, "test", { mode: 0o600 });
    assert.equal(protectedFile(path).toString(), "test");
    chmodSync(path, 0o644);
    assert.throws(() => protectedFile(path));
    chmodSync(path, 0o600);
    symlinkSync(path, join(dir, "link"));
    assert.throws(() => protectedFile(join(dir, "link")));
    assert.throws(() => protectedFile("relative"));
    assert.throws(() => protectedFile(dir));
    process.env.BUNKER_GATEWAY_SECRET_FILE = path;
    assert.throws(() => gatewayKey());
    process.env.BUNKER_ORIGIN = "https://bunker.example.test";
    process.env.BUNKER_IDENTITY_PROVIDERS_FILE = path;
    const valid = {
      id: "entra",
      name: "Entra",
      kind: "oidc",
      issuer: "https://issuer.example.test/tenant",
      clientId: "fixture",
      clientSecretFile: join(dir, "provider-secret"),
      redirectUri:
        "https://bunker.example.test/api/auth/federated/entra/callback",
    };
    for (const data of [
      [{ ...valid, issuer: "http://issuer.example.test" }],
      [{ ...valid, redirectUri: "https://evil.example.test/callback" }],
      [valid, valid],
      [{ ...valid, kind: "github" }],
    ]) {
      writeFileSync(path, JSON.stringify(data));
      assert.throws(() => providers());
    }
    writeFileSync(path, JSON.stringify([valid]));
    assert.equal(providers().length, 1);
    assert.throws(() =>
      createGateway({
        origin: "https://bunker.example.test",
        upstream: "http://192.0.2.1:3000",
        secret: Buffer.alloc(32),
        key: Buffer.alloc(0),
        cert: Buffer.alloc(0),
        ca: Buffer.alloc(0),
        clientAuth: "required",
      }),
    );
  } finally {
    for (const [key, value] of Object.entries({
      BUNKER_ORIGIN: prior.origin,
      BUNKER_IDENTITY_PROVIDERS_FILE: prior.providers,
      BUNKER_GATEWAY_SECRET_FILE: prior.key,
    })) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
