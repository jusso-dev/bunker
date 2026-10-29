import { execFileSync } from "node:child_process";
import { issueCertificate } from "../src/identity/certificates";
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { randomUUID, X509Certificate, createHash } from "node:crypto";
import { SignJWT, decodeJwt, exportJWK, generateKeyPair } from "jose";
import {
  fixtures,
  listen,
  close,
  tlsCall,
  expiredHostCertificate,
} from "./identity-fixtures";
import { createGateway } from "../src/gateway/server";
import { handle } from "../src/lib/api";
import { database } from "../src/lib/db";
import { digest, passwordHash } from "../src/lib/security";
import { proofHeader, signGatewayRequest } from "../src/identity/gateway-proof";
const enabled = !!process.env.BUNKER_TEST_DATABASE_URL;
test(
  "production identity across real verified TLS and PostgreSQL",
  { skip: !enabled },
  async (t) => {
    process.env.DATABASE_URL = process.env.BUNKER_TEST_DATABASE_URL;
    delete process.env.BUNKER_ALLOW_INSECURE_LOOPBACK;
    const f = fixtures(),
      db = database(),
      tenant = randomUUID(),
      other = randomUUID(),
      user = randomUUID(),
      org = randomUUID();
    process.env.BUNKER_CA_CERT_FILE = f.file("ca.pem");
    process.env.BUNKER_CA_KEY_FILE = f.file("ca.key");
    process.env.BUNKER_GATEWAY_SECRET_FILE = f.file("gateway.secret");
    const upstream = http.createServer(async (req, res) => {
      try {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk);
        const response = await handle(
          new Request(`https://${req.headers.host}${req.url}`, {
            method: req.method,
            headers: req.headers as Record<string, string>,
            ...(["GET", "HEAD"].includes(req.method!)
              ? {}
              : { body: Buffer.concat(chunks) }),
          }),
        );
        res.writeHead(response.status, {
          ...Object.fromEntries(response.headers),
          ...(response.headers.getSetCookie().length
            ? { "set-cookie": response.headers.getSetCookie() }
            : {}),
        });
        res.end(Buffer.from(await response.arrayBuffer()));
      } catch {
        res.writeHead(500);
        res.end();
      }
    });
    const upstreamPort = await listen(upstream);
    const shared = {
      key: f.read("server.key"),
      cert: f.read("server.pem"),
      ca: f.read("ca.pem"),
      secret: f.read("gateway.secret"),
      upstream: `http://127.0.0.1:${upstreamPort}`,
    };
    const browser = createGateway({
      ...shared,
      origin: "https://localhost",
      clientAuth: "public",
    });
    const host = createGateway({
      ...shared,
      origin: "https://localhost",
      clientAuth: "required",
    });
    const browserPort = await listen(browser),
      hostPort = await listen(host);
    const origin = `https://127.0.0.1:${browserPort}`,
      hostOrigin = `https://127.0.0.1:${hostPort}`;
    process.env.BUNKER_ORIGIN = origin;
    await db.query("INSERT INTO organizations VALUES($1,'identity test')", [
      org,
    ]);
    await db.query("INSERT INTO tenants VALUES($1,$3,'test'),($2,$3,'other')", [
      tenant,
      other,
      org,
    ]);
    await db.query(
      "INSERT INTO users VALUES($1,'identity-test@example.test',$2)",
      [user, passwordHash("disposable-test-password")],
    );
    await db.query("INSERT INTO memberships VALUES($1,$2,'admin')", [
      tenant,
      user,
    ]);
    const session = "test-session-" + randomUUID();
    await db.query(
      "INSERT INTO sessions VALUES($1,$2,now()+interval '1 hour')",
      [digest(session), user],
    );
    const adminHeaders = {
      cookie: `bunker_session=${session}`,
      origin,
      "content-type": "application/json",
    };
    const path = `/api/tenants/${tenant}`;
    let enrollment: {
      hostId: string;
      tenantId: string;
      certificate: string;
      trustChain: string;
      expiresAt: string;
      transport: string;
    };
    const newToken = async () => {
      const r = await tlsCall(
        origin + path + "/enrollments",
        f.read("ca.pem"),
        {
          method: "POST",
          body: JSON.stringify({ name: "real TLS host" }),
          headers: adminHeaders,
        },
      );
      assert.equal(r.status, 201, r.body);
      return JSON.parse(r.body).token as string;
    };
    try {
      await t.test(
        "CSR enrollment is atomic and returns only issued certificate, with assigned identity",
        async () => {
          const token = await newToken();
          const malformed = await tlsCall(
            origin + "/api/enroll",
            f.read("ca.pem"),
            {
              method: "POST",
              body: JSON.stringify({ token, csr: "x".repeat(100) }),
              headers: { "content-type": "application/json" },
            },
          );
          assert.equal(malformed.status, 400, malformed.body); // Signing failure must not consume the token.

          const options = {
            method: "POST",
            body: JSON.stringify({ token, csr: f.read("host.csr").toString() }),
            headers: { "content-type": "application/json" },
          };
          const results = await Promise.all([
            tlsCall(origin + "/api/enroll", f.read("ca.pem"), options),
            tlsCall(origin + "/api/enroll", f.read("ca.pem"), options),
          ]);
          assert.deepEqual(
            results.map((r) => r.status).sort(),
            [201, 401],
            JSON.stringify(
              results.map((r) => ({
                status: r.status,
                error: r.status === 201 ? "created" : r.body,
              })),
            ),
          );
          enrollment = JSON.parse(results.find((r) => r.status === 201)!.body);
          assert.equal(enrollment.transport, "mtls");
          assert.equal(enrollment.tenantId, tenant);
          assert.ok(!("token" in enrollment));
          const cert = new X509Certificate(enrollment.certificate);
          assert.ok(
            cert.verify(new X509Certificate(f.read("ca.pem")).publicKey),
          );
          assert.ok(
            cert.subjectAltName?.includes(
              `urn:bunker:tenant:${tenant}:host:${enrollment.hostId}`,
            ),
          );
          assert.ok(!cert.subjectAltName?.includes("attacker"));
          assert.ok(
            new Date(enrollment.expiresAt).getTime() <= Date.now() + 86400000,
          );
          const row = await db.query(
            "SELECT * FROM host_certificates WHERE host_id=$1",
            [enrollment.hostId],
          );
          assert.equal(row.rowCount, 1);
        },
      );
      await t.test(
        "real mTLS is mandatory; spoofed identity headers and untrusted certificates fail",
        async () => {
          await assert.rejects(
            tlsCall(hostOrigin + path + "/policies", f.read("ca.pem")),
          );
          await assert.rejects(
            tlsCall(hostOrigin + path + "/policies", f.read("ca.pem"), {
              key: f.read("server.key"),
              cert: f.read("server.pem"),
            }),
          ); // serverAuth is not clientAuth
          f.openssl(
            "req",
            "-sha256",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "outsider.key",
            "-out",
            "outsider.pem",
            "-days",
            "1",
            "-subj",
            "/CN=untrusted-fixture",
            "-addext",
            "extendedKeyUsage=clientAuth",
          );
          await assert.rejects(
            tlsCall(hostOrigin + path + "/policies", f.read("ca.pem"), {
              key: f.read("outsider.key"),
              cert: f.read("outsider.pem"),
            }),
          );
          const anonymous = await tlsCall(
            origin + path + "/policies",
            f.read("ca.pem"),
            {
              headers: {
                [proofHeader]: "spoof",
                "x-client-cert": enrollment.certificate.replaceAll("\n", ""),
              },
            },
          );
          assert.equal(anonymous.status, 401);
          const r = await tlsCall(
            hostOrigin + path + "/policies",
            f.read("ca.pem"),
            {
              key: f.read("host.key"),
              cert: Buffer.from(enrollment.certificate),
              headers: { [proofHeader]: "spoof" },
            },
          );
          assert.equal(r.status, 200, r.body);
          const wrong = await tlsCall(
            hostOrigin + `/api/tenants/${other}/policies`,
            f.read("ca.pem"),
            {
              key: f.read("host.key"),
              cert: Buffer.from(enrollment.certificate),
            },
          );
          assert.equal(wrong.status, 401);
          const admin = await tlsCall(
            hostOrigin + path + "/enrollments",
            f.read("ca.pem"),
            {
              key: f.read("host.key"),
              cert: Buffer.from(enrollment.certificate),
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ name: "forbidden" }),
            },
          );
          assert.equal(admin.status, 403);
        },
      );
      await t.test(
        "private upstream rejects missing, replayed, and request-tampered proofs",
        async () => {
          const target = path + "/policies",
            url = origin + target;
          assert.equal((await handle(new Request(url))).status, 401);
          const headers = new Headers();
          const proof = await signGatewayRequest(
            "GET",
            target,
            headers,
            Buffer.alloc(0),
            null,
            f.read("gateway.secret"),
          );
          headers.set(proofHeader, proof);
          assert.equal(
            (await handle(new Request(url, { headers }))).status,
            401,
          ); // anonymous, still consumes nonce
          assert.equal(
            (await handle(new Request(url, { headers }))).status,
            401,
          );
          const fingerprint = new X509Certificate(
            enrollment.certificate,
          ).fingerprint256
            .replaceAll(":", "")
            .toLowerCase();
          const sign = async () =>
            await signGatewayRequest(
              "GET",
              target,
              new Headers(),
              Buffer.alloc(0),
              fingerprint,
              f.read("gateway.secret"),
            );
          const concurrent = await sign();
          const attempts = await Promise.all([
            handle(
              new Request(url, { headers: { [proofHeader]: concurrent } }),
            ),
            handle(
              new Request(url, { headers: { [proofHeader]: concurrent } }),
            ),
          ]);
          assert.deepEqual(attempts.map((r) => r.status).sort(), [200, 401]);
          const held = await db.connect();
          const payload = decodeJwt(await sign());
          const short = await new SignJWT(payload)
            .setProtectedHeader({ alg: "HS256", typ: "JWT" })
            .setExpirationTime(Math.floor(Date.now() / 1000) + 1)
            .sign(f.read("gateway.secret"));
          try {
            await held.query("BEGIN");
            await held.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
              payload.jti,
            ]);
            const waiting = handle(
              new Request(url, { headers: { [proofHeader]: short } }),
            );
            await new Promise((resolve) => setTimeout(resolve, 1100));
            await held.query("COMMIT");
            assert.equal((await waiting).status, 401);
          } finally {
            await held.query("ROLLBACK");
            held.release();
          }
          const valid = await sign();
          assert.equal(
            (
              await handle(
                new Request(url, { headers: { [proofHeader]: valid } }),
              )
            ).status,
            200,
          );
          assert.equal(
            (
              await handle(
                new Request(url, { headers: { [proofHeader]: valid } }),
              )
            ).status,
            401,
          );
          for (const altered of [
            new Request(url + "?x=1", {
              headers: { [proofHeader]: await sign() },
            }),
            new Request(url, {
              headers: {
                [proofHeader]: await sign(),
                cookie: `bunker_session=${session}`,
              },
            }),
            new Request(url, {
              method: "POST",
              body: "{}",
              headers: {
                [proofHeader]: await sign(),
                "content-type": "application/json",
              },
            }),
          ])
            assert.equal((await handle(altered)).status, 401);
        },
      );
      await t.test(
        "expired and unregistered certificates fail; renewal preserves host identity",
        async () => {
          await assert.rejects(
            tlsCall(hostOrigin + path + "/policies", f.read("ca.pem"), {
              key: f.read("host.key"),
              cert: await expiredHostCertificate(f),
            }),
          );
          const unregistered = await issueCertificate(
            f.read("host.csr").toString(),
            tenant,
            randomUUID(),
          );
          assert.equal(
            (
              await tlsCall(hostOrigin + path + "/policies", f.read("ca.pem"), {
                key: f.read("host.key"),
                cert: Buffer.from(unregistered.certificate),
              })
            ).status,
            401,
          );
          const options = {
            key: f.read("host.key"),
            cert: Buffer.from(enrollment.certificate),
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ csr: f.read("host.csr").toString() }),
          };
          assert.equal(
            (
              await tlsCall(
                hostOrigin + path + `/hosts/${randomUUID()}/certificate`,
                f.read("ca.pem"),
                options,
              )
            ).status,
            403,
          );
          const renewed = await tlsCall(
            hostOrigin + path + `/hosts/${enrollment.hostId}/certificate`,
            f.read("ca.pem"),
            options,
          );
          assert.equal(renewed.status, 201, renewed.body);
          assert.equal(JSON.parse(renewed.body).hostId, enrollment.hostId);
          enrollment = JSON.parse(renewed.body);
          const target = path + "/policies",
            headers = new Headers();
          const valid = await signGatewayRequest(
            "GET",
            target,
            headers,
            Buffer.alloc(0),
            unregistered.fingerprint,
            f.read("gateway.secret"),
          );
          const expired = await new SignJWT(decodeJwt(valid))
            .setProtectedHeader({ alg: "HS256", typ: "JWT" })
            .setExpirationTime(Math.floor(Date.now() / 1000) - 1)
            .sign(f.read("gateway.secret"));
          assert.equal(
            (
              await handle(
                new Request(origin + target, {
                  headers: { [proofHeader]: expired },
                }),
              )
            ).status,
            401,
          );
          const tampered = valid.slice(0, -8) + "AAAAAAAA";
          assert.equal(
            (
              await handle(
                new Request(origin + target, {
                  headers: { [proofHeader]: tampered },
                }),
              )
            ).status,
            401,
          );
        },
      );
      await t.test(
        "revocation is effective on already issued certificates",
        async () => {
          const r = await tlsCall(
            origin + path + `/hosts/${enrollment.hostId}/revoke`,
            f.read("ca.pem"),
            { method: "POST", headers: adminHeaders, body: "{}" },
          );
          assert.equal(r.status, 200, r.body);
          const rejected = await tlsCall(
            hostOrigin + path + "/policies",
            f.read("ca.pem"),
            {
              key: f.read("host.key"),
              cert: Buffer.from(enrollment.certificate),
            },
          );
          assert.equal(rejected.status, 401);
        },
      );
      await t.test(
        "OIDC and GitHub OAuth use one-time browser-bound PKCE flows and explicit subjects",
        async () => {
          const keys = await generateKeyPair("RS256"),
            wrongKeys = await generateKeyPair("RS256"),
            jwk = await exportJWK(keys.publicKey);
          jwk.kid = "fixture";
          const entraIssuer =
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0";
          let pkce: string[] | undefined = ["S256"];
          let issuer = "",
            variant = "valid",
            expectedNonce = "",
            challenge = "",
            redirect = "";
          const providerServer = https.createServer(
            { key: f.read("server.key"), cert: f.read("server.pem") },
            async (req, res) => {
              res.setHeader("content-type", "application/json");
              if (
                req.url === "/.well-known/openid-configuration" ||
                req.url === "/entra-discovery"
              )
                return res.end(
                  JSON.stringify({
                    issuer:
                      req.url === "/entra-discovery" ? entraIssuer : issuer,
                    authorization_endpoint: issuer + "/authorize",
                    token_endpoint: issuer + "/token",
                    jwks_uri: issuer + "/jwks",
                    code_challenge_methods_supported: pkce,
                    response_types_supported: ["code"],
                    subject_types_supported: ["public"],
                    id_token_signing_alg_values_supported: ["RS256"],
                  }),
                );
              if (req.url === "/jwks")
                return res.end(JSON.stringify({ keys: [jwk] }));
              if (req.url === "/user")
                return res.end(
                  JSON.stringify({
                    id: 12345,
                    login: "not-an-identity",
                    email: "identity-test@example.test",
                  }),
                );
              if (
                req.url === "/token" ||
                req.url === "/login/oauth/access_token"
              ) {
                const chunks: Buffer[] = [];
                for await (const chunk of req) chunks.push(chunk);
                const form = new URLSearchParams(
                  Buffer.concat(chunks).toString(),
                );
                if (
                  form.get("redirect_uri") !== redirect ||
                  createHash("sha256")
                    .update(form.get("code_verifier") || "")
                    .digest("base64url") !== challenge ||
                  form.get("client_secret") !== "disposable-provider-secret"
                ) {
                  res.statusCode = 400;
                  return res.end(JSON.stringify({ error: "invalid_grant" }));
                }
                if (req.url !== "/token")
                  return res.end(
                    JSON.stringify({
                      access_token: "fixture-token",
                      token_type: "bearer",
                      scope: "read:user",
                    }),
                  );
                const jwt = await new SignJWT({
                  nonce: variant === "nonce" ? "wrong" : expectedNonce,
                })
                  .setProtectedHeader({ alg: "RS256", kid: "fixture" })
                  .setIssuer(
                    variant === "issuer"
                      ? "https://wrong.test"
                      : variant === "entra"
                        ? entraIssuer
                        : issuer,
                  )
                  .setAudience(
                    variant === "audience" ? "wrong" : "fixture-client",
                  )
                  .setSubject(
                    variant === "unlinked" ? "unlinked" : "linked-subject",
                  )
                  .setIssuedAt()
                  .setExpirationTime(variant === "expired" ? "-1h" : "5m")
                  .sign(
                    variant === "signature"
                      ? wrongKeys.privateKey
                      : keys.privateKey,
                  );
                return res.end(
                  JSON.stringify({
                    access_token: "fixture-token",
                    token_type: "bearer",
                    id_token: jwt,
                  }),
                );
              }
              res.statusCode = 404;
              res.end("{}");
            },
          );
          issuer = `https://127.0.0.1:${await listen(providerServer)}`;
          f.write("provider.secret", "disposable-provider-secret");
          f.write(
            "providers.json",
            JSON.stringify([
              {
                id: "test",
                name: "Local test issuer",
                kind: "oidc",
                issuer,
                clientId: "fixture-client",
                clientSecretFile: f.file("provider.secret"),
                redirectUri: origin + "/api/auth/federated/test/callback",
              },
              {
                id: "entra",
                name: "Tenant-pinned Entra",
                kind: "oidc",
                issuer: entraIssuer,
                clientId: "fixture-client",
                clientSecretFile: f.file("provider.secret"),
                redirectUri: origin + "/api/auth/federated/entra/callback",
              },
              {
                id: "github",
                name: "GitHub",
                kind: "github",
                issuer: "https://github.com",
                clientId: "fixture-client",
                clientSecretFile: f.file("provider.secret"),
                redirectUri: origin + "/api/auth/federated/github/callback",
              },
            ]),
          );
          process.env.BUNKER_IDENTITY_PROVIDERS_FILE = f.file("providers.json");
          await db.query(
            "INSERT INTO external_identities VALUES('test',$1,'linked-subject',$2),('github','https://github.com','12345',$2)",
            [issuer, user],
          );
          const originalFetch = globalThis.fetch;
          // All provider requests still use real verified TLS with the disposable CA.
          // GitHub's fixed production endpoints are redirected only inside this fixture transport.
          globalThis.fetch = async (input, init) => {
            const url = new URL(
              input instanceof Request ? input.url : String(input),
            );
            assert.ok(
              [
                issuer,
                new URL(entraIssuer).origin,
                "https://github.com",
                "https://api.github.com",
              ].includes(url.origin),
            );
            const result = await tlsCall(
              issuer +
                (url.origin === new URL(entraIssuer).origin
                  ? "/entra-discovery"
                  : url.pathname + url.search),
              f.read("ca.pem"),
              {
                method: init?.method || "GET",
                body: init?.body?.toString(),
                headers: Object.fromEntries(new Headers(init?.headers)),
              },
            );
            return new Response(result.body, {
              status: result.status,
              headers: result.headers as Record<string, string>,
            });
          };
          try {
            const start = async (id = "test") => {
              const result = await tlsCall(
                origin + `/api/auth/federated/${id}/start`,
                f.read("ca.pem"),
                { method: "POST", headers: { origin } },
              );
              assert.equal(result.status, 200, result.body);
              const auth = new URL(JSON.parse(result.body).authorizationUrl);
              expectedNonce = auth.searchParams.get("nonce") || "";
              challenge = auth.searchParams.get("code_challenge")!;
              redirect = auth.searchParams.get("redirect_uri")!;
              assert.equal(
                auth.searchParams.get("code_challenge_method"),
                "S256",
              );
              if (id !== "github") assert.ok(expectedNonce);
              else assert.ok(!auth.searchParams.has("nonce"));
              return {
                state: auth.searchParams.get("state")!,
                cookie: result.headers["set-cookie"]![0].split(";")[0],
                id,
              };
            };
            const callback = async (
              flow: Awaited<ReturnType<typeof start>>,
              cookie = flow.cookie,
            ) =>
              tlsCall(
                origin +
                  `/api/auth/federated/${flow.id}/callback?code=fixture&state=${flow.state}`,
                f.read("ca.pem"),
                { headers: { cookie } },
              );
            // Entra's pinned-tenant discovery omits the optional PKCE advertisement.
            await db.query(
              "INSERT INTO external_identities VALUES('entra',$1,'linked-subject',$2)",
              [entraIssuer, user],
            );
            pkce = undefined;
            variant = "entra";
            assert.equal((await callback(await start("entra"))).status, 303);
            for (const advertisement of [[], ["plain"]]) {
              pkce = advertisement;
              const denied = await tlsCall(
                origin + "/api/auth/federated/entra/start",
                f.read("ca.pem"),
                {
                  method: "POST",
                  headers: { origin },
                },
              );
              assert.equal(denied.status, 503);
            }
            pkce = ["S256"];
            variant = "valid";
            const flow = await start();
            assert.equal(
              (await callback(flow, "bunker_login=wrong")).status,
              401,
            );
            const signedIn = await callback(flow);
            assert.equal(signedIn.status, 303, signedIn.body);
            assert.match(
              String(signedIn.headers["set-cookie"]),
              /bunker_session=/,
            );
            assert.equal((await callback(flow)).status, 401);
            for (const invalid of [
              "nonce",
              "issuer",
              "audience",
              "signature",
              "expired",
              "unlinked",
            ]) {
              variant = invalid;
              const result = await callback(await start());
              assert.equal(
                result.status,
                invalid === "unlinked" ? 403 : 401,
                `${invalid}: ${result.body}`,
              );
            }
            variant = "valid";
            const github = await callback(await start("github"));
            assert.equal(github.status, 303, github.body);
            await db.query(
              "DELETE FROM external_identities WHERE provider='github'",
            );
            const unlinkedGithub = await callback(await start("github"));
            assert.equal(unlinkedGithub.status, 403); // Same email does not link.
            const command = (action: string) =>
              execFileSync(
                process.execPath,
                [
                  "--import",
                  "tsx",
                  new URL("../scripts/link-identity.ts", import.meta.url)
                    .pathname,
                  action,
                  "github",
                  "12345",
                  user,
                ],
                { stdio: "pipe" },
              );
            command("link");
            assert.equal((await callback(await start("github"))).status, 303);
            command("unlink");
            assert.equal((await callback(await start("github"))).status, 403);
            assert.equal(
              Number(
                (
                  await db.query(
                    "SELECT count(*) FROM sessions WHERE user_id=$1",
                    [user],
                  )
                ).rows[0].count,
              ),
              0,
            );
            const racing = await start();
            const administrator = await db.connect();
            try {
              await administrator.query("BEGIN");
              await administrator.query(
                "SELECT id FROM users WHERE id=$1 FOR UPDATE",
                [user],
              );
              const pending = callback(racing);
              let blocked = false;
              for (let attempt = 0; attempt < 100; attempt++) {
                const waiting = await db.query(
                  "SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id FROM users WHERE id=%'",
                );
                if (waiting.rowCount) {
                  blocked = true;
                  break;
                }
                await new Promise((resolve) => setTimeout(resolve, 10));
              }
              assert.ok(
                blocked,
                "callback waits on instance-admin identity lock",
              );
              await administrator.query(
                "DELETE FROM external_identities WHERE user_id=$1",
                [user],
              );
              await administrator.query(
                "DELETE FROM sessions WHERE user_id=$1",
                [user],
              );
              await administrator.query("COMMIT");
              assert.equal((await pending).status, 403);
              assert.equal(
                Number(
                  (
                    await db.query(
                      "SELECT count(*) FROM sessions WHERE user_id=$1",
                      [user],
                    )
                  ).rows[0].count,
                ),
                0,
              );
            } finally {
              await administrator.query("ROLLBACK");
              administrator.release();
            }
            const expired = await start();
            await db.query(
              "UPDATE login_flows SET expires_at=now()-interval '1 minute' WHERE state_hash=$1",
              [digest(expired.state)],
            );
            assert.equal((await callback(expired)).status, 401);
          } finally {
            globalThis.fetch = originalFetch;
            delete process.env.BUNKER_IDENTITY_PROVIDERS_FILE;
            await close(providerServer);
          }
        },
      );
    } finally {
      await close(browser);
      await close(host);
      await close(upstream);
      await db.end();
      f.cleanup();
    }
  },
);
