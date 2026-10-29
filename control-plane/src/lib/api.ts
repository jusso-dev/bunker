import { page } from "./pagination";
import {
  accountAudit,
  hasLocalPassword,
  replacePassword,
} from "./human-lifecycle";
import { evidenceOutcome } from "./evidence";
import { enqueueAlert } from "../notifications/outbox";
import { destinations } from "../notifications/config";
import {
  providers,
  startFederated,
  finishFederated,
} from "../identity/federation";
import { verifyGatewayRequest } from "../identity/gateway-proof";
import { issueCertificate } from "../identity/certificates";
import { gatewayKey } from "../identity/files";
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { z } from "zod";
import { transaction } from "./db";
import {
  ApiError,
  digest,
  token,
  passwordMatches,
  passwordHash,
  requireOrigin,
  requireAgentTransport,
  localAgentMode,
  requireSafeConfiguration,
} from "./security";
import * as S from "./schemas";
type Actor = {
  id: string;
  tenant: string;
  role: string;
  kind: "human" | "host";
};
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
async function body<T>(r: Request, s: z.ZodType<T>): Promise<T> {
  if (!r.headers.get("content-type")?.startsWith("application/json"))
    throw new ApiError(415, "Use application/json");
  const reader = r.body?.getReader();
  if (!reader) throw new ApiError(400, "JSON body required");
  let size = 0;
  const chunks: Uint8Array[] = [];
  const deadline = Date.now() + 10000;
  while (true) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const next = await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => {
            reject(new ApiError(408, "Request body timed out"));
            void reader.cancel().catch(() => {});
          },
          Math.max(0, deadline - Date.now()),
        );
      }),
    ]).finally(() => clearTimeout(timer));
    const { done, value } = next;
    if (done) break;
    size += value.length;
    if (size > 256000) {
      await reader.cancel();
      throw new ApiError(413, "Metadata request too large");
    }
    chunks.push(value);
  }
  try {
    return s.parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } catch (e) {
    if (e instanceof z.ZodError) throw e;
    throw new ApiError(400, "Invalid JSON");
  }
}
function sessionHash(r: Request) {
  const cookie = r.headers
    .get("cookie")
    ?.split(";")
    .map((x) => x.trim())
    .find((x) => x.startsWith("bunker_session="))
    ?.slice(15);
  return cookie ? digest(cookie) : null;
}
const clearCookie = {
  "Set-Cookie": "bunker_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
};
async function human(
  db: PoolClient,
  r: Request,
  exclusive = false,
): Promise<string> {
  // The authentication token/hash is never a management handle or API field.
  const hash = sessionHash(r);
  if (!hash) throw new ApiError(401, "Sign in required");
  const result = await db.query(
    "SELECT user_id FROM sessions WHERE token_hash=$1",
    [hash],
  );
  if (!result.rowCount) throw new ApiError(401, "Session expired");
  const id = result.rows[0].user_id;
  await db.query(
    `SELECT id FROM users WHERE id=$1 FOR ${exclusive ? "UPDATE" : "SHARE"}`,
    [id],
  );
  // Check again after waiting: a password change/revoke may have removed it.
  const live = await db.query(
    "SELECT 1 FROM sessions WHERE token_hash=$1 AND user_id=$2 AND expires_at>clock_timestamp()",
    [hash, id],
  );
  if (!live.rowCount) throw new ApiError(401, "Session expired");
  return id;
}
async function actor(
  db: PoolClient,
  r: Request,
  tenant: string,
  fingerprint: string | null,
): Promise<Actor> {
  if (fingerprint) {
    const found = await db.query(
      "SELECT h.id FROM host_certificates c JOIN hosts h ON h.id=c.host_id AND h.tenant_id=c.tenant_id WHERE c.fingerprint=$1 AND c.tenant_id=$2 AND c.revoked_at IS NULL AND h.revoked_at IS NULL AND c.expires_at>clock_timestamp()",
      [fingerprint, tenant],
    );
    if (!found.rowCount)
      throw new ApiError(401, "Invalid or revoked host certificate");
    return { id: found.rows[0].id, tenant, role: "host", kind: "host" };
  }
  if (r.headers.has("authorization")) {
    requireAgentTransport(r);
    const auth = r.headers.get("authorization")!;
    if (!auth.startsWith("Bearer "))
      throw new ApiError(401, "Invalid host authorization");
    const hosts = await db.query(
      "SELECT id FROM hosts WHERE tenant_id=$1 AND token_hash=$2 AND revoked_at IS NULL",
      [tenant, digest(auth.slice(7))],
    );
    if (!hosts.rowCount) throw new ApiError(401, "Invalid host authorization");
    return { id: hosts.rows[0].id, tenant, role: "host", kind: "host" };
  }
  const id = await human(db, r);
  const member = await db.query(
    "SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2",
    [tenant, id],
  );
  if (!member.rowCount) throw new ApiError(403, "Tenant access denied");
  return { id, tenant, role: member.rows[0].role, kind: "human" };
}
function permit(a: Actor, roles: string[]) {
  if (!roles.includes(a.role))
    throw new ApiError(403, "Role does not permit this action");
}
function hostOnly(a: Actor) {
  if (a.kind !== "host") throw new ApiError(403, "Host credential required");
}
async function audit(db: PoolClient, a: Actor, action: string, id?: string) {
  await db.query(
    "INSERT INTO audit(tenant_id,actor,action,resource_id) VALUES($1,$2,$3,$4)",
    [a.tenant, `${a.kind}:${a.id}`, action, id ?? null],
  );
}
async function expire(db: PoolClient, tenant: string) {
  const rows = await db.query(
    "UPDATE restores SET status='expired' WHERE tenant_id=$1 AND status IN ('pending','approved') AND expires_at<=clock_timestamp() RETURNING id",
    [tenant],
  );
  for (const row of rows.rows)
    await db.query(
      "INSERT INTO audit(tenant_id,actor,action,resource_id) VALUES($1,'system','restore.expired',$2)",
      [tenant, row.id],
    );
}
async function snapshotExists(db: PoolClient, a: Actor, id: string) {
  const found = await db.query(
    "SELECT body FROM snapshots WHERE tenant_id=$1 AND host_id=$2 AND id=$3",
    [a.tenant, a.id, id],
  );
  if (!found.rowCount) throw new ApiError(404, "Snapshot not found");
  return found.rows[0].body as z.infer<typeof S.snapshot>;
}
export async function handle(request: Request): Promise<Response> {
  try {
    requireSafeConfiguration();
    let fingerprint: string | null = null;
    if (
      !localAgentMode() &&
      (process.env.BUNKER_ORIGIN?.startsWith("https:") ||
        process.env.BUNKER_GATEWAY_SECRET_FILE)
    ) {
      const verified = await verifyGatewayRequest(request);
      request = verified.request;
      fingerprint = verified.fingerprint;
    }
    const url = new URL(request.url),
      parts = url.pathname.replace(/^\/api\/?/, "").split("/"),
      method = request.method;
    if (
      method !== "GET" &&
      (parts[0] === "auth" ||
        (!fingerprint && !request.headers.has("authorization"))) &&
      parts.join("/") !== "enroll"
    )
      requireOrigin(request);
    // Handle login separately so failed-attempt counters commit before returning 401.
    if (parts.join("/") === "auth/login" && method === "POST") {
      const data = await body(request, S.login);
      const response = await transaction(async (db) => {
        const key = digest(data.email.toLowerCase());
        await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [key]);
        const attempt = await db.query(
          "SELECT failures,window_start FROM login_attempts WHERE identity_hash=$1",
          [key],
        );
        if (
          attempt.rowCount &&
          Date.now() - new Date(attempt.rows[0].window_start).getTime() <
            900000 &&
          attempt.rows[0].failures >= 10
        )
          return json({ error: "Too many attempts; retry in 15 minutes" }, 429);
        const user = await db.query(
          "SELECT id,password_hash FROM users WHERE email=$1 FOR UPDATE",
          [data.email.toLowerCase()],
        );
        // Same expensive operation for unknown/federated-only users.
        if (!hasLocalPassword(user.rows[0]?.password_hash))
          passwordMatches(
            data.password,
            `${"0".repeat(32)}:${"0".repeat(128)}`,
          );
        const valid =
          hasLocalPassword(user.rows[0]?.password_hash) &&
          passwordMatches(
            data.password,
            user.rows[0]?.password_hash ??
              `${"0".repeat(32)}:${"0".repeat(128)}`,
          );
        if (!valid || !user.rowCount) {
          await db.query(
            "INSERT INTO login_attempts VALUES($1,1,now()) ON CONFLICT(identity_hash) DO UPDATE SET failures=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN 1 ELSE login_attempts.failures+1 END,window_start=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN now() ELSE login_attempts.window_start END",
            [key],
          );
          return json({ error: "Invalid credentials" }, 401);
        }
        await db.query("DELETE FROM login_attempts WHERE identity_hash=$1", [
          key,
        ]);
        const secret = token();
        await db.query(
          "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '8 hours')",
          [digest(secret), user.rows[0].id],
        );
        return json({ ok: true }, 200, {
          "Set-Cookie": `bunker_session=${secret}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.BUNKER_ORIGIN?.startsWith("https:") ? "; Secure" : ""}`,
        });
      });
      return response;
    }
    if (parts.join("/") === "auth/providers" && method === "GET")
      return json(
        providers().map(({ id, name, kind }) => ({ id, name, kind })),
      );
    if (parts.length === 4 && parts[0] === "auth" && parts[1] === "federated") {
      if (parts[3] === "start" && method === "POST")
        return await startFederated(parts[2]);
      if (parts[3] === "callback" && method === "GET")
        return await finishFederated(parts[2], request);
    }
    if (parts.join("/") === "auth/oidc")
      throw new ApiError(
        501,
        "Use the configured federated identity endpoints",
      );
    return await transaction(async (db) => {
      if (parts.join("/") === "auth/logout" && method === "POST") {
        const cookie = request.headers
          .get("cookie")
          ?.split(";")
          .map((x) => x.trim())
          .find((x) => x.startsWith("bunker_session="))
          ?.slice(15);
        // Logout is idempotent, including for expired or already revoked sessions.
        if (cookie) {
          const found = await db.query(
            "SELECT user_id FROM sessions WHERE token_hash=$1",
            [digest(cookie)],
          );
          if (found.rowCount)
            await db.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [
              found.rows[0].user_id,
            ]);
          await db.query("DELETE FROM sessions WHERE token_hash=$1", [
            digest(cookie),
          ]);
        }
        return json({ ok: true }, 200, {
          "Set-Cookie":
            "bunker_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        });
      }
      if (parts.join("/") === "auth/recovery" && method === "POST") {
        const data = await body(request, S.passwordRecovery);
        const hash = digest(data.token);
        const recovery = await db.query(
          "SELECT user_id FROM password_recoveries WHERE token_hash=$1",
          [hash],
        );
        if (!recovery.rowCount)
          throw new ApiError(401, "Recovery token invalid or expired");
        const user = recovery.rows[0].user_id;
        const found = await db.query(
          "SELECT password_hash FROM users WHERE id=$1 FOR UPDATE",
          [user],
        );
        const consumed = await db.query(
          "DELETE FROM password_recoveries WHERE token_hash=$1 AND user_id=$2 AND expires_at>clock_timestamp() RETURNING user_id",
          [hash, user],
        );
        if (
          !consumed.rowCount ||
          !hasLocalPassword(found.rows[0]?.password_hash)
        )
          throw new ApiError(401, "Recovery token invalid or expired");
        await replacePassword(
          db,
          user,
          data.newPassword,
          `human:${user}`,
          "password.recovered",
        );
        return json({ ok: true }, 200, clearCookie);
      }
      if (parts.join("/") === "auth/password" && method === "POST") {
        const data = await body(request, S.passwordChange);
        const user = await human(db, request, true);
        const found = (
          await db.query("SELECT email,password_hash FROM users WHERE id=$1", [
            user,
          ])
        ).rows[0];
        if (!hasLocalPassword(found.password_hash))
          throw new ApiError(
            409,
            "Use your identity provider to manage credentials",
          );
        // Share the login throttle; return failures so their counter commits.
        const key = digest(found.email);
        const attempt = await db.query(
          "SELECT failures,window_start FROM login_attempts WHERE identity_hash=$1",
          [key],
        );
        if (
          attempt.rowCount &&
          Date.now() - new Date(attempt.rows[0].window_start).getTime() <
            900000 &&
          attempt.rows[0].failures >= 10
        )
          return json({ error: "Too many attempts; retry in 15 minutes" }, 429);
        if (!passwordMatches(data.currentPassword, found.password_hash)) {
          await db.query(
            "INSERT INTO login_attempts VALUES($1,1,clock_timestamp()) ON CONFLICT(identity_hash) DO UPDATE SET failures=CASE WHEN login_attempts.window_start<clock_timestamp()-interval '15 minutes' THEN 1 ELSE login_attempts.failures+1 END,window_start=CASE WHEN login_attempts.window_start<clock_timestamp()-interval '15 minutes' THEN clock_timestamp() ELSE login_attempts.window_start END",
            [key],
          );
          return json({ error: "Current password is incorrect" }, 403);
        }
        await replacePassword(
          db,
          user,
          data.newPassword,
          `human:${user}`,
          "password.changed",
        );
        return json({ ok: true }, 200, clearCookie);
      }
      if (parts.join("/") === "auth/sessions" && method === "GET") {
        const user = await human(db, request);
        const result = await page(db, url, `sessions:${user}`, {
          from: "sessions",
          select: "handle,created_at,expires_at,(token_hash=$2) AS current",
          where: "user_id=$1 AND expires_at>clock_timestamp()",
          values: [user, sessionHash(request)],
          id: "handle",
        });
        return json(result.rows, 200, result.headers);
      }
      if (
        parts[0] === "auth" &&
        parts[1] === "sessions" &&
        method === "POST" &&
        ((parts.length === 3 && parts[2] === "revoke-others") ||
          (parts.length === 4 && parts[3] === "revoke"))
      ) {
        const user = await human(db, request, true);
        if (parts.length === 3) {
          await db.query(
            "DELETE FROM sessions WHERE user_id=$1 AND token_hash<>$2",
            [user, sessionHash(request)],
          );
          await accountAudit(
            db,
            user,
            `human:${user}`,
            "sessions.others-revoked",
          );
          return json({ ok: true });
        }
        const handle = S.uuid.parse(parts[2]);
        const removed = await db.query(
          "DELETE FROM sessions WHERE user_id=$1 AND handle=$2 RETURNING token_hash=$3 AS current",
          [user, handle, sessionHash(request)],
        );
        if (!removed.rowCount) throw new ApiError(404, "Session not found");
        await accountAudit(db, user, `human:${user}`, "session.revoked");
        return json(
          { ok: true },
          200,
          removed.rows[0].current ? clearCookie : {},
        );
      }
      if (parts.join("/") === "me" && method === "GET") {
        const id = await human(db, request);
        const result = await page(db, url, `tenants:${id}`, {
          from: "memberships m JOIN tenants t ON t.id=m.tenant_id",
          select: "t.id,t.name,m.role",
          where: "m.user_id=$1",
          values: [id],
          time: "t.created_at",
          id: "t.id",
        });
        const local = await db.query(
          "SELECT password_hash FROM users WHERE id=$1",
          [id],
        );
        return json(
          {
            userId: id,
            tenants: result.rows,
            localPassword: hasLocalPassword(local.rows[0]?.password_hash),
            hostTransport: localAgentMode()
              ? "development-loopback"
              : process.env.BUNKER_GATEWAY_SECRET_FILE
                ? "mtls"
                : "disabled-mtls-unimplemented",
          },
          200,
          result.headers,
        );
      }
      if (parts.join("/") === "enroll" && method === "POST") {
        if (localAgentMode()) requireAgentTransport(request);
        else if (!process.env.BUNKER_GATEWAY_SECRET_FILE)
          throw new ApiError(503, "Production gateway is not configured");
        const data = await body(request, S.enroll);
        if (!localAgentMode() && !data.csr)
          throw new ApiError(400, "CSR required for production enrollment");
        // Take the lock first: evaluating a timestamp in an UPDATE predicate can
        // happen before PostgreSQL waits for a concurrent row lock.
        await db.query(
          "SELECT id FROM enrollments WHERE token_hash=$1 FOR UPDATE",
          [digest(data.token)],
        );
        const enrolled = await db.query(
          "WITH consumption AS MATERIALIZED (SELECT clock_timestamp() AS at) UPDATE enrollments SET used_at=consumption.at FROM consumption WHERE token_hash=$1 AND used_at IS NULL AND expires_at>consumption.at RETURNING tenant_id,name",
          [digest(data.token)],
        );
        if (!enrolled.rowCount)
          throw new ApiError(401, "Enrollment token invalid or expired");
        const id = randomUUID(),
          secret = token(),
          tenant = enrolled.rows[0].tenant_id;
        await db.query(
          "INSERT INTO hosts(id,tenant_id,name,token_hash) VALUES($1,$2,$3,$4)",
          [id, tenant, enrolled.rows[0].name, digest(secret)],
        );
        const certificate = !localAgentMode()
          ? await issueCertificate(data.csr!, tenant, id)
          : null;
        if (certificate)
          await db.query(
            "INSERT INTO host_certificates(fingerprint,tenant_id,host_id,serial,expires_at) VALUES($1,$2,$3,$4,$5)",
            [
              certificate.fingerprint,
              tenant,
              id,
              certificate.serial,
              certificate.expiresAt,
            ],
          );
        await audit(
          db,
          { id, tenant, role: "host", kind: "host" },
          "host.enrolled",
          id,
        );
        return json(
          certificate
            ? {
                hostId: id,
                tenantId: tenant,
                transport: "mtls",
                certificate: certificate.certificate,
                trustChain: certificate.trustChain,
                expiresAt: certificate.expiresAt,
              }
            : {
                hostId: id,
                tenantId: tenant,
                token: secret,
                transport: "development-loopback",
              },
          201,
        );
      }
      if (parts[0] !== "tenants" || !S.uuid.safeParse(parts[1]).success)
        throw new ApiError(404, "Route not found");
      // PostgreSQL UUID equality ignores hex case; lock keys must do the same.
      parts[1] = parts[1].toLowerCase();
      // Readers hold a shared tenant lock through commit. Membership mutations
      // take it exclusively BEFORE authentication, then recheck the actor's role.
      // This also serializes concurrent demotions/removals of the last admins.
      if (!fingerprint && !request.headers.has("authorization")) {
        const exclusive = parts[2] === "members" && method === "POST";
        await db.query(
          `SELECT pg_advisory_xact_lock${exclusive ? "" : "_shared"}(hashtextextended($1,0))`,
          [`membership:${parts[1]}`],
        );
      }
      const a = await actor(db, request, parts[1], fingerprint),
        resource = parts[2],
        id = parts[3];
      if (id && !S.uuid.safeParse(id).success)
        throw new ApiError(400, "Invalid resource ID");
      if (
        parts.length === 5 &&
        resource === "hosts" &&
        parts[4] === "certificate" &&
        method === "POST"
      ) {
        hostOnly(a);
        if (!fingerprint || a.id !== id)
          throw new ApiError(
            403,
            "This host's valid mTLS identity is required",
          );
        const data = await body(request, S.certificateRequest);
        const certificate = await issueCertificate(data.csr, a.tenant, a.id);
        await db.query(
          "INSERT INTO host_certificates(fingerprint,tenant_id,host_id,serial,expires_at) VALUES($1,$2,$3,$4,$5)",
          [
            certificate.fingerprint,
            a.tenant,
            a.id,
            certificate.serial,
            certificate.expiresAt,
          ],
        );
        await audit(db, a, "host.certificate-issued", a.id);
        return json(
          {
            hostId: a.id,
            tenantId: a.tenant,
            transport: "mtls",
            certificate: certificate.certificate,
            trustChain: certificate.trustChain,
            expiresAt: certificate.expiresAt,
          },
          201,
        );
      }
      const collection = parts.length === 3;
      const item = parts.length === 4;
      const actionRoute = parts.length === 5;
      const readCollections = [
        "hosts",
        "members",
        "policies",
        "snapshots",
        "restores",
        "alerts",
        "evidence",
        "audit",
        "notifications",
        "export",
      ];
      const writeCollections = [
        "tenants",
        "members",
        "enrollments",
        "policies",
        "snapshots",
        "restores",
        "alerts",
        "evidence",
      ];
      const validRoute =
        (method === "GET" &&
          ((collection && readCollections.includes(resource)) ||
            (item &&
              ["snapshots", "restores", "alerts", "evidence"].includes(
                resource,
              )))) ||
        (method === "POST" &&
          ((collection && writeCollections.includes(resource)) ||
            (actionRoute &&
              ((resource === "restores" &&
                ["decision", "claim", "complete"].includes(parts[4])) ||
                (resource === "alerts" && parts[4] === "acknowledge") ||
                (resource === "hosts" && parts[4] === "revoke") ||
                (resource === "members" && parts[4] === "revoke")))));
      if (!validRoute) throw new ApiError(404, "Route not found");
      await expire(db, a.tenant);
      if (resource === "tenants" && method === "POST") {
        permit(a, ["admin"]);
        const data = await body(request, S.tenant);
        const newId = randomUUID();
        await db.query(
          "INSERT INTO tenants SELECT $1,organization_id,$2 FROM tenants WHERE id=$3",
          [newId, data.name, a.tenant],
        );
        await db.query("INSERT INTO memberships VALUES($1,$2,'admin')", [
          newId,
          a.id,
        ]);
        await audit(db, a, "tenant.created", newId);
        return json({ id: newId }, 201);
      }
      if (resource === "members" && method === "GET") {
        permit(a, ["admin"]);
        const result = await page(db, url, `${url.pathname}:human:${a.id}`, {
          from: "memberships m JOIN users u ON u.id=m.user_id",
          select: "u.id,u.email,m.role,m.created_at",
          where: "m.tenant_id=$1",
          values: [a.tenant],
          time: "m.created_at",
          id: "m.user_id",
        });
        return json(result.rows, 200, result.headers);
      }
      if (resource === "members" && method === "POST" && id) {
        permit(a, ["admin"]);
        const member = await db.query(
          "SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2",
          [a.tenant, id],
        );
        if (!member.rowCount) throw new ApiError(404, "Membership not found");
        if (member.rows[0].role === "admin") {
          const admins = await db.query(
            "SELECT 1 FROM memberships WHERE tenant_id=$1 AND role='admin' AND user_id<>$2",
            [a.tenant, id],
          );
          if (!admins.rowCount)
            throw new ApiError(
              409,
              "Cannot remove the last tenant administrator",
            );
        }
        await db.query(
          "DELETE FROM memberships WHERE tenant_id=$1 AND user_id=$2",
          [a.tenant, id],
        );
        await audit(db, a, "membership.revoked", id);
        return json({ id });
      }
      if (resource === "members" && method === "POST") {
        permit(a, ["admin"]);
        const data = await body(request, S.member);
        let user = (
          await db.query("SELECT id FROM users WHERE email=$1", [
            data.email.toLowerCase(),
          ])
        ).rows[0]?.id;
        if (!user) {
          if (!data.password)
            throw new ApiError(
              400,
              "Password required for a new local account",
            );
          user = randomUUID();
          await db.query("INSERT INTO users VALUES($1,$2,$3)", [
            user,
            data.email.toLowerCase(),
            passwordHash(data.password),
          ]);
        } else if (data.password)
          throw new ApiError(
            400,
            "Existing account passwords cannot be changed through membership administration",
          );
        if (user === a.id)
          throw new ApiError(409, "Cannot change your own role");
        if (data.role !== "admin") {
          const remaining = await db.query(
            "SELECT 1 FROM memberships WHERE tenant_id=$1 AND role='admin' AND user_id<>$2",
            [a.tenant, user],
          );
          if (!remaining.rowCount)
            throw new ApiError(
              409,
              "Cannot demote the last tenant administrator",
            );
        }
        await db.query(
          "INSERT INTO memberships VALUES($1,$2,$3) ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=excluded.role",
          [a.tenant, user, data.role],
        );
        await audit(db, a, "membership.updated", user);
        return json({ id: user }, 201);
      }
      if (resource === "enrollments" && method === "POST") {
        permit(a, ["admin", "operator"]);
        if (!localAgentMode()) gatewayKey();
        const data = await body(request, S.enrollment),
          secret = token(),
          newId = randomUUID();
        await db.query(
          "INSERT INTO enrollments(id,tenant_id,token_hash,name,expires_at) VALUES($1,$2,$3,$4,now()+interval '10 minutes')",
          [newId, a.tenant, digest(secret), data.name],
        );
        await audit(db, a, "enrollment.created", newId);
        return json({ token: secret, expiresInSeconds: 600 }, 201);
      }
      if (
        resource === "hosts" &&
        id &&
        parts[4] === "revoke" &&
        method === "POST"
      ) {
        permit(a, ["admin"]);
        const result = await db.query(
          "UPDATE hosts SET token_hash=$1,revoked_at=clock_timestamp() WHERE tenant_id=$2 AND id=$3 RETURNING id",
          [digest(token()), a.tenant, id],
        );
        if (!result.rowCount) throw new ApiError(404, "Host not found");
        await db.query(
          "UPDATE host_certificates SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND host_id=$2",
          [a.tenant, id],
        );
        await audit(db, a, "host.revoked", id);
        return json({ id });
      }
      if (resource === "hosts" && method === "GET") {
        permit(a, ["admin", "operator", "viewer", "approver"]);
        const result = await page(db, url, `${url.pathname}:human:${a.id}`, {
          from: "hosts",
          select: "id,name,created_at",
          where: "tenant_id=$1",
          values: [a.tenant],
        });
        return json(result.rows, 200, result.headers);
      }
      if (resource === "policies" && method === "GET") {
        if (a.kind === "host")
          return json(
            (
              await db.query(
                "SELECT id,body,version,updated_at FROM policies WHERE tenant_id=$1 AND (host_id=$2 OR host_id IS NULL) ORDER BY host_id NULLS LAST LIMIT 1",
                [a.tenant, a.id],
              )
            ).rows,
          );
        const result = await page(db, url, `${url.pathname}:human:${a.id}`, {
          from: "policies",
          select: "id,host_id,body,version,updated_at",
          where: "tenant_id=$1",
          values: [a.tenant],
          time: "updated_at",
        });
        return json(result.rows, 200, result.headers);
      }
      if (resource === "policies" && method === "POST") {
        permit(a, ["admin", "operator"]);
        const data = await body(request, S.policy);
        if (
          data.channels.includes("webhook") &&
          !destinations().some((d) => d.tenantId === a.tenant)
        )
          throw new ApiError(503, "Webhook destination is not provisioned");
        if (
          data.hostId &&
          !(
            await db.query(
              "SELECT id FROM hosts WHERE tenant_id=$1 AND id=$2",
              [a.tenant, data.hostId],
            )
          ).rowCount
        )
          throw new ApiError(404, "Host not found");
        const scope = data.hostId
          ? "(tenant_id,host_id) WHERE host_id IS NOT NULL"
          : "(tenant_id) WHERE host_id IS NULL";
        const result = await db.query(
          `INSERT INTO policies(id,tenant_id,host_id,body) VALUES($1,$2,$3,$4) ON CONFLICT ${scope} DO UPDATE SET body=excluded.body,version=policies.version+1,updated_at=now() RETURNING id,version`,
          [randomUUID(), a.tenant, data.hostId, data],
        );
        await audit(db, a, "policy.updated", result.rows[0].id);
        return json(result.rows[0], 201);
      }
      if (resource === "snapshots" && method === "POST") {
        hostOnly(a);
        const data = await body(request, S.snapshot);
        const result = await db.query(
          "INSERT INTO snapshots(id,tenant_id,host_id,body) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,id) DO NOTHING RETURNING id",
          [data.id, a.tenant, a.id, data],
        );
        if (!result.rowCount) {
          const existing = await snapshotExists(db, a, data.id);
          if (
            Object.keys(data).some(
              (key) =>
                existing[key as keyof typeof existing] !==
                data[key as keyof typeof data],
            )
          )
            throw new ApiError(
              409,
              "Snapshot ID already has different metadata",
            );
        } else await audit(db, a, "snapshot.reported", data.id);
        return json({ id: data.id }, 201);
      }
      if (resource === "restores" && method === "POST" && !id) {
        hostOnly(a);
        const data = await body(request, S.restore);
        const snap = await snapshotExists(db, a, data.snapshotId);
        if (
          snap.status !== "succeeded" ||
          snap.manifestDigest !== data.manifestDigest
        )
          throw new ApiError(409, "Snapshot manifest does not match");
        const newId = randomUUID();
        await db.query(
          "INSERT INTO restores(id,tenant_id,host_id,snapshot_id,body,status,expires_at) VALUES($1,$2,$3,$4,$5,'pending',now()+interval '15 minutes')",
          [newId, a.tenant, a.id, data.snapshotId, data],
        );
        await audit(db, a, "restore.requested", newId);
        return json({ id: newId, status: "pending" }, 201);
      }
      if (resource === "restores" && id && method === "POST") {
        const row = (
          await db.query(
            "SELECT * FROM restores WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
            [a.tenant, id],
          )
        ).rows[0];
        if (!row || (a.kind === "host" && row.host_id !== a.id))
          throw new ApiError(404, "Restore request not found");
        const action = parts[4];
        if (action === "decision") {
          permit(a, ["admin", "approver"]);
          const data = await body(request, S.decision);
          if (
            row.status !== "pending" ||
            new Date(row.expires_at).getTime() <= Date.now()
          )
            throw new ApiError(409, "Request is no longer pending");
          if (
            data.diffDigest !== row.body.diffDigest ||
            (data.decision === "approve" && !data.reviewedLocalDiff)
          )
            throw new ApiError(
              409,
              "Review the local diff and confirm its digest",
            );
          const status = data.decision === "approve" ? "approved" : "denied";
          await db.query(
            "UPDATE restores SET status=$1,decided_by=$2 WHERE tenant_id=$3 AND id=$4",
            [status, a.id, a.tenant, id],
          );
          await audit(db, a, `restore.${status}`, id);
          return json({ id, status });
        }
        if (action === "claim") {
          hostOnly(a);
          const data = await body(request, S.claim);
          if (
            row.status !== "approved" ||
            new Date(row.expires_at).getTime() <= Date.now() ||
            data.diffDigest !== row.body.diffDigest
          )
            throw new ApiError(409, "No matching live approval");
          await db.query(
            "UPDATE restores SET status='executing' WHERE tenant_id=$1 AND id=$2",
            [a.tenant, id],
          );
          await audit(db, a, "restore.claimed", id);
          return json({
            id,
            status: "executing",
            diffDigest: row.body.diffDigest,
            manifestDigest: row.body.manifestDigest,
            expiresAt: row.expires_at,
          });
        }
        if (action === "complete") {
          hostOnly(a);
          const data = await body(request, S.completion);
          if (
            row.status !== "executing" ||
            data.diffDigest !== row.body.diffDigest
          )
            throw new ApiError(
              409,
              "Restore must be claimed with matching digest",
            );
          await db.query(
            "UPDATE restores SET status=$1 WHERE tenant_id=$2 AND id=$3",
            [data.status, a.tenant, id],
          );
          await audit(db, a, `restore.${data.status}`, id);
          return json({ id, status: data.status });
        }
      }
      if (resource === "alerts" && method === "POST" && !id) {
        hostOnly(a);
        const data = await body(request, S.alert);
        if (data.snapshotId) await snapshotExists(db, a, data.snapshotId);
        const newAlertId = randomUUID();
        const result = await db.query(
          "INSERT INTO alerts(id,tenant_id,host_id,dedupe_key,body) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,host_id,dedupe_key) DO UPDATE SET occurrences=alerts.occurrences+1,last_seen_at=now() RETURNING id",
          [newAlertId, a.tenant, a.id, data.eventId, data],
        );
        if (result.rows[0].id === newAlertId)
          await enqueueAlert(db, a.tenant, a.id, newAlertId);
        await audit(db, a, "alert.reported", result.rows[0].id);
        return json({ id: result.rows[0].id }, 201);
      }
      if (
        resource === "alerts" &&
        id &&
        parts[4] === "acknowledge" &&
        method === "POST"
      ) {
        permit(a, ["admin", "operator"]);
        const result = await db.query(
          "UPDATE alerts SET acknowledged_by=$1 WHERE tenant_id=$2 AND id=$3 RETURNING id",
          [a.id, a.tenant, id],
        );
        if (!result.rowCount) throw new ApiError(404, "Alert not found");
        await audit(db, a, "alert.acknowledged", id);
        return json({ id });
      }
      if (resource === "evidence" && method === "POST") {
        hostOnly(a);
        const data = await body(request, S.evidence);
        const acknowledgeExisting = async () => {
          const existing = await db.query(
            "SELECT (tenant_id=$2 AND host_id=$3 AND snapshot_id=$4 AND body=$5::jsonb) AS matches FROM evidence WHERE id=$1",
            [data.id, a.tenant, a.id, data.snapshotId, JSON.stringify(data)],
          );
          if (!existing.rowCount) return false;
          if (!existing.rows[0].matches)
            throw new ApiError(409, "Evidence ID already exists");
          return true;
        };
        if (await acknowledgeExisting()) return json({ id: data.id }, 201);
        await snapshotExists(db, a, data.snapshotId);
        const inserted = await db.query(
          "INSERT INTO evidence(id,tenant_id,host_id,snapshot_id,body) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING RETURNING id",
          [data.id, a.tenant, a.id, data.snapshotId, data],
        );
        if (!inserted.rowCount) {
          // A durable host may retry after losing the acknowledgement. Only an
          // identical, same-owner report is idempotent; never rewrite evidence.
          if (!(await acknowledgeExisting()))
            throw new ApiError(409, "Evidence ID already exists");
          return json({ id: data.id }, 201);
        }
        await audit(db, a, "restore-test.reported", data.id);
        if (evidenceOutcome(data) === "failed") {
          const failedAlertId = randomUUID();
          await db.query(
            "INSERT INTO alerts(id,tenant_id,host_id,dedupe_key,body) VALUES($1,$2,$3,$4,$5)",
            [
              failedAlertId,
              a.tenant,
              a.id,
              `evidence:${data.id}`,
              {
                type: "restore-test-failed",
                severity: "critical",
                snapshotId: data.snapshotId,
                count: 1,
              },
            ],
          );
          await enqueueAlert(db, a.tenant, a.id, failedAlertId);
        }
        return json({ id: data.id }, 201);
      }
      if (resource === "notifications" && method === "GET") {
        permit(a, ["admin", "operator", "viewer", "approver"]);
        const result = await page(db, url, `${url.pathname}:human:${a.id}`, {
          from: "notification_outbox",
          select:
            "id,alert_id,state,attempts,last_error,last_status,created_at,delivered_at,available_at",
          where: "tenant_id=$1",
          values: [a.tenant],
        });
        return json(result.rows, 200, result.headers);
      }
      if (
        method === "GET" &&
        ["snapshots", "restores", "alerts", "evidence", "audit"].includes(
          resource,
        )
      ) {
        if (resource === "audit" && a.kind === "host")
          throw new ApiError(403, "Human access required");
        const values: unknown[] = [a.tenant];
        let where = "tenant_id=$1";
        if (a.kind === "host") {
          values.push(a.id);
          where += " AND host_id=$2";
        }
        if (id) {
          values.push(id);
          where += ` AND id=$${values.length}`;
        }
        const result = await page(
          db,
          url,
          `${url.pathname}:${a.kind}:${a.id}`,
          {
            from: resource,
            select: "*",
            where,
            values,
            numericId: resource === "audit",
          },
        );
        return json(result.rows, 200, result.headers);
      }
      if (resource === "export" && method === "GET") {
        permit(a, ["admin", "operator", "viewer", "approver"]);
        const report: Record<string, unknown> = {
          generatedAt: new Date().toISOString(),
          tenantId: a.tenant,
          recordLimitPerCategory: 10000,
          assurance:
            "Host-reported metadata only. This report is not a compliance certification. Each category is capped at the latest 10000 records.",
        };
        for (const table of ["snapshots", "evidence", "policies", "audit"])
          report[table] = (
            await db.query(
              `SELECT * FROM ${table} WHERE tenant_id=$1 ORDER BY ${table === "policies" ? "updated_at" : "created_at"} DESC LIMIT 10000`,
              [a.tenant],
            )
          ).rows;
        await audit(db, a, "evidence.exported");
        return json(report, 200, {
          "Content-Disposition": 'attachment; filename="bunker-evidence.json"',
        });
      }
      throw new ApiError(404, "Route not found");
    });
  } catch (e) {
    if (e instanceof z.ZodError)
      return json(
        {
          error: "Invalid metadata",
          issues: e.issues.map((i) => ({ path: i.path, message: i.message })),
        },
        400,
      );
    if (e instanceof ApiError) return json({ error: e.message }, e.status);
    const code = (e as { code?: string })?.code;
    if (code === "23505")
      return json({ error: "Resource already exists" }, 409);
    if (code === "23503")
      return json(
        { error: "Referenced resource not found in this tenant" },
        400,
      );
    return json(
      { error: "Control plane unavailable; no action was committed" },
      503,
    );
  }
}
