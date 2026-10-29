import type { PoolClient } from "pg";
import { ApiError, digest, passwordHash, token } from "./security";

export const hasLocalPassword = (hash: unknown): hash is string =>
  typeof hash === "string" && /^[a-f0-9]{32}:[a-f0-9]{128}$/.test(hash);

export async function accountAudit(
  db: PoolClient,
  user: string,
  actor: string,
  action: string,
) {
  await db.query(
    "INSERT INTO audit(tenant_id,actor,action,resource_id) SELECT tenant_id,$2,$3,user_id FROM memberships WHERE user_id=$1",
    [user, actor, action],
  );
}

/** Caller holds the user lock, shared with local login and identity link/callback. */
export async function replacePassword(
  db: PoolClient,
  user: string,
  password: string,
  actor: string,
  action: string,
) {
  const changed = await db.query(
    "UPDATE users SET password_hash=$2 WHERE id=$1 RETURNING email",
    [user, passwordHash(password)],
  );
  await db.query("DELETE FROM login_attempts WHERE identity_hash=$1", [
    digest(changed.rows[0].email),
  ]);
  await db.query("DELETE FROM sessions WHERE user_id=$1", [user]);
  await db.query("DELETE FROM password_recoveries WHERE user_id=$1", [user]);
  await accountAudit(db, user, actor, action);
}

/** Instance operator only. Never expose issuance through a tenant-admin API. */
export async function issueRecovery(db: PoolClient, user: string) {
  const found = await db.query(
    "SELECT password_hash FROM users WHERE id=$1 FOR UPDATE",
    [user],
  );
  if (!hasLocalPassword(found.rows[0]?.password_hash))
    throw new ApiError(
      409,
      "An existing local credential is required; use the identity provider for federated-only accounts",
    );
  const secret = token();
  await db.query("DELETE FROM password_recoveries WHERE user_id=$1", [user]);
  await db.query(
    "INSERT INTO password_recoveries(token_hash,user_id,created_at,expires_at) SELECT $1,$2,at,at+interval '15 minutes' FROM (SELECT clock_timestamp() AS at) t",
    [digest(secret), user],
  );
  await accountAudit(db, user, "instance-admin", "password.recovery-issued");
  return secret;
}
