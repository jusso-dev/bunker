// Instance-administrator operation. Tenant admins must not be able to take over
// a global user who may also belong to other tenants.
import { providers } from "../src/identity/federation";
import { database, transaction } from "../src/lib/db";
import { z } from "zod";
const [action, providerId, subject, userId] = process.argv.slice(2);
const p = providers().find((p) => p.id === providerId);
if (
  !p ||
  !["link", "unlink"].includes(action) ||
  !subject ||
  subject.length > 512 ||
  !z.uuid().safeParse(userId).success
)
  throw new Error(
    "Usage: link-identity link|unlink PROVIDER SUBJECT USER_UUID",
  );
await transaction(async (db) => {
  const user = await db.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [
    userId,
  ]);
  if (!user.rowCount)
    throw new Error(
      "User does not exist; create their account and membership first",
    );
  if (action === "link")
    await db.query(
      "INSERT INTO external_identities(provider,issuer,subject,user_id) VALUES($1,$2,$3,$4)",
      [p.id, p.issuer, subject, userId],
    );
  else {
    await db.query(
      "DELETE FROM external_identities WHERE provider=$1 AND issuer=$2 AND subject=$3 AND user_id=$4",
      [p.id, p.issuer, subject, userId],
    );
    await db.query("DELETE FROM sessions WHERE user_id=$1", [userId]);
  }
  await db.query(
    "INSERT INTO audit(tenant_id,actor,action,resource_id) SELECT tenant_id,'instance-admin',$1,user_id FROM memberships WHERE user_id=$2",
    [`identity.${action}`, userId],
  );
});
await database().end();
console.log("Identity administration complete.");
