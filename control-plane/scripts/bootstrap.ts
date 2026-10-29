import { randomUUID } from "node:crypto";
import { database, transaction } from "../src/lib/db";
import { passwordHash } from "../src/lib/security";
const [email, organizationName, tenantName] = process.argv.slice(2);
// Read password from stdin, never command arguments, logs, or source control.
let password = "";
for await (const chunk of process.stdin) password += chunk;
password = password.replace(/\r?\n$/, "");
if (
  !email ||
  !organizationName ||
  !tenantName ||
  password.length < 14 ||
  password.length > 256
)
  throw new Error(
    "Usage: bootstrap EMAIL ORGANIZATION TENANT; provide a 14–256 character password on stdin",
  );
await transaction(async (db) => {
  await db.query("SELECT pg_advisory_xact_lock(726032)");
  if ((await db.query("SELECT 1 FROM users LIMIT 1")).rowCount)
    throw new Error(
      "Already bootstrapped. Use tenant membership administration.",
    );
  const organization = randomUUID(),
    tenant = randomUUID(),
    user = randomUUID();
  await db.query("INSERT INTO organizations VALUES($1,$2)", [
    organization,
    organizationName,
  ]);
  await db.query("INSERT INTO tenants VALUES($1,$2,$3)", [
    tenant,
    organization,
    tenantName,
  ]);
  await db.query("INSERT INTO users VALUES($1,$2,$3)", [
    user,
    email.toLowerCase(),
    passwordHash(password),
  ]);
  await db.query("INSERT INTO memberships VALUES($1,$2,'admin')", [
    tenant,
    user,
  ]);
});
await database().end();
console.log("Initial administrator and tenant created.");
