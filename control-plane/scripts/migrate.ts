import { readFile } from "node:fs/promises";
import { database, transaction } from "../src/lib/db";
await transaction(async (db) => {
  await db.query("SELECT pg_advisory_xact_lock(726031)");
  const exists = await db.query(
    "SELECT to_regclass('public.schema_migrations') AS name",
  );
  if (!exists.rows[0].name) {
    await db.query(
      await readFile(
        new URL("../migrations/001_initial.sql", import.meta.url),
        "utf8",
      ),
    );
  }
  const applied = await db.query(
    "SELECT version FROM schema_migrations WHERE version=2",
  );
  if (!applied.rowCount)
    await db.query(
      await readFile(
        new URL("../migrations/002_identity.sql", import.meta.url),
        "utf8",
      ),
    );
  const notifications = await db.query(
    "SELECT version FROM schema_migrations WHERE version=3",
  );
  if (!notifications.rowCount)
    await db.query(
      await readFile(
        new URL("../migrations/003_notifications.sql", import.meta.url),
        "utf8",
      ),
    );
  const lifecycle = await db.query(
    "SELECT version FROM schema_migrations WHERE version=4",
  );
  if (!lifecycle.rowCount)
    await db.query(
      await readFile(
        new URL("../migrations/004_human_lifecycle.sql", import.meta.url),
        "utf8",
      ),
    );
});
await database().end();
console.log("Database schema is current.");
