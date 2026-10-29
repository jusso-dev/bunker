import { Pool, type PoolClient } from "pg";
const globalDb = globalThis as unknown as { bunkerPool?: Pool };
export function database() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  if (globalDb.bunkerPool) return globalDb.bunkerPool;
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    connectionTimeoutMillis: 5000,
    query_timeout: 15000,
    statement_timeout: 10000,
  });
  // pg-pool emits errors from idle clients outside any query promise. Handling
  // this event prevents an unhandled-event dump of server-supplied private detail.
  // The pool removes the failed client; subsequent work obtains a fresh one.
  pool.on("error", () => {
    console.error("Database idle connection failed; reconnecting.");
  });
  globalDb.bunkerPool = pool;
  return pool;
}
export async function transaction<T>(
  fn: (db: PoolClient) => Promise<T>,
): Promise<T> {
  const db = await database().connect();
  try {
    await db.query("BEGIN");
    const value = await fn(db);
    await db.query("COMMIT");
    return value;
  } catch (e) {
    await db.query("ROLLBACK");
    throw e;
  } finally {
    db.release();
  }
}
