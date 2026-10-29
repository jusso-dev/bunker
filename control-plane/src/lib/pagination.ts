import type { PoolClient } from "pg";
import { z } from "zod";
import { ApiError } from "./security";

const cursorSchema = z.strictObject({
  v: z.literal(1),
  scope: z.string().max(512),
  time: z.iso.datetime().regex(/\.\d{6}Z$/),
  id: z.string().max(40),
});

/** SQL identifiers/fragments come exclusively from route code, never from input. */
export async function page(
  db: PoolClient,
  url: URL,
  scope: string,
  query: {
    from: string;
    select: string;
    where: string;
    values: unknown[];
    time?: string;
    id?: string;
    numericId?: boolean;
  },
) {
  const time = query.time ?? "created_at",
    id = query.id ?? "id";
  const values = [...query.values];
  let where = query.where;
  for (const key of ["cursor", "before", "limit"])
    if (url.searchParams.getAll(key).length > 1)
      throw new ApiError(400, "Duplicate pagination parameter");
  const limitText = url.searchParams.get("limit") ?? "200";
  if (!/^[1-9]\d{0,2}$/.test(limitText) || Number(limitText) > 200)
    throw new ApiError(400, "Limit must be between 1 and 200");
  const limit = Number(limitText);
  const encoded = url.searchParams.get("cursor");
  const before = url.searchParams.get("before");
  if (encoded !== null) {
    if (before !== null)
      throw new ApiError(400, "Use cursor or before, not both");
    try {
      if (!/^[A-Za-z0-9_-]{1,2048}$/.test(encoded)) throw new Error();
      const decoded = Buffer.from(encoded, "base64url");
      if (decoded.toString("base64url") !== encoded) throw new Error();
      const cursor = cursorSchema.parse(JSON.parse(decoded.toString("utf8")));
      if (cursor.scope !== scope || !Number.isFinite(Date.parse(cursor.time)))
        throw new Error();
      if (query.numericId) {
        if (
          !/^[1-9]\d{0,18}$/.test(cursor.id) ||
          BigInt(cursor.id) > 9223372036854775807n
        )
          throw new Error();
      } else if (!z.uuid().safeParse(cursor.id).success) throw new Error();
      values.push(cursor.time, cursor.id);
      where += ` AND (${time},${id}) < ($${values.length - 1}::timestamptz,$${values.length}::${query.numericId ? "bigint" : "uuid"})`;
    } catch {
      throw new ApiError(400, "Invalid or out-of-scope cursor");
    }
  } else if (before !== null) {
    if (!z.iso.datetime().safeParse(before).success)
      throw new ApiError(400, "Invalid before timestamp");
    values.push(before);
    where += ` AND ${time} < $${values.length}::timestamptz`;
  }
  values.push(limit + 1);
  const result = await db.query(
    `SELECT ${query.select},to_char(${time} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS _page_time,${id}::text AS _page_id FROM ${query.from} WHERE ${where} ORDER BY ${time} DESC,${id} DESC LIMIT $${values.length}`,
    values,
  );
  const more = result.rows.length > limit;
  const rows = result.rows.slice(0, limit);
  const last = rows.at(-1);
  const next =
    more && last
      ? Buffer.from(
          JSON.stringify({
            v: 1,
            scope,
            time: last._page_time,
            id: last._page_id,
          }),
        ).toString("base64url")
      : null;
  const headers: Record<string, string> = next ? { "X-Next-Cursor": next } : {};
  return {
    rows: rows.map(({ _page_time, _page_id, ...row }) => {
      void _page_time;
      void _page_id;
      return row;
    }),
    headers,
  };
}
