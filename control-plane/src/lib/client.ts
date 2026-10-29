import createClient from "openapi-fetch";
import type { paths } from "./api.generated";
/** Typed client generated from the metadata contract. Human callers use same-origin cookies. */
export function metadataClient(baseUrl = "/api") {
  return createClient<paths>({ baseUrl, credentials: "same-origin" });
}

export class ClientError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ClientError";
  }
}

export async function api<T>(path: string, payload?: unknown): Promise<T> {
  return (await apiResponse<T>(path, payload)).data;
}
export async function apiPage<T>(path: string, cursor?: string | null) {
  return apiResponse<T>(
    path +
      (cursor
        ? `${path.includes("?") ? "&" : "?"}cursor=${encodeURIComponent(cursor)}`
        : ""),
  );
}
async function apiResponse<T>(
  path: string,
  payload?: unknown,
): Promise<{ data: T; next: string | null }> {
  const result = await fetch(`/api/${path}`, {
    method: payload === undefined ? "GET" : "POST",
    headers:
      payload === undefined ? {} : { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    cache: "no-store",
  });
  // Preserve HTTP status even when a proxy returns a non-JSON error body.
  const data = await result.json().catch(() => null);
  if (!result.ok) {
    const issues = Array.isArray(data?.issues)
      ? data.issues
          .map(
            (issue: { path?: unknown; message?: unknown } | null) =>
              `${Array.isArray(issue?.path) ? issue.path.join(".") : ""}: ${typeof issue?.message === "string" ? issue.message : "Invalid value"}`,
          )
          .join("; ")
      : "";
    throw new ClientError(
      result.status,
      (data?.error ?? `Request failed (${result.status})`) +
        (issues ? `: ${issues}` : ""),
    );
  }
  if (data === null) throw new Error("Invalid JSON response");
  return { data, next: result.headers.get("X-Next-Cursor") };
}

export async function logout(clearSession: () => void) {
  try {
    await api("auth/logout", {});
  } finally {
    clearSession();
  }
}

/** Prefer fresh rows by ID while retaining explicitly loaded history/selections. */
export function mergeRows<T extends { id: string }>(
  fresh: T[],
  older: T[],
): T[] {
  const seen = new Set(fresh.map((row) => row.id));
  return [...fresh, ...older.filter((row) => !seen.has(row.id))];
}
