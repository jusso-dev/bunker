import { createHash, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { z } from "zod";
import { transaction } from "../lib/db";
import { ApiError } from "../lib/security";
import { gatewayKey } from "./files";
export const proofHeader = "x-bunker-gateway";
const claims = z.object({
  method: z.string(),
  target: z.string(),
  body: z.string(),
  headers: z.string(),
  fingerprint: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .nullable(),
  jti: z.uuid(),
  iat: z.number(),
  exp: z.number(),
});
const hash = (data: Uint8Array | string) =>
  createHash("sha256").update(data).digest("hex");
const boundHeaders = (headers: Headers) =>
  hash(
    JSON.stringify(
      ["content-type", "origin", "cookie", "authorization"].map((k) => [
        k,
        headers.get(k),
      ]),
    ),
  );
export async function readBounded(request: Request) {
  const reader = request.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks: Uint8Array[] = [];
  let size = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      (async () => {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 256000)
            throw new ApiError(413, "Metadata request too large");
          chunks.push(value);
        }
        return Buffer.concat(chunks);
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new ApiError(408, "Request body timed out"));
          void reader.cancel().catch(() => {});
        }, 10000);
      }),
    ]);
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
export async function signGatewayRequest(
  method: string,
  target: string,
  headers: Headers,
  body: Uint8Array,
  fingerprint: string | null,
  key: Uint8Array,
) {
  return new SignJWT({
    method,
    target,
    headers: boundHeaders(headers),
    body: hash(body),
    fingerprint,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("bunker-tls-gateway")
    .setAudience("bunker-control-plane")
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime("30s")
    .sign(key);
}
export async function verifyGatewayRequest(
  request: Request,
): Promise<{ request: Request; fingerprint: string | null }> {
  const key = gatewayKey(); // Configuration errors remain 503, invalid authentication is 401.
  const body = await readBounded(request);
  let proof: z.infer<typeof claims>;
  try {
    const jwt = await jwtVerify(request.headers.get(proofHeader) || "", key, {
      algorithms: ["HS256"],
      issuer: "bunker-tls-gateway",
      audience: "bunker-control-plane",
      typ: "JWT",
      maxTokenAge: "30s",
    });
    proof = claims.parse(jwt.payload);
    const url = new URL(request.url);
    if (
      proof.exp - proof.iat > 30 ||
      proof.iat > Date.now() / 1000 ||
      proof.method !== request.method ||
      proof.target !== url.pathname + url.search ||
      proof.body !== hash(body) ||
      proof.headers !== boundHeaders(request.headers)
    )
      throw new Error();
  } catch {
    throw new ApiError(401, "Invalid gateway authentication");
  }
  // Consume in an independent committed transaction: rejected API requests cannot replay.
  await transaction(async (db) => {
    await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [proof.jti]);
    await db.query(
      "DELETE FROM gateway_nonces WHERE expires_at < clock_timestamp()",
    );
    const used = await db.query(
      "INSERT INTO gateway_nonces(id,expires_at) SELECT $1,to_timestamp($2) WHERE to_timestamp($2)>clock_timestamp() ON CONFLICT DO NOTHING RETURNING id",
      [proof.jti, proof.exp],
    );
    if (!used.rowCount)
      throw new ApiError(401, "Replayed gateway authentication");
  });
  return {
    request: new Request(request.url, {
      method: request.method,
      headers: request.headers,
      ...(body.length ? { body } : {}),
    }),
    fingerprint: proof.fingerprint,
  };
}
