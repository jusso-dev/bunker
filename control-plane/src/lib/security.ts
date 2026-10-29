import {
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createHash,
} from "node:crypto";
export const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export const token = () => randomBytes(32).toString("base64url");
export function passwordHash(password: string) {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${scryptSync(password, salt, 64).toString("hex")}`;
}
export function passwordMatches(password: string, encoded: string) {
  const [salt, hash] = encoded.split(":");
  const actual = scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, "hex");
  return expected.length === actual.length && timingSafeEqual(actual, expected);
}
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export function requireOrigin(request: Request) {
  if (request.headers.get("origin") !== process.env.BUNKER_ORIGIN)
    throw new ApiError(403, "A matching Origin header is required");
}
export function localAgentMode() {
  const origin = new URL(process.env.BUNKER_ORIGIN || "https://invalid");
  return (
    process.env.BUNKER_ALLOW_INSECURE_LOOPBACK === "true" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname) &&
    origin.protocol === "http:"
  );
}
export function requireAgentTransport(request: Request) {
  // Next.js does not expose the verified client TLS certificate. Never trust forwarded certificate headers.
  if (
    !localAgentMode() ||
    !["localhost", "127.0.0.1", "[::1]"].includes(new URL(request.url).hostname)
  )
    throw new ApiError(
      503,
      "Bearer host transport is restricted to explicit loopback development. Production hosts require the mTLS gateway.",
    );
}

export function requireSafeConfiguration() {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0")
    throw new ApiError(503, "Global TLS verification bypass is forbidden");
  let origin: URL;
  try {
    origin = new URL(process.env.BUNKER_ORIGIN || "");
  } catch {
    throw new ApiError(503, "BUNKER_ORIGIN must be configured");
  }
  if (
    origin.origin !== process.env.BUNKER_ORIGIN ||
    origin.username ||
    origin.password
  )
    throw new ApiError(503, "BUNKER_ORIGIN must be a canonical origin");
  if (
    origin.protocol !== "https:" &&
    !(
      origin.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname)
    )
  )
    throw new ApiError(503, "HTTPS is required outside loopback development");
}
