import { isIP } from "node:net";
import { z } from "zod";
import { protectedFile } from "../identity/files";
import { ApiError } from "../lib/security";

const destinationSchema = z
  .strictObject({
    tenantId: z.uuid(),
    id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
    url: z.string().max(2048),
    secretFile: z.string().optional(),
    secretEnv: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]*$/)
      .optional(),
  })
  .refine((v) => Boolean(v.secretFile) !== Boolean(v.secretEnv));
export type Destination = z.infer<typeof destinationSchema>;

// Never echo config, paths, URLs, secrets, parse issues, or transport errors.
export function destinations(): Destination[] {
  try {
    if (!process.env.BUNKER_WEBHOOK_CONFIG_FILE) return [];
    const config = z
      .strictObject({ destinations: z.array(destinationSchema).max(100) })
      .parse(
        JSON.parse(
          protectedFile(process.env.BUNKER_WEBHOOK_CONFIG_FILE).toString(
            "utf8",
          ),
        ),
      );
    if (
      new Set(config.destinations.map((d) => d.tenantId)).size !==
      config.destinations.length
    )
      throw new Error();
    for (const d of config.destinations) destinationUrl(d.url);
    return config.destinations;
  } catch {
    throw new ApiError(503, "Webhook configuration is unavailable");
  }
}
export function destinationUrl(raw: string): URL {
  const url = new URL(raw);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  )
    throw new Error("Invalid webhook destination");
  return url;
}
export function signingSecret(d: Destination): Buffer {
  try {
    const secret = d.secretFile
      ? protectedFile(d.secretFile)
      : Buffer.from(process.env[d.secretEnv!] ?? "", "utf8");
    if (secret.length < 32 || secret.length > 4096) throw new Error();
    return secret;
  } catch {
    throw new Error("Webhook signing secret unavailable");
  }
}
// Explicit, separately configured disposable test transport; never available in production.
export function testTransport(): { ca: Buffer } | undefined {
  if (!process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE) return;
  if (process.env.NODE_ENV !== "test")
    throw new Error("Webhook test transport requires NODE_ENV=test");
  const config = z
    .strictObject({ caFile: z.string() })
    .parse(
      JSON.parse(
        protectedFile(process.env.BUNKER_WEBHOOK_TEST_TRANSPORT_FILE).toString(
          "utf8",
        ),
      ),
    );
  return { ca: protectedFile(config.caFile) };
}
export function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  if (isIP(address) === 6) {
    // Only global unicast, excluding special-purpose 2001::/23, documentation and transition ranges.
    const parts = address.toLowerCase().split(":");
    const first = parseInt(parts[0], 16),
      second = parseInt(parts[1] || "0", 16);
    return (
      first >= 0x2000 &&
      first <= 0x3fff &&
      first !== 0x2002 &&
      first !== 0x3fff &&
      !(first === 0x2001 && (second < 0x200 || second === 0xdb8))
    );
  }
  return false;
}
