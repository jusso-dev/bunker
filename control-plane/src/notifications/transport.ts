import { createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { isIP } from "node:net";
import {
  destinationUrl,
  isPublicAddress,
  signingSecret,
  testTransport,
  type Destination,
} from "./config";

export type DeliveryResult = {
  ok: boolean;
  retryable: boolean;
  error?:
    | "configuration"
    | "network"
    | "timeout"
    | "response-too-large"
    | "http-retryable"
    | "http-rejected";
  status?: number;
};
export const DELIVERY_TIMEOUT_MS = 10_000;
export const RESPONSE_LIMIT = 16_384;
export function signature(
  secret: Buffer,
  timestamp: string,
  body: string,
): string {
  return createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
}
export async function deliver(
  destination: Destination,
  id: string,
  payload: unknown,
): Promise<DeliveryResult> {
  let url: URL, secret: Buffer, fixture: ReturnType<typeof testTransport>;
  try {
    url = destinationUrl(destination.url);
    secret = signingSecret(destination);
    fixture = testTransport();
    if (fixture && !["127.0.0.1", "localhost"].includes(url.hostname))
      throw new Error();
  } catch {
    return { ok: false, retryable: true, error: "configuration" };
  }
  // A total deadline includes DNS, TCP, TLS, headers and response streaming.
  return new Promise((resolve) => {
    let done = false;
    let active: ReturnType<typeof request> | undefined;
    const finish = (result: DeliveryResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      active?.destroy();
      resolve(result);
    };
    const timer = setTimeout(
      () => finish({ ok: false, retryable: true, error: "timeout" }),
      DELIVERY_TIMEOUT_MS,
    );
    void (async () => {
      const hostname = url.hostname.replace(/^\[|\]$/g, "");
      const addresses = isIP(hostname)
        ? [{ address: hostname, family: isIP(hostname) }]
        : await lookup(hostname, { all: true });
      if (done) return;
      if (
        !addresses.length ||
        addresses.some((a) =>
          fixture
            ? !["127.0.0.1", "::1"].includes(a.address)
            : !isPublicAddress(a.address),
        )
      ) {
        finish({ ok: false, retryable: false, error: "configuration" });
        return;
      }
      const selected = addresses.find((a) => a.family === 4) ?? addresses[0];
      const body = JSON.stringify(payload);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      active = request(
        url,
        {
          method: "POST",
          agent: false,
          rejectUnauthorized: true,
          family: selected.family,
          ...(fixture ? { ca: fixture.ca } : {}),
          // Pin the validated DNS answer. TLS still verifies the original URL hostname.
          lookup: (_hostname, _options, callback) =>
            callback(null, selected.address, selected.family),
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body),
            "user-agent": "Bunker-Webhook/1",
            "idempotency-key": id,
            "x-bunker-delivery-id": id,
            "x-bunker-timestamp": timestamp,
            "x-bunker-signature": `v1=${signature(secret, timestamp, body)}`,
          },
          maxHeaderSize: 16_384,
        },
        (response) => {
          const status = response.statusCode ?? 0;
          let bytes = 0;
          response.on("data", (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > RESPONSE_LIMIT)
              finish({
                ok: false,
                retryable: true,
                error: "response-too-large",
                status,
              });
          });
          response.on("end", () => {
            if (status >= 200 && status < 300)
              finish({ ok: true, retryable: false, status });
            else {
              const retryable =
                status === 408 || status === 429 || status >= 500;
              finish({
                ok: false,
                retryable,
                status,
                error: retryable ? "http-retryable" : "http-rejected",
              });
            }
          });
          response.on("error", () =>
            finish({ ok: false, retryable: true, error: "network" }),
          );
        },
      );
      active.on("error", () =>
        finish({ ok: false, retryable: true, error: "network" }),
      );
      active.end(body);
    })().catch(() => finish({ ok: false, retryable: true, error: "network" }));
  });
}
