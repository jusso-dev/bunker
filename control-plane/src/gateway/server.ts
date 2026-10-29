import https from "node:https";
import http from "node:http";
import { TLSSocket } from "node:tls";
import { createHash } from "node:crypto";
import { proofHeader, signGatewayRequest } from "../identity/gateway-proof";

export type GatewayOptions = {
  key: Buffer;
  cert: Buffer;
  ca: Buffer;
  secret: Buffer;
  origin: string;
  upstream: string;
  clientAuth: "required" | "public";
};
export function createGateway(options: GatewayOptions) {
  const upstream = new URL(options.upstream),
    origin = new URL(options.origin);
  if (
    process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" ||
    origin.protocol !== "https:" ||
    origin.origin !== options.origin ||
    origin.username ||
    origin.password ||
    options.secret.length !== 32 ||
    upstream.protocol !== "http:" ||
    !["127.0.0.1", "[::1]"].includes(upstream.hostname) ||
    upstream.username ||
    upstream.password ||
    upstream.pathname !== "/" ||
    upstream.search ||
    upstream.hash
  )
    throw new Error(
      "Invalid gateway configuration: HTTPS origin and private loopback upstream required",
    );
  // Separate public and host listeners avoid disabling TLS verification.
  // Host listener requires a trusted certificate and proof of private-key possession.
  const server = https.createServer(
    {
      key: options.key,
      cert: options.cert,
      ca: options.ca,
      requestCert: options.clientAuth === "required",
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
      maxHeaderSize: 16384,
    },
    async (req, res) => {
      const fail = (status: number, error: string) => {
        if (!res.headersSent)
          res.writeHead(status, {
            "content-type": "application/json",
            "cache-control": "no-store",
          });
        res.end(JSON.stringify({ error }));
      };
      try {
        const socket = req.socket as TLSSocket;
        const peer = socket.getPeerCertificate();
        if (
          options.clientAuth === "required" &&
          (!peer.raw || !socket.authorized)
        )
          return fail(401, "Invalid client certificate");
        const fingerprint =
          options.clientAuth === "required" && peer.raw && socket.authorized
            ? createHash("sha256").update(peer.raw).digest("hex")
            : null;
        if (
          !req.url?.startsWith("/") ||
          req.url.startsWith("//") ||
          req.url.includes("\\")
        )
          return fail(400, "Invalid request target");
        if (req.headers.authorization && !fingerprint)
          return fail(401, "Verified client certificate required");
        const headers = new Headers();
        const connectionHeaders = String(req.headers.connection || "")
          .toLowerCase()
          .split(",")
          .map((x) => x.trim());
        for (const [name, value] of Object.entries(req.headers)) {
          if (
            name.startsWith("x-bunker-") ||
            name.startsWith("x-forwarded-") ||
            name.startsWith("x-client-") ||
            name.startsWith("x-ssl-") ||
            [
              "forwarded",
              "host",
              "connection",
              "transfer-encoding",
              "content-length",
              "keep-alive",
              "upgrade",
              "te",
              "trailer",
              "proxy-authorization",
              "proxy-connection",
            ].includes(name) ||
            connectionHeaders.includes(name)
          )
            continue;
          if (value !== undefined)
            headers.set(name, Array.isArray(value) ? value.join("; ") : value);
        }
        const chunks: Buffer[] = [];
        let size = 0;
        const deadline = setTimeout(() => req.destroy(), 10000);
        try {
          for await (const chunk of req) {
            size += chunk.length;
            if (size > 256000) return fail(413, "Metadata request too large");
            chunks.push(chunk);
          }
        } finally {
          clearTimeout(deadline);
        }
        const body = Buffer.concat(chunks);
        const target = new URL(req.url, origin);
        if (target.origin !== origin.origin) return fail(400, "Invalid target");
        headers.set(
          proofHeader,
          await signGatewayRequest(
            req.method || "GET",
            target.pathname + target.search,
            headers,
            body,
            fingerprint,
            options.secret,
          ),
        );
        headers.set("host", origin.host);
        headers.set("x-forwarded-proto", "https");
        headers.set("content-length", String(body.length));
        const proxy = http.request(
          {
            hostname: upstream.hostname.replace(/^\[|\]$/g, ""),
            port: upstream.port || 80,
            path: target.pathname + target.search,
            method: req.method,
            headers: Object.fromEntries(headers),
            timeout: 15000,
          },
          (response) => {
            res.writeHead(response.statusCode || 502, response.headers);
            response.pipe(res);
          },
        );
        proxy.on("timeout", () => proxy.destroy());
        proxy.on("error", () => fail(502, "Upstream unavailable"));
        res.on("close", () => proxy.destroy());
        proxy.end(body);
      } catch {
        fail(400, "Invalid gateway request");
      }
    },
  );
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}
