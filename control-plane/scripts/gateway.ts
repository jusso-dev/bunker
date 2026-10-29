import { createGateway } from "../src/gateway/server";
import { gatewayKey, protectedFile } from "../src/identity/files";
const shared = {
  key: protectedFile(process.env.BUNKER_TLS_KEY_FILE),
  cert: protectedFile(process.env.BUNKER_TLS_CERT_FILE),
  ca: protectedFile(process.env.BUNKER_CA_CERT_FILE),
  secret: gatewayKey(),
  upstream: process.env.BUNKER_PRIVATE_UPSTREAM || "http://127.0.0.1:3000",
};
for (const [clientAuth, origin, port] of [
  [
    "public",
    process.env.BUNKER_ORIGIN,
    process.env.BUNKER_HTTPS_PORT || "8443",
  ],
  [
    "required",
    process.env.BUNKER_HOST_ORIGIN,
    process.env.BUNKER_MTLS_PORT || "8444",
  ],
] as const) {
  if (
    !origin ||
    !/^\d+$/.test(port) ||
    Number(port) < 1 ||
    Number(port) > 65535
  )
    throw new Error("Both HTTPS origins and valid listener ports are required");
  const server = createGateway({ ...shared, origin, clientAuth });
  server.listen(Number(port), process.env.BUNKER_GATEWAY_BIND || "127.0.0.1");
}
