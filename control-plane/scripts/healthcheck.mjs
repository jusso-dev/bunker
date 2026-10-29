// Verify server TLS even for probes; Kubernetes HTTPS probes skip verification.
import https from "node:https";
import { readFileSync } from "node:fs";
const origin = new URL(process.env.BUNKER_ORIGIN);
const request = https.request(
  {
    hostname: "127.0.0.1",
    port: 8443,
    servername: origin.hostname,
    path: process.argv.includes("--live") ? "/" : "/api/auth/providers",
    headers: { host: origin.host },
    ca: readFileSync("/run/bunker/secrets/tls-ca.crt"),
    rejectUnauthorized: true,
    timeout: 4000,
  },
  (response) => {
    response.resume();
    process.exitCode = response.statusCode === 200 ? 0 : 1;
  },
);
request.on("timeout", () => request.destroy());
request.on("error", () => {
  process.exitCode = 1;
});
request.end();
