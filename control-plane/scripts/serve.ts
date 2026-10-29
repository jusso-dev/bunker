// Container entrypoint: one network namespace, a private Next upstream, two TLS listeners.
import { spawn } from "node:child_process";
import {
  constants,
  copyFileSync,
  chmodSync,
  mkdirSync,
  readdirSync,
  statSync,
  lstatSync,
  existsSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { createGateway } from "../src/gateway/server";
import { protectedFile, gatewayKey } from "../src/identity/files";
import { providers } from "../src/identity/federation";

import { bootstrapNotifications } from "./notification-bootstrap";

bootstrapNotifications("api");

const source = "/run/secrets/bunker";
const destination = "/run/bunker/secrets";
// Kubernetes projects Secrets as symlinks. Copy this explicitly trusted mount into
// private regular files; never loosen protectedFile() for the running application.
if (existsSync(destination)) {
  if (lstatSync(destination).isSymbolicLink())
    throw new Error("Unsafe runtime directory");
  rmSync(destination, { recursive: true });
}
mkdirSync(destination, { recursive: true, mode: 0o700 });
if (
  !lstatSync(destination).isDirectory() ||
  lstatSync(destination).isSymbolicLink()
)
  throw new Error("Runtime secret directory must be a regular directory");
chmodSync(destination, 0o700);
for (const name of readdirSync(source)) {
  if (name.startsWith("..")) continue; // Kubernetes projection bookkeeping
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(name))
    throw new Error("Invalid secret filename");
  const input = join(source, name),
    output = join(destination, name);
  const stat = statSync(input);
  if (!stat.isFile() || stat.size > 65536)
    throw new Error("Invalid mounted secret file");
  // EXCL prevents overwriting an unexpected destination.
  copyFileSync(input, output, constants.COPYFILE_EXCL);
  chmodSync(output, 0o600);
}
if (process.env.BUNKER_ALLOW_INSECURE_LOOPBACK === "true")
  throw new Error(
    "Development authentication is forbidden in the production entrypoint",
  );
const identityFiles = {
  BUNKER_TLS_KEY_FILE: "tls.key",
  BUNKER_TLS_CERT_FILE: "tls.crt",
  BUNKER_CA_CERT_FILE: "ca.crt",
  BUNKER_CA_KEY_FILE: "ca.key",
  BUNKER_GATEWAY_SECRET_FILE: "gateway.secret",
  BUNKER_IDENTITY_PROVIDERS_FILE: "providers.json",
};
for (const [key, name] of Object.entries(identityFiles))
  process.env[key] = join(destination, name);
protectedFile(join(destination, "tls-ca.crt")); // probe trust roots, provisioned separately from host CA
const ca = new X509Certificate(protectedFile(process.env.BUNKER_CA_CERT_FILE));
if (
  !ca.ca ||
  !ca.checkPrivateKey(
    createPrivateKey(protectedFile(process.env.BUNKER_CA_KEY_FILE)),
  ) ||
  Date.parse(ca.validFrom) > Date.now() ||
  Date.parse(ca.validTo) <= Date.now() + 60000
)
  throw new Error("Invalid signing CA");
for (const p of providers()) {
  if (
    !p.clientSecretFile.startsWith(destination + "/") ||
    p.clientSecretFile.slice(destination.length + 1).includes("/") ||
    !protectedFile(p.clientSecretFile).toString().trim()
  )
    throw new Error(
      "Provider credentials must reference protected runtime files",
    );
}
const publicOrigin = process.env.BUNKER_ORIGIN;
const hostOrigin = process.env.BUNKER_HOST_ORIGIN;
if (!publicOrigin || !hostOrigin || publicOrigin === hostOrigin)
  throw new Error("Distinct public and host HTTPS origins are required");
const shared = {
  key: protectedFile(process.env.BUNKER_TLS_KEY_FILE),
  cert: protectedFile(process.env.BUNKER_TLS_CERT_FILE),
  ca: protectedFile(process.env.BUNKER_CA_CERT_FILE),
  secret: gatewayKey(),
  upstream: "http://127.0.0.1:3000",
};
const servers = [
  createGateway({ ...shared, origin: publicOrigin, clientAuth: "public" }),
  createGateway({ ...shared, origin: hostOrigin, clientAuth: "required" }),
];
const child = spawn(
  process.execPath,
  [
    "control-plane/node_modules/next/dist/bin/next",
    "start",
    "control-plane",
    "--hostname",
    "127.0.0.1",
    "--port",
    "3000",
  ],
  {
    stdio: "inherit",
    env: { ...process.env, BUNKER_ALLOW_INSECURE_LOOPBACK: "false" },
  },
);
let stopping = false;
const stop = (code: number) => {
  if (stopping) return;
  stopping = true;
  for (const server of servers) server.close();
  child.kill("SIGTERM");
  const deadline = setTimeout(() => {
    child.kill("SIGKILL");
    process.exit(code);
  }, 10000);
  deadline.unref();
  if (child.exitCode !== null || child.signalCode !== null) process.exit(code);
  child.once("exit", () => process.exit(code));
};
child.on("error", () => stop(1));
child.on("exit", () => stop(1));
process.on("SIGTERM", () => stop(0));
process.on("SIGINT", () => stop(0));
servers.forEach((server, i) => {
  server.on("error", () => stop(1));
  server.listen(8443 + i, "0.0.0.0");
});
