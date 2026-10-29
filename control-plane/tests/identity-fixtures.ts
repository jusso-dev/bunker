import {
  mkdtempSync,
  chmodSync,
  writeFileSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import https from "node:https";
import type { Server } from "node:net";
export function fixtures() {
  const dir = mkdtempSync(join(tmpdir(), "bunker-identity-"));
  const file = (name: string) => join(dir, name);
  const read = (name: string) => readFileSync(file(name));
  const write = (name: string, data: string | Buffer) => {
    writeFileSync(file(name), data, { mode: 0o600 });
    chmodSync(file(name), 0o600);
  };
  const openssl = (...args: string[]) =>
    execFileSync("openssl", args, { cwd: dir, stdio: "ignore" });
  openssl(
    "req",
    "-sha256",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-pkeyopt",
    "ec_param_enc:named_curve",
    "-nodes",
    "-keyout",
    "ca.key",
    "-out",
    "ca.pem",
    "-days",
    "2",
    "-subj",
    "/CN=Bunker Disposable Test CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  );
  openssl(
    "req",
    "-new",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-pkeyopt",
    "ec_param_enc:named_curve",
    "-nodes",
    "-keyout",
    "server.key",
    "-out",
    "server.csr",
    "-subj",
    "/CN=localhost",
  );
  write(
    "server.ext",
    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
  );
  openssl(
    "x509",
    "-sha256",
    "-req",
    "-in",
    "server.csr",
    "-CA",
    "ca.pem",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-out",
    "server.pem",
    "-days",
    "1",
    "-extfile",
    "server.ext",
  );
  openssl(
    "req",
    "-new",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-pkeyopt",
    "ec_param_enc:named_curve",
    "-nodes",
    "-keyout",
    "host.key",
    "-out",
    "host.csr",
    "-subj",
    "/CN=caller-controlled",
    "-addext",
    "subjectAltName=URI:urn:attacker",
  );
  write("gateway.secret", randomBytes(32));
  // OpenSSL honors umask for private keys; protect public config files as required too.
  for (const name of ["ca.key", "ca.pem", "server.key", "server.pem"])
    write(name, read(name));
  return {
    dir,
    file,
    read,
    write,
    openssl,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}
export const listen = (server: Server) =>
  new Promise<number>((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve((server.address() as { port: number }).port),
    ),
  );
export const close = (server: Server) =>
  new Promise<void>((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
export async function tlsCall(
  url: string,
  ca: Buffer,
  options: {
    method?: string;
    body?: string;
    headers?: Record<string, string>;
    key?: Buffer;
    cert?: Buffer;
  } = {},
) {
  return await new Promise<{
    status: number;
    headers: import("node:http").IncomingHttpHeaders;
    body: string;
  }>((resolve, reject) => {
    const request = https.request(
      url,
      { ca, rejectUnauthorized: true, ...options },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode!,
            headers: response.headers,
            body: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    request.on("error", reject);
    request.end(options.body);
  });
}

export async function expiredHostCertificate(f: ReturnType<typeof fixtures>) {
  // Deliberately expired leaf signed by the trusted disposable CA, exercising
  // OpenSSL validity checks during the actual TLS handshake.
  const {
    X509Certificate,
    X509CertificateGenerator,
    Pkcs10CertificateRequest,
    BasicConstraintsExtension,
    KeyUsagesExtension,
    KeyUsageFlags,
    ExtendedKeyUsageExtension,
  } = await import("@peculiar/x509");
  const { createPrivateKey, webcrypto } = await import("node:crypto");
  const key = createPrivateKey(f.read("ca.key"));
  const signingKey = await webcrypto.subtle.importKey(
    "pkcs8",
    key.export({ type: "pkcs8", format: "der" }),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const cert = await X509CertificateGenerator.create({
    subject: "CN=expired",
    issuer: new X509Certificate(f.read("ca.pem").toString()).subject,
    publicKey: new Pkcs10CertificateRequest(f.read("host.csr").toString())
      .publicKey,
    signingKey,
    notBefore: new Date(Date.now() - 7200000),
    notAfter: new Date(Date.now() - 3600000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      new ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.2"], true),
    ],
  });
  return Buffer.from(cert.toString("pem"));
}
