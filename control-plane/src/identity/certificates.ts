import "reflect-metadata";
import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  X509Certificate as NodeCertificate,
  webcrypto,
} from "node:crypto";
import {
  X509Certificate,
  X509CertificateGenerator,
  Pkcs10CertificateRequest,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  ExtendedKeyUsageExtension,
  SubjectAlternativeNameExtension,
} from "@peculiar/x509";
import { protectedFile } from "./files";
import { ApiError } from "../lib/security";

export async function issueCertificate(
  csrPem: string,
  tenant: string,
  host: string,
) {
  const certPem = protectedFile(process.env.BUNKER_CA_CERT_FILE).toString();
  const ca = new X509Certificate(certPem);
  const nodeCA = new NodeCertificate(certPem);
  const key = createPrivateKey(protectedFile(process.env.BUNKER_CA_KEY_FILE));
  const constraints = ca.getExtension(BasicConstraintsExtension);
  const usage = ca.getExtension(KeyUsagesExtension);
  if (
    !nodeCA.ca ||
    !constraints?.ca ||
    !usage ||
    !(usage.usages & KeyUsageFlags.keyCertSign) ||
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
    !nodeCA.checkPrivateKey(key) ||
    ca.notBefore.getTime() > Date.now() ||
    ca.notAfter.getTime() <= Date.now() + 60000
  )
    throw new ApiError(503, "Signing CA configuration is invalid");
  let csr: Pkcs10CertificateRequest;
  try {
    csr = new Pkcs10CertificateRequest(csrPem);
    if (!(await csr.verify())) throw new Error();
    const pub = createPublicKey(csr.publicKey.toString("pem"));
    const details = pub.asymmetricKeyDetails;
    if (
      !(
        pub.asymmetricKeyType === "ec" && details?.namedCurve === "prime256v1"
      ) &&
      !(
        pub.asymmetricKeyType === "rsa" &&
        (details?.modulusLength ?? 0) >= 2048 &&
        (details?.modulusLength ?? 0) <= 4096
      )
    )
      throw new Error();
  } catch {
    throw new ApiError(
      400,
      "Invalid CSR: signed P-256 or RSA 2048–4096 key required",
    );
  }
  const signingKey = await webcrypto.subtle.importKey(
    "pkcs8",
    key.export({ type: "pkcs8", format: "der" }),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const expiresAt = new Date(
    Math.min(Date.now() + 24 * 60 * 60 * 1000, ca.notAfter.getTime()),
  );
  const serial = randomBytes(20);
  serial[0] &= 0x7f;
  const cert = await X509CertificateGenerator.create({
    serialNumber: serial.toString("hex"),
    subject: `CN=${host}`,
    issuer: ca.subject,
    notBefore: new Date(Date.now() - 30000),
    notAfter: expiresAt,
    publicKey: csr.publicKey,
    signingKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      new ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.2"], true),
      new SubjectAlternativeNameExtension([
        { type: "url", value: `urn:bunker:tenant:${tenant}:host:${host}` },
      ]),
    ],
  });
  const certificate = cert.toString("pem");
  const fingerprint = new NodeCertificate(certificate).fingerprint256
    .replaceAll(":", "")
    .toLowerCase();
  return {
    certificate,
    trustChain: certPem,
    fingerprint,
    serial: cert.serialNumber,
    expiresAt: cert.notAfter.toISOString(),
  };
}
