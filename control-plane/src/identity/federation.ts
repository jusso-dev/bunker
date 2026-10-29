import * as oauth from "oauth4webapi";
import { z } from "zod";
import { protectedFile } from "./files";
import { transaction } from "../lib/db";
import { ApiError, digest, token } from "../lib/security";
const providerSchema = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9-]{0,39}$/),
  name: z.string().min(1).max(80),
  kind: z.enum(["oidc", "github"]),
  issuer: z.url(),
  clientId: z.string().min(1).max(256),
  clientSecretFile: z.string(),
  redirectUri: z.url(),
});
export type Provider = z.infer<typeof providerSchema>;
export function providers(): Provider[] {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0")
    throw new ApiError(503, "Global TLS verification bypass is forbidden");
  if (!process.env.BUNKER_IDENTITY_PROVIDERS_FILE) return [];
  try {
    const list = z
      .array(providerSchema)
      .max(10)
      .parse(
        JSON.parse(
          protectedFile(process.env.BUNKER_IDENTITY_PROVIDERS_FILE).toString(),
        ),
      );
    if (new Set(list.map((p) => p.id)).size !== list.length) throw new Error();
    for (const p of list) {
      const issuer = new URL(p.issuer);
      if (
        issuer.protocol !== "https:" ||
        issuer.username ||
        issuer.password ||
        issuer.search ||
        issuer.hash ||
        p.redirectUri !==
          `${process.env.BUNKER_ORIGIN}/api/auth/federated/${p.id}/callback` ||
        new URL(p.redirectUri).protocol !== "https:" ||
        (p.kind === "github" && p.issuer !== "https://github.com")
      )
        throw new Error();
    }
    return list;
  } catch {
    throw new ApiError(503, "Identity provider configuration is invalid");
  }
}
const provider = (id: string) => {
  const p = providers().find((p) => p.id === id);
  if (!p) throw new ApiError(404, "Identity provider not configured");
  return p;
};
// No insecure HTTP mode, redirect following, or provider-specific TLS bypasses.
const strictFetch: typeof fetch = (input, init) =>
  fetch(input, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(10000),
  });
async function metadata(p: Provider): Promise<oauth.AuthorizationServer> {
  if (p.kind === "github")
    return {
      issuer: p.issuer,
      authorization_endpoint: "https://github.com/login/oauth/authorize",
      token_endpoint: "https://github.com/login/oauth/access_token",
    };
  const as = await oauth.processDiscoveryResponse(
    new URL(p.issuer),
    await oauth.discoveryRequest(new URL(p.issuer), {
      [oauth.customFetch]: strictFetch,
    }),
  );
  for (const endpoint of [
    as.authorization_endpoint,
    as.token_endpoint,
    as.jwks_uri,
  ]) {
    if (!endpoint) throw new ApiError(503, "Incomplete OIDC metadata");
    const url = new URL(endpoint);
    if (url.protocol !== "https:" || url.username || url.password || url.hash)
      throw new ApiError(503, "Unsafe OIDC endpoint");
  }
  // The discovery advertisement is optional (including tenant-pinned Entra).
  // Always send S256 below; only an explicit incompatible advertisement is fatal.
  if (
    as.code_challenge_methods_supported !== undefined &&
    (!Array.isArray(as.code_challenge_methods_supported) ||
      !as.code_challenge_methods_supported.includes("S256"))
  )
    throw new ApiError(503, "Provider must support PKCE S256");
  return as;
}
function flowCookie(value: string, maxAge: number) {
  return `bunker_login=${value}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=${maxAge}`;
}
export async function startFederated(id: string) {
  const p = provider(id),
    as = await metadata(p),
    state = oauth.generateRandomState(),
    nonce = oauth.generateRandomNonce(),
    verifier = oauth.generateRandomCodeVerifier(),
    browser = token();
  const url = new URL(as.authorization_endpoint!);
  url.search = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    response_type: "code",
    scope: p.kind === "oidc" ? "openid profile" : "read:user",
    state,
    code_challenge: await oauth.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    ...(p.kind === "oidc" ? { nonce } : {}),
  }).toString();
  await transaction(async (db) => {
    await db.query(
      "DELETE FROM login_flows WHERE expires_at<clock_timestamp()",
    );
    await db.query(
      "INSERT INTO login_flows VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '5 minutes')",
      [digest(state), digest(browser), id, verifier, nonce],
    );
  });
  return Response.json(
    { authorizationUrl: url.toString() },
    {
      headers: {
        "cache-control": "no-store",
        "set-cookie": flowCookie(browser, 300),
      },
    },
  );
}
export async function finishFederated(id: string, request: Request) {
  const p = provider(id),
    url = new URL(request.url),
    state = url.searchParams.get("state"),
    cookie = request.headers
      .get("cookie")
      ?.split(";")
      .map((x) => x.trim())
      .find((x) => x.startsWith("bunker_login="))
      ?.slice(13);
  if (
    !state ||
    state.length > 256 ||
    !cookie ||
    cookie.length > 128 ||
    url.searchParams.getAll("state").length !== 1
  )
    throw new ApiError(401, "Invalid login flow");
  // Commit consumption before contacting the provider, including failures and concurrent callbacks.
  const flow = await transaction(async (db) => {
    await db.query(
      "SELECT state_hash FROM login_flows WHERE state_hash=$1 FOR UPDATE",
      [digest(state)],
    );
    const result = await db.query(
      "DELETE FROM login_flows WHERE state_hash=$1 AND browser_hash=$2 AND provider=$3 AND expires_at>clock_timestamp() RETURNING verifier,nonce",
      [digest(state), digest(cookie), id],
    );
    if (!result.rowCount)
      throw new ApiError(401, "Expired or consumed login flow");
    return result.rows[0] as { verifier: string; nonce: string };
  });
  let subject: string;
  try {
    const as = await metadata(p),
      client: oauth.Client = {
        client_id: p.clientId,
        id_token_signed_response_alg: "RS256",
      };
    const params = oauth.validateAuthResponse(as, client, url, state);
    const secret = protectedFile(p.clientSecretFile).toString().trim();
    if (!secret || secret.length > 4096)
      throw new ApiError(503, "Invalid provider credential file");
    const response = await oauth.authorizationCodeGrantRequest(
      as,
      client,
      oauth.ClientSecretPost(secret),
      params,
      p.redirectUri,
      flow.verifier,
      {
        [oauth.customFetch]: strictFetch,
        headers: { accept: "application/json" },
      },
    );
    const tokens = await oauth.processAuthorizationCodeResponse(
      as,
      client,
      response,
      p.kind === "oidc"
        ? { expectedNonce: flow.nonce, requireIdToken: true }
        : {},
    );
    if (p.kind === "oidc") {
      await oauth.validateApplicationLevelSignature(as, response, {
        [oauth.customFetch]: strictFetch,
      });
      subject = oauth.getValidatedIdTokenClaims(tokens)!.sub;
    } else {
      const userResponse = await strictFetch("https://api.github.com/user", {
        headers: {
          authorization: `Bearer ${tokens.access_token}`,
          accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });
      if (!userResponse.ok) throw new Error();
      const user = z
        .object({
          id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        })
        .parse(await userResponse.json());
      subject = String(user.id); // Stable GitHub numeric ID, never login name/email or an invented OIDC claim.
    }
    if (!subject || subject.length > 512) throw new Error();
  } catch (e) {
    if (e instanceof ApiError && e.status === 503) throw e;
    throw new ApiError(401, "Provider authentication failed");
  }
  const session = token();
  await transaction(async (db) => {
    const identity = await db.query(
      "SELECT user_id FROM external_identities WHERE provider=$1 AND issuer=$2 AND subject=$3",
      [p.id, p.issuer, subject],
    );
    if (!identity.rowCount)
      throw new ApiError(403, "Identity is not linked by an administrator");
    // Serialize with instance-admin unlink; recheck after the lock so a callback
    // cannot create a surviving session from a binding removed during its exchange.
    await db.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [
      identity.rows[0].user_id,
    ]);
    const stillLinked = await db.query(
      "SELECT 1 FROM external_identities WHERE provider=$1 AND issuer=$2 AND subject=$3 AND user_id=$4",
      [p.id, p.issuer, subject, identity.rows[0].user_id],
    );
    if (!stillLinked.rowCount)
      throw new ApiError(403, "Identity is no longer linked");
    await db.query(
      "INSERT INTO sessions VALUES($1,$2,clock_timestamp()+interval '8 hours')",
      [digest(session), identity.rows[0].user_id],
    );
  });
  const headers = new Headers({
    location: process.env.BUNKER_ORIGIN!,
    "cache-control": "no-store",
  });
  headers.append(
    "set-cookie",
    `bunker_session=${session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`,
  );
  headers.append("set-cookie", flowCookie("", 0));
  return new Response(null, { status: 303, headers });
}
