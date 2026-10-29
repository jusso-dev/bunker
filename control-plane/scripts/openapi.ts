import { writeFile } from "node:fs/promises";
import { z } from "zod";
import * as requests from "../src/lib/schemas";
import * as responses from "../src/lib/responses";
const schemas: Record<string, unknown> = {};
for (const [name, schema] of Object.entries({ ...requests, ...responses })) {
  if (schema instanceof z.ZodType) {
    const json = z.toJSONSchema(schema);
    delete json.$schema;
    schemas[name] = json;
  }
}
type Operation = {
  responses: Record<string, unknown>;
  parameters: unknown[];
  [key: string]: unknown;
};
const paths: Record<string, Record<string, Operation>> = {};
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
function route(
  path: string,
  method: "get" | "post",
  summary: string,
  response: keyof typeof responses,
  options: {
    request?: keyof typeof requests;
    mode?: "human" | "host" | "public" | "either";
    status?: 200 | 201;
    before?: boolean;
    pagination?: boolean;
  } = {},
) {
  const {
    request,
    mode = "human",
    status = 200,
    before = false,
    pagination = false,
  } = options;
  const parameters: unknown[] = [...path.matchAll(/\{(\w+)\}/g)].map((m) => ({
    name: m[1],
    in: "path",
    required: true,
    schema:
      m[1] === "provider"
        ? { type: "string", pattern: "^[a-z][a-z0-9-]{0,39}$" }
        : { type: "string", format: "uuid" },
  }));
  if (
    method === "post" &&
    (mode === "human" ||
      path === "/auth/login" ||
      path === "/auth/logout" ||
      path === "/auth/recovery" ||
      path.endsWith("/start"))
  )
    parameters.push({
      name: "Origin",
      in: "header",
      required: true,
      schema: { type: "string", format: "uri" },
    });
  if (before)
    parameters.push({
      name: "before",
      in: "query",
      required: false,
      description:
        "Legacy exclusive timestamp filter. Prefer cursor for lossless equal-timestamp boundaries; cannot be combined with cursor.",
      schema: { type: "string", format: "date-time" },
    });
  if (pagination)
    parameters.push(
      {
        name: "cursor",
        in: "query",
        required: false,
        description:
          "Opaque X-Next-Cursor from the previous page of the same collection, tenant and actor. Stable descending timestamp + ID keyset; preserves PostgreSQL microseconds. Do not construct or edit.",
        schema: { type: "string", maxLength: 2048 },
      },
      {
        name: "limit",
        in: "query",
        required: false,
        schema: { type: "integer", minimum: 1, maximum: 200, default: 200 },
      },
    );
  const operationResponses: Record<string, unknown> = {};
  for (const code of [
    String(status),
    "400",
    "401",
    "403",
    "404",
    "408",
    "409",
    "413",
    "415",
    "429",
    "501",
    "503",
  ])
    operationResponses[code] = {
      description:
        code === String(status)
          ? "Successful response"
          : "Request rejected; inspect error",
      content: {
        "application/json": {
          schema:
            code === String(status)
              ? ref(response)
              : {
                  type: "object",
                  required: ["error"],
                  properties: {
                    error: { type: "string" },
                    issues: {
                      type: "array",
                      items: {
                        type: "object",
                        required: ["path", "message"],
                        properties: {
                          path: {
                            type: "array",
                            items: { type: ["string", "number"] },
                          },
                          message: { type: "string" },
                        },
                      },
                    },
                  },
                },
        },
      },
    };
  if (pagination)
    (operationResponses[String(status)] as Record<string, unknown>).headers = {
      "X-Next-Cursor": {
        description:
          "Present only when more rows exist. Supply as cursor on the next request. Response bodies remain arrays (or the existing /me object).",
        schema: { type: "string" },
      },
    };
  (paths[path] ??= {})[method] = {
    operationId: method + path.replace(/[{}]/g, "").replaceAll("/", "_"),
    summary,
    parameters,
    security:
      mode === "public"
        ? []
        : mode === "either"
          ? [{ humanSession: [] }, { hostMtls: [] }, { hostBearer: [] }]
          : mode === "host"
            ? [{ hostMtls: [] }, { hostBearer: [] }]
            : [{ humanSession: [] }],
    ...(request
      ? {
          requestBody: {
            required: true,
            content: { "application/json": { schema: ref(request) } },
          },
        }
      : {}),
    responses: operationResponses,
  };
}
route(
  "/auth/login",
  "post",
  "Create an 8 hour independent human session",
  "okResponse",
  { request: "login", mode: "public" },
);
route(
  "/auth/logout",
  "post",
  "Revoke current session and clear its cookie, even if expired or absent; requires Origin",
  "okResponse",
  { mode: "public" },
);
route(
  "/me",
  "get",
  "List only tenants the signed-in human can access",
  "meResponse",
  { pagination: true, before: true },
);
route(
  "/enroll",
  "post",
  "Exchange one-use enrollment token and signed CSR for a tenant/host-bound certificate; CSR required in production",
  "enrollResponse",
  { request: "enroll", mode: "public", status: 201 },
);
route(
  "/auth/providers",
  "get",
  "List configured identity providers",
  "providersResponse",
  { mode: "public" },
);
route(
  "/auth/federated/{provider}/start",
  "post",
  "Start browser-bound state and PKCE sign-in; requires matching Origin",
  "federatedStartResponse",
  { mode: "public" },
);
route(
  "/auth/federated/{provider}/callback",
  "get",
  "Consume one-time login flow and create session for explicitly linked subject",
  "okResponse",
  { mode: "public" },
);
const callback = paths["/auth/federated/{provider}/callback"].get;
delete callback.responses["200"];
callback.responses["303"] = {
  description:
    "Verified linked identity; sets HttpOnly Secure session and redirects to configured origin",
  headers: {
    Location: { schema: { type: "string", format: "uri" } },
    "Set-Cookie": { schema: { type: "string" } },
  },
};
callback.parameters.push(
  { name: "state", in: "query", required: true, schema: { type: "string" } },
  { name: "code", in: "query", required: false, schema: { type: "string" } },
  {
    name: "bunker_login",
    in: "cookie",
    required: true,
    schema: { type: "string" },
  },
);
route(
  "/auth/password",
  "post",
  "Change existing local password after verifying current password; revoke all sessions including current",
  "okResponse",
  { request: "passwordChange" },
);
route(
  "/auth/recovery",
  "post",
  "Consume an operator-issued one-use local recovery token within 15 minutes; revoke all sessions; never modifies federation links",
  "okResponse",
  { request: "passwordRecovery", mode: "public" },
);
route(
  "/auth/sessions",
  "get",
  "List own active sessions using non-credential management handles; never returns authentication tokens or hashes",
  "sessionsResponse",
  { pagination: true, before: true },
);
route(
  "/auth/sessions/{id}/revoke",
  "post",
  "Revoke one of the signed-in user's own sessions; handles are scoped to the user",
  "okResponse",
);
route(
  "/auth/sessions/revoke-others",
  "post",
  "Revoke all other sessions of the signed-in user",
  "okResponse",
);
const base = "/tenants/{tenantId}";
for (const [resource, request, response] of [
  ["tenants", "tenant", "idResponse"],
  ["members", "member", "idResponse"],
  ["enrollments", "enrollment", "enrollmentResponse"],
  ["policies", "policy", "policyResponse"],
] as const)
  route(
    `${base}/${resource}`,
    "post",
    `Create or update ${resource}`,
    response,
    { request, status: 201 },
  );
for (const [resource, response] of [
  ["hosts", "hostsResponse"],
  ["members", "membersResponse"],
  ["policies", "policiesResponse"],
  ["snapshots", "snapshotsResponse"],
  ["restores", "restoresResponse"],
  ["alerts", "alertsResponse"],
  ["evidence", "evidenceResponse"],
  ["audit", "auditResponse"],
] as const) {
  const before = true;
  route(
    `${base}/${resource}`,
    "get",
    `List ${resource}; bounded timestamp + ID pagination${resource === "members" ? "; tenant admin only" : ""}`,
    response,
    {
      before,
      pagination: true,
      mode: ["hosts", "audit", "members"].includes(resource)
        ? "human"
        : "either",
    },
  );
}
paths[`${base}/policies`].get.description =
  "Human lists use updated_at + id pagination. An authenticated host still receives only its single effective host override or tenant-default policy, without pagination.";
paths["/me"].get.description =
  "Tenants are bounded to 200 per page, ordered by tenant creation time and ID descending. Follow X-Next-Cursor to reach all memberships. localPassword indicates whether an existing local credential can be changed; it is not identity-provider reset authority.";
for (const [resource, request, response] of [
  ["snapshots", "snapshot", "idResponse"],
  ["restores", "restore", "restoreCreatedResponse"],
  ["alerts", "alert", "idResponse"],
  ["evidence", "evidence", "idResponse"],
] as const)
  route(
    `${base}/${resource}`,
    "post",
    `Report ${resource} for authenticated host only`,
    response,
    { request, mode: "host", status: 201 },
  );
paths[`${base}/evidence`].post.description =
  "Accept legacy booleans or explicit passed/failed/not_run probes with bounded reason codes. Identical evidence ID, tenant, host and canonical JSON body retries return the same 201 acknowledgement without new audit, alert or notification records. Conflicting content or ownership returns 409. Only failed probes raise restore-test-failed alerts. Optional file-content scope excludes Git refs/config restoration.";

route(
  `${base}/restores/{id}/decision`,
  "post",
  "Human admin/approver approves or denies digest-bound request",
  "decisionResponse",
  { request: "decision" },
);
route(
  `${base}/restores/{id}/claim`,
  "post",
  "Atomically consume live approval; retries cannot execute again",
  "claimResponse",
  { request: "claim", mode: "host" },
);
route(
  `${base}/restores/{id}/complete`,
  "post",
  "Report completion only after claim",
  "completionResponse",
  { request: "completion", mode: "host" },
);
route(
  `${base}/members/{id}/revoke`,
  "post",
  "Tenant admin removes membership immediately; serialized last-admin protection; global identity and other tenants are unaffected",
  "idResponse",
);
route(
  `${base}/hosts/{id}/revoke`,
  "post",
  "Admin revokes host credential",
  "idResponse",
);
route(
  `${base}/alerts/{id}/acknowledge`,
  "post",
  "Human admin/operator acknowledges alert",
  "idResponse",
);
route(
  `${base}/notifications`,
  "get",
  "List webhook deliveries with bounded pagination; human access only; no destination or secret details",
  "notificationsResponse",
  { pagination: true, before: true },
);
route(
  `${base}/export`,
  "get",
  "Export up to 10000 recent records per evidence category; metadata is not certification",
  "exportResponse",
);
for (const [resource, response] of [
  ["snapshots", "snapshotsResponse"],
  ["restores", "restoresResponse"],
  ["alerts", "alertsResponse"],
  ["evidence", "evidenceResponse"],
] as const)
  route(
    `${base}/${resource}/{id}`,
    "get",
    `Read ${resource} by ID (returns empty or single-row array)`,
    response,
    { mode: "either", before: true, pagination: true },
  );
route(
  `${base}/hosts/{id}/certificate`,
  "post",
  "Issue a replacement certificate using a new CSR; requires this host's currently valid mTLS identity",
  "enrollResponse",
  { request: "certificateRequest", mode: "host", status: 201 },
);
const document = {
  openapi: "3.1.0",
  info: {
    title: "Bunker metadata control plane",
    version: "0.1.0",
    description:
      "No content or key ingestion endpoints. Human sessions and host credentials are separate. Production hosts require certificates on the strict mTLS gateway listener. The separate public HTTPS listener serves enrollment and humans. Development bearer transport requires explicit trusted-loopback mode. Human mutation requests, including login, require Origin matching BUNKER_ORIGIN. Poll policies and restores every 30 seconds.",
  },
  servers: [{ url: "/api" }],
  paths,
  components: {
    schemas,
    securitySchemes: {
      humanSession: { type: "apiKey", in: "cookie", name: "bunker_session" },
      hostMtls: {
        type: "mutualTLS",
        description:
          "Issued tenant/host certificate, checked for revocation on every request. Connect to BUNKER_HOST_ORIGIN. Never send gateway proof headers; gateway creates those internally.",
      },
      hostBearer: {
        type: "http",
        scheme: "bearer",
        description:
          "Development-only enrolled host credential. Never grants human actions.",
      },
    },
  },
};
await writeFile(
  new URL("../../shared/openapi.yaml", import.meta.url),
  JSON.stringify(document, null, 2) + "\n",
);
