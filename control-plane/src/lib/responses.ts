import { z } from "zod";
import * as s from "./schemas";

const timestamp = z.iso.datetime({ offset: true });
const scoped = {
  id: s.uuid,
  tenant_id: s.uuid,
  host_id: s.uuid,
  created_at: timestamp,
};
export const okResponse = z.strictObject({ ok: z.literal(true) });
export const idResponse = z.strictObject({ id: s.uuid });
export const meResponse = z.strictObject({
  userId: s.uuid,
  localPassword: z.boolean(),
  tenants: z.array(
    z.strictObject({ id: s.uuid, name: z.string(), role: s.role }),
  ),
  hostTransport: z.enum([
    "development-loopback",
    "disabled-mtls-unimplemented",
    "mtls",
  ]),
});
export const enrollmentResponse = z.strictObject({
  token: z.string(),
  expiresInSeconds: z.literal(600),
});
export const enrollResponse = z.union([
  z.strictObject({
    hostId: s.uuid,
    tenantId: s.uuid,
    token: z.string(),
    transport: z.literal("development-loopback"),
  }),
  z.strictObject({
    hostId: s.uuid,
    tenantId: s.uuid,
    transport: z.literal("mtls"),
    certificate: z.string(),
    trustChain: z.string(),
    expiresAt: timestamp,
  }),
]);
export const policyResponse = z.strictObject({
  id: s.uuid,
  version: z.number().int(),
});
export const hostRow = z.strictObject({
  id: s.uuid,
  name: z.string(),
  created_at: timestamp,
});
export const policyRow = z.strictObject({
  id: s.uuid,
  host_id: s.uuid.nullable().optional(),
  body: s.policy,
  version: z.number().int(),
  updated_at: timestamp,
});
export const snapshotRow = z.strictObject({ ...scoped, body: s.snapshot });
export const restoreRow = z.strictObject({
  ...scoped,
  snapshot_id: s.uuid,
  body: s.restore,
  status: z.enum([
    "pending",
    "approved",
    "denied",
    "expired",
    "executing",
    "succeeded",
    "failed",
  ]),
  decided_by: s.uuid.nullable(),
  expires_at: timestamp,
});
export const alertRow = z.strictObject({
  ...scoped,
  dedupe_key: z.string(),
  body: z.union([s.alert, s.alert.omit({ eventId: true })]),
  occurrences: z.number().int(),
  acknowledged_by: s.uuid.nullable(),
  last_seen_at: timestamp,
});
export const evidenceRow = z.strictObject({
  ...scoped,
  snapshot_id: s.uuid,
  body: s.evidence,
});
export const auditRow = z.strictObject({
  id: z.string().regex(/^\d+$/),
  tenant_id: s.uuid,
  actor: z.string(),
  action: z.string(),
  resource_id: s.uuid.nullable(),
  created_at: timestamp,
});
export const hostsResponse = z.array(hostRow);
export const policiesResponse = z.array(policyRow);
export const snapshotsResponse = z.array(snapshotRow);
export const restoresResponse = z.array(restoreRow);
export const alertsResponse = z.array(alertRow);
export const evidenceResponse = z.array(evidenceRow);
export const auditResponse = z.array(auditRow);
export const restoreCreatedResponse = z.strictObject({
  id: s.uuid,
  status: z.literal("pending"),
});
export const decisionResponse = z.strictObject({
  id: s.uuid,
  status: z.enum(["approved", "denied"]),
});
export const claimResponse = z.strictObject({
  id: s.uuid,
  status: z.literal("executing"),
  diffDigest: s.hash,
  manifestDigest: s.hash,
  expiresAt: timestamp,
});
export const completionResponse = z.strictObject({
  id: s.uuid,
  status: z.enum(["succeeded", "failed"]),
});
export const exportResponse = z.strictObject({
  generatedAt: timestamp,
  tenantId: s.uuid,
  recordLimitPerCategory: z.literal(10000),
  assurance: z.string(),
  snapshots: snapshotsResponse,
  policies: z.array(
    policyRow.extend({ tenant_id: s.uuid, host_id: s.uuid.nullable() }),
  ),
  evidence: evidenceResponse,
  audit: auditResponse,
});

export const providersResponse = z.array(
  z.strictObject({
    id: z.string(),
    name: z.string(),
    kind: z.enum(["oidc", "github"]),
  }),
);
export const federatedStartResponse = z.strictObject({
  authorizationUrl: z.url(),
});

export const notificationRow = z.strictObject({
  id: s.uuid,
  alert_id: s.uuid,
  state: z.enum(["pending", "delivering", "retrying", "delivered", "failed"]),
  attempts: z.number().int().min(0).max(8),
  last_error: z
    .enum([
      "configuration",
      "network",
      "timeout",
      "response-too-large",
      "http-retryable",
      "http-rejected",
      "lease-expired",
    ])
    .nullable(),
  last_status: z.number().int().nullable(),
  created_at: timestamp,
  delivered_at: timestamp.nullable(),
  available_at: timestamp,
});
export const notificationsResponse = z.array(notificationRow);

export const memberRow = z.strictObject({
  id: s.uuid,
  email: z.email(),
  role: s.role,
  created_at: timestamp,
});
export const membersResponse = z.array(memberRow);
export const sessionRow = z.strictObject({
  handle: s.uuid,
  created_at: timestamp,
  expires_at: timestamp,
  current: z.boolean(),
});
export const sessionsResponse = z.array(sessionRow);
