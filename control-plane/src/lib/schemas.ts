import { z } from "zod";
export const uuid = z.uuid();
export const hash = z.string().regex(/^[a-f0-9]{64}$/);
const label = z
  .string()
  .trim()
  .min(1)
  .max(100)
  .regex(/^[\p{L}\p{N} _@.()+-]+$/u);
export const role = z.enum(["admin", "operator", "viewer", "approver"]);
export const login = z.strictObject({
  email: z.email().max(254),
  password: z.string().min(1).max(256),
});
export const enrollment = z.strictObject({ name: label });
export const enroll = z.strictObject({
  token: z.string().min(32).max(128),
  csr: z.string().min(100).max(16384).optional(),
});
export const member = z.strictObject({
  email: z.email().max(254),
  password: z.string().min(14).max(256).optional(),
  role,
});
export const tenant = z.strictObject({ name: label });
export const policy = z.strictObject({
  name: label,
  hostId: uuid.nullable(),
  intervalMinutes: z.number().int().min(5).max(10080),
  endOfSession: z.boolean(),
  retentionDays: z.number().int().min(1).max(3650),
  exclusions: z.array(z.string().min(1).max(256)).max(100),
  sizeCapBytes: z.number().int().positive().max(1e12),
  immutable: z.boolean(),
  drCopy: z.boolean(),
  residency: z.enum(["AU", "unrestricted"]),
  storage: z.enum(["local", "s3", "r2", "azure", "gdrive", "onedrive"]),
  storageRef: label,
  keyRef: label,
  massDeleteThreshold: z.number().int().positive().max(1000000),
  missedBackupMinutes: z.number().int().min(10).max(43200),
  restoreTestIntervalHours: z.number().int().min(1).max(8760),
  channels: z
    .array(z.enum(["ui", "webhook"]))
    .min(1)
    .max(2)
    .refine(
      (channels) =>
        channels.includes("ui") && new Set(channels).size === channels.length,
      "UI delivery is required; channels must be unique",
    )
    .meta({ uniqueItems: true, contains: { const: "ui" } }),
});
export const snapshot = z.strictObject({
  id: uuid,
  agent: z.enum(["claude-code", "cursor", "codex", "copilot", "kiro"]),
  sessionId: uuid,
  manifestDigest: hash,
  fileCount: z.number().int().nonnegative().max(10000000),
  totalBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  capturedAt: z.iso.datetime(),
  status: z.enum(["succeeded", "failed"]),
});
export const change = z
  .strictObject({
    fileId: hash,
    action: z.enum(["create", "replace", "delete"]),
    beforeDigest: hash.nullable(),
    afterDigest: hash.nullable(),
    bytes: z.number().int().nonnegative().max(1e12),
  })
  .superRefine((v, c) => {
    if (
      (v.action === "create" &&
        (v.beforeDigest !== null || v.afterDigest === null)) ||
      (v.action === "replace" &&
        (v.beforeDigest === null || v.afterDigest === null)) ||
      (v.action === "delete" &&
        (v.beforeDigest === null || v.afterDigest !== null))
    )
      c.addIssue({
        code: "custom",
        message: "Digest presence must match the change action",
      });
  });
export const restore = z
  .strictObject({
    snapshotId: uuid,
    kind: z.enum(["file", "session", "workspace"]),
    manifestDigest: hash,
    diffDigest: hash,
    changes: z.array(change).min(1).max(1000),
  })
  .superRefine((v, c) => {
    if (v.kind === "file" && v.changes.length !== 1)
      c.addIssue({
        code: "custom",
        message: "File restore requires exactly one change",
      });
    if (new Set(v.changes.map((x) => x.fileId)).size !== v.changes.length)
      c.addIssue({ code: "custom", message: "Duplicate file IDs" });
  });
export const decision = z.strictObject({
  decision: z.enum(["approve", "deny"]),
  diffDigest: hash,
  reviewedLocalDiff: z.boolean(),
});
export const claim = z.strictObject({ diffDigest: hash });
export const completion = z.strictObject({
  status: z.enum(["succeeded", "failed"]),
  diffDigest: hash,
});
export const alert = z.strictObject({
  eventId: uuid,
  type: z.enum([
    "mass-delete",
    "force-push",
    "history-rewrite",
    "mcp-change",
    "skill-change",
    "backup-failed",
    "backup-missed",
    "restore-test-failed",
  ]),
  severity: z.enum(["warning", "critical"]),
  snapshotId: uuid.nullable(),
  count: z.number().int().nonnegative().max(10000000),
});
export const probeFailureReason = z.enum([
  "restore_failed",
  "timeout",
  "output_limit",
  "process_failed",
  "invalid_boot_response",
  "invalid_mcp_handshake",
  "cleanup_failed",
]);
export const probeSkipReason = z.enum([
  "not_configured",
  "runtime_unavailable",
  "network_unavailable",
  "credentials_unavailable",
  "unsupported_snapshot",
  "resource_limit",
]);
// Strict disjoint variants reject contradictory legacy booleans and success reasons.
// Legacy stored rows and older host writers remain readable without a migration.
function probe<T extends z.ZodRawShape>(identity: T) {
  return z.union([
    z.strictObject({ ...identity, outcome: z.literal("passed") }),
    z.strictObject({
      ...identity,
      outcome: z.literal("failed"),
      reasonCode: probeFailureReason,
    }),
    z.strictObject({
      ...identity,
      outcome: z.literal("not_run"),
      reasonCode: probeSkipReason,
    }),
    z.strictObject({ ...identity, passed: z.boolean() }),
  ]);
}
export const evidence = z.strictObject({
  id: uuid,
  snapshotId: uuid,
  finishedAt: z.iso.datetime(),
  sandbox: z.enum(["container", "temp-directory"]),
  scope: z.literal("file-content").optional(),
  agents: z
    .array(
      probe({
        agent: z.enum(["claude-code", "cursor", "codex", "copilot", "kiro"]),
      }),
    )
    .min(1)
    .max(5),
  mcps: z.array(probe({ name: label })).max(100),
});
export type Policy = z.infer<typeof policy>;

export const certificateRequest = z.strictObject({
  csr: z.string().min(100).max(16384),
});

export const passwordChange = z.strictObject({
  currentPassword: z.string().min(1).max(256),
  newPassword: z.string().min(14).max(256),
});
export const passwordRecovery = z.strictObject({
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  newPassword: z.string().min(14).max(256),
});
