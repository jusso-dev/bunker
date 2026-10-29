import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { destinations } from "./config";
import { alert } from "../lib/schemas";
import { ApiError } from "../lib/security";

export async function enqueueAlert(
  db: PoolClient,
  tenantId: string,
  hostId: string,
  alertId: string,
) {
  const policy = await db.query(
    "SELECT body FROM policies WHERE tenant_id=$1 AND (host_id=$2 OR host_id IS NULL) ORDER BY host_id NULLS LAST LIMIT 1",
    [tenantId, hostId],
  );
  if (!policy.rows[0]?.body.channels.includes("webhook")) return;
  const destination = destinations().find((d) => d.tenantId === tenantId);
  if (!destination)
    throw new ApiError(503, "Webhook destination is not provisioned");
  const result = await db.query(
    "SELECT body,created_at FROM alerts WHERE tenant_id=$1 AND host_id=$2 AND id=$3",
    [tenantId, hostId, alertId],
  );
  const row = result.rows[0];
  // Strict allowlist: no host labels, file paths, credentials, digests, or customer text.
  const metadata = alert.omit({ eventId: true }).parse({
    type: row.body.type,
    severity: row.body.severity,
    snapshotId: row.body.snapshotId,
    count: row.body.count,
  });
  const id = randomUUID();
  const payload = {
    version: 1,
    deliveryId: id,
    tenantId,
    hostId,
    alertId,
    occurredAt: row.created_at.toISOString(),
    ...metadata,
  };
  await db.query(
    "INSERT INTO notification_outbox(id,tenant_id,alert_id,destination_id,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,alert_id) DO NOTHING",
    [id, tenantId, alertId, destination.id, payload],
  );
}
