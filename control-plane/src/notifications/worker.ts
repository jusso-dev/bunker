import { randomUUID } from "node:crypto";
import { database, transaction } from "../lib/db";
import { destinations } from "./config";
import { deliver, type DeliveryResult } from "./transport";

export const MAX_ATTEMPTS = 8;
export const LEASE_SECONDS = 60;
export const retrySeconds = (attempt: number) =>
  Math.min(3600, 30 * 2 ** (attempt - 1));
export type Job = {
  id: string;
  tenant_id: string;
  destination_id: string;
  payload: unknown;
  lease_token: string;
  attempts: number;
};
export async function claimDelivery(): Promise<Job | undefined> {
  return transaction(async (db) => {
    // A crash on the final attempt must not leave a permanent delivering row.
    await db.query(
      "UPDATE notification_outbox SET state='failed',last_error='lease-expired',lease_token=NULL,lease_until=NULL WHERE state='delivering' AND lease_until<=clock_timestamp() AND attempts>=$1",
      [MAX_ATTEMPTS],
    );
    const result = await db.query<Job>(
      `WITH next AS (
        SELECT id FROM notification_outbox WHERE attempts<$1 AND
        ((state IN ('pending','retrying') AND available_at<=clock_timestamp()) OR
         (state='delivering' AND lease_until<=clock_timestamp()))
        ORDER BY available_at,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
      ) UPDATE notification_outbox o SET state='delivering',attempts=o.attempts+1,
        lease_token=$2,lease_until=clock_timestamp()+make_interval(secs => $3)
        FROM next WHERE o.id=next.id RETURNING o.*`,
      [MAX_ATTEMPTS, randomUUID(), LEASE_SECONDS],
    );
    return result.rows[0];
  });
}
export async function finishDelivery(
  job: Job,
  result: DeliveryResult,
): Promise<void> {
  const state = result.ok
    ? "delivered"
    : result.retryable && job.attempts < MAX_ATTEMPTS
      ? "retrying"
      : "failed";
  await database().query(
    `UPDATE notification_outbox SET state=$1,last_error=$2,last_status=$3,
      available_at=clock_timestamp()+make_interval(secs => $4),
      delivered_at=CASE WHEN $1='delivered' THEN clock_timestamp() ELSE NULL END,
      lease_token=NULL,lease_until=NULL
      WHERE id=$5 AND tenant_id=$6 AND lease_token=$7 AND state='delivering'`,
    [
      state,
      result.error ?? null,
      result.status ?? null,
      retrySeconds(job.attempts),
      job.id,
      job.tenant_id,
      job.lease_token,
    ],
  );
}
export async function runOnce(): Promise<boolean> {
  const job = await claimDelivery();
  if (!job) return false;
  let result: DeliveryResult;
  try {
    const destination = destinations().find(
      (d) => d.tenantId === job.tenant_id && d.id === job.destination_id,
    );
    result = destination
      ? await deliver(destination, job.id, job.payload)
      : { ok: false, retryable: true, error: "configuration" };
  } catch {
    result = { ok: false, retryable: true, error: "configuration" };
  }
  await finishDelivery(job, result);
  return true;
}
