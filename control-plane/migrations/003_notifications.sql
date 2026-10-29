-- A delivery belongs to exactly one tenant/alert. Its ID is the receiver's idempotency key.
ALTER TABLE alerts ADD CONSTRAINT alerts_tenant_id_id_key UNIQUE (tenant_id,id);
CREATE TABLE notification_outbox (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  alert_id uuid NOT NULL,
  destination_id text NOT NULL,
  payload jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivering','retrying','delivered','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token uuid,
  lease_until timestamptz,
  last_error text CHECK (last_error IN ('configuration','network','timeout','response-too-large','http-retryable','http-rejected','lease-expired')),
  last_status integer,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  FOREIGN KEY (tenant_id,alert_id) REFERENCES alerts(tenant_id,id),
  UNIQUE (tenant_id,alert_id)
);
CREATE INDEX notification_due ON notification_outbox(available_at,created_at) WHERE state IN ('pending','retrying','delivering');
CREATE INDEX notification_tenant ON notification_outbox(tenant_id,created_at DESC);
INSERT INTO schema_migrations(version) VALUES(3);
