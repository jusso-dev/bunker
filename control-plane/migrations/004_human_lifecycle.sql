-- Public management handles are unrelated to the authentication token/hash.
ALTER TABLE sessions ADD COLUMN handle uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;
ALTER TABLE sessions ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE tenants ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE memberships ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE TABLE password_recoveries (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  CHECK(expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);
CREATE INDEX recoveries_user ON password_recoveries(user_id);
CREATE INDEX sessions_user_page ON sessions(user_id,created_at DESC,handle DESC);
CREATE INDEX memberships_page ON memberships(tenant_id,created_at DESC,user_id DESC);
CREATE INDEX hosts_page ON hosts(tenant_id,created_at DESC,id DESC);
CREATE INDEX policies_page ON policies(tenant_id,updated_at DESC,id DESC);
CREATE INDEX snapshots_page ON snapshots(tenant_id,created_at DESC,id DESC);
CREATE INDEX restores_page ON restores(tenant_id,created_at DESC,id DESC);
CREATE INDEX alerts_page ON alerts(tenant_id,created_at DESC,id DESC);
CREATE INDEX evidence_page ON evidence(tenant_id,created_at DESC,id DESC);
CREATE INDEX audit_page ON audit(tenant_id,created_at DESC,id DESC);
INSERT INTO schema_migrations VALUES(4);
