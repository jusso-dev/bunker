ALTER TABLE hosts ADD COLUMN revoked_at timestamptz;
CREATE TABLE host_certificates (
  fingerprint text PRIMARY KEY,
  tenant_id uuid NOT NULL,
  host_id uuid NOT NULL,
  serial text UNIQUE NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  FOREIGN KEY(tenant_id,host_id) REFERENCES hosts(tenant_id,id)
);
CREATE TABLE gateway_nonces(id uuid PRIMARY KEY, expires_at timestamptz NOT NULL);
CREATE INDEX gateway_nonce_expiry ON gateway_nonces(expires_at);
CREATE TABLE external_identities (
  provider text NOT NULL,
  issuer text NOT NULL,
  subject text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id),
  PRIMARY KEY(provider,issuer,subject)
);
CREATE TABLE login_flows (
  state_hash text PRIMARY KEY,
  browser_hash text NOT NULL,
  provider text NOT NULL,
  verifier text NOT NULL,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL
);
INSERT INTO schema_migrations VALUES(2);
