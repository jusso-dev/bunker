# Bunker control plane

Next.js 16 / TypeScript / PostgreSQL metadata API and browser UI. This is a functional development core, **not production acceptance**. Production identity now has a strict TLS gateway, CSR certificate issuance/renewal, and configured OIDC/GitHub OAuth; live providers and deployment are not yet validated. See [IMPLEMENTATION.md](IMPLEMENTATION.md) for issue-by-issue status and [INTEGRATION.md](INTEGRATION.md) for the daemon contract.

## Run locally

Requires Node 22+, pnpm 10, PostgreSQL 15+ (tested with the locally installed PostgreSQL), and a dedicated empty database.

1. Run `pnpm install` from the repository root.
2. Set `DATABASE_URL` to your dedicated PostgreSQL connection string using your secret manager. Set `BUNKER_ORIGIN=http://localhost:3000`. Environment variables must be set in the invoking shell: standalone `tsx` scripts do not load Next.js `.env.local` files automatically.
3. Run `pnpm --filter @bunker/control-plane db:migrate`.
4. Run `pnpm --filter @bunker/control-plane bootstrap you@example.com 'Your organization' 'Your tenant'` with a 14–256 character initial password on stdin. Do not supply passwords as arguments or record them in shell history. For interactive use, read a password without echo in your shell and pipe that value to the command. Bootstrap refuses to run after any user exists.
5. Run `pnpm --filter @bunker/control-plane dev --hostname 127.0.0.1`. Open `http://localhost:3000` and sign in.
6. For **trusted local development only**, set `BUNKER_ALLOW_INSECURE_LOOPBACK=true` before starting. Bind the server to loopback. Do not place this mode behind a reverse proxy, expose it on a network, or share the machine with untrusted workloads. The HTTP URL check alone does not establish the network peer's identity.

For a production UI build: `pnpm build` then `pnpm --filter @bunker/control-plane start --hostname 127.0.0.1`. Use the TLS gateway and configured HTTPS origins. Production host API requires the separate mTLS gateway described below. The production container runs both processes; see [deployment configuration](../docs/user/deployment.md).

## Checks

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm --filter @bunker/control-plane test:integration
pnpm --filter @bunker/control-plane test:production # includes a built Next server behind actual TLS
pnpm build
pnpm --filter @bunker/control-plane generate:api
```

`test:integration` requires `initdb` and `pg_ctl`. It creates an isolated temporary PostgreSQL instance with a private Unix socket and **no TCP listener**, runs the real migration and HTTP-handler tests, and removes the instance on exit. It never uses the operator's `DATABASE_URL`. `pnpm test` runs fast security/schema tests; integration is a separate explicit check.

The OpenAPI document is JSON-formatted YAML 1.2. Regenerate it and its TypeScript types after changing schemas or routes. `src/lib/client.ts` wraps `openapi-fetch` using the generated contract. The UI uses its own fetch helper for error messages and data refresh.

## Production identity configuration

See [the protocol](INTEGRATION.md) and [ADR 0003](../docs/adr/0003-production-identity.md). Run migrations before starting either process. Bind Next to `127.0.0.1:3000` (`next start --hostname 127.0.0.1`); run `pnpm --filter @bunker/control-plane gateway` in the same network namespace. Expose the two gateway listeners, never the Next port. The host listener must receive the original client TLS handshake; any load balancer in front must use TCP pass-through, not terminate client mTLS. The configured server TLS certificate must cover both advertised hostnames. The container and Compose/Helm templates implement this shared-namespace arrangement; see [deployment configuration](../docs/user/deployment.md).

Use `.env.example` for file-reference variable names. Identity files must be absolute paths to regular, non-symlink files, owned by the process UID or root and inaccessible to group/other (0600). Files are bounded to 64 KiB. Projected secret-volume symlinks must be materialized as protected regular files before startup. Global `NODE_TLS_REJECT_UNAUTHORIZED=0` is rejected. The gateway secret is exactly 32 random binary bytes. The CA key is unencrypted PEM PKCS#8/SEC1 P-256, with a matching valid CA certificate containing CA/keyCertSign usages. Supply the secret through protected provisioning; never put its contents into env variables, source, logs, UI, or tickets. The gateway needs the server TLS key/chain, host CA certificate and gateway secret, but does not need the signing CA key or provider secrets. Next needs the signing CA key/certificate and gateway secret. Use protected read-only source mounts. The combined container shares one UID/security boundary; deployments requiring separate gateway/signing-key OS identities need additional isolation. For multi-process deployments, all Next instances must use the same PostgreSQL replay state. Certificate renewal is a host responsibility.

`BUNKER_IDENTITY_PROVIDERS_FILE` points to a protected JSON array. For example, with placeholders replaced by your registered application details:

```json
[
  {"id":"entra","name":"Microsoft Entra","kind":"oidc","issuer":"https://login.microsoftonline.com/TENANT_UUID/v2.0","clientId":"APPLICATION_ID","clientSecretFile":"/run/bunker/entra.secret","redirectUri":"https://console.example.test/api/auth/federated/entra/callback"},
  {"id":"google","name":"Google","kind":"oidc","issuer":"https://accounts.google.com","clientId":"APPLICATION_ID","clientSecretFile":"/run/bunker/google.secret","redirectUri":"https://console.example.test/api/auth/federated/google/callback"},
  {"id":"github","name":"GitHub","kind":"github","issuer":"https://github.com","clientId":"APPLICATION_ID","clientSecretFile":"/run/bunker/github.secret","redirectUri":"https://console.example.test/api/auth/federated/github/callback"}
]
```

Every redirect URI must exactly equal `BUNKER_ORIGIN/api/auth/federated/<id>/callback` and be registered with the provider. OIDC discovery may omit the optional PKCE advertisement (as tenant-pinned Entra does); explicit advertisements must include S256. All requests still require S256 PKCE. OIDC must use RS256 ID tokens, and provide HTTPS discovery/token/JWKS endpoints with exact issuer matching. Entra `common`/`organizations` issuers are not a substitute for a pinned tenant issuer. Provider client secrets are read from separate protected files. GitHub endpoints are fixed; GitHub consumer auth is OAuth, not OIDC. Only explicitly linked subjects can sign in. No live providers or real credentials were accessed during implementation.

Identity dependency versions are pinned in `package.json`; the root `pnpm-lock.yaml` is the canonical workspace lockfile. Use `pnpm install --frozen-lockfile` from the repository root. Independent review and deployment validation remain required before production use.

## External alerts

Signed webhook delivery is opt-in and uses a transactional PostgreSQL outbox with a separate worker. See [operator configuration, delivery contract and deployment wiring](WEBHOOKS.md).
