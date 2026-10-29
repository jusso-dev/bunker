# Container, Compose and Helm deployment

The control-plane image starts the production TLS gateway and Next in one container/network namespace. Next is hard-bound to `127.0.0.1:3000`. Only the public HTTPS listener (8443) and mandatory host mTLS listener (8444) are exposed. Missing identity configuration terminates startup; development authentication is rejected. If Next exits, the gateway exits too. This does not deploy anything automatically.

Use an explicitly named Docker/Kubernetes context for every command. The checked-in smoke harness uses `docker --context homelab` and creates only uniquely named disposable test resources. Never use a default context implicitly.

## Protected configuration

Provide `DATABASE_URL` through a secret environment reference or `DATABASE_URL_FILE` through a protected mount. Provision the database URL from a credential manager; do not put its value in arguments, source or logs. Set distinct `BUNKER_ORIGIN` and `BUNKER_HOST_ORIGIN` HTTPS origins, including nonstandard external ports where applicable. The server certificate must cover both hostnames. Any external load balancer must use TCP pass-through to the respective ports so the gateway receives the original TLS handshake. Neither Next port 3000 nor the database should be published.

Mount a trusted, read-only identity directory at `/run/secrets/bunker` with these filenames:

| File | Content |
| --- | --- |
| `tls.key` | Server TLS private key matching `tls.crt` |
| `tls.crt` | Server certificate and intermediate chain |
| `tls-ca.crt` | Trusted server CA bundle for verified health probes |
| `ca.key` | Host signing CA P-256 private key, unencrypted PKCS#8/SEC1 PEM |
| `ca.crt` | Matching valid host CA certificate with CA/keyCertSign usages |
| `gateway.secret` | Exactly 32 cryptographically random binary bytes |
| `providers.json` | Identity provider JSON array; `[]` explicitly disables federation |
| Provider credential filenames | Separate client-secret files referenced by `providers.json` |

Use the provider schema in [the control-plane README](https://github.com/jusso-dev/bunker/blob/main/control-plane/README.md). Each `clientSecretFile` in the mounted JSON must use `/run/bunker/secrets/<filename>`, for example `/run/bunker/secrets/entra.secret`. Set the exact tenant-specific Entra issuer and register the exact callback URL. The optional discovery PKCE advertisement may be absent; an explicit advertisement must include S256. Authorization requests and token exchanges always use S256 PKCE. Client secrets are never literal Helm values or Compose environment values.

The unprivileged UID/GID 1000 process must be able to read the source mount. For Compose, use a restricted source directory and files owned by UID 1000 or a deliberately provisioned readable group; verify effective mapping on your Docker host. Kubernetes uses a Secret projection with `0440` and `fsGroup: 1000`. Startup materializes projected symlinks into regular `0600` files in a `0700` directory on `/run/bunker`, backed by tmpfs/Memory emptyDir. It sets the identity `*_FILE` references internally. Do not mount unrelated secrets there. Source mount changes are not hot-reloaded: restart the container/pod after rotation, coordinating all replicas' shared gateway key and replay database.

The combined image treats the container/pod as one security boundary: gateway and Next share UID 1000 and can access the mounted material. It does not provide separate OS identities for the signing CA and gateway. Use a stronger signing/key-isolation design if your threat model requires that separation. The image retains development dependencies and migration/bootstrap tools; it is not a minimal runtime.

## Compose

`deploy/compose.yml` is the production transport template. Provision the PostgreSQL password and database URL in a protected directory outside version control. The URL must select user/database `bunker` at `database:5432` with the matching password. Set `BUNKER_DEPLOY_SECRETS` to that directory and `BUNKER_IDENTITY_SECRETS` to the identity directory. Bind-mount source paths refer to the selected Docker daemon's host, not necessarily the CLI machine. Supply both HTTPS origins as above.

Set `DOCKER_CONTEXT_NAME` explicitly to your reviewed context, then run from the repository root:

```sh
docker --context "$DOCKER_CONTEXT_NAME" compose -f deploy/compose.yml build control-plane
docker --context "$DOCKER_CONTEXT_NAME" compose -f deploy/compose.yml up -d database
docker --context "$DOCKER_CONTEXT_NAME" compose -f deploy/compose.yml run --rm control-plane node control-plane/node_modules/tsx/dist/cli.mjs control-plane/scripts/migrate.ts
```

Bootstrap once using `compose run --rm -T control-plane node control-plane/node_modules/tsx/dist/cli.mjs control-plane/scripts/bootstrap.ts EMAIL ORGANIZATION TENANT`, piping the initial administrator password from your secret manager on stdin. Then start `control-plane` with `compose up -d control-plane`. Administrative command overrides do not start listeners or materialize identity files. For `identity:link`, supply its `*_FILE` references to already protected regular files using a separately provisioned administrative job; projected symlinks are not accepted directly.

The default port bindings are loopback on the Docker host, 8443 and 8444. Set `BUNKER_LISTEN_ADDRESS` deliberately for remote access only after reviewing TLS, routing and firewall controls. Compose does not publish PostgreSQL. The application filesystem is read-only, with temporary storage for secrets and Next cache. Health checks validate server TLS and exercise the gateway proof/database path.

## Development mode

Use the local pnpm workflow in [the control-plane README](https://github.com/jusso-dev/bunker/blob/main/control-plane/README.md) for trusted development. Explicitly set `BUNKER_ALLOW_INSECURE_LOOPBACK=true`, an HTTP loopback origin, and bind Next to loopback. The production image entrypoint rejects this option; there is no automatic HTTP fallback. Never place development mode behind a reverse proxy or expose it on a network.

## Helm

Validate offline with `helm lint deploy/helm/bunker` and `helm template bunker deploy/helm/bunker`. The chart deploys the combined control-plane container and a ClusterIP Service with separate `https` and `mtls` ports. It creates no ingress or PostgreSQL. Override `image.repository`, `image.tag`, `origin`, `hostOrigin`, `existingSecret` and `identitySecret`. Image defaults are local placeholders.

Provision the database Secret with key `database-url` and the identity Secret with the filenames above. Use your platform's external-secret manager and appropriate RBAC/encryption-at-rest controls. The chart references existing Secrets and contains no credentials. Run migration/bootstrap jobs once with the same image/database before starting traffic; the chart deliberately does not automate schema changes or create an administrator. Use TCP pass-through for both Service ports; never route traffic directly to port 3000. Exec probes verify TLS using `tls-ca.crt`; readiness additionally checks the replay database, while liveness checks the UI path.

Optionally enable `networkPolicy.enabled`, set `databaseCIDR`/`databasePort`, and supply provider HTTPS `identityCIDRs` for discovery, token and JWKS calls (GitHub also needs its API). With no provider CIDRs, the enabled policy denies provider egress. Provider IPs change: adapt this to a reviewed egress proxy or CNI FQDN policy rather than assuming static ranges. Ingress defaults to same-namespace pods on 8443/8444 only; adapt selectors for your TCP load balancer and DNS topology. Enforcement requires a supporting CNI. The policy is disabled by default because the template cannot know your network.

## External notifications (opt-in)

Notifications are disabled in the default Compose deployment and Helm values. Tenant policies also default to UI-only alerts. Enabling the worker does not opt tenants in or backfill history. See [the webhook contract](https://github.com/jusso-dev/bunker/blob/main/control-plane/WEBHOOKS.md) for provisioning, signatures, retries and receiver deduplication. #26 remains deferred.

Run `scripts/migrate.ts` once before starting the updated API or worker; it includes `003_notifications.sql`. The full runtime image retains `tsx`, TypeScript sources and all three migrations. The separate worker runs `scripts/notification-entrypoint.ts`, validates/materializes configuration, then imports the existing notification loop in the same process. Docker restart supervision/Kubernetes Deployment supervision restarts failures; SIGTERM reaches the loop directly and has **60 seconds** to finish its bounded attempt. There is no worker HTTP listener, Service, port mapping or identity gateway. Monitor delivery failures and backlog in PostgreSQL/tenant notification status; an idle worker is healthy, so no HTTP liveness probe is used.

Provision a **config-only** directory/Secret with key `config.json`, containing the destination schema from WEBHOOKS.md. For this deployment, each `secretFile` must be `/run/bunker/notifications/signing/<filename>`; `secretEnv` is deliberately unsupported. Provision a separate **signing-only** directory/Secret with those filenames and exact 32–4096 byte signing secrets. Never mix these with identity keys, database credentials or each other. The API mounts only configuration; the worker mounts configuration, signing secrets and database credentials. The worker receives no gateway, server TLS, host CA or federation keys. The image itself contains no provisioned credentials.

Both processes copy trusted read-only projected configuration into `/run/bunker/notifications/config.json`. Only the worker copies the referenced signing files. Kubernetes `..data` symlinks are resolved within their source mount, then copied into private UID 1000-owned regular `0600` files under `0700` directories on memory-backed `/run/bunker`. Normal application `protectedFile` checks remain unchanged. Source mounts must be readable by UID/GID 1000 (the chart uses `0440` and `fsGroup: 1000`); files never become group-readable in the runtime directory. Restart API and worker after configuration/secret rotation. Coordinate receiver key overlap for queued/in-flight attempts. Never set `BUNKER_WEBHOOK_TEST_TRANSPORT_FILE` in a deployment.

### Compose worker

Use the explicit `deploy/compose.notifications.yml` overlay. Set these operator inputs in addition to the base deployment inputs:

- `BUNKER_NOTIFICATION_CONFIG_DIR`: absolute daemon-host path to the config-only directory.
- `BUNKER_NOTIFICATION_SIGNING_DIR`: a different absolute daemon-host path to the signing-only directory.
- `BUNKER_NOTIFICATION_NETWORK`: an existing, dedicated Docker network with operator-enforced firewall rules.
- `BUNKER_NOTIFICATION_DNS`: approved DNS resolver IP.

**Provision and verify the network firewall before opting in.** Compose cannot enforce destination-based egress or deny all inbound traffic by itself. On the reviewed network, allow worker-initiated DNS only to the approved resolver (UDP/TCP 53), HTTPS only to approved public receiver IPs (TCP 443), and return traffic; deny new inbound connections and all other egress. Account for Docker embedded DNS forwarding and both IPv4/IPv6, using Docker-compatible host firewall/CNI controls. The worker also joins an internal database-only network for PostgreSQL on 5432; keep that network limited to the database and worker. Do not use an ordinary unrestricted bridge as the approved network. No host ports are published for the worker. Use receiver HTTPS port 443, as required by the egress rules.

After running migrations with the base Compose command above:

```sh
docker --context "$DOCKER_CONTEXT_NAME" compose -f deploy/compose.yml -f deploy/compose.notifications.yml config --quiet
docker --context "$DOCKER_CONTEXT_NAME" compose -f deploy/compose.yml -f deploy/compose.notifications.yml up -d database control-plane notifications
```

The overlay reuses the image built for `control-plane`. Missing paths/network/DNS inputs fail configuration; the base deployment does not reference any of them. Removing the overlay does not stop an existing worker automatically: explicitly stop/remove the `notifications` service using the overlay first, then recreate the API with the base configuration. Opt tenant policies out first so new events remain UI-only; queued deliveries are retained.

### Helm worker

Set `notifications.enabled=true`, `notifications.configSecret`, `notifications.signingSecret`, `notifications.httpsCIDRs`, and `networkPolicy.databaseCIDR`/`databasePort`. Config, signing and identity Secret names must differ. The chart projects only `config.json` into the API and creates a separate worker Deployment with a distinct selector, no Service and no inbound NetworkPolicy rules. The existing API Service and identity NetworkPolicy cannot select worker pods.

The worker NetworkPolicy is **always rendered when enabled**, even if the optional API `networkPolicy.enabled` remains false. It permits only the selected PostgreSQL range/port, DNS on UDP/TCP 53 to `notifications.dnsNamespace` + `dnsPodLabels` (defaults select kube-system/kube-dns), and TCP 443 to the explicitly approved `notifications.httpsCIDRs`. Empty HTTPS/database selections fail rendering. Use narrow receiver ranges, not a blanket internet CIDR. A NetworkPolicy-enforcing CNI is required; audit other policies because Kubernetes allow rules are additive. Adapt the DNS selectors if using NodeLocal DNS or another DNS topology. Receiver IP changes require reviewed updates or a CNI FQDN policy; application DNS/SSRF checks and verified TLS remain enforced regardless.

Validate both disabled and enabled renders before installation; this repository does not deploy or create those Secrets. `notifications.replicaCount` defaults to one; multiple workers use transactional leases. Disabling the chart removes its worker; opt policies out first to avoid ingestion failures when API configuration is removed.

## Agent sidecar

The optional Compose `agent` profile mounts the workspace read-only and a separate repository read/write. Set `BUNKER_HOST_WORKSPACE`, `BUNKER_HOST_REPOSITORY` and `BUNKER_DEPLOY_SECRETS` to reviewed absolute daemon-host paths. Initialize the repository and provision its matching `passphrase` secret. UID 10001 needs repository write and workspace read access. No Docker socket or privilege is needed. Start with `compose --profile agent up -d agent` using your explicit context. Restore requires a separate operator-controlled writable workspace. Helm does not inject a generic sidecar.

## Reproducible local evidence

After building `bunker-control-plane:council-smoke`, run `pnpm --filter @bunker/control-plane exec tsx ../deploy/smoke-control-plane.mts`. It uses the existing disposable identity fixtures, an isolated internal Docker network, fresh PostgreSQL, and no real credentials. A separate client container checks that port 3000 is inaccessible, verifies server TLS, logs in, enrolls a CSR, retrieves policies over host mTLS, and rejects missing certificates and spoofed certificate headers. It also checks projected-secret copying, restart, verified probes, missing-configuration failure and shutdown when Next fails. It removes its containers/network/volume and local fixtures on exit. No host ports are published.

Run `pnpm --filter @bunker/control-plane exec tsx ../deploy/smoke-notifications.mts` against the same image for notification deployment evidence. It uses a fresh internal network/database and separate projected config/signing mounts, checks migration 003 twice, API-without-signing bootstrap, owned `0600` runtime files, durable claims across restart, production SSRF rejection and graceful SIGTERM. It removes its containers/network/volume and fixtures. Run the two smoke scripts sequentially on hosts with limited Docker address pools. Neither contacts a real receiver or uses real signing material.

This validates the image locally, not a live Kubernetes installation, public DNS/load balancer, live Entra/Google/GitHub onboarding, HA failover or production secret rotation. Operational backups, monitoring and database TLS remain deployment responsibilities.
