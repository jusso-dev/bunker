# Bunker on yumait-prod

This deployment uses AWS account `959038055523`, region `ap-southeast-2`,
cluster/context `yumait-prod`, and namespace/release `bunker`.

- Console: `https://bunker.yumait.au`
- Host API: `https://hosts.bunker.yumait.au:8444` (client certificate required)
- Application image: ECR `bunker/control-plane:0c0d4ea`
- PostgreSQL: private `bunker-eks-postgres`, PostgreSQL 17, encrypted 20 GiB gp3,
  seven-day automated backups, deletion protection, single AZ `db.t4g.micro`.
- Secrets: AWS Secrets Manager `bunker-eks-*`, projected by the existing
  `aws-secretsmanager` ClusterSecretStore. No secret values belong in this checkout.

The dedicated NLB passes TCP through to the application's HTTPS/mTLS listeners.
Cloudflare records are **DNS-only**. TLS termination at Cloudflare or an ALB would
break the host client-certificate check. The private Next listener and PostgreSQL
are not exposed by the service. Only the initial role-provisioning Job receives the database
administrator credential; the API uses the separate `bunker_app` role and verifies
the RDS server certificate using AWS's regional CA bundle.

The NLB, RDS instance/storage/backups, exportable ACM certificate, ECR images and
Secrets Manager secrets incur AWS charges. This small single-replica/single-AZ
deployment is not highly available. It does not establish provider backup,
native-agent, cross-platform, power-loss or disaster-recovery acceptance.

## Initial provisioning

Use the vault-backed AWS profile; do not run an interactive AWS login. Install
`boto3` and `cryptography` in an operator virtual environment. `provision.py prepare`
creates Bunker resources without changing other applications. It emits only
resource names/ARNs. Add the returned ACM DNS validation records to Cloudflare
without proxying them, and retain those records for automatic certificate renewal.

After RDS is available and ACM is issued:

```sh
AWS_PROFILE=homelab-admin python deploy/eks/provision.py finish \
  --certificate-arn arn:aws:acm:ap-southeast-2:959038055523:certificate/0b9bb6f7-f4c6-4d56-aafb-5f84cfec3947
kubectl --context yumait-prod apply -f deploy/eks/prerequisites.yaml
kubectl --context yumait-prod -n bunker wait --for=condition=Ready externalsecret --all --timeout=120s
kubectl --context yumait-prod apply -f deploy/eks/database-role.yaml
kubectl --context yumait-prod -n bunker wait --for=condition=Complete job/bunker-database-role --timeout=120s
kubectl --context yumait-prod apply -f deploy/eks/migrate.yaml
kubectl --context yumait-prod -n bunker wait --for=condition=Complete job/bunker-migrate-0c0d4ea --timeout=300s
```

Provisioning the initial administrator is a separate, first-deployment-only step:
`provision.py bootstrap --email justin@yumait.com.au`, then apply `bootstrap.yaml`.
The generated password is in Secrets Manager `bunker-eks-bootstrap`; retrieve it
through the AWS console, never logs or chat. Sign in and change the password from
the Account screen. The bootstrap command refuses an already initialized database.
After bootstrap, delete only its Kubernetes ExternalSecret/Secret; the AWS secret
remains available to the operator until the initial password has been replaced.

## Application updates

Build `deploy/Dockerfile.control-plane` for `linux/amd64` and push a new immutable
commit tag to ECR. Update `values.yaml` and the image reference in `migrate.yaml`;
use a new migration Job name for each release. Review the diff, lint/render the
chart, and take an RDS snapshot before schema changes on an existing installation.
Run the migration Job and check its completion before changing the application.
All four migrations, including human lifecycle migration 004, are required.

```sh
helm lint deploy/helm/bunker
helm upgrade --install bunker deploy/helm/bunker --kube-context yumait-prod \
  --namespace bunker --values deploy/eks/values.yaml --wait --timeout 5m
kubectl --context yumait-prod -n bunker rollout status deployment/bunker-control-plane --timeout=180s
```

Verify HTTPS `/api/auth/providers`, unauthenticated API denial, login, and denial of host
requests without a client certificate. Never use `curl -k`. Roll application code
back with Helm only when the earlier image is compatible with the migrated schema;
database restoration requires a separate reviewed recovery operation. Do not delete
RDS, its backups, or the identity secrets during an application rollback.

## Certificate renewal and key custody

`certificate-sync.yaml` runs `bunker/operations:tls-sync-v2` daily at 02:17 UTC.
ACM renews the exportable certificate; the job exports renewed material, preserves
the host signing CA and gateway key, updates Secrets Manager, waits for the exact
certificate to reach the Kubernetes Secret, then changes the Deployment's TLS
serial annotation. This also repairs an interruption between saving the secret
and restarting the application. Existing TLS material stays in use on sync errors.

The job uses EKS Pod Identity role `bunker-eks-certificate-sync`, scoped to this
ACM certificate and the Bunker identity secret. Its Kubernetes role can read only
the Bunker identity Secret, trigger that ExternalSecret, and patch only the Bunker
Deployment. Monitor failed Jobs, certificate expiration and Deployment readiness.
Build `deploy/eks/Dockerfile.operations` for `linux/amd64`, publish the immutable
tag referenced in `certificate-sync.yaml`, then apply that file using
`kubectl --context yumait-prod apply -f deploy/eks/certificate-sync.yaml`.
Run a verification Job from the CronJob after each operations-image update.
For host CA/gateway-key rotations, suspend the CronJob and wait for any active run
to finish before editing the shared identity secret; resume it after coordinated
application rollout. Do not run `provision.py finish` concurrently with rotation.

The host CA is an application signing key in Secrets Manager, not a managed HSM.
Protect IAM and Kubernetes access to it accordingly. Federation and outbound
notifications remain disabled until their providers/destinations are explicitly
provisioned. The initial tenant is `Yuma IT`.

Operational records should include the image digest, migrations, certificate
expiry, backup policy and both endpoints. Keep the infrastructure handbook current.
