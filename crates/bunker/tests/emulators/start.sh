#!/usr/bin/env sh
# Start TLS MinIO and Azurite for tests/storage_emulators.rs. Test use only.
#
#   crates/bunker/tests/emulators/start.sh WORKDIR   # writes WORKDIR/emulators.env
#   crates/bunker/tests/emulators/start.sh --stop
#
# A throwaway CA is generated per run. Tests trust it explicitly (in-process) or
# through SSL_CERT_FILE in child processes only; no system trust store changes.
# Credentials are random sentinel values so tests can prove they never leak.
set -eu

MINIO=bunker-minio-d
AZURITE=bunker-azurite-d
# minio/minio is no longer published; Chainguard's build includes mc. Pinned by digest.
MINIO_IMAGE=${BUNKER_MINIO_IMAGE:-cgr.dev/chainguard/minio:latest@sha256:3c60a2a8c4d33409a9bc7a623a7fcbfb4605adc3d89422d2f53b3f673a6e5597}
AZURITE_IMAGE=${BUNKER_AZURITE_IMAGE:-mcr.microsoft.com/azure-storage/azurite:latest@sha256:830430c1da1a2d537e08f3e6764dd1f5ae00cf0346bcaf625b968ec3f0971fd5}
REGION=ap-southeast-2
DOCKER_CONTEXT=${BUNKER_TEST_DOCKER_CONTEXT:-$(docker context show)}
docker_cmd() { docker --context "$DOCKER_CONTEXT" "$@"; }
# Publish addresses on the Docker host. Override them when Docker is remote and
# an SSH tunnel forwards local 9000/10000, e.g. BUNKER_EMULATOR_S3_PUBLISH=127.0.0.1:39000.
S3_PUBLISH=${BUNKER_EMULATOR_S3_PUBLISH:-127.0.0.1:9000}
AZURITE_PUBLISH=${BUNKER_EMULATOR_AZURITE_PUBLISH:-127.0.0.1:10000}

if [ "${1:-}" = "--stop" ]; then
  docker_cmd rm -f "$MINIO" "$AZURITE" >/dev/null 2>&1 || true
  exit 0
fi
[ $# -eq 1 ] || { echo "usage: $0 WORKDIR | --stop" >&2; exit 2; }
work=$1
umask 077
mkdir -p "$work/certs/CAs" "$work/server-certs/CAs"
certs=$work/certs

openssl ecparam -name prime256v1 -genkey -noout -out "$certs/ca.key"
openssl req -x509 -new -key "$certs/ca.key" -sha256 -days 2 -subj "/CN=Bunker emulator test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$certs/ca.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$certs/private.key"
openssl req -new -key "$certs/private.key" -subj "/CN=localhost" -out "$certs/server.csr"
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,IP:127.0.0.1" > "$certs/server.ext"
openssl x509 -req -in "$certs/server.csr" -CA "$certs/ca.pem" -CAkey "$certs/ca.key" \
  -CAcreateserial -days 2 -sha256 -extfile "$certs/server.ext" -out "$certs/public.crt"
cp "$certs/ca.pem" "$certs/CAs/ca.crt"
chmod 0755 "$certs" "$certs/CAs"
chmod 0644 "$certs/ca.pem" "$certs/public.crt" "$certs/CAs/ca.crt" "$certs/private.key"

# Copy only the server identity and public CA into containers. The CA signing
# key stays in the owner-only work directory.
cp "$certs/public.crt" "$certs/private.key" "$work/server-certs/"
cp "$certs/CAs/ca.crt" "$work/server-certs/CAs/"
chmod 0755 "$work/server-certs" "$work/server-certs/CAs"
chmod 0644 "$work/server-certs/"*.* "$work/server-certs/CAs/ca.crt"

s3_access="bunkersentinelaccess$(openssl rand -hex 8)"
s3_secret="bunkersentinelsecret$(openssl rand -hex 16)"
azure_account=bunkersentinel
azure_key=$(openssl rand -base64 64 | tr -d '\n')

docker_cmd rm -f "$MINIO" "$AZURITE" >/dev/null 2>&1 || true
# Containers are created first and files copied in: no host bind mounts.
docker_cmd create --name "$MINIO" -p "$S3_PUBLISH:9000" \
  -e MINIO_ROOT_USER="$s3_access" -e MINIO_ROOT_PASSWORD="$s3_secret" -e MINIO_SITE_REGION="$REGION" \
  "$MINIO_IMAGE" server /tmp/data --address :9000 --certs-dir /certs >/dev/null
docker_cmd cp "$work/server-certs/." "$MINIO:/certs"
docker_cmd create --name "$AZURITE" -p "$AZURITE_PUBLISH:10000" \
  -e AZURITE_ACCOUNTS="$azure_account:$azure_key" \
  "$AZURITE_IMAGE" azurite-blob --blobHost 0.0.0.0 --blobPort 10000 \
  --cert /certs/public.crt --key /certs/private.key --skipApiVersionCheck --inMemoryPersistence >/dev/null
docker_cmd cp "$work/server-certs/." "$AZURITE:/certs"
docker_cmd start "$MINIO" "$AZURITE" >/dev/null

ready() {
  i=0
  until curl -fsS --cacert "$certs/ca.pem" -o /dev/null "$1"; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { echo "emulator did not become ready: $1" >&2; exit 1; }
    sleep 1
  done
}
ready https://127.0.0.1:9000/minio/health/live
# Any TLS response (even 400) proves Azurite is serving with the generated certificate.
i=0
until curl -s --cacert "$certs/ca.pem" -o /dev/null https://127.0.0.1:10000/; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || { echo "Azurite did not become ready" >&2; exit 1; }
  sleep 1
done

# mc inside the MinIO container trusts the same CA via its certs directory.
docker_cmd exec "$MINIO" sh -c 'mkdir -p /tmp/mc/certs/CAs && cp /certs/CAs/ca.crt /tmp/mc/certs/CAs/'
minio_client() {
  docker_cmd exec -e MC_HOST_local="https://$s3_access:$s3_secret@localhost:9000" "$MINIO" mc -C /tmp/mc "$@" >/dev/null
}
minio_client mb --quiet local/bunker-plain
minio_client mb --quiet --with-lock local/bunker-lock

# Azure SharedKey-signed Create Container (path-style emulator resource).
date=$(LC_ALL=C TZ=GMT date '+%a, %d %b %Y %H:%M:%S GMT')
version=2021-08-06
hexkey=$(printf '%s' "$azure_key" | openssl base64 -d -A | od -An -v -tx1 | tr -d ' \n')
signature=$(printf 'PUT\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:%s\nx-ms-version:%s\n/%s/%s/bunker-plain\nrestype:container' \
  "$date" "$version" "$azure_account" "$azure_account" |
  openssl dgst -sha256 -mac HMAC -macopt "hexkey:$hexkey" -binary | openssl base64 -A)
curl -fsS --cacert "$certs/ca.pem" -X PUT -H "x-ms-date: $date" -H "x-ms-version: $version" \
  -H "Content-Length: 0" -H "Authorization: SharedKey $azure_account:$signature" \
  "https://127.0.0.1:10000/$azure_account/bunker-plain?restype=container" >/dev/null

cat > "$work/emulators.env" <<ENV
BUNKER_TEST_CA_FILE=$certs/ca.pem
BUNKER_TEST_S3_ENDPOINT=https://127.0.0.1:9000
BUNKER_TEST_S3_REGION=$REGION
BUNKER_TEST_S3_BUCKET=bunker-plain
BUNKER_TEST_S3_LOCK_BUCKET=bunker-lock
BUNKER_TEST_S3_ACCESS_KEY=$s3_access
BUNKER_TEST_S3_SECRET_KEY=$s3_secret
BUNKER_TEST_AZURITE_ENDPOINT=https://127.0.0.1:10000/$azure_account
BUNKER_TEST_AZURITE_ACCOUNT=$azure_account
BUNKER_TEST_AZURITE_CONTAINER=bunker-plain
BUNKER_TEST_AZURITE_KEY=$azure_key
ENV
echo "emulators ready; environment written to $work/emulators.env"
