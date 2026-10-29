#!/usr/bin/env sh
set -eu
# A root-owned credential file or systemd's read-only credential mount supplies
# the passphrase. Never enable shell tracing or pass the secret in argv.
: "${BUNKER_REPOSITORY:?set BUNKER_REPOSITORY}"
: "${BUNKER_WORKSPACE:?set BUNKER_WORKSPACE}"
if [ -n "${CREDENTIALS_DIRECTORY:-}" ]; then
  BUNKER_PASSPHRASE=$(cat "$CREDENTIALS_DIRECTORY/passphrase")
elif [ -n "${BUNKER_PASSPHRASE_FILE:-}" ]; then
  BUNKER_PASSPHRASE=$(cat "$BUNKER_PASSPHRASE_FILE")
fi
: "${BUNKER_PASSPHRASE:?provide a protected passphrase file or environment}"
export BUNKER_PASSPHRASE
if [ -n "${BUNKER_POLICY:-}" ]; then
  exec "${BUNKER_BINARY:-/usr/local/bin/bunker}" daemon --repo "$BUNKER_REPOSITORY" --workspace "$BUNKER_WORKSPACE" --policy "$BUNKER_POLICY"
fi
exec "${BUNKER_BINARY:-/usr/local/bin/bunker}" daemon --repo "$BUNKER_REPOSITORY" --workspace "$BUNKER_WORKSPACE"
