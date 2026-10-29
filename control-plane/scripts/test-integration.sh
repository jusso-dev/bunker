#!/bin/sh
set -eu
# Always use a fresh disposable database, never the operator's DATABASE_URL.
for command in initdb pg_ctl; do
  command -v "$command" >/dev/null 2>&1 || { echo "PostgreSQL tools initdb and pg_ctl are required" >&2; exit 1; }
done
BUNKER_TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bunker-postgres.XXXXXX")
cleanup() {
  pg_ctl -D "$BUNKER_TEST_DIR/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$BUNKER_TEST_DIR"
}
trap cleanup EXIT INT TERM
initdb -D "$BUNKER_TEST_DIR/data" -A trust -U bunker_test >/dev/null
# Unix socket in a private temporary directory; no network listener or fixed-port collision.
pg_ctl -D "$BUNKER_TEST_DIR/data" -l "$BUNKER_TEST_DIR/postgres.log" -o "-h '' -k '$BUNKER_TEST_DIR'" -w start >/dev/null
export BUNKER_TEST_DATABASE_URL="postgresql://bunker_test@localhost/postgres?host=$BUNKER_TEST_DIR"
pnpm exec tsx --test tests/api.test.ts

DATABASE_URL="$BUNKER_TEST_DATABASE_URL" pnpm exec tsx scripts/migrate.ts
pnpm exec tsx --test tests/human-lifecycle.test.ts
pnpm exec tsx --test tests/identity.test.ts
pnpm exec tsx --test tests/notifications.integration.test.ts
if [ "${BUNKER_TEST_REAL_NEXT:-false}" = "true" ]; then
  pnpm exec tsx --test tests/next-gateway.test.ts
fi
