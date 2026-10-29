#!/bin/sh
set -eu
# Run after pnpm build; visit the printed local URL and evaluate tests/human.browser.js.
# No network database or operator configuration is read.
BUNKER_TEST_DIR=$(mktemp -d /tmp/bunker-human-browser.XXXXXX)
cleanup() {
  pg_ctl -D "$BUNKER_TEST_DIR/data" -m immediate stop >/dev/null 2>&1 || true
  rm -r "$BUNKER_TEST_DIR"
}
trap cleanup EXIT INT TERM
initdb -D "$BUNKER_TEST_DIR/data" -A trust -U bunker_browser >/dev/null
pg_ctl -D "$BUNKER_TEST_DIR/data" -l "$BUNKER_TEST_DIR/postgres.log" -o "-h '' -k '$BUNKER_TEST_DIR'" -w start >/dev/null
export BUNKER_TEST_DATABASE_URL="postgresql://bunker_browser@localhost/postgres?host=$BUNKER_TEST_DIR"
export BUNKER_TEST_BROWSER_FIXTURE="$BUNKER_TEST_DIR/fixture.json"
pnpm exec tsx tests/human-browser-seed.ts
printf 'Browser fixture path: %s\n' "$BUNKER_TEST_BROWSER_FIXTURE"
BUNKER_IDENTITY_PROVIDERS_FILE= BUNKER_GATEWAY_SECRET_FILE= BUNKER_WEBHOOK_CONFIG_FILE= DATABASE_URL="$BUNKER_TEST_DATABASE_URL" BUNKER_ORIGIN=http://localhost:3417 BUNKER_ALLOW_INSECURE_LOOPBACK=true pnpm exec next start -H 127.0.0.1 -p 3417
