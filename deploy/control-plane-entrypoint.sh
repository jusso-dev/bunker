#!/usr/bin/env sh
set -eu
if [ -n "${DATABASE_URL_FILE:-}" ]; then
  DATABASE_URL=$(cat "$DATABASE_URL_FILE")
  export DATABASE_URL
fi
: "${DATABASE_URL:?supply DATABASE_URL or DATABASE_URL_FILE}"
exec "$@"
