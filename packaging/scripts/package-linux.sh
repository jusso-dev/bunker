#!/usr/bin/env sh
# Requires fpm and the target platform's native deb/rpm build tooling.
set -eu
if [ "$#" -ne 4 ]; then
  echo 'Usage: package-linux.sh deb|rpm VERSION BINARY OUTPUT_DIRECTORY' >&2
  exit 2
fi
format=$1
version=$2
binary=$3
output=$4
case "$format" in deb|rpm) ;; *) echo 'Expected deb or rpm' >&2; exit 2 ;; esac
case "$version" in ''|*[!0-9A-Za-z.+~-]*) echo 'Invalid version' >&2; exit 2 ;; esac
test -f "$binary"
command -v fpm >/dev/null
mkdir -p "$output"
exec fpm --input-type dir --output-type "$format" --name bunker --version "$version" \
  --architecture native --license Apache-2.0 --description 'Bunker local encrypted workspace backup (development)' \
  --url https://github.com/jusso-dev/bunker --maintainer 'Bunker contributors' \
  --package "$output" "$binary=/usr/bin/bunker"
