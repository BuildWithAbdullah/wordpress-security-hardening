#!/usr/bin/env bash
#
# check-headers.sh
#
# Verify that security headers are actually being sent in production. Deploying
# a header and never checking the live response is a common and embarrassing
# gap: PHP-level headers are silently absent on responses served from a
# full-page cache that bypasses PHP, and on static assets served directly by
# the web server.
#
#   ./check-headers.sh https://example.com
#
# Exit code is 0 when every required header is present, 1 otherwise, so it can
# be used as a post-deploy check in CI.

set -u

URL="${1:-}"
if [ -z "$URL" ]; then
  echo "usage: $0 <url>" >&2
  exit 2
fi

GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'

# Follow redirects, because a site that redirects http to https must be checked
# at its final destination.
HEADERS="$(curl -sSIL --max-time 20 "$URL" 2>/dev/null | tr -d '\r')"

if [ -z "$HEADERS" ]; then
  echo "${RED}Could not fetch ${URL}${OFF}" >&2
  exit 1
fi

FINAL_URL="$(curl -sSL -o /dev/null -w '%{url_effective}' --max-time 20 "$URL" 2>/dev/null)"
echo "Checked: ${FINAL_URL}"
echo

fail=0

get_header() {
  echo "$HEADERS" | grep -i "^$1:" | tail -1 | cut -d: -f2- | sed 's/^ *//'
}

require() {
  local name="$1" expected="${2:-}"
  local value
  value="$(get_header "$name")"

  if [ -z "$value" ]; then
    echo "${RED}MISSING${OFF}  $name"
    fail=1
    return
  fi

  if [ -n "$expected" ] && ! echo "$value" | grep -qi "$expected"; then
    echo "${YEL}CHECK${OFF}    $name: $value"
    echo "         ${DIM}expected to contain: $expected${OFF}"
    return
  fi

  echo "${GREEN}OK${OFF}       $name: $value"
}

advise() {
  local name="$1"
  local value
  value="$(get_header "$name")"
  if [ -z "$value" ]; then
    echo "${DIM}ABSENT   $name (optional, see docs/01-security-headers.md)${OFF}"
  else
    echo "${GREEN}OK${OFF}       $name: $value"
  fi
}

require "X-Content-Type-Options" "nosniff"
require "X-Frame-Options"
require "Referrer-Policy"
require "Permissions-Policy"

case "$FINAL_URL" in
  https://*) require "Strict-Transport-Security" "max-age" ;;
  *)         echo "${YEL}CHECK${OFF}    Strict-Transport-Security skipped: final URL is not HTTPS" ; fail=1 ;;
esac

advise "Content-Security-Policy"

echo
echo "Headers that should NOT be present:"
for leak in "X-Powered-By" "X-Pingback" "Server"; do
  value="$(get_header "$leak")"
  if [ -n "$value" ]; then
    echo "${YEL}LEAK${OFF}     $leak: $value"
  else
    echo "${GREEN}OK${OFF}       $leak absent"
  fi
done

echo
if [ "$fail" -eq 0 ]; then
  echo "${GREEN}All required headers present.${OFF}"
else
  echo "${RED}One or more required headers missing.${OFF}"
fi
exit "$fail"
