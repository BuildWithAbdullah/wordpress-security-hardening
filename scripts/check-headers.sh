#!/usr/bin/env bash
#
# check-headers.sh
#
# Fetch a URL and judge its security headers. Exit code is 0 when nothing
# failed and 1 otherwise, so it works as a post-deploy check in CI.
#
#   ./check-headers.sh https://example.com
#   ./check-headers.sh https://example.com --json
#   ./check-headers.sh https://example.com --save dump.headers
#
# This script collects. scripts/judge-headers.sh decides. Everything that could
# be wrong about a verdict lives in the other file, which needs no network and
# is driven by the test suite against saved dumps.
#
# Deploying a header and never checking the live response is a common and
# embarrassing gap: PHP-level headers are silently absent on responses served
# from a full-page cache that bypasses PHP, and on static assets served
# directly by the web server.

set -u

usage() {
  echo "usage: $0 <url> [--json] [--save <file>]" >&2
  exit 2
}

URL=""
SAVE=""
PASS_THROUGH=()

while [ $# -gt 0 ]; do
  case "$1" in
    --json) PASS_THROUGH+=( "--json" ) ;;
    --save) shift; [ $# -gt 0 ] || usage; SAVE="$1" ;;
    -h|--help) usage ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *)  [ -z "$URL" ] || usage; URL="$1" ;;
  esac
  shift
done

[ -n "$URL" ] || usage

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JUDGE="$HERE/judge-headers.sh"

if [ ! -x "$JUDGE" ]; then
  echo "cannot find an executable judge-headers.sh next to this script" >&2
  exit 2
fi

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

DUMP="$(mktemp)"
META="$(mktemp)"
cleanup() { [ -n "$SAVE" ] && cp "$DUMP" "$SAVE"; rm -f "$DUMP" "$META"; }
trap cleanup EXIT

# One request, GET, following redirects.
#
# Two things here were wrong in version 1 and both produced a confidently wrong
# answer rather than an error.
#
# It used -I, a HEAD request. A CDN or a host that answers HEAD from a different
# path, or rejects it with 405, returns a header set the visitor never sees, so
# headers that are sent on a real page were reported missing. -o /dev/null with
# a GET costs a body download and removes the whole class of problem.
#
# And it made two separate requests, one for the headers and one to learn the
# effective URL. The HSTS decision was therefore made about a response that was
# not necessarily the response being judged. One request now yields both: -D
# writes the headers of every hop, -w reports where it ended up.
if ! curl -sSL -X GET -o /dev/null -D "$DUMP" \
     -w '%{url_effective}\n%{http_code}\n' \
     --max-time 25 "$URL" > "$META" 2>/dev/null; then
  echo "Could not fetch ${URL}" >&2
  exit 1
fi

FINAL_URL="$(sed -n '1p' "$META")"
STATUS="$(sed -n '2p' "$META")"

if [ ! -s "$DUMP" ]; then
  echo "Fetched ${URL} but received no headers" >&2
  exit 1
fi

# A header set from an error page is not the header set of the site, and
# judging it produces findings about a page nobody visits.
case "$STATUS" in
  2*) : ;;
  *)  echo "Warning: final response status is ${STATUS}, so these headers may be an error page's." >&2 ;;
esac

exec "$JUDGE" "$DUMP" --url "$FINAL_URL" ${PASS_THROUGH[@]+"${PASS_THROUGH[@]}"}
