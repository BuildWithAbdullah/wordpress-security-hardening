#!/usr/bin/env bash
#
# judge-headers.sh
#
# Judge a saved response header dump. Reads a file, writes findings, exits
# non-zero if any finding is an error.
#
#   ./judge-headers.sh dump.headers
#   ./judge-headers.sh dump.headers --url https://example.com/ --json
#
# This file makes no network request of any kind, and the repository verifier
# asserts that by refusing to let the name of a network tool appear in it. That
# is the whole point of splitting it out of check-headers.sh: while fetching
# and judging were one script, not one verdict in it could be reached without a
# live site to point it at, so none of them ever had been.
#
# The dump is raw header output, which for a request that followed redirects
# contains one block per hop, in order. The final hop is the response a visitor
# actually receives, and it is the only one whose headers count. Version 1
# searched the whole dump and took the last match per header name, which
# reported a header as present when it was sent only on the redirect and not on
# the page. That is reported as its own finding now.

set -u

usage() {
  echo "usage: $0 <header-dump-file> [--url <final-url>] [--json]" >&2
  exit 2
}

DUMP=""
FINAL_URL=""
JSON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url)  shift; [ $# -gt 0 ] || usage; FINAL_URL="$1" ;;
    --json) JSON=1 ;;
    -h|--help) usage ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *)  [ -z "$DUMP" ] || usage; DUMP="$1" ;;
  esac
  shift
done

[ -n "$DUMP" ] || usage

if [ ! -f "$DUMP" ]; then
  echo "no such file: $DUMP" >&2
  exit 2
fi

# A dump with no status line is not a header dump. Saying so beats emitting a
# full set of missing-header findings about a file that was never headers.
if ! grep -qi '^HTTP/' "$DUMP"; then
  echo "not a header dump (no HTTP status line): $DUMP" >&2
  exit 2
fi

# The last status line starts the final block. Everything before it is a
# redirect hop.
LAST_HOP="$(awk 'BEGIN{n=0} /^HTTP\//{n++} END{print n+0}' "$DUMP")"
FINAL="$(awk -v want="$LAST_HOP" 'BEGIN{n=0} /^HTTP\//{n++} n==want' "$DUMP" | tr -d '\r')"
EARLIER="$(awk -v want="$LAST_HOP" 'BEGIN{n=0} /^HTTP\//{n++} n<want' "$DUMP" | tr -d '\r')"

# When no final URL is given, fall back to the dump's own Location chain, and
# failing that assume HTTPS. An explicit --url is always preferred: it is the
# effective URL the fetch reported, which is the only reliable answer.
if [ -z "$FINAL_URL" ]; then
  FINAL_URL="$(echo "$EARLIER" | grep -i '^location:' | tail -1 | cut -d: -f2- | sed 's/^ *//')"
  [ -n "$FINAL_URL" ] || FINAL_URL="https://unknown.invalid/"
fi

GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
if [ "$JSON" -eq 1 ] || [ ! -t 1 ]; then
  GREEN=""; RED=""; YEL=""; DIM=""; OFF=""
fi

errors=0
first_json=1

# findings are accumulated so the json array can be emitted in one piece
finding() {
  local level="$1" id="$2" header="$3" detail="$4"

  if [ "$level" = "error" ]; then
    errors=$((errors + 1))
  fi

  if [ "$JSON" -eq 1 ]; then
    [ "$first_json" -eq 1 ] || printf ',\n'
    first_json=0
    printf '  {"level":%s,"id":%s,"header":%s,"detail":%s}' \
      "\"$level\"" "\"$id\"" "\"$header\"" "\"$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')\""
    return
  fi

  case "$level" in
    error) printf '%sFAIL%s     %-28s %s\n' "$RED" "$OFF" "$header" "$detail" ;;
    warn)  printf '%sWARN%s     %-28s %s\n' "$YEL" "$OFF" "$header" "$detail" ;;
    note)  printf '%sNOTE%s     %-28s %s\n' "$DIM" "$OFF" "$header" "$detail" ;;
  esac
}

ok() {
  [ "$JSON" -eq 1 ] && return 0
  printf '%sOK%s       %-28s %s\n' "$GREEN" "$OFF" "$1" "${2:-}"
  return 0
}

header_in() {
  echo "$1" | grep -i "^$2:" | tail -1 | cut -d: -f2- | sed 's/^ *//; s/ *$//'
}

# A header line that is present with an empty value is not the same as an
# absent header, and conflating them loses a real case: several caching and
# security plugins emit "Permissions-Policy:" with nothing after it, which
# restricts no feature while satisfying any check that only asks whether the
# name appears.
header_present_in() {
  echo "$1" | grep -qi "^$2:"
}

# A header that is absent from the final response but present on a redirect hop
# looks like coverage in any tool that greps the whole dump.
redirect_only() {
  local name="$1"
  [ -n "$(header_in "$EARLIER" "$name")" ]
}

slug() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

require() {
  local name="$1" pattern="${2:-}" advice="${3:-}"
  local value
  value="$(header_in "$FINAL" "$name")"

  if [ -z "$value" ]; then
    if header_present_in "$FINAL" "$name"; then
      finding error "weak/$(slug "$name")" "$name" "sent with an empty value, which restricts nothing"
    elif redirect_only "$name"; then
      finding error "redirect-only" "$name" "sent on a redirect hop but not on the final response"
    else
      finding error "missing/$(slug "$name")" "$name" "not sent"
    fi
    return
  fi

  if [ -n "$pattern" ] && ! echo "$value" | grep -Eqi "$pattern"; then
    finding error "weak/$(slug "$name")" "$name" "$value ($advice)"
    return
  fi

  ok "$name" "$value"
}

[ "$JSON" -eq 1 ] && printf '[\n'

if [ "$JSON" -eq 0 ]; then
  echo "Judged: ${FINAL_URL}"
  echo "Hops in dump: ${LAST_HOP}"
  echo
fi

require "X-Content-Type-Options" '^nosniff$' \
  "the only value that does anything is nosniff"

# Version 1 accepted any value here, so X-Frame-Options: ALLOWALL reported OK.
# A permissive value that passes a check is worse than a missing header,
# because the check is what stops anyone looking again.
require "X-Frame-Options" '^(SAMEORIGIN|DENY)$' \
  "ALLOW-FROM is obsolete and ALLOWALL permits framing by anyone"

require "Referrer-Policy" '^(no-referrer|no-referrer-when-downgrade|origin|origin-when-cross-origin|same-origin|strict-origin|strict-origin-when-cross-origin)$' \
  "unsafe-url sends the full URL to every destination"

require "Permissions-Policy" '[a-z]' \
  "present but empty, so no feature is restricted"

case "$FINAL_URL" in
  https://*)
    hsts="$(header_in "$FINAL" "Strict-Transport-Security")"
    if [ -z "$hsts" ]; then
      if redirect_only "Strict-Transport-Security"; then
        finding error "redirect-only" "Strict-Transport-Security" \
          "sent on a redirect hop but not on the final response"
      else
        finding error "missing/strict-transport-security" "Strict-Transport-Security" "not sent"
      fi
    else
      max_age="$(echo "$hsts" | grep -Eoi 'max-age=[0-9]+' | head -1 | cut -d= -f2)"
      if [ -z "${max_age:-}" ]; then
        finding error "weak/strict-transport-security" "Strict-Transport-Security" \
          "$hsts (no max-age, so the browser ignores it)"
      elif [ "$max_age" -eq 0 ]; then
        finding error "disabled/strict-transport-security" "Strict-Transport-Security" \
          "max-age=0 switches HSTS off; this is how you back it out, not how you deploy it"
      elif [ "$max_age" -lt 2592000 ]; then
        finding warn "weak/strict-transport-security" "Strict-Transport-Security" \
          "max-age=${max_age} is under 30 days, which is a staging value"
      else
        ok "Strict-Transport-Security" "$hsts"
      fi
    fi
    ;;
  *)
    finding warn "transport/not-https" "Strict-Transport-Security" \
      "final URL is not HTTPS, so HSTS was not judged: ${FINAL_URL}"
    ;;
esac

csp="$(header_in "$FINAL" "Content-Security-Policy")"
if [ -z "$csp" ]; then
  finding note "csp/absent" "Content-Security-Policy" \
    "not sent; deliberately optional, see docs/01-security-headers.md"
elif echo "$csp" | grep -qi "unsafe-inline"; then
  # The README's central complaint, now a finding rather than a paragraph.
  finding warn "csp/unsafe-inline" "Content-Security-Policy" \
    "contains unsafe-inline, which permits exactly the injection a CSP is deployed to stop"
else
  ok "Content-Security-Policy" "$csp"
fi

if [ "$JSON" -eq 0 ]; then
  echo
  echo "Headers that give away more than they need to:"
fi

# Version 1 flagged Server on presence, so every site behind a CDN got a LEAK
# line for Server: cloudflare. A tool that cries wolf on a header nearly every
# server sends is a tool whose output gets skimmed. The leak is a version.
for leak in "X-Powered-By" "Server" "X-AspNet-Version" "X-Generator"; do
  value="$(header_in "$FINAL" "$leak")"
  [ -n "$value" ] || continue
  if echo "$value" | grep -Eq '[0-9]+\.[0-9]+'; then
    finding warn "leak/version" "$leak" "$value"
  else
    ok "$leak" "$value (no version)"
  fi
done

if [ -n "$(header_in "$FINAL" "X-Pingback")" ]; then
  finding warn "leak/pingback" "X-Pingback" "advertises the XML-RPC endpoint"
else
  ok "X-Pingback" "absent"
fi

if [ "$JSON" -eq 1 ]; then
  printf '\n]\n'
else
  echo
  if [ "$errors" -eq 0 ]; then
    echo "${GREEN}No failures.${OFF}"
  else
    echo "${RED}${errors} failure(s).${OFF}"
  fi
fi

exit $(( errors > 0 ? 1 : 0 ))
