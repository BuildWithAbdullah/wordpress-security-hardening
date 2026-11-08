#!/usr/bin/env bash
#
# judge-headers.sh
#
# Judge a saved response header dump. Reads a file, writes findings, exits
# non-zero if any finding is an error.
#
#   ./judge-headers.sh dump.headers --url https://example.com/
#   ./judge-headers.sh dump.headers --url https://example.com/ --json
#   ./judge-headers.sh dump.headers --normalize
#
# This file makes no network request of any kind, and the repository verifier
# asserts that by refusing to let the name of a network tool appear in it. That
# is the whole point of splitting it out of check-headers.sh: while fetching
# and judging were one script, not one verdict in it could be reached without a
# live site to point it at, so none of them ever had been.
#
# ---------------------------------------------------------------------------
# What version 3 changed, and why the parsing is now its own mode
#
# A dump is raw header output. For a request that followed redirects it holds
# one block per hop in order, and only the final hop is the response a visitor
# receives. Version 2 got that right and then read the hops with a case
# sensitive pattern while validating the file with a case insensitive one, so a
# dump whose status lines were lowercase was judged as a single hop containing
# every header from every hop. The fix that version 2 existed to make was
# undone by the mismatch.
#
# Version 2 also read one value per header name, the last line it saw. Repeated
# field lines are combined by HTTP into one comma separated value, so the
# browser sees neither of two conflicting values and the last line is not the
# one that applies. A response carrying X-Frame-Options: ALLOWALL and then
# X-Frame-Options: SAMEORIGIN was reported as a pass, and the same response with
# the lines the other way round was reported as a failure. Nothing about HTTP
# makes that order meaningful, so the verdict was being decided by luck.
#
# And it did not unfold. A header value continued on an indented following line
# is one value to every HTTP parser, so a policy whose unsafe-inline sat on the
# continuation line was invisible.
#
# All three were parsing, not judging. So the parsing is now one awk program
# with its own output format and its own mode, --normalize, which prints what
# the judge is about to read and nothing else. test/normalize.test.mjs drives
# that mode directly. A parser nothing can observe is a parser nobody has
# checked, and this one had three defects in it.

set -u

usage() {
  echo "usage: $0 <header-dump-file> [--url <final-url>] [--json] [--normalize]" >&2
  exit 2
}

DUMP=""
FINAL_URL=""
JSON=0
NORMALIZE=0
URL_GIVEN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url)  shift; [ $# -gt 0 ] || usage; FINAL_URL="$1"; URL_GIVEN=1 ;;
    --json) JSON=1 ;;
    --normalize) NORMALIZE=1 ;;
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
# Matched the same way the normalizer matches, which is the point: version 2
# validated case insensitively and parsed case sensitively.
if ! grep -qE '^[Hh][Tt][Tt][Pp]/' "$DUMP"; then
  echo "not a header dump (no HTTP status line): $DUMP" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Normalize
#
# Output is tab separated, one record per line, and is the only thing the judge
# below reads:
#
#   M <TAB> hops   <TAB> <count of status lines>
#   M <TAB> folded <TAB> <count of continuation lines joined>
#   S <TAB> <hop>  <TAB> <status line>
#   H <TAB> <hop>  <TAB> <lowercased name> <TAB> <value>
#
# Hops are numbered from 1. Lines before the first status line belong to no hop
# and are dropped. A tab inside a value becomes a single space, so the format
# stays unambiguous; a tab in a header value is legal HTTP and vanishingly rare,
# and losing it changes no verdict this script reaches.
# ---------------------------------------------------------------------------
normalize() {
  awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function flush() {
      if (pending) {
        gsub(/\t/, " ", pvalue)
        printf "H\t%d\t%s\t%s\n", phop, pname, pvalue
        pending = 0
      }
    }
    BEGIN { hop = 0; folded = 0; pending = 0 }
    {
      line = $0
      sub(/\r$/, "", line)

      if (line ~ /^[Hh][Tt][Tt][Pp]\//) {
        flush()
        hop++
        printf "S\t%d\t%s\n", hop, trim(line)
        next
      }

      if (line ~ /^[ \t]/ && trim(line) != "") {
        # A continuation line. One value to every HTTP parser, so join it.
        if (pending) {
          folded++
          pvalue = pvalue " " trim(line)
        }
        next
      }

      if (trim(line) == "") { flush(); next }

      if (hop == 0) next

      i = index(line, ":")
      if (i == 0) next

      flush()
      pname  = tolower(trim(substr(line, 1, i - 1)))
      pvalue = trim(substr(line, i + 1))
      phop   = hop
      pending = 1
    }
    END {
      flush()
      printf "M\thops\t%d\n", hop
      printf "M\tfolded\t%d\n", folded
    }
  ' "$1"
}

NORM="$(normalize "$DUMP")"

if [ "$NORMALIZE" -eq 1 ]; then
  printf '%s\n' "$NORM"
  exit 0
fi

HOPS="$(printf '%s\n' "$NORM" | awk -F'\t' '$1=="M" && $2=="hops" { print $3 }')"
FOLDED="$(printf '%s\n' "$NORM" | awk -F'\t' '$1=="M" && $2=="folded" { print $3 }')"

# ---------------------------------------------------------------------------
# Reading the normalized form
# ---------------------------------------------------------------------------

# Every value for a header in the final hop, in the order it was sent.
hvals() {
  printf '%s\n' "$NORM" | awk -F'\t' -v n="$1" -v h="$HOPS" '$1=="H" && $2==h && $3==n { print $4 }'
}

# How many times a header appears in the final hop. Distinct from the value,
# because a header present with an empty value is not an absent header and
# conflating them loses a real case.
hcount() {
  printf '%s\n' "$NORM" | awk -F'\t' -v n="$1" -v h="$HOPS" '$1=="H" && $2==h && $3==n { c++ } END { print c+0 }'
}

# How many times a header appears on any hop before the final one.
hcount_earlier() {
  printf '%s\n' "$NORM" | awk -F'\t' -v n="$1" -v h="$HOPS" '$1=="H" && $2<h && $3==n { c++ } END { print c+0 }'
}

# Values on earlier hops, in order.
hvals_earlier() {
  printf '%s\n' "$NORM" | awk -F'\t' -v n="$1" -v h="$HOPS" '$1=="H" && $2<h && $3==n { print $4 }'
}

final_header_count() {
  printf '%s\n' "$NORM" | awk -F'\t' -v h="$HOPS" '$1=="H" && $2==h { c++ } END { print c+0 }'
}

# ---------------------------------------------------------------------------
# Final URL
#
# An explicit --url is always preferred: it is the effective URL the fetch
# reported, which is the only reliable answer.
#
# Version 2 fell back to the dump's own Location chain and, failing that,
# assumed HTTPS. Both halves were wrong. The assumption produced confident HSTS
# findings about a transport nobody had established, and the Location fallback
# accepted a relative Location, so a dump whose last redirect was to /en/ had a
# final URL of "/en/", did not match https://*, and so reported the transport
# warning and skipped every HSTS check on a response that carried a perfectly
# good HSTS header.
#
# Only an absolute URL is accepted now, and when there is none the script says
# so rather than deciding. A guess is worse than a refusal when the finding
# looks specific.
# ---------------------------------------------------------------------------
if [ "$URL_GIVEN" -eq 0 ]; then
  FINAL_URL="$(hvals_earlier "location" | grep -E '^[A-Za-z][A-Za-z0-9+.-]*://' | tail -1 || true)"
fi

TRANSPORT="unknown"
case "$FINAL_URL" in
  https://*) TRANSPORT="https" ;;
  http://*)  TRANSPORT="http" ;;
  *)         TRANSPORT="unknown" ;;
esac

FINAL_HOST=""
if [ "$TRANSPORT" != "unknown" ]; then
  FINAL_HOST="$(printf '%s' "$FINAL_URL" | sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://##; s#[/?#].*$##; s#^[^@]*@##; s#:[0-9]+$##' | tr '[:upper:]' '[:lower:]')"
fi

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
if [ "$JSON" -eq 1 ] || [ ! -t 1 ]; then
  GREEN=""; RED=""; YEL=""; DIM=""; OFF=""
fi

errors=0
first_json=1

json_escape() {
  # Quotes and backslashes, and the control characters a header value can
  # legally carry. Without the last of those a tab in a value produced output
  # that was not JSON at all, and the caller saw a parse error rather than a
  # finding.
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
    | tr '\t' ' ' | tr -d '\000-\010\013\014\016-\037'
}

finding() {
  local level="$1" id="$2" header="$3" detail="$4"

  if [ "$level" = "error" ]; then
    errors=$((errors + 1))
  fi

  if [ "$JSON" -eq 1 ]; then
    [ "$first_json" -eq 1 ] || printf ',\n'
    first_json=0
    printf '  {"level":"%s","id":"%s","header":"%s","detail":"%s"}' \
      "$(json_escape "$level")" "$(json_escape "$id")" \
      "$(json_escape "$header")" "$(json_escape "$detail")"
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

# ---------------------------------------------------------------------------
# Numbers
#
# max-age is a non-negative integer with no upper bound in RFC 6797, and
# browsers clamp it themselves. Version 2 compared it with shell arithmetic, so
# a header carrying a twenty digit max-age printed two "integer expression
# expected" errors to stderr and then produced no finding and exit 0. Compare
# on digit length first and lexically after, which is exact for any length.
# ---------------------------------------------------------------------------
strip_zeros() {
  local n="$1"
  n="$(printf '%s' "$n" | sed -E 's/^0+//')"
  [ -n "$n" ] || n="0"
  printf '%s' "$n"
}

num_lt() {
  local a b
  a="$(strip_zeros "$1")"
  b="$(strip_zeros "$2")"
  if [ "${#a}" -ne "${#b}" ]; then
    [ "${#a}" -lt "${#b}" ]
  else
    [ "$a" \< "$b" ]
  fi
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Distinct values of a header in the final hop. Two identical lines are not a
# conflict: the browser sees a repeated value, which parses to the same thing.
#
# Compared case insensitively and with runs of whitespace collapsed, because
# the token values of every header this is used on are matched case
# insensitively by browsers. Comparing the raw bytes reported nosniff and
# NOSNIFF as a conflict, which is a false positive on a response that says the
# same thing twice, and a false positive on a conflict check is how the check
# gets switched off.
distinct_count() {
  hvals "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' \
    | sort -u | grep -c '' || true
}

[ "$JSON" -eq 1 ] && printf '[\n'

if [ "$JSON" -eq 0 ]; then
  if [ "$TRANSPORT" = "unknown" ]; then
    echo "Judged: (final URL not established)"
  else
    echo "Judged: ${FINAL_URL}"
  fi
  echo "Hops in dump: ${HOPS}"
  echo
fi

# ---------------------------------------------------------------------------
# dump
# ---------------------------------------------------------------------------
if [ "$(final_header_count)" -eq 0 ]; then
  finding error "dump/empty-final-hop" "(dump)" \
    "the final hop carries a status line and no headers, so the findings below are probably a truncated file rather than a site"
fi

if [ "${FOLDED:-0}" -gt 0 ]; then
  finding note "dump/folded-header" "(dump)" \
    "${FOLDED} continuation line(s) were joined to the header above before judging"
fi

# ---------------------------------------------------------------------------
# required
# ---------------------------------------------------------------------------
require() {
  local name="$1" pattern="$2" advice="$3"
  local key count earlier n value
  key="$(lower "$name")"
  count="$(hcount "$key")"

  if [ "$count" -eq 0 ]; then
    earlier="$(hcount_earlier "$key")"
    if [ "$earlier" -gt 0 ]; then
      finding error "redirect-only" "$name" \
        "sent on a redirect hop but not on the final response"
    else
      finding error "missing/$key" "$name" "not sent"
    fi
    return
  fi

  if [ "$count" -gt 1 ]; then
    n="$(distinct_count "$key")"
    if [ "$n" -gt 1 ]; then
      finding error "conflict/$key" "$name" \
        "sent ${count} times with values that do not agree, so the browser sees none of them: $(hvals "$key" | paste -sd '|' -)"
      return
    fi
  fi

  value="$(hvals "$key" | head -1)"

  if [ -z "$value" ]; then
    finding error "empty/$key" "$name" "sent with an empty value, which restricts nothing"
    return
  fi

  if ! printf '%s' "$value" | grep -Eqi "$pattern"; then
    finding error "weak/$key" "$name" "$value ($advice)"
    return
  fi

  ok "$name" "$value"
}

require "X-Content-Type-Options" '^nosniff$' \
  "the only value that does anything is nosniff"

require "X-Frame-Options" '^(SAMEORIGIN|DENY)$' \
  "ALLOW-FROM is obsolete and ALLOWALL permits framing by anyone"

require "Referrer-Policy" '^(no-referrer|no-referrer-when-downgrade|origin|origin-when-cross-origin|same-origin|strict-origin|strict-origin-when-cross-origin)$' \
  "unsafe-url sends the full URL to every destination"

require "Permissions-Policy" '[a-z]' \
  "present but names no feature, so none is restricted"

# ---------------------------------------------------------------------------
# hsts
# ---------------------------------------------------------------------------
judge_hsts() {
  local count earlier n hsts max_age
  count="$(hcount "strict-transport-security")"

  if [ "$count" -eq 0 ]; then
    earlier="$(hcount_earlier "strict-transport-security")"
    if [ "$earlier" -gt 0 ]; then
      finding error "redirect-only" "Strict-Transport-Security" \
        "sent on a redirect hop but not on the final response"
    else
      finding error "missing/strict-transport-security" "Strict-Transport-Security" "not sent"
    fi
    return
  fi

  if [ "$count" -gt 1 ]; then
    n="$(distinct_count "strict-transport-security")"
    if [ "$n" -gt 1 ]; then
      finding error "hsts/conflict" "Strict-Transport-Security" \
        "sent ${count} times with values that do not agree; RFC 6797 says the browser honours only the first: $(hvals "strict-transport-security" | paste -sd '|' -)"
    fi
  fi

  # The first one, because that is the one the browser processes. Version 2
  # read the last, which is how a response sending max-age=0 and then a year
  # was reported clean while every browser switched HSTS off.
  hsts="$(hvals "strict-transport-security" | head -1)"

  # A quoted directive value is legal. Version 2 required bare digits and so
  # called max-age="31536000" unreadable, at error level, on a header the
  # browser honours.
  max_age="$(printf '%s' "$hsts" | grep -Eoi 'max-age[[:space:]]*=[[:space:]]*"?[0-9]+"?' | head -1 | sed -E 's/.*=[[:space:]]*"?([0-9]+)"?.*/\1/')"

  if [ -z "${max_age:-}" ]; then
    finding error "hsts/no-max-age" "Strict-Transport-Security" \
      "$hsts (no readable max-age, so the browser ignores the header)"
    return
  fi

  max_age="$(strip_zeros "$max_age")"

  if [ "$max_age" = "0" ]; then
    finding error "hsts/disabled" "Strict-Transport-Security" \
      "max-age=0 switches HSTS off; this is how you back it out, not how you deploy it"
  elif num_lt "$max_age" 2592000; then
    finding warn "hsts/short-max-age" "Strict-Transport-Security" \
      "max-age=${max_age} is under 30 days, which is a staging value"
  else
    ok "Strict-Transport-Security" "$hsts"
  fi

  if printf '%s' "$(lower "$hsts")" | grep -q 'preload'; then
    if ! printf '%s' "$(lower "$hsts")" | grep -q 'includesubdomains' || num_lt "$max_age" 31536000; then
      finding error "hsts/preload-without-subdomains" "Strict-Transport-Security" \
        "preload is present without includeSubDomains and a max-age of at least a year, so the preload list refuses the submission and the site is not preloaded"
    fi
  fi
}

case "$TRANSPORT" in
  https) judge_hsts ;;
  http)
    finding warn "transport/not-https" "Strict-Transport-Security" \
      "final URL is HTTP, so HSTS was not judged: ${FINAL_URL}"
    ;;
  *)
    finding warn "transport/url-unknown" "Strict-Transport-Security" \
      "no final URL was given and the dump carries no absolute one, so the transport could not be established and HSTS was not judged"
    ;;
esac

# ---------------------------------------------------------------------------
# csp
# ---------------------------------------------------------------------------
csp_directive() {
  printf '%s' "$1" | tr ';' '\n' | awk -v d="$2" '
    { line = tolower($0); sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
      if (line == "") next
      i = index(line, " ")
      if (i == 0) { name = line; rest = "" } else { name = substr(line, 1, i - 1); rest = substr(line, i + 1) }
      if (name == d) { print rest; exit } }'
}

# A source list permits any host when it carries a bare asterisk or a bare
# scheme. Checked as whole tokens: a host of https://cdn.example.com is not a
# bare https: source, and reporting it as one would be a false positive on
# nearly every real policy.
permits_any_host() {
  printf '%s' "$1" | tr ' ' '\n' | sed -E "s/^'//; s/'$//" | grep -Eqx '\*|https:|http:|data:'
}

judge_csp() {
  local enforce_count ro_count policy script_src frame_ancestors
  enforce_count="$(hcount "content-security-policy")"
  ro_count="$(hcount "content-security-policy-report-only")"

  if [ "$enforce_count" -eq 0 ]; then
    if [ "$ro_count" -gt 0 ]; then
      finding warn "csp/report-only-only" "Content-Security-Policy" \
        "only a Report-Only policy is present, and Report-Only blocks nothing by design"
    else
      finding note "csp/absent" "Content-Security-Policy" \
        "not sent; deliberately optional, see docs/01-security-headers.md"
    fi
    return
  fi

  if [ "$enforce_count" -gt 1 ]; then
    finding warn "csp/conflict" "Content-Security-Policy" \
      "sent ${enforce_count} times; browsers apply every policy, so the effective policy is their intersection and is stricter than either one"
  fi

  policy="$(lower "$(hvals "content-security-policy" | paste -sd ';' -)")"

  script_src="$(csp_directive "$policy" "script-src")"
  [ -n "$script_src" ] || script_src="$(csp_directive "$policy" "default-src")"

  if printf '%s' "$script_src" | grep -q "unsafe-inline"; then
    finding warn "csp/unsafe-inline" "Content-Security-Policy" \
      "the script source list permits unsafe-inline, which allows exactly the injection a policy is deployed to stop"
  fi

  if printf '%s' "$script_src" | grep -q "unsafe-eval"; then
    finding warn "csp/unsafe-eval" "Content-Security-Policy" \
      "the script source list permits unsafe-eval"
  fi

  if [ -n "$script_src" ] && permits_any_host "$script_src"; then
    finding warn "csp/wildcard-script-src" "Content-Security-Policy" \
      "the script source list permits any host: ${script_src}"
  fi

  frame_ancestors="$(csp_directive "$policy" "frame-ancestors")"
  if [ -n "$frame_ancestors" ] && permits_any_host "$frame_ancestors"; then
    finding error "csp/frame-ancestors-permissive" "Content-Security-Policy" \
      "frame-ancestors permits framing (${frame_ancestors}), and it supersedes X-Frame-Options in every current browser"
  fi

  if [ "$enforce_count" -eq 1 ]; then
    ok "Content-Security-Policy" "present"
  fi
}

judge_csp

# ---------------------------------------------------------------------------
# cookie and cache
#
# Only cookies this script can name as session or authentication cookies are
# judged. A site with a custom session cookie name gets nothing said about it,
# which is stated as a limit rather than guessed at.
# ---------------------------------------------------------------------------
is_session_cookie() {
  printf '%s' "$1" | grep -Eqi '^(wordpress_logged_in_|wordpress_sec_|wp-postpass_|wp_woocommerce_session_|wordpress_[0-9a-f]{32}|phpsessid$)'
}

cookie_attr() {
  # The value of one attribute, or the empty string. Presence is tested with
  # cookie_has, because an attribute present with no value is normal here.
  printf '%s' "$1" | tr ';' '\n' | awk -v a="$2" '
    { line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
      low = tolower(line)
      i = index(low, "=")
      if (i == 0) { if (low == a) { print ""; exit } ; next }
      if (substr(low, 1, i - 1) == a) { print substr(line, i + 1); exit } }'
}

cookie_has() {
  printf '%s' "$1" | tr ';' '\n' | awk -v a="$2" '
    { line = tolower($0); sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
      i = index(line, "=")
      name = (i == 0) ? line : substr(line, 1, i - 1)
      if (name == a) { found = 1 } }
    END { exit found ? 0 : 1 }'
}

SESSION_COOKIE_SEEN=0

judge_cookies() {
  local line name attrs seen_names dup_report samesite domain bare
  seen_names=""
  dup_report=""

  while IFS= read -r line; do
    [ -n "$line" ] || continue

    name="$(printf '%s' "$line" | sed -E 's/=.*$//' | sed -E 's/^[ \t]+|[ \t]+$//g')"
    attrs="$(printf '%s' "$line" | cut -d';' -f2-)"
    [ "$attrs" != "$line" ] || attrs=""

    # Prefix rules apply to any cookie, session or not, because a browser
    # refuses the cookie outright when they are broken.
    case "$name" in
      __Secure-*)
        if ! cookie_has "$attrs" "secure"; then
          finding error "cookie/prefix-violation" "Set-Cookie" \
            "${name} uses the __Secure- prefix without the Secure attribute, so the browser refuses it"
        fi
        ;;
      __Host-*)
        if ! cookie_has "$attrs" "secure" \
           || [ "$(cookie_attr "$attrs" "path")" != "/" ] \
           || cookie_has "$attrs" "domain"; then
          finding error "cookie/prefix-violation" "Set-Cookie" \
            "${name} uses the __Host- prefix, which requires Secure and Path=/ and forbids Domain, so the browser refuses it"
        fi
        ;;
    esac

    samesite="$(lower "$(cookie_attr "$attrs" "samesite")")"
    if [ "$samesite" = "none" ] && ! cookie_has "$attrs" "secure"; then
      finding error "cookie/samesite-none-insecure" "Set-Cookie" \
        "${name} declares SameSite=None without Secure, which browsers reject outright"
    fi

    if is_session_cookie "$name"; then
      SESSION_COOKIE_SEEN=1

      case " $seen_names " in
        *" $name "*)
          case " $dup_report " in
            *" $name "*) : ;;
            *)
              dup_report="$dup_report $name"
              finding warn "cookie/conflict" "Set-Cookie" \
                "${name} is set more than once in one response, so the attributes that apply are whichever line came last"
              ;;
          esac
          ;;
      esac
      seen_names="$seen_names $name"

      if [ "$TRANSPORT" = "https" ] && ! cookie_has "$attrs" "secure"; then
        finding error "cookie/no-secure" "Set-Cookie" \
          "${name} is a session cookie set over HTTPS without Secure, so it is sent on any later plain HTTP request"
      fi

      if ! cookie_has "$attrs" "httponly"; then
        finding error "cookie/no-httponly" "Set-Cookie" \
          "${name} is a session cookie without HttpOnly, so any injected script can read it"
      fi

      if [ -z "$samesite" ]; then
        finding warn "cookie/no-samesite" "Set-Cookie" \
          "${name} is a session cookie with no explicit SameSite attribute"
      fi

      # Any Domain attribute broadens the cookie, and the leading dot is not
      # what decides it. RFC 6265 ignores a leading dot, so Domain=example.com
      # and Domain=.example.com both produce a domain-match cookie that is sent
      # to every subdomain, where a cookie with no Domain attribute at all is
      # sent only to the host that set it. Comparing the attribute against the
      # host, which is what this first did, therefore reported nothing for the
      # commonest form of the problem.
      domain="$(lower "$(cookie_attr "$attrs" "domain")")"
      if [ -n "$domain" ]; then
        bare="${domain#.}"
        if [ -n "$FINAL_HOST" ] && [ "$bare" != "$FINAL_HOST" ]; then
          finding warn "cookie/domain-too-broad" "Set-Cookie" \
            "${name} is scoped to ${domain}, which is wider than ${FINAL_HOST}, so it is sent to every host under it"
        else
          finding warn "cookie/domain-too-broad" "Set-Cookie" \
            "${name} carries Domain=${domain}, so it is sent to every subdomain rather than only the host that set it"
        fi
      fi
    fi
  done <<EOF
$(hvals "set-cookie")
EOF
}

judge_cookies

judge_cache() {
  local cc has_cc max_age s_maxage
  [ "$SESSION_COOKIE_SEEN" -eq 1 ] || return 0

  has_cc="$(hcount "cache-control")"
  cc="$(lower "$(hvals "cache-control" | paste -sd ',' -)")"

  if [ "$has_cc" -eq 0 ]; then
    finding warn "cache/no-directive-with-session-cookie" "Cache-Control" \
      "the response sets a session cookie and sends no Cache-Control, so a shared cache applies its own heuristics"
    return
  fi

  s_maxage="$(printf '%s' "$cc" | grep -Eo 's-maxage[[:space:]]*=[[:space:]]*[0-9]+' | head -1 | grep -Eo '[0-9]+$' || true)"
  max_age="$(printf '%s' "$cc" | grep -Eo '(^|[^-])max-age[[:space:]]*=[[:space:]]*[0-9]+' | head -1 | grep -Eo '[0-9]+$' || true)"

  if printf '%s' "$cc" | grep -q 'public'; then
    finding error "cache/session-cookie-publicly-cacheable" "Cache-Control" \
      "the response sets a session cookie and is marked public, so a shared cache may store it and hand it to the next visitor"
    return
  fi

  if [ -n "${s_maxage:-}" ] && [ "$(strip_zeros "$s_maxage")" != "0" ]; then
    finding error "cache/session-cookie-publicly-cacheable" "Cache-Control" \
      "the response sets a session cookie and carries s-maxage=${s_maxage}, which is an instruction to shared caches specifically"
    return
  fi

  if printf '%s' "$cc" | grep -Eq 'no-store|private|no-cache'; then
    ok "Cache-Control" "$cc"
    return
  fi

  if [ -n "${max_age:-}" ] && [ "$(strip_zeros "$max_age")" != "0" ]; then
    finding error "cache/session-cookie-publicly-cacheable" "Cache-Control" \
      "the response sets a session cookie and permits caching for ${max_age}s with no private or no-store directive"
    return
  fi

  ok "Cache-Control" "$cc"
}

judge_cache

# ---------------------------------------------------------------------------
# leak
# ---------------------------------------------------------------------------
if [ "$JSON" -eq 0 ]; then
  echo
  echo "Headers that give away more than they need to:"
fi

for leak in "X-Powered-By" "Server" "X-AspNet-Version" "X-Generator" "X-Redirect-By"; do
  key="$(lower "$leak")"
  [ "$(hcount "$key")" -gt 0 ] || continue
  value="$(hvals "$key" | head -1)"
  [ -n "$value" ] || continue
  if printf '%s' "$value" | grep -Eq '[0-9]+\.[0-9]+'; then
    finding warn "leak/version" "$leak" "$value"
  elif printf '%s' "$value" | grep -Eq '[0-9]'; then
    # X-Powered-By: PHP/8 is a version disclosure. Version 2 required a dotted
    # version and so reported this as an OK line.
    finding warn "leak/version-major" "$leak" "$value (a major version is still a version)"
  else
    finding note "leak/platform" "$leak" "$value (names the software, no version)"
  fi
done

if [ "$(hcount "x-pingback")" -gt 0 ]; then
  finding warn "leak/pingback" "X-Pingback" "advertises the XML-RPC endpoint"
else
  ok "X-Pingback" "absent"
fi

if hvals "link" | grep -qi 'api\.w\.org'; then
  finding note "leak/rest-root" "Link" \
    "advertises the REST API root, from which the users endpoint is one request away"
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
