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
# This file fetches. collect-decide.sh decides what the fetch produced.
# judge-headers.sh decides what the headers mean. Neither of those two needs a
# network, so both are driven by the test suite, and this file is left holding
# the one thing a test cannot reach: the request itself.
#
# Deploying a header and never checking the live response is a common and
# embarrassing gap: PHP-level headers are silently absent on responses served
# from a full-page cache that bypasses PHP, and on static assets served
# directly by the web server.
#
# Keep this file thin. tools/entry-thin.mjs fails the build when a decision
# appears here, because a decision in this file is a decision nothing can test.

set -u

# Resolve this file through any symlinks before looking for its siblings.
#
# dirname of BASH_SOURCE[0] is the directory of the symlink, not of the script,
# so the obvious one-liner broke the only sensible way to install a shell tool.
# Put a link to this file on PATH, which is what anybody would do, and every run
# printed "cannot find collect-decide.sh next to this script" and stopped. It
# worked from a checkout and failed once installed, which is the quietest kind
# of broken, and tools/exit-codes.mjs now runs the real script through a
# deliberately created symlink so it stays fixed.
resolve_self() {
  local src dir target
  src="${BASH_SOURCE[0]}"
  while [ -L "$src" ]; do
    dir="$(cd -P "$(dirname "$src")" > /dev/null && pwd)"
    target="$(readlink "$src")"
    case "$target" in
      /*) src="$target" ;;
      *)  src="$dir/$target" ;;
    esac
  done
  cd -P "$(dirname "$src")" > /dev/null && pwd
}

HERE="$(resolve_self)"
DECIDE="$HERE/collect-decide.sh"
JUDGE="$HERE/judge-headers.sh"

for required in "$DECIDE" "$JUDGE"; do
  if [ ! -r "$required" ]; then
    echo "cannot find $(basename "$required") next to this script" >&2
    exit 2
  fi
done

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

WORK="$(mktemp -d)"
PLAN="$WORK/plan"
DUMP="$WORK/dump"
META="$WORK/meta"
ARGS="$WORK/args"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

URL="$(bash "$DECIDE" plan "$PLAN" -- "$@")" || exit $?

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

bash "$DECIDE" finish --plan "$PLAN" --dump "$DUMP" --meta "$META" > "$ARGS" || exit $?

# The dump lives in the temporary directory the trap removes, so the judge has
# to run before this shell ends. Read the argument list into an array and run
# it, rather than exec, so the trap still fires.
JUDGE_ARGS=()
while IFS= read -r line; do
  JUDGE_ARGS+=( "$line" )
done < "$ARGS"

# Invoked through bash rather than executed directly, and the reason is not
# style. A repository whose files arrive by any route that does not carry file
# modes, which includes a source zip and GitHub's own web upload, has shell
# scripts at mode 644. Depending on the executable bit means the tool is broken
# for some ways of obtaining it and works for others, which is the worst kind
# of bug to be told about.
bash "$JUDGE" "${JUDGE_ARGS[@]}"
