#!/usr/bin/env bash
#
# collect-decide.sh
#
# Every decision scripts/check-headers.sh used to make, in a file that makes no
# network request and can therefore be driven by the test suite.
#
#   ./collect-decide.sh plan <plan-file> -- <check-headers arguments>
#   ./collect-decide.sh finish --plan <plan-file> --dump <file> --meta <file>
#
# ---------------------------------------------------------------------------
# Why this file exists
#
# check-headers.sh fetches a URL and hands the result to judge-headers.sh. The
# judging was split out in version 2 for a good reason: while fetching and
# judging were one file, no verdict in it could be reached without a live site,
# so none of them had ever been checked.
#
# The same argument applies a second time and version 2 did not finish the job.
# What was left in the fetching script was not only the fetch. It parsed the
# options, decided what counted as an unusable response, decided when to warn
# that the headers probably belong to an error page, and decided where --save
# writes. Those are decisions, they sit beside a curl call, and so the only
# coverage any of them had was `bash -n`. A file that is only syntax checked has
# no coverage at all, and --save had already shipped broken once: the EXIT trap
# that was supposed to clean up ran before the copy, so the option quietly did
# nothing.
#
# So the decisions are here, taking their inputs as file paths, and the fetching
# script is reduced to wiring. tools/entry-thin.mjs fails the build if a
# decision moves back.
#
# The plan file is key=value lines, read with a strict parser rather than
# sourced. Sourcing it would let a URL containing a semicolon run as shell.

set -u

usage() {
  cat >&2 <<'USAGE'
usage:
  collect-decide.sh plan <plan-file> -- <check-headers arguments>
  collect-decide.sh finish --plan <plan-file> --dump <file> --meta <file>
USAGE
  exit 2
}

# Everything after the double dash, parsed the way check-headers.sh used to
# parse it. A URL is required, --json is passed through to the judge, --save
# names a file the dump is copied to.
do_plan() {
  local plan_file="$1"; shift
  [ -n "$plan_file" ] || usage

  if [ "${1:-}" = "--" ]; then shift; fi

  local url="" save="" json=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=1 ;;
      --save)
        shift
        if [ $# -eq 0 ]; then
          echo "--save needs a file name" >&2
          return 2
        fi
        save="$1"
        ;;
      -h|--help) usage ;;
      -*)
        echo "unknown option: $1" >&2
        return 2
        ;;
      *)
        if [ -n "$url" ]; then
          echo "more than one URL given: $url and $1" >&2
          return 2
        fi
        url="$1"
        ;;
    esac
    shift
  done

  if [ -z "$url" ]; then
    echo "a URL is required" >&2
    return 2
  fi

  # A bare host is the mistake people actually make, and curl would treat it as
  # a path. Saying so beats fetching something unexpected.
  case "$url" in
    http://*|https://*) : ;;
    *)
      echo "the URL needs a scheme: ${url}" >&2
      return 2
      ;;
  esac

  # A save path is written to before anything is judged, so refuse one that
  # would be ambiguous rather than discovering it after the fetch.
  case "$save" in
    -*)
      echo "--save needs a file name, not an option: ${save}" >&2
      return 2
      ;;
  esac

  {
    printf 'url=%s\n' "$url"
    printf 'save=%s\n' "$save"
    printf 'json=%s\n' "$json"
  } > "$plan_file" || {
    echo "could not write the plan to ${plan_file}" >&2
    return 2
  }

  printf '%s\n' "$url"
  return 0
}

plan_value() {
  awk -F'=' -v k="$2" 'index($0, k "=") == 1 { print substr($0, length(k) + 2) }' "$1"
}

# Decide what the fetch produced, write the saved copy if one was asked for, and
# print the judge's argument list, one argument per line.
do_finish() {
  local plan_file="" dump="" meta=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --plan) shift; [ $# -gt 0 ] || usage; plan_file="$1" ;;
      --dump) shift; [ $# -gt 0 ] || usage; dump="$1" ;;
      --meta) shift; [ $# -gt 0 ] || usage; meta="$1" ;;
      *) usage ;;
    esac
    shift
  done

  [ -n "$plan_file" ] && [ -n "$dump" ] && [ -n "$meta" ] || usage

  for f in "$plan_file" "$dump" "$meta"; do
    if [ ! -f "$f" ]; then
      echo "no such file: $f" >&2
      return 2
    fi
  done

  local url save json final_url status
  url="$(plan_value "$plan_file" url)"
  save="$(plan_value "$plan_file" save)"
  json="$(plan_value "$plan_file" json)"

  final_url="$(sed -n '1p' "$meta")"
  status="$(sed -n '2p' "$meta")"

  # An empty dump means the request completed and carried no headers, which is
  # not something to judge. Version 2 reported this and it is kept, because it
  # is the difference between a site with no security headers and a transfer
  # that produced nothing.
  if [ ! -s "$dump" ]; then
    echo "Fetched ${url} but received no headers" >&2
    return 1
  fi

  if [ -z "$final_url" ]; then
    echo "The fetch did not report an effective URL, so HSTS cannot be judged" >&2
    final_url=""
  fi

  # Written before anything else can fail, and written explicitly rather than
  # from a trap. The handoff at the end of check-headers.sh is an exec, which
  # replaces the shell, so an EXIT trap never runs and a --save done that way
  # quietly does nothing. That had shipped.
  if [ -n "$save" ]; then
    if ! cp "$dump" "$save" 2>/dev/null; then
      echo "could not write ${save}" >&2
      return 2
    fi
    echo "Saved the response headers to ${save}" >&2
  fi

  # A header set from an error page is not the header set of the site, and
  # judging it produces findings about a page nobody visits.
  case "$status" in
    2*) : ;;
    '')  echo "Warning: the fetch did not report a status code." >&2 ;;
    *)   echo "Warning: final response status is ${status}, so these headers may be an error page's." >&2 ;;
  esac

  printf '%s\n' "$dump"
  if [ -n "$final_url" ]; then
    printf -- '--url\n'
    printf '%s\n' "$final_url"
  fi
  if [ "$json" = "1" ]; then
    printf -- '--json\n'
  fi
  return 0
}

[ $# -gt 0 ] || usage

mode="$1"; shift

case "$mode" in
  plan)   do_plan "$@" ;;
  finish) do_finish "$@" ;;
  *)      usage ;;
esac
