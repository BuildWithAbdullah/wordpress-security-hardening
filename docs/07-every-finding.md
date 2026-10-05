# Every finding

Generated from `tools/catalogue.mjs` by `npm run docs`. Do not edit by hand.

This is the complete list of what `scripts/judge-headers.sh` can report, and
`test/catalogue.test.mjs` drives every entry out of a real run of the real
script. A finding that cannot be produced does not stay on the list, and a
finding the script produces that is not on the list fails the suite.

What the findings do **not** cover is in
[06 What the checks do not see](06-what-the-checks-do-not-see.md). Read that
before putting any of this in front of a client.

## Levels

| Level | Meaning |
|---|---|
| `error` | Fails the run. Exit code 1. |
| `warn` | Reported, does not fail the run. |
| `note` | Reported for the record. |

Only an error changes the exit code. A post-deploy check that fails the build
over a version string in a `Server` header is a check somebody switches off.

## Findings (15)

### `missing/x-content-type-options`

Level: `error`.

X-Content-Type-Options was not sent on the final response.

### `weak/x-content-type-options`

Level: `error`.

Sent, but the value is not nosniff, which is the only value that does anything.

### `missing/x-frame-options`

Level: `error`.

X-Frame-Options was not sent on the final response.

### `weak/x-frame-options`

Level: `error`.

Sent with a value that permits framing, such as ALLOWALL, or with the obsolete ALLOW-FROM.

### `missing/referrer-policy`

Level: `error`.

Referrer-Policy was not sent on the final response.

### `weak/referrer-policy`

Level: `error`.

Sent as unsafe-url, or empty, so the full URL goes to every destination.

### `missing/permissions-policy`

Level: `error`.

Permissions-Policy was not sent on the final response.

### `weak/permissions-policy`

Level: `error`.

Sent with an empty or letterless value, so no browser feature is restricted.

### `missing/strict-transport-security`

Level: `error`.

The final response is HTTPS and sent no HSTS header.

### `weak/strict-transport-security`

Level: `warn`.

max-age is under 30 days, which is a staging value left in production, or absent from the header.

### `disabled/strict-transport-security`

Level: `error`.

max-age=0, which switches HSTS off. That is the back-out value, not a deployment.

### `transport/not-https`

Level: `warn`.

The final URL is not HTTPS, so HSTS could not be judged at all.

### `csp/absent`

Level: `note`.

No Content-Security-Policy. Deliberately a note: on a page-builder site, not deploying one is often the right call.

### `csp/unsafe-inline`

Level: `warn`.

A CSP is present and permits unsafe-inline, which allows the injection the policy was deployed to stop.

### `leak/pingback`

Level: `warn`.

X-Pingback advertises the XML-RPC endpoint in every response.

## Open families (2)

These carry a value read from the response, so the set of concrete messages is
not finite. The suite requires each family to be produced rather than listing
every message it can produce.

### `redirect-only`

Level: `error`. Carries the header name.

A required header is sent on a redirect hop but not on the final response. Any checker that searches the whole dump calls this a pass.

### `leak/version`

Level: `warn`. Carries the header name and its value.

A response header gives away a software version, for example Server or X-Powered-By. Presence alone is not the finding.
