# Every finding

Generated from `tools/catalogue.mjs` by `npm run docs`. Do not edit by hand.

This is the complete list of what `scripts/judge-headers.sh` can report, and
`test/catalogue.test.mjs` drives every entry out of a real run of the real
script. A finding that cannot be produced does not stay on the list, and a
finding the script produces that is not on the list fails the suite.

One entry per reason, not one per check. A check that refuses a response for
four different reasons is four entries, because the fix is different in each
case and because a fixture written per reason is what proves the reason is
reachable at all.

What the findings do **not** cover is in
[06 What the checks do not see](06-what-the-checks-do-not-see.md). Read that
before putting any of this in front of a client.

## Severities

| Severity | Meaning |
|---|---|
| `error` | Fails the run. Exit code 1. |
| `warn` | Reported, does not fail the run. |
| `note` | Reported for the record. |

Each entry below declares the complete set of severities it can carry, and the
suite asserts that set in both directions: a severity a real run produces that
is not declared fails the build, and a severity declared here that no test has
ever produced fails it too.

Only an error changes the exit code. A post-deploy check that fails the build
over a version string in a `Server` header is a check somebody switches off.

## The findings (48 across 8 areas)

### required (17)

The response headers that should be on every page.

#### `missing/x-content-type-options`

Severity: `error`.

**When.** X-Content-Type-Options is not sent on the final response, and no redirect hop carried it either.

Without it, a file served as text/plain that happens to contain markup can be sniffed and executed as HTML. Any site with a media library accepts uploads.

#### `empty/x-content-type-options`

Severity: `error`.

**When.** X-Content-Type-Options is sent with nothing after the colon.

A separate reason from a weak value, and a separate fix. An empty header is almost always a plugin writing a setting it was never given, and it satisfies every check that only asks whether the name appears.

#### `weak/x-content-type-options`

Severity: `error`.

**When.** X-Content-Type-Options is sent with a value other than nosniff.

nosniff is the only value the header has. Anything else is a value somebody typed.

#### `conflict/x-content-type-options`

Severity: `error`.

**When.** X-Content-Type-Options is sent more than once with values that do not agree.

HTTP combines repeated field lines into one comma-separated value, so the browser sees neither of the two values that were sent. Reported as its own reason because no order between them is meaningful and a checker that picks one is deciding the verdict by luck.

#### `missing/x-frame-options`

Severity: `error`.

**When.** X-Frame-Options is not sent on the final response, and no redirect hop carried it either.

Clickjacking. Note that a CSP frame-ancestors directive supersedes this header where both are present, so read csp/frame-ancestors-permissive beside this one.

#### `empty/x-frame-options`

Severity: `error`.

**When.** X-Frame-Options is sent with nothing after the colon.

An empty X-Frame-Options permits framing and passes a presence check.

#### `weak/x-frame-options`

Severity: `error`.

**When.** X-Frame-Options is sent with a value that permits framing.

ALLOWALL permits framing by anyone and ALLOW-FROM was never implemented by more than one browser and is obsolete. A permissive value that passes a check is worse than a missing header, because the check is what stops anyone looking again.

#### `conflict/x-frame-options`

Severity: `error`.

**When.** X-Frame-Options is sent more than once with values that do not agree.

The combined value is not one of the two the server sent, and browsers apply no framing protection for a value they cannot parse. Version 2 took the last line and so reported a response carrying ALLOWALL and SAMEORIGIN as a pass or a failure depending which came first.

#### `missing/referrer-policy`

Severity: `error`.

**When.** Referrer-Policy is not sent on the final response, and no redirect hop carried it either.

The browser default is no-referrer-when-downgrade in most engines, which still sends the full URL to every HTTPS destination.

#### `empty/referrer-policy`

Severity: `error`.

**When.** Referrer-Policy is sent with nothing after the colon.

An empty value falls back to the browser default, which is the thing the header was deployed to replace.

#### `weak/referrer-policy`

Severity: `error`.

**When.** Referrer-Policy is sent with a token that sends the full URL cross-origin.

unsafe-url sends the whole URL, including a path that may carry a reset token or an order id, to every destination.

#### `conflict/referrer-policy`

Severity: `error`.

**When.** Referrer-Policy is sent more than once with values that do not agree.

Referrer-Policy is a token list and a browser takes the last token it recognises, so two headers mean the effective policy depends on which proxy appended its line last.

#### `missing/permissions-policy`

Severity: `error`.

**When.** Permissions-Policy is not sent on the final response, and no redirect hop carried it either.

Nothing is restricted, so an injected script can reach for geolocation, camera, microphone and the payment request API.

#### `empty/permissions-policy`

Severity: `error`.

**When.** Permissions-Policy is sent with nothing after the colon.

Several caching and security plugins emit this header with nothing after it. It restricts no feature and satisfies any check that only asks whether the name appears, which is why it has its own reason.

#### `weak/permissions-policy`

Severity: `error`.

**When.** Permissions-Policy is sent with a value that contains no directive name.

A value with no letters in it, such as a stray comma or a bare asterisk, names no feature and therefore restricts none.

#### `conflict/permissions-policy`

Severity: `error`.

**When.** Permissions-Policy is sent more than once with values that do not agree.

The combined list is parsed as one structured header and a repeated feature name makes the whole header invalid in some engines, so the restriction silently disappears.

#### `redirect-only`

Severity: `error`.
Carries the header name.

**When.** The header appears in the dump but not in the hop the visitor receives.

A required header is sent on a redirect hop and not on the final response. Any checker that searches the whole dump calls this a pass, and version 1 of this script did.

### hsts (6)

Strict-Transport-Security, which is the one that cannot be undone remotely.

#### `missing/strict-transport-security`

Severity: `error`.

**When.** The final response is HTTPS and sent no HSTS header.

Every first visit over HTTP, and every visit from a link that is still HTTP, is interceptable.

#### `hsts/no-max-age`

Severity: `error`.

**When.** The header is present and carries no readable max-age directive.

max-age is the only required directive. Without it the browser ignores the whole header, so the site has the appearance of HSTS and none of it. Note that a quoted value is legal: version 2 rejected max-age="31536000" as unreadable, which is a browser-honoured header reported as a failure.

#### `hsts/disabled`

Severity: `error`.

**When.** The HSTS header is present and its max-age directive is zero.

Zero is how HSTS is backed out, not how it is deployed. It tells every browser that has the policy to forget it.

#### `hsts/short-max-age`

Severity: `warn`.

**When.** max-age is above zero but under 30 days.

A staging value left in production. A warning rather than an error, because starting short is the correct way to deploy HSTS and a check that fails the build for it is a check somebody switches off.

#### `hsts/conflict`

Severity: `error`.

**When.** More than one Strict-Transport-Security header is present.

RFC 6797 says the browser processes only the first one. Version 2 read the last, so a response sending max-age=0 and then a year was reported clean while every browser switched HSTS off. This is the reason the duplicate cases exist as findings at all.

#### `hsts/preload-without-subdomains`

Severity: `error`.

**When.** preload is present without includeSubDomains, or with a max-age under a year.

The preload list refuses a submission that does not carry both, so the site is not preloaded and nobody is told. The token is in the header, the certificate lapse risk has been taken, and the benefit was never collected.

### csp (7)

Content-Security-Policy, including its interaction with X-Frame-Options.

#### `csp/absent`

Severity: `note`.

**When.** No Content-Security-Policy header.

Deliberately a note. On a page-builder site, not deploying one is often the right call, and a tool that fails the build over it is a tool whose output gets skimmed.

#### `csp/unsafe-inline`

Severity: `warn`.

**When.** A policy is present and permits unsafe-inline for scripts.

This permits exactly the injection a CSP is deployed to stop. Common on WordPress because the block editor and most page builders emit inline script.

#### `csp/unsafe-eval`

Severity: `warn`.

**When.** A policy is present and permits unsafe-eval.

A separate reason from unsafe-inline and a separate fix: this one is usually one named library, and finding it is a different job from removing inline handlers.

#### `csp/wildcard-script-src`

Severity: `warn`.

**When.** script-src, or default-src standing in for it, permits any host.

A wildcard or a bare scheme source permits script from anywhere that scheme can reach, which is every host. The policy still appears in a report as deployed.

#### `csp/report-only-only`

Severity: `warn`.

**When.** A Report-Only policy is present and no enforcing policy is.

Report-Only enforces nothing by design. It is the right first step and a common last one: the header is in the response, it shows up in any audit that greps for a policy, and it has never blocked anything.

#### `csp/conflict`

Severity: `warn`.

**When.** More than one enforcing Content-Security-Policy header is present.

Browsers apply every policy, so the effective policy is the intersection and is stricter than either author intended. This is a breakage risk rather than a weakness, and it is the usual cause of a page that works until a plugin or a CDN adds its own policy.

#### `csp/frame-ancestors-permissive`

Severity: `error`.

**When.** The policy sets frame-ancestors to a value that permits framing.

frame-ancestors supersedes X-Frame-Options in every current browser, so a correct X-Frame-Options sent beside it is not what applies. A site can therefore pass an X-Frame-Options check and be framable, which is why this is an error rather than a warning.

### cookie (7)

Attributes on the cookies that carry a WordPress session.

#### `cookie/no-secure`

Severity: `error`.

**When.** A session cookie is set on an HTTPS response without the Secure attribute.

The cookie is sent on any later plain HTTP request to the same host, including one an attacker causes by injecting an http:// image.

#### `cookie/no-httponly`

Severity: `error`.

**When.** A session cookie is set without HttpOnly.

Any injected script can read the session. HttpOnly is what makes a cross-site scripting bug something short of a full account takeover.

#### `cookie/no-samesite`

Severity: `warn`.

**When.** A session cookie is set without an explicit SameSite attribute.

Browser defaults differ and have changed more than once. A warning rather than an error because the current default in the major engines is Lax, so the gap is narrower than it was, and stating it explicitly is still the only way to know.

#### `cookie/samesite-none-insecure`

Severity: `error`.

**When.** A cookie declares SameSite=None without Secure.

Browsers reject the cookie outright. This breaks the login as well as weakening it, which is why it is an error: the site is not less secure, it is not working.

#### `cookie/prefix-violation`

Severity: `error`.

**When.** A cookie named with the __Secure- or __Host- prefix does not meet that prefix rule.

__Secure- requires Secure. __Host- requires Secure, requires Path=/ and forbids Domain. A browser silently refuses a cookie that breaks its own prefix rule, so the name that was chosen to make the cookie safer is what stops it being set.

#### `cookie/domain-too-broad`

Severity: `warn`.

**When.** A session cookie is scoped to a parent domain.

A cookie set on .example.com is sent to every subdomain, including a staging or legacy host that may be running something older. On a multisite install this is often deliberate, which is why it is a warning.

#### `cookie/conflict`

Severity: `warn`.

**When.** The same cookie name is set twice in one response with different attributes.

The browser keeps the last one, so the attributes that end up applying depend on which line was appended last. Like the other conflict reasons, the point is that the verdict should not be decided by an order nothing promises.

### cache (2)

Whether a response carrying a session may be stored by a shared cache.

#### `cache/session-cookie-publicly-cacheable`

Severity: `error`.

**When.** A response that sets a session cookie permits storage by a shared cache.

A CDN or reverse proxy may store the response, Set-Cookie and all, and hand it to the next visitor. This is how one user ends up logged in as another, and it is a configuration away on every WordPress site behind a CDN.

#### `cache/no-directive-with-session-cookie`

Severity: `warn`.

**When.** A response sets a session cookie and sends no Cache-Control at all.

With no directive a shared cache applies its own heuristics, which differ between products and change between versions. A warning rather than an error because many caches do refuse to store a response carrying Set-Cookie, and none of them promise to.

### leak (5)

Headers that give away more than they need to.

#### `leak/pingback`

Severity: `warn`.

**When.** X-Pingback advertises the XML-RPC endpoint.

Every response tells a scanner where the endpoint is. Closing the endpoint matters more than hiding it, and both are cheap.

#### `leak/rest-root`

Severity: `note`.

**When.** A Link header advertises the REST API root.

A note, not a weakness: this is WordPress working as designed. It is here because the users endpoint is one request from that root, and hardening that endpoint is the other half of the author enumeration fix in mu-plugins/02-harden-login.php.

#### `leak/version`

Severity: `warn`.
Carries the header name and its value.

**When.** A response header gives away a software version with more than one component.

Presence alone is not the finding. Version 1 flagged Server on presence, so every site behind a CDN got a line for Server: cloudflare, and a tool that cries wolf on a header nearly every server sends is a tool whose output gets skimmed.

#### `leak/version-major`

Severity: `warn`.
Carries the header name and its value.

**When.** A response header gives away a single-component version.

X-Powered-By: PHP/8 is a version disclosure and version 2 reported it as clean, because the check required a dotted version. A separate reason because the remedy is the same but the detection is what was wrong.

#### `leak/platform`

Severity: `note`.
Carries the header name and its value.

**When.** A response header names the software without a version.

A note. Server: nginx or X-Redirect-By: WordPress tells a scanner what to try without telling it what to try first. Version 2 printed an OK line for these, which reads as approval of a header that did not need to be sent.

### transport (2)

Whether the transport could be established well enough to judge HSTS.

#### `transport/not-https`

Severity: `warn`.

**When.** The final URL is HTTP, so HSTS could not be judged.

Nothing about HSTS can be concluded from a plain HTTP response, and guessing would produce a confident finding about a header the browser would have ignored.

#### `transport/url-unknown`

Severity: `warn`.

**When.** No final URL was given and the dump does not carry an absolute one.

Version 2 assumed HTTPS here, and separately treated a relative Location as a non-HTTPS URL, so a dump whose last redirect was to /en/ produced a transport warning and skipped the HSTS checks entirely on a response that had a perfectly good HSTS header. Refusing to decide is the honest answer: a guess is worse than a refusal when the finding looks specific.

### dump (2)

The shape of the dump itself, where it changes how much the findings are worth.

#### `dump/folded-header`

Severity: `note`.

**When.** A header value is continued on a following line.

The value is joined before judging, and this note says so, because a tool that silently unfolds is a tool whose output you cannot reconcile against the raw dump. Version 2 did not unfold at all, so a policy whose unsafe-inline sat on the continuation line was reported clean.

#### `dump/empty-final-hop`

Severity: `error`.

**When.** The final hop has a status line and no header lines.

Almost always a dump truncated mid-write rather than a site that sends no headers. The missing findings beside this one are therefore not worth acting on, and saying that is more useful than six confident errors about a file that was cut short.

## Open families

These carry a value read from the response, so the set of concrete messages is
not finite. The suite requires each family to be produced rather than listing
every message it can produce. They are listed above under their own areas, and
are named here together so the distinction is visible:

- `redirect-only`, which carries the header name
- `leak/version`, which carries the header name and its value
- `leak/version-major`, which carries the header name and its value
- `leak/platform`, which carries the header name and its value
