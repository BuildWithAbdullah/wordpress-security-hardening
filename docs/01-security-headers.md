# Security headers

Five headers are safe to deploy on essentially any WordPress site. A sixth,
Content Security Policy, is not, and knowing why is more useful than the other
five combined.

## The five

| Header | Value | Risk |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | None |
| `X-Frame-Options` | `SAMEORIGIN` | Breaks legitimate external embedding |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | None |
| `Permissions-Policy` | deny what the site does not use | Breaks features you failed to check for |
| `Strict-Transport-Security` | `max-age=31536000` | Hard to undo, see below |

[`mu-plugins/00-security-headers.php`](../mu-plugins/00-security-headers.php)
sends all five.

## Where to send them from

Prefer the web server or CDN. Headers sent from PHP are not applied to static
assets served directly by nginx or Apache, and are not applied to responses
served from a full-page cache that never boots PHP. On a cached WordPress site
that is most of your traffic.

The mu-plugin is the portable fallback for shared and managed hosting where you
have no server config. Use it, then verify against the live site rather than
assuming.

Why an mu-plugin rather than a normal plugin or `functions.php`: must-use
plugins load automatically, cannot be deactivated from the dashboard, and
survive theme changes and plugin updates. A client troubleshooting a problem by
deactivating plugins should not silently lose their security headers as a side
effect.

## Verify, always

```bash
bash scripts/check-headers.sh https://example.com
```

Deploying a header and never checking the live response is a routine gap. The
script makes one GET request, follows redirects, and hands the saved headers to
`scripts/judge-headers.sh`, which decides. It exits non-zero when a required
header is missing or carries a value that does nothing, so it works as a
post-deploy check.

Two things about it are worth knowing, because both were wrong in the first
version of this repository and both produced a confident pass rather than an
error.

It judges the **final** response only. A header sent on the redirect from
`http://` to `https://` and not on the page is reported as
`redirect-only`, not as present. Any checker that searches a whole redirect
chain for a header name will tell you that site is covered.

It checks **values**, not just presence. `X-Frame-Options: ALLOWALL` is a
finding, because a permissive value that passes a check is worse than a missing
header: the check is what stops anyone looking again.

To judge a response you already have, with no request made at all:

```bash
bash scripts/judge-headers.sh saved.headers --url https://example.com/
bash scripts/judge-headers.sh saved.headers --url https://example.com/ --json
```

Every finding either script can emit is listed in
[07 Every finding](07-every-finding.md).

## HSTS deserves its own paragraph

Once a browser has seen `Strict-Transport-Security`, that browser will refuse
to reach the site over HTTP for the duration of `max-age`. There is no remote
undo. If the certificate later lapses, visitors get a hard error with no
click-through.

So:

1. Confirm HTTPS works on every hostname the site answers on.
2. Confirm the certificate renews automatically.
3. Deploy with a short `max-age`, say 300.
4. Raise it to a year once you have watched a renewal succeed.

Leave `includeSubDomains` off unless you have audited every subdomain. It
applies to all of them, including the staging subdomain nobody remembered,
and to any legacy service still on HTTP.

Leave `preload` off too, unless you are submitting the site to the preload
list and have read what that commits you to. The list refuses a submission
that does not carry `includeSubDomains` and a `max-age` of at least a year, so
a header carrying `preload` without both has taken the risk of preloading and
collected none of the benefit. `scripts/judge-headers.sh` reports that as
`hsts/preload-without-subdomains`.

### Backing it out

This is the part that is easy to get wrong, and the plugin got it wrong until
version 3.

HSTS lives in the browser, not in the response. Once a browser has seen the
header it refuses to reach the site over HTTP for the rest of the original
`max-age`, and nothing the site stops doing changes that. **Sending no header
is not a withdrawal.** It is silence, and the policy carries on applying.

The only way to withdraw HSTS is to serve `max-age=0` and keep serving it
until the old policy has expired in every browser that saw it. So:

```php
define( 'WPSH_HSTS_MAX_AGE', 0 );   // withdraw: sends max-age=0
define( 'WPSH_HSTS', false );       // send no header at all
```

Those are two different instructions and version 2 had them sharing one
setting, which meant the one operator who most needed the header sent, somebody
whose certificate was about to lapse and who had worked out they needed to back
the policy out, was the one it refused to send it for.

`max-age=0` left in place is itself a finding, reported as `hsts/disabled` at
error level, so a withdrawal that was never finished fails the next
post-deploy check rather than sitting there as a site that quietly has no
HSTS.

## Permissions-Policy: check before you deny

The default the plugin sends:

```
Permissions-Policy: geolocation=(), camera=(), microphone=(), usb=()
```

Denying a feature the site actually uses breaks it silently, and the breakage
looks like an application bug rather than a header. Before deploying, check
for:

- a store locator or delivery estimator, which needs `geolocation`
- a video consultation or virtual try-on feature, which needs `camera` and
  `microphone`

### Why payment is not in the default any more

Version 2 of the plugin sent `payment=()` as part of the default, and that was
a defect rather than a conservative choice. `payment=()` switches off the
Payment Request API, which is what Apple Pay, Google Pay and every other wallet
button is built on, so installing a file whose first line promises headers that
are safe on essentially any WordPress site removed the express checkout from
any store that installed it.

The failure has the worst available shape. Nothing errors, nothing appears in a
log, and the express button is simply not rendered, which reads as a theme
problem or a payment gateway problem. It gets found weeks later by somebody
comparing conversion rates, and by then nobody connects it to a security
change.

The principle it illustrates decides the rest of the list. A file meant to be
installed without reading it has to default to the restrictions whose absence
costs nothing and whose presence breaks nothing. `geolocation`, `camera` and
`microphone` qualify: a store locator, a video consultation and a voice search
all need one of them, but none of them exists on a site that has not
deliberately built it, so the feature and the person who built it are both
findable. A wallet checkout is different. It arrives with the payment gateway,
nobody builds it, and most store owners do not know it is a browser feature at
all.

A site with no wallet checkout should restrict it, deliberately:

```php
define( 'WPSH_PERMISSIONS_POLICY', 'geolocation=(), camera=(), microphone=(), payment=(), usb=()' );
```

## Content Security Policy: why it is deliberately omitted

A properly configured CSP is the strongest header on the list. It is also the
one most likely to take a site down, and on a typical WordPress build the
honest answer is often that it should not be deployed at all in the time
available.

A conventional WordPress site with a page builder loads inline styles and
inline scripts generated at render time, plus a tag manager, plus an
analytics script, plus a pixel or two, plus whatever a marketing team added
last quarter. A CSP strict enough to be worth having blocks most of that.

The components that reliably break under a first CSP attempt:

- **Page builders.** Elementor, Divi, WPBakery and the block editor all emit
  inline `style` attributes and inline scripts.
- **Tag managers.** Google Tag Manager exists to inject arbitrary third-party
  script. A CSP that permits it permits everything it can load, which
  substantially defeats the point.
- **Marketing pixels.** Each one is another origin, and they change without
  telling you.
- **Accessibility overlays and chat widgets.** Both inject script and style at
  runtime.

Making that work means either enumerating every origin and maintaining that
list forever, or using nonces, which means every inline script has to be
generated through a mechanism that can apply one. On a site whose inline
scripts come from three plugins and a page builder, that is not a header
change, it is a rebuild.

**Not deploying a CSP is a legitimate engineering decision, and it should be
written down as one.** A report that says

> Content Security Policy was not deployed. The site's page builder, tag
> manager and two marketing pixels all rely on inline and third-party script
> that a meaningful policy would block. Deploying one would require a scripted
> nonce mechanism and an origin inventory, which is a separate piece of work.
> The five headers above are in place and verified.

is worth more than a permissive CSP full of `unsafe-inline` that provides no
protection and creates the impression of protection.

## If a CSP is in scope

Do it in report-only mode first, for weeks, not days.

```
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

Collect violations across real traffic, including logged-in admin sessions and
the checkout flow, then build the policy from what you observed. Move to
enforcing only when the report stream is quiet. Expect that to take longer than
the client expects, and quote it separately.
