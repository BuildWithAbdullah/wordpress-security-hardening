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
./scripts/check-headers.sh https://example.com
```

Deploying a header and never checking the live response is a routine gap. The
script follows redirects, checks the five, notes whether a CSP is present, and
flags `X-Powered-By` and `Server` values that leak version information. It
exits non-zero when a required header is missing, so it works as a post-deploy
check.

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

## Permissions-Policy: check before you deny

```
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
```

Denying a feature the site actually uses breaks it silently, and the breakage
looks like an application bug rather than a header. Before deploying, check
for:

- a store locator or delivery estimator, which needs `geolocation`
- a video consultation or virtual try-on feature, which needs `camera` and
  `microphone`
- a payment integration using the Payment Request API, which needs `payment`

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
