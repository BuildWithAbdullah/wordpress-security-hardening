# Session cookies and shared caches

The two areas version 3 added to the header judge, and the reason they were
worth adding is that they are the findings on this list a reader is most likely
to have never been told about. Every WordPress hardening guide covers
`X-Frame-Options`. Almost none of them covers what happens when a response
carrying a login cookie reaches a CDN.

## The one that actually loses accounts

A response that sets a session cookie and permits storage by a shared cache can
be stored by that cache, `Set-Cookie` and all, and handed to the next visitor.
That visitor is then logged in as somebody else.

This is not exotic. It is a configuration away on any WordPress site behind a
CDN, and the usual route to it is somebody switching on full-page caching to
fix a speed complaint, then widening the rules because an edge case was not
being cached, and eventually marking something `public` that sets a cookie.

```
HTTP/2 200
cache-control: public, max-age=600
set-cookie: wordpress_logged_in_9f2c=...; Path=/; Secure; HttpOnly; SameSite=Lax
```

Every attribute on that cookie is correct. It is still a serious bug, and this
is the point: cookie hygiene and cache directives are two separate controls and
getting one right does nothing for the other.

Reported as `cache/session-cookie-publicly-cacheable`, at error level. The
judge reports it when the response sets a cookie it recognises as a session
cookie and the `Cache-Control` either says `public`, or carries a positive
`s-maxage`, which is an instruction aimed at shared caches specifically, or
carries a positive `max-age` with no `private`, `no-store` or `no-cache`
alongside it.

A response that sets a session cookie and sends no `Cache-Control` at all gets
`cache/no-directive-with-session-cookie`, at warning level rather than error.
Many shared caches do refuse to store a response carrying `Set-Cookie`. None of
them promises to, the behaviour differs between products, and it changes between
versions, so the absence of a directive is a gap rather than a defect.

What a WordPress site should send on anything carrying a session:

```
Cache-Control: private, no-store, max-age=0
```

`mu-plugins/00-security-headers.php` sends `no-store, max-age=0` on the login
page and in the admin for exactly this reason, and deliberately does not touch
front-end responses, because setting `no-store` there would disable every page
cache on the site. That is a performance incident dressed up as a security
control.

## Which cookies the judge will say anything about

Only the ones it can name:

- `wordpress_logged_in_*`
- `wordpress_sec_*`
- `wordpress_<32 hex characters>`
- `wp-postpass_*`
- `wp_woocommerce_session_*`
- `PHPSESSID`

A site with a custom session cookie name gets nothing said about it, and that
is a declared limit rather than an oversight. The alternative is inferring from
the absence of attributes, which would report every analytics and consent cookie
on every site, and a checker that is wrong about most of what it reports is a
checker nobody reads.

Cookie prefix rules are the exception: `__Secure-` and `__Host-` are checked on
any cookie, because a browser refuses a cookie that breaks its own prefix rule
outright, so the breakage is real whatever the cookie is for.

## The attributes, and what each one is actually for

**`Secure`.** The cookie is sent only over HTTPS. Without it, the cookie goes
on any later plain HTTP request to the same host, including one an attacker
causes by injecting an `http://` image into a page. Reported as
`cookie/no-secure` at error level, on an HTTPS response.

**`HttpOnly`.** Script cannot read the cookie. This is the attribute that makes
a cross-site scripting bug something short of a full account takeover, and it is
the one most often missing on cookies a plugin sets itself. Reported as
`cookie/no-httponly` at error level.

**`SameSite`.** Reported as `cookie/no-samesite` at warning rather than error,
because the current default in the major engines is `Lax` and the gap is
narrower than it was. Stating it explicitly is still the only way to know, and
browser defaults here have changed more than once.

**`SameSite=None` without `Secure`** is a different finding and it is an error:
browsers reject the cookie outright. A site in this state is not less secure, it
is not working, and the symptom is a login that silently fails to persist.
Reported as `cookie/samesite-none-insecure`.

**`Domain`.** Any `Domain` attribute widens the cookie from one host to every
host under it, including a staging or legacy subdomain that may be running
something older. The leading dot is not what decides this: RFC 6265 ignores a
leading dot, so `Domain=example.com` and `Domain=.example.com` behave the same
and both are wider than no `Domain` at all. Reported as
`cookie/domain-too-broad` at warning level, because on a multisite install it is
often deliberate.

That last one is worth noticing as a correction. The check originally compared
the attribute against the host and reported nothing when they matched, which is
the commonest form of the problem.

**The same cookie set twice** with different attributes gets
`cookie/conflict`. The browser keeps the last one, so which attributes apply
depends on which line was appended last, and nothing about HTTP makes that order
meaningful. This is the same reasoning as the duplicate-header findings: a
verdict should not be decided by an order nothing promises.

## What this does not cover

Nothing here inspects a cookie's value, its lifetime, or whether the session it
refers to is still valid server side. Session fixation, session length and
revocation on password change are application concerns and are invisible in a
header dump.

And as with everything in this repository, one URL is judged per run. A site can
set a correctly flagged cookie on the login page and a careless one on an
endpoint a plugin added, and checking the login page tells you nothing about the
second. See [06 What the checks do not see](06-what-the-checks-do-not-see.md).
