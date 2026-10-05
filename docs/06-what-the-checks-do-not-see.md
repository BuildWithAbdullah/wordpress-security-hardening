# What the checks do not see

Every other document here describes something the repository can demonstrate.
This one is the list of things it cannot, and it is the document worth reading
before quoting any of this back to a client.

A hardening report that only contains findings reads as a complete picture of
the site's security. It is not one, and the gap between those two things is
where a client's expectations get set wrongly.

## The header judge

`scripts/judge-headers.sh` reads one response. That is a narrower claim than it
looks.

**It judges one URL.** Headers on a WordPress site are frequently not uniform.
The home page is served from a full-page cache that never boots PHP, so a
PHP-level header is absent there and present on an uncached page such as the
cart or a logged-in view. The reverse happens too: a CDN adds headers at the
edge for HTML and not for anything else. Checking the home page and reporting
"headers are deployed" is wrong on a large share of real sites. Run it against
an uncached URL as well, and against a static asset, and say which you checked.

**It cannot see what a header does to the site.** `Permissions-Policy` with
`geolocation=()` is correct on most sites and breaks a store locator. There is
no way to tell from the response which kind of site you are looking at. The
same is true of `X-Frame-Options` on a site whose booking page is deliberately
embedded in a partner's. The tool reports the header; whether it is the right
header is a conversation.

**HSTS cannot be judged for safety, only for presence.** `max-age=31536000` is
reported as correct. Whether the certificate renews automatically, whether every
subdomain is on HTTPS, and whether the client can tolerate a hard failure if the
certificate lapses are the questions that actually matter, and none of them is
in a response header. `weak/strict-transport-security` on a short max-age is a
prompt to ask, not a defect on its own: a short max-age during a staged rollout
is the correct state to be in.

**`csp/absent` is a note on purpose.** Not deploying a Content Security Policy
on a page-builder site, and writing down why, is usually the right call. A
permissive policy full of `unsafe-inline` protects nothing and looks like
protection, which is why `csp/unsafe-inline` is a finding and absence is not.

**A `leak/version` finding is noise reduction, not a vulnerability.** Removing a
version from a header stops some automated scanners that filter by advertised
version. It does not stop anyone who is actually looking, and it must never be
reported in a way that implies the underlying component is now up to date.

**`redirect-only` exists because the tooling was wrong, not the site.** Any
checker that searches a whole redirect chain for a header name reports a pass
when the header is sent on the hop and not on the page. If you have used
another tool for this, that is worth testing before trusting it.

## The plugin probe

`lib/wp-shim.php` is a hook registry. It lets the suite load a real mu-plugin,
fire a real hook and assert on the real return value, with no WordPress, no
database and no web server. That covers the logic in these files completely and
leaves one thing uncovered, which is the important one.

**It cannot prove WordPress fires these hooks where the plugins assume.** The
suite shows that `login_init` sends the header set. It cannot show that
WordPress runs `login_init` before output on wp-login.php, because that is
WordPress's behaviour and not this repository's. That assumption is exactly the
class of thing that was wrong in version 1 of the headers plugin, where
`wp_headers` was assumed to cover the login page and does not.

So the suite is necessary and not sufficient. The live check against a deployed
site is what closes that gap, which is why `scripts/check-headers.sh` exists at
all and why `## Verifying` in the README tells you to run both.

**The shim implements only what the plugins call.** It is not a WordPress
emulator and adding behaviour to it that no plugin uses would be inventing
confidence.

**Capability checks are modelled, not real.** `current_user_can` in the shim
answers from a list the test supplied. Whether `list_users` is the right
capability for the REST users route on a particular site, with its particular
roles and whatever role editor plugin is installed, is a decision the trade-off
note in `02-harden-login.php` describes and the suite cannot make.

## The repository verifier

`tools/verify.mjs` checks the repository, not a site: that documentation quotes
the current code, that every test file is actually run, that the pure half of
the header script has stayed pure, that an example has both sides. It is there
because a repository can rot while staying green. It says nothing at all about
whether any of this is deployed anywhere.

## What none of it covers

The three mu-plugins and one script here are application-level hardening, and
that is a slice of the job. Not covered anywhere in this repository, and worth
saying out loud in any report that cites it:

- Updates. Nothing here keeps WordPress, a theme or a plugin current, and an
  out-of-date component is the way most sites are actually compromised.
- Backups, and specifically whether a restore has ever been performed. An
  untested backup is a belief, not a control.
- A web application firewall, rate limiting, and anything else that has to act
  before PHP boots. `docs/03-login-lockout.md` says why lockout belongs there
  and not here.
- Hosting. Shared hosting with a world-readable `wp-config.php`, an outdated PHP
  version, or a neighbour account on the same user is a problem no plugin
  reaches.
- Credentials and account hygiene. Two-factor enrolment, administrator count,
  and whether the developer still has access are the findings that come up most
  and are the least technical.
- File integrity and whether the site is already compromised.
  `docs/05-incident-response.md` is the starting point, and
  [wordpress-emergency-recovery](https://github.com/BuildWithAbdullah/wordpress-emergency-recovery)
  is the tooling for it.
