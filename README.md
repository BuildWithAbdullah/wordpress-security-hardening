# WordPress Security Hardening

Drop-in must-use plugins, a live header check, and the reasoning for the
decisions that are not a code change.

Everything here is either installed on a site or driven by a test. The three
plugins are loaded under a hook registry and their real callbacks fired, so
every header, every removed XML-RPC method and every branch of the address
allowlist is asserted on without a WordPress install, a database or a network
request. The header check is split so that the half which decides anything is a
pure function of a saved response, and the suite drives every verdict it can
reach.

No dependencies. Nothing to install. 82 tests and 14 failing and corrected
pairs.

## What it does

| File | What it does |
|---|---|
| [`00-security-headers.php`](mu-plugins/00-security-headers.php) | The five headers that are safe on any site, on the front end, on the login page and in the admin, plus version disclosure removal |
| [`01-disable-xmlrpc.php`](mu-plugins/01-disable-xmlrpc.php) | Closes XML-RPC authentication, multicall amplification and pingback reflection, inbound and outbound |
| [`02-harden-login.php`](mu-plugins/02-harden-login.php) | Authentication errors that do not confirm a username, no author or REST user enumeration, optional network restriction for IPv4 and IPv6 |
| [`check-headers.sh`](scripts/check-headers.sh) | Fetches a URL and judges what came back |
| [`judge-headers.sh`](scripts/judge-headers.sh) | Judges a saved response. Makes no request, which is why the suite can drive all of it |

Install the plugins into `wp-content/mu-plugins/`. Must-use plugins load
automatically, cannot be deactivated from the dashboard, and survive theme and
plugin updates. A client deactivating plugins to troubleshoot should not
silently lose their security headers as a side effect.

Prefer sending headers from the web server or CDN where you control it. Headers
sent from PHP are not applied to static assets or to responses served from a
full-page cache that never boots PHP, which on a cached site is most of the
traffic. The mu-plugin is the portable fallback for shared and managed hosting.

## The code is the easy part

Most of the value in a hardening engagement is in four judgement calls that go
wrong routinely:

- **Not deploying a Content Security Policy**, and writing down why, rather than
  shipping a permissive one full of `unsafe-inline` that protects nothing and
  looks like protection.
- **Not setting two-factor to Required** until every administrator is enrolled,
  because doing it first locks the client out of their own site.
- **Deleting deactivated plugins rather than updating them**, because
  deactivated is not disabled and the files are still reachable.
- **Not pushing a major version bump on a live site** because the vendor said to
  test it in staging.

Each of those is documented here as a decision with its reasoning, because
"deliberately not done, for this reason" is a finding and "not done" is an
oversight.

## Six corrections worth reading before you copy any of this

Version 1 of this repository was fourteen files of prose and three plugins that
nothing tested. Writing the tests found six defects, and every one of them had
shipped. They are listed here rather than quietly fixed, because the pattern
each belongs to is more useful than the fix.

**Security headers were sent on the front end only.** One filter on
`wp_headers`, which is what nearly every guide shows, and it does work. It works
in `WP::send_headers()` and nowhere else. It does not run on `wp-login.php` and
it does not run in `wp-admin`, so the two URLs on a WordPress site under
constant attack received no `X-Frame-Options` and no HSTS from the plugin whose
job was to send them, and the site passed a header check pointed at its home
page. The header set is now a pure function of context and all three contexts
call it. Pair: [`14-headers-frontend-only`](examples/14-headers-frontend-only.fail.php).

**The generic login message replaced every notice, not just failures.**
`login_errors` carries everything `wp-login.php` renders. A user who clicked Log
Out was told their password was wrong. So was a user who requested a reset link.
Both get reported months later as a login bug that nobody connects to a security
change. Pair:
[`11-login-errors-unconditional`](examples/11-login-errors-unconditional.fail.php).

**The address allowlist locked out IPv6 clients.** Built on `ip2long`, like
every snippet, which returns false for every IPv6 address. An administrator on a
dual-stack connection, which is most of them, was refused the login form with
their IPv4 address sitting in the allowlist. The one failure mode the feature's
own comment warns about was built into it. It now matches on packed bytes, which
also removes a signed-arithmetic bug that affected any IPv4 address above
`127.255.255.255` on a 32-bit build. Pair:
[`13-ip-allowlist-ipv4-only`](examples/13-ip-allowlist-ipv4-only.fail.php).

**The author archive block was a permanent redirect.** 301 is the obvious
choice, because the intent is permanent. Browsers cache a 301 and stop asking,
so a client who wants author archives back a year later finds returning visitors
still cannot reach them and no server-side change fixes it. A hardening measure
should never be the thing that cannot be undone. Pair:
[`12-author-redirect-permanent`](examples/12-author-redirect-permanent.fail.php).

**The header check made a HEAD request, and made two requests.** A CDN or host
that answers HEAD differently, or rejects it with 405, returns a header set no
visitor ever sees, so headers that were being sent were reported missing. And
the effective URL was fetched separately from the headers, which meant the HSTS
decision could be made about a different response than the one being judged. One
GET now yields both.

**The header check searched the whole redirect chain.** A header sent on the
`http` to `https` redirect and absent from the page was reported as present.
That is now its own finding, `redirect-only`, rather than a pass. Pair:
[`07-headers-on-redirect-only`](examples/07-headers-on-redirect-only.fail.headers).

Two defaults also changed. Stripping the `ver` query string from stylesheets and
scripts is now off unless asked for, because it breaks cache busting on every
deploy in exchange for an obscurity measure the same file describes as not
security. And `interest-cohort=()` is gone from `Permissions-Policy`, since it
addressed a proposal that was abandoned and was only making the header longer.

## Examples

Fourteen failing and corrected pairs in [`examples/`](examples). Ten are saved
response headers, four are PHP.

Every pair is held to the same contract by the suite: the check has to be seen
failing on the failing side and passing on the corrected side, and for the PHP
pairs it also has to fail against an empty page. A check that has never been
observed to catch anything is a check that may not work, and the only way to
find out is to try it. One pair carries an exemption from the empty-page rule
with the reason written next to it, because with no filter registered the right
outcome happens for the wrong reason.

The PHP pairs are also run against the shipped plugin they were drawn from, so
an example cannot drift from the thing it documents.

## Verify against a live site

```bash
./scripts/check-headers.sh https://example.com
./scripts/check-headers.sh https://example.com --json
./scripts/check-headers.sh https://example.com --save response.headers
```

```
Judged: https://example.com/
Hops in dump: 2

OK       X-Content-Type-Options       nosniff
OK       X-Frame-Options              SAMEORIGIN
OK       Referrer-Policy              strict-origin-when-cross-origin
OK       Permissions-Policy           geolocation=(), camera=(), microphone=(), payment=(), usb=()
OK       Strict-Transport-Security    max-age=31536000
NOTE     Content-Security-Policy      not sent; deliberately optional, see docs/01-security-headers.md

Headers that give away more than they need to:
WARN     X-Powered-By                 PHP/8.2.4
OK       Server                       cloudflare (no version)
OK       X-Pingback                   absent

No failures.
```

Exits non-zero when a required header is missing or carries a value that does
nothing, so it works as a post-deploy check. Warnings do not fail the run: a
check that fails a build over a version string is a check somebody switches off.

To judge a response you already have, without making any request:

```bash
./scripts/judge-headers.sh response.headers --url https://example.com/
```

`Server: cloudflare` is not a finding. `Server: Apache/2.4.41` is. The first
version of this script flagged the header on presence, which meant every site
behind a CDN got a warning about nothing.

Every finding either script can emit is listed in
[07 Every finding](docs/07-every-finding.md), which is generated from the
catalogue the suite drives.

## Verifying

```bash
npm test                  # 82 tests, no WordPress, no database, no network
npm run verify            # repository assertions
npm run check             # php -l and bash -n over every source file
npm run docs -- --check   # fails if the generated findings document is stale
```

Node 20 or newer, and PHP 8 for the plugin tests. Nothing to install: there are
no dependencies, and CI has a job that fails if a lockfile ever appears.

**What the tests actually do.** `lib/wp-shim.php` is a hook registry, not a
WordPress emulator. The suite loads a real mu-plugin under it, fires a real
hook, and asserts on the real return value. So `login_init` genuinely sends the
header set, `rest_endpoints` genuinely removes two routes and leaves the rest,
and the address matcher is driven over a table of thirty-three cases including
IPv6, non-byte-aligned prefixes, cross-family comparisons and malformed input.
Each case is a separate PHP process, because a plugin that reads a constant at
registration time cannot be reconfigured inside one.

`npm run verify` checks the repository rather than the code: that the README
quotes the `Permissions-Policy` value and HSTS max-age the plugin actually
sends, that every test file is named in the test script, that
`judge-headers.sh` still names no network tool, that the login plugin has not
gone back to integer address arithmetic, and that every documented finding
exists. A repository can stay green while rotting, and these are the ways it
does.

CI runs all four commands on Node 20, 22 and 24.

## Limits

[06 What the checks do not see](docs/06-what-the-checks-do-not-see.md) is the
document to read before quoting any of this to a client, and the short version
is this: the suite proves the logic in these files is correct and cannot prove
that WordPress fires these hooks where the plugins assume. That assumption is
precisely what was wrong in version 1 of the headers plugin. The live check
against a deployed site is what closes that gap, which is why both exist.

The header check also judges one URL, and headers on a WordPress site are
frequently not uniform: the home page served from a full-page cache can have a
different set from an uncached page. Check more than the home page and say which
you checked.

Application-level hardening only. It does not replace a web application
firewall, a maintained update routine, or off-site backups that have actually
been restored once.

## Documentation

| Document | What it covers |
|---|---|
| [01 Security headers](docs/01-security-headers.md) | The five, where to send them from, why HSTS needs care, and why CSP is usually the wrong call on a page-builder site |
| [02 XML-RPC](docs/02-xmlrpc.md) | Why multicall amplification defeats login rate limiting, how to check for legitimate use first, and how to verify it is closed |
| [03 Login lockout](docs/03-login-lockout.md) | Thresholds worth setting, why rate limiting belongs at the edge, and the 2FA sequence that does not lock the client out |
| [04 Scan and update workflow](docs/04-scan-workflow.md) | Reading a scan honestly, the four update outcomes, and what a firewall log actually tells you |
| [05 Compromise recovery](docs/05-incident-response.md) | Order of work, finding the entry point before cleaning, and delisting from blocklists |
| [06 What the checks do not see](docs/06-what-the-checks-do-not-see.md) | The limits of all of it, per tool, and what is not covered at all |
| [07 Every finding](docs/07-every-finding.md) | Generated. Every verdict the header judge can reach |
| [Hardening checklist](checklists/hardening-checklist.md) | The full engagement in order |

## Two things worth knowing up front

**Outdated software is not an infection.** A scan returning seven findings, all
of them out-of-date components, is a site that has not been maintained. Report
it that way, because "seven security findings" reads as a breach to a client who
does not know the difference.

**Routine attack volume is not a targeted attack.** A firewall on an ordinary
site will block something in the order of a thousand attacks a month, several
hundred of them brute force, with no targeting whatsoever. Give the number with
that context. It shows the control is working, and it stops the client reading
background noise as evidence somebody is after them specifically.

## Scope

WordPress 6.x on PHP 8.x. The mu-plugins have no dependencies and do not require
a plugin. The header scripts need `bash`, and the collector needs `curl`.

## Related

- [wordpress-emergency-recovery](https://github.com/BuildWithAbdullah/wordpress-emergency-recovery) - what to do when hardening came too late
- [site-audit-cli](https://github.com/BuildWithAbdullah/site-audit-cli) - security as one of four audit domains, with the same catalogue-and-drive approach
- [site-migration-and-dns](https://github.com/BuildWithAbdullah/site-migration-and-dns) - the same split between a pure judge and the one directory allowed to touch the network

## Licence

MIT. Use them, ship them, no attribution required.
