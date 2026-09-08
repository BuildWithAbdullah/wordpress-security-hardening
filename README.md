# WordPress Security Hardening

Drop-in must-use plugins, a live header verification script, and the reasoning
for the decisions that are not a code change.

The code here is the easy part. Most of the value in a hardening engagement is
in four judgement calls that go wrong routinely:

- **Not deploying a Content Security Policy**, and writing down why, rather
  than shipping a permissive one full of `unsafe-inline` that protects nothing
  and looks like protection.
- **Not setting two-factor to Required** until every administrator is
  enrolled, because doing it first locks the client out of their own site.
- **Deleting deactivated plugins rather than updating them**, because
  deactivated is not disabled and the files are still reachable.
- **Not pushing a major version bump on a live site** because the vendor said
  to test it in staging.

Each of those is documented here as a decision with its reasoning, because
"deliberately not done, for this reason" is a finding and "not done" is an
oversight.

## Must-use plugins

Install into `wp-content/mu-plugins/`. Must-use plugins load automatically,
cannot be deactivated from the dashboard, and survive theme and plugin updates.
A client deactivating plugins to troubleshoot should not silently lose their
security headers as a side effect.

| File | What it does |
|---|---|
| [`00-security-headers.php`](mu-plugins/00-security-headers.php) | The five headers that are safe on any site, plus version disclosure removal |
| [`01-disable-xmlrpc.php`](mu-plugins/01-disable-xmlrpc.php) | Closes XML-RPC authentication, multicall amplification and pingback reflection |
| [`02-harden-login.php`](mu-plugins/02-harden-login.php) | Generic login errors, author and REST user enumeration, optional network restriction |

Prefer sending headers from the web server or CDN where you control it. Headers
sent from PHP are not applied to static assets or to responses served from a
full-page cache that never boots PHP, which on a cached site is most of the
traffic. The mu-plugin is the portable fallback for shared and managed hosting.

## Verify against the live site

```bash
./scripts/check-headers.sh https://example.com
```

```
OK       X-Content-Type-Options: nosniff
OK       X-Frame-Options: SAMEORIGIN
OK       Referrer-Policy: strict-origin-when-cross-origin
OK       Permissions-Policy: geolocation=(), camera=(), microphone=()
OK       Strict-Transport-Security: max-age=31536000
ABSENT   Content-Security-Policy (optional, see docs/01-security-headers.md)

Headers that should NOT be present:
LEAK     X-Powered-By: PHP/8.2.4
OK       X-Pingback absent
```

Follows redirects, exits non-zero on a missing header so it works as a
post-deploy check, and flags headers that leak version information.

## Documentation

| Document | What it covers |
|---|---|
| [01 Security headers](docs/01-security-headers.md) | The five, where to send them from, why HSTS needs care, and why CSP is usually the wrong call on a page-builder site |
| [02 XML-RPC](docs/02-xmlrpc.md) | Why multicall amplification defeats login rate limiting, how to check for legitimate use first, and how to verify it is closed |
| [03 Login lockout](docs/03-login-lockout.md) | Thresholds worth setting, why rate limiting belongs at the edge, and the 2FA sequence that does not lock the client out |
| [04 Scan and update workflow](docs/04-scan-workflow.md) | Reading a scan honestly, the four update outcomes, and what a firewall log actually tells you |
| [05 Compromise recovery](docs/05-incident-response.md) | Order of work, finding the entry point before cleaning, and delisting from blocklists |
| [Hardening checklist](checklists/hardening-checklist.md) | The full engagement in order |

## Two things worth knowing up front

**Outdated software is not an infection.** A scan returning seven findings, all
of them out-of-date components, is a site that has not been maintained. Report
it that way, because "seven security findings" reads as a breach to a client
who does not know the difference.

**Routine attack volume is not a targeted attack.** A firewall on an ordinary
site will block something in the order of a thousand attacks a month, several
hundred of them brute force, with no targeting whatsoever. Give the number with
that context. It shows the control is working, and it stops the client reading
background noise as evidence somebody is after them specifically.

## Scope

WordPress 6.x on PHP 8.x. The mu-plugins have no dependencies and do not
require a plugin. The header script needs `curl` and `bash`.

Application-level hardening only. It does not replace a web application
firewall, a maintained update routine, or off-site backups that have actually
been restored once.

## Licence

MIT.
