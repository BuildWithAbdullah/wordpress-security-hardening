# WordPress Security Hardening

Drop-in must-use plugins, a live header check, and the reasoning for the
decisions that are not a code change.

Everything here is either installed on a site or driven by a test. The three
plugins are loaded under a hook registry and their real callbacks fired, so
every header, every removed XML-RPC method and every branch of the address
allowlist is asserted on without a WordPress install, a database or a network
request. The header check is split three ways so that the only file which cannot
be tested is the one that makes the request, and nothing in it decides anything.

No dependencies. Nothing to install. 183 tests, 38 repository assertions, and
every finding and every limit reachable from a file in the repository.

## What it does

| File | What it does |
|---|---|
| [`00-security-headers.php`](mu-plugins/00-security-headers.php) | The headers that are safe on any site, on the front end, on the login page and in the admin, plus version disclosure removal |
| [`01-disable-xmlrpc.php`](mu-plugins/01-disable-xmlrpc.php) | Closes XML-RPC authentication, multicall amplification and pingback reflection, inbound and outbound |
| [`02-harden-login.php`](mu-plugins/02-harden-login.php) | Authentication errors that do not confirm a username, no author or REST user enumeration, optional network restriction for IPv4 and IPv6 |
| [`check-headers.sh`](scripts/check-headers.sh) | Makes one request. Decides nothing, which is why nothing in it needs a test |
| [`collect-decide.sh`](scripts/collect-decide.sh) | Everything the fetching script used to decide: options, what counts as an unusable response, where `--save` writes |
| [`judge-headers.sh`](scripts/judge-headers.sh) | Judges a saved response. Makes no request, so the suite drives all of it, including its parser |

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

## Eleven corrections, and the two tests that were asserting the bugs

Version 1 was prose and three plugins that nothing tested. Version 2 added the
tests and found six defects. Version 3 went back over the same files with a
fixture per reason rather than per header, and found eleven more. Every one of
them had shipped. They are listed rather than quietly fixed, because the pattern
each belongs to is more useful than the fix.

Two of them are worth reading first, because in both cases the defect had a
passing test requiring it.

**The address allowlist was bypassable with one request header.** Switching on
proxy support made the lookup read the leftmost entry of `X-Forwarded-For`, and
the leftmost entry is whatever the client sent. A proxy appends the address it
is talking to on the right; it does not replace what arrived. So an attacker who
sent `X-Forwarded-For: 203.0.113.10` reached an origin that saw
`203.0.113.10, <their real address>` and read the first one. The feature whose
only job is deciding who is shown a login form handed that decision to the
person being judged. The file's own comment said proxy headers were unsafe
behind a misconfigured proxy; they are unsafe behind a correctly configured one
too, which is the whole point of the chain being ordered. Version 2 had a test
named "a trusted proxy chain yields the leftmost address", and it passed. The
lookup now counts in from the trusted end, and a hop count too high for the
chain present refuses to answer rather than guessing. Pair:
[`23-xff-leftmost-trusted`](examples/23-xff-leftmost-trusted.fail.php).

**Backing HSTS out sent no header, which does not back it out.** A max age of
zero is not a deployment, so version 2 omitted the header. HSTS lives in the
browser: once it has seen the policy it refuses HTTP for the rest of the
original max age, and nothing the site stops doing changes that. The only way to
withdraw it is to serve `max-age=0` until the old policy has expired everywhere,
so the one operator who most needed that header sent was the one version 2
refused to send it for. Here too a test required the old behaviour and passed.
Zero now sends zero, and `WPSH_HSTS` set to false is the separate way to send
nothing. Pair:
[`25-hsts-backout-omits-header`](examples/25-hsts-backout-omits-header.fail.php).

The rest, in short:

**A duplicate header was judged by reading the last line.** HTTP combines
repeated field lines into one comma-separated value, so the browser sees neither
of two conflicting values and the last line is not the one that applies. A
response sending `max-age=0` and then a year was reported clean while every
browser switched HSTS off, because RFC 6797 says only the first is processed. A
response sending `ALLOWALL` and then `SAMEORIGIN` was reported as a pass, and the
same response with the lines swapped as a failure. Nothing about HTTP makes that
order meaningful, so the verdict was being decided by luck. Both are now their
own findings. Pairs: [`15-hsts-duplicated`](examples/15-hsts-duplicated.fail.headers)
and [`16-x-frame-options-duplicated`](examples/16-x-frame-options-duplicated.fail.headers).

**The hop count was case sensitive behind a case insensitive validity check.** A
dump whose status lines were lowercase passed validation and then counted as
zero hops, which merged every hop into one block, so a header sent only on the
redirect read as present on the final response. That is exactly the finding
version 2 existed to add, undone by a mismatch between two patterns ten lines
apart.

**Folded header values were invisible.** A value continued on an indented
following line is one value to every HTTP parser. A policy whose `unsafe-inline`
sat on the continuation line was reported clean. Pair:
[`21-folded-policy-hides-inline`](examples/21-folded-policy-hides-inline.fail.headers).

**A quoted `max-age` was reported as a failure.** `max-age="31536000"` is legal
in RFC 6797 and the browser honours it. Version 2 required bare digits and
called it unreadable, at error level, which is a working header failing a build.

**A twenty digit `max-age` printed shell errors and then nothing.** Compared with
shell arithmetic, so `[: integer expression expected` went to stderr twice and
the run exited 0 with no finding. `max-age` has no upper bound in the
specification. It is compared on digit length now.

**`X-Powered-By: PHP/8` was reported as clean.** The version check required a
dotted version. A major version is still a version.

**The default `Permissions-Policy` switched off checkout.** `payment=()`
disables the Payment Request API, which every wallet checkout button is built
on, so installing a file whose first line promises headers safe on essentially
any WordPress site removed the express checkout from any store that installed
it. Nothing errors, nothing logs, the button is simply not rendered, and it gets
noticed weeks later by someone comparing conversion rates. The file's list of
features to check first named geolocation, camera and microphone and did not
mention payment. Pair:
[`24-permissions-policy-blocks-payment`](examples/24-permissions-policy-blocks-payment.fail.php).

**Installing the collector on PATH broke it entirely.** It found its siblings
from `dirname` of `BASH_SOURCE` without following symlinks, so a link on PATH,
which is the only sensible way to install a shell tool, made every run print
"cannot find collect-decide.sh next to this script" and stop. It worked from a
checkout and failed once installed. `tools/exit-codes.mjs` now runs it through a
deliberately created symlink, which is one `ln -s` and one run.

**A relative `Location` produced a confident wrong verdict.** With no effective
URL given, version 2 fell back to the dump's own `Location` chain, accepted a
relative one, decided `/en/` was not HTTPS, and skipped every HSTS check on a
response that carried a perfectly good HSTS header. Only an absolute URL is
accepted now, and when there is none the script says so rather than deciding. A
guess is worse than a refusal when the finding looks specific.

Version 2's own six, briefly: security headers were sent on the front end only,
so the login page and the admin got none; the generic login message replaced
every notice rather than only failures; the address allowlist locked out IPv6
clients because it was built on `ip2long`; the author archive block was a
permanent redirect and so could not be undone; the header check made a HEAD
request and made two of them; and it searched the whole redirect chain, so a
header sent only on the redirect was reported as present.

## One entry per reason

There are 48 catalogued findings across 8 areas, and that structure is the
reason most of the defects above exist as findings at all.

A catalogue is one entry per reason, not one per check. A header that can be
absent, present and empty, present with a value that does nothing, or sent twice
with values that disagree is four entries, because the fix is different in each
case. Writing a fixture per reason rather than per header is what forced the
duplicate cases, the folded value, the quoted `max-age` and the cookie prefix
rules into existence, and three of them turned out to be wrong.

Each entry declares the complete set of severities it can carry, and the suite
asserts that set in both directions. A severity a real run produces that is not
declared fails the build, and a severity declared that no test has ever produced
fails it too. The second direction is the one that does the work: version 2
declared `weak/strict-transport-security` as a warning while the script emitted
it as an error when `max-age` was unparsable, so the generated document told a
reader the run would not fail and the run exited 1.

## Examples and fixtures

There are 25 example pairs in [`examples/`](examples), eighteen of them saved
response headers and seven PHP. A pair has to be a plausible site, which keeps
it honest and keeps it from reaching the reasons that only occur one at a time,
so between them they reach 22 of the catalogued findings. The rest get one of
the 35 fixtures in [`fixtures/`](fixtures), one per remaining reason.

Every pair declares the exact set of findings its failing side produces and the
exact set that survives on the corrected side, compared as set equality in both
directions. Checking only that the headline finding has gone lets a correction
introduce a second problem and still pass, which is how a repository ships a fix
that is worse than what it replaced.

Several fixtures declare that they produce nothing, and those earn their keep.
An empty declaration is an assertion that the script stays quiet about something
it cannot know: a quoted `max-age` has to be accepted, a session cookie under an
unrecognised name left alone, a style-only `unsafe-inline` not reported. It is
the assertion that catches a checker becoming noisier than it should be.

Every PHP pair is also run against the shipped plugin it was drawn from, and
against an empty page, so an example cannot drift from the thing it documents
and an audit that is really asking nothing cannot pass.

## Verify against a live site

```bash
bash scripts/check-headers.sh https://example.com
bash scripts/check-headers.sh https://example.com --json
bash scripts/check-headers.sh https://example.com --save response.headers
```

Run through `bash` rather than directly, or `chmod +x scripts/*.sh` once. Not
every way of obtaining a repository carries file modes: a source zip and
GitHub's own web upload both produce mode 644, so a script that depends on its
executable bit works for some people and not others. Nothing here depends on
it, and the verifier asserts that.

```
Judged: https://example.com/
Hops in dump: 2

OK       X-Content-Type-Options       nosniff
OK       X-Frame-Options              SAMEORIGIN
OK       Referrer-Policy              strict-origin-when-cross-origin
OK       Permissions-Policy           geolocation=(), camera=(), microphone=(), usb=()
OK       Strict-Transport-Security    max-age=31536000
NOTE     Content-Security-Policy      not sent; deliberately optional, see docs/01-security-headers.md

Headers that give away more than they need to:
WARN     X-Powered-By                 PHP/8.2.4
NOTE     Server                       cloudflare (names the software, no version)
OK       X-Pingback                   absent

No failures.
```

Exits non-zero when a required header is missing or carries a value that does
nothing, so it works as a post-deploy check. Warnings do not fail the run: a
check that fails a build over a version string is a check somebody switches off.

To judge a response you already have, without making any request:

```bash
bash scripts/judge-headers.sh response.headers --url https://example.com/
```

And to see what the judge is about to read, which is where three of the eleven
defects were:

```bash
bash scripts/judge-headers.sh response.headers --normalize
```

`Server: cloudflare` is not a version leak. `Server: Apache/2.4.41` is. The first
version of this script flagged the header on presence, which meant every site
behind a CDN got a warning about nothing.

Every finding either script can emit is listed in
[07 Every finding](docs/07-every-finding.md), which is generated from the
catalogue the suite drives.

## Verifying

```bash
npm test                  # the suite, no WordPress, no database, no network
npm run verify            # the claims this repository makes about itself
npm run check             # php -l and bash -n over every source file
npm run exit-codes        # runs the real scripts, exit codes derived from the manifests
npm run audit-verdicts    # every audit, in its own process, verdicts derived
npm run entry-thin        # fails if a decision moved into the file nothing can test
npm run docs:check        # fails if a generated document is stale
npm run count             # the test count, taken by running them
```

Node 20.0.0 or newer, and PHP 8 for the plugin tests. Nothing to install: there
are no dependencies, and CI has a job that fails if a lockfile ever appears.

**What the tests actually do.** `lib/wp-shim.php` is a hook registry, not a
WordPress emulator. The suite loads a real mu-plugin under it, fires a real
hook, and asserts on the real return value. So `login_init` genuinely sends the
header set, `rest_endpoints` genuinely removes two routes and leaves the rest,
and the address matcher is driven over a table of cases including IPv6,
non-byte-aligned prefixes, cross-family comparisons and malformed input. Each
case is a separate PHP process, because a plugin that reads a constant at
registration time cannot be reconfigured inside one.

**What the verifier does, and what its number means.** It checks the repository
rather than the code: that the README quotes counts the code actually produces,
that every test file is named in the test script, that `judge-headers.sh` still
names no network tool, that nothing shipped imports from a directory the package
does not ship, that the engines floor names an exact version and that CI asserts
the running version is it. A repository can stay green while rotting, and these
are the ways it does.

The number it prints is 38 and not several hundred, and that is deliberate.
The previous verifier made an assertion per file, so adding one document moved
the total, and a count that changes when something it is not about changes is a
file count wearing a self check. It is a fixed list of named claims now. The
total also does not depend on whether they pass, so it cannot be read as a
score, and it is not comparable with a number from a verifier still counting per
file.

CI runs six jobs: the suite on Node 20.0.0, 22.23.4 and 24.11.1, a job that
fails unless the declared floor is the version that actually ran and that the
package refuses to install below it, a job for the four gates that are not the
suite, and a job that fails if anything becomes installable.

## Limits

There are 10 declared limits, generated into
[06 What the checks do not see](docs/06-what-the-checks-do-not-see.md) from the
manifest the suite checks. Version 2 declared none at all, which is what made
this the first thing to fix: a paragraph saying a checker cannot see something
still reads correctly after the checker learns to see it, and a reader then
trusts a caveat that is no longer true.

Each one names a case nothing is said about, which has to keep producing
nothing, and a nearby case that is caught, which has to keep producing
something. A limit that has quietly been fixed fails the build, and so does a
check that has quietly stopped working.

The short version of all of them: the suite proves the logic in these files is
correct and cannot prove that WordPress fires these hooks where the plugins
assume. That assumption is precisely what was wrong in version 1 of the headers
plugin. The live check against a deployed site is what closes that gap, which is
why both exist. The live check in turn judges one URL, and headers on a
WordPress site are frequently not uniform, so check more than the home page and
say which you checked.

Application-level hardening only. It does not replace a web application
firewall, a maintained update routine, or off-site backups that have actually
been restored once.

## Documentation

| Document | What it covers |
|---|---|
| [01 Security headers](docs/01-security-headers.md) | Where to send them from, why HSTS needs care, and why CSP is usually the wrong call on a page-builder site |
| [02 XML-RPC](docs/02-xmlrpc.md) | Why multicall amplification defeats login rate limiting, how to check for legitimate use first, and how to verify it is closed |
| [03 Login lockout](docs/03-login-lockout.md) | Thresholds worth setting, why rate limiting belongs at the edge, and the 2FA sequence that does not lock the client out |
| [04 Scan and update workflow](docs/04-scan-workflow.md) | Reading a scan honestly, the four update outcomes, and what a firewall log actually tells you |
| [05 Compromise recovery](docs/05-incident-response.md) | Order of work, finding the entry point before cleaning, and delisting from blocklists |
| [06 What the checks do not see](docs/06-what-the-checks-do-not-see.md) | Generated. Every limit, with the case that demonstrates it and the one that contrasts it |
| [07 Every finding](docs/07-every-finding.md) | Generated. Every verdict the header judge can reach, with its severity set |
| [08 Session cookies and caching](docs/08-session-cookies-and-caching.md) | The two areas version 3 added, including the one that hands one visitor another visitor's session |
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
- [site-migration-and-dns](https://github.com/BuildWithAbdullah/site-migration-and-dns) - the same split between a pure judge and the one file allowed to touch the network

## Licence

MIT. Use them, ship them, no attribution required.
