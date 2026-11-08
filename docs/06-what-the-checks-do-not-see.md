# What the checks do not see

Generated from `tools/limits.mjs` by `npm run docs`. Do not edit by hand.

Read this before putting any output from this repository in front of a client.
A green run means the things listed in
[07 Every finding](07-every-finding.md) were not found. It does not mean the
site is fine, and the gap between those two statements is what this page is.

Every limit below is checked in both directions by `test/limits.test.mjs`.
Each one names a case the repository says nothing about, which has to keep
producing nothing, and a nearby case it does catch, which has to keep
producing something. A limit that has quietly been fixed fails the build, and
so does a check that has quietly stopped working. Without the second
direction the prose would read correctly in either case.

There are 10 of them.

## 1. `session-cookie-names-are-a-fixed-list`

Cookie findings apply only to cookies this repository can name as session or authentication cookies. A site with a custom session cookie name gets nothing said about it.

**Why it is the right trade.** The alternative is inferring from the absence of attributes, which reports every analytics and consent cookie on every site. A checker that is wrong about most of what it reports is a checker nobody reads.

**Demonstrated by.** The case nothing is said about is `cookie-custom-name-is-invisible.headers`, and the nearby case that is caught is `17-session-cookie-unflagged`.

## 2. `script-source-list-only`

The unsafe-inline and unsafe-eval checks read the script source list, or default-src where there is no script-src. A policy that permits unsafe-inline for styles only is not reported.

**Why it is the right trade.** An inline style is a far smaller problem than an inline script, and most real WordPress policies permit inline styles because the block editor emits them. Reporting those would make the finding worthless.

**Demonstrated by.** The case nothing is said about is `csp-style-only-unsafe-inline.headers`, and the nearby case that is caught is `08-csp-unsafe-inline`.

## 3. `no-directive-interaction-model`

The policy checks are lexical. Interactions between directives are not modelled, so strict-dynamic beside a bare scheme source is still reported as permitting any host, which in that policy it does not.

**Why it is the right trade.** Modelling the interactions means implementing the CSP source matching algorithm, and a half-implemented version of it would be confidently wrong rather than noisy. The false positive is declared and has a fixture.

**Demonstrated by.** The case nothing is said about is `csp-style-only-unsafe-inline.headers`, and the nearby case that is caught is `csp-strict-dynamic-still-reported.headers`.

## 4. `leak-headers-are-a-fixed-list`

Five header names are inspected for a version. A version in any other header, in a cookie name or in a Link target is not seen.

**Why it is the right trade.** Searching every header for a version-shaped value reports a build number in a cache header on every site behind a CDN. Version 1 of this script flagged Server on presence alone and that is exactly how its output started getting skimmed.

**Demonstrated by.** The case nothing is said about is `leak-unlisted-header.headers`, and the nearby case that is caught is `leak-version-major.headers`.

## 5. `hsts-needs-an-established-transport`

Nothing is concluded about HSTS unless the final URL is known and is HTTPS. On a plain HTTP response, or when no final URL was given and the dump carries no absolute one, the HSTS header in the dump is deliberately not judged.

**Why it is the right trade.** A browser ignores HSTS over HTTP, so a finding about it would be a confident statement about a header nobody acts on. Version 2 assumed HTTPS when it did not know, which is how it produced HSTS verdicts about a transport nobody had established.

**Demonstrated by.** The case nothing is said about is `transport-url-unknown.headers`, and the nearby case that is caught is `hsts-missing.headers`.

## 6. `one-response-per-run`

One URL is judged per run. Headers are routinely absent on responses the visitor also receives: a page served from a full-page cache that bypasses PHP, and any static asset served directly by nginx or Apache. None of that is visible here.

**Why it is the right trade.** This is the gap the whole repository exists around, and it cannot be closed by a checker that fetches one page. The remedy is in the documentation: send the headers at the server or CDN level where you control it, and check more than the home page.

**Demonstrated by.** The case nothing is said about is `judge-refuses-two-dumps`, and the nearby case that is caught is `judge-reads-only-the-final-hop`.

## 7. `php-headers-cannot-prove-delivery`

The plugins send headers from PHP, and the test suite observes them being sent from PHP. That the client received them is not and cannot be asserted here.

**Why it is the right trade.** Nothing short of a live request proves delivery, which is why scripts/check-headers.sh exists as a separate deliverable. The suite asserts the header set and the hooks; the live check asserts the response.

**Demonstrated by.** The case nothing is said about is `plugins-send-only-through-php-hooks`, and the nearby case that is caught is `header-set-is-observable`.

## 8. `no-rate-limiting`

No login attempt counting, lockout or throttling. mu-plugins/02-harden-login.php covers what code can do about enumeration and about messages that confirm a username, and nothing about volume.

**Why it is the right trade.** Lockout belongs where it can see the request before PHP boots and act across the whole site rather than one endpoint. Implementing it in a must-use plugin means a database write per failed attempt, which is a denial of service surface rather than a defence. See docs/03-login-lockout.md for the thresholds worth setting at the edge.

**Demonstrated by.** The case nothing is said about is `plugins-keep-no-state`, and the nearby case that is caught is `enumeration-is-blocked`.

## 9. `shim-is-not-wordpress`

lib/wp-shim.php fires real hooks against real plugin code and is not WordPress. Anything that depends on load order outside the hooks, on the object cache, on multisite, or on when the current user is determined, is out of reach.

**Why it is the right trade.** A shim that needed a database and a full bootstrap would be a WordPress install, and the suite would then need one to run, which is the thing that stops anybody running it. The trade is stated rather than hidden: these tests prove the plugin logic, not the platform.

**Demonstrated by.** The case nothing is said about is `shim-has-no-database`, and the nearby case that is caught is `shim-fires-real-hooks`.

## 10. `proxy-hop-count-is-trusted`

The allowlist reads the client address by counting in from the trusted end of X-Forwarded-For. A hop count set higher than the number of proxies that really exist makes it read an entry the client could have written.

**Why it is the right trade.** Nothing in a request distinguishes the entry a real proxy wrote from an invented one, so there is no signal left to check. The mitigation is that the count is a deliberate declaration of the topology the site has, and that a count too high for the chain present refuses to answer rather than guessing.

**Demonstrated by.** The case nothing is said about is `overstated-hop-count-reads-a-forged-entry`, and the nearby case that is caught is `correct-hop-count-ignores-a-forged-entry`.

## The one that is not on the list

Hardening is not a state a site reaches. Everything here reduces a surface or
removes a signal, and none of it substitutes for keeping WordPress, the theme
and the plugins updated, for having a restore that somebody has actually
tested, or for knowing who has an administrator account and why. A site with
every finding in this repository cleared and an out of date plugin is not a
hardened site.
