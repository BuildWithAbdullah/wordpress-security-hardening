/**
 * What this repository cannot do, stated and then asserted.
 *
 * Version 2 had no declared limits at all, which is the gap the last five
 * rebuilds on this account have each closed first. A limit that is only written
 * in prose decays the moment the code changes, and the decay is invisible: the
 * paragraph still reads correctly, it is just describing a tool that no longer
 * behaves that way.
 *
 * So every limit here names the thing that demonstrates it, and
 * test/limits.test.mjs checks it in both directions. `blind` is the case the
 * limit says nothing about, and it has to produce nothing, or, where it names
 * an `absent` list, nothing matching those id prefixes. That second form exists
 * because one limit is reached by a finding whose whole content is a refusal to
 * decide: saying "the transport was not established" is allowed, and producing
 * an HSTS verdict anyway is not. `contrast` is the
 * nearby case the repository does catch, and it has to produce something. A
 * limit whose blind case produces a finding is a limit that has quietly been
 * fixed and should be deleted. A limit whose contrast case produces nothing is
 * a check that has quietly stopped working, and without the second direction
 * nobody would find out.
 */

/**
 * @type {Array<{
 *   id: string,
 *   limit: string,
 *   why: string,
 *   blind: {kind: 'fixture'|'pair'|'probe', ref: string},
 *   contrast: {kind: 'fixture'|'pair'|'probe', ref: string}
 * }>}
 */
export const LIMITS = [
	{
		id: 'session-cookie-names-are-a-fixed-list',
		limit:
			'Cookie findings apply only to cookies this repository can name as session or authentication cookies. A site with a custom session cookie name gets nothing said about it.',
		why:
			'The alternative is inferring from the absence of attributes, which reports every analytics and consent cookie on every site. A checker that is wrong about most of what it reports is a checker nobody reads.',
		blind: { kind: 'fixture', ref: 'cookie-custom-name-is-invisible.headers' },
		contrast: { kind: 'pair', ref: '17-session-cookie-unflagged' },
	},
	{
		id: 'script-source-list-only',
		limit:
			'The unsafe-inline and unsafe-eval checks read the script source list, or default-src where there is no script-src. A policy that permits unsafe-inline for styles only is not reported.',
		why:
			'An inline style is a far smaller problem than an inline script, and most real WordPress policies permit inline styles because the block editor emits them. Reporting those would make the finding worthless.',
		blind: { kind: 'fixture', ref: 'csp-style-only-unsafe-inline.headers' },
		contrast: { kind: 'pair', ref: '08-csp-unsafe-inline' },
	},
	{
		id: 'no-directive-interaction-model',
		limit:
			'The policy checks are lexical. Interactions between directives are not modelled, so strict-dynamic beside a bare scheme source is still reported as permitting any host, which in that policy it does not.',
		why:
			'Modelling the interactions means implementing the CSP source matching algorithm, and a half-implemented version of it would be confidently wrong rather than noisy. The false positive is declared and has a fixture.',
		blind: { kind: 'fixture', ref: 'csp-style-only-unsafe-inline.headers' },
		contrast: { kind: 'fixture', ref: 'csp-strict-dynamic-still-reported.headers' },
	},
	{
		id: 'leak-headers-are-a-fixed-list',
		limit:
			'Five header names are inspected for a version. A version in any other header, in a cookie name or in a Link target is not seen.',
		why:
			'Searching every header for a version-shaped value reports a build number in a cache header on every site behind a CDN. Version 1 of this script flagged Server on presence alone and that is exactly how its output started getting skimmed.',
		blind: { kind: 'fixture', ref: 'leak-unlisted-header.headers' },
		contrast: { kind: 'fixture', ref: 'leak-version-major.headers' },
	},
	{
		id: 'hsts-needs-an-established-transport',
		limit:
			'Nothing is concluded about HSTS unless the final URL is known and is HTTPS. On a plain HTTP response, or when no final URL was given and the dump carries no absolute one, the HSTS header in the dump is deliberately not judged.',
		why:
			'A browser ignores HSTS over HTTP, so a finding about it would be a confident statement about a header nobody acts on. Version 2 assumed HTTPS when it did not know, which is how it produced HSTS verdicts about a transport nobody had established.',
		// The blind case does produce a finding, and that finding is the refusal
		// itself. What must be absent is any verdict about HSTS, which is what
		// `absent` names: a blind case is allowed to say "I am not deciding this"
		// and is not allowed to decide it.
		blind: {
			kind: 'fixture',
			ref: 'transport-url-unknown.headers',
			absent: ['hsts/', 'missing/strict-transport-security'],
		},
		contrast: { kind: 'fixture', ref: 'hsts-missing.headers' },
	},
	{
		id: 'one-response-per-run',
		limit:
			'One URL is judged per run. Headers are routinely absent on responses the visitor also receives: a page served from a full-page cache that bypasses PHP, and any static asset served directly by nginx or Apache. None of that is visible here.',
		why:
			'This is the gap the whole repository exists around, and it cannot be closed by a checker that fetches one page. The remedy is in the documentation: send the headers at the server or CDN level where you control it, and check more than the home page.',
		blind: { kind: 'probe', ref: 'judge-refuses-two-dumps' },
		contrast: { kind: 'probe', ref: 'judge-reads-only-the-final-hop' },
	},
	{
		id: 'php-headers-cannot-prove-delivery',
		limit:
			'The plugins send headers from PHP, and the test suite observes them being sent from PHP. That the client received them is not and cannot be asserted here.',
		why:
			'Nothing short of a live request proves delivery, which is why scripts/check-headers.sh exists as a separate deliverable. The suite asserts the header set and the hooks; the live check asserts the response.',
		blind: { kind: 'probe', ref: 'plugins-send-only-through-php-hooks' },
		contrast: { kind: 'probe', ref: 'header-set-is-observable' },
	},
	{
		id: 'no-rate-limiting',
		limit:
			'No login attempt counting, lockout or throttling. mu-plugins/02-harden-login.php covers what code can do about enumeration and about messages that confirm a username, and nothing about volume.',
		why:
			'Lockout belongs where it can see the request before PHP boots and act across the whole site rather than one endpoint. Implementing it in a must-use plugin means a database write per failed attempt, which is a denial of service surface rather than a defence. See docs/03-login-lockout.md for the thresholds worth setting at the edge.',
		blind: { kind: 'probe', ref: 'plugins-keep-no-state' },
		contrast: { kind: 'probe', ref: 'enumeration-is-blocked' },
	},
	{
		id: 'shim-is-not-wordpress',
		limit:
			'lib/wp-shim.php fires real hooks against real plugin code and is not WordPress. Anything that depends on load order outside the hooks, on the object cache, on multisite, or on when the current user is determined, is out of reach.',
		why:
			'A shim that needed a database and a full bootstrap would be a WordPress install, and the suite would then need one to run, which is the thing that stops anybody running it. The trade is stated rather than hidden: these tests prove the plugin logic, not the platform.',
		blind: { kind: 'probe', ref: 'shim-has-no-database' },
		contrast: { kind: 'probe', ref: 'shim-fires-real-hooks' },
	},
	{
		id: 'proxy-hop-count-is-trusted',
		limit:
			'The allowlist reads the client address by counting in from the trusted end of X-Forwarded-For. A hop count set higher than the number of proxies that really exist makes it read an entry the client could have written.',
		why:
			'Nothing in a request distinguishes the entry a real proxy wrote from an invented one, so there is no signal left to check. The mitigation is that the count is a deliberate declaration of the topology the site has, and that a count too high for the chain present refuses to answer rather than guessing.',
		blind: { kind: 'probe', ref: 'overstated-hop-count-reads-a-forged-entry' },
		contrast: { kind: 'probe', ref: 'correct-hop-count-ignores-a-forged-entry' },
	},
];

export const LIMIT_IDS = LIMITS.map((l) => l.id);
