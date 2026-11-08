/**
 * Every finding scripts/judge-headers.sh can emit, one entry per reason.
 *
 * One entry per reason, not one per check. A check that refuses a response for
 * three different reasons is three entries, because a reader fixing the site
 * needs to know which of the three they are looking at, and because a fixture
 * written for each reason is what proves the reason is reachable at all. That
 * rule found most of the defects in this rebuild: writing one fixture per
 * reason rather than one per header forced the duplicate-header cases, the
 * folded-value case and the cookie prefix cases into existence, and three of
 * them turned out to be reported wrongly or not at all.
 *
 * Each entry declares `levels`: the complete set of severities the finding can
 * carry. test/catalogue.test.mjs asserts that in both directions. A severity a
 * real run produces that is not declared fails the suite, and a severity
 * declared here that no test has ever produced fails it too. The second
 * direction is the one that does the work: version 2 declared
 * weak/strict-transport-security as a warning while the script emitted it as
 * an error when max-age was unparsable, so the generated document told a
 * reader the run would not fail and the run exited 1.
 */

/** Levels, in order of severity. Only an error changes the exit code. */
export const LEVELS = ['error', 'warn', 'note'];

/** The areas findings are grouped into, in report order. */
export const AREAS = [
	{ id: 'required', what: 'The response headers that should be on every page.' },
	{ id: 'hsts', what: 'Strict-Transport-Security, which is the one that cannot be undone remotely.' },
	{ id: 'csp', what: 'Content-Security-Policy, including its interaction with X-Frame-Options.' },
	{ id: 'cookie', what: 'Attributes on the cookies that carry a WordPress session.' },
	{ id: 'cache', what: 'Whether a response carrying a session may be stored by a shared cache.' },
	{ id: 'leak', what: 'Headers that give away more than they need to.' },
	{ id: 'transport', what: 'Whether the transport could be established well enough to judge HSTS.' },
	{ id: 'dump', what: 'The shape of the dump itself, where it changes how much the findings are worth.' },
];

/**
 * Findings with a fixed id.
 *
 * @type {Array<{id: string, area: string, levels: string[], reason: string, what: string}>}
 */
export const FINDINGS = [
	// ---------------------------------------------------------------- required
	{
		id: 'missing/x-content-type-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Content-Type-Options is not sent on the final response, and no redirect hop carried it either.',
		what: 'Without it, a file served as text/plain that happens to contain markup can be sniffed and executed as HTML. Any site with a media library accepts uploads.',
	},
	{
		id: 'empty/x-content-type-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Content-Type-Options is sent with nothing after the colon.',
		what: 'A separate reason from a weak value, and a separate fix. An empty header is almost always a plugin writing a setting it was never given, and it satisfies every check that only asks whether the name appears.',
	},
	{
		id: 'weak/x-content-type-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Content-Type-Options is sent with a value other than nosniff.',
		what: 'nosniff is the only value the header has. Anything else is a value somebody typed.',
	},
	{
		id: 'conflict/x-content-type-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Content-Type-Options is sent more than once with values that do not agree.',
		what: 'HTTP combines repeated field lines into one comma-separated value, so the browser sees neither of the two values that were sent. Reported as its own reason because no order between them is meaningful and a checker that picks one is deciding the verdict by luck.',
	},

	{
		id: 'missing/x-frame-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Frame-Options is not sent on the final response, and no redirect hop carried it either.',
		what: 'Clickjacking. Note that a CSP frame-ancestors directive supersedes this header where both are present, so read csp/frame-ancestors-permissive beside this one.',
	},
	{
		id: 'empty/x-frame-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Frame-Options is sent with nothing after the colon.',
		what: 'An empty X-Frame-Options permits framing and passes a presence check.',
	},
	{
		id: 'weak/x-frame-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Frame-Options is sent with a value that permits framing.',
		what: 'ALLOWALL permits framing by anyone and ALLOW-FROM was never implemented by more than one browser and is obsolete. A permissive value that passes a check is worse than a missing header, because the check is what stops anyone looking again.',
	},
	{
		id: 'conflict/x-frame-options',
		area: 'required',
		levels: ['error'],
		reason: 'X-Frame-Options is sent more than once with values that do not agree.',
		what: 'The combined value is not one of the two the server sent, and browsers apply no framing protection for a value they cannot parse. Version 2 took the last line and so reported a response carrying ALLOWALL and SAMEORIGIN as a pass or a failure depending which came first.',
	},

	{
		id: 'missing/referrer-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Referrer-Policy is not sent on the final response, and no redirect hop carried it either.',
		what: 'The browser default is no-referrer-when-downgrade in most engines, which still sends the full URL to every HTTPS destination.',
	},
	{
		id: 'empty/referrer-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Referrer-Policy is sent with nothing after the colon.',
		what: 'An empty value falls back to the browser default, which is the thing the header was deployed to replace.',
	},
	{
		id: 'weak/referrer-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Referrer-Policy is sent with a token that sends the full URL cross-origin.',
		what: 'unsafe-url sends the whole URL, including a path that may carry a reset token or an order id, to every destination.',
	},
	{
		id: 'conflict/referrer-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Referrer-Policy is sent more than once with values that do not agree.',
		what: 'Referrer-Policy is a token list and a browser takes the last token it recognises, so two headers mean the effective policy depends on which proxy appended its line last.',
	},

	{
		id: 'missing/permissions-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Permissions-Policy is not sent on the final response, and no redirect hop carried it either.',
		what: 'Nothing is restricted, so an injected script can reach for geolocation, camera, microphone and the payment request API.',
	},
	{
		id: 'empty/permissions-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Permissions-Policy is sent with nothing after the colon.',
		what: 'Several caching and security plugins emit this header with nothing after it. It restricts no feature and satisfies any check that only asks whether the name appears, which is why it has its own reason.',
	},
	{
		id: 'weak/permissions-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Permissions-Policy is sent with a value that contains no directive name.',
		what: 'A value with no letters in it, such as a stray comma or a bare asterisk, names no feature and therefore restricts none.',
	},
	{
		id: 'conflict/permissions-policy',
		area: 'required',
		levels: ['error'],
		reason: 'Permissions-Policy is sent more than once with values that do not agree.',
		what: 'The combined list is parsed as one structured header and a repeated feature name makes the whole header invalid in some engines, so the restriction silently disappears.',
	},

	// -------------------------------------------------------------------- hsts
	{
		id: 'missing/strict-transport-security',
		area: 'hsts',
		levels: ['error'],
		reason: 'The final response is HTTPS and sent no HSTS header.',
		what: 'Every first visit over HTTP, and every visit from a link that is still HTTP, is interceptable.',
	},
	{
		id: 'hsts/no-max-age',
		area: 'hsts',
		levels: ['error'],
		reason: 'The header is present and carries no readable max-age directive.',
		what: 'max-age is the only required directive. Without it the browser ignores the whole header, so the site has the appearance of HSTS and none of it. Note that a quoted value is legal: version 2 rejected max-age="31536000" as unreadable, which is a browser-honoured header reported as a failure.',
	},
	{
		id: 'hsts/disabled',
		area: 'hsts',
		levels: ['error'],
		reason: 'The HSTS header is present and its max-age directive is zero.',
		what: 'Zero is how HSTS is backed out, not how it is deployed. It tells every browser that has the policy to forget it.',
	},
	{
		id: 'hsts/short-max-age',
		area: 'hsts',
		levels: ['warn'],
		reason: 'max-age is above zero but under 30 days.',
		what: 'A staging value left in production. A warning rather than an error, because starting short is the correct way to deploy HSTS and a check that fails the build for it is a check somebody switches off.',
	},
	{
		id: 'hsts/conflict',
		area: 'hsts',
		levels: ['error'],
		reason: 'More than one Strict-Transport-Security header is present.',
		what: 'RFC 6797 says the browser processes only the first one. Version 2 read the last, so a response sending max-age=0 and then a year was reported clean while every browser switched HSTS off. This is the reason the duplicate cases exist as findings at all.',
	},
	{
		id: 'hsts/preload-without-subdomains',
		area: 'hsts',
		levels: ['error'],
		reason: 'preload is present without includeSubDomains, or with a max-age under a year.',
		what: 'The preload list refuses a submission that does not carry both, so the site is not preloaded and nobody is told. The token is in the header, the certificate lapse risk has been taken, and the benefit was never collected.',
	},

	// --------------------------------------------------------------------- csp
	{
		id: 'csp/absent',
		area: 'csp',
		levels: ['note'],
		reason: 'No Content-Security-Policy header.',
		what: 'Deliberately a note. On a page-builder site, not deploying one is often the right call, and a tool that fails the build over it is a tool whose output gets skimmed.',
	},
	{
		id: 'csp/unsafe-inline',
		area: 'csp',
		levels: ['warn'],
		reason: 'A policy is present and permits unsafe-inline for scripts.',
		what: 'This permits exactly the injection a CSP is deployed to stop. Common on WordPress because the block editor and most page builders emit inline script.',
	},
	{
		id: 'csp/unsafe-eval',
		area: 'csp',
		levels: ['warn'],
		reason: 'A policy is present and permits unsafe-eval.',
		what: 'A separate reason from unsafe-inline and a separate fix: this one is usually one named library, and finding it is a different job from removing inline handlers.',
	},
	{
		id: 'csp/wildcard-script-src',
		area: 'csp',
		levels: ['warn'],
		reason: 'script-src, or default-src standing in for it, permits any host.',
		what: 'A wildcard or a bare scheme source permits script from anywhere that scheme can reach, which is every host. The policy still appears in a report as deployed.',
	},
	{
		id: 'csp/report-only-only',
		area: 'csp',
		levels: ['warn'],
		reason: 'A Report-Only policy is present and no enforcing policy is.',
		what: 'Report-Only enforces nothing by design. It is the right first step and a common last one: the header is in the response, it shows up in any audit that greps for a policy, and it has never blocked anything.',
	},
	{
		id: 'csp/conflict',
		area: 'csp',
		levels: ['warn'],
		reason: 'More than one enforcing Content-Security-Policy header is present.',
		what: 'Browsers apply every policy, so the effective policy is the intersection and is stricter than either author intended. This is a breakage risk rather than a weakness, and it is the usual cause of a page that works until a plugin or a CDN adds its own policy.',
	},
	{
		id: 'csp/frame-ancestors-permissive',
		area: 'csp',
		levels: ['error'],
		reason: 'The policy sets frame-ancestors to a value that permits framing.',
		what: 'frame-ancestors supersedes X-Frame-Options in every current browser, so a correct X-Frame-Options sent beside it is not what applies. A site can therefore pass an X-Frame-Options check and be framable, which is why this is an error rather than a warning.',
	},

	// ------------------------------------------------------------------ cookie
	{
		id: 'cookie/no-secure',
		area: 'cookie',
		levels: ['error'],
		reason: 'A session cookie is set on an HTTPS response without the Secure attribute.',
		what: 'The cookie is sent on any later plain HTTP request to the same host, including one an attacker causes by injecting an http:// image.',
	},
	{
		id: 'cookie/no-httponly',
		area: 'cookie',
		levels: ['error'],
		reason: 'A session cookie is set without HttpOnly.',
		what: 'Any injected script can read the session. HttpOnly is what makes a cross-site scripting bug something short of a full account takeover.',
	},
	{
		id: 'cookie/no-samesite',
		area: 'cookie',
		levels: ['warn'],
		reason: 'A session cookie is set without an explicit SameSite attribute.',
		what: 'Browser defaults differ and have changed more than once. A warning rather than an error because the current default in the major engines is Lax, so the gap is narrower than it was, and stating it explicitly is still the only way to know.',
	},
	{
		id: 'cookie/samesite-none-insecure',
		area: 'cookie',
		levels: ['error'],
		reason: 'A cookie declares SameSite=None without Secure.',
		what: 'Browsers reject the cookie outright. This breaks the login as well as weakening it, which is why it is an error: the site is not less secure, it is not working.',
	},
	{
		id: 'cookie/prefix-violation',
		area: 'cookie',
		levels: ['error'],
		reason: 'A cookie named with the __Secure- or __Host- prefix does not meet that prefix rule.',
		what: '__Secure- requires Secure. __Host- requires Secure, requires Path=/ and forbids Domain. A browser silently refuses a cookie that breaks its own prefix rule, so the name that was chosen to make the cookie safer is what stops it being set.',
	},
	{
		id: 'cookie/domain-too-broad',
		area: 'cookie',
		levels: ['warn'],
		reason: 'A session cookie is scoped to a parent domain.',
		what: 'A cookie set on .example.com is sent to every subdomain, including a staging or legacy host that may be running something older. On a multisite install this is often deliberate, which is why it is a warning.',
	},
	{
		id: 'cookie/conflict',
		area: 'cookie',
		levels: ['warn'],
		reason: 'The same cookie name is set twice in one response with different attributes.',
		what: 'The browser keeps the last one, so the attributes that end up applying depend on which line was appended last. Like the other conflict reasons, the point is that the verdict should not be decided by an order nothing promises.',
	},

	// ------------------------------------------------------------------- cache
	{
		id: 'cache/session-cookie-publicly-cacheable',
		area: 'cache',
		levels: ['error'],
		reason: 'A response that sets a session cookie permits storage by a shared cache.',
		what: 'A CDN or reverse proxy may store the response, Set-Cookie and all, and hand it to the next visitor. This is how one user ends up logged in as another, and it is a configuration away on every WordPress site behind a CDN.',
	},
	{
		id: 'cache/no-directive-with-session-cookie',
		area: 'cache',
		levels: ['warn'],
		reason: 'A response sets a session cookie and sends no Cache-Control at all.',
		what: 'With no directive a shared cache applies its own heuristics, which differ between products and change between versions. A warning rather than an error because many caches do refuse to store a response carrying Set-Cookie, and none of them promise to.',
	},

	// -------------------------------------------------------------------- leak
	{
		id: 'leak/pingback',
		area: 'leak',
		levels: ['warn'],
		reason: 'X-Pingback advertises the XML-RPC endpoint.',
		what: 'Every response tells a scanner where the endpoint is. Closing the endpoint matters more than hiding it, and both are cheap.',
	},
	{
		id: 'leak/rest-root',
		area: 'leak',
		levels: ['note'],
		reason: 'A Link header advertises the REST API root.',
		what: 'A note, not a weakness: this is WordPress working as designed. It is here because the users endpoint is one request from that root, and hardening that endpoint is the other half of the author enumeration fix in mu-plugins/02-harden-login.php.',
	},

	// --------------------------------------------------------------- transport
	{
		id: 'transport/not-https',
		area: 'transport',
		levels: ['warn'],
		reason: 'The final URL is HTTP, so HSTS could not be judged.',
		what: 'Nothing about HSTS can be concluded from a plain HTTP response, and guessing would produce a confident finding about a header the browser would have ignored.',
	},
	{
		id: 'transport/url-unknown',
		area: 'transport',
		levels: ['warn'],
		reason: 'No final URL was given and the dump does not carry an absolute one.',
		what: 'Version 2 assumed HTTPS here, and separately treated a relative Location as a non-HTTPS URL, so a dump whose last redirect was to /en/ produced a transport warning and skipped the HSTS checks entirely on a response that had a perfectly good HSTS header. Refusing to decide is the honest answer: a guess is worse than a refusal when the finding looks specific.',
	},

	// -------------------------------------------------------------------- dump
	{
		id: 'dump/folded-header',
		area: 'dump',
		levels: ['note'],
		reason: 'A header value is continued on a following line.',
		what: 'The value is joined before judging, and this note says so, because a tool that silently unfolds is a tool whose output you cannot reconcile against the raw dump. Version 2 did not unfold at all, so a policy whose unsafe-inline sat on the continuation line was reported clean.',
	},
	{
		id: 'dump/empty-final-hop',
		area: 'dump',
		levels: ['error'],
		reason: 'The final hop has a status line and no header lines.',
		what: 'Almost always a dump truncated mid-write rather than a site that sends no headers. The missing findings beside this one are therefore not worth acting on, and saying that is more useful than six confident errors about a file that was cut short.',
	},
];

/**
 * Open families: one id carrying a value read from the response, so the set of
 * concrete messages is not finite. Listed separately because the catalogue test
 * requires each family to be produced rather than requiring an exhaustive list
 * of messages.
 *
 * @type {Array<{id: string, area: string, levels: string[], carries: string, reason: string, what: string}>}
 */
export const FAMILIES = [
	{
		id: 'redirect-only',
		area: 'required',
		levels: ['error'],
		carries: 'the header name',
		what: 'A required header is sent on a redirect hop and not on the final response. Any checker that searches the whole dump calls this a pass, and version 1 of this script did.',
		reason: 'The header appears in the dump but not in the hop the visitor receives.',
	},
	{
		id: 'leak/version',
		area: 'leak',
		levels: ['warn'],
		carries: 'the header name and its value',
		reason: 'A response header gives away a software version with more than one component.',
		what: 'Presence alone is not the finding. Version 1 flagged Server on presence, so every site behind a CDN got a line for Server: cloudflare, and a tool that cries wolf on a header nearly every server sends is a tool whose output gets skimmed.',
	},
	{
		id: 'leak/version-major',
		area: 'leak',
		levels: ['warn'],
		carries: 'the header name and its value',
		reason: 'A response header gives away a single-component version.',
		what: 'X-Powered-By: PHP/8 is a version disclosure and version 2 reported it as clean, because the check required a dotted version. A separate reason because the remedy is the same but the detection is what was wrong.',
	},
	{
		id: 'leak/platform',
		area: 'leak',
		levels: ['note'],
		carries: 'the header name and its value',
		reason: 'A response header names the software without a version.',
		what: 'A note. Server: nginx or X-Redirect-By: WordPress tells a scanner what to try without telling it what to try first. Version 2 printed an OK line for these, which reads as approval of a header that did not need to be sent.',
	},
];

export const ALL = [...FINDINGS, ...FAMILIES];
export const ALL_IDS = ALL.map((f) => f.id);

/** The complete declared severity set for one id. */
export function levelsFor(id) {
	const entry = ALL.find((f) => f.id === id);
	return entry ? entry.levels : null;
}
