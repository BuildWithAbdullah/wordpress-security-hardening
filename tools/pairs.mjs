/**
 * Every example pair, with the exact set of findings each side produces.
 *
 * A pair is a failing file and the corrected file beside it. The point of
 * writing the expectations down rather than snapshotting them is the
 * `residual` field: the exact set of findings that survive the correction.
 *
 * Asserted as set equality in both directions, not as inclusion. A corrected
 * example that still produces something is fine, and often unavoidable, but the
 * set has to be declared and it has to be exactly right. Checking only that the
 * headline finding has gone lets a correction introduce a second problem and
 * still pass, which is how a repository ends up shipping a fix that is worse
 * than what it replaced.
 *
 * Findings are written as `level:id` so the expected exit code is derivable
 * from the manifest and the severity table rather than from a list kept inside
 * tools/exit-codes.mjs. A list inside the tool is a second copy of the
 * expectations, and a second copy is a thing that drifts.
 */

/** @type {Array<{stem: string, kind: 'headers', url: string, about: string, finds: string[], residual: string[]}>} */
export const HEADER_PAIRS = [
	{
		stem: '01-x-frame-options-permissive',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A value that passes a presence check and permits framing by anyone. Version 1 of the script accepted any value here, so this reported OK.',
		finds: ['error:weak/x-frame-options'],
		residual: [],
	},
	{
		stem: '02-nosniff-missing',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'The header a site with a media library most needs, absent. Without it a file served as text/plain that happens to contain markup can be sniffed and executed as HTML, and any site with a media library accepts uploads.',
		finds: ['error:missing/x-content-type-options'],
		residual: [],
	},
	{
		stem: '03-referrer-policy-unsafe',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'unsafe-url, which sends the whole URL to every destination, including a path carrying a password reset token.',
		finds: ['error:weak/referrer-policy'],
		residual: [],
	},
	{
		stem: '04-permissions-policy-empty',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'Present with nothing after the colon, which is what several caching plugins emit. It restricts no feature and satisfies any check that asks whether the name appears.',
		finds: ['error:empty/permissions-policy'],
		residual: [],
	},
	{
		stem: '05-hsts-staging-max-age',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A five minute max age, which is the value you deploy with and then forget to raise. A warning rather than a failure, because starting short is the correct way to deploy HSTS and a check that fails a build for it is a check somebody switches off.',
		finds: ['warn:hsts/short-max-age'],
		residual: [],
	},
	{
		stem: '06-hsts-disabled',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'max-age=0, which is the back-out value left in place. Zero tells every browser that has the policy to forget it, so a site in this state has the header, has no HSTS, and passes any check that only asks whether the header is present.',
		finds: ['error:hsts/disabled'],
		residual: [],
	},
	{
		stem: '07-headers-on-redirect-only',
		kind: 'headers',
		url: 'https://example.com/home/',
		about:
			'Every header sent on the 301 and three of them missing from the page. Any checker that greps the whole dump calls this a pass, and version 1 did.',
		finds: ['error:redirect-only'],
		residual: [],
	},
	{
		stem: '08-csp-unsafe-inline',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A policy that permits the injection it was deployed to stop. The corrected side uses a nonce, which is what a WordPress site actually needs.',
		finds: ['warn:csp/unsafe-inline'],
		residual: [],
	},
	{
		stem: '09-version-disclosure',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'Two headers carrying a version. The corrected side still names the software, which is why leak/platform is in the residual set rather than absent from it: this is as far as a header can be trimmed without lying about what is serving the page.',
		finds: ['warn:leak/version'],
		residual: ['note:leak/platform'],
	},
	{
		stem: '10-pingback-advertised',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'X-Pingback telling a scanner where the XML-RPC endpoint is, on every response. Closing the endpoint matters more than hiding it, which is what mu-plugins/01-disable-xmlrpc.php does, and both are cheap.',
		finds: ['warn:leak/pingback'],
		residual: [],
	},
	{
		stem: '15-hsts-duplicated',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'HSTS sent twice, max-age=0 first and a year second. RFC 6797 says the browser honours the first, so this site has no HSTS. Version 2 read the last line and reported it clean.',
		finds: ['error:hsts/conflict', 'error:hsts/disabled'],
		residual: [],
	},
	{
		stem: '16-x-frame-options-duplicated',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'ALLOWALL and then SAMEORIGIN. The browser sees the two combined, which is not a value it can parse, so it applies no framing protection. Version 2 reported this as a pass, and the same response with the lines swapped as a failure.',
		finds: ['error:conflict/x-frame-options'],
		residual: [],
	},
	{
		stem: '17-session-cookie-unflagged',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A logged-in cookie with a path and nothing else. Four findings at once, which is the honest count: each attribute is a separate decision somebody did not make.',
		finds: [
			'error:cookie/no-secure',
			'error:cookie/no-httponly',
			'warn:cookie/no-samesite',
			'warn:cache/no-directive-with-session-cookie',
		],
		residual: [],
	},
	{
		stem: '18-session-cookie-publicly-cacheable',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A correctly flagged session cookie on a response marked public. A shared cache may store it and hand it to the next visitor, which is how one person ends up logged in as another, and it is a configuration away on any site behind a CDN.',
		finds: ['error:cache/session-cookie-publicly-cacheable'],
		residual: [],
	},
	{
		stem: '19-frame-ancestors-supersedes-xfo',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A correct X-Frame-Options beside a policy whose frame-ancestors permits anyone. frame-ancestors wins in every current browser, so the site passes an X-Frame-Options check and is framable. An error rather than a warning for that reason.',
		finds: ['error:csp/frame-ancestors-permissive'],
		residual: [],
	},
	{
		stem: '20-hsts-preload-incomplete',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'preload with a thirty day max age and no includeSubDomains. The preload list refuses the submission, so the risk of preloading has been taken and the benefit was never collected.',
		finds: ['error:hsts/preload-without-subdomains'],
		residual: [],
	},
	{
		stem: '21-folded-policy-hides-inline',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A policy whose unsafe-inline sits on a continuation line. One value to every HTTP parser and invisible to version 2, which did not unfold. Both sides are folded, so the note is in the residual set: the correction here is the policy, not the folding.',
		finds: ['note:dump/folded-header', 'warn:csp/unsafe-inline'],
		residual: ['note:dump/folded-header'],
	},
	{
		stem: '22-csp-report-only-only',
		kind: 'headers',
		url: 'https://example.com/',
		about:
			'A Report-Only policy and nothing enforcing. The right first step and a common last one: it appears in any audit that greps for a policy and it has never blocked anything.',
		finds: ['warn:csp/report-only-only'],
		residual: [],
	},
];

/**
 * The PHP pairs are judged by an audit rather than by a finding set, because
 * what they demonstrate is a behaviour rather than a header. See
 * tools/audits.mjs.
 */
export const PHP_PAIR_STEMS = [
	'11-login-errors-unconditional',
	'12-author-redirect-permanent',
	'13-ip-allowlist-ipv4-only',
	'14-headers-frontend-only',
	'23-xff-leftmost-trusted',
	'24-permissions-policy-blocks-payment',
	'25-hsts-backout-omits-header',
];

/** The ids a header pair reaches, on either side. */
export function idsReachedByPairs() {
	const ids = new Set();
	for (const pair of HEADER_PAIRS) {
		for (const entry of [...pair.finds, ...pair.residual]) {
			ids.add(entry.slice(entry.indexOf(':') + 1));
		}
	}
	return ids;
}

/** An error anywhere in the expected set means the run exits 1. */
export function expectedExit(entries) {
	return entries.some((entry) => entry.startsWith('error:')) ? 1 : 0;
}
