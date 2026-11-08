/**
 * One fixture per reason the example pairs do not reach.
 *
 * Eighteen pairs reach 22 of the 48 catalogued findings. A pair has to be a
 * plausible site, which keeps it honest and keeps it from reaching the reasons
 * that only occur one at a time. So the rest get a fixture each, and writing
 * them is where most of the defects in this rebuild came from: the duplicate
 * header cases, the quoted max age, the folded value and the cookie prefix
 * rules all existed as fixtures before they existed as behaviour.
 *
 * Each fixture declares the exact set of findings it produces, as `level:id`,
 * and test/fixtures.test.mjs compares that set both ways. A fixture that
 * produces something it did not declare fails, and a declared finding the
 * fixture does not produce fails too.
 *
 * Several declare an empty set on purpose. Those are the blind side of a
 * declared limit, or of a correction: a quoted max age has to be accepted
 * rather than reported, a twenty digit max age has to be compared rather than
 * crash the shell, a session cookie under a name the script cannot recognise
 * has to produce nothing rather than a guess. An empty declaration is an
 * assertion, and it is the one that catches a checker becoming noisier than it
 * should be.
 *
 * `url` is what the fetch would have reported. Two fixtures deliberately have
 * none, because what they demonstrate is what happens when it is not known.
 */

/** @type {Array<{file: string, url: string|null, about: string, finds: string[]}>} */
export const FIXTURES = [
	// ---------------------------------------------------------------- required
	{
		file: 'required-xcto-empty.headers',
		url: 'https://example.com/',
		about: 'Present with nothing after the colon, which is not the same as absent.',
		finds: ['error:empty/x-content-type-options'],
	},
	{
		file: 'required-xcto-weak.headers',
		url: 'https://example.com/',
		about: 'A value somebody typed. nosniff is the only value the header has.',
		finds: ['error:weak/x-content-type-options'],
	},
	{
		file: 'required-xcto-conflict.headers',
		url: 'https://example.com/',
		about: 'nosniff and then sniff. Combined into one value the browser cannot use.',
		finds: ['error:conflict/x-content-type-options'],
	},
	{
		file: 'required-xfo-missing.headers',
		url: 'https://example.com/',
		about:
			'Absent, with no redirect hop to have carried it, which is what separates this from redirect-only. The two look identical to a checker that searches the whole dump and they need different fixes.',
		finds: ['error:missing/x-frame-options'],
	},
	{
		file: 'required-xfo-empty.headers',
		url: 'https://example.com/',
		about:
			'An empty X-Frame-Options permits framing and passes a presence check. Present and empty is a different reason from absent, and usually a different cause: a plugin writing a setting it was never given.',
		finds: ['error:empty/x-frame-options'],
	},
	{
		file: 'required-rp-missing.headers',
		url: 'https://example.com/',
		about:
			'Absent, so the browser default applies, which is the thing the header was deployed to replace. In most engines that default still sends the full URL to every HTTPS destination.',
		finds: ['error:missing/referrer-policy'],
	},
	{
		file: 'required-rp-empty.headers',
		url: 'https://example.com/',
		about:
			'Present and empty, which also falls back to the browser default, and is reported as its own reason so a reader knows to look for what emitted a bare header rather than for what failed to emit one.',
		finds: ['error:empty/referrer-policy'],
	},
	{
		file: 'required-rp-conflict.headers',
		url: 'https://example.com/',
		about:
			'origin and then unsafe-url. A browser takes the last token it recognises from the combined list, so the effective policy depends on which proxy appended its line last.',
		finds: ['error:conflict/referrer-policy'],
	},
	{
		file: 'required-pp-missing.headers',
		url: 'https://example.com/',
		about:
			'Absent, so nothing is restricted and an injected script can reach for geolocation, camera, microphone and the payment request API. This is the commonest state of this header on a WordPress site.',
		finds: ['error:missing/permissions-policy'],
	},
	{
		file: 'required-pp-weak.headers',
		url: 'https://example.com/',
		about:
			'A bare comma. It parses, it names no feature, and it restricts none, which makes it the one value that is neither absent nor empty nor useful.',
		finds: ['error:weak/permissions-policy'],
	},
	{
		file: 'required-pp-conflict.headers',
		url: 'https://example.com/',
		about:
			'camera=() and then camera=(self). A repeated feature name makes the combined structured header invalid in some engines, so the restriction disappears rather than tightening.',
		finds: ['error:conflict/permissions-policy'],
	},

	// -------------------------------------------------------------------- hsts
	{
		file: 'hsts-missing.headers',
		url: 'https://example.com/',
		about:
			'An HTTPS response with no HSTS at all. Every first visit over HTTP, and every visit arriving from a link that is still HTTP, is interceptable. This is also the contrast case for the limit about an unestablished transport.',
		finds: ['error:missing/strict-transport-security'],
	},
	{
		file: 'hsts-no-max-age.headers',
		url: 'https://example.com/',
		about:
			'includeSubDomains and no max-age. The browser ignores the whole header, so the site has the appearance of HSTS and none of it.',
		finds: ['error:hsts/no-max-age'],
	},
	{
		file: 'hsts-quoted-max-age-is-fine.headers',
		url: 'https://example.com/',
		about:
			'Declares nothing on purpose. A quoted directive value is legal in RFC 6797 and the browser honours it. Version 2 required bare digits and reported this as hsts/no-max-age at error level, which is a working header failing a build.',
		finds: [],
	},
	{
		file: 'hsts-huge-max-age-is-fine.headers',
		url: 'https://example.com/',
		about:
			'Declares nothing on purpose. max-age has no upper bound in the specification and browsers clamp it themselves. Version 2 compared it with shell arithmetic, so a twenty digit value printed two "integer expression expected" errors to stderr and then produced no finding and exit 0.',
		finds: [],
	},
	{
		file: 'hsts-repeated-agreeing.headers',
		url: 'https://example.com/',
		about:
			'Declares nothing on purpose, and it is the false positive the conflict checks have to avoid. The same value sent twice in different letter case is one value to a browser, so a conflict reported here would be a conflict check nobody keeps switched on.',
		finds: [],
	},

	// --------------------------------------------------------------------- csp
	{
		file: 'csp-absent.headers',
		url: 'https://example.com/',
		about:
			'No policy at all. A note rather than a warning, because on a page-builder site not deploying one is often the right call, and a tool that fails a build over it is a tool whose output gets skimmed.',
		finds: ['note:csp/absent'],
	},
	{
		file: 'csp-unsafe-eval.headers',
		url: 'https://example.com/',
		about:
			'A separate reason from unsafe-inline, and a separate fix: unsafe-eval is usually traceable to one named library, where inline script is spread through the theme and the editor. Finding them are different jobs.',
		finds: ['warn:csp/unsafe-eval'],
	},
	{
		file: 'csp-wildcard-script-src.headers',
		url: 'https://example.com/',
		about:
			'A bare https: source, which permits script from every host that scheme can reach, which is every host. The policy still appears in an audit as deployed and it is doing almost nothing.',
		finds: ['warn:csp/wildcard-script-src'],
	},
	{
		file: 'csp-wildcard-via-default-src.headers',
		url: 'https://example.com/',
		about:
			'No script-src at all, and a default-src of asterisk standing in for it. The same reason reached by the fallback the specification defines, which is the path a checker that only reads script-src misses.',
		finds: ['warn:csp/wildcard-script-src'],
	},
	{
		file: 'csp-conflict.headers',
		url: 'https://example.com/',
		about:
			'Two enforcing policies. Browsers apply both, so the effective policy is their intersection and is stricter than either author intended. A warning, because this is a breakage risk rather than a weakness.',
		finds: ['warn:csp/conflict'],
	},

	// ------------------------------------------------------------------ cookie
	{
		file: 'cookie-samesite-none-insecure.headers',
		url: 'https://example.com/',
		about:
			'Not a session cookie, and still a finding: a browser refuses SameSite=None without Secure outright, so this is broken rather than weak, whatever the cookie is for.',
		finds: ['error:cookie/samesite-none-insecure'],
	},
	{
		file: 'cookie-host-prefix-violation.headers',
		url: 'https://example.com/',
		about:
			'__Host- without Secure. The prefix was chosen to make the cookie safer and it is what stops the cookie being set at all.',
		finds: ['error:cookie/prefix-violation'],
	},
	{
		file: 'cookie-secure-prefix-violation.headers',
		url: 'https://example.com/',
		about:
			'__Secure- without Secure. The same reason reached through the other prefix rule, which is here because the two rules have different requirements and an implementation that gets one right usually forgets the other.',
		finds: ['error:cookie/prefix-violation'],
	},
	{
		file: 'cookie-domain-too-broad.headers',
		url: 'https://example.com/',
		about:
			'A session cookie carrying Domain=.example.com on example.com. This is the case that first reported nothing, because the check compared the attribute against the host and they matched. A leading dot is ignored by RFC 6265: the attribute itself is what widens the cookie from one host to every subdomain.',
		finds: ['warn:cookie/domain-too-broad'],
	},
	{
		file: 'cookie-conflict.headers',
		url: 'https://example.com/',
		about:
			'One cookie name set twice with different attributes. The browser keeps the last, so which attributes apply depends on which line was appended last.',
		finds: ['warn:cookie/conflict'],
	},
	{
		file: 'cookie-custom-name-is-invisible.headers',
		url: 'https://example.com/',
		about:
			'Declares nothing on purpose, and it is the blind side of a declared limit. my_app_session carries a session and has none of the attributes that would make it safe, and the script says nothing because it cannot know what the cookie is for. Guessing from the absence of attributes would report every analytics cookie on every site.',
		finds: [],
	},

	{
		file: 'csp-style-only-unsafe-inline.headers',
		url: 'https://example.com/',
		about:
			'Declares nothing on purpose, and it is the blind side of a declared limit. The policy permits unsafe-inline for styles and not for scripts. An inline style is a different and much smaller problem than an inline script, so the check reads the script source list rather than the whole policy. A lexical search of the header would report this, and reporting it would be a false positive on most real WordPress policies.',
		finds: [],
	},
	{
		file: 'csp-strict-dynamic-still-reported.headers',
		url: 'https://example.com/',
		about:
			'The other side of the same limit, and an honest false positive. strict-dynamic makes browsers ignore the host sources beside it, so the bare https: in this policy does nothing and the finding is wrong. The check is lexical and does not model directive interactions, which is stated as a limit rather than guessed at. Declared here so it is a known cost rather than a surprise.',
		finds: ['warn:csp/wildcard-script-src'],
	},

	// -------------------------------------------------------------------- leak
	{
		file: 'leak-unlisted-header.headers',
		url: 'https://example.com/',
		about:
			'Declares nothing on purpose. x-backend-version: 3.4.1 is a version disclosure and the script says nothing, because it inspects five named headers rather than looking for version-shaped values anywhere. The alternative reports a build number in a cache header on every site behind a CDN.',
		finds: [],
	},
	{
		file: 'leak-version-major.headers',
		url: 'https://example.com/',
		about:
			'PHP/8. A version with one component is still a version, and version 2 required a dotted one, so it printed an OK line for this.',
		finds: ['warn:leak/version-major'],
	},
	{
		file: 'leak-rest-root.headers',
		url: 'https://example.com/',
		about:
			'The Link header WordPress sends by design. A note rather than a weakness, kept because the users endpoint is one request from that root, and hardening that endpoint is the other half of the author enumeration fix in mu-plugins/02-harden-login.php.',
		finds: ['note:leak/rest-root'],
	},

	// --------------------------------------------------------------- transport
	{
		file: 'transport-not-https.headers',
		url: 'http://example.com/',
		about:
			'A plain HTTP final response. Nothing about HSTS can be concluded, and the header that is present in the dump is deliberately not judged.',
		finds: ['warn:transport/not-https'],
	},
	{
		file: 'transport-url-unknown.headers',
		url: null,
		about:
			'A redirect to /en/ and no final URL given. Version 2 took that relative Location as the final URL, decided it was not HTTPS, and skipped every HSTS check on a response carrying a perfectly good HSTS header. Refusing to decide is the honest answer.',
		finds: ['warn:transport/url-unknown'],
	},

	// -------------------------------------------------------------------- dump
	{
		file: 'dump-empty-final-hop.headers',
		url: 'https://example.com/',
		about:
			'A status line and nothing else, which is a truncated file rather than a site. The five missing findings are declared alongside it because they are what the script does say, and the point of the first finding is to tell a reader not to act on them.',
		finds: [
			'error:dump/empty-final-hop',
			'error:missing/x-content-type-options',
			'error:missing/x-frame-options',
			'error:missing/referrer-policy',
			'error:missing/permissions-policy',
			'error:missing/strict-transport-security',
			'note:csp/absent',
		],
	},
];

/** Every id a fixture declares. */
export function idsReachedByFixtures() {
	const ids = new Set();
	for (const fixture of FIXTURES) {
		for (const entry of fixture.finds) {
			ids.add(entry.slice(entry.indexOf(':') + 1));
		}
	}
	return ids;
}
