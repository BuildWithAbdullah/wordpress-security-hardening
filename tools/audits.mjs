/**
 * One audit per PHP example pair.
 *
 * An audit is a question put to a loaded file. It returns true when the file
 * behaves correctly, and the contract every audit has to satisfy is:
 *
 *   false on the failing example
 *   true  on the corrected example
 *   true  on the shipped plugin the pair was drawn from
 *   false when nothing is loaded at all
 *
 * The last one is what stops an audit that is really asking nothing. An audit
 * that passes against an empty page has never been seen to catch anything, and
 * the only way to find that out is to try it. Where an audit genuinely cannot
 * fail against an empty page, it says so and says why, in writing, rather than
 * leaving the hole as an oversight.
 *
 * The third one is what stops the examples drifting from the plugins they exist
 * to explain. An example that documents a correction the plugin no longer makes
 * is worse than no example.
 *
 * Kept here rather than inside the test file so tools/audit-verdicts.mjs can
 * derive the same four expectations from the same manifest and run them in
 * separate processes, outside the test runner. Two gates reading one manifest,
 * rather than two lists that drift.
 */

import { probe } from './php.mjs';

export const AUDITS = {
	'11-login-errors-unconditional': {
		plugin: 'mu-plugins/02-harden-login.php',
		proves: 'a login notice that is not an authentication failure survives the filter',
		run(load) {
			const out = probe({
				load,
				error_codes: [],
				ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'You are now logged out.' }],
			});
			return out.results['0'].value === 'You are now logged out.';
		},
		emptyPasses: true,
		emptyReason:
			'no filter registered means no message is rewritten, so the correct outcome happens for the wrong reason. The failing example is what gives this audit its teeth.',
	},

	'12-author-redirect-permanent': {
		plugin: 'mu-plugins/02-harden-login.php',
		proves: 'the author archive block is reversible, which means a 302',
		run(load) {
			const out = probe({
				load,
				state: { logged_in: false, is_author: true },
				ops: [{ op: 'do_action', tag: 'template_redirect' }],
			});
			return out.events.redirects.length === 1 && out.events.redirects[0].status === 302;
		},
	},

	'13-ip-allowlist-ipv4-only': {
		plugin: 'mu-plugins/02-harden-login.php',
		proves: 'an IPv6 client inside an allowlisted IPv6 range is matched, and IPv4 still is',
		run(load) {
			const out = probe({
				load,
				ops: [
					{ op: 'call', fn: 'wpsh_ip_in_range', args: ['2001:db8:1234:5678::1', '2001:db8:1234::/48'] },
					{ op: 'call', fn: 'wpsh_ip_in_range', args: ['203.0.113.42', '203.0.113.0/24'] },
				],
			});
			// Both have to hold. A matcher that fixed IPv6 by breaking IPv4 is
			// not a correction.
			return out.results['0'].value === true && out.results['1'].value === true;
		},
	},

	'14-headers-frontend-only': {
		plugin: 'mu-plugins/00-security-headers.php',
		proves: 'the login page receives the headers, not only the front end',
		run(load) {
			const out = probe({
				load,
				state: { is_ssl: true },
				ops: [{ op: 'do_action', tag: 'login_init' }],
			});
			const sent = out.events.sent_headers.map((h) => h.name);
			return sent.includes('X-Frame-Options') && sent.includes('Strict-Transport-Security');
		},
	},

	'23-xff-leftmost-trusted': {
		plugin: 'mu-plugins/02-harden-login.php',
		proves:
			'a forged leftmost X-Forwarded-For entry is not what the allowlist reads, and the real client behind the same proxy still is',
		run(load) {
			// An attacker at 198.51.100.77 claiming to be an allowlisted
			// address. One proxy, so the chain the origin sees is the forged
			// entry, then the attacker, then the proxy as REMOTE_ADDR.
			const forged = probe({
				load,
				state: {
					server: {
						REMOTE_ADDR: '198.51.100.3',
						HTTP_X_FORWARDED_FOR: '203.0.113.10, 198.51.100.77',
					},
				},
				constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
				ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
			});

			// The same topology with nothing forged. A correction that closed
			// the hole by refusing every proxied request would pass the first
			// half and be useless, so both halves are required.
			const honest = probe({
				load,
				state: {
					server: {
						REMOTE_ADDR: '198.51.100.3',
						HTTP_X_FORWARDED_FOR: '203.0.113.10',
					},
				},
				constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
				ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
			});

			return forged.results['0'].value === '198.51.100.77' && honest.results['0'].value === '203.0.113.10';
		},
	},

	'24-permissions-policy-blocks-payment': {
		plugin: 'mu-plugins/00-security-headers.php',
		proves: 'the default Permissions-Policy restricts no payment or wallet feature',
		run(load) {
			const out = probe({
				load,
				ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
			});
			const value = (out.results['0'].value || {})['Permissions-Policy'];
			if (typeof value !== 'string' || value.length === 0) return false;
			// payment=() with any spacing. The directive is what disables the
			// Payment Request API, which is what every wallet button is built
			// on.
			return !/(^|[,\s])payment\s*=\s*\(\s*\)/i.test(value);
		},
	},

	'25-hsts-backout-omits-header': {
		plugin: 'mu-plugins/00-security-headers.php',
		proves: 'a max age of zero sends max-age=0 rather than sending nothing',
		run(load) {
			const out = probe({
				load,
				constants: { WPSH_HSTS_MAX_AGE: 0 },
				ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
			});
			const value = (out.results['0'].value || {})['Strict-Transport-Security'];
			return value === 'max-age=0';
		},
	},
};

export const AUDIT_STEMS = Object.keys(AUDITS);

/**
 * The four expectations, derived rather than listed. tools/audit-verdicts.mjs
 * and test/php-pairs.test.mjs both read this, so there is one copy of the
 * contract.
 */
export function expectationsFor(stem) {
	const audit = AUDITS[stem];
	const cases = [
		{ name: 'failing example', load: [`examples/${stem}.fail.php`], expect: false },
		{ name: 'corrected example', load: [`examples/${stem}.pass.php`], expect: true },
		{ name: 'shipped plugin', load: [audit.plugin], expect: true },
	];
	if (!audit.emptyPasses) {
		cases.push({ name: 'nothing loaded', load: [], expect: false });
	}
	return cases;
}
