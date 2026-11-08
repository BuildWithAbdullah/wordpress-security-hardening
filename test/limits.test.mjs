import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { judgeFile, judge, ROOT, cleanResponse } from '../tools/judge.mjs';
import { probe } from '../tools/php.mjs';
import { LIMITS, LIMIT_IDS } from '../tools/limits.mjs';
import { FIXTURES } from '../tools/fixtures.mjs';
import { HEADER_PAIRS } from '../tools/pairs.mjs';

const JUDGE = join(ROOT, 'scripts', 'judge-headers.sh');
const HEADERS_PLUGIN = 'mu-plugins/00-security-headers.php';
const LOGIN_PLUGIN = 'mu-plugins/02-harden-login.php';

/**
 * Every limit is checked in both directions.
 *
 * `blind` is the case the limit says nothing about, and it has to produce
 * nothing. `contrast` is the nearby case the repository does catch, and it has
 * to produce something.
 *
 * The second direction is the one that earns its keep. A limit whose blind case
 * quietly started producing a finding is a limit that has been fixed and should
 * be deleted; a limit whose contrast case quietly stopped producing one is a
 * check that has stopped working, and the prose would still read correctly
 * either way.
 *
 * The probes below are named in tools/limits.mjs and resolved here, so a limit
 * cannot name a demonstration that does not exist.
 */
const PROBES = {
	'judge-refuses-two-dumps'() {
		const result = spawnSync('bash', [JUDGE, 'fixtures/csp-absent.headers', 'fixtures/hsts-missing.headers'], {
			cwd: ROOT,
			encoding: 'utf8',
		});
		// Two dumps is a usage error, not a pair of runs. One response is judged
		// per invocation and the tool says so rather than quietly judging one of
		// them.
		return { produced: false, detail: `exit ${result.status}`, ok: result.status === 2 };
	},

	'judge-reads-only-the-final-hop'() {
		const dump =
			'HTTP/1.1 301\nlocation: https://example.test/\nx-frame-options: SAMEORIGIN\n\n' +
			cleanResponse({ 'x-frame-options': null });
		const ids = judge(dump, { url: 'https://example.test/' }).findings.map((f) => f.id);
		return { produced: ids.includes('redirect-only'), detail: ids.join(' '), ok: true };
	},

	'plugins-send-only-through-php-hooks'() {
		// Nothing in the plugins writes a server configuration file or shells
		// out, so there is no route by which they could affect a response PHP
		// never serves. That is the limit, and this is what makes it true rather
		// than merely stated.
		const forbidden = [/file_put_contents/, /\bfopen\s*\(/, /\bexec\s*\(/, /shell_exec/, /\bsystem\s*\(/, /proc_open/];
		const sources = ['mu-plugins/00-security-headers.php', 'mu-plugins/01-disable-xmlrpc.php', LOGIN_PLUGIN].map(
			(file) => readFileSync(join(ROOT, file), 'utf8'),
		);
		const hits = [];
		for (const [index, text] of sources.entries()) {
			for (const pattern of forbidden) {
				if (pattern.test(text)) hits.push(`${index}:${pattern}`);
			}
		}
		return { produced: hits.length > 0, detail: hits.join(' '), ok: true };
	},

	'header-set-is-observable'() {
		const out = probe({
			load: [HEADERS_PLUGIN],
			ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
		});
		const value = out.results['0'].value;
		return { produced: value && Object.keys(value).length >= 5, detail: Object.keys(value || {}).join(' '), ok: true };
	},

	'plugins-keep-no-state'() {
		// No attempt counter, no lockout table, no option writes. A must-use
		// plugin that wrote a row per failed login would be a denial of service
		// surface rather than a defence.
		const forbidden = [/update_option/, /add_option/, /set_transient/, /update_user_meta/, /\$wpdb/];
		const hits = [];
		for (const file of ['mu-plugins/00-security-headers.php', 'mu-plugins/01-disable-xmlrpc.php', LOGIN_PLUGIN]) {
			const text = readFileSync(join(ROOT, file), 'utf8');
			for (const pattern of forbidden) if (pattern.test(text)) hits.push(`${file} ${pattern}`);
		}
		return { produced: hits.length > 0, detail: hits.join(' '), ok: true };
	},

	'enumeration-is-blocked'() {
		const out = probe({
			load: [LOGIN_PLUGIN],
			state: { logged_in: false, is_author: true },
			ops: [{ op: 'do_action', tag: 'template_redirect' }],
		});
		return { produced: out.events.redirects.length === 1, detail: JSON.stringify(out.events.redirects), ok: true };
	},

	'shim-has-no-database'() {
		const text = readFileSync(join(ROOT, 'lib', 'wp-shim.php'), 'utf8');
		const forbidden = [/\$wpdb/, /mysqli/, /\bPDO\b/, /SELECT .* FROM/i];
		const hits = forbidden.filter((pattern) => pattern.test(text)).map(String);
		return { produced: hits.length > 0, detail: hits.join(' '), ok: true };
	},

	'shim-fires-real-hooks'() {
		// A real filter in a real plugin changing a real value. The shim is not
		// WordPress and it is not a mock either, which is the half of the trade
		// that works.
		const out = probe({
			load: ['mu-plugins/01-disable-xmlrpc.php'],
			ops: [{ op: 'apply_filters', tag: 'xmlrpc_enabled', value: true }],
		});
		return { produced: out.results['0'].value === false, detail: JSON.stringify(out.results['0']), ok: true };
	},

	'overstated-hop-count-reads-a-forged-entry'() {
		// One hop declared and no proxy actually present. The chain is the
		// client's own header plus the client's own address, so one in from the
		// end is what the client wrote. There is no signal in the request that
		// distinguishes this from a real proxy, which is the limit.
		const out = probe({
			load: [LOGIN_PLUGIN],
			state: { server: { REMOTE_ADDR: '198.51.100.77', HTTP_X_FORWARDED_FOR: '203.0.113.42' } },
			constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
			ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
		});
		// `produced: false` means the repository does not catch this, which is
		// what the limit claims.
		return { produced: out.results['0'].value !== '203.0.113.42', detail: String(out.results['0'].value), ok: true };
	},

	'correct-hop-count-ignores-a-forged-entry'() {
		const out = probe({
			load: [LOGIN_PLUGIN],
			state: {
				server: { REMOTE_ADDR: '10.0.0.1', HTTP_X_FORWARDED_FOR: '203.0.113.42, 198.51.100.77' },
			},
			constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
			ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
		});
		return { produced: out.results['0'].value === '198.51.100.77', detail: String(out.results['0'].value), ok: true };
	},
};

function resolve(reference) {
	/**
	 * `absent`, where a limit declares it, narrows what counts as produced. A
	 * blind case may report that it is refusing to decide; it may not report the
	 * decision.
	 */
	const judged = (ids) => {
		const relevant = reference.absent ? ids.filter((id) => reference.absent.some((p) => id.startsWith(p))) : ids;
		return { produced: relevant.length > 0, detail: ids.join(' ') || '(nothing)', ok: true };
	};

	if (reference.kind === 'fixture') {
		const fixture = FIXTURES.find((f) => f.file === reference.ref);
		assert.ok(fixture, `no fixture named ${reference.ref}`);
		const result = judgeFile(`fixtures/${fixture.file}`, fixture.url ? { url: fixture.url } : {});
		return judged(result.findings.map((f) => f.id));
	}
	if (reference.kind === 'pair') {
		const pair = HEADER_PAIRS.find((p) => p.stem === reference.ref);
		assert.ok(pair, `no pair named ${reference.ref}`);
		const result = judgeFile(`examples/${pair.stem}.fail.headers`, { url: pair.url });
		return judged(result.findings.map((f) => f.id));
	}
	const probeFn = PROBES[reference.ref];
	assert.ok(probeFn, `no probe named ${reference.ref}`);
	return probeFn();
}

test('every limit names a demonstration that exists', () => {
	for (const limit of LIMITS) {
		assert.doesNotThrow(() => resolve(limit.blind), `${limit.id}: blind case ${limit.blind.ref} does not resolve`);
		assert.doesNotThrow(
			() => resolve(limit.contrast),
			`${limit.id}: contrast case ${limit.contrast.ref} does not resolve`,
		);
	}
});

test('the blind side of every limit produces nothing', () => {
	for (const limit of LIMITS) {
		const outcome = resolve(limit.blind);
		assert.ok(outcome.ok, `${limit.id}: the blind probe itself failed (${outcome.detail})`);
		assert.equal(
			outcome.produced,
			false,
			`${limit.id}: the blind case produced something (${outcome.detail}), so the limit no longer holds and should be deleted rather than left in the documentation`,
		);
	}
});

test('the contrast side of every limit produces something', () => {
	for (const limit of LIMITS) {
		const outcome = resolve(limit.contrast);
		assert.ok(outcome.ok, `${limit.id}: the contrast probe itself failed (${outcome.detail})`);
		assert.equal(
			outcome.produced,
			true,
			`${limit.id}: the nearby case this repository is supposed to catch produced nothing (${outcome.detail}), so a check has stopped working`,
		);
	}
});

test('every limit states what it cannot do and why', () => {
	for (const limit of LIMITS) {
		assert.ok(limit.limit && limit.limit.length > 80, `${limit.id} does not state the limit`);
		assert.ok(limit.why && limit.why.length > 80, `${limit.id} does not say why it is the right trade`);
	}
});

test('limit ids are unique', () => {
	assert.equal(new Set(LIMIT_IDS).size, LIMIT_IDS.length);
});

test('there are enough limits to be an honest account', () => {
	// Version 2 declared none at all, which is what made this the first thing to
	// fix. The number is a floor rather than a target: the point is that a
	// repository making this many claims has more than a couple of edges.
	assert.ok(LIMITS.length >= 8, `only ${LIMITS.length} limits declared`);
});

test('every probe named in the file is used by a limit', () => {
	const used = new Set();
	for (const limit of LIMITS) {
		for (const reference of [limit.blind, limit.contrast]) {
			if (reference.kind === 'probe') used.add(reference.ref);
		}
	}
	const unused = Object.keys(PROBES).filter((name) => !used.has(name));
	assert.deepEqual(unused, [], 'a probe nothing references is a demonstration of nothing');
});

test('docs/06 names every declared limit', () => {
	// The prose and the manifest have to agree, or a reader is told about a
	// different set of limits than the suite checks.
	const text = readFileSync(join(ROOT, 'docs', '06-what-the-checks-do-not-see.md'), 'utf8');
	for (const limit of LIMITS) {
		assert.ok(text.includes(limit.id), `docs/06 does not mention the limit ${limit.id}`);
	}
});
