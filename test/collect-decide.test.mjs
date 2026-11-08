import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT } from '../tools/judge.mjs';

const DECIDE = join(ROOT, 'scripts', 'collect-decide.sh');

/**
 * The decisions that used to sit beside the curl call.
 *
 * Everything in this file was in scripts/check-headers.sh in version 2, where
 * the only coverage it could have was `bash -n`. A file that is only syntax
 * checked has no coverage at all, and --save had already shipped broken once:
 * the EXIT trap meant to clean up ran before the copy, so the option quietly
 * did nothing and the message saying it had worked was printed anyway.
 */
function work() {
	return mkdtempSync(join(tmpdir(), 'wpsh-decide-'));
}

function plan(args, dir = work()) {
	const planFile = join(dir, 'plan');
	const result = spawnSync('bash', [DECIDE, 'plan', planFile, '--', ...args], { encoding: 'utf8', cwd: ROOT });
	return { ...result, planFile, dir };
}

function finish({ planFile, dump, meta, dir }) {
	const dumpFile = join(dir, 'dump');
	const metaFile = join(dir, 'meta');
	writeFileSync(dumpFile, dump);
	writeFileSync(metaFile, meta);
	const result = spawnSync('bash', [DECIDE, 'finish', '--plan', planFile, '--dump', dumpFile, '--meta', metaFile], {
		encoding: 'utf8',
		cwd: ROOT,
	});
	return { ...result, argv: (result.stdout || '').split('\n').filter(Boolean), dumpFile };
}

const GOOD_DUMP = 'HTTP/2 200\nx-frame-options: DENY\n\n';

test('a URL and nothing else is a valid plan', () => {
	const result = plan(['https://example.test/']);
	assert.equal(result.status, 0);
	assert.equal(result.stdout.trim(), 'https://example.test/');
	const written = readFileSync(result.planFile, 'utf8');
	assert.match(written, /^url=https:\/\/example\.test\/$/m);
	assert.match(written, /^save=$/m);
	assert.match(written, /^json=0$/m);
});

test('the json option is recorded and passed through to the judge', () => {
	const planned = plan(['https://example.test/', '--json']);
	assert.equal(planned.status, 0);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/\n200\n' });
	assert.equal(result.status, 0);
	assert.ok(result.argv.includes('--json'));
});

test('a URL with no scheme is refused before anything is fetched', () => {
	const result = plan(['example.test']);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /needs a scheme/);
});

test('two URLs are refused rather than one of them being picked', () => {
	const result = plan(['https://a.test/', 'https://b.test/']);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /more than one URL/);
});

test('an unknown option is refused', () => {
	const result = plan(['https://example.test/', '--wat']);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /unknown option/);
});

test('save with no file name is refused', () => {
	const result = plan(['https://example.test/', '--save']);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /file name/);
});

test('save followed by an option is refused rather than writing to a file called --json', () => {
	const result = plan(['https://example.test/', '--save', '--json']);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /not an option/);
});

test('no URL at all is refused', () => {
	const result = plan([]);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /URL is required/);
});

test('the judge argument list names the dump and the effective URL', () => {
	const planned = plan(['https://example.test/']);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/en/\n200\n' });
	assert.equal(result.status, 0);
	assert.deepEqual(result.argv, [result.dumpFile, '--url', 'https://example.test/en/']);
});

test('the effective URL is the one the fetch reported, not the one asked for', () => {
	// The HSTS decision is made about the response being judged, which is the
	// one at the end of the redirect chain. Version 1 made two requests and so
	// could judge one response against another response's URL.
	const planned = plan(['http://example.test/']);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://www.example.test/\n200\n' });
	assert.ok(result.argv.includes('https://www.example.test/'));
	assert.ok(!result.argv.includes('http://example.test/'));
});

test('an empty dump is reported rather than judged', () => {
	const planned = plan(['https://example.test/']);
	const result = finish({ ...planned, dump: '', meta: 'https://example.test/\n200\n' });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /received no headers/);
});

test('a non 2xx final status is warned about and still judged', () => {
	const planned = plan(['https://example.test/']);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/\n404\n' });
	assert.equal(result.status, 0);
	assert.match(result.stderr, /may be an error page/);
	assert.ok(result.argv.length >= 1);
});

test('a 2xx final status is not warned about', () => {
	const planned = plan(['https://example.test/']);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/\n204\n' });
	assert.doesNotMatch(result.stderr, /may be an error page/);
});

test('a missing status is warned about in its own words', () => {
	const planned = plan(['https://example.test/']);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/\n\n' });
	assert.match(result.stderr, /did not report a status code/);
});

test('a missing effective URL leaves the judge to refuse rather than guessing one', () => {
	const planned = plan(['https://example.test/']);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: '\n200\n' });
	assert.equal(result.status, 0);
	assert.ok(!result.argv.includes('--url'), 'no url should be passed when none was reported');
	assert.match(result.stderr, /HSTS cannot be judged/);
});

/**
 * The option that had already shipped broken. It is written before anything
 * else can fail and it is written explicitly rather than from a trap.
 */
test('save writes the dump where it was asked to', () => {
	const dir = work();
	const target = join(dir, 'saved.headers');
	const planned = plan(['https://example.test/', '--save', target], dir);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/\n200\n' });
	assert.equal(result.status, 0);
	assert.equal(readFileSync(target, 'utf8'), GOOD_DUMP);
	assert.match(result.stderr, /Saved the response headers/);
});

test('a save path that cannot be written is an error, not a silent skip', () => {
	const dir = work();
	const planned = plan(['https://example.test/', '--save', join(dir, 'no', 'such', 'dir', 'x.headers')], dir);
	const result = finish({ ...planned, dump: GOOD_DUMP, meta: 'https://example.test/\n200\n' });
	assert.equal(result.status, 2);
	assert.match(result.stderr, /could not write/);
});

test('a plan file is read with a parser, not sourced', () => {
	// Sourcing the plan would let a URL containing a semicolon run as shell. The
	// value is written verbatim and read back verbatim.
	const dir = work();
	const planFile = join(dir, 'plan');
	writeFileSync(planFile, 'url=https://example.test/?a=1;echo PWNED\nsave=\njson=0\n');
	const result = finish({ planFile, dir, dump: GOOD_DUMP, meta: 'https://example.test/\n200\n' });
	assert.doesNotMatch(result.stdout + result.stderr, /PWNED/);
});

test('a missing input file is a usage error rather than a crash', () => {
	const dir = work();
	const result = spawnSync(
		'bash',
		[DECIDE, 'finish', '--plan', join(dir, 'nope'), '--dump', join(dir, 'nope'), '--meta', join(dir, 'nope')],
		{ encoding: 'utf8', cwd: ROOT },
	);
	assert.equal(result.status, 2);
	assert.match(result.stderr, /no such file/);
});

test('an unknown mode is a usage error', () => {
	const result = spawnSync('bash', [DECIDE, 'wat'], { encoding: 'utf8', cwd: ROOT });
	assert.equal(result.status, 2);
	assert.match(result.stderr, /usage/);
});
