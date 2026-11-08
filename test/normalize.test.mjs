import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT } from '../tools/judge.mjs';

const JUDGE = join(ROOT, 'scripts', 'judge-headers.sh');

/**
 * The parser, driven on its own.
 *
 * Version 2 had three defects and all three were in the parsing, not in the
 * judging: a case sensitive hop count behind a case insensitive validity check,
 * one value read per header name where HTTP allows several, and no unfolding at
 * all. None of them could be seen, because the parser had no output of its own.
 * It does now, and this file is the reason it does. A parser nothing can observe
 * is a parser nobody has checked.
 */
function normalize(dump) {
	const dir = mkdtempSync(join(tmpdir(), 'wpsh-norm-'));
	const path = join(dir, 'response.headers');
	writeFileSync(path, dump, 'utf8');
	const out = execFileSync('bash', [JUDGE, path, '--normalize'], { encoding: 'utf8' });
	return out
		.split('\n')
		.filter(Boolean)
		.map((line) => line.split('\t'));
}

function headers(records, hop) {
	return records.filter((r) => r[0] === 'H' && (hop === undefined || Number(r[1]) === hop)).map((r) => [r[2], r[3]]);
}

function meta(records, key) {
	const row = records.find((r) => r[0] === 'M' && r[1] === key);
	return row ? Number(row[2]) : undefined;
}

test('a single hop is one hop', () => {
	const records = normalize('HTTP/2 200\nx-frame-options: DENY\n\n');
	assert.equal(meta(records, 'hops'), 1);
	assert.deepEqual(headers(records, 1), [['x-frame-options', 'DENY']]);
});

test('each hop keeps its own headers', () => {
	const records = normalize(
		'HTTP/1.1 301\nlocation: https://example.test/\nx-frame-options: DENY\n\n' +
			'HTTP/2 200\nx-frame-options: SAMEORIGIN\n\n',
	);
	assert.equal(meta(records, 'hops'), 2);
	assert.deepEqual(headers(records, 1), [
		['location', 'https://example.test/'],
		['x-frame-options', 'DENY'],
	]);
	assert.deepEqual(headers(records, 2), [['x-frame-options', 'SAMEORIGIN']]);
});

/**
 * The defect that undid the whole point of version 2. The validity check was
 * `grep -qi '^HTTP/'` and the hop count was `awk '/^HTTP\//'`, so a dump whose
 * status lines were lowercase passed validation and then counted as zero hops,
 * which merged every hop into one block. A header sent only on the redirect read
 * as present on the final response, which is exactly the finding version 2
 * existed to add.
 */
test('status lines are recognised whatever their case', () => {
	const records = normalize(
		'http/1.1 301\nlocation: https://example.test/\nx-frame-options: DENY\n\n' + 'http/2 200\nserver: nginx\n\n',
	);
	assert.equal(meta(records, 'hops'), 2);
	assert.deepEqual(headers(records, 2), [['server', 'nginx']]);
});

test('a repeated header keeps every value in the order it was sent', () => {
	const records = normalize('HTTP/2 200\nset-cookie: a=1\nset-cookie: b=2\nset-cookie: c=3\n\n');
	assert.deepEqual(
		headers(records, 1).map(([, value]) => value),
		['a=1', 'b=2', 'c=3'],
	);
});

test('a continuation line is joined to the header above it', () => {
	const records = normalize("HTTP/2 200\ncontent-security-policy: script-src 'self'\n  'unsafe-inline'\n\n");
	assert.deepEqual(headers(records, 1), [['content-security-policy', "script-src 'self' 'unsafe-inline'"]]);
	assert.equal(meta(records, 'folded'), 1);
});

test('several continuation lines all join', () => {
	const records = normalize('HTTP/2 200\npermissions-policy: a=()\n b=()\n\tc=()\n\n');
	assert.deepEqual(headers(records, 1), [['permissions-policy', 'a=() b=() c=()']]);
	assert.equal(meta(records, 'folded'), 2);
});

test('nothing is folded when nothing is indented', () => {
	const records = normalize('HTTP/2 200\nserver: nginx\nx-frame-options: DENY\n\n');
	assert.equal(meta(records, 'folded'), 0);
});

test('a header name is lowercased and a value is trimmed', () => {
	const records = normalize('HTTP/2 200\nX-Frame-Options:    SAMEORIGIN   \n\n');
	assert.deepEqual(headers(records, 1), [['x-frame-options', 'SAMEORIGIN']]);
});

test('a value containing a colon is kept whole', () => {
	const records = normalize("HTTP/2 200\ncontent-security-policy: default-src https://cdn.example.com:8443\n\n");
	assert.deepEqual(headers(records, 1), [['content-security-policy', 'default-src https://cdn.example.com:8443']]);
});

test('an empty value is a record with an empty value, not an absent record', () => {
	const records = normalize('HTTP/2 200\npermissions-policy:\n\n');
	assert.deepEqual(headers(records, 1), [['permissions-policy', '']]);
});

test('carriage returns are stripped', () => {
	const records = normalize('HTTP/2 200\r\nx-frame-options: DENY\r\n\r\n');
	assert.deepEqual(headers(records, 1), [['x-frame-options', 'DENY']]);
	assert.equal(meta(records, 'hops'), 1);
});

test('lines before the first status line belong to no hop and are dropped', () => {
	const records = normalize('junk: value\nHTTP/2 200\nserver: nginx\n\n');
	assert.deepEqual(headers(records), [['server', 'nginx']]);
});

test('a line with no colon is not a header', () => {
	const records = normalize('HTTP/2 200\nthis is not a header\nserver: nginx\n\n');
	assert.deepEqual(headers(records), [['server', 'nginx']]);
});

test('a status line is recorded for every hop', () => {
	const records = normalize('HTTP/1.1 301 Moved\n\nHTTP/2 200\n\n');
	const statuses = records.filter((r) => r[0] === 'S').map((r) => r[2]);
	assert.deepEqual(statuses, ['HTTP/1.1 301 Moved', 'HTTP/2 200']);
});

test('a tab inside a value becomes a space so the format stays unambiguous', () => {
	const records = normalize('HTTP/2 200\nserver: ngi\tnx\n\n');
	assert.deepEqual(headers(records, 1), [['server', 'ngi nx']]);
});

test('normalize decides nothing, so it succeeds on a dump the judge would fail', () => {
	// fixtures/dump-empty-final-hop.headers makes the judge exit 1. The parser
	// has no opinion about it at all, which is the separation the mode exists to
	// make visible.
	const out = execFileSync('bash', [JUDGE, 'fixtures/dump-empty-final-hop.headers', '--normalize'], {
		cwd: ROOT,
		encoding: 'utf8',
	});
	assert.match(out, /^S\t1\tHTTP\/2 200/m);
	assert.match(out, /^M\thops\t1$/m);
});
