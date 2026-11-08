import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { judgeFile, ROOT } from '../tools/judge.mjs';
import { HEADER_PAIRS, PHP_PAIR_STEMS, expectedExit } from '../tools/pairs.mjs';

const EXAMPLES = join(ROOT, 'examples');

/** The findings a run produced, as `level:id`, sorted and deduplicated. */
function entries(path, url) {
	const result = judgeFile(path, url ? { url } : {});
	return [...new Set(result.findings.map((f) => `${f.level}:${f.id}`))].sort();
}

test('every headers fixture on disk belongs to a declared pair', () => {
	const stems = new Set(
		readdirSync(EXAMPLES)
			.filter((name) => name.endsWith('.headers'))
			.map((name) => name.replace(/\.(fail|pass)\.headers$/, '')),
	);
	assert.deepEqual([...stems].sort(), HEADER_PAIRS.map((p) => p.stem).sort());
});

test('every example file on disk belongs to a declared pair', () => {
	const declared = new Set();
	for (const pair of HEADER_PAIRS) {
		declared.add(`${pair.stem}.fail.headers`);
		declared.add(`${pair.stem}.pass.headers`);
	}
	for (const stem of PHP_PAIR_STEMS) {
		declared.add(`${stem}.fail.php`);
		declared.add(`${stem}.pass.php`);
	}
	assert.deepEqual(readdirSync(EXAMPLES).sort(), [...declared].sort());
});

/**
 * Set equality, both ways, on both sides of every pair.
 *
 * Checking only that the headline finding has gone on the corrected side lets a
 * correction introduce a second problem and still pass, which is how a
 * repository ends up shipping a fix that is worse than the thing it replaced.
 * So the failing side declares exactly what it produces and the corrected side
 * declares exactly what survives.
 */
test('each failing example produces exactly the declared findings', () => {
	for (const pair of HEADER_PAIRS) {
		assert.deepEqual(
			entries(`examples/${pair.stem}.fail.headers`, pair.url),
			[...pair.finds].sort(),
			`${pair.stem}.fail: ${pair.about}`,
		);
	}
});

test('each corrected example produces exactly its declared residual set', () => {
	for (const pair of HEADER_PAIRS) {
		assert.deepEqual(
			entries(`examples/${pair.stem}.pass.headers`, pair.url),
			[...pair.residual].sort(),
			`${pair.stem}.pass: the residual set is wrong, so the correction does something other than what is declared`,
		);
	}
});

test('every failing example actually produces something', () => {
	for (const pair of HEADER_PAIRS) {
		assert.ok(pair.finds.length > 0, `${pair.stem} declares no findings on its failing side, so it demonstrates nothing`);
	}
});

test('no correction leaves the headline finding behind', () => {
	for (const pair of HEADER_PAIRS) {
		const residual = new Set(pair.residual);
		const fixed = pair.finds.filter((entry) => !residual.has(entry));
		assert.ok(
			fixed.length > 0,
			`${pair.stem}: every finding on the failing side survives the correction, so nothing was corrected`,
		);
	}
});

test('exit codes follow from the declared severities', () => {
	for (const pair of HEADER_PAIRS) {
		const fail = judgeFile(`examples/${pair.stem}.fail.headers`, { url: pair.url });
		const pass = judgeFile(`examples/${pair.stem}.pass.headers`, { url: pair.url });
		assert.equal(fail.status, expectedExit(pair.finds), `${pair.stem}.fail exit code`);
		assert.equal(pass.status, expectedExit(pair.residual), `${pair.stem}.pass exit code`);
	}
});

test('each pair says what it is about', () => {
	for (const pair of HEADER_PAIRS) {
		assert.ok(pair.about && pair.about.length > 60, `${pair.stem} does not explain itself`);
	}
});

test('each headers example is a header dump and not something else', () => {
	for (const pair of HEADER_PAIRS) {
		for (const side of ['fail', 'pass']) {
			const text = readFileSync(join(EXAMPLES, `${pair.stem}.${side}.headers`), 'utf8');
			assert.match(text, /^HTTP\//, `${pair.stem}.${side} does not start with a status line`);
			assert.ok(text.endsWith('\n'), `${pair.stem}.${side} does not end with a newline`);
		}
	}
});

test('both sides of a pair differ', () => {
	for (const pair of HEADER_PAIRS) {
		const fail = readFileSync(join(EXAMPLES, `${pair.stem}.fail.headers`), 'utf8');
		const pass = readFileSync(join(EXAMPLES, `${pair.stem}.pass.headers`), 'utf8');
		assert.notEqual(fail, pass, `${pair.stem}: both sides are the same file`);
	}
});
