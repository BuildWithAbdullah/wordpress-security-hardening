import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { judgeFile, ROOT } from '../tools/judge.mjs';
import { FIXTURES } from '../tools/fixtures.mjs';
import { HEADER_PAIRS, idsReachedByPairs } from '../tools/pairs.mjs';
import { ALL_IDS } from '../tools/catalogue.mjs';

const DIR = join(ROOT, 'fixtures');

function entries(file, url) {
	const result = judgeFile(`fixtures/${file}`, url ? { url } : {});
	return [...new Set(result.findings.map((f) => `${f.level}:${f.id}`))].sort();
}

test('every fixture on disk is declared', () => {
	assert.deepEqual(readdirSync(DIR).sort(), FIXTURES.map((f) => f.file).sort());
});

test('each fixture produces exactly what it declares', () => {
	for (const fixture of FIXTURES) {
		assert.deepEqual(entries(fixture.file, fixture.url), [...fixture.finds].sort(), `${fixture.file}: ${fixture.about}`);
	}
});

/**
 * Several fixtures declare nothing on purpose, and those are the ones that earn
 * their keep. An empty declaration is an assertion that the script stays quiet
 * about something it cannot know, and it is what catches a checker becoming
 * noisier than it should be. A quoted max age has to be accepted, a twenty
 * digit one compared rather than crash the shell, a session cookie under an
 * unrecognised name left alone.
 */
test('the fixtures that declare nothing produce nothing', () => {
	const silent = FIXTURES.filter((f) => f.finds.length === 0);
	assert.ok(silent.length >= 5, 'the blind side of the limits needs fixtures of its own');
	for (const fixture of silent) {
		assert.deepEqual(entries(fixture.file, fixture.url), [], `${fixture.file} should produce nothing: ${fixture.about}`);
	}
});

test('together the pairs and the fixtures reach every catalogued finding', () => {
	const reached = new Set(idsReachedByPairs());
	for (const fixture of FIXTURES) {
		for (const entry of fixture.finds) reached.add(entry.slice(entry.indexOf(':') + 1));
	}
	const missing = ALL_IDS.filter((id) => !reached.has(id));
	assert.deepEqual(missing, [], 'these findings are catalogued and nothing reaches them');
});

test('the pairs alone do not reach everything, which is why the fixtures exist', () => {
	// If the pairs ever did reach everything the fixtures would be redundant,
	// and this test is how that would be noticed rather than left to accumulate.
	const byPairs = idsReachedByPairs();
	assert.ok(
		byPairs.size < ALL_IDS.length,
		'the pairs now reach every finding, so the fixtures should be reviewed rather than kept out of habit',
	);
	assert.ok(byPairs.size >= HEADER_PAIRS.length, 'every pair should reach at least one finding');
});

test('each fixture says what it is about', () => {
	for (const fixture of FIXTURES) {
		assert.ok(fixture.about && fixture.about.length > 60, `${fixture.file} does not explain itself`);
	}
});

test('each fixture is a header dump', () => {
	for (const fixture of FIXTURES) {
		const text = readFileSync(join(DIR, fixture.file), 'utf8');
		assert.match(text, /^HTTP\//, `${fixture.file} does not start with a status line`);
		assert.ok(text.endsWith('\n'), `${fixture.file} does not end with a newline`);
	}
});

test('no two fixtures are the same file', () => {
	const seen = new Map();
	for (const fixture of FIXTURES) {
		const text = readFileSync(join(DIR, fixture.file), 'utf8');
		assert.ok(!seen.has(text), `${fixture.file} is identical to ${seen.get(text)}`);
		seen.set(text, fixture.file);
	}
});

test('a fixture with no url declares why it has none', () => {
	for (const fixture of FIXTURES.filter((f) => f.url === null)) {
		assert.match(
			fixture.about,
			/final URL|transport/i,
			`${fixture.file} has no url and does not say that the missing url is the point`,
		);
	}
});
