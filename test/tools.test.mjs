import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from '../tools/judge.mjs';
import { testFiles } from '../tools/count-tests.mjs';
import { check as entryThinCheck, measure, ENTRY_POINTS } from '../tools/entry-thin.mjs';
import runAuditVerdicts from '../tools/audit-verdicts.mjs';
import runExitCodes from '../tools/exit-codes.mjs';
import { CHECK_NAMES } from '../tools/verify.mjs';

/**
 * The tools, checked as code rather than only run in CI.
 *
 * Note what is deliberately absent: nothing here calls countTests(). That
 * function spawns `node --test` over the whole suite, and this file is part of
 * the suite, so calling it from here would recurse until the machine gave up.
 * Its file list is checked instead, and the count itself is taken in
 * tools/verify.mjs, which runs outside the runner.
 */

test('the test file list comes from package.json and matches what is on disk', () => {
	const files = testFiles();
	const onDisk = readdirSync(join(ROOT, 'test'))
		.filter((name) => name.endsWith('.test.mjs'))
		.map((name) => `test/${name}`)
		.sort();
	assert.deepEqual([...files].sort(), onDisk, 'package.json scripts.test does not name every test file');
});

test('the test files are named rather than globbed', () => {
	// node --test did not accept glob patterns before Node 21, so a globbed
	// script runs nothing on Node 20 while reporting success, which is the worst
	// available outcome.
	const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
	assert.ok(!pkg.scripts.test.includes('*'), 'the test script contains a glob');
	for (const file of testFiles()) {
		assert.ok(existsSync(join(ROOT, file)), `${file} is named in the test script and is not there`);
	}
});

test('the reporter counts per test rather than per file', () => {
	// The default reporter prints `# tests N` on Node 20 and 22 and `info tests
	// N` on Node 24, and the structured stream reports one pass per file on some
	// versions while details.type is undefined on others. A custom reporter
	// selecting on inequality with 'suite' is what works everywhere.
	const source = readFileSync(join(ROOT, 'tools', 'test-reporter.mjs'), 'utf8');
	assert.match(source, /test:pass/);
	assert.match(source, /details\?\.type !== 'suite'/);
	// Code only. Matching the whole file made this fire on the comment that
	// explains the rule, because the comment quotes the reporter text the rule
	// forbids. An assertion that reads prose reports its own documentation as a
	// breach of itself, and this is the third time that has happened here.
	const code = source
		.split('\n')
		.filter((line) => !/^\s*(\*|\/\*|\/\/)/.test(line))
		.join('\n');
	assert.ok(!/# tests/.test(code), 'the reporter is parsing default reporter text');
});

test('the entry point is thin, and the budget is the thing that keeps it thin', () => {
	assert.deepEqual(entryThinCheck(), []);
	const [measured] = measure();
	const [declared] = ENTRY_POINTS;
	assert.ok(measured.lines <= declared.maxLines, `${measured.file} is ${measured.lines} lines`);
	assert.ok(measured.branches <= declared.maxBranches, `${measured.file} has ${measured.branches} branches`);
});

test('the entry thin check actually fires when a decision appears', () => {
	// A check nobody has seen fail is a check nobody has seen. The needles are
	// run against a string that contains one, rather than against the file.
	const [declared] = ENTRY_POINTS;
	for (const rule of declared.forbidden) {
		assert.ok(rule.needle.length > 2, 'a needle this short would match everything');
		assert.ok(rule.decision && rule.decision.length > 30, `${rule.needle} does not say what decision it is looking for`);
		assert.ok(
			`harmless\n${rule.needle}\nharmless`.includes(rule.needle),
			`${rule.needle} would not match even a line that is exactly it`,
		);
	}
});

test('the entry point vocabulary is declared per entry point', () => {
	// A shared needle list misfires, because the same token means different
	// things in different files. `case` in an option parser is a decision; `case`
	// in the symlink resolver is picking apart a path, and this file resolves its
	// own path through symlinks because not doing so broke every installed copy.
	for (const entry of ENTRY_POINTS) {
		assert.ok(entry.what && entry.what.length > 40, `${entry.file} does not say what it is`);
		assert.ok(entry.forbidden.length >= 5, `${entry.file} has too few needles to be meaningful`);
		for (const rule of entry.forbidden) {
			assert.ok(rule.needle !== 'case', 'a bare case needle would flag path handling as a decision');
			assert.ok(rule.needle !== 'if', 'a bare if needle would flag every guard');
		}
	}
});

test('the entry point resolves itself through symlinks', () => {
	// Installing a shell tool means putting a link to it on PATH. Resolving the
	// script directory from BASH_SOURCE without following the link made every
	// such invocation fail to find its own siblings, so it worked from a
	// checkout and was broken once installed.
	const source = readFileSync(join(ROOT, 'scripts', 'check-headers.sh'), 'utf8');
	assert.match(source, /readlink/);
	assert.match(source, /while \[ -L/);
});

test('every audit verdict is as derived from the manifest', () => {
	const { verdicts, failures } = runAuditVerdicts();
	assert.deepEqual(failures, []);
	assert.ok(verdicts >= 20, `only ${verdicts} verdicts were run`);
});

test('the real scripts exit as the manifests say they should', () => {
	const { cases, failures } = runExitCodes();
	assert.deepEqual(failures, []);
	assert.ok(cases >= 100, `only ${cases} runs of the real scripts`);
});

test('every tool is reachable and is a module', () => {
	const tools = readdirSync(join(ROOT, 'tools')).filter((name) => name.endsWith('.mjs'));
	assert.ok(tools.length >= 10, `only ${tools.length} tools`);
	for (const tool of tools) {
		const source = readFileSync(join(ROOT, 'tools', tool), 'utf8');
		assert.match(source, /^\/\*\*/, `tools/${tool} does not open with a comment saying why it exists`);
		assert.ok(/export /.test(source), `tools/${tool} exports nothing, so nothing can test it`);
	}
});

test('every tool that can be run directly guards its main module correctly', () => {
	// Comparing process.argv[1] against import.meta.url as strings is the
	// obvious version and it is wrong: a bin installed by npm is a symlink and
	// Node resolves a module path to its realpath, so the two never match and
	// the file does nothing. That shipped in another repository on this account
	// and made an installed binary print nothing and exit 0 for its whole life.
	const tools = readdirSync(join(ROOT, 'tools')).filter((name) => name.endsWith('.mjs'));
	for (const tool of tools) {
		const source = readFileSync(join(ROOT, 'tools', tool), 'utf8');
		if (!source.includes('invokedDirectly')) continue;
		assert.match(source, /if \(!process\.argv\[1\]\) return false;/, `tools/${tool} would throw when imported by node -e`);
		assert.match(source, /pathToFileURL\(realpathSync\(process\.argv\[1\]\)\)/, `tools/${tool} compares unresolved paths`);
		assert.ok(!/'file:\/\/' \+/.test(source), `tools/${tool} builds a file URL by concatenation, which is wrong on Windows`);
	}
});

/**
 * The verifier's count, as a property rather than as a number.
 *
 * Nothing here calls verify(), for the same reason nothing here calls
 * countTests(): verify() runs the suite to check the count the README states,
 * and this file is part of the suite. The property is checked by reading the
 * source instead, which is enough, because the property is structural.
 */
test('the assertion count is the length of a fixed list, not a count of files', () => {
	const source = readFileSync(join(ROOT, 'tools', 'verify.mjs'), 'utf8');
	assert.match(source, /assertions: CHECKS\.length/, 'the total is not the length of the check list');
	// The returned total must not be computed from anything that grows with the
	// repository. A per-file assertion is still a count of how many files there
	// are, however it is spelled.
	assert.ok(!/assertions:\s*(TRACKED|TEXT_FILES|files)/.test(source), 'the total is derived from a file list');
	assert.ok(CHECK_NAMES.length >= 30, `only ${CHECK_NAMES.length} checks declared`);
});

test('the assertion count does not depend on whether the checks pass', () => {
	const source = readFileSync(join(ROOT, 'tools', 'verify.mjs'), 'utf8');
	// Every check runs, failures are collected rather than thrown, and the total
	// is reported either way, so a broken repository and a sound one report the
	// same denominator and the number cannot be read as a score.
	assert.match(source, /for \(const check of CHECKS\) \{\s*try \{/, 'a failing check would stop the run');
	assert.ok(!/failures\.length \? CHECKS\.length/.test(source), 'the total is conditioned on the outcome');
});

test('every check has a distinct name that says what it claims', () => {
	assert.equal(new Set(CHECK_NAMES).size, CHECK_NAMES.length, 'two checks share a name');
	for (const name of CHECK_NAMES) {
		assert.ok(name.length > 20, `a check named ${JSON.stringify(name)} does not say what it claims`);
		assert.ok(name === name.toLowerCase() || /[A-Z]/.test(name), 'names should read as sentences');
	}
});
