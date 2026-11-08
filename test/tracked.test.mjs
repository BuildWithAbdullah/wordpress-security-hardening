import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { trackedFiles, ignored, rules, ROOT } from '../tools/tracked.mjs';

/**
 * The gitignore matcher, checked against git itself on a purpose-built tree.
 *
 * tools/verify.mjs counts files and reads them, so it has to know which files
 * are in the repository. Shelling out to git ls-files is not available: the
 * verifier has to run from an extracted archive and from a published tree with
 * no git directory at all.
 *
 * So the matcher is real code, and the parts implementations get wrong are the
 * parts checked here. The one that is almost always wrong is the last of them: a
 * negation cannot re-include a file inside an excluded directory, because git
 * never looks inside that directory to find the negation.
 */
function tree(gitignore, files) {
	const dir = mkdtempSync(join(tmpdir(), 'wpsh-ignore-'));
	writeFileSync(join(dir, '.gitignore'), gitignore);
	for (const file of files) {
		const full = join(dir, file);
		mkdirSync(join(full, '..'), { recursive: true });
		writeFileSync(full, 'x');
	}
	return dir;
}

function gitSees(dir) {
	const available = spawnSync('git', ['--version'], { encoding: 'utf8' });
	if (available.status !== 0) return null;
	execFileSync('git', ['init', '-q'], { cwd: dir });
	execFileSync('git', ['add', '-A'], { cwd: dir });
	return execFileSync('git', ['ls-files'], { cwd: dir, encoding: 'utf8' })
		.split('\n')
		.filter(Boolean)
		.sort();
}

function compare(gitignore, files) {
	const dir = tree(gitignore, files);
	const mine = trackedFiles(dir);
	const theirs = gitSees(dir);
	return { mine, theirs };
}

test('a simple extension rule agrees with git', () => {
	const { mine, theirs } = compare('*.log\n', ['keep.txt', 'drop.log', 'deep/drop.log', 'deep/keep.txt']);
	assert.deepEqual(mine, ['.gitignore', 'deep/keep.txt', 'keep.txt']);
	if (theirs) assert.deepEqual(mine, theirs);
});

test('a directory rule agrees with git', () => {
	const { mine, theirs } = compare('build/\n', ['build/out.js', 'src/in.js']);
	assert.deepEqual(mine, ['.gitignore', 'src/in.js']);
	if (theirs) assert.deepEqual(mine, theirs);
});

test('an anchored rule only matches at the root', () => {
	const { mine, theirs } = compare('/notes.md\n', ['notes.md', 'docs/notes.md']);
	assert.deepEqual(mine, ['.gitignore', 'docs/notes.md']);
	if (theirs) assert.deepEqual(mine, theirs);
});

test('last match wins, so a later negation re-includes a file', () => {
	const { mine, theirs } = compare('*.log\n!keep.log\n', ['drop.log', 'keep.log']);
	assert.deepEqual(mine, ['.gitignore', 'keep.log']);
	if (theirs) assert.deepEqual(mine, theirs);
});

test('a negation can re-include a file in a subdirectory', () => {
	// This is the case wordpress-emergency-recovery needs for real: it ignores
	// *.log and one of its example pairs is about a debug log in the web root,
	// so that log has to be committed.
	const { mine, theirs } = compare('*.log\n!examples/**/*.log\n', [
		'random.log',
		'examples/one/debug.log',
		'examples/two/debug.log',
	]);
	assert.deepEqual(mine, ['.gitignore', 'examples/one/debug.log', 'examples/two/debug.log']);
	if (theirs) assert.deepEqual(mine, theirs);
});

/**
 * The one that matters, and the one a naive implementation gets wrong. git does
 * not descend into an ignored directory, so it never sees the negation and the
 * file stays untracked. An implementation that walks everything and then applies
 * the rules per file reports a file git does not have.
 */
test('a negation cannot re-include a file inside an excluded directory', () => {
	const { mine, theirs } = compare('build/\n!build/keep.js\n', ['build/keep.js', 'build/drop.js', 'src/in.js']);
	assert.deepEqual(mine, ['.gitignore', 'src/in.js']);
	if (theirs) assert.deepEqual(mine, theirs, 'git and this matcher disagree about an excluded directory');
});

test('a later rule can re-exclude what an earlier one included', () => {
	const { mine, theirs } = compare('*.log\n!keep.log\nkeep.log\n', ['keep.log']);
	assert.deepEqual(mine, ['.gitignore']);
	if (theirs) assert.deepEqual(mine, theirs);
});

test('a comment and a blank line are not rules', () => {
	const parsed = rules(tree('# a comment\n\n*.log\n', []));
	assert.equal(parsed.length, 1);
	assert.equal(parsed[0].pattern, '*.log');
});

test('a question mark matches one character and not a slash', () => {
	const { mine, theirs } = compare('a?.txt\n', ['ab.txt', 'abc.txt', 'a/b.txt']);
	assert.deepEqual(mine, ['.gitignore', 'a/b.txt', 'abc.txt']);
	if (theirs) assert.deepEqual(mine, theirs);
});

test('the matcher answers about directories and files separately', () => {
	const dir = tree('build/\n', []);
	const parsed = rules(dir);
	assert.equal(ignored('build', true, parsed), true);
	// A file named build is not the directory the rule names.
	assert.equal(ignored('build', false, parsed), false);
});

test('this repository has no untracked surprises', () => {
	const files = trackedFiles(ROOT);
	assert.ok(files.length > 100, `only ${files.length} tracked files found`);
	assert.ok(!files.some((f) => f.startsWith('node_modules/')), 'node_modules is being counted');
	assert.ok(!files.some((f) => f.startsWith('.git/')), 'the git directory is being counted');
	assert.ok(files.includes('package.json'));
	assert.ok(files.includes('scripts/judge-headers.sh'));
});

test('the gitignore does not hide a file the repository needs', () => {
	const parsed = rules(ROOT);
    // The dependency free repositories deliberately track no lockfile, so
    // ignoring one is right here and would be wrong in a repository that tracks
    // it. Stating which of the two this is keeps the next change honest.
	assert.ok(!parsed.some((rule) => rule.pattern === 'package-lock.json'));
	const files = trackedFiles(ROOT);
	assert.ok(!files.includes('package-lock.json'), 'this repository depends on nothing and should have no lockfile');
});
