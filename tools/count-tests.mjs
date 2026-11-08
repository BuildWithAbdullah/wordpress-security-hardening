/**
 * Count the tests, by running them.
 *
 *   node tools/count-tests.mjs           print the count
 *   node tools/count-tests.mjs --json    print it as JSON
 *
 * The README states a test count and tools/verify.mjs compares that statement
 * against this. A count in a README that nothing compares is a number that was
 * true once.
 *
 * The file list comes out of package.json rather than a glob, for the same
 * reason the CI step names the files: node --test did not accept glob patterns
 * before Node 21, so a globbed command runs nothing on Node 20 while reporting
 * success. Reading scripts.test and stripping the runner prefix keeps one list.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

export function testFiles() {
	const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
	const command = pkg.scripts?.test ?? '';
	const prefix = 'node --test ';
	if (!command.startsWith(prefix)) {
		throw new Error(`package.json scripts.test does not start with "${prefix}": ${command}`);
	}
	return command
		.slice(prefix.length)
		.split(/\s+/)
		.filter(Boolean);
}

export function countTests() {
	const files = testFiles();
	const reporter = join('tools', 'test-reporter.mjs');

	// spawnSync rather than spawn, deliberately. The asynchronous form of this
	// never reached its close event when the child was node --test, and the
	// synchronous form finishes. The opposite is true when the parent has to
	// answer requests the child makes, which is the case in tools/exit-codes.mjs
	// for a different tool; the rule is to decide by whether the parent is
	// serving the child, not by preference.
	const result = spawnSync(
		process.execPath,
		['--test', `--test-reporter=./${reporter}`, '--test-reporter-destination=stdout', ...files],
		{ cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
	);

	const line = (result.stdout || '').split('\n').find((l) => l.startsWith('WPSH_COUNT '));
	if (!line) {
		throw new Error(
			`the reporter printed no count.\nstatus ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
		);
	}

	const pass = Number(/pass=(\d+)/.exec(line)[1]);
	const fail = Number(/fail=(\d+)/.exec(line)[1]);

	return { pass, fail, total: pass + fail, files: files.length, status: result.status };
}

/**
 * The main module guard, written the way it has to be written.
 *
 * Comparing process.argv[1] against import.meta.url as strings is the obvious
 * version and it is wrong: npm installs a bin as a symlink and Node resolves a
 * module path to its realpath, so the two never match and the file does
 * nothing when it is run. Both sides are resolved here, and the URL is built
 * with pathToFileURL rather than by concatenating a prefix, which would be
 * wrong on Windows. argv[1] is checked first because realpathSync of undefined
 * throws when the module is imported by node -e.
 */
const invokedDirectly = (() => {
	if (!process.argv[1]) return false;
	try {
		return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
	} catch {
		return false;
	}
})();

if (invokedDirectly) {
	const counts = countTests();
	if (process.argv.includes('--json')) {
		console.log(JSON.stringify(counts));
	} else {
		console.log(`${counts.total} tests in ${counts.files} files: ${counts.pass} passed, ${counts.fail} failed.`);
	}
	process.exit(counts.fail > 0 || counts.status !== 0 ? 1 : 0);
}

export default countTests;
