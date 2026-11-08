/**
 * Run the real script over every example and every fixture, and check the exit
 * code each time.
 *
 *   node tools/exit-codes.mjs
 *
 * The suite drives judge-headers.sh through tools/judge.mjs, which is the right
 * way to test the verdicts. It is not a substitute for running the thing the
 * way a user runs it, and the difference has cost this account a whole release
 * before: a package whose binary printed nothing and exited 0 for every user
 * who installed it the documented way, while fifty tests passed, because the
 * only coverage of the entry point was a syntax check.
 *
 * So this runs the scripts as a person would, and the expected exit code is
 * derived rather than listed. Each manifest entry carries its findings as
 * `level:id`, an error means exit 1, anything else means exit 0, and that is
 * the whole rule. A list of expected exit codes kept inside this file would be
 * a second copy of the expectations, and a second copy drifts.
 *
 * It also runs check-headers.sh through a symlink. That is one ln -s and one
 * run, and it is the cheap way to close the class of bug where a tool works
 * from a checkout and fails once installed. It found one here on the first
 * attempt: resolving the script directory from BASH_SOURCE without following
 * the link made every symlinked invocation fail to find its own siblings.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { HEADER_PAIRS, expectedExit } from './pairs.mjs';
import { FIXTURES } from './fixtures.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const JUDGE = join(ROOT, 'scripts', 'judge-headers.sh');
const CHECK = join(ROOT, 'scripts', 'check-headers.sh');
const DECIDE = join(ROOT, 'scripts', 'collect-decide.sh');

/**
 * spawnSync, deliberately, and the reason is the opposite of the reason in
 * tools/count-tests.mjs. Nothing in this process answers a request the child
 * makes, so there is no deadlock to create. Where a parent does serve the
 * child, the synchronous form waits for a child that is waiting for the parent
 * and every case takes the full timeout while still returning the right
 * answer, which is the worst shape a bug can have.
 */
function run(argv, options = {}) {
	const result = spawnSync('bash', argv, {
		cwd: ROOT,
		encoding: 'utf8',
		timeout: 30000,
		...options,
	});
	if (result.error) throw result.error;
	return result;
}

const cases = [];

for (const pair of HEADER_PAIRS) {
	cases.push({
		what: `${pair.stem}.fail`,
		argv: [JUDGE, `examples/${pair.stem}.fail.headers`, '--url', pair.url, '--json'],
		expect: expectedExit(pair.finds),
	});
	cases.push({
		what: `${pair.stem}.pass`,
		argv: [JUDGE, `examples/${pair.stem}.pass.headers`, '--url', pair.url, '--json'],
		expect: expectedExit(pair.residual),
	});
}

for (const fixture of FIXTURES) {
	const argv = [JUDGE, `fixtures/${fixture.file}`];
	if (fixture.url) argv.push('--url', fixture.url);
	argv.push('--json');
	cases.push({ what: `fixtures/${fixture.file}`, argv, expect: expectedExit(fixture.finds) });
}

// The usage and refusal exits, which are 2 rather than 0 or 1, and which no
// finding set can describe.
cases.push({ what: 'judge with no arguments', argv: [JUDGE], expect: 2 });
cases.push({ what: 'judge with a missing file', argv: [JUDGE, 'does-not-exist.headers'], expect: 2 });
cases.push({ what: 'judge with an unknown option', argv: [JUDGE, 'fixtures/csp-absent.headers', '--wat'], expect: 2 });
cases.push({ what: 'decide with no mode', argv: [DECIDE], expect: 2 });
cases.push({ what: 'check with no URL', argv: [CHECK], expect: 2 });
cases.push({ what: 'check with a schemeless URL', argv: [CHECK, 'example.com'], expect: 2 });

// Both modes of the judge have to agree about the exit code. A tool with two
// modes that makes different assertions in each is a tool whose quieter mode is
// untested, and the quiet mode is the one CI uses.
for (const pair of HEADER_PAIRS) {
	cases.push({
		what: `${pair.stem}.fail (human output)`,
		argv: [JUDGE, `examples/${pair.stem}.fail.headers`, '--url', pair.url],
		expect: expectedExit(pair.finds),
	});
}

// And the normalize mode, which decides nothing and must therefore always
// succeed on a file the judge accepts.
for (const fixture of FIXTURES) {
	cases.push({
		what: `fixtures/${fixture.file} (normalize)`,
		argv: [JUDGE, `fixtures/${fixture.file}`, '--normalize'],
		expect: 0,
	});
}

export function runAll() {
	const failures = [];

	for (const testCase of cases) {
		const result = run(testCase.argv);
		if (result.status !== testCase.expect) {
			failures.push(
				`${testCase.what}: expected exit ${testCase.expect}, got ${result.status}\n` +
					`  ${['bash', ...testCase.argv].join(' ')}\n` +
					`  stderr: ${(result.stderr || '').trim().split('\n').slice(0, 3).join(' | ')}`,
			);
		}
	}

	// check-headers.sh through a symlink. It needs no network to reach the
	// failure this catches: finding its own siblings happens before the fetch.
	const linkDir = mkdtempSync(join(tmpdir(), 'wpsh-link-'));
	const link = join(linkDir, 'check-headers');
	symlinkSync(realpathSync(CHECK), link);

	const viaLink = run([link, 'not-a-url']);
	if (viaLink.status !== 2) {
		failures.push(`check-headers.sh through a symlink: expected exit 2, got ${viaLink.status}`);
	}
	if (/cannot find/.test(viaLink.stderr || '')) {
		failures.push(
			'check-headers.sh run through a symlink could not find its siblings, ' +
				'so installing it on PATH is broken while running it from a checkout works',
		);
	}

	return { cases: cases.length + 1, failures };
}

const invokedDirectly = (() => {
	if (!process.argv[1]) return false;
	try {
		return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
	} catch {
		return false;
	}
})();

if (invokedDirectly) {
	const { cases: count, failures } = runAll();
	if (failures.length) {
		console.error(failures.join('\n'));
		console.error(`\n${failures.length} of ${count} exit code checks failed.`);
		process.exit(1);
	}
	console.log(`${count} runs of the real scripts, every exit code as derived from the manifests.`);
}

export default runAll;
