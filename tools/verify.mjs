/**
 * Repository assertions: the claims this repository makes about itself.
 *
 *   node tools/verify.mjs
 *   node tools/verify.mjs --json
 *
 * ---------------------------------------------------------------------------
 * Why the number this prints is 34 and not several hundred
 *
 * The previous version of this file reported 467 assertions and the number was
 * not a measurement. It made an assertion per file, so adding one document to
 * docs/ moved it, and adding a source module moved it, and a stray lockfile in
 * the working tree moved it. A self-referential count that changes when
 * something it is not about changes is not a self check; it is a file count
 * wearing one.
 *
 * So this is a fixed list of named checks, and the number it prints is the
 * length of that list. A check is free to loop over every tracked file inside
 * itself, and that still counts as one, because what is being asserted is one
 * claim. The number moves when a claim is added or removed and at no other
 * time, which is what makes it worth printing.
 *
 * The consequence is worth stating plainly because it is easy to misread: 34
 * here and several hundred in a repository still counting per file are
 * different units, not a difference in rigour. This version checks strictly
 * more than the one that reported 467.
 *
 * The total also does not depend on whether the checks pass. Every check runs,
 * failures are collected, and the count is reported either way, so a broken
 * repository and a sound one report the same denominator.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { trackedFiles } from './tracked.mjs';
import { ALL, ALL_IDS, AREAS } from './catalogue.mjs';
import { HEADER_PAIRS, PHP_PAIR_STEMS, idsReachedByPairs } from './pairs.mjs';
import { FIXTURES, idsReachedByFixtures } from './fixtures.mjs';
import { LIMITS } from './limits.mjs';
import { AUDIT_STEMS } from './audits.mjs';
import { countTests } from './count-tests.mjs';
import { check as entryThin } from './entry-thin.mjs';
import renderCatalogueDoc from './catalogue-doc.mjs';
import renderLimitsDoc from './limits-doc.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

const read = (file) => readFileSync(join(ROOT, file), 'utf8');
const TRACKED = trackedFiles(ROOT);
const TEXT_EXTENSIONS = /\.(mjs|js|php|sh|md|json|yml|yaml|headers|txt)$/;
const TEXT_FILES = TRACKED.filter((file) => TEXT_EXTENSIONS.test(file) || file === 'LICENSE');

/**
 * Needles assembled from code points, never written as characters.
 *
 * A purity check fails on its own subject matter. Writing an em dash into the
 * one file whose job is to find em dashes is how the check reports itself, and
 * that has happened on this account. Note also that a unicode escape written
 * through a quoted heredoc comes out as the real character, so these are built
 * at run time and the file on disk contains neither.
 */
const EM_DASH = String.fromCharCode(0x2014);
const EN_DASH = String.fromCharCode(0x2013);
const UNIVERSITY = String.fromCharCode(70, 65, 83, 84) + '-' + String.fromCharCode(78, 85, 67, 69, 83);

/**
 * A number the README states, matched as a whole line.
 *
 * Matching it as a pattern anywhere in the file lets the number wrap onto two
 * lines and keep passing, and lets a second copy of it appear and keep passing.
 * So the README is split into lines, each is matched, and anything other than
 * exactly one match is a failure. This helper has earned its keep in four
 * repositories now.
 */
function statedOnOneLine(readme, pattern, what) {
	const matching = readme.split('\n').filter((line) => pattern.test(line));
	if (matching.length === 0) {
		throw new Error(`the README does not state ${what} on any single line (looking for ${pattern})`);
	}
	if (matching.length > 1) {
		throw new Error(`the README states ${what} on ${matching.length} lines, so one of them can go stale silently`);
	}
	return matching[0];
}

function statedNumber(readme, pattern, what) {
	const line = statedOnOneLine(readme, pattern, what);
	return Number(pattern.exec(line)[1]);
}

/** Lines that are neither blank nor a comment, for scans that must not read prose. */
function codeOnly(text, commentPrefixes = ['#']) {
	return text
		.split('\n')
		.map((line) => line.trim())
		.filter((line) => line !== '' && !commentPrefixes.some((prefix) => line.startsWith(prefix)))
		.join('\n');
}

const CHECKS = [
	{
		name: 'no em dash or en dash in any tracked text file',
		run() {
			const offenders = TEXT_FILES.filter((file) => {
				const text = read(file);
				return text.includes(EM_DASH) || text.includes(EN_DASH);
			});
			if (offenders.length) throw new Error(`dashes in: ${offenders.join(', ')}`);
		},
	},
	{
		name: 'no mention of the university anywhere',
		run() {
			const offenders = TEXT_FILES.filter((file) => read(file).includes(UNIVERSITY));
			if (offenders.length) throw new Error(`named in: ${offenders.join(', ')}`);
		},
	},
	{
		name: 'the judge names no network tool',
		run() {
			const code = codeOnly(read('scripts/judge-headers.sh'));
			for (const tool of ['curl', 'wget', 'nc ', 'openssl s_client', 'ping ']) {
				if (code.includes(tool)) throw new Error(`judge-headers.sh names ${tool}`);
			}
		},
	},
	{
		name: 'the decider names no network tool either',
		run() {
			const code = codeOnly(read('scripts/collect-decide.sh'));
			for (const tool of ['curl', 'wget', 'nc ', 'openssl s_client']) {
				if (code.includes(tool)) throw new Error(`collect-decide.sh names ${tool}`);
			}
		},
	},
	{
		name: 'the one file that does fetch is the only one that mentions curl',
		run() {
			const fetchers = TRACKED.filter(
				(file) => file.endsWith('.sh') && codeOnly(read(file)).includes('curl'),
			);
			if (fetchers.length !== 1 || fetchers[0] !== 'scripts/check-headers.sh') {
				throw new Error(`expected only scripts/check-headers.sh to fetch, found: ${fetchers.join(', ') || 'none'}`);
			}
		},
	},
	{
		name: 'the entry point holds no decision and stays inside its budget',
		run() {
			const problems = entryThin();
			if (problems.length) throw new Error(problems.join('; '));
		},
	},
	{
		name: 'the README states the test count, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) tests\b/, 'the test count');
			const counted = countTests();
			if (counted.fail > 0 || counted.status !== 0) {
				throw new Error(`the suite is not green (${counted.fail} failing), so no count from it is quotable`);
			}
			if (stated !== counted.total) {
				throw new Error(`the README says ${stated} tests and the suite has ${counted.total}`);
			}
		},
	},
	{
		name: 'the README states the repository assertion count, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) repository assertions\b/, 'the assertion count');
			if (stated !== CHECKS.length) {
				throw new Error(`the README says ${stated} repository assertions and there are ${CHECKS.length}`);
			}
		},
	},
	{
		name: 'the README states the catalogue size, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) catalogued findings\b/, 'the catalogue size');
			if (stated !== ALL.length) throw new Error(`the README says ${stated} findings and there are ${ALL.length}`);
		},
	},
	{
		name: 'the README states the area count, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) areas\b/, 'the area count');
			if (stated !== AREAS.length) throw new Error(`the README says ${stated} areas and there are ${AREAS.length}`);
		},
	},
	{
		name: 'the README states the pair count, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) example pairs\b/, 'the pair count');
			const actual = HEADER_PAIRS.length + PHP_PAIR_STEMS.length;
			if (stated !== actual) throw new Error(`the README says ${stated} pairs and there are ${actual}`);
		},
	},
	{
		name: 'the README states the fixture count, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) fixtures\b/, 'the fixture count');
			if (stated !== FIXTURES.length) throw new Error(`the README says ${stated} fixtures and there are ${FIXTURES.length}`);
		},
	},
	{
		name: 'the README states the limit count, on one line, and it is right',
		run() {
			const readme = read('README.md');
			const stated = statedNumber(readme, /\b(\d+) declared limits\b/, 'the limit count');
			if (stated !== LIMITS.length) throw new Error(`the README says ${stated} limits and there are ${LIMITS.length}`);
		},
	},
	{
		name: 'the README has a Verifying section that names every gate',
		run() {
			const readme = read('README.md');
			if (!/^## Verifying$/m.test(readme)) throw new Error('no ## Verifying section');
			for (const script of ['npm test', 'npm run verify', 'npm run check', 'npm run exit-codes', 'npm run audit-verdicts']) {
				if (!readme.includes(script)) throw new Error(`the Verifying section does not mention ${script}`);
			}
		},
	},
	{
		name: 'the licence is MIT and requires no attribution',
		run() {
			const licence = read('LICENSE');
			if (!licence.includes('MIT License')) throw new Error('LICENSE is not MIT');
			const pkg = JSON.parse(read('package.json'));
			if (pkg.license !== 'MIT') throw new Error(`package.json says ${pkg.license}`);
		},
	},
	{
		name: 'the engines floor names an exact version, not a bare major',
		run() {
			// A floor of ">=20" plus a CI job named "20" is not a tested promise:
			// actions/setup-node resolves a bare major to the newest release of
			// that line, so the version that was tested is whatever shipped that
			// week and the floor that was declared is something else. All three
			// components, in both places.
			const floor = JSON.parse(read('package.json')).engines?.node;
			if (!/^>=\d+\.\d+\.\d+$/.test(floor ?? '')) {
				throw new Error(`engines.node is ${JSON.stringify(floor)}, which does not name an exact floor version`);
			}
		},
	},
	{
		name: 'the declared floor is itself one of the versions CI runs',
		run() {
			const floor = JSON.parse(read('package.json')).engines.node.replace('>=', '');
			const workflow = read('.github/workflows/verify.yml');
			const matrix = [...workflow.matchAll(/node:\s*\[([^\]]+)\]/g)].flatMap((m) =>
				m[1].split(',').map((v) => v.trim().replace(/'/g, '')),
			);
			if (!matrix.includes(floor)) {
				throw new Error(`the floor is ${floor} and the CI matrix is ${matrix.join(', ')}, so the floor is untested`);
			}
		},
	},
	{
		name: 'no CI job names a bare major version',
		run() {
			// actions/setup-node resolves a bare major to the newest release of
			// that line, so ">=18 plus a job named 18" is not a tested promise.
			const workflow = read('.github/workflows/verify.yml');
			const bare = [...workflow.matchAll(/node-version:\s*'?([^'\n]+)'?/g)]
				.map((m) => m[1].trim())
				.filter((value) => !value.startsWith('${{') && !/^\d+\.\d+\.\d+$/.test(value));
			if (bare.length) throw new Error(`these node-version values are not exact: ${bare.join(', ')}`);
			const matrix = [...workflow.matchAll(/node:\s*\[([^\]]+)\]/g)].flatMap((m) =>
				m[1].split(',').map((v) => v.trim().replace(/'/g, '')),
			);
			const looseMatrix = matrix.filter((value) => !/^\d+\.\d+\.\d+$/.test(value));
			if (looseMatrix.length) throw new Error(`these matrix versions are not exact: ${looseMatrix.join(', ')}`);
		},
	},
	{
		name: 'CI asserts the declared floor is the version actually run',
		run() {
			const pkg = JSON.parse(read('package.json'));
			const workflow = read('.github/workflows/verify.yml');
			const floor = pkg.engines.node.replace('>=', '');
			if (!workflow.includes(`v${floor}`)) {
				throw new Error(`no CI step compares process.version against v${floor}`);
			}
			if (!workflow.includes('engine-strict')) {
				throw new Error('no CI step checks that the package refuses to install below its floor');
			}
		},
	},
	{
		name: 'no CI step redirects an npm run',
		run() {
			// npm run writes a banner to stdout, so a redirected npm run captures
			// it. Comment lines are dropped first: scanning the prose picked the
			// words out of the comment that explains the rule and reported a
			// script named "writes".
			const workflow = codeOnly(read('.github/workflows/verify.yml'));
			const redirects = [...workflow.matchAll(/npm run [\w:-]+[^\n]*>/g)].map((m) => m[0]);
			if (redirects.length) throw new Error(`redirected: ${redirects.join(', ')}`);
		},
	},
	{
		name: 'the generated finding document matches its builder',
		run() {
			// Compared against the builder, not regenerated by the checker. A
			// verifier that runs the generator and then reads the file always
			// passes.
			if (read('docs/07-every-finding.md') !== renderCatalogueDoc()) {
				throw new Error('docs/07-every-finding.md is out of date');
			}
		},
	},
	{
		name: 'the generated limits document matches its builder',
		run() {
			if (read('docs/06-what-the-checks-do-not-see.md') !== renderLimitsDoc()) {
				throw new Error('docs/06-what-the-checks-do-not-see.md is out of date');
			}
		},
	},
	{
		name: 'every tracked JavaScript module parses',
		run() {
			const files = TRACKED.filter((file) => file.endsWith('.mjs'));
			if (files.length === 0) throw new Error('no modules found, so this check is asserting nothing');
			const result = spawnSync(process.execPath, ['--check', ...files], { cwd: ROOT, encoding: 'utf8' });
			if (result.status !== 0) throw new Error(result.stderr.trim());
		},
	},
	{
		name: 'every tracked PHP file parses',
		run() {
			const files = TRACKED.filter((file) => file.endsWith('.php'));
			if (files.length === 0) throw new Error('no PHP files found, so this check is asserting nothing');
			for (const file of files) {
				const result = spawnSync('php', ['-l', file], { cwd: ROOT, encoding: 'utf8' });
				if (result.status !== 0) throw new Error(`${file}: ${(result.stdout || result.stderr).trim()}`);
			}
		},
	},
	{
		name: 'every tracked shell script parses',
		run() {
			const files = TRACKED.filter((file) => file.endsWith('.sh'));
			if (files.length !== 3) throw new Error(`expected three shell scripts, found ${files.length}`);
			for (const file of files) {
				const result = spawnSync('bash', ['-n', file], { cwd: ROOT, encoding: 'utf8' });
				if (result.status !== 0) throw new Error(`${file}: ${result.stderr.trim()}`);
			}
		},
	},
	{
		name: 'nothing the package ships imports from a directory it does not ship',
		run() {
			// It worked in the repository and would have failed in every installed
			// copy, which is the quietest kind of broken. And the specifier has to
			// be resolved against the importing file, not the repository root, or
			// src/run.mjs importing ./checks/x.mjs looks like a reach outside the
			// package and every module gets reported.
			const pkg = JSON.parse(read('package.json'));
			const shipped = pkg.files.map((entry) => entry.replace(/\/$/, ''));
			const isShipped = (relative) => shipped.some((entry) => relative === entry || relative.startsWith(`${entry}/`));

			const problems = [];
			for (const file of TRACKED.filter((f) => f.endsWith('.mjs') || f.endsWith('.php'))) {
				if (!isShipped(file)) continue;
				const text = read(file);
				const specifiers = [
					...[...text.matchAll(/from\s+'(\.[^']+)'/g)].map((m) => m[1]),
					...[...text.matchAll(/require\s+__DIR__\s*\.\s*'(\/[^']+)'/g)].map((m) => `.${m[1]}`),
				];
				for (const specifier of specifiers) {
					const target = resolvePath(dirname(join(ROOT, file)), specifier);
					const relative = target.slice(ROOT.length + 1).split('\\').join('/');
					if (!isShipped(relative)) {
						problems.push(`${file} imports ${specifier}, which resolves to ${relative} and is not shipped`);
					}
				}
			}
			if (problems.length) throw new Error(problems.join('; '));
		},
	},
	{
		name: 'this repository tracks no lockfile, because it depends on nothing',
		run() {
			const pkg = JSON.parse(read('package.json'));
			if (pkg.dependencies || pkg.devDependencies) throw new Error('a dependency appeared');
			if (TRACKED.includes('package-lock.json')) {
				throw new Error('a lockfile is tracked, and a tracked lockfile carries its own copy of the engines field');
			}
		},
	},
	{
		name: 'the pairs and the fixtures together reach every catalogued finding',
		run() {
			const reached = new Set([...idsReachedByPairs(), ...idsReachedByFixtures()]);
			const missing = ALL_IDS.filter((id) => !reached.has(id));
			if (missing.length) throw new Error(`nothing reaches: ${missing.join(', ')}`);
		},
	},
	{
		name: 'no manifest names a finding that is not catalogued',
		run() {
			const reached = new Set([...idsReachedByPairs(), ...idsReachedByFixtures()]);
			const unknown = [...reached].filter((id) => !ALL_IDS.includes(id));
			if (unknown.length) throw new Error(`not in the catalogue: ${unknown.join(', ')}`);
		},
	},
	{
		name: 'every file a manifest names exists, and every example is named',
		run() {
			const expected = new Set();
			for (const pair of HEADER_PAIRS) {
				expected.add(`examples/${pair.stem}.fail.headers`);
				expected.add(`examples/${pair.stem}.pass.headers`);
			}
			for (const stem of PHP_PAIR_STEMS) {
				expected.add(`examples/${stem}.fail.php`);
				expected.add(`examples/${stem}.pass.php`);
			}
			for (const fixture of FIXTURES) expected.add(`fixtures/${fixture.file}`);

			const onDisk = new Set(TRACKED.filter((f) => f.startsWith('examples/') || f.startsWith('fixtures/')));
			const missing = [...expected].filter((f) => !onDisk.has(f));
			const unnamed = [...onDisk].filter((f) => !expected.has(f));
			if (missing.length || unnamed.length) {
				throw new Error(`missing: ${missing.join(', ') || 'none'}; unnamed: ${unnamed.join(', ') || 'none'}`);
			}
		},
	},
	{
		name: 'the audit list and the PHP pair list are the same list',
		run() {
			const a = [...AUDIT_STEMS].sort().join(',');
			const b = [...PHP_PAIR_STEMS].sort().join(',');
			if (a !== b) throw new Error(`audits: ${a}\npairs:  ${b}`);
		},
	},
	{
		name: 'every limit names a blind case and a contrast case that exist',
		run() {
			const fixtures = new Set(FIXTURES.map((f) => f.file));
			const pairs = new Set(HEADER_PAIRS.map((p) => p.stem));
			const problems = [];
			for (const limit of LIMITS) {
				for (const side of ['blind', 'contrast']) {
					const reference = limit[side];
					if (reference.kind === 'fixture' && !fixtures.has(reference.ref)) {
						problems.push(`${limit.id} ${side} names a fixture that is not declared: ${reference.ref}`);
					}
					if (reference.kind === 'pair' && !pairs.has(reference.ref)) {
						problems.push(`${limit.id} ${side} names a pair that does not exist: ${reference.ref}`);
					}
				}
			}
			if (problems.length) throw new Error(problems.join('; '));
		},
	},
	{
		name: 'every must-use plugin refuses to run outside WordPress and declares MIT',
		run() {
			const plugins = TRACKED.filter((file) => file.startsWith('mu-plugins/'));
			if (plugins.length !== 3) throw new Error(`expected three plugins, found ${plugins.length}`);
			const pkg = JSON.parse(read('package.json'));
			for (const plugin of plugins) {
				const text = read(plugin);
				if (!text.includes("if ( ! defined( 'ABSPATH' ) )")) throw new Error(`${plugin} has no ABSPATH guard`);
				if (!text.includes('License:      MIT')) throw new Error(`${plugin} does not declare MIT`);
				if (!text.includes(`Version:      ${pkg.version}`)) {
					throw new Error(`${plugin} does not declare version ${pkg.version}`);
				}
			}
		},
	},
	{
		name: 'the harness is never installed on a site',
		run() {
			const pkg = JSON.parse(read('package.json'));
			const shipped = pkg.files.map((entry) => entry.replace(/\/$/, ''));
			for (const directory of ['lib', 'test', 'tools', 'examples', 'fixtures']) {
				if (shipped.includes(directory)) throw new Error(`${directory} is in package.json files and is harness`);
			}
		},
	},
	{
		name: 'every document is linked from the README',
		run() {
			const readme = read('README.md');
			const docs = TRACKED.filter((file) => file.startsWith('docs/'));
			if (docs.length < 7) throw new Error(`only ${docs.length} documents found`);
			const unlinked = docs.filter((file) => !readme.includes(file.slice('docs/'.length)) && !readme.includes(file));
			if (unlinked.length) throw new Error(`not linked from the README: ${unlinked.join(', ')}`);
		},
	},
	{
		name: 'the five reusable tools are all present',
		run() {
			const wanted = ['count-tests.mjs', 'tracked.mjs', 'exit-codes.mjs', 'audit-verdicts.mjs', 'entry-thin.mjs'];
			const missing = wanted.filter((tool) => !TRACKED.includes(`tools/${tool}`));
			if (missing.length) throw new Error(`missing: ${missing.join(', ')}`);
		},
	},
	{
		name: 'no tracked file is empty',
		run() {
			const empty = TRACKED.filter((file) => statSync(join(ROOT, file)).size === 0);
			if (empty.length) throw new Error(`empty: ${empty.join(', ')}`);
		},
	},
	{
		name: 'the judge offers a normalize mode and the suite drives it',
		run() {
			const judge = read('scripts/judge-headers.sh');
			if (!judge.includes('--normalize')) throw new Error('the judge has no normalize mode');
			if (!TRACKED.includes('test/normalize.test.mjs')) throw new Error('nothing drives the normalize mode');
			const out = execFileSync('bash', ['scripts/judge-headers.sh', 'fixtures/csp-absent.headers', '--normalize'], {
				cwd: ROOT,
				encoding: 'utf8',
			});
			if (!/^M\thops\t1$/m.test(out)) throw new Error('the normalize mode did not report the hop count');
		},
	},
];

export function verify() {
	const failures = [];
	for (const check of CHECKS) {
		try {
			check.run();
		} catch (error) {
			failures.push(`${check.name}: ${error.message}`);
		}
	}
	// The denominator does not depend on the outcome. A broken repository and a
	// sound one report the same total, so the number cannot be read as a score.
	return { assertions: CHECKS.length, failures };
}

export const CHECK_NAMES = CHECKS.map((check) => check.name);

const invokedDirectly = (() => {
	if (!process.argv[1]) return false;
	try {
		return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
	} catch {
		return false;
	}
})();

if (invokedDirectly) {
	const { assertions, failures } = verify();
	if (process.argv.includes('--json')) {
		console.log(JSON.stringify({ assertions, failures }));
	} else if (failures.length) {
		console.error(failures.join('\n'));
		console.error(`\n${failures.length} of ${assertions} repository assertions failed.`);
	} else {
		console.log(`${assertions} repository assertions passed.`);
	}
	process.exit(failures.length ? 1 : 0);
}

export default verify;
