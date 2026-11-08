/**
 * Fail the build when a decision moves into a file no test can reach.
 *
 *   node tools/entry-thin.mjs
 *
 * scripts/check-headers.sh makes the one HTTP request in this repository, which
 * means nothing in the test suite can run it. Whatever sits in that file has
 * exactly the coverage `bash -n` gives it, which is none. The whole of
 * scripts/collect-decide.sh was carved out of it for that reason: option
 * parsing, deciding what counts as an unusable response, deciding when the
 * headers probably belong to an error page, deciding where --save writes. Those
 * are decisions and they are now somewhere a test can call them.
 *
 * Carving them out once is not enough, because the obvious next change puts one
 * back. A conditional in the fetching script is cheaper to write than a round
 * trip through the decider, and nothing would complain. So this does.
 *
 * ---------------------------------------------------------------------------
 * The vocabulary is declared per entry point, not once for the repository
 *
 * That is not tidiness. A shared needle list misfires, because the same token
 * means different things in different files. `case` in an option parser is a
 * decision about what the user asked for. `case` in a symlink resolver is
 * picking apart a path, which is wiring, and this file resolves its own path
 * through symlinks because not doing so broke every installed copy. A single
 * list containing `case` would have flagged the fix for a real bug as a
 * violation, and the usual response to that is to delete the check.
 *
 * So each needle is written against the file it is for, and each one names the
 * decision it is looking for rather than the syntax it happens to use.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * There is one entry point in this repository, and that is the point. Adding a
 * second means adding an entry here with its own vocabulary, which is the
 * moment to decide what that file is and is not allowed to know.
 */
export const ENTRY_POINTS = [
	{
		file: 'scripts/check-headers.sh',
		what: 'the only file that makes a network request, and therefore the only file no test can run',
		maxLines: 50,
		maxBranches: 12,
		forbidden: [
			{
				needle: 'while [ $#',
				decision: 'parsing the argument list, which belongs in collect-decide.sh plan',
			},
			{
				needle: 'case "$1"',
				decision: 'dispatching on an option the user passed, which belongs in collect-decide.sh plan',
			},
			{
				needle: '--json)',
				decision: 'recognising an option, which belongs in collect-decide.sh plan',
			},
			{
				needle: '--save',
				decision: 'handling the save option, which belongs in collect-decide.sh finish',
			},
			{
				needle: 'usage(',
				decision: 'owning the usage text, which belongs with the parser that produces it',
			},
			{
				needle: '$STATUS',
				decision:
					'interpreting the response status, which belongs in collect-decide.sh finish. The status is still collected here, because collecting it is part of the request',
			},
			{
				needle: 'error page',
				decision: 'deciding what the headers probably are, which belongs in collect-decide.sh finish',
			},
			{
				needle: '-s "$DUMP"',
				decision: 'deciding whether the fetch produced anything usable, which belongs in collect-decide.sh finish',
			},
			{
				needle: 'cp "$DUMP"',
				decision: 'writing the saved copy, which belongs in collect-decide.sh finish',
			},
		],
	},
];

/** Lines that are neither blank nor a comment. */
function codeLines(text) {
	return text
		.split('\n')
		.map((line) => line.trim())
		.filter((line) => line !== '' && !line.startsWith('#'));
}

/**
 * A rough branch count, and rough is the right precision. The number is a
 * budget rather than a measurement: it exists so that a file growing a second
 * decision shows up as a number going the wrong way.
 */
function branchCount(lines) {
	let count = 0;
	for (const line of lines) {
		for (const token of [/\bif\b/, /\belif\b/, /\bwhile\b/, /\bcase\b/, /&&/, /\|\|/]) {
			if (token.test(line)) count++;
		}
	}
	return count;
}

export function check() {
	const problems = [];

	for (const entry of ENTRY_POINTS) {
		const text = readFileSync(join(ROOT, entry.file), 'utf8');
		const lines = codeLines(text);

		/**
		 * Code only. Scanning the whole file made this fire on its own
		 * documentation: the usage comment at the top of check-headers.sh names
		 * the options it accepts, which is exactly what the file should say and
		 * exactly what the needle is looking for. An assertion that reads prose
		 * reports the comment that explains the rule as a breach of it.
		 */
		const code = lines.join('\n');

		for (const rule of entry.forbidden) {
			if (code.includes(rule.needle)) {
				problems.push(`${entry.file} contains ${JSON.stringify(rule.needle)}: ${rule.decision}`);
			}
		}

		if (lines.length > entry.maxLines) {
			problems.push(
				`${entry.file} has ${lines.length} lines of code, over its budget of ${entry.maxLines}. ` +
					'Either it grew a decision or the budget needs a deliberate change.',
			);
		}

		const branches = branchCount(lines);
		if (branches > entry.maxBranches) {
			problems.push(
				`${entry.file} has about ${branches} branches, over its budget of ${entry.maxBranches}. ` +
					'A branch here is a decision nothing can test.',
			);
		}
	}

	return problems;
}

export function measure() {
	return ENTRY_POINTS.map((entry) => {
		const lines = codeLines(readFileSync(join(ROOT, entry.file), 'utf8'));
		return { file: entry.file, lines: lines.length, branches: branchCount(lines) };
	});
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
	const problems = check();
	if (problems.length) {
		console.error(problems.join('\n'));
		process.exit(1);
	}
	for (const m of measure()) {
		console.log(`${m.file}: ${m.lines} lines of code, about ${m.branches} branches, no decisions.`);
	}
}

export default check;
