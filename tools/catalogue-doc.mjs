/**
 * Generate docs/07-every-finding.md from the catalogue.
 *
 *   node tools/catalogue-doc.mjs            write the document
 *   node tools/catalogue-doc.mjs --check    fail if it is out of date
 *
 * The document is generated because a hand-written list of a checker's findings
 * drifts from the checker, and the drift is invisible: the document still reads
 * correctly, it is just describing a tool that no longer exists. CI runs the
 * check, so a new finding cannot land without its documentation.
 *
 * It prints the complete severity set per finding rather than one level, which
 * is the thing version 2 got wrong. One declared level per finding meant the
 * document asserted that an unparsable max-age would not fail the run, while
 * the run exited 1.
 */

import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FINDINGS, FAMILIES, AREAS, ALL } from './catalogue.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TARGET = join(ROOT, 'docs', '07-every-finding.md');

const LEVEL_MEANING = {
	error: 'Fails the run. Exit code 1.',
	warn: 'Reported, does not fail the run.',
	note: 'Reported for the record.',
};

function renderEntry(lines, entry) {
	lines.push(`#### \`${entry.id}\``);
	lines.push('');
	lines.push(`Severity: ${entry.levels.map((l) => `\`${l}\``).join(' or ')}.`);
	if (entry.carries) lines.push(`Carries ${entry.carries}.`);
	lines.push('');
	lines.push(`**When.** ${entry.reason}`);
	lines.push('');
	lines.push(entry.what);
	lines.push('');
}

export function render() {
	const lines = [];

	lines.push('# Every finding');
	lines.push('');
	lines.push('Generated from `tools/catalogue.mjs` by `npm run docs`. Do not edit by hand.');
	lines.push('');
	lines.push('This is the complete list of what `scripts/judge-headers.sh` can report, and');
	lines.push('`test/catalogue.test.mjs` drives every entry out of a real run of the real');
	lines.push('script. A finding that cannot be produced does not stay on the list, and a');
	lines.push('finding the script produces that is not on the list fails the suite.');
	lines.push('');
	lines.push('One entry per reason, not one per check. A check that refuses a response for');
	lines.push('four different reasons is four entries, because the fix is different in each');
	lines.push('case and because a fixture written per reason is what proves the reason is');
	lines.push('reachable at all.');
	lines.push('');
	lines.push('What the findings do **not** cover is in');
	lines.push('[06 What the checks do not see](06-what-the-checks-do-not-see.md). Read that');
	lines.push('before putting any of this in front of a client.');
	lines.push('');
	lines.push('## Severities');
	lines.push('');
	lines.push('| Severity | Meaning |');
	lines.push('|---|---|');
	for (const [level, meaning] of Object.entries(LEVEL_MEANING)) {
		lines.push(`| \`${level}\` | ${meaning} |`);
	}
	lines.push('');
	lines.push('Each entry below declares the complete set of severities it can carry, and the');
	lines.push('suite asserts that set in both directions: a severity a real run produces that');
	lines.push('is not declared fails the build, and a severity declared here that no test has');
	lines.push('ever produced fails it too.');
	lines.push('');
	lines.push('Only an error changes the exit code. A post-deploy check that fails the build');
	lines.push('over a version string in a `Server` header is a check somebody switches off.');
	lines.push('');
	lines.push(`## The findings (${ALL.length} across ${AREAS.length} areas)`);
	lines.push('');

	for (const area of AREAS) {
		const fixed = FINDINGS.filter((f) => f.area === area.id);
		const families = FAMILIES.filter((f) => f.area === area.id);
		lines.push(`### ${area.id} (${fixed.length + families.length})`);
		lines.push('');
		lines.push(area.what);
		lines.push('');
		for (const entry of fixed) renderEntry(lines, entry);
		for (const entry of families) {
			renderEntry(lines, entry);
		}
	}

	lines.push('## Open families');
	lines.push('');
	lines.push('These carry a value read from the response, so the set of concrete messages is');
	lines.push('not finite. The suite requires each family to be produced rather than listing');
	lines.push('every message it can produce. They are listed above under their own areas, and');
	lines.push('are named here together so the distinction is visible:');
	lines.push('');
	for (const family of FAMILIES) {
		lines.push(`- \`${family.id}\`, which carries ${family.carries}`);
	}
	lines.push('');

	return lines.join('\n');
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
	const generated = render();

	if (process.argv.includes('--check')) {
		let current = '';
		try {
			current = readFileSync(TARGET, 'utf8');
		} catch {
			console.error('docs/07-every-finding.md does not exist. Run npm run docs.');
			process.exit(1);
		}
		if (current !== generated) {
			console.error('docs/07-every-finding.md is out of date. Run npm run docs and commit it.');
			process.exit(1);
		}
		console.log('docs/07-every-finding.md is current.');
	} else {
		writeFileSync(TARGET, generated, 'utf8');
		console.log(`Wrote docs/07-every-finding.md (${ALL.length} entries across ${AREAS.length} areas).`);
	}
}

export default render;
