/**
 * Generate docs/06-what-the-checks-do-not-see.md from tools/limits.mjs.
 *
 *   node tools/limits-doc.mjs            write the document
 *   node tools/limits-doc.mjs --check    fail if it is out of date
 *
 * The limits are the part of a repository like this that goes stale fastest and
 * least visibly. A paragraph saying the checker cannot see something still reads
 * correctly after the checker learns to see it, and a reader then trusts a
 * caveat that is no longer true, which is worse than having no caveat at all.
 *
 * So the document is generated from the manifest the suite checks, and CI fails
 * if the two differ. Version 2 had no declared limits anywhere, which is the
 * gap this closes.
 */

import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { LIMITS } from './limits.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TARGET = join(ROOT, 'docs', '06-what-the-checks-do-not-see.md');

export function render() {
	const lines = [];

	lines.push('# What the checks do not see');
	lines.push('');
	lines.push('Generated from `tools/limits.mjs` by `npm run docs`. Do not edit by hand.');
	lines.push('');
	lines.push('Read this before putting any output from this repository in front of a client.');
	lines.push('A green run means the things listed in');
	lines.push('[07 Every finding](07-every-finding.md) were not found. It does not mean the');
	lines.push('site is fine, and the gap between those two statements is what this page is.');
	lines.push('');
	lines.push('Every limit below is checked in both directions by `test/limits.test.mjs`.');
	lines.push('Each one names a case the repository says nothing about, which has to keep');
	lines.push('producing nothing, and a nearby case it does catch, which has to keep');
	lines.push('producing something. A limit that has quietly been fixed fails the build, and');
	lines.push('so does a check that has quietly stopped working. Without the second');
	lines.push('direction the prose would read correctly in either case.');
	lines.push('');
	lines.push(`There are ${LIMITS.length} of them.`);
	lines.push('');

	for (const [index, limit] of LIMITS.entries()) {
		lines.push(`## ${index + 1}. \`${limit.id}\``);
		lines.push('');
		lines.push(limit.limit);
		lines.push('');
		lines.push(`**Why it is the right trade.** ${limit.why}`);
		lines.push('');
		lines.push(
			`**Demonstrated by.** The case nothing is said about is \`${limit.blind.ref}\`, ` +
				`and the nearby case that is caught is \`${limit.contrast.ref}\`.`,
		);
		lines.push('');
	}

	lines.push('## The one that is not on the list');
	lines.push('');
	lines.push('Hardening is not a state a site reaches. Everything here reduces a surface or');
	lines.push('removes a signal, and none of it substitutes for keeping WordPress, the theme');
	lines.push('and the plugins updated, for having a restore that somebody has actually');
	lines.push('tested, or for knowing who has an administrator account and why. A site with');
	lines.push('every finding in this repository cleared and an out of date plugin is not a');
	lines.push('hardened site.');
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
			console.error('docs/06-what-the-checks-do-not-see.md does not exist. Run npm run docs.');
			process.exit(1);
		}
		if (current !== generated) {
			console.error('docs/06-what-the-checks-do-not-see.md is out of date. Run npm run docs and commit it.');
			process.exit(1);
		}
		console.log('docs/06-what-the-checks-do-not-see.md is current.');
	} else {
		writeFileSync(TARGET, generated, 'utf8');
		console.log(`Wrote docs/06-what-the-checks-do-not-see.md (${LIMITS.length} limits).`);
	}
}

export default render;
