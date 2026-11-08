/**
 * Which files in the working tree git would track.
 *
 * tools/verify.mjs counts files and reads them, and a verifier that counts text
 * files has to read .gitignore or it counts things that are not in the
 * repository. The obvious shortcut, shelling out to git ls-files, is not
 * available: the verifier has to run from an extracted archive and from a
 * published tree with no git directory.
 *
 * So this is a gitignore matcher, and the parts implementations usually get
 * wrong are the parts that are tested in CI against git itself on a
 * purpose-built tree:
 *
 *   last match wins, so a later rule can override an earlier one
 *   a leading ! negates, and a negation can re-include a file an earlier
 *     pattern excluded
 *   a negation cannot re-include a file inside an excluded directory, because
 *     git never looks inside that directory to see the negation
 *   a pattern with no slash matches at any depth
 *   a pattern with a trailing slash matches directories only
 *   a leading slash anchors to the repository root
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

export { ROOT };

/** Parse .gitignore into rules, in file order. */
export function rules(root = ROOT) {
	const path = join(root, '.gitignore');
	if (!existsSync(path)) return [];

	return readFileSync(path, 'utf8')
		.split('\n')
		.map((line) => line.replace(/\r$/, ''))
		.filter((line) => line.trim() !== '' && !line.startsWith('#'))
		.map((line) => {
			let pattern = line.trim();
			const negated = pattern.startsWith('!');
			if (negated) pattern = pattern.slice(1);

			const directoryOnly = pattern.endsWith('/');
			if (directoryOnly) pattern = pattern.slice(0, -1);

			const anchored = pattern.startsWith('/') || pattern.slice(0, -1).includes('/');
			if (pattern.startsWith('/')) pattern = pattern.slice(1);

			return { pattern, negated, directoryOnly, anchored, source: line.trim() };
		});
}

function toRegExp(pattern) {
	let out = '';
	for (let i = 0; i < pattern.length; i++) {
		const c = pattern[i];
		if (c === '*') {
			if (pattern[i + 1] === '*') {
				out += '.*';
				i++;
				if (pattern[i + 1] === '/') i++;
			} else {
				out += '[^/]*';
			}
		} else if (c === '?') {
			out += '[^/]';
		} else if ('\\^$.|+()[]{}'.includes(c)) {
			out += `\\${c}`;
		} else {
			out += c;
		}
	}
	return new RegExp(`^${out}$`);
}

function matchesRule(rule, relativePath, isDirectory) {
	if (rule.directoryOnly && !isDirectory) return false;

	const re = toRegExp(rule.pattern);

	if (rule.anchored) return re.test(relativePath);

	// An unanchored pattern matches the entry at any depth, which means it is
	// compared against every trailing segment run of the path.
	const parts = relativePath.split('/');
	for (let i = 0; i < parts.length; i++) {
		if (re.test(parts.slice(i).join('/'))) return true;
	}
	return false;
}

/**
 * Whether git would ignore this path. Last matching rule wins, which is why
 * the loop does not return early.
 */
export function ignored(relativePath, isDirectory, parsed = rules()) {
	let decision = false;
	for (const rule of parsed) {
		if (matchesRule(rule, relativePath, isDirectory)) decision = !rule.negated;
	}
	return decision;
}

/**
 * Every tracked file, as paths relative to the root, sorted.
 *
 * The walk does not descend into an ignored directory, and that is not an
 * optimisation. git does not look inside an ignored directory either, so a
 * negation written for a file in there cannot re-include it. Descending and
 * then applying the negation would report files git does not track, which is
 * the specific thing implementations of this get wrong.
 */
export function trackedFiles(root = ROOT) {
	const parsed = rules(root);
	const found = [];

	const walk = (directory) => {
		for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
			a.name.localeCompare(b.name),
		)) {
			if (entry.name === '.git') continue;

			const full = join(directory, entry.name);
			const rel = relative(root, full).split(sep).join('/');

			let isDirectory = entry.isDirectory();
			if (entry.isSymbolicLink()) {
				try {
					isDirectory = statSync(full).isDirectory();
				} catch {
					continue;
				}
			}

			if (ignored(rel, isDirectory, parsed)) continue;

			if (isDirectory) walk(full);
			else found.push(rel);
		}
	};

	walk(root);
	return found.sort();
}

export default trackedFiles;
