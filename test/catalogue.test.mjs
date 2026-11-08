import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judgeFile } from '../tools/judge.mjs';
import { ALL, ALL_IDS, FINDINGS, FAMILIES, AREAS, LEVELS, levelsFor } from '../tools/catalogue.mjs';
import { HEADER_PAIRS } from '../tools/pairs.mjs';
import { FIXTURES } from '../tools/fixtures.mjs';

/**
 * Everything here is driven out of a real run of the real script. Nothing is
 * asserted about the catalogue on its own, because a catalogue that agrees with
 * itself is documentation, and documentation of a checker drifts from the
 * checker within about two commits.
 *
 * The run is done once and reused, because it is 53 invocations of a shell
 * script and each one spawns awk several times.
 */
const observed = new Map(); // id -> Set of levels actually produced

function record(path, url) {
	const args = url ? { url } : {};
	const result = judgeFile(path, args);
	for (const finding of result.findings) {
		if (!observed.has(finding.id)) observed.set(finding.id, new Set());
		observed.get(finding.id).add(finding.level);
	}
}

for (const pair of HEADER_PAIRS) {
	record(`examples/${pair.stem}.fail.headers`, pair.url);
	record(`examples/${pair.stem}.pass.headers`, pair.url);
}
for (const fixture of FIXTURES) {
	record(`fixtures/${fixture.file}`, fixture.url);
}

test('every catalogued finding is produced by a real run', () => {
	const unreachable = ALL_IDS.filter((id) => !observed.has(id));
	assert.deepEqual(
		unreachable,
		[],
		'a finding nobody can produce is not a finding, it is a plan. Delete it or write the fixture that reaches it',
	);
});

test('every finding a real run produces is catalogued', () => {
	const uncatalogued = [...observed.keys()].filter((id) => !ALL_IDS.includes(id));
	assert.deepEqual(
		uncatalogued,
		[],
		'the script emitted a finding that is not in tools/catalogue.mjs, so docs/07-every-finding.md does not describe what the script does',
	);
});

/**
 * The severity set, both ways, and the second direction is the one that does the
 * work.
 *
 * Version 2 declared one level per finding and emitted
 * weak/strict-transport-security at error when max-age was unparsable and at
 * warn when it was short. The generated document therefore told a reader the
 * run would not fail, and the run exited 1. Nothing caught it, because nothing
 * compared the declaration against a run.
 */
test('every severity a real run produces is declared', () => {
	const problems = [];
	for (const [id, levels] of observed) {
		const declared = levelsFor(id);
		if (!declared) continue;
		for (const level of levels) {
			if (!declared.includes(level)) {
				problems.push(`${id} was emitted at ${level}, which it does not declare (declares ${declared.join(', ')})`);
			}
		}
	}
	assert.deepEqual(problems, []);
});

test('every declared severity has been produced by some run', () => {
	const problems = [];
	for (const entry of ALL) {
		const seen = observed.get(entry.id) ?? new Set();
		for (const level of entry.levels) {
			if (!seen.has(level)) {
				problems.push(
					`${entry.id} declares it can be a ${level} and no example or fixture has ever produced one. ` +
						'Either write the case or stop declaring it',
				);
			}
		}
	}
	assert.deepEqual(problems, []);
});

test('no finding declares a level that is not a level', () => {
	for (const entry of ALL) {
		assert.ok(entry.levels.length > 0, `${entry.id} declares no severity at all`);
		for (const level of entry.levels) {
			assert.ok(LEVELS.includes(level), `${entry.id} declares an unknown severity: ${level}`);
		}
	}
});

test('every finding belongs to a declared area', () => {
	const areas = new Set(AREAS.map((a) => a.id));
	for (const entry of ALL) {
		assert.ok(areas.has(entry.area), `${entry.id} is in area ${entry.area}, which is not declared`);
	}
});

test('every declared area has at least one finding in it', () => {
	for (const area of AREAS) {
		const members = ALL.filter((entry) => entry.area === area.id);
		assert.ok(members.length > 0, `area ${area.id} has no findings`);
	}
});

test('ids are unique', () => {
	assert.equal(new Set(ALL_IDS).size, ALL_IDS.length);
});

test('every entry says what it is and why, one reason per entry', () => {
	for (const entry of ALL) {
		assert.ok(entry.reason && entry.reason.length > 20, `${entry.id} does not state its reason`);
		assert.ok(entry.what && entry.what.length > 40, `${entry.id} does not explain itself`);
	}
});

test('a family carries something and a fixed finding does not', () => {
	for (const family of FAMILIES) {
		assert.ok(family.carries && family.carries.length > 5, `${family.id} is a family and says nothing about what it carries`);
	}
	for (const finding of FINDINGS) {
		assert.ok(!('carries' in finding), `${finding.id} is not a family and should not declare a payload`);
	}
});

/**
 * One entry per reason, not one per check. The weakest form of this rule that
 * can be asserted mechanically: no two entries may describe the same reason in
 * the same area, and every required header must have the full set of reasons
 * rather than a single catch-all.
 */
test('each required header has every reason it can fail for', () => {
	const required = ['x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy'];
	for (const header of required) {
		for (const prefix of ['missing', 'empty', 'weak', 'conflict']) {
			assert.ok(
				ALL_IDS.includes(`${prefix}/${header}`),
				`${header} has no ${prefix} reason, so two different problems share one finding`,
			);
		}
	}
});

test('no two entries state the same reason', () => {
	const seen = new Map();
	for (const entry of ALL) {
		const key = entry.reason.trim().toLowerCase();
		assert.ok(!seen.has(key), `${entry.id} and ${seen.get(key)} state the same reason`);
		seen.set(key, entry.id);
	}
});
