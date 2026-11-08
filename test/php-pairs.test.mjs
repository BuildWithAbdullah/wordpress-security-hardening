import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from '../tools/php.mjs';
import { AUDITS, AUDIT_STEMS, expectationsFor } from '../tools/audits.mjs';
import { PHP_PAIR_STEMS } from '../tools/pairs.mjs';

const EXAMPLES = join(ROOT, 'examples');

/**
 * The audits live in tools/audits.mjs rather than here, so that
 * tools/audit-verdicts.mjs can derive the same four expectations from the same
 * manifest and run them outside the test runner. Two readers, one copy of the
 * contract. Two lists would have drifted by the second pair.
 */

test('the pair list and the audit list are the same list', () => {
	assert.deepEqual([...AUDIT_STEMS].sort(), [...PHP_PAIR_STEMS].sort());
});

test('every PHP example on disk belongs to a declared pair', () => {
	const stems = new Set(
		readdirSync(EXAMPLES)
			.filter((name) => name.endsWith('.php'))
			.map((name) => name.replace(/\.(fail|pass)\.php$/, '')),
	);
	assert.deepEqual([...stems].sort(), [...AUDIT_STEMS].sort());
});

test('each pair has both sides', () => {
	const files = new Set(readdirSync(EXAMPLES));
	for (const stem of AUDIT_STEMS) {
		assert.ok(files.has(`${stem}.fail.php`), `${stem} has no failing side`);
		assert.ok(files.has(`${stem}.pass.php`), `${stem} has no corrected side`);
	}
});

test('every audit fails on its failing example', () => {
	for (const stem of AUDIT_STEMS) {
		assert.equal(
			AUDITS[stem].run([`examples/${stem}.fail.php`]),
			false,
			`${stem}: the audit passed on the failing example, so it proves nothing`,
		);
	}
});

test('every audit passes on its corrected example', () => {
	for (const stem of AUDIT_STEMS) {
		assert.equal(
			AUDITS[stem].run([`examples/${stem}.pass.php`]),
			true,
			`${stem}: ${AUDITS[stem].proves} did not hold on the corrected example`,
		);
	}
});

/**
 * The pairs exist to explain the corrections in mu-plugins/. An audit that
 * passes on its corrected example and fails on the real plugin means the example
 * documents a correction the plugin no longer makes, which is worse than no
 * example.
 */
test('every audit passes against the shipped plugin it was drawn from', () => {
	for (const stem of AUDIT_STEMS) {
		const plugin = AUDITS[stem].plugin;
		assert.ok(plugin, `${stem} does not name the plugin it was drawn from`);
		assert.equal(AUDITS[stem].run([plugin]), true, `${stem}: ${AUDITS[stem].proves} does not hold in ${plugin}`);
	}
});

test('every audit fails against an empty page, unless it says why it cannot', () => {
	for (const stem of AUDIT_STEMS) {
		const audit = AUDITS[stem];
		if (audit.emptyPasses) {
			assert.ok(audit.emptyReason && audit.emptyReason.length > 60, `${stem} needs its exemption explained`);
			continue;
		}
		assert.equal(
			audit.run([]),
			false,
			`${stem}: the audit passes with nothing loaded, so it is asking nothing`,
		);
	}
});

test('each audit states what it proves', () => {
	for (const stem of AUDIT_STEMS) {
		assert.ok(AUDITS[stem].proves && AUDITS[stem].proves.length > 25, `${stem} does not say what it proves`);
	}
});

test('the derived expectations are what this file asserts, and there are enough of them', () => {
	// expectationsFor is what tools/audit-verdicts.mjs runs. If it ever produced
	// fewer cases than the contract describes, that tool would go quiet while
	// still reporting success.
	let total = 0;
	for (const stem of AUDIT_STEMS) {
		const cases = expectationsFor(stem);
		const names = cases.map((c) => c.name);
		assert.ok(names.includes('failing example'), `${stem} has no failing case derived`);
		assert.ok(names.includes('corrected example'), `${stem} has no corrected case derived`);
		assert.ok(names.includes('shipped plugin'), `${stem} has no plugin case derived`);
		if (!AUDITS[stem].emptyPasses) {
			assert.ok(names.includes('nothing loaded'), `${stem} has no empty case derived`);
		}
		total += cases.length;
	}
	assert.ok(total >= AUDIT_STEMS.length * 3, `only ${total} verdicts derived across ${AUDIT_STEMS.length} pairs`);
});
