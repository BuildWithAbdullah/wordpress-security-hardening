import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { judgeFile, ids, ROOT } from '../tools/judge.mjs';

const EXAMPLES = join(ROOT, 'examples');
const URL = 'https://example.test/';

/**
 * The finding each header pair exists to demonstrate.
 *
 * A pair is only worth shipping if the corrected side is provably corrected,
 * which means the same check has to be seen failing on the other side. A
 * repository full of checks that have never caught anything is a repository
 * whose checks may not work.
 */
const PAIRS = {
  '01-x-frame-options-permissive': 'weak/x-frame-options',
  '02-nosniff-missing': 'missing/x-content-type-options',
  '03-referrer-policy-unsafe': 'weak/referrer-policy',
  '04-permissions-policy-empty': 'weak/permissions-policy',
  '05-hsts-staging-max-age': 'weak/strict-transport-security',
  '06-hsts-disabled': 'disabled/strict-transport-security',
  '07-headers-on-redirect-only': 'redirect-only',
  '08-csp-unsafe-inline': 'csp/unsafe-inline',
  '09-version-disclosure': 'leak/version',
  '10-pingback-advertised': 'leak/pingback',
};

test('every header fixture on disk belongs to a declared pair', () => {
  const stems = new Set(
    readdirSync(EXAMPLES)
      .filter((name) => name.endsWith('.headers'))
      .map((name) => name.replace(/\.(fail|pass)\.headers$/, '')),
  );

  assert.deepEqual([...stems].sort(), Object.keys(PAIRS).sort());
});

test('each pair has both sides', () => {
  const files = new Set(readdirSync(EXAMPLES));
  for (const stem of Object.keys(PAIRS)) {
    assert.ok(files.has(`${stem}.fail.headers`), `${stem} has no failing side`);
    assert.ok(files.has(`${stem}.pass.headers`), `${stem} has no corrected side`);
  }
});

test('the failing side of each pair produces that pair finding', () => {
  for (const [stem, id] of Object.entries(PAIRS)) {
    const found = ids(judgeFile(join(EXAMPLES, `${stem}.fail.headers`), { url: URL }));
    assert.ok(found.includes(id), `${stem}.fail.headers produced ${JSON.stringify(found)}`);
  }
});

test('the corrected side of each pair does not', () => {
  for (const [stem, id] of Object.entries(PAIRS)) {
    const found = ids(judgeFile(join(EXAMPLES, `${stem}.pass.headers`), { url: URL }));
    assert.ok(!found.includes(id), `${stem}.pass.headers still produces ${id}`);
  }
});

test('no corrected fixture trips any other pair finding either', () => {
  // The cross-check. Without it a corrected example can quietly carry a
  // different defect, and the pair still passes because its own check is
  // satisfied.
  const everyPairId = new Set(Object.values(PAIRS));

  for (const stem of Object.keys(PAIRS)) {
    const found = ids(judgeFile(join(EXAMPLES, `${stem}.pass.headers`), { url: URL }));
    const trips = found.filter((id) => everyPairId.has(id));
    assert.deepEqual(trips, [], `${stem}.pass.headers trips ${trips.join(', ')}`);
  }
});

test('no corrected fixture produces an error level finding', () => {
  for (const stem of Object.keys(PAIRS)) {
    const result = judgeFile(join(EXAMPLES, `${stem}.pass.headers`), { url: URL });
    const errors = result.findings.filter((f) => f.level === 'error');
    assert.deepEqual(errors, [], `${stem}.pass.headers: ${JSON.stringify(errors)}`);
    assert.equal(result.status, 0);
  }
});

test('every fixture is a parseable header dump rather than prose', () => {
  for (const name of readdirSync(EXAMPLES).filter((n) => n.endsWith('.headers'))) {
    const result = judgeFile(join(EXAMPLES, name), { url: URL });
    assert.notEqual(result.status, 2, `${name} was refused as input: ${result.stderr}`);
  }
});
