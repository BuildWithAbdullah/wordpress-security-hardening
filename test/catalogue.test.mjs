import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judge, ids, cleanResponse } from '../tools/judge.mjs';
import { FINDINGS, FAMILIES, ALL_IDS } from '../tools/catalogue.mjs';

/**
 * One case per catalogued finding, each a real dump put through the real
 * script. If a finding cannot be driven out of a dump, it is a finding the
 * script cannot emit, and it has no business being documented.
 */
const CASES = {
  'missing/x-content-type-options': [cleanResponse({ 'x-content-type-options': null }), 'https://example.test/'],
  'weak/x-content-type-options': [cleanResponse({ 'x-content-type-options': 'none' }), 'https://example.test/'],
  'missing/x-frame-options': [cleanResponse({ 'x-frame-options': null }), 'https://example.test/'],
  'weak/x-frame-options': [cleanResponse({ 'x-frame-options': 'ALLOWALL' }), 'https://example.test/'],
  'missing/referrer-policy': [cleanResponse({ 'referrer-policy': null }), 'https://example.test/'],
  'weak/referrer-policy': [cleanResponse({ 'referrer-policy': 'unsafe-url' }), 'https://example.test/'],
  'missing/permissions-policy': [cleanResponse({ 'permissions-policy': null }), 'https://example.test/'],
  'weak/permissions-policy': [cleanResponse({ 'permissions-policy': '' }), 'https://example.test/'],
  'missing/strict-transport-security': [cleanResponse({ 'strict-transport-security': null }), 'https://example.test/'],
  'weak/strict-transport-security': [cleanResponse({ 'strict-transport-security': 'max-age=300' }), 'https://example.test/'],
  'disabled/strict-transport-security': [cleanResponse({ 'strict-transport-security': 'max-age=0' }), 'https://example.test/'],
  'transport/not-https': [cleanResponse({ 'strict-transport-security': null }), 'http://example.test/'],
  'csp/absent': [cleanResponse(), 'https://example.test/'],
  'csp/unsafe-inline': [
    cleanResponse({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" }),
    'https://example.test/',
  ],
  'leak/pingback': [cleanResponse({ 'x-pingback': 'https://example.test/xmlrpc.php' }), 'https://example.test/'],
  'leak/version': [cleanResponse({ 'x-powered-by': 'PHP/8.2.4' }), 'https://example.test/'],
  'redirect-only': [
    'HTTP/1.1 301 Moved Permanently\nlocation: https://example.test/\nx-frame-options: SAMEORIGIN\n\n' +
      cleanResponse({ 'x-frame-options': null }),
    'https://example.test/',
  ],
};

test('every catalogued finding has a case that drives it', () => {
  const missing = ALL_IDS.filter((id) => !(id in CASES));
  assert.deepEqual(missing, [], `catalogued but never driven: ${missing.join(', ')}`);
});

test('every case drives the finding it claims to', () => {
  for (const [id, [dump, url]] of Object.entries(CASES)) {
    const found = ids(judge(dump, { url }));
    assert.ok(found.includes(id), `case for ${id} produced ${JSON.stringify(found)} instead`);
  }
});

test('the script emits no finding that is not catalogued', () => {
  const seen = new Set();
  for (const [dump, url] of Object.values(CASES)) {
    for (const id of ids(judge(dump, { url }))) seen.add(id);
  }
  const stray = [...seen].filter((id) => !ALL_IDS.includes(id));
  assert.deepEqual(stray, [], `emitted but not catalogued: ${stray.join(', ')}`);

  // Both directions. The first test proves the catalogue is not aspirational;
  // this proves the collected set is exactly the catalogue and nothing more.
  assert.deepEqual([...seen].sort(), [...ALL_IDS].sort());
});

test('the level each finding is catalogued with is the level it is emitted at', () => {
  const levels = new Map([...FINDINGS, ...FAMILIES].map((f) => [f.id, f.level]));

  for (const [id, [dump, url]] of Object.entries(CASES)) {
    const emitted = judge(dump, { url }).findings.filter((f) => f.id === id);
    assert.ok(emitted.length > 0, `${id} was not emitted`);
    for (const finding of emitted) {
      assert.equal(
        finding.level,
        levels.get(id),
        `${id} is catalogued as ${levels.get(id)} and emitted as ${finding.level}`,
      );
    }
  }
});

test('ids are unique and every entry says what it means', () => {
  const all = [...FINDINGS, ...FAMILIES];
  assert.equal(new Set(all.map((f) => f.id)).size, all.length, 'duplicate id in the catalogue');
  for (const finding of all) {
    assert.match(finding.id, /^[a-z0-9-]+(\/[a-z0-9-]+)?$/, `unusable id: ${finding.id}`);
    assert.ok(['error', 'warn', 'note'].includes(finding.level), `bad level on ${finding.id}`);
    assert.ok(finding.what.length > 30, `${finding.id} needs a real description`);
    assert.ok(finding.what.trim().endsWith('.'), `${finding.id} description should be a sentence`);
  }
});

test('only an error level finding changes the exit code', () => {
  for (const [id, [dump, url]] of Object.entries(CASES)) {
    const result = judge(dump, { url });
    const hasError = result.findings.some((f) => f.level === 'error');
    assert.equal(
      result.status,
      hasError ? 1 : 0,
      `${id}: exit ${result.status} with errors=${hasError}`,
    );
  }
});
