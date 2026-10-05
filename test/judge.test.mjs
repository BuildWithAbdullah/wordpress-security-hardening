import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judge, ids, cleanResponse } from '../tools/judge.mjs';

test('a clean HTTPS response produces no error findings and exits zero', () => {
  const result = judge(cleanResponse(), { url: 'https://example.test/' });
  const errors = result.findings.filter((f) => f.level === 'error');
  assert.deepEqual(errors, [], `unexpected errors: ${JSON.stringify(errors)}`);
  assert.equal(result.status, 0);
});

test('a missing required header is an error and the exit code is one', () => {
  const result = judge(cleanResponse({ 'x-frame-options': null }), {
    url: 'https://example.test/',
  });
  assert.ok(ids(result).includes('missing/x-frame-options'));
  assert.equal(result.status, 1);
});

test('warnings alone do not fail the run, so a post-deploy check is not noise', () => {
  const result = judge(cleanResponse({ 'x-pingback': 'https://example.test/xmlrpc.php' }), {
    url: 'https://example.test/',
  });
  assert.ok(ids(result).includes('leak/pingback'));
  assert.equal(result.status, 0, 'a warning must not fail the check');
});

test('only the final hop is judged, so a redirect cannot lend its headers to the page', () => {
  // The whole dump contains every required header. The final response contains
  // none of them. Version 1 searched the dump and reported a pass.
  const dump =
    'HTTP/1.1 301 Moved Permanently\n' +
    'location: https://example.test/\n' +
    'x-frame-options: SAMEORIGIN\n' +
    'x-content-type-options: nosniff\n' +
    'referrer-policy: same-origin\n' +
    'permissions-policy: camera=()\n' +
    'strict-transport-security: max-age=31536000\n\n' +
    'HTTP/2 200\n' +
    'content-type: text/html\n\n';

  const result = judge(dump, { url: 'https://example.test/' });
  const found = ids(result);

  assert.equal(
    found.filter((id) => id === 'redirect-only').length,
    5,
    'all five required headers were present on the hop and absent on the page',
  );
  assert.ok(!found.includes('missing/x-frame-options'), 'redirect-only is the more precise finding');
  assert.equal(result.status, 1);
});

test('a header present on both hops is judged from the final hop', () => {
  const dump =
    'HTTP/1.1 301 Moved Permanently\n' +
    'location: https://example.test/\n' +
    'x-frame-options: SAMEORIGIN\n\n' +
    cleanResponse({ 'x-frame-options': 'ALLOWALL' });

  const result = judge(dump, { url: 'https://example.test/' });
  assert.ok(ids(result).includes('weak/x-frame-options'));
  assert.ok(!ids(result).includes('redirect-only'));
});

test('an empty header value is not treated as an absent header', () => {
  const empty = judge(cleanResponse({ 'permissions-policy': '' }), {
    url: 'https://example.test/',
  });
  const absent = judge(cleanResponse({ 'permissions-policy': null }), {
    url: 'https://example.test/',
  });

  assert.ok(ids(empty).includes('weak/permissions-policy'));
  assert.ok(ids(absent).includes('missing/permissions-policy'));
  assert.notDeepEqual(ids(empty), ids(absent));
});

test('Server without a version is not reported as a leak', () => {
  const plain = judge(cleanResponse({ server: 'cloudflare' }), { url: 'https://example.test/' });
  assert.ok(!ids(plain).includes('leak/version'), 'Server: cloudflare is not a finding');

  const versioned = judge(cleanResponse({ server: 'Apache/2.4.41 (Ubuntu)' }), {
    url: 'https://example.test/',
  });
  assert.ok(ids(versioned).includes('leak/version'));
});

test('HSTS is not judged at all over plain HTTP, and that is said rather than assumed', () => {
  const result = judge(cleanResponse({ 'strict-transport-security': null }), {
    url: 'http://example.test/',
  });
  const found = ids(result);
  assert.ok(found.includes('transport/not-https'));
  assert.ok(
    !found.includes('missing/strict-transport-security'),
    'reporting HSTS missing on an HTTP URL would be a finding about nothing',
  );
});

test('a file that is not a header dump is refused rather than judged', () => {
  const result = judge('this is a CSV, not headers\n1,2,3\n', { url: 'https://example.test/' });
  assert.equal(result.status, 2, 'exit 2 is the usage and input error code');
  assert.deepEqual(result.findings, []);
  assert.match(result.stderr, /not a header dump/);
});

test('header matching ignores case, because HTTP/2 lowercases names', () => {
  const upper = judge(
    'HTTP/2 200\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY\n' +
      'Referrer-Policy: no-referrer\nPermissions-Policy: camera=()\n' +
      'Strict-Transport-Security: max-age=31536000\n\n',
    { url: 'https://example.test/' },
  );
  assert.deepEqual(
    upper.findings.filter((f) => f.level === 'error'),
    [],
  );
});

test('DENY is accepted as well as SAMEORIGIN', () => {
  const result = judge(cleanResponse({ 'x-frame-options': 'DENY' }), {
    url: 'https://example.test/',
  });
  assert.ok(!ids(result).includes('weak/x-frame-options'));
});
