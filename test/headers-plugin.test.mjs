import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probe, applyFilter, callFn } from '../tools/php.mjs';

const PLUGIN = 'mu-plugins/00-security-headers.php';

const REQUIRED = [
  'X-Content-Type-Options',
  'X-Frame-Options',
  'Referrer-Policy',
  'Permissions-Policy',
];

test('the front end filter adds every required header', () => {
  const { value } = applyFilter(PLUGIN, 'wp_headers', {}, { state: { is_ssl: true } });
  for (const name of REQUIRED) {
    assert.ok(name in value, `wp_headers did not add ${name}`);
  }
  assert.equal(value['X-Content-Type-Options'], 'nosniff');
  assert.equal(value['X-Frame-Options'], 'SAMEORIGIN');
  assert.equal(value['Strict-Transport-Security'], 'max-age=31536000');
});

test('the front end filter keeps headers WordPress already set', () => {
  const { value } = applyFilter(PLUGIN, 'wp_headers', { 'X-Custom': 'kept' });
  assert.equal(value['X-Custom'], 'kept');
});

/**
 * The reason version 2 of this plugin exists. Version 1 registered wp_headers
 * and nothing else, and wp_headers does not run on wp-login.php, so the login
 * form had none of these.
 */
test('the login page is sent the required headers', () => {
  const out = probe({
    load: [PLUGIN],
    state: { is_ssl: true },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });

  const sent = new Map(out.events.sent_headers.map((h) => [h.name, h.value]));
  for (const name of REQUIRED) {
    assert.ok(sent.has(name), `login_init did not send ${name}`);
  }
  assert.equal(sent.get('Strict-Transport-Security'), 'max-age=31536000');
});

test('the admin is sent the required headers', () => {
  const out = probe({
    load: [PLUGIN],
    state: { is_ssl: true, is_admin: true },
    ops: [{ op: 'do_action', tag: 'admin_init' }],
  });

  const sent = new Map(out.events.sent_headers.map((h) => [h.name, h.value]));
  for (const name of REQUIRED) {
    assert.ok(sent.has(name), `admin_init did not send ${name}`);
  }
});

test('an AJAX request in the admin is left alone', () => {
  const out = probe({
    load: [PLUGIN],
    state: { is_ssl: true, is_admin: true, doing_ajax: true },
    ops: [{ op: 'do_action', tag: 'admin_init' }],
  });
  assert.deepEqual(out.events.sent_headers, [], 'framing and robots directives are noise on AJAX');
});

test('the login page and the admin are told not to be indexed, and the front end is not', () => {
  const login = callFn(PLUGIN, 'wpsh_header_set', ['login', true]).value;
  const admin = callFn(PLUGIN, 'wpsh_header_set', ['admin', true]).value;
  const front = callFn(PLUGIN, 'wpsh_header_set', ['frontend', true]).value;

  assert.equal(login['X-Robots-Tag'], 'noindex, nofollow');
  assert.equal(admin['X-Robots-Tag'], 'noindex, nofollow');
  assert.ok(!('X-Robots-Tag' in front));

  // no-store on the front end would switch off every page cache on the site.
  assert.equal(login['Cache-Control'], 'no-store, max-age=0');
  assert.ok(!('Cache-Control' in front), 'a cache directive here is a performance incident');
});

test('HSTS is sent only over HTTPS, in every context', () => {
  for (const context of ['frontend', 'login', 'admin']) {
    const secure = callFn(PLUGIN, 'wpsh_header_set', [context, true]).value;
    const plain = callFn(PLUGIN, 'wpsh_header_set', [context, false]).value;

    assert.ok('Strict-Transport-Security' in secure, `${context} over HTTPS should send HSTS`);
    assert.ok(
      !('Strict-Transport-Security' in plain),
      `${context} over HTTP must not, because the browser ignores it`,
    );
  }
});

test('the HSTS max-age can be staged down', () => {
  const short = probe({
    load: [PLUGIN],
    constants: { WPSH_HSTS_MAX_AGE: 300 },
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  assert.equal(short.results['0'].value['Strict-Transport-Security'], 'max-age=300');
});

/**
 * Version 2 had a test here requiring a max age of zero to omit the header, and
 * it passed. It was asserting the defect, the same way the allowlist test in
 * test/ip-range.test.mjs was.
 *
 * HSTS lives in the browser, not in the response. Sending nothing does not undo
 * it: a browser that has the policy keeps it for the rest of the original max
 * age whatever the site stops doing. Withdrawing it means serving max-age=0 and
 * continuing to serve it until the old policy has expired everywhere, so the one
 * operator who most needs that header sent was the one version 2 refused to send
 * it for.
 */
test('a max age of zero sends the back-out header rather than nothing', () => {
  const off = probe({
    load: [PLUGIN],
    constants: { WPSH_HSTS_MAX_AGE: 0 },
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  assert.equal(
    off.results['0'].value['Strict-Transport-Security'],
    'max-age=0',
    'zero is the withdrawal value and has to be sent for the withdrawal to happen',
  );
});

test('a negative max age is clamped to the back-out value', () => {
  const out = probe({
    load: [PLUGIN],
    constants: { WPSH_HSTS_MAX_AGE: -1 },
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  // A negative max age has no meaning, and the nearest thing the operator can
  // have meant is the back-out.
  assert.equal(out.results['0'].value['Strict-Transport-Security'], 'max-age=0');
});

test('not sending HSTS at all is a separate, explicit choice', () => {
  const out = probe({
    load: [PLUGIN],
    constants: { WPSH_HSTS: false },
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  assert.ok(
    !('Strict-Transport-Security' in out.results['0'].value),
    'WPSH_HSTS false is the way to send no header, now that zero means withdraw',
  );
});

test('the default Permissions-Policy restricts no payment or wallet feature', () => {
  const out = probe({
    load: [PLUGIN],
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  const value = out.results['0'].value['Permissions-Policy'];
  assert.ok(typeof value === 'string' && value.length > 0);
  // payment=() switches off the Payment Request API, which every wallet
  // checkout button is built on. Version 2 had it in the default, so installing
  // this file on a store removed the express checkout and left the card form
  // working, which looks like a theme bug and gets noticed weeks later.
  assert.ok(
    !/(^|[,\s])payment\s*=\s*\(\s*\)/i.test(value),
    `the default must not disable payment: ${value}`,
  );
  // And it still restricts the things whose absence costs nothing.
  for (const feature of ['geolocation', 'camera', 'microphone']) {
    assert.ok(value.includes(`${feature}=()`), `${feature} should still be restricted by default`);
  }
});

test('a site with no wallet checkout can restrict payment deliberately', () => {
  const out = probe({
    load: [PLUGIN],
    constants: { WPSH_PERMISSIONS_POLICY: 'geolocation=(), payment=()' },
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  assert.equal(out.results['0'].value['Permissions-Policy'], 'geolocation=(), payment=()');
});

test('includeSubDomains is not sent, because it breaks subdomains nobody audited', () => {
  const { value } = callFn(PLUGIN, 'wpsh_header_set', ['frontend', true]);
  assert.ok(!/includeSubDomains/i.test(value['Strict-Transport-Security']));
});

test('the Permissions-Policy list can be replaced wholesale', () => {
  const out = probe({
    load: [PLUGIN],
    constants: { WPSH_PERMISSIONS_POLICY: 'geolocation=(self)' },
    ops: [{ op: 'call', fn: 'wpsh_header_set', args: ['frontend', true] }],
  });
  assert.equal(out.results['0'].value['Permissions-Policy'], 'geolocation=(self)');
});

test('the dead interest-cohort directive is gone', () => {
  const { value } = callFn(PLUGIN, 'wpsh_header_set', ['frontend', true]);
  assert.ok(
    !/interest-cohort/i.test(value['Permissions-Policy']),
    'it addressed a proposal that was abandoned, so it only made the header longer',
  );
});

test('the generator meta tag is removed', () => {
  const out = probe({ load: [PLUGIN], ops: [{ op: 'registered', tags: ['wp_head'] }] });
  assert.ok((out.removed.wp_head ?? []).includes('wp_generator'));
});

/**
 * Version 1 stripped the asset version query string unconditionally, which
 * breaks cache busting for every stylesheet and script on the site in exchange
 * for an obscurity measure the same file describes as not security.
 */
test('asset version stripping is off unless it is asked for', () => {
  const off = probe({
    load: [PLUGIN],
    ops: [{ op: 'apply_filters', tag: 'style_loader_src', value: 'https://example.test/a.css?ver=6.5' }],
  });
  assert.equal(
    off.results['0'].value,
    'https://example.test/a.css?ver=6.5',
    'the cache busting parameter must survive by default',
  );

  const on = probe({
    load: [PLUGIN],
    constants: { WPSH_STRIP_ASSET_VERSIONS: true },
    ops: [
      { op: 'apply_filters', tag: 'style_loader_src', value: 'https://example.test/a.css?ver=6.5' },
      { op: 'apply_filters', tag: 'script_loader_src', value: 'https://example.test/b.js?ver=6.5&x=1' },
    ],
  });
  assert.equal(on.results['0'].value, 'https://example.test/a.css');
  assert.equal(on.results['1'].value, 'https://example.test/b.js?x=1', 'other parameters stay');
});

test('the header set is a pure function of its arguments', () => {
  // Same arguments, separate processes, identical result. Nothing is read from
  // the request, so every value in the file is reachable from a test.
  const a = callFn(PLUGIN, 'wpsh_header_set', ['login', true]).value;
  const b = callFn(PLUGIN, 'wpsh_header_set', ['login', true]).value;
  assert.deepEqual(a, b);
});

test('an unknown context still gets the baseline headers rather than nothing', () => {
  const { value } = callFn(PLUGIN, 'wpsh_header_set', ['something-new', true]);
  for (const name of REQUIRED) {
    assert.ok(name in value, `a new context lost ${name}`);
  }
});
