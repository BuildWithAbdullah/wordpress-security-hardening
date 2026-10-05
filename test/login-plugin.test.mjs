import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probe, applyFilter } from '../tools/php.mjs';

const PLUGIN = 'mu-plugins/02-harden-login.php';
const GENERIC = 'The username or password you entered is not correct.';

const ROUTES = {
  '/wp/v2/posts': {},
  '/wp/v2/users': {},
  '/wp/v2/users/(?P<id>[\\d]+)': {},
  '/wp/v2/media': {},
};

test('a failed login gets the same message whether or not the account exists', () => {
  for (const code of ['invalid_username', 'incorrect_password']) {
    const out = probe({
      load: [PLUGIN],
      error_codes: [code],
      ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'Unknown username. Check again.' }],
    });
    assert.equal(out.results['0'].value, GENERIC, `${code} leaked a distinguishable message`);
  }
});

/**
 * The defect version 1 shipped. login_errors carries every notice wp-login.php
 * renders, not only failures, so an unconditional filter told a user who had
 * just logged out that their password was wrong.
 */
test('a notice that is not an authentication failure passes through untouched', () => {
  const out = probe({
    load: [PLUGIN],
    error_codes: [],
    ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'You are now logged out.' }],
  });
  assert.equal(out.results['0'].value, 'You are now logged out.');
});

test('a non-authentication error code also passes through', () => {
  const out = probe({
    load: [PLUGIN],
    error_codes: ['confirm'],
    ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'Check your email for the link.' }],
  });
  assert.equal(out.results['0'].value, 'Check your email for the link.');
});

test('a mixed error set is genericised, because one auth code is enough to confirm an account', () => {
  const out = probe({
    load: [PLUGIN],
    error_codes: ['confirm', 'incorrect_password'],
    ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'The password you entered for alice is wrong.' }],
  });
  assert.equal(out.results['0'].value, GENERIC);
});

test('no WP_Error at all leaves the message alone', () => {
  const out = probe({
    load: [PLUGIN],
    ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'Registration complete.' }],
  });
  assert.equal(out.results['0'].value, 'Registration complete.');
});

test('an anonymous request for an author archive is redirected', () => {
  const out = probe({
    load: [PLUGIN],
    state: { logged_in: false, get: { author: '1' } },
    ops: [{ op: 'do_action', tag: 'template_redirect' }],
  });
  assert.equal(out.events.redirects.length, 1);
  assert.equal(out.events.redirects[0].location, 'https://example.test/');
});

/**
 * 301 was the version 1 behaviour and it is not reversible. A browser caches a
 * permanent redirect and stops asking, so re-enabling author archives later
 * does not reach anyone who has already been redirected.
 */
test('the author redirect is temporary, so the decision can be undone', () => {
  const out = probe({
    load: [PLUGIN],
    state: { logged_in: false, is_author: true },
    ops: [{ op: 'do_action', tag: 'template_redirect' }],
  });
  assert.equal(out.events.redirects[0].status, 302);
  assert.notEqual(out.events.redirects[0].status, 301);
});

test('the redirect uses the safe helper, so an open redirect cannot be smuggled in', () => {
  const out = probe({
    load: [PLUGIN],
    state: { logged_in: false, is_author: true },
    ops: [{ op: 'do_action', tag: 'template_redirect' }],
  });
  assert.equal(out.events.redirects[0].safe, true);
});

test('a signed in user keeps author archives, because editorial workflows use them', () => {
  const out = probe({
    load: [PLUGIN],
    state: { logged_in: true, is_author: true, get: { author: '1' } },
    ops: [{ op: 'do_action', tag: 'template_redirect' }],
  });
  assert.deepEqual(out.events.redirects, []);
});

test('an ordinary page is not redirected', () => {
  const out = probe({
    load: [PLUGIN],
    state: { logged_in: false, is_author: false, get: {} },
    ops: [{ op: 'do_action', tag: 'template_redirect' }],
  });
  assert.deepEqual(out.events.redirects, []);
});

test('the REST users routes are removed for anonymous requests, and only those routes', () => {
  const { value } = applyFilter(PLUGIN, 'rest_endpoints', ROUTES, { state: { logged_in: false } });
  assert.ok(!('/wp/v2/users' in value));
  assert.ok(!('/wp/v2/users/(?P<id>[\\d]+)' in value));
  assert.ok('/wp/v2/posts' in value, 'disabling the REST API would break the block editor');
  assert.ok('/wp/v2/media' in value);
});

test('an administrator keeps them', () => {
  const { value } = applyFilter(PLUGIN, 'rest_endpoints', ROUTES, {
    state: { logged_in: true, caps: ['list_users'] },
  });
  assert.deepEqual(Object.keys(value).sort(), Object.keys(ROUTES).sort());
});

test('a signed in user without the capability does not keep them', () => {
  const { value } = applyFilter(PLUGIN, 'rest_endpoints', ROUTES, {
    state: { logged_in: true, caps: ['edit_posts'] },
  });
  assert.ok(!('/wp/v2/users' in value));
});

/**
 * The documented trade. list_users is an administrator, which means an Editor
 * cannot populate the author dropdown in the block editor. Sites that need
 * that relax the capability, and the point of the test is that the constant
 * actually works rather than being a README promise.
 */
test('the capability can be relaxed for sites with Editors who reassign posts', () => {
  const out = probe({
    load: [PLUGIN],
    state: { logged_in: true, caps: ['edit_others_posts'] },
    constants: { WPSH_USERS_ENDPOINT_CAP: 'edit_others_posts' },
    ops: [{ op: 'apply_filters', tag: 'rest_endpoints', value: ROUTES }],
  });
  assert.ok('/wp/v2/users' in out.results['0'].value);
});

test('with no allowlist defined the login form is open, which is the default', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '198.51.100.7' } },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.deepEqual(out.events.dies, []);
});

test('an address inside the allowlist is admitted', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '203.0.113.42' } },
    constants: { ALLOWED_LOGIN_IPS: ['203.0.113.0/24'] },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.deepEqual(out.events.dies, []);
});

test('an address outside it is refused with 403', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '198.51.100.7' } },
    constants: { ALLOWED_LOGIN_IPS: ['203.0.113.0/24'] },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.equal(out.events.dies.length, 1);
  assert.equal(out.events.dies[0].status, 403);
});

/**
 * The lockout version 1 built in. An administrator on a dual-stack connection
 * arrives over IPv6, matches nothing, and is refused the login form with their
 * IPv4 address sitting in the list.
 */
test('an allowlisted IPv6 range admits an IPv6 client', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '2001:db8:1234:5678::1' } },
    constants: { ALLOWED_LOGIN_IPS: ['203.0.113.0/24', '2001:db8:1234::/48'] },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.deepEqual(out.events.dies, [], 'an IPv6 client was locked out of an allowlisted range');
});

test('an unreadable address fails open rather than locking everyone out', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: 'not-an-address' } },
    constants: { ALLOWED_LOGIN_IPS: ['203.0.113.0/24'] },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.deepEqual(out.events.dies, []);
});

test('a forged forwarding header is ignored unless the site opted in', () => {
  const forged = {
    REMOTE_ADDR: '198.51.100.7',
    HTTP_X_FORWARDED_FOR: '203.0.113.42',
  };

  const untrusted = probe({
    load: [PLUGIN],
    state: { server: forged },
    constants: { ALLOWED_LOGIN_IPS: ['203.0.113.0/24'] },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.equal(untrusted.events.dies.length, 1, 'an allowlist built on a forgeable header is decorative');

  const trusted = probe({
    load: [PLUGIN],
    state: { server: forged },
    constants: { ALLOWED_LOGIN_IPS: ['203.0.113.0/24'], WPSH_TRUST_PROXY: true },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.deepEqual(trusted.events.dies, []);
});

test('an empty allowlist is treated as no allowlist, not as deny everyone', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '198.51.100.7' } },
    constants: { ALLOWED_LOGIN_IPS: [] },
    ops: [{ op: 'do_action', tag: 'login_init' }],
  });
  assert.deepEqual(out.events.dies, []);
});
