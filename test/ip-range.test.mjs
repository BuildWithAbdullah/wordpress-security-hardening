import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probe } from '../tools/php.mjs';

const PLUGIN = 'mu-plugins/02-harden-login.php';

/**
 * The address matcher decides who is shown a login form, so it is worth a
 * table rather than a couple of happy cases. Every row is one call into the
 * real function in the real plugin.
 */
const CASES = [
  // [ address, range, expected, why ]
  ['203.0.113.10', '203.0.113.10', true, 'exact IPv4 match'],
  ['203.0.113.11', '203.0.113.10', false, 'exact IPv4 mismatch'],
  ['203.0.113.42', '203.0.113.0/24', true, 'inside a /24'],
  ['203.0.114.42', '203.0.113.0/24', false, 'the next /24 along'],
  ['198.51.100.1', '198.51.100.0/32', false, 'a /32 is a single address'],
  ['198.51.100.0', '198.51.100.0/32', true, 'and it matches that address'],
  ['10.0.0.1', '10.0.0.0/8', true, 'a byte-aligned prefix'],
  ['11.0.0.1', '10.0.0.0/8', false, 'just outside it'],

  // Prefixes that do not land on a byte boundary are where integer
  // implementations tend to go wrong.
  ['192.168.3.9', '192.168.0.0/22', true, 'inside a /22, which splits a byte'],
  ['192.168.4.9', '192.168.0.0/22', false, 'the first address past a /22'],
  ['203.0.113.130', '203.0.113.128/25', true, 'upper half of a /25'],
  ['203.0.113.126', '203.0.113.128/25', false, 'lower half is not'],

  // ip2long returns a negative value on a 32-bit build for anything above
  // 127.255.255.255, which is where sign errors show up.
  ['200.0.0.1', '200.0.0.0/8', true, 'high IPv4 space, where signed arithmetic goes wrong'],
  ['255.255.255.255', '255.255.255.0/24', true, 'the top of the IPv4 space'],

  // IPv6. Version 1 answered false for every one of these.
  ['2001:db8::1', '2001:db8::1', true, 'exact IPv6 match'],
  ['2001:db8::2', '2001:db8::1', false, 'exact IPv6 mismatch'],
  ['2001:db8:1234:5678::1', '2001:db8:1234::/48', true, 'inside an IPv6 /48'],
  ['2001:db8:1235:5678::1', '2001:db8:1234::/48', false, 'the next /48 along'],
  ['2001:db8::1', '2001:db8::/32', true, 'a wide IPv6 prefix'],
  ['2001:db9::1', '2001:db8::/32', false, 'outside it'],
  ['2001:db8:0:0:0:0:0:1', '2001:db8::1', true, 'the expanded form of the same address'],
  ['::1', '::1/128', true, 'IPv6 loopback'],

  // Families never match each other. The alternative is treating a mismatch
  // as a match, in the function that gates the login form.
  ['203.0.113.10', '2001:db8::/32', false, 'IPv4 address against an IPv6 range'],
  ['2001:db8::1', '203.0.113.0/24', false, 'IPv6 address against an IPv4 range'],
  ['::ffff:203.0.113.10', '203.0.113.0/24', false, 'an IPv4 mapped address is not an IPv4 address'],

  // Malformed input is refused rather than guessed at.
  ['not-an-address', '203.0.113.0/24', false, 'unparseable address'],
  ['203.0.113.10', 'not-a-range', false, 'unparseable range'],
  ['203.0.113.10', '203.0.113.0/', false, 'empty prefix length'],
  ['203.0.113.10', '203.0.113.0/abc', false, 'non-numeric prefix length'],
  ['203.0.113.10', '203.0.113.0/33', false, 'prefix length past the IPv4 maximum'],
  ['2001:db8::1', '2001:db8::/129', false, 'prefix length past the IPv6 maximum'],
  ['203.0.113.10', '', false, 'empty range'],
  ['', '203.0.113.0/24', false, 'empty address'],
  ['  203.0.113.42  ', '  203.0.113.0/24  ', true, 'surrounding whitespace is tolerated'],
];

test('every address and range pair matches as documented', () => {
  // One PHP process for the whole table rather than one per row: these are
  // pure calls with no constants involved, so nothing couples them.
  const out = probe({
    load: [PLUGIN],
    ops: CASES.map(([ip, range]) => ({ op: 'call', fn: 'wpsh_ip_in_range', args: [ip, range] })),
  });

  const wrong = [];
  CASES.forEach(([ip, range, expected, why], index) => {
    const actual = out.results[String(index)].value;
    if (actual !== expected) {
      wrong.push(`${why}: ${ip} in ${range} gave ${actual}, expected ${expected}`);
    }
  });

  assert.deepEqual(wrong, [], wrong.join('\n'));
});

test('a /0 range is not a silent allow-everything', () => {
  // Worth pinning down rather than leaving to whichever way the arithmetic
  // happens to fall. A prefix of zero bits does mean every address in that
  // family, and that is a deliberate answer, not an accident of masking.
  const out = probe({
    load: [PLUGIN],
    ops: [
      { op: 'call', fn: 'wpsh_ip_in_range', args: ['203.0.113.10', '0.0.0.0/0'] },
      { op: 'call', fn: 'wpsh_ip_in_range', args: ['2001:db8::1', '0.0.0.0/0'] },
    ],
  });
  assert.equal(out.results['0'].value, true, 'every IPv4 address is inside 0.0.0.0/0');
  assert.equal(out.results['1'].value, false, 'but an IPv6 address is not, because the family differs');
});

test('the client address prefers the value the client cannot forge', () => {
  const out = probe({
    load: [PLUGIN],
    state: {
      server: { REMOTE_ADDR: '198.51.100.7', HTTP_X_FORWARDED_FOR: '203.0.113.42' },
    },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  assert.equal(out.results['0'].value, '198.51.100.7');
});

/**
 * Version 2 had a test here named "a trusted proxy chain yields the leftmost
 * address", and it passed. It was asserting the defect. The leftmost entry of
 * X-Forwarded-For is the one value in the chain the client always controls, so
 * a test that required it to be returned was a test requiring the allowlist to
 * be forgeable, and it is the reason the bug survived a rewrite of the file it
 * lived in.
 *
 * The replacements below count from the other end, and the first of them is the
 * attack rather than the happy path, deliberately.
 */
test('a forged leftmost entry is not what the lookup returns', () => {
  const out = probe({
    load: [PLUGIN],
    state: {
      server: {
        // One proxy at 10.0.0.1. The attacker is at 203.0.113.99 and has sent
        // an X-Forwarded-For claiming to be the allowlisted address, which the
        // proxy appended to rather than replaced.
        REMOTE_ADDR: '10.0.0.1',
        HTTP_X_FORWARDED_FOR: '203.0.113.42, 203.0.113.99',
      },
    },
    constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  assert.equal(out.results['0'].value, '203.0.113.99');
});

test('the real client behind a declared proxy is still found', () => {
  const out = probe({
    load: [PLUGIN],
    state: {
      server: { REMOTE_ADDR: '10.0.0.1', HTTP_X_FORWARDED_FOR: '203.0.113.42' },
    },
    constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  assert.equal(out.results['0'].value, '203.0.113.42');
});

test('two declared proxies read two entries in from the end', () => {
  const out = probe({
    load: [PLUGIN],
    state: {
      server: {
        REMOTE_ADDR: '10.0.0.1',
        HTTP_X_FORWARDED_FOR: '198.51.100.9, 203.0.113.42, 10.0.0.5',
      },
    },
    constants: { WPSH_TRUSTED_PROXY_HOPS: 2 },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  assert.equal(out.results['0'].value, '203.0.113.42');
});

test('WPSH_TRUST_PROXY from version 2 reads as one hop, and is no longer forgeable', () => {
  const out = probe({
    load: [PLUGIN],
    state: {
      server: {
        REMOTE_ADDR: '10.0.0.1',
        HTTP_X_FORWARDED_FOR: '203.0.113.42, 203.0.113.99',
      },
    },
    constants: { WPSH_TRUST_PROXY: true },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  // An upgrade keeps working without an edit to wp-config.php, and the bypass
  // closes. Reading the old constant as nothing would have silently disabled
  // the allowlist on every site that had it.
  assert.equal(out.results['0'].value, '203.0.113.99');
});

test('a chain shorter than the declared hops refuses to answer', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '10.0.0.1', HTTP_X_FORWARDED_FOR: '203.0.113.42' } },
    constants: { WPSH_TRUSTED_PROXY_HOPS: 3 },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  // Taking the leftmost entry here is exactly the defect, so it declines. The
  // caller treats null as "cannot establish" and locks nobody out, which makes
  // a wrong hop count loud rather than quietly forgeable.
  assert.equal(out.results['0'].value, null);
});

test('a direct request that skipped the proxy uses the peer address', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '203.0.113.42' } },
    constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  // No forwarded chain means nothing to count into, and REMOTE_ADDR is both the
  // visitor and unforgeable.
  assert.equal(out.results['0'].value, '203.0.113.42');
});

test('a junk forwarding header is refused rather than guessed around', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '10.0.0.1', HTTP_X_FORWARDED_FOR: 'nonsense' } },
    constants: { WPSH_TRUSTED_PROXY_HOPS: 1 },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  // The chain is one entry plus the peer, so one hop in from the end is the
  // junk entry, and junk does not validate. Falling back to the peer would be
  // reading a different position than the site declared, which is the kind of
  // helpfulness that put the original bug there.
  assert.equal(out.results['0'].value, null);
});

test('no forwarding and no proxies declared uses the peer address', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '203.0.113.42', HTTP_X_FORWARDED_FOR: '198.51.100.9' } },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  // With no proxy declared the forwarding header is ignored entirely, which is
  // the default and the safe one.
  assert.equal(out.results['0'].value, '203.0.113.42');
});

test('no usable address at all is reported as none, not as a string', () => {
  const out = probe({
    load: [PLUGIN],
    state: { server: { REMOTE_ADDR: '' } },
    ops: [{ op: 'call', fn: 'wpsh_client_ip', args: [] }],
  });
  assert.equal(out.results['0'].value, null);
});
