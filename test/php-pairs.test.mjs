import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { probe, ROOT } from '../tools/php.mjs';

const EXAMPLES = join(ROOT, 'examples');

/**
 * Each audit is a question put to a loaded file. It returns true when the file
 * behaves correctly.
 *
 * The contract every audit has to satisfy, enforced below:
 *
 *   false on the failing example
 *   true  on the corrected example
 *   false when nothing is loaded at all
 *
 * The third is what stops an audit that is really asking nothing. An audit
 * that passes against an empty page has never been seen to catch anything, and
 * the only way to find that out is to try it.
 */
const AUDITS = {
  '11-login-errors-unconditional': {
    proves: 'a login notice that is not an authentication failure survives the filter',
    run(load) {
      const out = probe({
        load,
        error_codes: [],
        ops: [{ op: 'apply_filters', tag: 'login_errors', value: 'You are now logged out.' }],
      });
      return out.results['0'].value === 'You are now logged out.';
    },
    // With nothing loaded the filter is a no-op, so the message survives
    // trivially. The audit therefore also has to see the failure case, which
    // is what the pairing below checks, and the empty case is excluded here
    // with the reason written down rather than left as an oversight.
    emptyPasses: true,
    emptyReason:
      'no filter registered means no message is rewritten, so the correct outcome happens for the wrong reason. The failing example is what gives this audit its teeth.',
  },

  '12-author-redirect-permanent': {
    proves: 'the author archive block is reversible, which means a 302',
    run(load) {
      const out = probe({
        load,
        state: { logged_in: false, is_author: true },
        ops: [{ op: 'do_action', tag: 'template_redirect' }],
      });
      return out.events.redirects.length === 1 && out.events.redirects[0].status === 302;
    },
  },

  '13-ip-allowlist-ipv4-only': {
    proves: 'an IPv6 client inside an allowlisted IPv6 range is matched',
    run(load) {
      const out = probe({
        load,
        ops: [
          { op: 'call', fn: 'wpsh_ip_in_range', args: ['2001:db8:1234:5678::1', '2001:db8:1234::/48'] },
          { op: 'call', fn: 'wpsh_ip_in_range', args: ['203.0.113.42', '203.0.113.0/24'] },
        ],
      });
      // Both have to hold. A matcher that fixed IPv6 by breaking IPv4 is not
      // a correction.
      return out.results['0'].value === true && out.results['1'].value === true;
    },
  },

  '14-headers-frontend-only': {
    proves: 'the login page receives the headers, not only the front end',
    run(load) {
      const out = probe({
        load,
        state: { is_ssl: true },
        ops: [{ op: 'do_action', tag: 'login_init' }],
      });
      const sent = out.events.sent_headers.map((h) => h.name);
      return sent.includes('X-Frame-Options') && sent.includes('Strict-Transport-Security');
    },
  },
};

test('every PHP fixture on disk belongs to a declared pair', () => {
  const stems = new Set(
    readdirSync(EXAMPLES)
      .filter((name) => name.endsWith('.php'))
      .map((name) => name.replace(/\.(fail|pass)\.php$/, '')),
  );
  assert.deepEqual([...stems].sort(), Object.keys(AUDITS).sort());
});

test('each pair has both sides', () => {
  const files = new Set(readdirSync(EXAMPLES));
  for (const stem of Object.keys(AUDITS)) {
    assert.ok(files.has(`${stem}.fail.php`), `${stem} has no failing side`);
    assert.ok(files.has(`${stem}.pass.php`), `${stem} has no corrected side`);
  }
});

test('every audit fails on its failing example', () => {
  for (const [stem, audit] of Object.entries(AUDITS)) {
    const result = audit.run([`examples/${stem}.fail.php`]);
    assert.equal(result, false, `${stem}: the audit passed on the failing example, so it proves nothing`);
  }
});

test('every audit passes on its corrected example', () => {
  for (const [stem, audit] of Object.entries(AUDITS)) {
    const result = audit.run([`examples/${stem}.pass.php`]);
    assert.equal(result, true, `${stem}: ${audit.proves} did not hold on the corrected example`);
  }
});

test('every audit fails against an empty page, unless it says why it cannot', () => {
  for (const [stem, audit] of Object.entries(AUDITS)) {
    const result = audit.run([]);
    if (audit.emptyPasses) {
      assert.ok(audit.emptyReason && audit.emptyReason.length > 60, `${stem} needs its exemption explained`);
      continue;
    }
    assert.equal(result, false, `${stem}: the audit passes with nothing loaded, so it is asking nothing`);
  }
});

test('every audit passes against the shipped plugin it was drawn from', () => {
  // The pairs exist to explain the corrections in mu-plugins/. If an audit
  // passes on its corrected example and fails on the real plugin, the example
  // has drifted from the thing it documents.
  const AGAINST_PLUGIN = {
    '11-login-errors-unconditional': 'mu-plugins/02-harden-login.php',
    '12-author-redirect-permanent': 'mu-plugins/02-harden-login.php',
    '13-ip-allowlist-ipv4-only': 'mu-plugins/02-harden-login.php',
    '14-headers-frontend-only': 'mu-plugins/00-security-headers.php',
  };

  assert.deepEqual(Object.keys(AGAINST_PLUGIN).sort(), Object.keys(AUDITS).sort());

  for (const [stem, plugin] of Object.entries(AGAINST_PLUGIN)) {
    const result = AUDITS[stem].run([plugin]);
    assert.equal(result, true, `${stem}: ${AUDITS[stem].proves} does not hold in ${plugin}`);
  }
});

test('each audit states what it proves', () => {
  for (const [stem, audit] of Object.entries(AUDITS)) {
    assert.ok(audit.proves && audit.proves.length > 25, `${stem} does not say what it proves`);
  }
});
