import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probe, applyFilter } from '../tools/php.mjs';

const PLUGIN = 'mu-plugins/01-disable-xmlrpc.php';

const METHODS = {
  'pingback.ping': 'cb',
  'pingback.extensions.getPingbacks': 'cb',
  'system.multicall': 'cb',
  'system.listMethods': 'cb',
  'system.getCapabilities': 'cb',
  'wp.getPosts': 'cb',
  'demo.sayHello': 'cb',
};

test('XML-RPC authentication is refused', () => {
  const { value } = applyFilter(PLUGIN, 'xmlrpc_enabled', true);
  assert.equal(value, false);
});

/**
 * Disabling authentication is not enough on its own. The pingback methods do
 * not authenticate, so they stay reachable through a filter that only answers
 * the enabled question.
 */
test('the methods that do not authenticate are removed by name', () => {
  const { value } = applyFilter(PLUGIN, 'xmlrpc_methods', METHODS);

  for (const gone of [
    'pingback.ping',
    'pingback.extensions.getPingbacks',
    'system.multicall',
    'system.listMethods',
    'system.getCapabilities',
  ]) {
    assert.ok(!(gone in value), `${gone} is still registered`);
  }
});

test('read-only methods are left in place, so harmless integrations keep working', () => {
  const { value } = applyFilter(PLUGIN, 'xmlrpc_methods', METHODS);
  assert.ok('wp.getPosts' in value);
  assert.ok('demo.sayHello' in value);
});

test('multicall is refused at execution as well as removed from the list', () => {
  // A host or a plugin that re-registers the method should not get it back.
  for (const method of ['pingback.ping', 'system.multicall']) {
    const out = probe({
      load: [PLUGIN],
      ops: [{ op: 'do_action', tag: 'xmlrpc_call', args: [method] }],
    });
    assert.equal(out.events.dies.length, 1, `${method} was allowed to execute`);
    assert.equal(out.events.dies[0].status, 403);
  }
});

test('a legitimate method is not killed at execution', () => {
  const out = probe({
    load: [PLUGIN],
    ops: [{ op: 'do_action', tag: 'xmlrpc_call', args: ['wp.getPosts'] }],
  });
  assert.deepEqual(out.events.dies, []);
});

test('the endpoint is no longer advertised in the response headers', () => {
  const { value } = applyFilter(PLUGIN, 'wp_headers', {
    'X-Pingback': 'https://example.test/xmlrpc.php',
    'X-Custom': 'kept',
  });
  assert.ok(!('X-Pingback' in value));
  assert.equal(value['X-Custom'], 'kept', 'only the one header should go');
});

test('the discovery link is removed from the head', () => {
  const out = probe({ load: [PLUGIN], ops: [{ op: 'registered', tags: ['wp_head'] }] });
  assert.ok((out.removed.wp_head ?? []).includes('rsd_link'));
});

/**
 * Closing the inbound method does not stop WordPress making pingback requests
 * of its own when a post is published, to a URL taken from post content. That
 * is a separate feature and it is how a site keeps making requests somebody
 * else chose long after the endpoint was closed.
 */
test('outbound pingbacks are switched off as well as inbound', () => {
  const { value } = applyFilter(PLUGIN, 'pre_option_default_pingback_flag', '1');
  assert.equal(value, '0');
});

test('the whole file can be made inert from wp-config without deleting it', () => {
  const out = probe({
    load: [PLUGIN],
    constants: { WPSH_KEEP_XMLRPC: true },
    ops: [
      { op: 'apply_filters', tag: 'xmlrpc_enabled', value: true },
      { op: 'registered', tags: ['xmlrpc_methods', 'wp_headers', 'xmlrpc_call'] },
    ],
  });

  assert.equal(out.results['0'].value, true, 'the opt-out should leave XML-RPC alone');
  assert.deepEqual(out.results['1'].value, {
    xmlrpc_methods: 0,
    wp_headers: 0,
    xmlrpc_call: 0,
  });
});
