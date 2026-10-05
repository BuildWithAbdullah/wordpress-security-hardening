/**
 * Node side of the plugin probe: loads a real mu-plugin under the hook shim,
 * fires real hooks, and returns what happened.
 *
 * Each call is a separate PHP process. Constants and function definitions
 * cannot be unwound inside one, and a plugin that reads a constant at
 * registration time cannot be reconfigured afterwards, so sharing a process
 * between cases would quietly couple them.
 */

import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const PROBE = join(ROOT, 'lib', 'probe.php');

export { ROOT };

/**
 * @param {object} request See lib/probe.php for the shape.
 * @returns {{results: object, events: object, removed: object}}
 */
export function probe(request) {
  let stdout;
  try {
    stdout = execFileSync('php', [PROBE], {
      input: JSON.stringify(request),
      encoding: 'utf8',
    });
  } catch (error) {
    throw new Error(
      `probe.php failed (status ${error.status}).\nstderr: ${error.stderr ?? ''}\nstdout: ${error.stdout ?? ''}`,
    );
  }

  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`probe.php did not emit JSON:\n${stdout}`);
  }
}

/** Apply one filter to one value and return the result. */
export function applyFilter(load, tag, value, extra = {}) {
  const out = probe({
    load: Array.isArray(load) ? load : [load],
    ops: [{ op: 'apply_filters', tag, value }],
    ...extra,
  });
  return out.results['0'];
}

/** Fire one action and return the recorded events. */
export function fireAction(load, tag, extra = {}) {
  const out = probe({
    load: Array.isArray(load) ? load : [load],
    ops: [{ op: 'do_action', tag }],
    ...extra,
  });
  return { result: out.results['0'], events: out.events, removed: out.removed };
}

/** Call one function in a loaded file. */
export function callFn(load, fn, args, extra = {}) {
  const out = probe({
    load: Array.isArray(load) ? load : [load],
    ops: [{ op: 'call', fn, args }],
    ...extra,
  });
  return out.results['0'];
}
