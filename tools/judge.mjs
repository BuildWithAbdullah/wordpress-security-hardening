/**
 * Node side of the header judge: runs the real shell script against a dump and
 * returns its findings.
 *
 * The suite deliberately does not reimplement the judging in JavaScript. A
 * second implementation agrees with the first until one of them is edited, and
 * then the tests pass while the thing that ships is wrong.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const JUDGE = join(ROOT, 'scripts', 'judge-headers.sh');

export { ROOT };

/**
 * @param {string} dumpPath
 * @param {{url?: string}} options
 * @returns {{status: number, findings: Array, stderr: string}}
 */
export function judgeFile(dumpPath, options = {}) {
  const args = [dumpPath];
  if (options.url) args.push('--url', options.url);
  args.push('--json');

  let stdout = '';
  let stderr = '';
  let status = 0;

  try {
    stdout = execFileSync('bash', [JUDGE, ...args], { encoding: 'utf8' });
  } catch (error) {
    status = typeof error.status === 'number' ? error.status : 1;
    stdout = error.stdout ?? '';
    stderr = error.stderr ?? '';
  }

  let findings = [];
  if (stdout.trim()) {
    try {
      findings = JSON.parse(stdout);
    } catch {
      throw new Error(`judge-headers.sh did not emit JSON. Output was:\n${stdout}\n${stderr}`);
    }
  }

  return { status, findings, stderr };
}

/** Judge a dump given as a string, via a temporary file. */
export function judge(dumpText, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'wpsh-'));
  const path = join(dir, 'response.headers');
  writeFileSync(path, dumpText, 'utf8');
  return judgeFile(path, options);
}

/** The finding ids a run produced, in order. */
export function ids(result) {
  return result.findings.map((f) => f.id);
}

/** A clean HTTPS response that produces no error findings. */
export function cleanResponse(overrides = {}) {
  const base = {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'SAMEORIGIN',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=(), camera=(), microphone=()',
    'strict-transport-security': 'max-age=31536000',
  };
  const merged = { ...base, ...overrides };
  const lines = ['HTTP/2 200', 'content-type: text/html; charset=UTF-8'];
  for (const [name, value] of Object.entries(merged)) {
    if (value === null) continue;
    lines.push(`${name}: ${value}`);
  }
  return lines.join('\n') + '\n\n';
}
