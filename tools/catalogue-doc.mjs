/**
 * Generate docs/07-every-finding.md from the catalogue.
 *
 *   node tools/catalogue-doc.mjs            write the document
 *   node tools/catalogue-doc.mjs --check    fail if it is out of date
 *
 * The document is generated because a hand-written list of a checker's
 * findings drifts from the checker, and the drift is invisible: the document
 * still reads correctly, it is just describing a tool that no longer exists.
 * CI runs the check, so a new finding cannot land without its documentation.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FINDINGS, FAMILIES } from './catalogue.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TARGET = join(ROOT, 'docs', '07-every-finding.md');

const LEVELS = {
  error: 'Fails the run. Exit code 1.',
  warn: 'Reported, does not fail the run.',
  note: 'Reported for the record.',
};

function render() {
  const lines = [];

  lines.push('# Every finding');
  lines.push('');
  lines.push('Generated from `tools/catalogue.mjs` by `npm run docs`. Do not edit by hand.');
  lines.push('');
  lines.push('This is the complete list of what `scripts/judge-headers.sh` can report, and');
  lines.push('`test/catalogue.test.mjs` drives every entry out of a real run of the real');
  lines.push('script. A finding that cannot be produced does not stay on the list, and a');
  lines.push('finding the script produces that is not on the list fails the suite.');
  lines.push('');
  lines.push('What the findings do **not** cover is in');
  lines.push('[06 What the checks do not see](06-what-the-checks-do-not-see.md). Read that');
  lines.push('before putting any of this in front of a client.');
  lines.push('');
  lines.push('## Levels');
  lines.push('');
  lines.push('| Level | Meaning |');
  lines.push('|---|---|');
  for (const [level, meaning] of Object.entries(LEVELS)) {
    lines.push(`| \`${level}\` | ${meaning} |`);
  }
  lines.push('');
  lines.push('Only an error changes the exit code. A post-deploy check that fails the build');
  lines.push('over a version string in a `Server` header is a check somebody switches off.');
  lines.push('');
  lines.push(`## Findings (${FINDINGS.length})`);
  lines.push('');

  for (const finding of FINDINGS) {
    lines.push(`### \`${finding.id}\``);
    lines.push('');
    lines.push(`Level: \`${finding.level}\`.`);
    lines.push('');
    lines.push(finding.what);
    lines.push('');
  }

  lines.push(`## Open families (${FAMILIES.length})`);
  lines.push('');
  lines.push('These carry a value read from the response, so the set of concrete messages is');
  lines.push('not finite. The suite requires each family to be produced rather than listing');
  lines.push('every message it can produce.');
  lines.push('');

  for (const family of FAMILIES) {
    lines.push(`### \`${family.id}\``);
    lines.push('');
    lines.push(`Level: \`${family.level}\`. Carries ${family.carries}.`);
    lines.push('');
    lines.push(family.what);
    lines.push('');
  }

  return lines.join('\n');
}

const generated = render();

if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(TARGET, 'utf8');
  } catch {
    console.error('docs/07-every-finding.md does not exist. Run npm run docs.');
    process.exit(1);
  }
  if (current !== generated) {
    console.error('docs/07-every-finding.md is out of date. Run npm run docs and commit it.');
    process.exit(1);
  }
  console.log('docs/07-every-finding.md is current.');
} else {
  writeFileSync(TARGET, generated, 'utf8');
  console.log(`Wrote docs/07-every-finding.md (${FINDINGS.length + FAMILIES.length} entries).`);
}
