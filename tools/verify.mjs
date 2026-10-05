/**
 * Assertions about the repository rather than about the code.
 *
 * A test suite proves the code behaves. It cannot notice that the README
 * documents a header the code stopped sending, that a new test file was never
 * added to the test script, or that a corrected matcher quietly grew back the
 * function it was written to replace. Those are the ways a repository rots
 * while staying green, so they are checked here and in CI.
 *
 *   node tools/verify.mjs
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FINDINGS, FAMILIES, ALL_IDS } from './catalogue.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

let checked = 0;
const failures = [];

function assert(condition, message) {
  checked += 1;
  if (!condition) failures.push(message);
}

function read(relative) {
  return readFileSync(join(ROOT, relative), 'utf8');
}

/**
 * Source with its comments removed.
 *
 * The checks below ask what the code does, and a comment explaining why a
 * construct was removed necessarily names it. Scanning raw source makes a
 * well-documented correction indistinguishable from a regression, which is the
 * wrong incentive: it rewards deleting the explanation.
 */
function phpCode(relative) {
  return read(relative)
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^[ \t]*\/\/.*$/gm, ' ')
    .replace(/^[ \t]*#.*$/gm, ' ');
}

function shellCode(relative) {
  return read(relative)
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

/**
 * Every file in the working tree, so a new directory cannot slip past the text
 * checks.
 *
 * Deliberately a walk rather than `git ls-files`. The index does not know about
 * a file that has just been written and still lists one that has just been
 * removed, so a git-based list checks the wrong set at exactly the moment the
 * checks matter.
 */
const SKIP = new Set(['.git', 'node_modules', '.idea', '.vscode']);

function walk(relative = '') {
  const here = join(ROOT, relative);
  const out = [];
  for (const entry of readdirSync(here, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...walk(child));
    } else if (entry.isFile()) {
      out.push(child);
    }
  }
  return out;
}

function tracked() {
  return walk();
}

const TEXT = new Set(['.md', '.php', '.sh', '.mjs', '.js', '.json', '.yml', '.yaml', '.headers', '']);

function textFiles() {
  return tracked().filter((f) => TEXT.has(extname(f)) && f !== 'LICENSE');
}

// ---------------------------------------------------------------------------
// House rules
//
// The forbidden characters are assembled from their code points at runtime. An
// earlier repository in this set failed its own check because the needles were
// written out literally in the file doing the checking, and there is no way to
// refer to one of these characters in a file this rule covers.
// ---------------------------------------------------------------------------

const FORBIDDEN_DASHES = [String.fromCharCode(0x2014), String.fromCharCode(0x2013)];

for (const file of textFiles()) {
  const body = read(file);
  for (const dash of FORBIDDEN_DASHES) {
    assert(!body.includes(dash), `${file} contains a long dash`);
  }
}

/**
 * Every needle below is assembled from parts at runtime for the same reason
 * the dashes are: this file is one of the files being scanned, so a needle
 * written out literally makes the check fail on its own source. There is no way
 * to refer to a forbidden string in a file the rule covers.
 */
const INSTITUTION = ['uni', 'vers', 'ity'].join('');
const ALLOWED_INSTITUTION_HOST = `deque${INSTITUTION}.com`;
const WORK_MARKERS = [['TO', 'DO'].join(''), ['FIX', 'ME'].join('')];

for (const file of textFiles()) {
  const body = read(file).toLowerCase();
  const hits = [...body.matchAll(new RegExp(INSTITUTION, 'g'))].filter((match) => {
    const around = body.slice(Math.max(0, match.index - 40), match.index + 40);
    return !around.includes(ALLOWED_INSTITUTION_HOST);
  });
  assert(hits.length === 0, `${file} mentions an institution`);
}

for (const file of textFiles()) {
  const body = read(file);
  for (const marker of WORK_MARKERS) {
    assert(!new RegExp(`\\b${marker}\\b`).test(body), `${file} still has unfinished work marked in it`);
  }
}

assert(/^MIT License/.test(read('LICENSE')), 'LICENSE is not the MIT text');
assert(read('README.md').includes('## Verifying'), 'README has no Verifying section');
assert(read('README.md').includes('## Limits'), 'README has no Limits section');

// ---------------------------------------------------------------------------
// The mu-plugins are the deliverable. They have to be installable on their own.
// ---------------------------------------------------------------------------

const PLUGINS = readdirSync(join(ROOT, 'mu-plugins')).filter((f) => f.endsWith('.php')).sort();
assert(PLUGINS.length === 3, `expected three mu-plugins, found ${PLUGINS.length}`);

for (const name of PLUGINS) {
  const body = read(`mu-plugins/${name}`);
  assert(/Plugin Name:/.test(body), `mu-plugins/${name} has no plugin header`);
  assert(/License: *MIT/.test(body), `mu-plugins/${name} does not state the licence`);
  assert(
    body.includes("if ( ! defined( 'ABSPATH' ) ) {"),
    `mu-plugins/${name} can be requested directly without the ABSPATH guard`,
  );
  assert(
    !/\brequire\b|\binclude\b/.test(body.replace(/^\s*\*.*$/gm, '')),
    `mu-plugins/${name} pulls in another file, so it is not drop-in`,
  );
  // The test harness must never become a runtime dependency of the plugins.
  assert(!body.includes('lib/'), `mu-plugins/${name} references the test harness`);
}

/**
 * Integer address arithmetic is the defect the version 2 matcher exists to
 * remove. If it comes back, it comes back silently, and only an IPv6 client
 * finds out.
 */
assert(
  !phpCode('mu-plugins/02-harden-login.php').includes('ip2long'),
  'the login plugin is matching addresses as integers again',
);
assert(
  phpCode('mu-plugins/02-harden-login.php').includes('inet_pton'),
  'the login plugin should match addresses on packed bytes',
);

/** Functions that get pasted into a theme need a redeclare guard. */
for (const fn of ['wpsh_send_headers', 'wpsh_client_ip', 'wpsh_ip_in_range', 'wpsh_login_message']) {
  const body = PLUGINS.map((n) => read(`mu-plugins/${n}`)).join('\n');
  if (!body.includes(`function ${fn}(`)) continue;
  assert(
    body.includes(`if ( ! function_exists( '${fn}' ) ) {`),
    `${fn} is declared without a function_exists guard, which is a fatal error if the file is pasted into a theme`,
  );
}

for (const name of PLUGINS.concat(readdirSync(join(ROOT, 'examples')).filter((f) => f.endsWith('.php')))) {
  const path = PLUGINS.includes(name) ? `mu-plugins/${name}` : `examples/${name}`;
  try {
    execFileSync('php', ['-l', join(ROOT, path)], { stdio: 'pipe' });
    assert(true, `${path} parses`);
  } catch {
    assert(false, `${path} does not parse`);
  }
}

// ---------------------------------------------------------------------------
// Judgement is separate from collection, and the split has to stay real.
// ---------------------------------------------------------------------------

const NETWORK = /\b(curl|wget|nc|ncat|socat|telnet|ssh|lynx|wsget)\b/;
assert(
  !NETWORK.test(shellCode('scripts/judge-headers.sh')),
  'judge-headers.sh invokes a network tool, so it is no longer a pure judge',
);
assert(
  NETWORK.test(shellCode('scripts/check-headers.sh')),
  'check-headers.sh makes no request, so the split has become vestigial',
);
assert(
  read('scripts/check-headers.sh').includes('judge-headers.sh'),
  'check-headers.sh does not hand off to the judge',
);
assert(
  shellCode('scripts/check-headers.sh').includes('-X GET'),
  'the collector is not making a GET request, and a HEAD response is not the one a visitor receives',
);
assert(
  !/curl +-[A-Za-z]*I/.test(shellCode('scripts/check-headers.sh')),
  'the collector is making a HEAD request again',
);

/**
 * The executable bit is deliberately not asserted.
 *
 * It does not survive every route a copy of this repository can arrive by: a
 * source zip and GitHub's web upload both produce mode 644. Requiring the bit
 * would make this check pass on one clone and fail on another, which is worse
 * than not checking. What is asserted instead is that nothing depends on it.
 */
for (const name of readdirSync(join(ROOT, 'scripts'))) {
  const path = join(ROOT, 'scripts', name);
  assert(read(`scripts/${name}`).startsWith('#!/usr/bin/env bash'), `scripts/${name} has no bash shebang`);
  try {
    execFileSync('bash', ['-n', path], { stdio: 'pipe' });
    assert(true, `scripts/${name} parses`);
  } catch {
    assert(false, `scripts/${name} does not parse`);
  }
}

const collector = shellCode('scripts/check-headers.sh');
assert(
  /exec bash "\$JUDGE"/.test(collector),
  'check-headers.sh runs the judge directly, so it breaks on any copy that arrived without file modes',
);
assert(
  !/\[ ! -x /.test(collector),
  'check-headers.sh tests the executable bit, which not every copy of this repository has',
);

/**
 * The handoff is an exec, which replaces the shell, so an EXIT trap never
 * runs. Anything that has to happen on the way out has to happen before it.
 * --save was silently doing nothing for exactly this reason.
 */
const execIndex = collector.indexOf('exec bash');
const saveIndex = collector.indexOf('cp "$DUMP" "$SAVE"');
assert(saveIndex !== -1, 'check-headers.sh no longer honours --save');
assert(
  saveIndex < execIndex,
  'the --save copy happens after the exec, where it can never run',
);
assert(
  !/trap [^\n]*SAVE/.test(collector),
  'the EXIT trap touches SAVE again, and an exec means that trap never fires',
);

// ---------------------------------------------------------------------------
// The test script names every test file.
//
// node --test did not accept glob patterns before Node 21, so a globbed script
// silently runs nothing on an older runtime while reporting success. Another
// repository in this set shipped that bug for two weeks.
// ---------------------------------------------------------------------------

const pkg = JSON.parse(read('package.json'));
const testScript = pkg.scripts.test;
assert(!testScript.includes('*'), 'the test script uses a glob, which runs nothing on Node 20');

for (const file of readdirSync(join(ROOT, 'test'))) {
  assert(testScript.includes(`test/${file}`), `test/${file} is not named in the test script`);
}
const namedCount = testScript.split('test/').length - 1;
assert(
  namedCount === readdirSync(join(ROOT, 'test')).length,
  'the test script names a file that does not exist',
);

assert(pkg.license === 'MIT', 'package.json does not declare MIT');
assert(!pkg.dependencies, 'a dependency appeared, and this repository claims to have none');
assert(!pkg.devDependencies, 'a development dependency appeared');
assert(/^>=20/.test(pkg.engines.node), 'the declared Node floor moved without the CI matrix moving');

// ---------------------------------------------------------------------------
// Examples come in pairs, and the catalogue is documented.
// ---------------------------------------------------------------------------

const exampleFiles = readdirSync(join(ROOT, 'examples'));
const stems = new Set(exampleFiles.map((f) => f.replace(/\.(fail|pass)\.(headers|php)$/, '')));

for (const stem of stems) {
  const ext = exampleFiles.includes(`${stem}.fail.headers`) ? 'headers' : 'php';
  assert(exampleFiles.includes(`${stem}.fail.${ext}`), `${stem} has no failing side`);
  assert(exampleFiles.includes(`${stem}.pass.${ext}`), `${stem} has no corrected side`);
}

assert(exampleFiles.length === stems.size * 2, 'an example file does not belong to a pair');

for (const name of exampleFiles.filter((f) => f.endsWith('.php'))) {
  const body = read(`examples/${name}`);
  const side = name.includes('.fail.') ? 'Failing' : 'Corrected';
  assert(
    body.includes(`${side} example:`),
    `examples/${name} does not open by saying which side of the pair it is`,
  );
}

for (const name of exampleFiles.filter((f) => f.endsWith('.fail.php'))) {
  assert(
    read(`examples/${name}`).includes('.pass.php'),
    `examples/${name} does not point at its corrected version`,
  );
}

const docs = readdirSync(join(ROOT, 'docs'))
  .map((f) => read(`docs/${f}`))
  .join('\n');

for (const id of ALL_IDS) {
  assert(docs.includes(id), `finding ${id} is not documented anywhere in docs/`);
}

assert(
  new Set([...FINDINGS, ...FAMILIES].map((f) => f.id)).size === ALL_IDS.length,
  'the catalogue has a duplicate id',
);

// ---------------------------------------------------------------------------
// Documentation that quotes the code has to quote the current code.
//
// The old README listed three Permissions-Policy directives while the plugin
// sent six, and nothing noticed, because nothing was looking.
// ---------------------------------------------------------------------------

const headersPlugin = read('mu-plugins/00-security-headers.php');
const readme = read('README.md');

const policy = phpCode('mu-plugins/00-security-headers.php').match(/'(geolocation=\(\)[^']*)'/);
assert(policy !== null, 'could not find the Permissions-Policy default in the plugin');
if (policy) {
  assert(
    readme.includes(policy[1]),
    'the README does not quote the Permissions-Policy value the plugin actually sends',
  );
  for (const directive of policy[1].split(',').map((d) => d.trim().split('=')[0])) {
    assert(docs.includes(directive), `the ${directive} directive is sent but not documented`);
  }
}

const maxAge = phpCode('mu-plugins/00-security-headers.php').match(/WPSH_HSTS_MAX_AGE[^:;]*: *(\d+)/);
assert(maxAge !== null, 'could not find the HSTS default in the plugin');
if (maxAge) {
  assert(readme.includes(maxAge[1]), `the README does not mention the HSTS default of ${maxAge[1]}`);
}

assert(
  !phpCode('mu-plugins/00-security-headers.php').includes('interest-cohort'),
  'the dead interest-cohort directive is back in the header set',
);

/**
 * Counts in the README are the first thing a reader checks, so they have to
 * hold.
 *
 * The reporter is named rather than left to the default, and that is not
 * decoration. Node 20 and 22 print TAP when output is piped; Node 24 prints the
 * spec reporter regardless, so the summary line changes from "# pass 82" to one
 * with a leading information glyph. Parsing whatever the runner happened to
 * print meant this check passed on two Node versions and failed on the third,
 * for no reason connected to the repository. Asking for TAP pins the format,
 * and the fallback below reads the other shape anyway.
 */
const testOutput = execFileSync(
  'node',
  ['--test', '--test-reporter=tap', ...readdirSync(join(ROOT, 'test')).map((f) => `test/${f}`)],
  {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  },
);
const passCount = Number(testOutput.match(/^[^\d\n]*pass (\d+)$/m)?.[1] ?? -1);
assert(passCount > 0, 'could not read the test count from the runner');

const failCount = Number(testOutput.match(/^[^\d\n]*fail (\d+)$/m)?.[1] ?? -1);
assert(failCount === 0, `the suite reports ${failCount} failing tests`);
assert(
  readme.includes(`${passCount} tests`),
  `the README does not say ${passCount} tests, which is what the suite runs`,
);

const pairCount = stems.size;
assert(
  readme.includes(`${pairCount} failing and corrected`),
  `the README does not say ${pairCount} failing and corrected pairs`,
);

/** Every document the README links to has to exist. */
for (const match of readme.matchAll(/\]\((?!https?:)([^)#]+)\)/g)) {
  const target = match[1];
  try {
    statSync(join(ROOT, target));
    assert(true, `${target} exists`);
  } catch {
    assert(false, `the README links to ${target}, which is not in the repository`);
  }
}

// ---------------------------------------------------------------------------
// The harness is a harness, and says so.
// ---------------------------------------------------------------------------

for (const name of readdirSync(join(ROOT, 'lib'))) {
  const body = read(`lib/${name}`);
  assert(
    /test harness/.test(body),
    `lib/${name} does not say it is a test harness, and someone will install it`,
  );
}

assert(
  read('lib/wp-shim.php').includes('not WordPress'),
  'the shim should be explicit that it is not WordPress',
);

const workflow = read('.github/workflows/verify.yml');
assert(workflow.includes('npm test'), 'CI does not run the test suite');
assert(workflow.includes('npm run verify'), 'CI does not run this verifier');
assert(workflow.includes('npm run check'), 'CI does not lint the PHP and shell sources');
for (const version of ['20', '22', '24']) {
  assert(workflow.includes(`'${version}'`), `CI does not cover Node ${version}`);
}

// ---------------------------------------------------------------------------

if (failures.length > 0) {
  console.error(`${failures.length} of ${checked} assertions failed:\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}

console.log(`${checked} repository assertions passed.`);
