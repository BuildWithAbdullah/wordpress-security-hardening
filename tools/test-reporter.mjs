/**
 * A test reporter whose only job is to count tests the same way on every
 * version of Node this repository supports.
 *
 * Parsing the default reporter does not work. The same suite printed
 * `# tests 264` on Node 20 and 22 and `info tests 264` on Node 24, so a
 * verifier that matched the first form reported "unknown failing" on a run
 * where every test passed. That is not hypothetical: it shipped in another
 * repository on this account and silently dropped assertions on any current
 * runtime.
 *
 * The structured event stream is version dependent too. node:test's run() API
 * forwards one test:pass per whole file on some versions, and details.type is
 * `undefined` rather than `'test'` on others. What is present on every version
 * is the per test event in a custom reporter, so this is a custom reporter, and
 * it selects on `details.type !== 'suite'` rather than on equality with
 * `'test'`.
 *
 * It prints one line and nothing else, so the caller has nothing to parse
 * loosely.
 *
 * Note that a file which fails to load counts as one test here, because that is
 * what the runner reports. It is safe, because the failure count is then
 * non-zero and CI is red, but it is the reason tools/verify.mjs refuses to
 * quote a count from a run that was not green.
 */

export default async function* reporter(source) {
	let pass = 0;
	let fail = 0;

	for await (const event of source) {
		if (event.type === 'test:pass' && event.data?.details?.type !== 'suite') pass++;
		if (event.type === 'test:fail' && event.data?.details?.type !== 'suite') fail++;
	}

	yield `WPSH_COUNT pass=${pass} fail=${fail}\n`;
}
