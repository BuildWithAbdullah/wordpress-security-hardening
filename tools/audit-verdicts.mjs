/**
 * Run every audit over every file it has an expectation about, each in its own
 * process, and derive the expectations from the manifest.
 *
 *   node tools/audit-verdicts.mjs
 *
 * This is the no-binary half of tools/exit-codes.mjs. The deliverable the
 * audits are about is a set of must-use plugins, not a command, so there is no
 * exit code to check and no installed copy to run. What there is instead is a
 * contract per audit, and it can be derived the same way: the failing example
 * must fail, the corrected example must pass, the shipped plugin the pair was
 * drawn from must pass, and an empty page must fail unless the audit says in
 * writing why it cannot.
 *
 * Every verdict is a separate PHP process, which lib/probe.php arranges and
 * which is not a detail. Constants and function definitions cannot be unwound
 * inside one process, and a plugin that reads a constant at registration time
 * cannot be reconfigured afterwards, so sharing a process between cases would
 * quietly couple them. The failing example and the corrected example of a pair
 * both define wpsh_client_ip; loading them in one process would be a fatal
 * redeclare, and the only reason it is not is that they never meet.
 *
 * It exists beside the test file rather than inside it so that the contract has
 * two readers and one copy. test/php-pairs.test.mjs asserts the same
 * expectations through node:test, and both import tools/audits.mjs. Two lists
 * would have drifted by the second pair.
 */

import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { AUDITS, AUDIT_STEMS, expectationsFor } from './audits.mjs';

export function runAll() {
	const failures = [];
	let verdicts = 0;

	for (const stem of AUDIT_STEMS) {
		const audit = AUDITS[stem];

		if (!audit.proves || audit.proves.length < 25) {
			failures.push(`${stem} does not say what it proves`);
		}
		if (audit.emptyPasses && (!audit.emptyReason || audit.emptyReason.length < 60)) {
			failures.push(`${stem} claims it cannot fail against an empty page and does not explain why`);
		}

		for (const expectation of expectationsFor(stem)) {
			verdicts++;
			let got;
			try {
				got = audit.run(expectation.load);
			} catch (error) {
				failures.push(`${stem} / ${expectation.name}: the audit threw: ${error.message}`);
				continue;
			}
			if (got !== expectation.expect) {
				failures.push(
					`${stem} / ${expectation.name}: expected ${expectation.expect}, got ${got}. ` +
						`The audit proves that ${audit.proves}.`,
				);
			}
		}
	}

	return { verdicts, failures };
}

const invokedDirectly = (() => {
	if (!process.argv[1]) return false;
	try {
		return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
	} catch {
		return false;
	}
})();

if (invokedDirectly) {
	const { verdicts, failures } = runAll();
	if (failures.length) {
		console.error(failures.join('\n'));
		console.error(`\n${failures.length} of ${verdicts} audit verdicts were not as derived.`);
		process.exit(1);
	}
	console.log(`${verdicts} audit verdicts across ${AUDIT_STEMS.length} pairs, each in its own process, all as derived.`);
}

export default runAll;
