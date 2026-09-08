# Scan and update workflow

A malware scan that comes back clean is not the end of the job. On most sites
the scan returns no infection and a list of outdated components, and the real
work is deciding what to update, what to delete, and what to deliberately leave
alone.

## Scan first, and record what clean means

Run a full file and database scan before changing anything, so there is a
recorded baseline.

What a scanner checks, and what each result means:

| Check | A clean result means |
|---|---|
| Core file integrity | No WordPress core file differs from the official release |
| Known malware signatures | No file matches a known pattern |
| Backdoors and web shells | No known remote-execution file found |
| Suspicious database content | No injected script in post content or options |
| Outdated software | Nothing is running a version with a published vulnerability |

The distinction that matters in the report: **outdated software is not an
infection**. A scan returning seven findings, all of them out-of-date
components, is a site that has not been maintained, not a site that has been
compromised. Say which one it is plainly, because "seven security findings"
reads as a breach to a client who does not know the difference.

Cross-check reputation separately, because a scanner looks at the site and a
blocklist looks at the site's reputation:

- Google Safe Browsing
- VirusTotal, which aggregates a large number of engines
- Norton Safe Web

## The update decision

Not everything outdated should be updated, and not everything unused should be
kept. Four outcomes, and each one belongs in the report with its reason.

**Update.** The default for anything with a published vulnerability and a
minor version bump.

**Delete.** A deactivated plugin still has its files on disk, and a
vulnerability in a deactivated plugin is often still reachable, because the
attacker requests the file directly rather than going through WordPress.
Deactivated is not disabled. Delete it.

This is also the right outcome for a plugin that duplicates something the
hosting stack already provides. A caching plugin that is deactivated, carries a
critical vulnerability, and duplicates an object cache the host already runs is
not worth updating and maintaining. It is worth removing.

The same applies to inactive themes. Every installed theme is code on disk. Keep
the active theme, keep its parent if it is a child theme, keep one default
theme as a fallback, and delete the rest.

**Update, but not now.** A major version bump with a vendor warning to test in
staging first is not a change to make on a live site on a Friday. Record it as
recommended, note that it requires a staging test, and say who will do it. A
page builder major version is the standard example, and pushing it blind is how
a hardening engagement turns into an emergency layout repair.

**Keep deliberately.** Sometimes a component that looks redundant is part of
the hosting stack and removing it degrades the site. Note why it was kept, or
the next person will remove it.

## Before any update

- [ ] Take a backup and **confirm it completed**. Do not trust the button.
      Managed hosting backup interfaces fail more often than anyone expects,
      and the failure is usually silent. Check the timestamp of the most recent
      successful automated backup independently.
- [ ] Confirm you can restore. An untested backup is an assumption.
- [ ] Update one thing at a time on a live site, checking the front end between
      each. Batch updates are faster right up until something breaks and you do
      not know which one did it.

## After

- [ ] Re-scan.
- [ ] Load the front end, a product or contact page, and the checkout or form
      flow.
- [ ] Log in as a non-administrator and confirm nothing is broken for them.
- [ ] Verify the security headers are still being sent:
      `./scripts/check-headers.sh https://example.com`
- [ ] Record versions before and after, so the next person has a baseline.

## Reading the firewall log

A firewall on an ordinary site records a large volume of blocked traffic with
no targeting behind it. Roughly a thousand blocked attacks a month with several
hundred brute force attempts is unremarkable.

What is worth attention:

- The same source persisting across days rather than minutes.
- Requests for paths specific to plugins the site actually runs, which suggests
  the attacker fingerprinted it first.
- Successful logins from unfamiliar locations, which is the only entry in the
  log that indicates something has already gone wrong.
- Requests to `xmlrpc.php` succeeding after you closed it.

Put the volume figure in the report with that framing. It shows the control is
working, and it stops the client reading routine noise as evidence of a
targeted attack.
