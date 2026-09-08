# Compromise and blocklist recovery

A hacked site is a different engagement from a hardening engagement. Order
matters, and the order is not the intuitive one.

## Do not clean first

The instinct is to delete the malicious files immediately. Resist it for the
twenty minutes it takes to do the first two steps, because cleaning first
destroys the evidence you need to find the entry point, and a site cleaned
without closing the entry point is reinfected within days.

## Order of work

**1. Contain.** Take the site offline or put it behind maintenance mode if it
is serving malware to visitors. Change every administrator password and the
hosting, FTP, SFTP and database credentials. Invalidate all sessions. Revoke
application passwords, which survive a password change by design and are a
common reinfection route.

**2. Preserve.** Take a full copy of files and database before changing
anything, and store it somewhere separate. This is your evidence and your
fallback if the clean goes wrong.

**3. Find the entry point.** This is the step people skip, and skipping it is
why sites get reinfected.

- Access logs around the timestamp of the earliest modified file.
- Files modified out of pattern:
  `find . -type f -name '*.php' -newermt '2026-08-01' -ls`
- Vulnerable component versions at the time of compromise, checked against a
  vulnerability database.
- Administrator accounts created around that date.
- Scheduled tasks and cron entries that re-create files.
- `wp-config.php`, `.htaccess` and `wp-content/uploads` for PHP files that
  should not exist there.

**4. Clean.** Replace WordPress core with a fresh copy of the same version.
Replace plugins and themes with fresh copies from source rather than editing
the infected files. Clean the database by hand: injected scripts commonly live
in `wp_options`, in post content, and in widget content.

**5. Close.** Update or remove whatever let them in. If you never found the
entry point, say so, and treat the site as likely to be reinfected.

**6. Harden.** Now the rest of this repository applies.

**7. Verify and delist.**

## Delisting

Cleaning the site does not restore its reputation. Blocklists have to be told,
each one separately, and each has its own process.

- **Google Safe Browsing.** Request a review in Search Console, Security
  Issues. Usually the fastest, often within seventy-two hours.
- **VirusTotal.** Aggregates a large number of engines. Individual vendors
  have their own dispute forms; the aggregate score updates as they clear.
- **Norton Safe Web.** Its own dispute submission.
- **McAfee, Yandex, and others.** Each separate.
- **Host and email deliverability.** If the site sent spam, the IP or domain
  may be on a mail blocklist, which is a separate problem with separate
  consequences for the client's ordinary email.

Capture before-and-after evidence for each. A VirusTotal result moving from
several engines flagging the domain to zero, alongside a Norton rating moving
from Warning to Safe, is exactly the kind of proof a client can understand and
show to whoever is asking them about it.

Do not request review until the site is genuinely clean. A failed review can
lengthen the process.

## Setting expectations

Three things clients consistently do not know, and all three are better said at
the start than discovered later.

**Cleaning and delisting are separate.** The site can be clean for days while
still showing a browser warning. That is normal and it is not a sign the clean
failed.

**Some damage is not reversible by you.** Search ranking loss from a period of
being flagged recovers on its own timescale. Email deliverability damage can
take longer than the site cleanup.

**If the entry point was not found, the risk remains.** Say this plainly rather
than implying a clean site is a solved problem. A client who understands why
monitoring matters will pay for monitoring.

## Afterwards

- Off-site backups, verified by restoring one.
- File integrity monitoring, so the next modification is noticed in hours
  rather than when a customer reports a warning.
- A component update routine, since out-of-date software was probably the way
  in.
- Reputation monitoring, so a future flag is caught before the client's
  customers find it.
