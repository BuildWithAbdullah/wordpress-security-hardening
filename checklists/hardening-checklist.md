# Hardening checklist

A working order for a WordPress hardening engagement. Every item that is
deliberately not done should appear in the report with its reason; an
undocumented omission reads as an oversight.

## 1. Baseline

- [ ] Full malware and file integrity scan, recorded before any changes.
- [ ] Reputation check: Google Safe Browsing, VirusTotal, Norton Safe Web.
- [ ] Record WordPress, PHP, plugin and theme versions.
- [ ] Confirm a recent automated backup completed. Verify the timestamp
      independently rather than trusting the host's button.
- [ ] Confirm HTTPS on every hostname, with no mixed content.
- [ ] List administrator accounts and when each last logged in.
- [ ] Note whether the scan findings are infections or merely outdated
      software. They are usually the latter, and the distinction belongs in
      the report.

## 2. Access

- [ ] No account named `admin`.
- [ ] Remove ex-developer and ex-agency administrator accounts.
- [ ] Editors and authors are not administrators.
- [ ] Review application passwords. They bypass 2FA and outlive the
      integrations that created them.
- [ ] Strong password enforcement for administrators.
- [ ] 2FA enabled and set to Optional. Do not set it to Required until every
      administrator is enrolled, or you will lock them all out.
- [ ] Generic login error messages.
- [ ] Author archive and REST user enumeration blocked.

## 3. Rate limiting

- [ ] Failed login lockout at 5 attempts.
- [ ] Immediate lockout on invalid usernames. Highest-yield setting, most
      often left off.
- [ ] Common admin usernames blocked.
- [ ] Rate limiting at the edge or web server where possible, not in
      application code.
- [ ] CAPTCHA configured, or handed over as a client action with instructions
      if it needs their own API keys.

## 4. Attack surface

- [ ] XML-RPC closed, after checking the access log for legitimate use.
- [ ] `X-Pingback` header gone.
- [ ] File editing disabled: `define( 'DISALLOW_FILE_EDIT', true );`
- [ ] PHP execution blocked in `wp-content/uploads`.
- [ ] Directory listing off.
- [ ] `wp-config.php` not readable, and moved above web root where the host
      allows it.
- [ ] Version numbers removed from the generator tag and asset URLs. Note in
      the report that this is obscurity, not security.

## 5. Headers

- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: SAMEORIGIN`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy`, after checking which features the site actually
      uses.
- [ ] `Strict-Transport-Security`, short `max-age` first, raised after
      watching a certificate renewal succeed.
- [ ] Verified live: `./scripts/check-headers.sh https://example.com`
- [ ] CSP decision recorded, whether it was deployed or deliberately not.

## 6. Components

- [ ] Update everything with a published vulnerability and a minor bump.
- [ ] Delete deactivated plugins. Deactivated is not disabled; the files are
      still reachable.
- [ ] Delete unused themes, keeping the active theme, its parent, and one
      default as a fallback.
- [ ] Major version bumps with a vendor staging warning: record as
      recommended, do not push blind on a live site.
- [ ] Note anything deliberately retained as part of the hosting stack, so the
      next person does not remove it.
- [ ] One change at a time, checking the front end between each.

## 7. Backups and monitoring

- [ ] Automated backups running and verified as completing.
- [ ] Backups stored off-site, not only on the same server.
- [ ] A restore has actually been tested.
- [ ] File integrity monitoring on.
- [ ] Alert email goes to an address the client monitors, not to yours.

## 8. Verify and hand over

- [ ] Re-scan and compare against the baseline.
- [ ] Re-check headers on the live site.
- [ ] Confirm the front end, a form, and checkout still work.
- [ ] Log in as a non-administrator and confirm nothing broke for them.
- [ ] Report: what was changed, what was deliberately not changed and why,
      and what remains a client action.
- [ ] Firewall volume figures with context, so routine background noise is
      not read as a targeted attack.

## Things that are client actions, not omissions

State these explicitly in the handover:

- CAPTCHA keys, which must be created under the client's own account.
- Making 2FA required, after every administrator has enrolled.
- Off-site backup storage credentials.
- Major version updates that need a staging test.
- Alerting destinations.
