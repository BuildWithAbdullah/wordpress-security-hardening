# Login lockout and account protection

Brute force against `wp-login.php` and `xmlrpc.php` is constant background
traffic on every WordPress site on the internet. A firewall plugin on a modest
site will typically record something in the order of a thousand blocked attacks
a month, roughly half of them brute force attempts, with no targeting
whatsoever.

That volume matters for two reasons. It means lockout is not optional, and it
means the log is not evidence of a targeted attack unless something in it
stands out.

## Thresholds worth setting

These are the settings that matter, in the order they matter.

| Setting | Value | Why |
|---|---|---|
| Failed login attempts before lockout | 5 | Low enough to stop automation, high enough that a real person mistyping twice is fine |
| Lockout duration | 60 minutes, increasing on repeat | Slows a distributed run without permanently denying a legitimate user |
| Lock out invalid usernames immediately | Enabled | A request for a username that does not exist is never a legitimate typo by an existing user |
| Block common admin usernames | `admin`, `administrator`, `test`, the domain name | These are the first guesses in every list |
| Enforce strong passwords for admins | Enabled | The lockout is the second line, not the first |

The invalid-username setting is the one most often left off and it is the
highest yield. Automated runs guess usernames; real users know theirs.

## Rate limiting belongs at the edge

Code in `functions.php` runs after WordPress has booted, which means every
blocked attempt still costs a full PHP process and several database queries. A
sustained run then becomes a performance problem on top of a security one.

In order of preference:

1. **CDN or WAF.** Cloudflare, Sucuri, or the host's own edge rules. The
   request never reaches the origin.
2. **Web server.** nginx `limit_req` or Apache with `mod_evasive` on the login
   paths. Reaches the origin, never boots PHP.
3. **Firewall plugin.** Wordfence, Solid Security, or similar. Boots PHP but
   catches the request early.

The mu-plugin in this repository deliberately does not implement rate
limiting. Doing it properly needs shared state and a view of the request before
PHP starts, and a half-implementation in application code creates the
impression of protection without the substance.

## Two-factor authentication, and when not to force it

2FA on administrator accounts is the single highest-value control on this
list. It defeats credential stuffing entirely, which is the attack that
actually succeeds.

The judgement call is whether to set it to Required.

Setting it to Required on a site with three administrator accounts, none of
them enrolled, locks all three out at the next login. If one of those accounts
belongs to a developer who left, or to a client who reads email once a week, the
site is now unreachable by anyone who can fix it.

The sequence that works:

1. Set 2FA to Optional and enable it.
2. Enrol the accounts you control.
3. Give the client written instructions and a deadline.
4. Confirm enrolment.
5. Only then set it to Required.

Steps 3 to 5 usually sit outside the engagement. Say so in the report rather
than leaving it looking like an oversight: *"Two-factor authentication is
enabled and set to Optional. Three administrator accounts exist and none are
currently enrolled. Setting it to Required before those accounts are enrolled
would lock all three out. Recommended next step: enrol all three, then switch
to Required."*

That reads as a considered decision, which it is. Setting it to Required and
handing over a locked site does not.

## Things that need the client's own credentials

Some controls cannot be completed by a contractor, and pretending otherwise
produces a half-configured control that looks finished.

- **CAPTCHA on the login form** needs the client's own Google reCAPTCHA or
  hCaptcha API keys, created under their account. Configure everything else and
  hand over the one step, with instructions.
- **Email alerting** should go to an address the client monitors, not to yours.
- **Off-site backups** need their storage account.

List these explicitly as client actions in the handover. An unfinished item
that is documented is a task. An unfinished item that is not documented is a
finding against you later.

## Account hygiene

- [ ] No account named `admin`.
- [ ] Every administrator is a person who still needs the access. Ex-developer
      and ex-agency accounts are extremely common and are a real risk.
- [ ] Editors and authors are not administrators.
- [ ] No shared accounts. When one person leaves, a shared password has to be
      rotated and never is.
- [ ] Application passwords reviewed. They bypass 2FA by design, and stale ones
      from a decommissioned integration are a live credential nobody is
      watching.

That last one is worth checking on every engagement. Application passwords are
easy to create, invisible on the dashboard unless you go looking, and outlive
the integration that needed them.
