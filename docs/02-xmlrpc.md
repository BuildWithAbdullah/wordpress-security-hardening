# XML-RPC

`xmlrpc.php` accepts unauthenticated POST requests and will check credentials
on request. Two features make it worth closing.

## Why it is worse than a second login form

**`system.multicall` amplifies.** One HTTP request can carry hundreds of
credential attempts. A rate limiter that counts requests sees a single request
and allows it, while the endpoint processes five hundred password guesses. This
is the reason a site with login rate limiting still shows credential
compromise.

**`pingback.ping` reflects.** It can be used to make the site issue outbound
requests to a target of the attacker's choosing, turning it into a small
participant in a reflection attack against somebody else. The site owner finds
out when their host complains about outbound traffic.

## Check before you close it

XML-RPC still has legitimate users, and switching it off blind is how a client
discovers their publishing workflow is broken a week later.

- The WordPress mobile app on some configurations, though it prefers the REST
  API now.
- Some Jetpack features.
- A number of remote publishing, backup and migration tools.

Look in the access log for requests to `xmlrpc.php` that returned 200 and came
from something other than an obvious scanner:

```bash
grep 'xmlrpc\.php' access.log | awk '$9 == 200' | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

A handful of addresses making regular successful requests is an integration.
Hundreds of addresses making failing requests is the background noise of the
internet.

## Two ways to close it

**Application level**, which is portable and leaves harmless read-only methods
working:
[`mu-plugins/01-disable-xmlrpc.php`](../mu-plugins/01-disable-xmlrpc.php)

It disables authentication, removes the pingback and multicall methods, and
stops advertising the endpoint in the head and in the `X-Pingback` header.

Note that `add_filter( 'xmlrpc_enabled', '__return_false' )` on its own is not
enough. It disables authenticated methods, and the pingback methods do not
authenticate, so they remain reachable. Both are needed.

**Server level**, which is better where you control the config, because the
request never reaches PHP and costs nothing:

nginx:

```nginx
location = /xmlrpc.php {
    deny all;
    access_log off;
    log_not_found off;
}
```

Apache:

```apache
<Files "xmlrpc.php">
    Require all denied
</Files>
```

If a single integration genuinely needs it, allow that source rather than
opening the endpoint to everyone:

```nginx
location = /xmlrpc.php {
    allow 203.0.113.10;
    deny all;
}
```

## Verify

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://example.com/xmlrpc.php
```

`403` or `404` means it is closed. `405` means the file is still being executed
and is only rejecting the method, which is not the same thing. `200` with an
XML body means it is open.

Check the header is gone too:

```bash
curl -sSI https://example.com | grep -i x-pingback
```

No output is the correct result.
