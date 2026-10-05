<?php
/**
 * Plugin Name:  Security Headers
 * Description:  Sends the five response headers that are safe to deploy on
 *               essentially any WordPress site, on the front end, on the login
 *               page and in the admin. Content Security Policy is deliberately
 *               not included; see docs/01-security-headers.md.
 * Version:      2.0.0
 * Author:       Abdullah Shabbir
 * License:      MIT
 *
 * Install: drop into wp-content/mu-plugins/. Must-use plugins load
 * automatically, cannot be deactivated from the dashboard, and survive plugin
 * updates. That is the right place for hardening: a client who deactivates a
 * security plugin while troubleshooting should not silently lose their headers
 * too.
 *
 * Prefer sending these at the web server or CDN level if you control it.
 * PHP-level headers are not sent for static assets served directly by nginx or
 * Apache, or for responses served from a full-page cache that bypasses PHP.
 * This file is the portable fallback for shared and managed hosting where you
 * do not have a server config.
 *
 * ---------------------------------------------------------------------------
 * Why version 2 exists, and it is worth reading before deploying version 1
 * anywhere
 *
 * Version 1 registered one filter on `wp_headers` and stopped there. That
 * filter runs in WP::send_headers(), which handles front-end requests. It does
 * not run on wp-login.php, and it does not run in wp-admin. So the two URLs on
 * a WordPress site that are actually under constant attack, the login form and
 * the dashboard, received no X-Frame-Options and no HSTS from a plugin whose
 * whole job was to send them. The site passed a header check against its home
 * page and shipped.
 *
 * The fix is structural rather than a third hook bolted on. The header set is
 * now one pure function of context, and the three places WordPress gives you
 * to send headers all call it. There is one list, so there is nothing to keep
 * in sync and no context that can be quietly forgotten.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The header set for a context. Pure: no globals, no side effects, no request.
 *
 * Keeping this separate from the sending is what makes every header in the
 * file reachable from a test. While the two were one closure, not one of these
 * values had ever been observed by anything other than a browser.
 *
 * @param string $context One of 'frontend', 'login', 'admin'.
 * @param bool   $is_ssl  Whether the current request is over HTTPS.
 * @return array Header name to value.
 */
function wpsh_header_set( $context, $is_ssl ) {

	$headers = array();

	/**
	 * Stops the browser from second-guessing a declared Content-Type. Without
	 * it, a file served as text/plain that happens to contain markup can be
	 * sniffed and executed as HTML. Relevant to any site that accepts uploads,
	 * which is any site with a media library. No compatibility risk.
	 */
	$headers['X-Content-Type-Options'] = 'nosniff';

	/**
	 * Clickjacking. SAMEORIGIN allows the site to frame itself, which matters
	 * because several page builders and the block editor preview use
	 * same-origin iframes. DENY breaks those.
	 *
	 * If the site is legitimately embedded elsewhere, for example a booking
	 * page inside a partner site, use a CSP frame-ancestors directive instead
	 * and drop this header.
	 */
	$headers['X-Frame-Options'] = 'SAMEORIGIN';

	/**
	 * Sends the full URL to same-origin destinations and only the origin
	 * cross-origin, and nothing at all when downgrading to HTTP.
	 *
	 * strict-origin-when-cross-origin is the right default. no-referrer looks
	 * stronger and breaks analytics attribution and some payment gateway
	 * return flows, which is a support ticket rather than a security win.
	 */
	$headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';

	/**
	 * Switches off browser features the site does not use, so an injected
	 * script cannot reach for them either.
	 *
	 * Check before deploying. A site with a store locator needs geolocation. A
	 * site with a video consultation feature needs camera and microphone.
	 * Removing a feature the site uses breaks it silently, and the failure
	 * looks like a bug rather than a header.
	 *
	 * Override the whole directive list in wp-config.php:
	 *   define( 'WPSH_PERMISSIONS_POLICY', 'geolocation=(self), camera=()' );
	 *
	 * The list is deliberately short. Version 1 also sent interest-cohort=(),
	 * which addressed a proposal that was abandoned, so it was doing nothing
	 * except making the header longer and the author look like they had copied
	 * it from somewhere.
	 */
	$headers['Permissions-Policy'] = defined( 'WPSH_PERMISSIONS_POLICY' )
		? WPSH_PERMISSIONS_POLICY
		: 'geolocation=(), camera=(), microphone=(), payment=(), usb=()';

	/**
	 * HSTS. Only sent over HTTPS, because sending it over HTTP is meaningless
	 * and the browser ignores it.
	 *
	 * Deploy this last and deliberately. Once a browser has seen it, that
	 * browser will refuse to reach the site over HTTP for max-age seconds, and
	 * there is no way to undo that remotely. If the certificate later lapses,
	 * visitors get a hard error rather than a warning they can click through.
	 *
	 * Start short, confirm the certificate renews automatically, then raise it:
	 *   define( 'WPSH_HSTS_MAX_AGE', 300 );
	 *
	 * includeSubDomains is intentionally omitted. It applies to every subdomain
	 * including ones you may have forgotten, and a staging or legacy subdomain
	 * still on HTTP will break. Add it only after auditing every subdomain.
	 */
	if ( $is_ssl ) {
		$max_age = defined( 'WPSH_HSTS_MAX_AGE' ) ? (int) WPSH_HSTS_MAX_AGE : 31536000;
		if ( $max_age > 0 ) {
			$headers['Strict-Transport-Security'] = 'max-age=' . $max_age;
		}
	}

	/**
	 * The login page and the admin are not public pages, and nothing good comes
	 * of a search engine or an intermediary caching them.
	 *
	 * Front-end responses are left alone. Setting no-store there would disable
	 * every page cache on the site, which is a performance incident dressed up
	 * as a security control.
	 */
	if ( 'login' === $context || 'admin' === $context ) {
		$headers['X-Robots-Tag']  = 'noindex, nofollow';
		$headers['Cache-Control'] = 'no-store, max-age=0';
	}

	return $headers;
}

/**
 * Send a header set.
 *
 * Guarded with function_exists because these files get pasted into a theme's
 * functions.php at least as often as they get installed properly, and a
 * redeclare is a fatal error on a live site.
 */
if ( ! function_exists( 'wpsh_send_headers' ) ) {
	/**
	 * @param array $headers Header name to value.
	 */
	function wpsh_send_headers( $headers ) {
		if ( headers_sent() ) {
			return;
		}
		foreach ( (array) $headers as $name => $value ) {
			header( $name . ': ' . $value, true );
		}
	}
}

/** Front end. WordPress merges this into the response headers itself. */
add_filter(
	'wp_headers',
	function ( $headers ) {
		return array_merge( (array) $headers, wpsh_header_set( 'frontend', is_ssl() ) );
	}
);

/**
 * wp-login.php. There is no header filter here, so the headers are sent
 * directly. login_init fires before any output.
 */
add_action(
	'login_init',
	function () {
		wpsh_send_headers( wpsh_header_set( 'login', is_ssl() ) );
	}
);

/**
 * wp-admin. admin_init fires before the admin header is rendered.
 *
 * Skipped for AJAX and REST requests, which are served by the admin bootstrap
 * but are not documents, so framing and robots directives are noise on them.
 */
add_action(
	'admin_init',
	function () {
		if ( wp_doing_ajax() ) {
			return;
		}
		wpsh_send_headers( wpsh_header_set( 'admin', is_ssl() ) );
	}
);

/**
 * Remove the WordPress version from the generator meta tag.
 *
 * This is obscurity, not security, and it should be described that way in a
 * report. It does not stop a targeted attacker, who will fingerprint the
 * version from other signals in seconds. It does reduce noise from automated
 * scanners that filter by advertised version, which is most of the background
 * traffic any site receives.
 *
 * Do not let it substitute for actually updating.
 */
remove_action( 'wp_head', 'wp_generator' );

/**
 * Strip the version query string from stylesheet and script URLs.
 *
 * Off by default, and that is a change from version 1, which did it
 * unconditionally.
 *
 * The `ver` parameter is what busts the browser cache when a theme or plugin
 * updates. Removing it means a returning visitor can keep a stale stylesheet
 * until their cache expires on its own, which presents as a broken layout that
 * only some people see and that nobody can reproduce. Trading that for an
 * obscurity measure this same file describes as not security was the wrong
 * default.
 *
 * Enable it only where a cache-busting strategy already exists that does not
 * rely on the query string, for example hashed asset filenames:
 *   define( 'WPSH_STRIP_ASSET_VERSIONS', true );
 */
if ( defined( 'WPSH_STRIP_ASSET_VERSIONS' ) && WPSH_STRIP_ASSET_VERSIONS ) {
	$wpsh_strip_ver = function ( $src ) {
		return remove_query_arg( 'ver', $src );
	};
	add_filter( 'style_loader_src', $wpsh_strip_ver, 9999 );
	add_filter( 'script_loader_src', $wpsh_strip_ver, 9999 );
	unset( $wpsh_strip_ver );
}
