<?php
/**
 * Plugin Name:  Security Headers
 * Description:  Sends the five response headers that are safe to deploy on
 *               essentially any WordPress site. Content Security Policy is
 *               deliberately not included; see docs/01-security-headers.md.
 * Version:      1.0.0
 * Author:       Abdullah Shabbir
 * License:      MIT
 *
 * Install: drop into wp-content/mu-plugins/. Must-use plugins load
 * automatically, cannot be deactivated from the dashboard, and survive plugin
 * updates. That is the right place for hardening: a client who deactivates
 * a security plugin while troubleshooting should not silently lose their
 * headers too.
 *
 * Prefer sending these at the web server or CDN level if you control it.
 * PHP-level headers are not sent for static assets served directly by nginx
 * or Apache, or for responses served from a full-page cache that bypasses PHP.
 * This file is the portable fallback for shared and managed hosting where you
 * do not have a server config.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter(
	'wp_headers',
	/**
	 * @param array $headers
	 * @return array
	 */
	function ( $headers ) {

		/**
		 * Stops the browser from second-guessing a declared Content-Type.
		 * Without it, a file served as text/plain that happens to contain
		 * markup can be sniffed and executed as HTML. Relevant to any site
		 * that accepts uploads, which is any site with a media library.
		 * No compatibility risk.
		 */
		$headers['X-Content-Type-Options'] = 'nosniff';

		/**
		 * Clickjacking. SAMEORIGIN allows the site to frame itself, which
		 * matters because several page builders and the block editor preview
		 * use same-origin iframes. DENY breaks those.
		 *
		 * If the site is legitimately embedded elsewhere, for example a
		 * booking page inside a partner site, use a CSP frame-ancestors
		 * directive instead and drop this header.
		 */
		$headers['X-Frame-Options'] = 'SAMEORIGIN';

		/**
		 * Sends the full URL to same-origin destinations and only the origin
		 * cross-origin, and nothing at all when downgrading to HTTP.
		 *
		 * strict-origin-when-cross-origin is the right default. no-referrer
		 * looks stronger and breaks analytics attribution and some payment
		 * gateway return flows, which is a support ticket rather than a
		 * security win.
		 */
		$headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';

		/**
		 * Switches off browser features the site does not use, so an injected
		 * script cannot reach for them either.
		 *
		 * Check before deploying. A site with a store locator needs
		 * geolocation. A site with a video consultation feature needs camera
		 * and microphone. Removing a feature the site uses breaks it
		 * silently, and the failure looks like a bug rather than a header.
		 */
		$headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()';

		/**
		 * HSTS. Only sent over HTTPS, because sending it over HTTP is
		 * meaningless and the browser ignores it.
		 *
		 * Deploy this last and deliberately. Once a browser has seen it, that
		 * browser will refuse to reach the site over HTTP for max-age
		 * seconds, and there is no way to undo that remotely. If the
		 * certificate later lapses, visitors get a hard error rather than a
		 * warning they can click through.
		 *
		 * Start with a short max-age, confirm the certificate renews
		 * automatically, then raise it. One year is the usual end state.
		 *
		 * includeSubDomains is intentionally omitted here. It applies to every
		 * subdomain including ones you may have forgotten, and a staging or
		 * legacy subdomain still on HTTP will break. Add it only after
		 * auditing every subdomain.
		 */
		if ( is_ssl() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}

		return $headers;
	}
);

/**
 * Remove the WordPress version from the generator meta tag and from asset
 * query strings.
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

add_filter(
	'style_loader_src',
	function ( $src ) {
		return remove_query_arg( 'ver', $src );
	},
	9999
);

add_filter(
	'script_loader_src',
	function ( $src ) {
		return remove_query_arg( 'ver', $src );
	},
	9999
);
