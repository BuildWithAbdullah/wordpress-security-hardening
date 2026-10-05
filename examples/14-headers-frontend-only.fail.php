<?php
/**
 * Failing example: security headers on the front end only.
 *
 * One filter on wp_headers, which is what every guide shows, and it does work.
 * It works on front-end requests, because that filter runs in
 * WP::send_headers() and nowhere else.
 *
 * It does not run on wp-login.php and it does not run in wp-admin. So the two
 * URLs on a WordPress site that are under constant attack receive no
 * X-Frame-Options and no HSTS from the plugin that exists to send them, and the
 * site passes a header check pointed at its home page.
 *
 * Corrected in 14-headers-frontend-only.pass.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter(
	'wp_headers',
	function ( $headers ) {
		$headers['X-Content-Type-Options'] = 'nosniff';
		$headers['X-Frame-Options']        = 'SAMEORIGIN';
		$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
		if ( is_ssl() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}
		return $headers;
	}
);
