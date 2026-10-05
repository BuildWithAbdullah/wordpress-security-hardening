<?php
/**
 * Corrected example: one header set, every context that can send it.
 *
 * The set is a pure function of the context, and the three places WordPress
 * offers are all wired to it. One list, so there is nothing to keep in sync and
 * no context that can be quietly forgotten, and the set is reachable from a
 * test without a web server.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_example_header_set( $context, $is_ssl ) {
	$headers = array(
		'X-Content-Type-Options' => 'nosniff',
		'X-Frame-Options'        => 'SAMEORIGIN',
		'Referrer-Policy'        => 'strict-origin-when-cross-origin',
	);

	if ( $is_ssl ) {
		$headers['Strict-Transport-Security'] = 'max-age=31536000';
	}

	if ( 'login' === $context || 'admin' === $context ) {
		$headers['X-Robots-Tag'] = 'noindex, nofollow';
	}

	return $headers;
}

if ( ! function_exists( 'wpsh_send_headers' ) ) {
	function wpsh_send_headers( $headers ) {
		if ( headers_sent() ) {
			return;
		}
		foreach ( (array) $headers as $name => $value ) {
			header( $name . ': ' . $value, true );
		}
	}
}

add_filter(
	'wp_headers',
	function ( $headers ) {
		return array_merge( (array) $headers, wpsh_example_header_set( 'frontend', is_ssl() ) );
	}
);

add_action(
	'login_init',
	function () {
		wpsh_send_headers( wpsh_example_header_set( 'login', is_ssl() ) );
	}
);

add_action(
	'admin_init',
	function () {
		wpsh_send_headers( wpsh_example_header_set( 'admin', is_ssl() ) );
	}
);
