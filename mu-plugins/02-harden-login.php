<?php
/**
 * Plugin Name:  Login Hardening
 * Description:  Generic authentication errors, no user enumeration, and
 *               optional restriction of the login form to known networks.
 * Version:      1.0.0
 * Author:       Abdullah Shabbir
 * License:      MIT
 *
 * Install: wp-content/mu-plugins/
 *
 * This file covers what code can do. It does not implement rate limiting.
 * Lockout belongs in a firewall plugin or at the edge, where it can see the
 * request before PHP boots and can act across the whole site rather than one
 * endpoint. See docs/03-login-lockout.md for the thresholds worth setting.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generic login errors.
 *
 * By default WordPress distinguishes "unknown username" from "the password
 * you entered for the username X is incorrect". The second message confirms
 * a valid account, which converts a two-variable guessing problem into a
 * one-variable one. Return the same message either way.
 */
add_filter(
	'login_errors',
	function () {
		return __( 'The username or password you entered is not correct.' );
	}
);

/**
 * Author archive enumeration.
 *
 * /?author=1 redirects to /author/adminusername/, which hands over a valid
 * username to anyone who asks. This is the most common way a "random" brute
 * force run arrives already knowing the account name.
 *
 * Only blocked for visitors who are not logged in, so editorial workflows
 * that rely on author archives still work in the admin.
 */
add_action(
	'template_redirect',
	function () {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		if ( isset( $_GET['author'] ) || is_author() ) {
			wp_safe_redirect( home_url(), 301 );
			exit;
		}
	}
);

/**
 * The REST users endpoint is the other enumeration route, and it is the one
 * people forget after blocking author archives.
 *
 * /wp-json/wp/v2/users returns usernames to unauthenticated requests on a
 * default install. Restrict it to authenticated users who can list users.
 *
 * Note this is deliberately narrow: it does not disable the REST API, which
 * would break the block editor, and it does not touch any other route.
 */
add_filter(
	'rest_endpoints',
	function ( $endpoints ) {
		if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
			return $endpoints;
		}
		unset( $endpoints['/wp/v2/users'] );
		unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		return $endpoints;
	}
);

/**
 * Block the login form except from listed networks.
 *
 * Powerful and dangerous in equal measure. Leave the constant undefined and
 * nothing happens, which is the default.
 *
 * Only enable this when the client has a static IP, has confirmed it, and
 * understands they will be locked out if it changes. Getting back in means
 * editing this file over SFTP, so confirm the client or you has working SFTP
 * access before switching it on. A client locked out of their own site by
 * their security consultant is a bad afternoon.
 *
 * Define in wp-config.php:
 *   define( 'ALLOWED_LOGIN_IPS', array( '203.0.113.10', '198.51.100.0/24' ) );
 */
add_action(
	'login_init',
	function () {
		if ( ! defined( 'ALLOWED_LOGIN_IPS' ) || ! is_array( ALLOWED_LOGIN_IPS ) || ! ALLOWED_LOGIN_IPS ) {
			return;
		}

		$ip = wpsh_client_ip();
		if ( null === $ip ) {
			return; // Cannot determine the address; fail open rather than lock everyone out.
		}

		foreach ( ALLOWED_LOGIN_IPS as $allowed ) {
			if ( wpsh_ip_in_range( $ip, $allowed ) ) {
				return;
			}
		}

		wp_die( 'Login is not available from this network.', 'Forbidden', array( 'response' => 403 ) );
	}
);

/**
 * Best-effort client IP.
 *
 * REMOTE_ADDR is the only value that cannot be forged by the client. Proxy
 * headers are trusted only when the site has explicitly opted in, because
 * behind a misconfigured proxy X-Forwarded-For is attacker-controlled and any
 * IP allowlist built on it is decorative.
 *
 *   define( 'WPSH_TRUST_PROXY', true );  // only behind a proxy you control
 */
function wpsh_client_ip() {
	if ( defined( 'WPSH_TRUST_PROXY' ) && WPSH_TRUST_PROXY && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$parts = explode( ',', wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
		$candidate = trim( $parts[0] );
		if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
			return $candidate;
		}
	}
	if ( ! empty( $_SERVER['REMOTE_ADDR'] ) && filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP ) ) {
		return wp_unslash( $_SERVER['REMOTE_ADDR'] );
	}
	return null;
}

/**
 * Single IPv4 address or CIDR range match.
 */
function wpsh_ip_in_range( $ip, $range ) {
	if ( false === strpos( $range, '/' ) ) {
		return $ip === $range;
	}

	list( $subnet, $bits ) = explode( '/', $range, 2 );
	$bits = (int) $bits;

	$ip_long     = ip2long( $ip );
	$subnet_long = ip2long( $subnet );

	if ( false === $ip_long || false === $subnet_long || $bits < 0 || $bits > 32 ) {
		return false;
	}

	$mask = -1 << ( 32 - $bits );
	return ( $ip_long & $mask ) === ( $subnet_long & $mask );
}
