<?php
/**
 * Plugin Name:  Login Hardening
 * Description:  Authentication errors that do not confirm a username, no user
 *               enumeration, and optional restriction of the login form to
 *               known networks.
 * Version:      2.0.0
 * Author:       Abdullah Shabbir
 * License:      MIT
 *
 * Install: wp-content/mu-plugins/
 *
 * This file covers what code can do. It does not implement rate limiting.
 * Lockout belongs in a firewall plugin or at the edge, where it can see the
 * request before PHP boots and can act across the whole site rather than one
 * endpoint. See docs/03-login-lockout.md for the thresholds worth setting.
 *
 * ---------------------------------------------------------------------------
 * Three corrections in version 2, each of which had shipped
 *
 * 1. The login_errors filter was returning the generic message for every
 *    notice on wp-login.php, not just failed authentication. Logging out
 *    showed "The username or password you entered is not correct." A password
 *    reset said the same. It is now scoped to authentication error codes, and
 *    the confirmation and logout notices pass through untouched.
 *
 * 2. The author archive block redirected with 301. Browsers cache a permanent
 *    redirect indefinitely and do not recheck it, so a client who later wants
 *    author archives back finds that returning visitors still cannot reach
 *    them, with no server-side change that fixes it. It is 302 now. A
 *    hardening measure should never be the thing that cannot be undone.
 *
 * 3. The IP allowlist matched with ip2long only, which returns false for every
 *    IPv6 address. An administrator whose connection preferred IPv6, which on
 *    a modern network is most of them, matched no entry in the list and was
 *    refused the login form, with their IPv4 address sitting in the allowlist.
 *    The one failure mode this feature's own comment warns about was built
 *    into it.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The WP_Error codes that mean authentication failed.
 *
 * These are the only ones worth replacing. Everything else wp-login.php puts
 * through this filter is a notice the user asked for.
 */
if ( ! function_exists( 'wpsh_auth_error_codes' ) ) {
	function wpsh_auth_error_codes() {
		return array(
			'invalid_username',
			'invalid_email',
			'incorrect_password',
			'authentication_failed',
			'empty_password',
			'invalidcombo',
		);
	}
}

/**
 * Decide what wp-login.php should display. Pure function of the error codes
 * present and the message WordPress was going to show.
 *
 * By default WordPress distinguishes "unknown username" from "the password you
 * entered for the username X is incorrect". The second message confirms a
 * valid account, which turns a two-variable guessing problem into a
 * one-variable one. Return the same message for either.
 *
 * @param string   $message The message WordPress assembled.
 * @param string[] $codes   Error codes on the WP_Error object, if any.
 * @return string
 */
if ( ! function_exists( 'wpsh_login_message' ) ) {
	function wpsh_login_message( $message, $codes ) {
		$auth = array_intersect( (array) $codes, wpsh_auth_error_codes() );
		if ( ! $auth ) {
			return $message;
		}
		return __( 'The username or password you entered is not correct.' );
	}
}

add_filter(
	'login_errors',
	function ( $message ) {
		global $errors;

		$codes = ( $errors instanceof WP_Error ) ? $errors->get_error_codes() : array();

		/**
		 * No WP_Error at all means wp-login.php is rendering a notice rather
		 * than reporting a failure, so there is nothing to genericise. Returning
		 * the generic message here is exactly the bug version 1 shipped.
		 */
		if ( ! $codes ) {
			return $message;
		}

		return wpsh_login_message( $message, $codes );
	}
);

/**
 * Author archive enumeration.
 *
 * /?author=1 redirects to /author/adminusername/, which hands a valid username
 * to anyone who asks. This is the most common way a "random" brute force run
 * arrives already knowing the account name.
 *
 * Only applied to visitors who are not logged in, so editorial workflows that
 * rely on author archives still work for signed-in users.
 *
 * 302, not 301. See the note at the top of the file.
 */
add_action(
	'template_redirect',
	function () {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		if ( isset( $_GET['author'] ) || is_author() ) {
			wp_safe_redirect( home_url( '/' ), 302 );
			exit;
		}
	}
);

/**
 * The REST users endpoint is the other enumeration route, and it is the one
 * people forget after blocking author archives.
 *
 * /wp-json/wp/v2/users returns usernames to unauthenticated requests on a
 * default install. Restrict it to users who have a reason to read it.
 *
 * Deliberately narrow: it does not disable the REST API, which would break the
 * block editor, and it does not touch any other route.
 *
 * The capability is `list_users` by default, which is an administrator. That is
 * the tight choice and it has a cost: an Editor opening the block editor cannot
 * populate the author dropdown, so reassigning a post to another author stops
 * working for exactly the role that exists to do it. If the site has Editors
 * who need that, relax it in wp-config.php:
 *
 *   define( 'WPSH_USERS_ENDPOINT_CAP', 'edit_others_posts' );
 *
 * Both values are a real trade and neither is wrong. What is wrong is finding
 * out which one you picked from a client reporting that the editor is broken.
 */
add_filter(
	'rest_endpoints',
	function ( $endpoints ) {
		$cap = defined( 'WPSH_USERS_ENDPOINT_CAP' ) ? WPSH_USERS_ENDPOINT_CAP : 'list_users';

		if ( is_user_logged_in() && current_user_can( $cap ) ) {
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
 * Only enable this when the client has a static address, has confirmed it, and
 * understands they will be locked out if it changes. Getting back in means
 * editing this file over SFTP, so confirm that working SFTP access exists
 * before switching it on. A client locked out of their own site by their
 * security consultant is a bad afternoon.
 *
 * Define in wp-config.php. IPv4 and IPv6, single addresses or CIDR:
 *   define( 'ALLOWED_LOGIN_IPS', array(
 *       '203.0.113.10',
 *       '198.51.100.0/24',
 *       '2001:db8:1234::/48',
 *   ) );
 *
 * List the IPv6 range as well as the IPv4 one. A dual-stack client will arrive
 * over whichever the browser and network pick, which is not the one they read
 * off a web page when you asked them for their address.
 */
add_action(
	'login_init',
	function () {
		if ( ! defined( 'ALLOWED_LOGIN_IPS' ) || ! is_array( ALLOWED_LOGIN_IPS ) || ! ALLOWED_LOGIN_IPS ) {
			return;
		}

		$ip = wpsh_client_ip();
		if ( null === $ip ) {
			// Cannot determine the address. Fail open rather than lock everyone out.
			return;
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
 * Best-effort client address.
 *
 * REMOTE_ADDR is the only value that cannot be forged by the client. Proxy
 * headers are trusted only when the site has explicitly opted in, because
 * behind a misconfigured proxy X-Forwarded-For is attacker-controlled and any
 * allowlist built on it is decorative.
 *
 *   define( 'WPSH_TRUST_PROXY', true );  // only behind a proxy you control
 */
if ( ! function_exists( 'wpsh_client_ip' ) ) {
	function wpsh_client_ip() {
		if ( defined( 'WPSH_TRUST_PROXY' ) && WPSH_TRUST_PROXY && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts     = explode( ',', wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			$candidate = trim( $parts[0] );
			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$candidate = wp_unslash( $_SERVER['REMOTE_ADDR'] );
			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}
		return null;
	}
}

/**
 * Match an address against a single address or a CIDR range, for IPv4 and
 * IPv6 alike.
 *
 * Works on the packed byte form from inet_pton rather than on integers. ip2long
 * returns false for every IPv6 address, and its result is a signed 32-bit value
 * on a 32-bit build, so integer arithmetic on addresses is wrong in two
 * different ways at once. Bytes have neither problem and the two families need
 * no separate code path beyond refusing to compare across them.
 *
 * An address and a range from different families never match. That is correct
 * rather than convenient: the alternative is treating a mismatch as a match,
 * and this function decides who gets a login form.
 */
if ( ! function_exists( 'wpsh_ip_in_range' ) ) {
	function wpsh_ip_in_range( $ip, $range ) {
		$ip = is_string( $ip ) ? trim( $ip ) : '';

		$ip_bin = @inet_pton( $ip );
		if ( false === $ip_bin ) {
			return false;
		}

		$range = is_string( $range ) ? trim( $range ) : '';

		if ( false === strpos( $range, '/' ) ) {
			$range_bin = @inet_pton( $range );
			return false !== $range_bin && $range_bin === $ip_bin;
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );

		$subnet_bin = @inet_pton( trim( $subnet ) );
		if ( false === $subnet_bin ) {
			return false;
		}

		// Never compare an IPv4 address against an IPv6 range, or the reverse.
		if ( strlen( $subnet_bin ) !== strlen( $ip_bin ) ) {
			return false;
		}

		if ( '' === trim( $bits ) || ! ctype_digit( trim( $bits ) ) ) {
			return false;
		}

		$bits     = (int) trim( $bits );
		$max_bits = strlen( $ip_bin ) * 8;
		if ( $bits < 0 || $bits > $max_bits ) {
			return false;
		}

		$whole_bytes = intdiv( $bits, 8 );
		$spare_bits  = $bits % 8;

		if ( $whole_bytes > 0 && substr( $ip_bin, 0, $whole_bytes ) !== substr( $subnet_bin, 0, $whole_bytes ) ) {
			return false;
		}

		if ( 0 === $spare_bits ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $spare_bits ) ) & 0xFF );

		return ( $ip_bin[ $whole_bytes ] & $mask ) === ( $subnet_bin[ $whole_bytes ] & $mask );
	}
}
