<?php
/**
 * Plugin Name:  Disable XML-RPC Authentication
 * Description:  Closes the XML-RPC authentication surface, including the
 *               multicall amplification that makes it useful for brute force.
 * Version:      1.0.0
 * Author:       Abdullah Shabbir
 * License:      MIT
 *
 * Install: wp-content/mu-plugins/
 *
 * ---------------------------------------------------------------------------
 * Why this matters more than its reputation suggests
 *
 * xmlrpc.php accepts unauthenticated POST requests and will happily check
 * credentials for you. Two things make it attractive to attackers:
 *
 *   1. system.multicall lets a single HTTP request carry hundreds of
 *      credential attempts. A login rate limiter that counts requests sees
 *      one request and lets it through, while the endpoint processes 500
 *      password guesses.
 *
 *   2. pingback.ping can be used to make the site issue outbound requests to
 *      a target of the attacker's choosing, turning it into a small
 *      participant in a reflection attack against somebody else.
 *
 * Check before disabling. Legitimate users of XML-RPC still exist: the
 * WordPress mobile app on older configurations, some Jetpack features, and a
 * few remote publishing and backup tools. Search the access log for
 * xmlrpc.php requests that returned 200 and came from something other than an
 * obvious scanner before you switch it off.
 *
 * The approach here disables authentication and the pingback methods rather
 * than blocking the file outright, which leaves any harmless read-only use
 * working. To block it entirely, do it at the server level so the request
 * never reaches PHP at all; see docs/02-xmlrpc.md.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Refuse XML-RPC authentication. */
add_filter( 'xmlrpc_enabled', '__return_false' );

/**
 * xmlrpc_enabled alone leaves the pingback methods reachable, because they do
 * not authenticate. Remove them explicitly.
 */
add_filter(
	'xmlrpc_methods',
	function ( $methods ) {
		unset(
			$methods['pingback.ping'],
			$methods['pingback.extensions.getPingbacks'],
			$methods['system.multicall'],
			$methods['system.listMethods'],
			$methods['system.getCapabilities']
		);
		return $methods;
	}
);

/** Stop advertising the endpoint in the head and in response headers. */
remove_action( 'wp_head', 'rsd_link' );

add_filter(
	'wp_headers',
	function ( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
);

/**
 * Some hosts and plugins re-enable pingbacks. Belt and braces: reject the
 * pingback ping at the point of execution.
 */
add_action(
	'xmlrpc_call',
	function ( $method ) {
		if ( 'pingback.ping' === $method ) {
			wp_die(
				'Pingback is disabled on this site.',
				'Pingback disabled',
				array( 'response' => 403 )
			);
		}
	}
);
