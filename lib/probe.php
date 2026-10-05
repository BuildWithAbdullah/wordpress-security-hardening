<?php
/**
 * The bridge the test suite drives the plugins through.
 *
 * Reads one JSON request on stdin, writes one JSON response on stdout. Part of
 * the test harness; never installed on a site.
 *
 *   {
 *     "state":     { "is_ssl": true, "logged_in": false, "caps": [], ... },
 *     "constants": { "ALLOWED_LOGIN_IPS": ["203.0.113.0/24"] },
 *     "load":      ["mu-plugins/00-security-headers.php"],
 *     "ops":       [ { "op": "apply_filters", "tag": "wp_headers", "value": {} },
 *                    { "op": "do_action", "tag": "xmlrpc_call",
*                      "args": ["pingback.ping"] },
 *                    { "op": "call", "fn": "wpsh_ip_in_range",
 *                      "args": ["203.0.113.10", "203.0.113.0/24"] } ]
 *   }
 *
 * Constants are defined before the plugin loads, because a plugin that reads a
 * constant at registration time cannot be reconfigured afterwards. Each request
 * is a fresh PHP process for the same reason: constants and function
 * definitions cannot be unwound inside one.
 */

require __DIR__ . '/wp-shim.php';

$root = dirname( __DIR__ );
$raw  = stream_get_contents( STDIN );
$req  = json_decode( $raw, true );

if ( ! is_array( $req ) ) {
	fwrite( STDERR, "probe: could not parse the request as JSON\n" );
	exit( 2 );
}

foreach ( (array) ( $req['state'] ?? array() ) as $key => $value ) {
	WPShim::$state[ $key ] = $value;
}

$_GET    = (array) WPShim::state( 'get', array() );
$_SERVER = array_merge( $_SERVER, (array) WPShim::state( 'server', array() ) );

/**
 * wp-login.php exposes the WP_Error it is about to render as a global named
 * $errors, and the login_errors filter has to read it to know whether it is
 * looking at a failure or a notice. Set it up the same way here.
 */
if ( array_key_exists( 'error_codes', $req ) ) {
	$GLOBALS['errors'] = new WP_Error( (array) $req['error_codes'] );
}

foreach ( (array) ( $req['constants'] ?? array() ) as $name => $value ) {
	if ( ! defined( $name ) ) {
		define( $name, $value );
	}
}

foreach ( (array) ( $req['load'] ?? array() ) as $relative ) {
	$path = $root . '/' . ltrim( $relative, '/' );
	if ( ! is_file( $path ) ) {
		fwrite( STDERR, "probe: no such file: $relative\n" );
		exit( 2 );
	}
	require $path;
}

$results = array();

foreach ( (array) ( $req['ops'] ?? array() ) as $index => $op ) {
	$kind   = $op['op'] ?? '';
	$record = array( 'op' => $kind );

	try {
		switch ( $kind ) {
			case 'apply_filters':
				$record['value'] = apply_filters( $op['tag'], $op['value'] ?? null );
				break;

			case 'do_action':
				$args = array_merge( array( $op['tag'] ), (array) ( $op['args'] ?? array() ) );
				call_user_func_array( 'do_action', $args );
				$record['value'] = null;
				break;

			case 'call':
				if ( ! function_exists( $op['fn'] ) ) {
					$record['error'] = 'undefined function ' . $op['fn'];
					break;
				}
				$record['value'] = call_user_func_array( $op['fn'], (array) ( $op['args'] ?? array() ) );
				break;

			case 'registered':
				$record['value'] = array();
				foreach ( (array) $op['tags'] as $tag ) {
					$record['value'][ $tag ] = count( WPShim::callbacks( $tag ) );
				}
				break;

			default:
				$record['error'] = 'unknown op ' . $kind;
		}
	} catch ( WPShimExit $e ) {
		$record['exited'] = true;
	} catch ( WPShimDie $e ) {
		$record['died']   = true;
		$record['status'] = isset( $e->args['response'] ) ? (int) $e->args['response'] : 0;
	} catch ( Throwable $e ) {
		$record['error'] = get_class( $e ) . ': ' . $e->getMessage();
	}

	$results[ $index ] = $record;
}

echo json_encode(
	array(
		'results' => $results,
		'events'  => WPShim::$events,
		'removed' => WPShim::$removed,
	),
	JSON_UNESCAPED_SLASHES
);
