<?php
/**
 * A hook registry that is not WordPress.
 *
 * The three files in mu-plugins/ are ordinary WordPress plugins: they register
 * callbacks and let WordPress call them. That makes them hard to test, because
 * the interesting behaviour only happens once something fires a hook.
 *
 * This file provides the smallest set of WordPress functions those three files
 * touch, backed by a registry that tests can fire by hand. It is a
 * test harness and nothing else: never loaded on a live site, never installed
 * in mu-plugins/, and implementing no WordPress behaviour beyond what the
 * plugins under test actually call.
 *
 * What that buys: every filter and action in the repository can be invoked,
 * with controlled state, and its return value asserted on. No database, no web
 * server, no WordPress download, no network.
 *
 * What it does not buy: proof that WordPress fires these hooks when and where
 * the plugins assume. That assumption is the one thing a shim cannot check,
 * and it is written down in docs/06-what-the-checks-do-not-see.md.
 */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Thrown in place of terminating the request. */
class WPShimDie extends Exception {
	public $title;
	public $args;
	public function __construct( $message, $title = '', $args = array() ) {
		parent::__construct( (string) $message );
		$this->title = $title;
		$this->args  = $args;
	}
}

/** Thrown in place of exit() after a redirect. */
class WPShimExit extends Exception {}

class WPShim {

	/** @var array tag => list of array( priority, callable ) */
	public static $hooks = array();

	/** @var array tag => list of callables or names that were removed */
	public static $removed = array();

	/** @var array */
	public static $state = array();

	/** @var array */
	public static $events = array();

	public static function reset() {
		self::$hooks   = array();
		self::$removed = array();
		self::$events  = array(
			'redirects'    => array(),
			'dies'         => array(),
			'sent_headers' => array(),
		);
		self::$state = array(
			'is_ssl'      => true,
			'is_admin'    => false,
			'logged_in'   => false,
			'caps'        => array(),
			'is_author'   => false,
			'doing_ajax'  => false,
			'get'         => array(),
			'server'      => array( 'REMOTE_ADDR' => '203.0.113.10' ),
			'home_url'    => 'https://example.test',
		);
	}

	public static function state( $key, $default = null ) {
		return array_key_exists( $key, self::$state ) ? self::$state[ $key ] : $default;
	}

	/** Callbacks for a tag, in priority order, with registration order preserved. */
	public static function callbacks( $tag ) {
		if ( empty( self::$hooks[ $tag ] ) ) {
			return array();
		}
		$list = self::$hooks[ $tag ];
		// usort is not stable on every PHP build, so sort on the pair.
		usort(
			$list,
			function ( $a, $b ) {
				if ( $a[0] === $b[0] ) {
					return $a[2] <=> $b[2];
				}
				return $a[0] <=> $b[0];
			}
		);
		return $list;
	}
}

WPShim::reset();

function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
	static $seq = 0;
	WPShim::$hooks[ $tag ][] = array( (int) $priority, $callback, $seq++, (int) $accepted_args );
	return true;
}

function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
	return add_filter( $tag, $callback, $priority, $accepted_args );
}

function apply_filters( $tag, $value ) {
	$extra = array_slice( func_get_args(), 2 );
	foreach ( WPShim::callbacks( $tag ) as $entry ) {
		$args  = array_merge( array( $value ), $extra );
		$args  = array_slice( $args, 0, max( 1, $entry[3] ) );
		$value = call_user_func_array( $entry[1], $args );
	}
	return $value;
}

function do_action( $tag ) {
	$extra = array_slice( func_get_args(), 1 );
	foreach ( WPShim::callbacks( $tag ) as $entry ) {
		call_user_func_array( $entry[1], array_slice( $extra, 0, $entry[3] ) );
	}
}

function remove_action( $tag, $callback, $priority = 10 ) {
	WPShim::$removed[ $tag ][] = is_string( $callback ) ? $callback : 'closure';
	return true;
}

function remove_filter( $tag, $callback, $priority = 10 ) {
	return remove_action( $tag, $callback, $priority );
}

function has_action( $tag, $callback = false ) {
	return ! empty( WPShim::$hooks[ $tag ] );
}

function has_filter( $tag, $callback = false ) {
	return has_action( $tag, $callback );
}

function __( $text, $domain = null ) {
	return $text;
}

function esc_html__( $text, $domain = null ) {
	return $text;
}

function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}

function __return_false() {
	return false;
}

function __return_true() {
	return true;
}

function is_ssl() {
	return (bool) WPShim::state( 'is_ssl' );
}

function is_admin() {
	return (bool) WPShim::state( 'is_admin' );
}

function is_user_logged_in() {
	return (bool) WPShim::state( 'logged_in' );
}

function current_user_can( $capability ) {
	return in_array( $capability, (array) WPShim::state( 'caps', array() ), true );
}

function is_author() {
	return (bool) WPShim::state( 'is_author' );
}

function home_url( $path = '' ) {
	return rtrim( (string) WPShim::state( 'home_url' ), '/' ) . $path;
}

function wp_safe_redirect( $location, $status = 302 ) {
	WPShim::$events['redirects'][] = array(
		'location' => $location,
		'status'   => (int) $status,
		'safe'     => true,
	);
	throw new WPShimExit( 'redirect' );
}

function wp_redirect( $location, $status = 302 ) {
	WPShim::$events['redirects'][] = array(
		'location' => $location,
		'status'   => (int) $status,
		'safe'     => false,
	);
	throw new WPShimExit( 'redirect' );
}

function wp_die( $message = '', $title = '', $args = array() ) {
	WPShim::$events['dies'][] = array(
		'message' => (string) $message,
		'title'   => (string) $title,
		'status'  => isset( $args['response'] ) ? (int) $args['response'] : 0,
	);
	throw new WPShimDie( $message, $title, $args );
}

/** Minimal stand-in for the WP_Error shape the login filter reads. */
class WP_Error {
	private $codes;
	public function __construct( $codes = array() ) {
		$this->codes = (array) $codes;
	}
	public function get_error_codes() {
		return $this->codes;
	}
}

function wp_doing_ajax() {
	return (bool) WPShim::state( 'doing_ajax', false );
}

function wp_unslash( $value ) {
	if ( is_array( $value ) ) {
		return array_map( 'wp_unslash', $value );
	}
	return is_string( $value ) ? stripslashes( $value ) : $value;
}

function remove_query_arg( $key, $url ) {
	$parts = explode( '?', (string) $url, 2 );
	if ( count( $parts ) < 2 || '' === $parts[1] ) {
		return $parts[0];
	}
	$keep = array();
	foreach ( explode( '&', $parts[1] ) as $pair ) {
		if ( '' === $pair ) {
			continue;
		}
		$name = explode( '=', $pair, 2 )[0];
		if ( urldecode( $name ) === $key ) {
			continue;
		}
		$keep[] = $pair;
	}
	return $keep ? $parts[0] . '?' . implode( '&', $keep ) : $parts[0];
}

/**
 * The plugins send headers through wpsh_send_headers(), and each defines it
 * behind a function_exists guard. Defining it here first, before any plugin is
 * loaded, means the real action callback runs and the real header set is
 * recorded rather than handed to PHP's header(), which is a no-op under the
 * CLI SAPI and cannot be observed afterwards.
 *
 * The guard in the plugin is ordinary defensive practice, not a hook for the
 * tests: these files get pasted into theme functions.php as often as they get
 * installed properly, and a redeclare there is a fatal error.
 */
function wpsh_send_headers( $headers ) {
	foreach ( (array) $headers as $name => $value ) {
		WPShim::$events['sent_headers'][] = array(
			'name'  => $name,
			'value' => $value,
		);
	}
}
