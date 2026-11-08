<?php
/**
 * Corrected example: the default restricts nothing a store needs.
 *
 * payment is out of the default list and the override is documented, so a site
 * with no wallet checkout can restrict it deliberately:
 *
 *   define( 'WPSH_PERMISSIONS_POLICY', 'geolocation=(), camera=(), microphone=(), payment=(), usb=()' );
 *
 * The principle is worth stating because it decides the other directives too. A
 * file that is meant to be installed without reading it has to default to the
 * restrictions whose absence costs nothing and whose presence breaks nothing.
 * Everything else belongs behind a constant with a note about what it breaks.
 *
 * geolocation, camera and microphone stay in the default. A store locator, a
 * video consultation and a voice search all need one of them, which is why
 * they are named in the file as things to check first, but none of them is
 * present on a site that has not deliberately built it. A wallet checkout is
 * different: it arrives with the payment gateway, nobody builds it, and most
 * store owners do not know it is a browser feature at all.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_header_set( $context, $is_ssl ) {
	$headers = array();

	$headers['X-Content-Type-Options'] = 'nosniff';
	$headers['X-Frame-Options']        = 'SAMEORIGIN';
	$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';

	$headers['Permissions-Policy'] = defined( 'WPSH_PERMISSIONS_POLICY' )
		? WPSH_PERMISSIONS_POLICY
		: 'geolocation=(), camera=(), microphone=(), usb=()';

	if ( $is_ssl ) {
		$headers['Strict-Transport-Security'] = 'max-age=31536000';
	}

	return $headers;
}
