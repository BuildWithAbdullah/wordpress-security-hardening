<?php
/**
 * Failing example: a default Permissions-Policy that switches off checkout.
 *
 * The list reads like a sensible default and it is the one that gets copied,
 * because every directive in it names a feature an ordinary content site does
 * not use. payment=() is the one that does not belong, and version 2 of
 * mu-plugins/00-security-headers.php shipped it.
 *
 * payment=() switches off the Payment Request API. Apple Pay and Google Pay
 * buttons are built on it, as is every express checkout a store is likely to
 * have, so dropping this file onto a WooCommerce site removes the fast
 * checkout and leaves the ordinary card form working.
 *
 * That is the worst available shape for a defect in a hardening file. Nothing
 * errors. Nothing appears in a log. The express button is simply not rendered,
 * which looks like a theme problem or a payment gateway problem, and it is
 * noticed weeks later by someone comparing conversion rates. The file's own
 * list of features to check before deploying named geolocation, camera and
 * microphone, and did not mention payment at all.
 *
 * A site that has no wallet checkout should restrict payment, and the
 * corrected file says so. It just cannot be the default in a file whose first
 * line promises headers that are safe on essentially any WordPress site.
 *
 * Corrected in 24-permissions-policy-blocks-payment.pass.php.
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
		: 'geolocation=(), camera=(), microphone=(), payment=(), usb=()';

	if ( $is_ssl ) {
		$headers['Strict-Transport-Security'] = 'max-age=31536000';
	}

	return $headers;
}
