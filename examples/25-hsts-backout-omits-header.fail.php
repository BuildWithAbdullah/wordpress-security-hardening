<?php
/**
 * Failing example: a max age of zero that sends no header.
 *
 * The guard looks like defensive programming. A max age of zero is not a
 * deployment, so do not send the header. Version 2 of
 * mu-plugins/00-security-headers.php had exactly this.
 *
 * It is wrong because HSTS lives in the browser, not in the response. Once a
 * browser has seen the header it refuses to reach the site over HTTP for the
 * whole of the original max age, and nothing the site stops doing changes
 * that. Sending no header is not a withdrawal; it is silence, and the policy
 * carries on applying.
 *
 * The only way to withdraw HSTS is to serve max-age=0 and keep serving it until
 * the old policy has expired in every browser that saw it. So the one operator
 * who most needs the header sent is the one this guard refuses to send it for:
 * somebody whose certificate is about to lapse, who has worked out that they
 * need to back the policy out, who sets the constant to zero, and whose site
 * then goes quiet while every returning visitor keeps being forced to HTTPS.
 *
 * Corrected in 25-hsts-backout-omits-header.pass.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_header_set( $context, $is_ssl ) {
	$headers = array();

	$headers['X-Content-Type-Options'] = 'nosniff';
	$headers['X-Frame-Options']        = 'SAMEORIGIN';
	$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
	$headers['Permissions-Policy']     = 'geolocation=(), camera=(), microphone=(), usb=()';

	if ( $is_ssl ) {
		$max_age = defined( 'WPSH_HSTS_MAX_AGE' ) ? (int) WPSH_HSTS_MAX_AGE : 31536000;
		if ( $max_age > 0 ) {
			$headers['Strict-Transport-Security'] = 'max-age=' . $max_age;
		}
	}

	return $headers;
}
