<?php
/**
 * Corrected example: zero means zero, and not sending it is a separate choice.
 *
 * Two different intentions were sharing one setting, which is why the defect
 * was easy to write. "Withdraw the policy" and "do not deploy the policy" are
 * not the same instruction and they need different headers: the first is
 * max-age=0, which actively tells browsers to forget what they know, and the
 * second is no header at all.
 *
 * So they are two settings now. WPSH_HSTS_MAX_AGE of zero sends max-age=0.
 * WPSH_HSTS set to false sends nothing.
 *
 * A negative value is clamped to zero rather than refused, because a negative
 * max age has no meaning and the nearest thing the operator can have meant is
 * the back-out.
 *
 * The pairing with the checker is deliberate. scripts/judge-headers.sh reports
 * max-age=0 as hsts/disabled at error level, so a back-out that is left in
 * place fails the next post-deploy check rather than sitting there as a site
 * that quietly has no HSTS.
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

	$send_hsts = ! defined( 'WPSH_HSTS' ) || WPSH_HSTS;

	if ( $is_ssl && $send_hsts ) {
		$max_age = defined( 'WPSH_HSTS_MAX_AGE' ) ? (int) WPSH_HSTS_MAX_AGE : 31536000;
		if ( $max_age < 0 ) {
			$max_age = 0;
		}
		$headers['Strict-Transport-Security'] = 'max-age=' . $max_age;
	}

	return $headers;
}
