<?php
/**
 * Corrected example: the generic message only where authentication failed.
 *
 * wp-login.php exposes the WP_Error it is about to render as a global named
 * $errors. No error codes means the page is showing a notice rather than
 * reporting a failure, so there is nothing to genericise and the message is
 * returned untouched.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter(
	'login_errors',
	function ( $message ) {
		global $errors;

		$codes = ( $errors instanceof WP_Error ) ? $errors->get_error_codes() : array();
		if ( ! $codes ) {
			return $message;
		}

		$auth = array_intersect(
			$codes,
			array(
				'invalid_username',
				'invalid_email',
				'incorrect_password',
				'authentication_failed',
				'empty_password',
				'invalidcombo',
			)
		);

		if ( ! $auth ) {
			return $message;
		}

		return __( 'The username or password you entered is not correct.' );
	}
);
