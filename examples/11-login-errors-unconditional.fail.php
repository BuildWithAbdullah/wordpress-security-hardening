<?php
/**
 * Failing example: the generic login message applied to every notice.
 *
 * This is how the defect arrives. The intent is right, the one-line filter
 * looks right, and it is what nearly every hardening snippet on the internet
 * shows. What it misses is that wp-login.php puts more than failed
 * authentication through login_errors.
 *
 * The visible result: a user clicks Log Out and is told their password is
 * wrong. A user requests a reset link and is told their password is wrong. Both
 * get reported as a login bug months later, by which point nobody connects it
 * to a security change.
 *
 * Corrected in 11-login-errors-unconditional.pass.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter(
	'login_errors',
	function () {
		return __( 'The username or password you entered is not correct.' );
	}
);
