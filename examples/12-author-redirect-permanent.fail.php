<?php
/**
 * Failing example: the author archive block as a permanent redirect.
 *
 * 301 is the obvious choice, because the intent really is permanent. The
 * problem is that a browser caches a 301 and stops asking, often for as long as
 * the profile lives. Turn author archives back on a year later and returning
 * visitors still cannot reach them, and no server-side change fixes it.
 *
 * A hardening measure should never be the one thing that cannot be undone.
 *
 * Corrected in 12-author-redirect-permanent.pass.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'template_redirect',
	function () {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		if ( isset( $_GET['author'] ) || is_author() ) {
			wp_safe_redirect( home_url(), 301 );
			exit;
		}
	}
);
