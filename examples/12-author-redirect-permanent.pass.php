<?php
/**
 * Corrected example: the same block as a temporary redirect.
 *
 * 302 costs nothing. The enumeration route is closed exactly as firmly,
 * because the redirect still happens on every request, and the decision stays
 * reversible from the server.
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
			wp_safe_redirect( home_url( '/' ), 302 );
			exit;
		}
	}
);
