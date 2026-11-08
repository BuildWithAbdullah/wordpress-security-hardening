<?php
/**
 * Failing example: an address allowlist that reads the client's own claim.
 *
 * This is the version of this function that is in every snippet, and the
 * comment above it is usually the one that was in version 2 of
 * mu-plugins/02-harden-login.php: proxy headers are unsafe behind a
 * misconfigured proxy, so gate them behind an opt-in and trust them once the
 * site says it is behind one.
 *
 * That reasoning is wrong, and it is wrong in the direction that matters.
 * X-Forwarded-For is a list that grows on the right. Each proxy appends the
 * address it received the request from; none of them clears what was already
 * there. So for a visitor C behind one proxy P the chain is
 *
 *     <anything C invented>, C, P
 *
 * where P is REMOTE_ADDR. The leftmost entry is the one place in the whole
 * request that is always under the client's control, and it is the one this
 * function returns.
 *
 * What that costs: an attacker sends
 *
 *     X-Forwarded-For: 203.0.113.10
 *
 * to a site whose allowlist contains 203.0.113.0/24, and is shown the login
 * form. The feature whose only job is to decide who sees that form has handed
 * the decision to the person it is judging. Nothing in the logs looks unusual,
 * because the request is ordinary and the header is one a CDN sends too.
 *
 * Corrected in 23-xff-leftmost-trusted.pass.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_client_ip() {
	if ( defined( 'WPSH_TRUSTED_PROXY_HOPS' ) && (int) WPSH_TRUSTED_PROXY_HOPS > 0
		&& ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$parts     = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
		$candidate = trim( $parts[0] );
		if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
			return $candidate;
		}
	}

	if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
		$candidate = trim( $_SERVER['REMOTE_ADDR'] );
		if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
			return $candidate;
		}
	}

	return null;
}
