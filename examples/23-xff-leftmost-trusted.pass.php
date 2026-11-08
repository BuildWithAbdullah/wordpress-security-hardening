<?php
/**
 * Corrected example: count in from the end the site's own machines wrote.
 *
 * The chain is ordered and the ordering is the fix. Everything the client could
 * have invented is on the left. Everything a machine the site owns wrote is on
 * the right, ending in REMOTE_ADDR, which cannot be forged at all because it is
 * the peer the kernel is talking to.
 *
 * So the site says how many proxies sit in front of PHP and the lookup walks
 * that many entries in from the right. With one proxy the visitor is the entry
 * one place in from the end, whatever a forged header put in front of it.
 *
 * Two cases are worth noticing because they are the ones that decide whether
 * this is safe in practice.
 *
 * A request that reaches the origin directly, bypassing the CDN, carries no
 * X-Forwarded-For at all. There is nothing to count into, and REMOTE_ADDR is
 * both the visitor and unforgeable, so that is the answer.
 *
 * A chain shorter than the declared number of hops means the site is claiming
 * proxies that are not there. Taking the leftmost entry in that case is exactly
 * the defect this file exists to correct, so it refuses to answer instead. The
 * caller treats null as "cannot establish" and does not lock anyone out, which
 * makes a wrong hop count loud rather than quietly forgeable.
 *
 * The one case this cannot defend against is a hop count set higher than the
 * number of proxies that really exist. That is stated as a limit rather than
 * papered over, because there is no signal in the request that distinguishes a
 * real proxy's entry from an invented one.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_client_ip() {
	$peer = ! empty( $_SERVER['REMOTE_ADDR'] ) ? trim( $_SERVER['REMOTE_ADDR'] ) : '';

	$hops = 0;
	if ( defined( 'WPSH_TRUSTED_PROXY_HOPS' ) ) {
		$hops = max( 0, (int) WPSH_TRUSTED_PROXY_HOPS );
	} elseif ( defined( 'WPSH_TRUST_PROXY' ) && WPSH_TRUST_PROXY ) {
		$hops = 1;
	}

	$forwarded = array();
	if ( $hops > 0 && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		foreach ( explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ) as $part ) {
			$part = trim( $part );
			if ( '' !== $part ) {
				$forwarded[] = $part;
			}
		}
	}

	if ( ! $forwarded ) {
		return filter_var( $peer, FILTER_VALIDATE_IP ) ? $peer : null;
	}

	$chain = array_merge( $forwarded, array( $peer ) );
	$index = count( $chain ) - 1 - $hops;

	if ( $index < 0 ) {
		return null;
	}

	$candidate = $chain[ $index ];

	return filter_var( $candidate, FILTER_VALIDATE_IP ) ? $candidate : null;
}
