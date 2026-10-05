<?php
/**
 * Corrected example: the same allowlist on packed bytes.
 *
 * inet_pton handles both families and returns the address as bytes, so the
 * prefix comparison is a byte comparison plus one masked byte. No integers, so
 * no sign problem and no 32-bit assumption, and IPv6 needs no separate code
 * path beyond refusing to compare across families.
 *
 * Refusing a cross-family comparison is deliberate. The alternative is
 * treating a mismatch as a match, in a function that decides who is shown a
 * login form.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_ip_in_range( $ip, $range ) {
	$ip_bin = @inet_pton( is_string( $ip ) ? trim( $ip ) : '' );
	if ( false === $ip_bin ) {
		return false;
	}

	$range = is_string( $range ) ? trim( $range ) : '';

	if ( false === strpos( $range, '/' ) ) {
		$range_bin = @inet_pton( $range );
		return false !== $range_bin && $range_bin === $ip_bin;
	}

	list( $subnet, $bits ) = explode( '/', $range, 2 );

	$subnet_bin = @inet_pton( trim( $subnet ) );
	if ( false === $subnet_bin || strlen( $subnet_bin ) !== strlen( $ip_bin ) ) {
		return false;
	}

	if ( ! ctype_digit( trim( $bits ) ) ) {
		return false;
	}

	$bits = (int) trim( $bits );
	if ( $bits < 0 || $bits > strlen( $ip_bin ) * 8 ) {
		return false;
	}

	$whole_bytes = intdiv( $bits, 8 );
	$spare_bits  = $bits % 8;

	if ( $whole_bytes > 0 && substr( $ip_bin, 0, $whole_bytes ) !== substr( $subnet_bin, 0, $whole_bytes ) ) {
		return false;
	}

	if ( 0 === $spare_bits ) {
		return true;
	}

	$mask = chr( ( 0xFF << ( 8 - $spare_bits ) ) & 0xFF );

	return ( $ip_bin[ $whole_bytes ] & $mask ) === ( $subnet_bin[ $whole_bytes ] & $mask );
}
