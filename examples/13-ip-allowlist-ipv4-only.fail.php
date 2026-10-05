<?php
/**
 * Failing example: an address allowlist built on integer arithmetic.
 *
 * ip2long is the standard way to do this and it is in every snippet. It
 * returns false for every IPv6 address, so this matcher answers "not
 * allowed" for an IPv6 client no matter what is in the list.
 *
 * What that costs in practice: the administrator is on a dual-stack
 * connection, which is most of them, the browser picks IPv6, and they are
 * refused the login form while the IPv4 address they read off a web page and
 * sent you sits in the allowlist. Getting back in means SFTP. The one failure
 * mode the feature is warned about is built into it.
 *
 * It is also wrong in a second, quieter way: ip2long returns a signed value on
 * a 32-bit build, so the mask arithmetic goes wrong for any address above
 * 127.255.255.255 on those hosts.
 *
 * Corrected in 13-ip-allowlist-ipv4-only.pass.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

function wpsh_ip_in_range( $ip, $range ) {
	if ( false === strpos( $range, '/' ) ) {
		return $ip === $range;
	}

	list( $subnet, $bits ) = explode( '/', $range, 2 );
	$bits = (int) $bits;

	$ip_long     = ip2long( $ip );
	$subnet_long = ip2long( $subnet );

	if ( false === $ip_long || false === $subnet_long || $bits < 0 || $bits > 32 ) {
		return false;
	}

	$mask = -1 << ( 32 - $bits );
	return ( $ip_long & $mask ) === ( $subnet_long & $mask );
}
