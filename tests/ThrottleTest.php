<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

defined( 'ABSPATH' ) || define( 'ABSPATH', __DIR__ );

require_once __DIR__ . '/../includes/class-spp-throttle.php';

/**
 * Unit tests for the throttle's client-address bucketing.
 *
 * SPP_Throttle::ip_bucket() is pure byte work with no WordPress calls, so it is
 * tested directly without booting WordPress.
 */
final class ThrottleTest extends TestCase {

	public function test_ipv4_is_counted_whole(): void {
		$this->assertSame( '203.0.113.7', SPP_Throttle::ip_bucket( '203.0.113.7' ) );
		$this->assertSame( '10.0.0.1', SPP_Throttle::ip_bucket( '10.0.0.1' ) );
	}

	public function test_two_ipv4_addresses_get_separate_buckets(): void {
		$this->assertNotSame(
			SPP_Throttle::ip_bucket( '203.0.113.7' ),
			SPP_Throttle::ip_bucket( '203.0.113.8' )
		);
	}

	public function test_ipv6_is_masked_to_its_64(): void {
		$this->assertSame( '2001:db8:1:2::/64', SPP_Throttle::ip_bucket( '2001:db8:1:2:3:4:5:6' ) );
	}

	/**
	 * The whole point of the mask: one allocation is one attempt budget.
	 */
	public function test_addresses_in_one_ipv6_64_share_a_bucket(): void {
		$first  = SPP_Throttle::ip_bucket( '2001:db8:abcd:1234::1' );
		$second = SPP_Throttle::ip_bucket( '2001:db8:abcd:1234:ffff:ffff:ffff:ffff' );

		$this->assertSame( $first, $second );
	}

	public function test_different_ipv6_64s_do_not_share_a_bucket(): void {
		$this->assertNotSame(
			SPP_Throttle::ip_bucket( '2001:db8:abcd:1234::1' ),
			SPP_Throttle::ip_bucket( '2001:db8:abcd:1235::1' )
		);
	}

	/**
	 * Masking these would collapse every IPv4 client into one shared bucket,
	 * turning the fix into a site-wide lockout.
	 */
	public function test_ipv4_mapped_addresses_are_not_masked(): void {
		$first  = SPP_Throttle::ip_bucket( '::ffff:203.0.113.7' );
		$second = SPP_Throttle::ip_bucket( '::ffff:203.0.113.8' );

		$this->assertNotSame( $first, $second );
		$this->assertStringNotContainsString( '/64', $first );
	}

	public function test_loopback_and_unspecified_are_not_masked(): void {
		$this->assertStringNotContainsString( '/64', SPP_Throttle::ip_bucket( '::1' ) );
		$this->assertStringNotContainsString( '/64', SPP_Throttle::ip_bucket( '::' ) );
	}

	public function test_empty_and_malformed_input_is_returned_unchanged(): void {
		$this->assertSame( '', SPP_Throttle::ip_bucket( '' ) );
		$this->assertSame( 'not-an-ip', SPP_Throttle::ip_bucket( 'not-an-ip' ) );
	}

	public function test_link_local_ipv6_is_masked(): void {
		$this->assertSame( 'fe80::/64', SPP_Throttle::ip_bucket( 'fe80::1234:5678:9abc:def0' ) );
	}
}
