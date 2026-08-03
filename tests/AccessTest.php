<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

defined( 'ABSPATH' ) || define( 'ABSPATH', __DIR__ );

require_once __DIR__ . '/../includes/class-spp-access.php';

/**
 * Unit tests for the access decision.
 *
 * SPP_Access is pure PHP with no WordPress calls, so it is tested directly
 * without booting WordPress.
 */
final class AccessTest extends TestCase {

	/**
	 * Settings with protection on and a password saved.
	 */
	private function settings( array $overrides = array() ): array {
		return array_merge(
			array(
				'enabled'         => true,
				'password_hash'   => '$P$Bexample',
				'allow_admins'    => true,
				'allow_logged_in' => false,
				'allow_feeds'     => false,
				'allow_rest'      => false,
			),
			$overrides
		);
	}

	/**
	 * An anonymous visitor with no cookie.
	 */
	private function context( array $overrides = array() ): array {
		return array_merge(
			array(
				'is_logged_in'       => false,
				'can_manage_options' => false,
				'is_feed'            => false,
				'is_rest'            => false,
				'has_valid_cookie'   => false,
			),
			$overrides
		);
	}

	public function test_anonymous_visitor_is_gated(): void {
		$this->assertTrue( SPP_Access::should_gate( $this->settings(), $this->context() ) );
	}

	public function test_disabled_protection_allows_everyone(): void {
		$settings = $this->settings( array( 'enabled' => false ) );
		$this->assertFalse( SPP_Access::should_gate( $settings, $this->context() ) );
	}

	public function test_empty_password_hash_fails_open(): void {
		$settings = $this->settings( array( 'password_hash' => '' ) );
		$this->assertFalse( SPP_Access::should_gate( $settings, $this->context() ) );
	}

	public function test_admin_allowed_when_allow_admins_is_on(): void {
		$context = $this->context(
			array(
				'is_logged_in'       => true,
				'can_manage_options' => true,
			)
		);
		$this->assertFalse( SPP_Access::should_gate( $this->settings(), $context ) );
	}

	public function test_admin_gated_when_allow_admins_is_off(): void {
		$settings = $this->settings( array( 'allow_admins' => false ) );
		$context  = $this->context(
			array(
				'is_logged_in'       => true,
				'can_manage_options' => true,
			)
		);
		$this->assertTrue( SPP_Access::should_gate( $settings, $context ) );
	}

	public function test_subscriber_gated_by_default(): void {
		$context = $this->context( array( 'is_logged_in' => true ) );
		$this->assertTrue( SPP_Access::should_gate( $this->settings(), $context ) );
	}

	public function test_subscriber_allowed_when_allow_logged_in_is_on(): void {
		$settings = $this->settings( array( 'allow_logged_in' => true ) );
		$context  = $this->context( array( 'is_logged_in' => true ) );
		$this->assertFalse( SPP_Access::should_gate( $settings, $context ) );
	}

	public function test_feed_gated_by_default(): void {
		$context = $this->context( array( 'is_feed' => true ) );
		$this->assertTrue( SPP_Access::should_gate( $this->settings(), $context ) );
	}

	public function test_feed_allowed_when_allow_feeds_is_on(): void {
		$settings = $this->settings( array( 'allow_feeds' => true ) );
		$context  = $this->context( array( 'is_feed' => true ) );
		$this->assertFalse( SPP_Access::should_gate( $settings, $context ) );
	}

	public function test_rest_gated_by_default(): void {
		$context = $this->context( array( 'is_rest' => true ) );
		$this->assertTrue( SPP_Access::should_gate( $this->settings(), $context ) );
	}

	public function test_rest_allowed_when_allow_rest_is_on(): void {
		$settings = $this->settings( array( 'allow_rest' => true ) );
		$context  = $this->context( array( 'is_rest' => true ) );
		$this->assertFalse( SPP_Access::should_gate( $settings, $context ) );
	}

	public function test_valid_cookie_allows_access(): void {
		$context = $this->context( array( 'has_valid_cookie' => true ) );
		$this->assertFalse( SPP_Access::should_gate( $this->settings(), $context ) );
	}

	public function test_missing_context_keys_default_to_denied(): void {
		$this->assertTrue( SPP_Access::should_gate( $this->settings(), array() ) );
	}

	public function test_missing_settings_keys_are_treated_as_disabled(): void {
		$this->assertFalse( SPP_Access::should_gate( array(), $this->context() ) );
	}

	private const NOW    = 1700000000;
	private const LATER  = 1700003600;

	public function test_token_is_stable_for_the_same_inputs(): void {
		$this->assertSame(
			SPP_Access::unlock_token( 'hash', 'salt', self::LATER ),
			SPP_Access::unlock_token( 'hash', 'salt', self::LATER )
		);
	}

	public function test_token_changes_when_the_password_hash_changes(): void {
		$this->assertNotSame(
			SPP_Access::unlock_token( 'hash-a', 'salt', self::LATER ),
			SPP_Access::unlock_token( 'hash-b', 'salt', self::LATER )
		);
	}

	public function test_token_changes_when_the_salt_changes(): void {
		$this->assertNotSame(
			SPP_Access::unlock_token( 'hash', 'salt-a', self::LATER ),
			SPP_Access::unlock_token( 'hash', 'salt-b', self::LATER )
		);
	}

	public function test_token_changes_when_the_expiry_changes(): void {
		$this->assertNotSame(
			SPP_Access::unlock_token( 'hash', 'salt', self::LATER ),
			SPP_Access::unlock_token( 'hash', 'salt', self::LATER + 1 )
		);
	}

	public function test_token_contains_no_password_hash_material(): void {
		$token = SPP_Access::unlock_token( 'super-secret-hash', 'salt', self::LATER );
		$this->assertStringNotContainsString( 'super-secret-hash', $token );
	}

	/**
	 * The signed message must carry a label nobody else uses, so this signature
	 * cannot collide with another consumer of the same shared auth salt.
	 */
	public function test_token_message_is_domain_separated(): void {
		$unlabelled = self::LATER . '.' . hash_hmac(
			'sha256',
			'hash|' . self::LATER,
			'salt'
		);

		$this->assertNotSame( $unlabelled, SPP_Access::unlock_token( 'hash', 'salt', self::LATER ) );
	}

	public function test_verify_token_accepts_a_matching_unexpired_token(): void {
		$token = SPP_Access::unlock_token( 'hash', 'salt', self::LATER );
		$this->assertTrue( SPP_Access::verify_token( $token, 'hash', 'salt', self::NOW ) );
	}

	public function test_verify_token_rejects_a_token_from_a_different_password(): void {
		$token = SPP_Access::unlock_token( 'old-hash', 'salt', self::LATER );
		$this->assertFalse( SPP_Access::verify_token( $token, 'new-hash', 'salt', self::NOW ) );
	}

	public function test_verify_token_rejects_an_empty_candidate(): void {
		$this->assertFalse( SPP_Access::verify_token( '', 'hash', 'salt', self::NOW ) );
	}

	/**
	 * With no password set, no cookie may ever verify. Otherwise a token minted
	 * while the password was empty would keep working after one was set.
	 */
	public function test_verify_token_rejects_everything_when_no_password_is_set(): void {
		$token = SPP_Access::unlock_token( '', 'salt', self::LATER );
		$this->assertFalse( SPP_Access::verify_token( $token, '', 'salt', self::NOW ) );
	}

	public function test_verify_token_rejects_an_expired_token(): void {
		$token = SPP_Access::unlock_token( 'hash', 'salt', self::NOW - 1 );
		$this->assertFalse( SPP_Access::verify_token( $token, 'hash', 'salt', self::NOW ) );
	}

	public function test_verify_token_rejects_a_token_expiring_exactly_now(): void {
		$token = SPP_Access::unlock_token( 'hash', 'salt', self::NOW );
		$this->assertFalse( SPP_Access::verify_token( $token, 'hash', 'salt', self::NOW ) );
	}

	/**
	 * The expiry is inside the signature, so extending it must break the HMAC
	 * rather than buying more time.
	 */
	public function test_verify_token_rejects_a_tampered_expiry(): void {
		$token  = SPP_Access::unlock_token( 'hash', 'salt', self::NOW - 1 );
		$parts  = explode( '.', $token, 2 );
		$forged = ( self::LATER ) . '.' . $parts[1];

		$this->assertFalse( SPP_Access::verify_token( $forged, 'hash', 'salt', self::NOW ) );
	}

	public function test_verify_token_rejects_a_malformed_candidate(): void {
		$this->assertFalse( SPP_Access::verify_token( 'no-separator', 'hash', 'salt', self::NOW ) );
		$this->assertFalse( SPP_Access::verify_token( '.', 'hash', 'salt', self::NOW ) );
		$this->assertFalse( SPP_Access::verify_token( '123.', 'hash', 'salt', self::NOW ) );
		$this->assertFalse( SPP_Access::verify_token( '.abc', 'hash', 'salt', self::NOW ) );
	}

	/**
	 * Values like "9e99" cast to a huge int, so they must be rejected before the
	 * cast rather than after it.
	 */
	public function test_verify_token_rejects_a_non_numeric_expiry(): void {
		$this->assertFalse( SPP_Access::verify_token( '9e99.abc', 'hash', 'salt', self::NOW ) );
		$this->assertFalse( SPP_Access::verify_token( ' 123.abc', 'hash', 'salt', self::NOW ) );
		$this->assertFalse( SPP_Access::verify_token( '-1.abc', 'hash', 'salt', self::NOW ) );
	}
}
