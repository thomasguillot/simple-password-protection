<?php
/**
 * Access decision. Pure PHP — no WordPress functions may be called here.
 *
 * @package SimplePasswordProtection
 */

defined( 'ABSPATH' ) || exit;

/**
 * Decides whether a request must be blocked, and derives unlock tokens.
 */
class SPP_Access {

	const TOKEN_LABEL = 'spp-unlock|v1';

	/**
	 * Whether this request should be blocked by the gate.
	 *
	 * @param array $settings Plugin settings.
	 * @param array $context  Request context: is_logged_in, can_manage_options,
	 *                        is_feed, is_rest, has_valid_cookie.
	 * @return bool True when the request must be blocked.
	 */
	public static function should_gate( $settings, $context ) {
		if ( empty( $settings['enabled'] ) ) {
			return false;
		}

		// Fail open: protection is on but there is no password to check against,
		// so gating would lock the owner out behind a password nobody knows.
		if ( empty( $settings['password_hash'] ) ) {
			return false;
		}

		if ( ! empty( $context['can_manage_options'] ) && ! empty( $settings['allow_admins'] ) ) {
			return false;
		}

		if ( ! empty( $context['is_logged_in'] ) && ! empty( $settings['allow_logged_in'] ) ) {
			return false;
		}

		if ( ! empty( $context['is_feed'] ) && ! empty( $settings['allow_feeds'] ) ) {
			return false;
		}

		if ( ! empty( $context['is_rest'] ) && ! empty( $settings['allow_rest'] ) ) {
			return false;
		}

		if ( ! empty( $context['has_valid_cookie'] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Derives the unlock cookie value from the stored password hash.
	 *
	 * Format: `<expires>.<hmac>`, where the HMAC covers both the stored password
	 * hash and the expiry. The stored hash never leaves the server.
	 *
	 * The expiry is inside the signature on purpose. Cookie `expires` is enforced
	 * only by the browser, so a copied or replayed cookie would otherwise be
	 * valid forever — until the password changed. Signing the expiry means the
	 * server enforces the advertised lifetime too, and the expiry cannot be
	 * edited without invalidating the signature.
	 *
	 * Changing the password changes the hash, which invalidates every existing
	 * cookie regardless of expiry.
	 *
	 * @param string $password_hash Stored password hash.
	 * @param string $salt          Site auth salt.
	 * @param int    $expires       Unix timestamp after which the token is void.
	 * @return string
	 */
	public static function unlock_token( $password_hash, $salt, $expires ) {
		$expires = (int) $expires;

		/*
		 * The label is domain separation, and it is the reason this signature
		 * cannot be confused with anybody else's. wp_salt( 'auth' ) is a shared
		 * key: core derives its own auth cookies from it too, and any plugin may
		 * call hash_hmac() with it. Nothing in core currently produces this exact
		 * construction, so today the formats simply do not collide — but resting
		 * on that is resting on an accident. Prefixing a constant nobody else
		 * uses makes a collision impossible rather than merely unlikely.
		 *
		 * Bumping the version in the label invalidates every outstanding cookie.
		 */
		return $expires . '.' . hash_hmac(
			'sha256',
			self::TOKEN_LABEL . '|' . (string) $password_hash . '|' . $expires,
			(string) $salt
		);
	}

	/**
	 * Verifies a cookie value against the stored password hash.
	 *
	 * @param string $candidate     Cookie value supplied by the browser.
	 * @param string $password_hash Stored password hash.
	 * @param string $salt          Site auth salt.
	 * @param int    $now           Current unix timestamp.
	 * @return bool
	 */
	public static function verify_token( $candidate, $password_hash, $salt, $now ) {
		$candidate = (string) $candidate;

		// With no password set, nothing may verify. Otherwise a token minted
		// while the password was empty would survive a later password being set.
		if ( '' === $candidate || '' === (string) $password_hash ) {
			return false;
		}

		$parts = explode( '.', $candidate, 2 );

		if ( 2 !== count( $parts ) || '' === $parts[0] || '' === $parts[1] ) {
			return false;
		}

		// Reject anything that is not a plain integer before casting, so values
		// like "9e99" or " 123" cannot slip through as a valid expiry.
		if ( ! ctype_digit( $parts[0] ) ) {
			return false;
		}

		$expires = (int) $parts[0];

		if ( $expires <= (int) $now ) {
			return false;
		}

		return hash_equals(
			self::unlock_token( $password_hash, $salt, $expires ),
			$candidate
		);
	}
}
