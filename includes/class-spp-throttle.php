<?php
/**
 * Failed-attempt throttling, keyed on client IP.
 *
 * @package SimplePasswordProtection
 */

defined( 'ABSPATH' ) || exit;

/**
 * Limits password guesses from a single IP address.
 *
 * Two design choices carry the correctness here.
 *
 * The database is the single authority. An earlier version incremented an
 * object-cache counter and only fell back to the database, which split the
 * authority in two: a Redis restart or eviction silently reset the budget to
 * zero, and a cache-recorded attempt was invisible to the database path and
 * vice versa. Since a reservation is only meaningful if it is authoritative —
 * the caller refuses to run a password comparison once its reserved number
 * exceeds MAX_ATTEMPTS — one durable counter is worth far more than the write
 * it saves. Failed guesses are rare by construction, and under an actual attack
 * durable counting is exactly what is wanted.
 *
 * Windows are fixed, not anchored to the first failure. The window boundary is
 * part of the option name, so rolling over is just a different key: there is no
 * expired-record read-then-delete step for two concurrent requests to race on.
 * The trade is that an attacker timing a burst across a boundary can get up to
 * 2 * MAX_ATTEMPTS guesses in quick succession, which still makes online
 * guessing impractical.
 */
class SPP_Throttle {

	const MAX_ATTEMPTS = 5;
	const WINDOW       = 900; // 15 minutes.
	const PREFIX       = 'spp_throttle_';
	const SWEEP_HOOK   = 'spp_throttle_sweep';

	/**
	 * Rows removed per sweep run, so one cron request cannot be made to load or
	 * delete an unbounded number of attacker-created rows.
	 */
	const SWEEP_BATCH = 500;

	/**
	 * Stored in place of a counter that is not a plain integer. Far above
	 * MAX_ATTEMPTS so a corrupt row refuses attempts rather than granting them.
	 */
	const CORRUPT_SENTINEL = 999999;

	/**
	 * The requesting client's IP address, reduced to its routable prefix.
	 *
	 * Only REMOTE_ADDR is trusted. X-Forwarded-For is client-supplied, so
	 * honouring it would let an attacker sidestep the throttle by rotating the
	 * header. Sites behind a reverse proxy should use the spp_client_ip filter.
	 *
	 * @return string Validated IP address or prefix, or an empty string.
	 */
	public static function client_ip() {
		$raw = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
		$ip  = filter_var( $raw, FILTER_VALIDATE_IP );

		/**
		 * Filters the client IP address used for throttling.
		 *
		 * Whatever this returns is passed through ip_bucket() again before use,
		 * so it may be either a plain validated address or an already-bucketed
		 * prefix — ip_bucket() is idempotent, since a value like
		 * "2001:db8::/64" fails FILTER_VALIDATE_IP and is returned unchanged.
		 * That is what lets a filter return a plain filter_var() result, as the
		 * readme's own reverse-proxy example does, without silently reinstating
		 * per-/128 IPv6 counting.
		 *
		 * If your proxy sets a forwarded header, validate it against your own
		 * trusted proxy chain and pick the correct index before returning it —
		 * returning a raw client-supplied header hands an attacker both
		 * unlimited attempts (by rotating it) and the ability to lock out any
		 * address they choose.
		 *
		 * @param string $ip Validated IP address, or an empty string.
		 */
		return self::ip_bucket( (string) apply_filters( 'spp_client_ip', false === $ip ? '' : $ip ) );
	}

	/**
	 * Reduces an address to the prefix the throttle counts against.
	 *
	 * IPv6 is masked to its /64. Residential and VPS IPv6 allocations are a /64
	 * or larger, so counting the full /128 would give one attacker 2^64
	 * independent budgets — five attempts each, from a single cheap host — while
	 * the same code still locks out IPv4 visitors sharing a NAT egress. Keying
	 * the smallest block that is actually allocated as a unit is what makes the
	 * limit mean anything.
	 *
	 * IPv4-mapped and IPv4-compatible forms are left whole: their top 64 bits
	 * are all zero, so masking would collapse every such client into one shared
	 * bucket and turn the fix into a site-wide lockout.
	 *
	 * Pure string/byte work — no WordPress calls — so it is unit tested directly.
	 *
	 * @param string $ip Validated IP address.
	 * @return string Address or prefix to count against.
	 */
	public static function ip_bucket( $ip ) {
		$ip = (string) $ip;

		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $ip;
		}

		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return $ip;
		}

		// ::ffff:a.b.c.d and ::a.b.c.d carry an IPv4 address in their low bytes.
		if ( 0 === strncmp( $packed, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12 )
			|| 0 === strncmp( $packed, "\0\0\0\0\0\0\0\0\0\0\0\0", 12 ) ) {
			return $ip;
		}

		$masked = inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) );

		return false === $masked ? $ip : $masked . '/64';
	}

	/**
	 * Start of the current fixed window, as a unix timestamp.
	 *
	 * @return int
	 */
	private static function window_start() {
		return (int) ( floor( time() / self::WINDOW ) * self::WINDOW );
	}

	/**
	 * Option name holding this client's count for the current window.
	 *
	 * @return string
	 */
	private static function option_name() {
		return self::PREFIX . md5( self::client_ip() ) . '_' . self::window_start();
	}

	/**
	 * Attempts already recorded in the current window.
	 *
	 * @return int
	 */
	private static function attempts() {
		return (int) get_option( self::option_name(), 0 );
	}

	/**
	 * Whether this client is currently locked out.
	 *
	 * @return bool
	 */
	public static function is_locked_out() {
		return self::attempts() >= self::MAX_ATTEMPTS;
	}

	/**
	 * Seconds until the current window ends.
	 *
	 * @return int
	 */
	public static function seconds_remaining() {
		return max( 0, ( self::window_start() + self::WINDOW ) - time() );
	}

	/**
	 * Reserves one attempt and returns its number.
	 *
	 * A read-modify-write through get_option()/update_option() would let two
	 * concurrent requests read the same value and both write back the same
	 * number, so the reservation would not be unique and a burst could slip past
	 * the cap. The unique index on option_name makes this single statement
	 * atomic instead.
	 *
	 * @return int Reserved attempt number. Always >= 1.
	 */
	public static function record_failure() {
		global $wpdb;

		$name = self::option_name();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		/*
		 * The IF() guard matters. A bare `option_value + 1` makes MySQL coerce a
		 * non-numeric value to 0 and store 1 — so a corrupt row would silently
		 * hand out a fresh attempt budget, which is the opposite of the
		 * fail-closed behaviour below. Replacing it with a sentinel far above
		 * MAX_ATTEMPTS means a corrupt counter refuses attempts instead.
		 */
		$written = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload)
				 VALUES (%s, '1', 'off')
				 ON DUPLICATE KEY UPDATE option_value =
					IF( option_value REGEXP '^[0-9]+$', option_value + 1, %d )",
				$name,
				self::CORRUPT_SENTINEL
			)
		);

		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
				$name
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		self::forget_cached( $name );

		/*
		 * Fail CLOSED when the counter cannot be trusted.
		 *
		 * If the write did not land, or the stored value is not a plain integer,
		 * returning a low number would hand every request attempt 1 and silently
		 * switch throttling off — unlimited guesses with nothing in any log. The
		 * cost of the opposite choice is bounded: the window is part of the key,
		 * so a wedged counter clears itself within one window rather than
		 * locking anyone out permanently.
		 */
		if ( false === $written || null === $count || ! ctype_digit( (string) $count ) ) {
			return self::MAX_ATTEMPTS + 1;
		}

		// Reading back a larger number than we reserved is safe: it can only
		// refuse more attempts, never fewer.
		return max( 1, (int) $count );
	}

	/**
	 * Drops cached knowledge of an option written behind the Options API's back.
	 *
	 * Clearing the value cache alone is not enough. A get_option() miss before
	 * the row existed records the name in the `notoptions` cache, and with a
	 * persistent object cache that negative entry survives the request — so
	 * every later read would keep reporting the option as absent and the counter
	 * would be written but never seen.
	 *
	 * Deliberately does not touch `alloptions`: these rows are autoload 'off' and
	 * never appear in it, so invalidating it would force every autoloaded option
	 * to be re-read once per failed guess — a self-inflicted stampede under
	 * exactly the attack this counter exists to limit.
	 *
	 * @param string $name Option name.
	 * @return void
	 */
	private static function forget_cached( $name ) {
		wp_cache_delete( $name, 'options' );

		$notoptions = wp_cache_get( 'notoptions', 'options' );

		if ( is_array( $notoptions ) && isset( $notoptions[ $name ] ) ) {
			unset( $notoptions[ $name ] );
			wp_cache_set( 'notoptions', $notoptions, 'options' );
		}
	}

	/**
	 * Clears this client's record after a successful unlock.
	 *
	 * A direct DELETE, not delete_option(): see sweep()'s comment for why.
	 * record_failure() always creates this row first, so every successful
	 * unlock would otherwise add one permanently dead entry to the site-wide
	 * `notoptions` array that delete_option() writes to.
	 *
	 * @return void
	 */
	public static function clear() {
		global $wpdb;

		$name = self::option_name();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s",
				$name
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		self::forget_cached( $name );
	}

	/**
	 * Registers the cleanup schedule.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( self::SWEEP_HOOK, array( __CLASS__, 'sweep' ) );

		// Hourly, not daily: windows turn over every 15 minutes, so a daily sweep
		// would let a sustained or IP-rotating attack accumulate rows for a full
		// day before anything cleaned up.
		if ( ! wp_next_scheduled( self::SWEEP_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::SWEEP_HOOK );
		}
	}

	/**
	 * Removes rows for windows that have passed.
	 *
	 * Garbage collecting only when the same IP returns would never clean up after
	 * one-shot or distributed sources, leaving an attacker-controlled way to grow
	 * the options table indefinitely.
	 *
	 * @return void
	 */
	public static function sweep() {
		global $wpdb;

		$cutoff = self::window_start() - self::WINDOW;

		/*
		 * Selected in a bounded batch, and filtered in SQL rather than in PHP.
		 * Fetching every matching row would let an attacker rotating source
		 * addresses — trivial from a single IPv6 /64 — make this cron request
		 * exhaust memory or time out before deleting anything, so the sweep
		 * would keep failing while the table kept growing.
		 */
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$names = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options}
				 WHERE option_name LIKE %s
				   AND CAST( SUBSTRING_INDEX( option_name, '_', -1 ) AS UNSIGNED ) < %d
				 LIMIT %d",
				$wpdb->esc_like( self::PREFIX ) . '%',
				$cutoff,
				self::SWEEP_BATCH
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		if ( ! $names ) {
			return;
		}

		/*
		 * One bulk DELETE, then drop each name from the object cache by hand.
		 *
		 * delete_option() is the obvious call and is the wrong one here: it
		 * records every name it removes in the site-wide `notoptions` array and
		 * writes the whole thing back to the object cache. These names are
		 * single-use by construction — the window is in the name and has already
		 * passed, so nothing will ever look one up again — so each sweep would
		 * add SWEEP_BATCH permanently dead entries to an array that is re-read
		 * on every option cache miss, on every request, and that a persistent
		 * object cache never expires. Measured: 500 deletions = 500 entries and
		 * ~31KB added, 1003 queries. Left to accumulate it crosses Memcached's
		 * 1MB item limit, at which point the set silently fails and negative
		 * option caching is broken site-wide until someone flushes.
		 *
		 * The usual argument for delete_option() — cache coherency — does not
		 * apply: these rows are autoload 'off', so they are never in
		 * `alloptions`, which is the same fact forget_cached() already relies on.
		 */
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name IN ("
					. implode( ',', array_fill( 0, count( $names ), '%s' ) ) . ')',
				$names
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		foreach ( $names as $name ) {
			wp_cache_delete( $name, 'options' );
		}

		/*
		 * A full batch means there is probably more, so come back shortly rather
		 * than draining at one batch per hour.
		 *
		 * The catch-up event carries an argument. Without one it would be
		 * indistinguishable from the recurring hourly event, so the duplicate
		 * check inside wp_schedule_single_event() would drop it every time and
		 * this branch would never do anything.
		 */
		if ( count( $names ) >= self::SWEEP_BATCH ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::SWEEP_HOOK, array( 'catchup' ) );
		}
	}

	/**
	 * Clears the schedule on deactivation.
	 *
	 * @return void
	 */
	public static function deactivate() {
		// wp_unschedule_hook(), not wp_clear_scheduled_hook(): the latter only
		// matches events with no arguments, which would leave a pending catch-up
		// event behind.
		wp_unschedule_hook( self::SWEEP_HOOK );
	}
}
