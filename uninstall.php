<?php
/**
 * Uninstall handler.
 *
 * @package SimplePasswordProtection
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'spp_settings' );

// An option since 1.0.0; delete_transient() is kept only to clean up rows left
// by pre-release builds that stored it as one.
delete_option( 'spp_cache_flush_failed' );
delete_transient( 'spp_cache_flush_failed' );

// wp_unschedule_hook(), not wp_clear_scheduled_hook(): the latter only matches
// events with no arguments, which would strand the catch-up event
// SPP_Throttle::sweep() schedules with array( 'catchup' ).
wp_unschedule_hook( 'spp_throttle_sweep' );

/*
 * Each client that failed a password attempt leaves a throttle row behind.
 * These are ordinary options, not transients, so nothing in core would ever
 * remove them and "nothing else is left behind" would not be true.
 *
 * The _transient_ patterns clean up rows written by pre-release builds that
 * stored the counter as a transient.
 */
/*
 * Deleted in bounded batches with a single statement each.
 *
 * Loading every matching name and calling delete_option() on each is what this
 * used to do, and it is the same unbounded pattern SPP_Throttle::sweep() is
 * deliberately batched to avoid: after a sustained distributed attack there can
 * be hundreds of thousands of rows, which is tens of megabytes of PHP array and
 * two queries per row. Uninstall has no resumption, so exhausting memory or the
 * time limit here would delete the plugin while leaving its rows behind, with no
 * code left anywhere to remove them — and would abort before the delete_option()
 * calls above if they had not already run.
 *
 * delete_option() would also pollute the site-wide `notoptions` cache with one
 * permanently dead entry per row. The final wp_cache_flush() makes per-name
 * cache invalidation unnecessary here.
 */
global $wpdb;

do {
	$spp_deleted = $wpdb->query(
		"DELETE FROM {$wpdb->options}
		 WHERE option_name LIKE 'spp\_throttle\_%'
		    OR option_name LIKE '\_transient\_spp\_throttle\_%'
		    OR option_name LIKE '\_transient\_timeout\_spp\_throttle\_%'
		 LIMIT 1000"
	);
} while ( $spp_deleted >= 1000 );

// Object-cache-backed throttle keys live in their own group; clearing the group
// is not portable, so flush leaves nothing plugin-owned behind either way.
wp_cache_flush();
