<?php
/**
 * Settings storage and admin screen.
 *
 * @package SimplePasswordProtection
 */

defined( 'ABSPATH' ) || exit;

/**
 * Reads, writes and renders the plugin settings.
 */
class SPP_Settings {

	const OPTION       = 'spp_settings';
	const GROUP        = 'spp';
	const SLUG         = 'simple-password-protection';
	const FLUSH_FAILED = 'spp_cache_flush_failed';

	/**
	 * Nonce action for acknowledging a failed cache purge.
	 */
	const DISMISS_FLUSH_ACTION = 'spp_dismiss_flush';

	/**
	 * Hook suffix of the settings screen, for enqueue targeting.
	 *
	 * @var string
	 */
	private static $hook = '';

	/**
	 * Default settings. Every key the plugin reads must appear here.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'enabled'         => false,
			'password_hash'   => '',
			'password_set_at' => 0,
			'message'         => '',
			'logo_id'         => 0,
			'allow_admins'    => true,
			'allow_logged_in' => false,
			'allow_feeds'     => false,
			'allow_rest'      => false,
		);
	}

	/**
	 * Current settings, with defaults filled in for any missing key.
	 *
	 * @return array
	 */
	public static function get() {
		$stored = get_option( self::OPTION, array() );

		// A non-array here means something else wrote to the row. Fall back to
		// defaults rather than fataling in array_merge().
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		return array_merge( self::defaults(), $stored );
	}

	/**
	 * Creates the option row on activation.
	 *
	 * @return void
	 */
	public static function activate() {
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, self::defaults() );
		}
	}

	/**
	 * Registers admin hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'admin_notices', array( __CLASS__, 'maybe_warn' ) );
		add_action( 'admin_init', array( __CLASS__, 'maybe_dismiss_flush_warning' ) );

		// Registered unconditionally, not just in wp-admin: settings can also be
		// changed over WP-CLI or the REST API, and a stale page cache is exactly
		// as dangerous whichever route wrote the option.
		add_action( 'update_option_' . self::OPTION, array( __CLASS__, 'on_settings_updated' ), 10, 2 );
		add_action( 'add_option_' . self::OPTION, array( __CLASS__, 'on_settings_added' ), 10, 2 );
	}

	/**
	 * Flushes page caches when the protection state changes.
	 *
	 * A full-page cache populated while the site was public keeps serving those
	 * pages to anonymous visitors after protection is switched on, because the
	 * cache answers before WordPress loads and the gate never runs. Enabling
	 * protection therefore has to invalidate it.
	 *
	 * @param mixed $old_value Previous option value.
	 * @param mixed $value     New option value.
	 * @return void
	 */
	public static function on_settings_updated( $old_value, $value ) {
		$old_value = is_array( $old_value ) ? $old_value : array();
		$value     = is_array( $value ) ? $value : array();

		/*
		 * Every key that changes who gets through, not just `enabled`. Untick
		 * "Allow RSS feeds" on a site whose /feed/ is already cached and the
		 * cache keeps serving the very content the toggle was turned off to
		 * hide, because the cache answers before WordPress loads.
		 */
		$relevant = array(
			'enabled',
			'password_hash',
			'allow_admins',
			'allow_logged_in',
			'allow_feeds',
			'allow_rest',
		);

		foreach ( $relevant as $key ) {
			$old = isset( $old_value[ $key ] ) ? $old_value[ $key ] : null;
			$new = isset( $value[ $key ] ) ? $value[ $key ] : null;

			// Loose-ish comparison via scalar normalisation: booleans arrive as
			// true/false but may round-trip through the database as "1"/"".
			if ( self::normalise( $old ) !== self::normalise( $new ) ) {
				self::flush_page_caches();
				return;
			}
		}
	}

	/**
	 * Normalises a setting value for change comparison.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	private static function normalise( $value ) {
		if ( is_bool( $value ) || null === $value ) {
			return $value ? '1' : '';
		}

		return (string) $value;
	}

	/**
	 * Flushes caches when the option row is created for the first time.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Option value.
	 * @return void
	 */
	public static function on_settings_added( $option, $value ) {
		if ( is_array( $value ) && ! empty( $value['enabled'] ) ) {
			self::flush_page_caches();
		}
	}

	/**
	 * Invalidates page caches.
	 *
	 * Deliberately broad. This runs only when protection is toggled or the
	 * password changes — rare, deliberate admin actions — and the cost of
	 * over-flushing is a brief cache miss, while the cost of under-flushing is
	 * serving the whole site to people who never entered the password.
	 *
	 * @return void
	 */
	private static function flush_page_caches() {
		// Batcache and other page caches backed by the object cache.
		$flushed = wp_cache_flush();

		/*
		 * A failed purge is not cosmetic: pages cached while the site was public
		 * keep being served to anonymous visitors while the UI reports the site
		 * as protected. Record it so maybe_warn() can say so out loud rather
		 * than letting the admin believe the gate is effective.
		 */
		/*
		 * Stored as an option, not a transient. With a persistent object cache
		 * a transient IS the object cache — the very thing that just failed — so
		 * the warning would be written into the dead backend and never read back.
		 * The signal must not share a failure mode with the thing it reports on.
		 */
		// WP Super Cache.
		if ( function_exists( 'wp_cache_clear_cache' ) ) {
			wp_cache_clear_cache();
		}

		// W3 Total Cache.
		if ( function_exists( 'w3tc_flush_all' ) ) {
			w3tc_flush_all();
		}

		// LiteSpeed Cache.
		do_action( 'litespeed_purge_all' );

		/**
		 * Fires when the plugin invalidates page caches.
		 *
		 * Use this to purge a cache layer the plugin does not know about.
		 */
		do_action( 'spp_flush_caches' );

		/*
		 * Decided last, after every purge above has run, so a success recorded
		 * here cannot pre-date work that had not happened yet.
		 *
		 * Be clear about what this flag can and cannot mean. wp_cache_flush() is
		 * the only purge on this path that reports an outcome at all —
		 * wp_cache_clear_cache(), w3tc_flush_all() and both actions return
		 * nothing, so a page-cache plugin that fails to delete its files does so
		 * silently and there is no return value to inspect. A cleared flag
		 * therefore means "the object cache flush did not report failure", not
		 * "every cache layer is definitely empty", which is why the admin notice
		 * tells the reader to purge their CDN and caching plugin by hand rather
		 * than claiming the plugin has done it for them.
		 */
		if ( false === $flushed ) {
			update_option( self::FLUSH_FAILED, time(), false );
		} else {
			delete_option( self::FLUSH_FAILED );
		}
	}

	/**
	 * Adds the Settings submenu entry.
	 *
	 * @return void
	 */
	public static function add_menu() {
		self::$hook = add_options_page(
			__( 'Password Protection', 'simple-password-protection' ),
			__( 'Password Protection', 'simple-password-protection' ),
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'render_page' )
		);
	}

	/**
	 * Registers the setting, section and fields.
	 *
	 * @return void
	 */
	public static function register() {
		register_setting(
			self::GROUP,
			self::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( __CLASS__, 'sanitize' ),
				'default'           => self::defaults(),
			)
		);

		add_settings_section( 'spp_main', '', '__return_false', self::SLUG );

		add_settings_field(
			'spp_enabled',
			__( 'Protection', 'simple-password-protection' ),
			array( __CLASS__, 'field_enabled' ),
			self::SLUG,
			'spp_main'
		);

		// These three rows reproduce wp-admin/user-edit.php so core's
		// user-profile script binds to them. The classes are the binding
		// contract: user-profile.js selects `.user-pass1-wrap` and `.pw-weak`.
		add_settings_field(
			'spp_password',
			__( 'Password', 'simple-password-protection' ),
			array( __CLASS__, 'field_password' ),
			self::SLUG,
			'spp_main',
			array( 'class' => 'user-pass1-wrap' )
		);

		add_settings_field(
			'spp_password_repeat',
			__( 'Repeat New Password', 'simple-password-protection' ),
			array( __CLASS__, 'field_password_repeat' ),
			self::SLUG,
			'spp_main',
			array( 'class' => 'user-pass2-wrap hide-if-js' )
		);

		add_settings_field(
			'spp_password_weak',
			__( 'Confirm Password', 'simple-password-protection' ),
			array( __CLASS__, 'field_password_weak' ),
			self::SLUG,
			'spp_main',
			array( 'class' => 'pw-weak' )
		);

		add_settings_field(
			'spp_message',
			__( 'Message', 'simple-password-protection' ),
			array( __CLASS__, 'field_message' ),
			self::SLUG,
			'spp_main'
		);

		add_settings_field(
			'spp_logo',
			__( 'Logo', 'simple-password-protection' ),
			array( __CLASS__, 'field_logo' ),
			self::SLUG,
			'spp_main'
		);

		add_settings_field(
			'spp_bypass',
			__( 'Allow through without a password', 'simple-password-protection' ),
			array( __CLASS__, 'field_bypass' ),
			self::SLUG,
			'spp_main'
		);
	}

	/**
	 * Sanitises submitted settings.
	 *
	 * @param mixed $input Raw submitted values.
	 * @return array
	 */
	public static function sanitize( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$current = self::get();
		$clean   = self::defaults();

		/*
		 * When the option row does not exist yet, update_option() sanitises and
		 * then hands off to add_option(), which sanitises the SAME array again.
		 * On that second pass pass1 has already been consumed and self::get()
		 * still returns defaults, so carrying the "current" hash forward would
		 * wipe the hash the first pass just produced — the very first save would
		 * store enabled=true with no password and the site would fail open.
		 *
		 * Honour an already-hashed value arriving in the input instead. This is
		 * not a privilege hole: reaching here at all requires manage_options,
		 * and that capability can set the password to anything regardless.
		 */
		/*
		 * The shape is checked, not just the type. Storing a string that no
		 * input can ever satisfy would gate the site behind a password that does
		 * not exist while the screen reported "Password set" — the same failure
		 * the 4096-byte guard further down exists to prevent. Every hash core
		 * can verify starts with '$' ('$wp', '$2y', '$P$') or is a 32-character
		 * legacy md5.
		 *
		 * password_set_at is stamped here rather than taken from the input: it
		 * is the admin-facing record of when the password last changed, and a
		 * caller-supplied value could back-date a change to hide it.
		 *
		 * It is only stamped when the incoming hash actually differs from the
		 * one already stored, compared with hash_equals() rather than !==: a
		 * write that merely carries the existing hash forward — exactly what
		 * the second sanitize pass described above does — must not reset the
		 * "changed <date>" record shown on the settings screen.
		 */
		if ( isset( $input['password_hash'] ) && is_string( $input['password_hash'] ) && self::looks_hashed( $input['password_hash'] ) ) {
			if ( ! hash_equals( (string) $current['password_hash'], $input['password_hash'] ) ) {
				$current['password_set_at'] = time();
			}

			$current['password_hash'] = $input['password_hash'];
		}

		$clean['enabled']         = ! empty( $input['enabled'] );
		$clean['allow_admins']    = ! empty( $input['allow_admins'] );
		$clean['allow_logged_in'] = ! empty( $input['allow_logged_in'] );
		$clean['allow_feeds']     = ! empty( $input['allow_feeds'] );
		$clean['allow_rest']      = ! empty( $input['allow_rest'] );
		/*
		 * wp_strip_all_tags(), not sanitize_textarea_field().
		 *
		 * Both strip markup identically — sanitize_textarea_field() gets there
		 * by calling this very function — so angle-bracketed text is dropped
		 * either way: "Use <team name> lowercase" stores as "Use  lowercase".
		 * That is inherent to stripping tags, and it is what the field
		 * description means by "HTML is not kept".
		 *
		 * What sanitize_textarea_field() adds on top, and what this avoids, is
		 * two silent corruptions of ordinary text, both verified on WP 7.0.2:
		 * it deletes percent-escapes, so a URL containing "a%20b" is stored as
		 * "ab"; and wp_pre_kses_less_than() rewrites a lone "<" to "&lt;",
		 * which the esc_html() at render time then double-escapes into a
		 * visible "&lt;".
		 *
		 * The second argument keeps newlines so the multi-line message
		 * survives. wp_check_invalid_utf8() guards against malformed
		 * byte sequences slipping through unsanitised. Output is escaped once,
		 * correctly, at render time (esc_html() in render(), esc_textarea() in
		 * field_message()) — do not add escaping here too.
		 */
		$clean['message']         = isset( $input['message'] ) ? wp_strip_all_tags( wp_check_invalid_utf8( (string) $input['message'] ), false ) : '';
		$clean['logo_id']         = isset( $input['logo_id'] ) ? absint( $input['logo_id'] ) : 0;

		// Carry the existing password forward unless a new one was submitted.
		$clean['password_hash']   = $current['password_hash'];
		$clean['password_set_at'] = $current['password_set_at'];

		/*
		 * pass1 is deliberately not sanitised: sanitize_text_field() would
		 * silently mangle valid passwords containing markup-like characters.
		 * It is hashed immediately and never stored or echoed.
		 */
		$pass1 = isset( $input['pass1'] ) ? (string) $input['pass1'] : '';
		$pass2 = isset( $input['pass2'] ) ? (string) $input['pass2'] : '';

		if ( '' === trim( $pass1 ) ) {
			return $clean;
		}

		/*
		 * With JavaScript the repeat field is hidden and disabled, so it never
		 * arrives. Without it both fields are visible and submitted, and a typo
		 * would otherwise store a password the admin does not know — unusable and
		 * unrecoverable, since the hash is one-way.
		 */
		if ( '' !== $pass2 && ! hash_equals( $pass1, $pass2 ) ) {
			add_settings_error(
				self::OPTION,
				'spp_password_mismatch',
				__( 'The passwords did not match, so the password was left unchanged.', 'simple-password-protection' ),
				'error'
			);

			return $clean;
		}

		/*
		 * Since WP 6.8 wp_hash_password() returns the sentinel '*' for input
		 * over 4096 bytes, and no input can ever satisfy wp_check_password()
		 * against it. Storing that would gate the site permanently with a
		 * password that does not exist, while the UI reported "Password set".
		 */
		if ( strlen( $pass1 ) > 4096 ) {
			add_settings_error(
				self::OPTION,
				'spp_password_too_long',
				__( 'That password is too long (the maximum is 4096 bytes), so the password was left unchanged.', 'simple-password-protection' ),
				'error'
			);

			return $clean;
		}

		$clean['password_hash']   = wp_hash_password( $pass1 );
		$clean['password_set_at'] = time();

		return $clean;
	}

	/**
	 * Whether a value has the shape of a hash wp_check_password() could verify.
	 *
	 * Rejects, among other things, the '*' sentinel wp_hash_password() returns
	 * for over-long input — storing that would gate the site behind a password
	 * no input can ever match.
	 *
	 * @param string $hash Candidate hash.
	 * @return bool
	 */
	private static function looks_hashed( $hash ) {
		// Prefixed ('$wp$...'), bcrypt ('$2y$...') and phpass ('$P$...').
		if ( isset( $hash[0] ) && '$' === $hash[0] && strlen( $hash ) > 3 ) {
			return true;
		}

		// Legacy unsalted md5, which wp_check_password() still accepts.
		return 32 === strlen( $hash ) && ctype_xdigit( $hash );
	}

	/**
	 * Renders the settings screen.
	 *
	 * @return void
	 */
	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

			<form method="post" action="options.php">
				<?php
				settings_fields( self::GROUP );
				do_settings_sections( self::SLUG );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Enable checkbox.
	 *
	 * @return void
	 */
	public static function field_enabled() {
		$settings = self::get();
		?>
		<label>
			<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[enabled]" value="1" <?php checked( $settings['enabled'] ); ?> />
			<?php esc_html_e( 'Require a password to view this site', 'simple-password-protection' ); ?>
		</label>
		<?php
	}

	/**
	 * Password field, mirroring wp-admin/user-edit.php.
	 *
	 * @return void
	 */
	public static function field_password() {
		$settings = self::get();
		?>
		<input type="hidden" value=" " /><!-- #24364 workaround -->
		<button type="button" class="button wp-generate-pw hide-if-no-js" aria-expanded="false">
			<?php echo esc_html( $settings['password_hash'] ? __( 'Set New Password', 'simple-password-protection' ) : __( 'Set Password', 'simple-password-protection' ) ); ?>
		</button>

		<div class="wp-pwd hide-if-js">
			<div class="password-input-wrapper">
				<input type="password" name="<?php echo esc_attr( self::OPTION ); ?>[pass1]" id="pass1" class="regular-text ltr" value="" autocomplete="new-password" spellcheck="false" data-pw="<?php echo esc_attr( wp_generate_password( 24 ) ); ?>" aria-describedby="pass-strength-result" />
				<div style="display:none" id="pass-strength-result" aria-live="polite"></div>
			</div>
			<button type="button" class="button wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="<?php esc_attr_e( 'Hide password', 'simple-password-protection' ); ?>">
				<span class="dashicons dashicons-hidden" aria-hidden="true"></span>
				<span class="text"><?php esc_html_e( 'Hide', 'simple-password-protection' ); ?></span>
			</button>
			<button type="button" class="button wp-cancel-pw hide-if-no-js" data-toggle="0" aria-label="<?php esc_attr_e( 'Cancel password change', 'simple-password-protection' ); ?>">
				<span class="dashicons dashicons-no" aria-hidden="true"></span>
				<span class="text"><?php esc_html_e( 'Cancel', 'simple-password-protection' ); ?></span>
			</button>
			<button type="button" class="button spp-copy-pw hide-if-no-js" id="spp-copy-pw">
				<span class="dashicons dashicons-clipboard" aria-hidden="true"></span>
				<span class="text"><?php esc_html_e( 'Copy', 'simple-password-protection' ); ?></span>
			</button>
		</div>

		<?php
		// Two descriptions occupying the same slot. The status is what you want
		// to read at rest; the storage caveat only matters while a password is
		// actually on screen to be copied. admin.js swaps them when the generate
		// and cancel buttons are used. Without JavaScript both are visible,
		// which is correct rather than broken.
		?>
		<p class="description spp-status<?php echo empty( $settings['password_hash'] ) ? ' spp-status--unset' : ''; ?>" id="spp-password-status">
			<?php echo esc_html( self::status_text( $settings ) ); ?>
		</p>

		<p class="description hide-if-js" id="spp-password-note">
			<?php esc_html_e( 'The password is stored hashed, so it cannot be shown again later. Copy it now if you need to share it.', 'simple-password-protection' ); ?>
		</p>
		<?php
	}

	/**
	 * Whether a password is currently set, and when it last changed.
	 *
	 * @param array $settings Plugin settings.
	 * @return string
	 */
	private static function status_text( $settings ) {
		if ( empty( $settings['password_hash'] ) ) {
			return __( 'No password set yet.', 'simple-password-protection' );
		}

		// password_set_at can be 0 only if the option row was edited by hand.
		if ( empty( $settings['password_set_at'] ) ) {
			return __( 'Password set.', 'simple-password-protection' );
		}

		return sprintf(
			/* translators: %s: date the password was last changed. */
			__( 'Password set · changed %s', 'simple-password-protection' ),
			wp_date( get_option( 'date_format' ), (int) $settings['password_set_at'] )
		);
	}

	/**
	 * Hidden repeat field. Present only for LastPass compatibility, which
	 * user-profile.js handles by copying pass2 into pass1.
	 *
	 * @return void
	 */
	public static function field_password_repeat() {
		?>
		<input type="password" name="<?php echo esc_attr( self::OPTION ); ?>[pass2]" id="pass2" class="regular-text" value="" autocomplete="new-password" spellcheck="false" />
		<?php
	}

	/**
	 * Weak-password confirmation. Core's script disables Save until this is
	 * ticked when the entered password scores weak.
	 *
	 * @return void
	 */
	public static function field_password_weak() {
		?>
		<label>
			<input type="checkbox" name="pw_weak" class="pw-checkbox" />
			<span><?php esc_html_e( 'Confirm use of weak password', 'simple-password-protection' ); ?></span>
		</label>
		<?php
	}

	/**
	 * Optional message shown above the password box.
	 *
	 * @return void
	 */
	public static function field_message() {
		$settings = self::get();
		?>
		<textarea class="large-text" rows="3" name="<?php echo esc_attr( self::OPTION ); ?>[message]" id="spp-message"><?php echo esc_textarea( $settings['message'] ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Shown above the password box. Line breaks are kept; HTML is not. Leave empty for none.', 'simple-password-protection' ); ?></p>
		<?php
	}

	/**
	 * Logo picker.
	 *
	 * @return void
	 */
	public static function field_logo() {
		$settings = self::get();
		$logo_id  = (int) $settings['logo_id'];
		$logo_url = $logo_id ? wp_get_attachment_image_url( $logo_id, 'medium' ) : '';
		?>
		<input type="hidden" name="<?php echo esc_attr( self::OPTION ); ?>[logo_id]" id="spp-logo-id" value="<?php echo esc_attr( $logo_id ); ?>" />

		<div id="spp-logo-preview" class="spp-logo-preview" <?php echo $logo_url ? '' : 'hidden'; ?>>
			<img src="<?php echo esc_url( $logo_url ); ?>" alt="" />
		</div>

		<p>
			<button type="button" class="button" id="spp-logo-select"><?php esc_html_e( 'Choose image', 'simple-password-protection' ); ?></button>
			<button type="button" class="button-link spp-logo-remove" id="spp-logo-remove" <?php echo $logo_url ? '' : 'hidden'; ?>><?php esc_html_e( 'Remove', 'simple-password-protection' ); ?></button>
		</p>

		<p class="description"><?php esc_html_e( 'Replaces the WordPress logo on the password screen. Shown up to 320 by 84 pixels.', 'simple-password-protection' ); ?></p>
		<?php
	}

	/**
	 * Bypass checkboxes.
	 *
	 * @return void
	 */
	public static function field_bypass() {
		$settings = self::get();
		$option   = esc_attr( self::OPTION );

		$boxes = array(
			'allow_admins'    => __( 'Administrators (anyone who can manage options)', 'simple-password-protection' ),
			'allow_logged_in' => __( 'All logged-in users', 'simple-password-protection' ),
			'allow_feeds'     => __( 'RSS and Atom feeds', 'simple-password-protection' ),
			'allow_rest'      => __( 'The REST API', 'simple-password-protection' ),
		);

		echo '<fieldset>';

		foreach ( $boxes as $key => $label ) {
			printf(
				'<label style="display:block;margin-bottom:6px;"><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s /> %4$s</label>',
				$option, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_attr( $key ),
				checked( $settings[ $key ], true, false ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_html( $label )
			);
		}

		echo '</fieldset>';

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Everyone else sees the password screen.', 'simple-password-protection' )
		);

		// The block editor talks to the REST API, which is gated for anyone who
		// cannot already read every post in wp-admin. Without this line a
		// Contributor just sees an editor that will not save, with nothing on
		// screen connecting that to the gate.
		printf(
			'<p class="description">%s</p>',
			esc_html__(
				'Editors and administrators can always use the block editor. Contributors and Authors need the site password once — or this set to all logged-in users — before the editor will save.',
				'simple-password-protection'
			)
		);
	}

	/**
	 * Enqueues assets on the settings screen only.
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @return void
	 */
	public static function enqueue( $hook ) {
		if ( $hook !== self::$hook ) {
			return;
		}

		wp_enqueue_media();

		// This is what activates the generate button, strength meter,
		// show/hide toggle and weak-password confirmation.
		wp_enqueue_script( 'user-profile' );

		wp_enqueue_style( 'spp-admin', SPP_URL . 'assets/admin.css', array(), SPP_VERSION );
		wp_enqueue_script( 'spp-admin', SPP_URL . 'assets/admin.js', array( 'jquery', 'clipboard', 'wp-a11y' ), SPP_VERSION, true );

		wp_localize_script(
			'spp-admin',
			'sppAdmin',
			array(
				'mediaTitle'  => __( 'Choose a logo', 'simple-password-protection' ),
				'mediaButton' => __( 'Use this image', 'simple-password-protection' ),
				'copied'      => __( 'Copied', 'simple-password-protection' ),
				'copy'        => __( 'Copy', 'simple-password-protection' ),
			)
		);
	}

	/**
	 * Clears the failed-purge warning when an administrator acknowledges it.
	 *
	 * Deliberately requires manage_options AND a valid nonce: the warning says
	 * the site may still be serving private pages from a stale cache, so
	 * silencing it is a state change and must not be reachable by a link someone
	 * else can get an administrator to click.
	 *
	 * @return void
	 */
	public static function maybe_dismiss_flush_warning() {
		if ( ! isset( $_GET['spp-dismiss-flush'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		check_admin_referer( self::DISMISS_FLUSH_ACTION );

		delete_option( self::FLUSH_FAILED );

		wp_safe_redirect( admin_url( 'options-general.php?page=' . self::SLUG ) );
		exit;
	}

	/**
	 * Warns when protection is on but no password exists.
	 *
	 * @return void
	 */
	public static function maybe_warn() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings = self::get();

		// Checked regardless of `enabled`: a purge that failed while switching
		// protection OFF can leave gate screens cached over real pages.
		$flush_failed_at = get_option( self::FLUSH_FAILED, false );

		if ( false !== $flush_failed_at ) {
			/*
			 * Dismissible, and cleared no other way.
			 *
			 * This reports a condition the plugin cannot re-check on its own: the
			 * option is otherwise only removed by a later SUCCESSFUL
			 * wp_cache_flush(), which only happens if a protection-relevant
			 * setting changes again. On a host whose object-cache drop-in
			 * declines full flushes by design that never comes, so a
			 * non-dismissible notice would sit on every admin screen forever.
			 *
			 * Expiring it on a timer was the other candidate and is worse: it
			 * makes an unresolved warning about stale public copies of a private
			 * site disappear on its own, and an admin who does not open wp-admin
			 * that day never learns of it. Dismissal has to be a deliberate act
			 * — the admin confirming they have purged by hand — not the clock.
			 */
			$link = sprintf(
				'<a href="%s">%s</a>',
				esc_url(
					wp_nonce_url(
						admin_url( 'options-general.php?page=' . self::SLUG . '&spp-dismiss-flush=1' ),
						self::DISMISS_FLUSH_ACTION
					)
				),
				esc_html__( 'I have purged it manually', 'simple-password-protection' )
			);

			wp_admin_notice(
				esc_html__(
					'Simple Password Protection could not clear your page cache automatically. Pages cached before this change may still be served. Purge your caching plugin and any CDN or edge cache manually.',
					'simple-password-protection'
				) . ' ' . $link,
				array(
					'type'               => 'warning',
					'dismissible'        => false,
					'additional_classes' => array( 'spp-notice' ),
				)
			);
		}

		if ( empty( $settings['enabled'] ) || ! empty( $settings['password_hash'] ) ) {
			return;
		}

		$message = sprintf(
			/* translators: %s: link to the plugin settings screen. */
			__( 'Simple Password Protection is enabled but no password is set, so your site is <strong>not</strong> protected. %s', 'simple-password-protection' ),
			'<a href="' . esc_url( admin_url( 'options-general.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Set a password', 'simple-password-protection' ) . '</a>'
		);

		wp_admin_notice(
			wp_kses( $message, array( 'strong' => array(), 'a' => array( 'href' => array() ) ) ),
			array(
				'type'               => 'error',
				'dismissible'        => false,
				'additional_classes' => array( 'spp-notice' ),
			)
		);
	}
}
