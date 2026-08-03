<?php
/**
 * The password gate screen.
 *
 * WordPress defines login_header() and login_footer() inside wp-login.php, so
 * neither is callable from a front-end request. This class therefore reproduces
 * core's login document itself while enqueuing core's own `login` stylesheet, so
 * the screen still inherits login.css, RTL, dashicons, buttons and form styling
 * rather than shipping a parallel design.
 *
 * Markup mirrors wp-login.php::login_header() (WP 7.0.2), lines 93-222.
 *
 * @package SimplePasswordProtection
 */

defined( 'ABSPATH' ) || exit;

/**
 * Renders the gate and processes unlock attempts.
 */
class SPP_Screen {

	const NONCE_ACTION  = 'spp_unlock';
	const NONCE_NAME    = 'spp_nonce';
	const REMEMBER_DAYS = 14;

	/**
	 * Server-side cap on a browser-session unlock, in seconds.
	 *
	 * Without Remember Me the cookie has no `expires`, so the browser drops it on
	 * close — but a copied cookie would otherwise stay valid forever. The signed
	 * token is capped so the server enforces a lifetime too.
	 */
	const SESSION_MAX = DAY_IN_SECONDS;

	/**
	 * Error message to show on the gate, if any.
	 *
	 * @var string
	 */
	private static $error = '';

	/**
	 * Name of the unlock cookie.
	 *
	 * The `wp-` prefix is load-bearing, not cosmetic. Page caches conventionally
	 * bypass the cache for any request carrying a cookie whose name begins with
	 * `wp` or `wordpress` — Batcache does exactly this. Without the prefix an
	 * unlocked visitor keeps being served cached pages, and after a password
	 * change they would keep seeing a cached gate screen. Core uses the same
	 * convention for its own post-password cookie, `wp-postpass_`.
	 *
	 * @return string
	 */
	public static function cookie_name() {
		return 'wp-spp-unlock_' . COOKIEHASH;
	}

	/**
	 * Whether the request carries a valid unlock cookie.
	 *
	 * @param array $settings Plugin settings.
	 * @return bool
	 */
	public static function has_valid_cookie( $settings ) {
		$name = self::cookie_name();

		if ( empty( $_COOKIE[ $name ] ) ) {
			return false;
		}

		$candidate = sanitize_text_field( wp_unslash( $_COOKIE[ $name ] ) );

		return SPP_Access::verify_token( $candidate, $settings['password_hash'], wp_salt( 'auth' ), time() );
	}

	/**
	 * Processes an unlock submission.
	 *
	 * On success this sets the cookie, redirects and exits. On failure it records
	 * an error for render() to display.
	 *
	 * @param array $settings Plugin settings.
	 * @return void
	 */
	public static function handle_post( $settings ) {
		if ( ! isset( $_POST['spp_password'] ) ) {
			return;
		}

		if ( ! isset( $_POST[ self::NONCE_NAME ] )
			|| ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST[ self::NONCE_NAME ] ) ), self::NONCE_ACTION ) ) {
			self::$error = __( 'Your session expired. Please try again.', 'simple-password-protection' );
			return;
		}

		/*
		 * Require the submission to be same-origin before charging anything.
		 *
		 * For a logged-out visitor wp_verify_nonce() hashes uid 0 and an empty
		 * session token, so the gate's nonce is a site-wide constant valid for
		 * up to 24 hours — not per-visitor. Without this check an attacker could
		 * harvest it once, then host a page (or buy an ad) that auto-submits five
		 * hidden cross-origin POSTs. No cookie is needed, so SameSite does not
		 * help, and every visitor who loaded that page would have five attempts
		 * charged against their own IP and be locked out of the real site.
		 */
		if ( ! self::is_same_origin() ) {
			self::$error = __( 'Your session expired. Please try again.', 'simple-password-protection' );
			return;
		}

		if ( SPP_Throttle::is_locked_out() ) {
			self::$error = self::lockout_message();
			return;
		}

		/*
		 * Reserve the attempt BEFORE verifying, and let the reserved number — not
		 * the earlier is_locked_out() read — decide whether to proceed.
		 *
		 * Counting failures after the comparison makes this check-then-act: a
		 * burst of simultaneous requests all read a count below the limit, all
		 * guess, and only then increment. Even reserving first is not enough if
		 * the reservation is ignored, because every request in the burst would
		 * still reach wp_check_password(). Refusing once the reserved number
		 * exceeds the limit is what actually caps comparisons per window.
		 */
		$attempt = SPP_Throttle::record_failure();

		if ( $attempt > SPP_Throttle::MAX_ATTEMPTS ) {
			self::$error = self::lockout_message();
			return;
		}

		/*
		 * Not sanitised on purpose: the raw submission is compared against a hash
		 * and is never stored or echoed. Sanitising would silently mangle valid
		 * passwords containing markup-like characters.
		 */
		$password = (string) wp_unslash( $_POST['spp_password'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		/*
		 * Refuse an over-long submission before hashing it.
		 *
		 * Core does cap passwords at 4096 bytes, but that branch sits AFTER the
		 * $wp_hasher one in wp_check_password() (wp-includes/pluggable.php), so
		 * any plugin that sets $GLOBALS['wp_hasher'] — a supported, still-used
		 * override — skips the cap entirely and hands the whole request body to
		 * phpass, which runs md5() over it 8192 times. An 8MB body is then tens
		 * of gigabytes of hashing in one request. wp_check_password() is itself
		 * pluggable, so this path must not depend on somebody else's guard for
		 * the only attacker-controlled expensive operation it performs.
		 *
		 * The attempt has already been reserved above, so this costs a guess.
		 */
		if ( strlen( $password ) > 4096 ) {
			self::$error = SPP_Throttle::is_locked_out()
				? self::lockout_message()
				: __( 'Incorrect password.', 'simple-password-protection' );

			return;
		}

		if ( ! wp_check_password( $password, $settings['password_hash'] ) ) {
			self::$error = SPP_Throttle::is_locked_out()
				? self::lockout_message()
				: __( 'Incorrect password.', 'simple-password-protection' );

			return;
		}

		SPP_Throttle::clear();

		$remember = ! empty( $_POST['spp_remember'] );
		$lifetime = $remember ? self::REMEMBER_DAYS * DAY_IN_SECONDS : self::SESSION_MAX;
		$expires  = time() + $lifetime;

		setcookie(
			self::cookie_name(),
			SPP_Access::unlock_token( $settings['password_hash'], wp_salt( 'auth' ), $expires ),
			array(
				// Only Remember Me sets a browser expiry; the signed token carries
				// the server-enforced one either way.
				'expires'  => $remember ? $expires : 0,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		$redirect = isset( $_POST['spp_redirect_to'] )
			? esc_url_raw( wp_unslash( $_POST['spp_redirect_to'] ) )
			: '';

		wp_safe_redirect( wp_validate_redirect( $redirect, home_url( '/' ) ) );
		exit;
	}

	/**
	 * Whether the submission came from this site rather than a third party.
	 *
	 * Origin is preferred; browsers send it on cross-origin POSTs. Referer is the
	 * fallback. A request carrying no usable origin information — neither header,
	 * or the literal `Origin: null` a `Referrer-Policy: no-referrer` document
	 * sends — is accepted, because rejecting those locks out legitimate visitors
	 * entirely. The check exists to stop a hostile page burning someone's
	 * attempts, not to be an authentication control.
	 *
	 * The comparison is against home_url()'s host only, and alternate hostnames
	 * are deliberately not supported. The gate exits on `wp` priority 0, before
	 * core's redirect_canonical at template_redirect priority 10, so www/non-www
	 * normalisation never runs on a gated site — and current_url() always builds
	 * the form action from home_url()'s origin, so a visitor who reached the
	 * site on a non-canonical hostname posts cross-origin and is refused here on
	 * their first attempt. It self-heals on the second (the failed POST leaves
	 * them on the canonical host).
	 *
	 * Accepting the request's own Host header as well looks like the fix and is
	 * not one: because the form action is pinned to home_url(), Host is already
	 * the canonical host on exactly the requests that fail, so the extra branch
	 * never fires for a real submission while widening what a hand-crafted one
	 * may claim. Canonicalise alternate hostnames at the web server instead.
	 *
	 * @return bool
	 */
	private static function is_same_origin() {
		$source = '';

		if ( ! empty( $_SERVER['HTTP_ORIGIN'] ) ) {
			$source = (string) wp_unslash( $_SERVER['HTTP_ORIGIN'] );
		} elseif ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			$source = (string) wp_unslash( $_SERVER['HTTP_REFERER'] );
		}

		if ( '' === $source ) {
			return true;
		}

		$source_origin = self::origin_of( $source );
		$home_origin   = self::origin_of( home_url( '/' ) );

		/*
		 * No usable origin information, so there is nothing to reject on.
		 *
		 * This is the `Origin: null` case as much as the missing-header one, and
		 * it is not hypothetical: a document served with `Referrer-Policy:
		 * no-referrer` posts with the literal string `null` as its Origin and no
		 * Referer at all — per the Fetch spec, and confirmed in Chromium against
		 * a same-origin form POST. Treating that as cross-origin would answer
		 * "Your session expired" to every submission on such a site, forever,
		 * with no attempt charged and nothing in the throttle to explain it, and
		 * administrators would not notice because they bypass the gate.
		 *
		 * Accepting it does reopen the narrow vector this check closes: a
		 * sandboxed iframe can force `Origin: null` deliberately. That is the
		 * right trade. This is not an authentication control — the password
		 * still has to be correct — it only raises the cost of burning someone
		 * else's attempts, and an attacker who simply POSTs five guesses from
		 * their own machine already exhausts a shared address's budget without
		 * needing a victim at all. A gate nobody can unlock is a worse outcome
		 * than a nuisance that was already available by an easier route.
		 */
		if ( '' === $source_origin || '' === $home_origin ) {
			return true;
		}

		return $source_origin === $home_origin;
	}

	/**
	 * Reduces a URL to its origin, for comparison.
	 *
	 * An origin is scheme + host + port, and all three matter. Comparing host
	 * alone — which this did until it was measured — accepts a page served from
	 * a different scheme or port of the same name: `http://example.com:8080`
	 * passes against `https://example.com`. That is a different origin by the
	 * definition every browser enforces, and a co-hosted dev server or a
	 * neighbour on shared hosting is exactly the foothold this check exists to
	 * deny, since from there they could burn a visitor's attempt budget.
	 *
	 * The port is filled in from the scheme when it is absent, so
	 * `https://example.com` and `https://example.com:443` compare equal.
	 *
	 * @param string $url URL to reduce.
	 * @return string Origin, or an empty string when there is no usable host.
	 */
	private static function origin_of( $url ) {
		$parts = wp_parse_url( (string) $url );

		if ( empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = isset( $parts['scheme'] ) ? strtolower( $parts['scheme'] ) : '';

		if ( ! empty( $parts['port'] ) ) {
			$port = (int) $parts['port'];
		} elseif ( 'https' === $scheme ) {
			$port = 443;
		} elseif ( 'http' === $scheme ) {
			$port = 80;
		} else {
			$port = 0;
		}

		return $scheme . '://' . strtolower( $parts['host'] ) . ':' . $port;
	}

	/**
	 * Human-readable lockout message with a minute countdown.
	 *
	 * @return string
	 */
	private static function lockout_message() {
		$minutes = (int) ceil( SPP_Throttle::seconds_remaining() / MINUTE_IN_SECONDS );
		$minutes = max( 1, $minutes );

		return sprintf(
			/* translators: %d: number of minutes until the lockout expires. */
			_n(
				'Too many failed attempts. Try again in %d minute.',
				'Too many failed attempts. Try again in %d minutes.',
				$minutes,
				'simple-password-protection'
			),
			$minutes
		);
	}

	/**
	 * The URL the visitor originally asked for.
	 *
	 * Built from the home URL's origin plus REQUEST_URI, never by passing
	 * REQUEST_URI through home_url(). On a subdirectory install home_url() would
	 * concatenate its own path again — home `https://example.com/blog` plus
	 * REQUEST_URI `/blog/about/` yields `https://example.com/blog/blog/about/`,
	 * so the form would post to a 404 and the unlock redirect would land there.
	 *
	 * @return string
	 */
	private static function current_url() {
		$path = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		$home = wp_parse_url( home_url( '/' ) );

		if ( empty( $home['scheme'] ) || empty( $home['host'] ) ) {
			return home_url( '/' );
		}

		$origin = $home['scheme'] . '://' . $home['host'];

		if ( ! empty( $home['port'] ) ) {
			$origin .= ':' . (int) $home['port'];
		}

		return esc_url_raw( $origin . '/' . ltrim( (string) $path, '/' ) );
	}

	/**
	 * CSS that swaps core's WordPress mark for the uploaded logo.
	 *
	 * Core styles the mark on `.login h1 a` at 84x84 with two background-image
	 * declarations, so the override has to restate size and dimensions.
	 *
	 * @param array $settings Plugin settings.
	 * @return string Style element, or an empty string when no logo is set.
	 */
	private static function logo_css( $settings ) {
		if ( empty( $settings['logo_id'] ) ) {
			return '';
		}

		$logo_url = wp_get_attachment_image_url( (int) $settings['logo_id'], 'full' );

		// The attachment may have been deleted since it was chosen.
		if ( ! $logo_url ) {
			return '';
		}

		/*
		 * esc_url()'s allowlist permits parentheses and quotes, so a URL
		 * containing them could close url() early and append arbitrary
		 * declarations to the gate's stylesheet. Normal uploads cannot produce
		 * such a URL — sanitize_file_name() strips them — but CDN, offload and
		 * image-optimisation plugins rewrite wp_get_attachment_url() output, so
		 * the characters are stripped rather than trusted.
		 */
		/*
		 * esc_url_raw(), not esc_url(): the display variant rewrites & to &#038;,
		 * and <style> content is raw text that the browser does not entity-decode,
		 * so a CDN URL with two query arguments would render as a broken link and
		 * the logo would silently vanish.
		 */
		$logo_url = str_replace( array( '(', ')', "'", '"', '\\' ), '', esc_url_raw( $logo_url ) );

		// esc_url_raw() returns '' for a scheme it does not allow, which a CDN or
		// offload filter can produce. url('') resolves to the document itself, so
		// emitting it would make every gate render fetch a second uncacheable
		// copy of the gate as an image.
		if ( '' === $logo_url ) {
			return '';
		}

		return sprintf(
			'<style id="spp-logo">.login h1 a{background-image:url(\'%s\');background-size:contain;background-position:center center;width:auto;max-width:320px;height:84px;}</style>',
			$logo_url
		);
	}

	/**
	 * Body classes, mirroring wp-login.php.
	 *
	 * @return string
	 */
	private static function body_class() {
		$classes = array( 'login', 'no-js', 'wp-core-ui', 'admin-color-modern' );

		if ( is_rtl() ) {
			$classes[] = 'rtl';
		}

		$classes[] = 'locale-' . sanitize_html_class( strtolower( str_replace( '_', '-', get_locale() ) ) );

		return implode( ' ', $classes );
	}

	/**
	 * Sends headers and renders the gate. Does not exit; the caller does.
	 *
	 * @param array $settings Plugin settings.
	 * @return void
	 */
	public static function render( $settings ) {
		/*
		 * Page caches must never store this screen: a cached gate would serve one
		 * stale nonce to every visitor.
		 *
		 * DONOTCACHEPAGE covers WP Super Cache, W3 Total Cache and friends.
		 * Batcache does not read it — it decides in advanced-cache.php, long
		 * before plugins load — so it needs its own explicit cancel.
		 */
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}

		if ( function_exists( 'batcache_cancel' ) ) {
			batcache_cancel();
		}

		nocache_headers();

		if ( ! headers_sent() ) {
			/*
			 * WP::handle_404() has already run and may have set 404. Forcing 200
			 * makes every gated response identical: otherwise a real slug returns
			 * 200 and a made-up one returns 404, letting an anonymous visitor
			 * enumerate every published slug on a site whose whole purpose is
			 * that none of them are visible.
			 */
			status_header( 200 );

			/*
			 * WP::send_headers() runs before template_redirect and, for feed
			 * requests, sets an ETag derived from get_lastpostmodified(). Left in
			 * place that leaks when the site last published — on a site whose
			 * whole point is that nothing about its content is visible — and it
			 * would also let a conditional GET be answered 304 from the feed's
			 * own validator rather than by the gate.
			 */
			header_remove( 'ETag' );
			header_remove( 'Last-Modified' );

			/*
			 * WP::send_headers() adds X-Pingback for a singular post with pings
			 * open. Left in place it is the same oracle in a different header:
			 * a real slug returns the gate WITH X-Pingback, a made-up one returns
			 * the identical gate without it, so slugs can still be enumerated
			 * despite the forced 200.
			 */
			header_remove( 'X-Pingback' );

			// Same ordering problem: a gated /feed/ would otherwise emit this
			// HTML under application/rss+xml and feed readers would show a parse
			// error instead of the password form.
			header( 'Content-Type: text/html; charset=' . get_bloginfo( 'charset' ) );

			header( 'X-Robots-Tag: noindex, nofollow' );
		}

		wp_enqueue_style( 'login' );

		$site_name = get_bloginfo( 'name', 'display' );

		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta http-equiv="Content-Type" content="<?php bloginfo( 'html_type' ); ?>; charset=<?php bloginfo( 'charset' ); ?>" />
<meta name="viewport" content="width=device-width" />
<meta name="robots" content="noindex, nofollow" />
<title><?php
	printf(
		/* translators: 1: Gate screen name, 2: Site name. */
		esc_html__( '%1$s &lsaquo; %2$s', 'simple-password-protection' ),
		esc_html__( 'Protected', 'simple-password-protection' ),
		esc_html( $site_name )
	);
?></title>
<?php
		wp_print_styles( array( 'login' ) );

		// Not escaped: logo_css() builds the element itself and escapes the URL.
		echo self::logo_css( $settings ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
<?php // Core sets `#login form p { margin-bottom: 0 }`, which outranks a lone class, so the selector has to match its specificity. ?>
<?php // white-space keeps the author's line breaks without ever emitting HTML. ?>
<style id="spp-gate">#login form p.spp-message{margin:0 0 16px;padding:0;font-size:14px;line-height:1.5;color:#3c434a;white-space:pre-line;}</style>
</head>
<body class="<?php echo esc_attr( self::body_class() ); ?>">
<script>document.body.className = document.body.className.replace('no-js','js');</script>

<div id="login">
	<h1 role="presentation" class="wp-login-logo">
		<a href="<?php echo esc_url( home_url( '/' ) ); ?>"><?php echo esc_html( $site_name ); ?></a>
	</h1>

		<?php
		if ( '' !== self::$error ) {
			wp_admin_notice(
				'<p>' . esc_html( self::$error ) . '</p>',
				array(
					'type'           => 'error',
					'id'             => 'login_error',
					'paragraph_wrap' => false,
				)
			);
		}
		?>

	<form name="spp_form" id="loginform" action="<?php echo esc_url( self::current_url() ); ?>" method="post">
		<?php if ( ! empty( $settings['message'] ) ) : ?>
			<p class="spp-message"><?php echo esc_html( $settings['message'] ); ?></p>
		<?php endif; ?>

		<p>
			<label for="spp_password"><?php esc_html_e( 'Password', 'simple-password-protection' ); ?></label>
			<input type="password" name="spp_password" id="spp_password" class="input" value="" size="20" autocomplete="current-password" autofocus />
		</p>

		<p class="forgetmenot">
			<input name="spp_remember" type="checkbox" id="spp_remember" value="1" />
			<label for="spp_remember"><?php esc_html_e( 'Remember Me', 'simple-password-protection' ); ?></label>
		</p>

		<p class="submit">
			<input type="submit" name="spp_submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Enter', 'simple-password-protection' ); ?>" />
			<input type="hidden" name="spp_redirect_to" value="<?php echo esc_url( self::current_url() ); ?>" />
			<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_NAME ); ?>
		</p>
	</form>

	<p id="backtoblog">
		<a href="<?php echo esc_url( home_url( '/' ) ); ?>">
			<?php
			printf(
				/* translators: %s: site name. */
				esc_html__( '&larr; Go to %s', 'simple-password-protection' ),
				esc_html( $site_name )
			);
			?>
		</a>
	</p>
</div>
</body>
</html>
		<?php
	}
}
