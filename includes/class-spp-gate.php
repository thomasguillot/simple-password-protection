<?php
/**
 * Request interception.
 *
 * @package SimplePasswordProtection
 */

defined( 'ABSPATH' ) || exit;

/**
 * Wires the access decision into WordPress.
 */
class SPP_Gate {

	/**
	 * Guards against rendering the gate twice in one request.
	 *
	 * @var bool
	 */
	private static $handled = false;

	/**
	 * Registers hooks.
	 *
	 * @return void
	 */
	public static function init() {
		/*
		 * `wp`, not just `template_redirect`, and this is load-bearing.
		 *
		 * template_redirect only fires inside `if ( wp_using_themes() )` in
		 * wp-includes/template-loader.php, and WP_USE_THEMES is defined by
		 * index.php and nothing else. The feed, robots.txt and trackback
		 * handlers sit BELOW that guard — core's own comment there reads
		 * "Process feeds and trackbacks even if not using themes". So any
		 * request that reaches template-loader.php by another route serves
		 * those without template_redirect ever firing:
		 *
		 *   GET /wp-blog-header.php/feed/   -> full RSS, gate never ran
		 *   GET /wp-blog-header.php?robots=1 -> real robots.txt
		 *   GET /wp-signup.php/feed/         -> full RSS
		 *
		 * The `wp` action fires at the end of WP::main() for every wp() call —
		 * which is every one of those entry points, plus index.php — and after
		 * parse_request/query_posts/handle_404, so is_feed() and friends are
		 * already accurate. wp() never runs in wp-admin, and a REST request dies
		 * inside parse_request before this fires, so is_exempt() still applies.
		 *
		 * template_redirect is kept as well: it costs nothing, and it keeps the
		 * gate working if a future core release stops calling wp() on some path.
		 * self::$handled makes the pair idempotent.
		 *
		 * NOT covered, and not coverable from a plugin: wp-activate.php defines
		 * WP_INSTALLING before loading WordPress, and wp_get_active_and_valid_plugins()
		 * returns nothing at all while installing, so no plugin code runs on that
		 * request. See the readme for the server-level block.
		 */
		add_action( 'wp', array( __CLASS__, 'maybe_gate' ), 0 );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_gate' ), 1 );

		/*
		 * Priority 101, after core's rest_cookie_check_errors at 100. That
		 * callback calls wp_set_current_user( 0 ) for a request carrying valid
		 * auth cookies but no REST nonce. Running before it would mean deciding
		 * the edit_posts exemption against an identity core is about to discard:
		 * SPP would wave the request through as an editor, then core would
		 * downgrade it to anonymous and serve it anyway.
		 */
		add_filter( 'rest_authentication_errors', array( __CLASS__, 'maybe_gate_rest' ), 101 );

		// admin-ajax.php and xmlrpc.php never reach template_redirect, so each
		// needs its own entry point.
		add_action( 'admin_init', array( __CLASS__, 'maybe_gate_ajax' ), 1 );

		// wp-comments-post.php calls wp_handle_comment_submission() straight
		// after wp-load.php, and wp-trackback.php calls wp() without the
		// template loader, so neither fires template_redirect or admin_init.
		add_action( 'init', array( __CLASS__, 'maybe_gate_direct_scripts' ), 0 );

		// xmlrpc.php defines XMLRPC_REQUEST and requires wp-load.php — which is
		// what fires `init` — before it does anything else, so this runs ahead
		// of ?rsd handling and serve_request() too.
		add_action( 'init', array( __CLASS__, 'maybe_gate_xmlrpc' ), 0 );

		// Must run before WP::send_headers(), which can answer 304 and exit
		// inside wp() — before template_redirect gets a say.
		add_action( 'parse_request', array( __CLASS__, 'suppress_conditional_get' ), 0 );
		add_filter( 'xmlrpc_enabled', array( __CLASS__, 'filter_xmlrpc_enabled' ) );
		add_filter( 'xmlrpc_methods', array( __CLASS__, 'filter_xmlrpc_methods' ) );

		// Teach WP Super Cache that the unlock cookie makes a request non-anonymous.
		add_filter( 'wpsc_rejected_cookies', array( __CLASS__, 'filter_rejected_cookies' ) );

		// wp-admin is never gated, but one core dashboard widget hands out post
		// titles and permalinks to anyone who can merely log in.
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'filter_dashboard_widgets' ) );
	}

	/**
	 * Removes the dashboard widget that leaks content to an otherwise-gated user.
	 *
	 * wp-admin is deliberately exempt from the gate — that is what stops an owner
	 * locking themselves out of the settings screen. The cost is that anything
	 * core shows inside wp-admin is outside the gate too, and core's Activity
	 * widget is registered with no capability check whatsoever
	 * (wp-admin/includes/dashboard.php: only the At a Glance and Quick Draft
	 * widgets beside it are capability-gated). wp_dashboard_recent_posts() then
	 * prints the title, date and permalink of the most recent published posts to
	 * anyone who can load the Dashboard, which is anyone with `read`.
	 *
	 * A Subscriber is precisely the visitor the capability tests in maybe_gate_rest()
	 * and maybe_gate_ajax() go out of their way to keep gated. On a site with open
	 * registration or WooCommerce accounts, registering was otherwise enough to
	 * enumerate the post titles and slugs the gate exists to hide — the same
	 * enumeration render() forces status 200 and strips X-Pingback to prevent.
	 *
	 * Anyone who already reads every post in wp-admin — exempt_capability(),
	 * the same threshold the REST and AJAX gates use — sees all of this in
	 * edit.php already, so they are left alone and the Dashboard keeps working
	 * normally for them.
	 *
	 * @return void
	 */
	public static function filter_dashboard_widgets() {
		if ( current_user_can( self::exempt_capability() ) ) {
			return;
		}

		$settings = SPP_Settings::get();

		if ( ! self::is_active( $settings ) ) {
			return;
		}

		$context = array(
			'is_logged_in'       => is_user_logged_in(),
			'can_manage_options' => current_user_can( 'manage_options' ),
			'is_feed'            => false,
			'is_rest'            => false,
			'has_valid_cookie'   => SPP_Screen::has_valid_cookie( $settings ),
		);

		if ( ! SPP_Access::should_gate( $settings, $context ) ) {
			return;
		}

		remove_meta_box( 'dashboard_activity', 'dashboard', 'normal' );
	}

	/**
	 * Whether protection is switched on and usable.
	 *
	 * @param array $settings Plugin settings.
	 * @return bool
	 */
	private static function is_active( $settings ) {
		return ! empty( $settings['enabled'] ) && ! empty( $settings['password_hash'] );
	}

	/**
	 * Requests that are never gated, regardless of settings.
	 *
	 * wp-login.php is exempt by construction: it never fires template_redirect.
	 *
	 * @return bool
	 */
	private static function is_exempt() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		if ( wp_doing_cron() ) {
			return true;
		}

		if ( is_admin() ) {
			return true;
		}

		return false;
	}

	/**
	 * Marks the current response as unstorable by any shared cache.
	 *
	 * This has to run for EVERY front-end response while protection is active,
	 * not only for the gate screen. Otherwise an unlocked visitor's page view is
	 * emitted with ordinary cacheable headers, a full-page cache that does not
	 * recognise the unlock cookie stores that private HTML under the anonymous
	 * cache key, and every later anonymous request is served the protected page
	 * straight from cache without WordPress ever running.
	 *
	 * Batcache is already handled by the cookie's `wp-` prefix, but WP Super
	 * Cache, nginx fastcgi_cache and Varnish match their own narrower cookie
	 * allowlists and are not.
	 *
	 * A protected site is not a public high-traffic site, so losing page caching
	 * while the gate is on is the right trade.
	 *
	 * @return void
	 */
	private static function prevent_caching() {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}

		// Batcache decides in advanced-cache.php, before plugins load, and never
		// reads DONOTCACHEPAGE.
		if ( function_exists( 'batcache_cancel' ) ) {
			batcache_cancel();
		}

		if ( ! headers_sent() ) {
			nocache_headers();
		}
	}

	/**
	 * Registers the unlock cookie with WP Super Cache, persistently.
	 *
	 * The `wpsc_rejected_cookies` filter below is not enough on its own, and
	 * relying on it alone was wrong. WP Super Cache decides whether to serve a
	 * cached page inside `advanced-cache.php`, which runs before any ordinary
	 * plugin is loaded, so a filter this plugin adds on `plugins_loaded` cannot
	 * reach that decision. The `wpsc_add_cookie` action is the documented
	 * integration point precisely because it writes the cookie name into WP
	 * Super Cache's own config file, where the early code can see it.
	 *
	 * A no-op when WP Super Cache is not installed: nothing is listening.
	 *
	 * @return void
	 */
	public static function activate() {
		do_action( 'wpsc_add_cookie', SPP_Screen::cookie_name() );
	}

	/**
	 * Removes the unlock cookie from WP Super Cache's persisted list.
	 *
	 * @return void
	 */
	public static function deactivate() {
		do_action( 'wpsc_delete_cookie', SPP_Screen::cookie_name() );
	}

	/**
	 * Adds the unlock cookie to WP Super Cache's non-anonymous cookie list.
	 *
	 * Kept alongside activate()'s persistent registration: this one covers the
	 * decision about whether to STORE a page, which does run with plugins
	 * loaded, while the persisted entry covers whether to SERVE one.
	 *
	 * @param array $cookies Cookie name fragments that suppress caching.
	 * @return array
	 */
	public static function filter_rejected_cookies( $cookies ) {
		if ( ! is_array( $cookies ) ) {
			$cookies = array();
		}

		$cookies[] = 'wp-spp-unlock_';

		return $cookies;
	}

	/**
	 * Capability that exempts a logged-in user from the REST and AJAX gates.
	 *
	 * @return string
	 */
	private static function exempt_capability() {
		/**
		 * Filters the capability that lets a logged-in user past the gate on
		 * REST, admin-ajax and admin-post requests.
		 *
		 * Defaults to `edit_others_posts`: the capability that actually means
		 * "already reads every post in wp-admin", which is the whole
		 * justification for the exemption. Editors and administrators have it.
		 *
		 * `edit_posts` is the tempting default because it is the lowest
		 * capability the block editor needs, but it is the wrong test. It is
		 * WordPress's "can write" capability, not "can read everything": a
		 * Contributor holds it without `edit_others_posts`, so wp-admin shows
		 * them nothing of anyone else's posts while /wp/v2/posts would return
		 * every published post in full. That also contradicts the front end,
		 * where the same user cannot load the home page without the password.
		 *
		 * Lower it to `edit_posts` if your Contributors and Authors should be
		 * able to use the editor without knowing the site password and you
		 * accept that this lets them read all published content.
		 *
		 * @param string $capability Capability required to bypass the gate.
		 */
		return (string) apply_filters( 'spp_rest_exempt_capability', 'edit_others_posts' );
	}

	/**
	 * Builds the context array for SPP_Access.
	 *
	 * @param array $settings Plugin settings.
	 * @param bool  $is_rest  Whether this is a REST request.
	 * @return array
	 */
	private static function context( $settings, $is_rest = false ) {
		return array(
			'is_logged_in'       => is_user_logged_in(),
			'can_manage_options' => current_user_can( 'manage_options' ),
			'is_feed'            => ! $is_rest && is_feed(),
			'is_rest'            => $is_rest,
			'has_valid_cookie'   => SPP_Screen::has_valid_cookie( $settings ),
		);
	}

	/**
	 * Gates front-end requests.
	 *
	 * @return void
	 */
	public static function maybe_gate() {
		if ( self::is_exempt() ) {
			return;
		}

		// Registered on both `wp` and `template_redirect`; only the first one to
		// arrive does the work.
		if ( self::$handled ) {
			return;
		}

		self::$handled = true;

		$settings = SPP_Settings::get();

		if ( self::is_active( $settings ) ) {
			self::prevent_caching();

			/*
			 * Runs before the access check so a correct password unlocks and
			 * redirects within the same request.
			 *
			 * Only while protection is actually on. handle_post() reserves a
			 * throttle attempt — a database write — before it looks at anything
			 * else, and for a logged-out visitor wp_verify_nonce() keeps
			 * accepting a nonce for up to 24 hours. Left unconditional, a nonce
			 * harvested while the site was gated would let someone keep writing
			 * throttle rows for a day after protection was switched off, against
			 * a gate that is no longer doing anything.
			 */
			SPP_Screen::handle_post( $settings );
		}

		if ( ! SPP_Access::should_gate( $settings, self::context( $settings ) ) ) {
			return;
		}

		SPP_Screen::render( $settings );
		exit;
	}

	/**
	 * Gates anonymous REST requests.
	 *
	 * Only anonymous traffic is gated. A logged-in user can already read
	 * everything through wp-admin, which is never gated, so returning 401 to
	 * their REST calls buys no confidentiality — it only breaks the block editor,
	 * the media modal and autosave for every non-administrator role.
	 *
	 * @param WP_Error|null|true $result Existing authentication result.
	 * @return WP_Error|null|true
	 */
	public static function maybe_gate_rest( $result ) {
		// Respect an error another handler already raised.
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		if ( self::is_exempt() ) {
			return $result;
		}

		$settings = SPP_Settings::get();

		/*
		 * Protected JSON must not be storable either. WordPress only sends
		 * no-cache headers on REST responses for logged-in requests, so an
		 * unlocked anonymous request would otherwise return cacheable protected
		 * content that a proxy could replay to visitors with no unlock cookie.
		 */
		if ( self::is_active( $settings ) ) {
			self::prevent_caching();
		}

		/*
		 * Users who already read every post in wp-admin are exempt, because
		 * gating them would buy no confidentiality while breaking the block
		 * editor, the media modal and autosave for them.
		 *
		 * The test is capability-based rather than merely "logged in", and the
		 * capability is the one that matches that sentence — see
		 * exempt_capability(). Everyone below it goes through the normal
		 * decision, so a Contributor who has entered the site password is let
		 * through on the strength of the unlock cookie, exactly as they are on
		 * the front end, and one who has not is refused in both places. That
		 * consistency is the point: REST must not hand out what the front door
		 * would not.
		 */
		if ( is_user_logged_in() && current_user_can( self::exempt_capability() ) ) {
			return $result;
		}

		if ( ! SPP_Access::should_gate( $settings, self::context( $settings, true ) ) ) {
			return $result;
		}

		return new WP_Error(
			'spp_password_required',
			__( 'This site is password protected.', 'simple-password-protection' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Gates unauthenticated admin-ajax requests.
	 *
	 * admin-ajax.php loads admin.php and never reaches template_redirect, and
	 * is_admin() is true there, so the normal gate cannot see it. Themes and
	 * plugins routinely register wp_ajax_nopriv_* handlers that return post
	 * content — a load-more button, a search-suggest endpoint — which would
	 * otherwise serve protected content to anyone.
	 *
	 * Only unauthenticated requests are gated; a logged-in user's AJAX is left
	 * alone for the same reason as REST.
	 *
	 * @return void
	 */
	public static function maybe_gate_ajax() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$is_ajax = wp_doing_ajax();

		// admin-post.php also fires admin_init, also skips template_redirect,
		// and also dispatches *_nopriv_ handlers — but wp_doing_ajax() is false
		// there, so it needs detecting separately.
		$script         = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';
		$is_admin_post  = ( 'admin-post.php' === $script );

		if ( ! $is_ajax && ! $is_admin_post ) {
			return;
		}

		/*
		 * Same capability test as REST, and for the same reason. "Logged in" is
		 * too loose: a Subscriber or WooCommerce customer cannot read posts in
		 * wp-admin, so an authenticated wp_ajax_* or admin_post_* handler that
		 * returns post content would be a genuine way around the gate for them.
		 */
		if ( is_user_logged_in() && current_user_can( self::exempt_capability() ) ) {
			return;
		}

		$settings = SPP_Settings::get();

		if ( ! self::is_active( $settings ) ) {
			return;
		}

		self::prevent_caching();

		// Everyone else goes through the normal decision, so allow_admins and
		// allow_logged_in are honoured here too rather than being ignored.
		$context = array(
			'is_logged_in'       => is_user_logged_in(),
			'can_manage_options' => current_user_can( 'manage_options' ),
			'is_feed'            => false,
			'is_rest'            => false,
			'has_valid_cookie'   => SPP_Screen::has_valid_cookie( $settings ),
		);

		if ( ! SPP_Access::should_gate( $settings, $context ) ) {
			return;
		}

		if ( $is_ajax ) {
			wp_send_json_error(
				array( 'message' => __( 'This site is password protected.', 'simple-password-protection' ) ),
				401
			);
		}

		wp_die(
			esc_html__( 'This site is password protected.', 'simple-password-protection' ),
			esc_html__( 'Password required', 'simple-password-protection' ),
			array( 'response' => 401 )
		);
	}

	/**
	 * Stops core answering a gated request with a bare 304.
	 *
	 * For a feed request WP::send_headers() computes Last-Modified and ETag and,
	 * on a matching If-Modified-Since or If-None-Match, sends 304 and exits —
	 * all inside wp(), before template_redirect fires. The gate never runs, and
	 * the validators it echoes back reveal get_lastpostmodified(), so repeating
	 * the request over time maps out publishing activity on a site whose whole
	 * point is that nothing about its content is visible.
	 *
	 * Removing the request headers is enough to stop the short-circuit. Losing
	 * 304s while the gate is up costs nothing, since every gated response is
	 * already sent uncacheable.
	 *
	 * @return void
	 */
	public static function suppress_conditional_get() {
		if ( is_admin() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		if ( ! self::is_active( SPP_Settings::get() ) ) {
			return;
		}

		unset( $_SERVER['HTTP_IF_MODIFIED_SINCE'], $_SERVER['HTTP_IF_NONE_MATCH'] );
	}

	/**
	 * Gates core scripts that bypass both the template loader and admin_init.
	 *
	 * wp-comments-post.php and wp-trackback.php each load WordPress and act
	 * immediately. On a gated site they would otherwise accept anonymous comment
	 * and trackback submissions, write them to the database, trigger moderation
	 * email, and answer with responses that differ by whether the target post
	 * exists — the same kind of signal render() forces status 200 to suppress.
	 *
	 * @return void
	 */
	public static function maybe_gate_direct_scripts() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';

		$direct = array(
			'wp-comments-post.php',
			'wp-trackback.php',
			// Requires wp-load.php and emits its document immediately: no wp(),
			// no template loader, no admin_init. On a site using the Link
			// Manager it hands out every bookmark name, URL and feed.
			'wp-links-opml.php',
		);

		if ( ! in_array( $script, $direct, true ) ) {
			return;
		}

		$settings = SPP_Settings::get();

		if ( ! self::is_active( $settings ) ) {
			return;
		}

		self::prevent_caching();

		$context = array(
			'is_logged_in'       => is_user_logged_in(),
			'can_manage_options' => current_user_can( 'manage_options' ),
			'is_feed'            => false,
			'is_rest'            => false,
			'has_valid_cookie'   => SPP_Screen::has_valid_cookie( $settings ),
		);

		if ( ! SPP_Access::should_gate( $settings, $context ) ) {
			return;
		}

		wp_die(
			esc_html__( 'This site is password protected.', 'simple-password-protection' ),
			esc_html__( 'Password required', 'simple-password-protection' ),
			array( 'response' => 401 )
		);
	}

	/**
	 * Whether the current request should be allowed to use XML-RPC.
	 *
	 * @return bool
	 */
	private static function xmlrpc_allowed() {
		$settings = SPP_Settings::get();

		if ( ! self::is_active( $settings ) ) {
			return true;
		}

		return SPP_Screen::has_valid_cookie( $settings );
	}

	/**
	 * Disables XML-RPC authentication while the gate is up.
	 *
	 * @param bool $enabled Whether XML-RPC is enabled.
	 * @return bool
	 */
	public static function filter_xmlrpc_enabled( $enabled ) {
		return self::xmlrpc_allowed() ? $enabled : false;
	}

	/**
	 * Removes every XML-RPC method while the gate is up.
	 *
	 * xmlrpc.php answers system.listMethods and pingback.ping without any
	 * authentication, so a gated site would otherwise still expose its XML-RPC
	 * surface — and a Subscriber who is meant to be gated could read posts
	 * through it.
	 *
	 * @param array $methods Registered XML-RPC methods.
	 * @return array
	 */
	public static function filter_xmlrpc_methods( $methods ) {
		return self::xmlrpc_allowed() ? $methods : array();
	}

	/**
	 * Refuses the whole XML-RPC endpoint outright while the gate is up.
	 *
	 * Emptying xmlrpc_methods is not enough on its own: IXR_Server::setCallbacks()
	 * unconditionally re-adds system.getCapabilities, system.listMethods and
	 * system.multicall AFTER that filter runs, so a gated site would still parse
	 * every XML-RPC request body and execute those three methods regardless —
	 * multicall chief among them, since it lets a caller batch an arbitrary
	 * number of calls into a single request. xmlrpc.php?rsd is also reachable
	 * whatever the filters say, and emits the RSD discovery document.
	 *
	 * xmlrpc.php defines XMLRPC_REQUEST and requires wp-load.php — which is what
	 * fires this very `init` hook — before it does anything else, so refusing
	 * here runs ahead of both ?rsd handling and serve_request().
	 *
	 * xmlrpc.php also sets $_COOKIE = array() before loading WordPress, so
	 * SPP_Screen::has_valid_cookie() can never see an unlock cookie on this
	 * request: there is no cookie an XML-RPC client could present, which is why
	 * this refuses the endpoint outright rather than pretending a cookie could
	 * get someone through. The xmlrpc_enabled/xmlrpc_methods filters are kept
	 * as defence in depth regardless.
	 *
	 * The denial is uniform on purpose: no post data, a fixed body, and a plain
	 * string rather than wp_die()'s HTML page, which an XML-RPC client has no
	 * use for.
	 *
	 * @return void
	 */
	public static function maybe_gate_xmlrpc() {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}

		if ( self::xmlrpc_allowed() ) {
			return;
		}

		if ( ! headers_sent() ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=UTF-8' );
		}

		echo 'Forbidden';
		exit;
	}
}
