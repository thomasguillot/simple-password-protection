# Simple Password Protection

Put a single shared password in front of your site, with your own logo on the gate.

## Description

Simple Password Protection puts one shared password in front of your site's front end. Anyone who does not have the password sees a password form instead of your content. Anyone who enters it correctly is given a cookie and browses the site normally.

The gate screen is built from WordPress's own login chrome, so it inherits core's styling, right-to-left layouts, admin colour schemes, and focus handling. The one bespoke touch is a logo you upload to replace the WordPress "W" mark, plus an optional message above the password box.

This is a deliberately small plugin. There is one password for the whole site. There are no per-page rules, no per-role passwords, no separate visitor accounts, and no IP allowlists.

### What it does

* Blocks the front end behind a single shared password.
* Replaces the WordPress logo on the gate with an image from your media library.
* Shows an optional message above the password box.
* Lets anyone with the `manage_options` capability through without entering the password. This is on by default and can be turned off.
* Optionally lets every logged-in user through.
* Blocks RSS and Atom feeds and the REST API by default, with a separate toggle for each.
* Remembers a visitor for 14 days when they tick Remember Me, or until they close the browser when they do not.
* Locks an IP address out after five wrong passwords, until the end of the current 15-minute window.

### What it does not do

* It does not support per-post, per-page or per-role passwords.
* It does not support multiple passwords or per-visitor credentials.
* It is built for single sites, not multisite networks.
* It does not protect files served directly by your web server. See the FAQ.
* It cannot cover `wp-activate.php`, which WordPress loads with no plugins at all. See the FAQ.

Entry points other than normal page views are handled too. Anonymous `admin-ajax.php`
and `admin-post.php` requests are refused with 401, so a theme's `wp_ajax_nopriv_` or
`admin_post_nopriv_` handler cannot hand out post content. The same applies to the core
scripts that load WordPress and answer directly without ever reaching the template
loader: `wp-comments-post.php`, `wp-trackback.php` and `wp-links-opml.php`.

Feeds, `robots.txt` and trackbacks are a special case, because WordPress serves those
even on requests that never fire the hook plugins normally use to intercept a page
view. Asking for `wp-blog-header.php/feed/` rather than `/feed/` is enough to reach
them. The gate therefore hooks `wp` as well, which every route that boots WordPress
normally passes through. The one route it cannot cover is `wp-activate.php`—see the
FAQ for the one-line server block.

**XML-RPC is switched off entirely while the gate is up.** The
whole endpoint is refused with a 403 before WordPress parses the request body, so
`pingback.ping`, the authenticated content methods, the RSD discovery document and
even the protocol-level `system.*` calls are all unreachable. Removing the methods
alone would not have been enough: WordPress re-registers `system.listMethods`,
`system.getCapabilities` and `system.multicall` after the filter that removes
everything else, leaving `multicall` as a resource-abuse surface on a site that had
been told it was closed.

This one is all-or-nothing: `xmlrpc.php` empties `$_COOKIE` before loading
WordPress and runs before authentication, so there is no point at which the plugin
could tell an administrator, or a visitor who knows the password, apart from an
anonymous caller.

Be aware of the consequence: **anything that talks to your site over XML-RPC stops
working while protection is on**—the WordPress mobile apps, MarsEdit, and Jetpack's
connection. If you rely on any of those, this plugin is not the right fit for that site
while the gate is up.

### How the password is stored

The password is hashed with `wp_hash_password()` and checked with `wp_check_password()`. The plaintext password is never written to the database and never sent back to the browser. That means it cannot be recovered, only replaced.

The unlock cookie does not contain the password or the hash. It contains an HMAC of the stored hash, keyed on the site's auth salt. Because the cookie value derives from the hash, changing the password immediately invalidates every unlock cookie that has already been handed out.

### Caching

While protection is on, **every** front-end response is marked uncacheable, not only the gate screen. The plugin defines `DONOTCACHEPAGE`, calls `batcache_cancel()` where Batcache is present, and sends `nocache_headers()`. The gate screen additionally sends `X-Robots-Tag: noindex` and a `noindex, nofollow` robots meta tag; pages served to a visitor who has entered the password are ordinary page views and are not marked noindex.

This is deliberate and it does mean you lose page caching while the gate is up. It is not optional: if an unlocked visitor's page view were cacheable, a full-page cache that does not recognise the unlock cookie would store that private page under the anonymous cache key and then serve it to visitors who never entered the password. The unlock cookie is named `wp-spp-unlock_...` precisely because caches conventionally bypass cookies starting with `wp`. The plugin also registers that cookie with WP Super Cache on activation, using the `wpsc_add_cookie` action so the name is written into WP Super Cache's own configuration—a filter would be too late, because WP Super Cache decides whether to serve a cached page before ordinary plugins load.

Enabling protection, changing the password, or changing any bypass toggle flushes the page cache, because pages cached earlier would otherwise keep being served from before the change. **A CDN or edge cache in front of your site is outside the plugin's reach—purge it yourself.** If the automatic flush fails, the plugin says so with an admin notice rather than letting you believe the gate is effective.

### Filters

`spp_client_ip` filters the IP address used for throttling. It receives a validated IP string, or an empty string when `REMOTE_ADDR` is missing or invalid. It never receives the bucketed value that is counted, which for IPv6 is a prefix like `2001:db8:1:2::/64`. Whatever the filter returns goes through that same bucketing afterwards, so the reverse-proxy example below can return a plain validated address without masking it first.

## Installation

1. Upload the plugin folder to `wp-content/plugins/`, or install the zip from **Plugins → Add New → Upload Plugin**.
2. Activate the plugin.
3. Go to **Settings → Password Protection**.
4. Click **Set Password**, accept the generated password or type your own, and copy it somewhere safe. You will not be able to read it again.
5. Under **Protection**, tick **Require a password to view this site** and save.

If you enable protection before setting a password, the site stays public and an admin notice tells you so. This is deliberate: locking a site behind a password that does not exist would lock you out too.

The same choice is made if the plugin's settings row is ever unreadable, whether something else wrote over `spp_settings` or the database corrupted it. The plugin falls back to its defaults, so the site is public rather than gated. That is the safer failure for a plugin that also has to let you back in to fix it. The alternative is refusing every request on the strength of a settings row nobody can parse, which turns a rare storage fault into an outage. If confidentiality matters more to you than availability, check the settings screen after any migration or bulk option edit.

## Frequently Asked Questions

### I forgot the password. How do I get it back?

You cannot. The password is stored as a hash, so there is nothing to read back, decrypt, or email. Nobody, including you, can recover it.

What you can do is replace it. Log in to `/wp-admin/`, go to **Settings → Password Protection**, click **Set New Password**, and save. Administrators reach the admin area without passing the gate, so being locked out of the front end does not lock you out of the settings screen.

Setting a new password also signs out everyone who was already through the gate, because every unlock cookie is derived from the stored hash. Plan for that if you are sharing the password with a group.

### Why are feeds and the REST API blocked by default, and when should I allow them?

Both are doors into the same content the gate is meant to hide. An RSS feed hands a stranger your post titles, excerpts, and often the full post body. The REST API serves posts, pages, media, and user names to unauthenticated requests. Leaving either open would defeat the point of the gate, so both are blocked unless you say otherwise.

Allow feeds when you are gating a site that people legitimately follow in a reader, or when a service you control pulls the feed and you accept that the feed URL is effectively public.

Allow the REST API when something anonymous needs it: a headless front end, a mobile app, or an external integration that authenticates some other way.

Editors and administrators are exempt from the REST gate whatever this toggle says, so the block editor, the media modal, and autosave keep working for them. Gating them would buy nothing, because they already read every post in wp-admin, which is never gated.

The exemption is based on the `edit_others_posts` capability, not on being logged in and not on `edit_posts`. That distinction matters more than it looks. `edit_posts` is WordPress's "can write" capability rather than "can read everything": a Contributor or an Author holds it *without* `edit_others_posts`, so wp-admin shows them nothing of anyone else's posts. Exempting them would have let `/wp-json/wp/v2/posts` return every published post in full to an account that cannot load your home page without the password, so REST would hand out what the front door refuses.

So Contributors and Authors are treated like any other visitor: they enter the password once and everything works, including the editor, because the unlock cookie is sent with their REST calls too. If you would rather they never needed it, tick **All logged-in users**, or lower the bar explicitly:

```php
add_filter( 'spp_rest_exempt_capability', function () {
	return 'edit_posts';
} );
```

That is a real trade: it gives every Contributor read access to all published content on the site.

Turn either toggle on only if you understand that it exposes the content behind it to anyone who knows the URL.

### Throttling locks out all my visitors at once. What is going on?

The throttle counts failed attempts per IP address, and it reads that address from `REMOTE_ADDR` only. If your site sits behind Cloudflare, a load balancer, a caching proxy, or any other reverse proxy, `REMOTE_ADDR` is the proxy's address, not the visitor's. Every visitor then looks like the same IP, so five wrong guesses from any one of them locks out everyone.

The fix is to tell the plugin where the real address is, using the `spp_client_ip` filter:

```php
add_filter(
	'spp_client_ip',
	function ( $ip ) {
		// Cloudflare. Use the header your own proxy sets.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$validated = filter_var( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ), FILTER_VALIDATE_IP );

			if ( false !== $validated ) {
				return $validated;
			}
		}

		return $ip;
	}
);
```

The plugin does not read `X-Forwarded-For` on your behalf, and that is on purpose. That header is supplied by the client, so unless a proxy you control overwrites it on every request, an attacker can put whatever they like in it and rotate the value to get unlimited password guesses. Trusting it by default would turn the throttle off for everyone while looking like it was on. Only add a header to the filter if you know your proxy sets it and strips any incoming copy.

Two details worth knowing about how the limit is enforced.

The counter lives in the database, not the object cache, and is incremented with a single atomic statement. That costs one write per failed guess, which is deliberate: an object-cache counter silently resets its budget to zero whenever Redis restarts or evicts, and a limit that resets on eviction is not a limit. An attempt is reserved *before* the password is checked, and the reservation number decides whether the check runs at all, so a burst of simultaneous guesses cannot each slip past a stale count.

IPv6 addresses are counted per `/64`, not per address. A single IPv6 address is a misleading thing to rate-limit: the smallest block anyone is given is a `/64`, so a `$5` virtual server comes with 18 quintillion addresses, and five guesses on each of them would not be a limit at all. Counting the `/64` means one allocation gets one budget. IPv4 is counted whole.

The flip side is the honest weakness of any IP-based throttle, worth knowing before you rely on it: everyone sharing one IPv4 address shares one budget. Mobile networks, office and school NATs, and VPN exits routinely put thousands of people behind a single address, and somebody on that address making five wrong guesses every fifteen minutes can keep everyone else on it locked out for as long as they care to. Treat the throttle as a speed bump rather than an intrusion-prevention system. What protects the site is a password strong enough that guessing it is hopeless.

Windows are fixed rather than rolling, and the lockout lasts until the end of the current 15-minute window, so the wait is somewhere between a few seconds and 15 minutes rather than always 15. The upside is that rolling over to a new window needs no cleanup step for concurrent requests to race on. The trade is that an attacker timing a burst across a boundary gets up to ten guesses in quick succession rather than five. That still makes online guessing impractical.

### Does this protect my uploads and other files?

No. The gate runs inside WordPress, so it only covers requests WordPress handles. A PDF or image at a direct `wp-content/uploads/...` URL is served by your web server without WordPress being involved, and stays reachable to anyone who has the link. If you need those protected too, block the uploads directory at the server level.

### Should I block anything at the web server?

One file, yes: `wp-activate.php`.

WordPress fires the hook plugins use to intercept a page view only when the request came through `index.php`, but it processes feeds, `robots.txt` and trackbacks regardless of how it was reached. The plugin handles that by hooking `wp` as well, which catches every route that boots WordPress normally—including someone asking for `wp-blog-header.php/feed/` directly.

`wp-activate.php` is the exception, and it cannot be fixed from inside a plugin. It declares itself an installer before loading WordPress, and WordPress deliberately loads *no plugins at all* during installation. No plugin code runs on that request, so nothing this plugin does can gate it, and `wp-activate.php/feed/` will serve your feed. The file only does anything on multisite, so on a single site you lose nothing by blocking it:

```nginx
# nginx
location = /wp-activate.php { deny all; }
```

```apache
# Apache
<Files "wp-activate.php">
	Require all denied
</Files>
```

If your feed is empty, or you have ticked "RSS and Atom feeds" anyway, there is nothing here to leak and you can skip this.

### Can administrators get in without the password?

Yes, by default. **Allow administrators** is on out of the box and covers any user with the `manage_options` capability, which on a standard single site means administrators. Turn it off if you want everyone, including yourself, to pass through the gate on the front end. The admin area is never gated either way.

### Does it work on multisite?

It is built and tested for single sites. There is no network activation and no network settings screen. Activating it per site on a network may work, but it is not supported.

### What happens when I deactivate or delete the plugin?

Deactivating removes the gate immediately and your site is public again. Deleting the plugin runs the uninstall handler, which removes the `spp_settings` option row and any leftover throttle records. Nothing else is left behind.

After deactivating, purge your page cache and any CDN—gate screens or protected pages cached during the switch-over can otherwise linger.

## Screenshots

1. The settings screen at Settings → Password Protection, with the password field, logo picker, and access toggles.
2. The gate screen with a custom logo and a message above the password box.
3. The gate screen showing the lockout message after too many failed attempts.

## Changelog

### 1.0.0

* Initial release.
