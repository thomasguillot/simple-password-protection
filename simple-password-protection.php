<?php
/**
 * Plugin Name:       Simple Password Protection
 * Plugin URI:        https://thomasguillot.com
 * Description:       Put a single shared password in front of your site, with your own logo on the gate.
 * Version:           1.0.0
 * Requires at least: 6.7
 * Requires PHP:      7.4
 * Author:            Thomas Guillot
 * Author URI:        https://thomasguillot.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       simple-password-protection
 * Domain Path:       /languages
 *
 * @package SimplePasswordProtection
 */

defined( 'ABSPATH' ) || exit;

define( 'SPP_VERSION', '1.0.0' );
define( 'SPP_FILE', __FILE__ );
define( 'SPP_DIR', plugin_dir_path( __FILE__ ) );
define( 'SPP_URL', plugin_dir_url( __FILE__ ) );

require_once SPP_DIR . 'includes/class-spp-access.php';
require_once SPP_DIR . 'includes/class-spp-settings.php';
require_once SPP_DIR . 'includes/class-spp-throttle.php';
require_once SPP_DIR . 'includes/class-spp-screen.php';
require_once SPP_DIR . 'includes/class-spp-gate.php';

add_action( 'plugins_loaded', array( 'SPP_Gate', 'init' ) );
add_action( 'plugins_loaded', array( 'SPP_Settings', 'init' ) );
add_action( 'plugins_loaded', array( 'SPP_Throttle', 'init' ) );

// Creating the row up front keeps the Settings API on its single-sanitize
// update_option() path instead of the double-sanitize add_option() one.
register_activation_hook( __FILE__, array( 'SPP_Settings', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'SPP_Throttle', 'deactivate' ) );

// Registers the unlock cookie with page caches that need it written to their own
// config to see it, rather than to a filter that runs after they have decided.
register_activation_hook( __FILE__, array( 'SPP_Gate', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'SPP_Gate', 'deactivate' ) );
