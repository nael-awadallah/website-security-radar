<?php

/**
 * Plugin Name: Website Security Radar — Malware Scanner, File Monitor & Hardening Check
 * Plugin URI: https://wordpress.org/plugins/website-security-radar/
 * Description: Lightweight security intelligence for WordPress agencies and website owners.
 * Version: 1.0.0
 * Author: Nael Awadallah
 * Author URI: https://www.nael-portfolio.site
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: website-security-radar
 * Requires at least: 6.2
 * Requires PHP: 8.0
 *
 * @package WebsiteSecurityRadar
 */
if (!defined('ABSPATH')) {
	exit;
}

define('WSR_PLUGIN_VERSION', '1.0.0');
define('WSR_PLUGIN_FILE', __FILE__);
define('WSR_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WSR_PLUGIN_URL', plugin_dir_url(__FILE__));

require_once WSR_PLUGIN_DIR . 'includes/class-helpers.php';
require_once WSR_PLUGIN_DIR . 'includes/class-settings.php';
require_once WSR_PLUGIN_DIR . 'includes/class-file-scanner.php';
require_once WSR_PLUGIN_DIR . 'includes/class-malware-scanner.php';
require_once WSR_PLUGIN_DIR . 'includes/class-hardening-checker.php';
require_once WSR_PLUGIN_DIR . 'includes/class-baseline.php';
require_once WSR_PLUGIN_DIR . 'includes/class-notifier.php';
require_once WSR_PLUGIN_DIR . 'includes/class-cron.php';
require_once WSR_PLUGIN_DIR . 'includes/class-admin-page.php';
require_once WSR_PLUGIN_DIR . 'includes/class-plugin.php';

register_activation_hook(__FILE__, array('WSR_Plugin', 'activate'));
register_deactivation_hook(__FILE__, array('WSR_Plugin', 'deactivate'));

WSR_Plugin::get_instance()->init();
