<?php
/**
 * Uninstall Website Security Radar.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/includes/class-helpers.php';

delete_option( WSR_Helpers::SETTINGS_OPTION );
delete_option( WSR_Helpers::BASELINE_OPTION );
delete_option( WSR_Helpers::RESULTS_OPTION );
delete_option( WSR_Helpers::PREVIOUS_RESULTS_OPTION );
delete_option( WSR_Helpers::IGNORE_OPTION );
delete_option( WSR_Helpers::REVIEWED_OPTION );
delete_option( WSR_Helpers::TIMELINE_OPTION );
delete_option( WSR_Helpers::USER_ACTIVITY_OPTION );
delete_option( WSR_Helpers::SCAN_STATUS_OPTION );
delete_option( WSR_Helpers::VULNERABILITY_CACHE_OPTION );
delete_option( WSR_Helpers::CRITICAL_ALERT_STATE_OPTION );
delete_transient( WSR_Helpers::SCAN_LOCK_TRANSIENT );
wp_clear_scheduled_hook( WSR_Helpers::CRON_HOOK );
wp_clear_scheduled_hook( WSR_Helpers::VULNERABILITY_RETRY_HOOK );
