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
delete_option( WSR_Helpers::IGNORE_OPTION );
delete_option( WSR_Helpers::REVIEWED_OPTION );
delete_option( WSR_Helpers::TIMELINE_OPTION );

$timestamp = wp_next_scheduled( WSR_Helpers::CRON_HOOK );

if ( $timestamp ) {
	wp_unschedule_event( $timestamp, WSR_Helpers::CRON_HOOK );
}
