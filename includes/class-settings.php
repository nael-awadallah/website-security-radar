<?php
/**
 * Settings.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Settings {
	public function register(): void {
		register_setting(
			'wsr_settings_group',
			WSR_Helpers::SETTINGS_OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
				'show_in_rest'      => false,
			)
		);
	}

	public function sanitize( array $input ): array {
		$input    = wp_unslash( $input );
		$defaults = WSR_Helpers::get_default_settings();
		$output   = array();

		$output['max_file_size']         = max( 1024, absint( $input['max_file_size'] ?? $defaults['max_file_size'] ) );
		$output['enable_scheduled_scan'] = ! empty( $input['enable_scheduled_scan'] ) ? 1 : 0;
		$output['enable_email_alerts']   = ! empty( $input['enable_email_alerts'] ) ? 1 : 0;
		$output['alert_email']           = sanitize_email( $input['alert_email'] ?? $defaults['alert_email'] );
		$output['scan_uploads']          = ! empty( $input['scan_uploads'] ) ? 1 : 0;
		$output['scan_themes']           = ! empty( $input['scan_themes'] ) ? 1 : 0;
		$output['scan_plugins']          = ! empty( $input['scan_plugins'] ) ? 1 : 0;
		$output['scan_root_files']       = ! empty( $input['scan_root_files'] ) ? 1 : 0;
		$output['timeline_event_limit']  = min( WSR_Helpers::TIMELINE_DEFAULT_LIMIT, max( 50, absint( $input['timeline_event_limit'] ?? $defaults['timeline_event_limit'] ) ) );

		return $output;
	}
}
