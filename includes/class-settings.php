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

	public function sanitize( $input ): array {
		$input    = is_array( $input ) ? wp_unslash( $input ) : array();
		$defaults = WSR_Helpers::get_default_settings();
		$current  = WSR_Helpers::get_settings();
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
		$output['enable_vulnerability_checks'] = ! empty( $input['enable_vulnerability_checks'] ) ? 1 : 0;
		$output['vulnerability_provider']      = sanitize_key( (string) ( $input['vulnerability_provider'] ?? $defaults['vulnerability_provider'] ) );
		$output['vulnerability_min_severity']  = WSR_Helpers::sanitize_severity( (string) ( $input['vulnerability_min_severity'] ?? $defaults['vulnerability_min_severity'] ) );
		$output['report_agency_name']          = sanitize_text_field( (string) ( $input['report_agency_name'] ?? $defaults['report_agency_name'] ) );
		$output['report_agency_logo_url']      = esc_url_raw( (string) ( $input['report_agency_logo_url'] ?? $defaults['report_agency_logo_url'] ) );
		$output['report_footer_text']          = sanitize_textarea_field( (string) ( $input['report_footer_text'] ?? $defaults['report_footer_text'] ) );

		if ( ! array_key_exists( $output['vulnerability_provider'], WSR_Helpers::get_vulnerability_provider_options() ) ) {
			$output['vulnerability_provider'] = $defaults['vulnerability_provider'];
		}

		$api_key_input  = trim( (string) ( $input['vulnerability_api_key'] ?? '' ) );
		$masked_current = WSR_Helpers::mask_api_key( (string) ( $current['vulnerability_api_key'] ?? '' ) );

		if ( '' === $api_key_input ) {
			$output['vulnerability_api_key'] = '';
		} elseif ( $api_key_input === $masked_current ) {
			$output['vulnerability_api_key'] = (string) ( $current['vulnerability_api_key'] ?? '' );
		} else {
			$output['vulnerability_api_key'] = sanitize_text_field( $api_key_input );
		}

		return $output;
	}
}
