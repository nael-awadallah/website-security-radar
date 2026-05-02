<?php
/**
 * Helpers.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Helpers {
	const SETTINGS_OPTION       = 'website_security_radar_settings';
	const BASELINE_OPTION       = 'website_security_radar_baseline';
	const RESULTS_OPTION        = 'website_security_radar_scan_results';
	const PREVIOUS_RESULTS_OPTION = 'website_security_radar_previous_scan_results';
	const IGNORE_OPTION         = 'website_security_radar_ignored_paths';
	const REVIEWED_OPTION       = 'website_security_radar_reviewed_results';
	const TIMELINE_OPTION       = 'website_security_radar_timeline';
	const USER_ACTIVITY_OPTION  = 'website_security_radar_user_activity';
	const SCAN_STATUS_OPTION    = 'website_security_radar_scan_status';
	const VULNERABILITY_CACHE_OPTION = 'website_security_radar_vulnerability_cache';
	const CRITICAL_ALERT_STATE_OPTION = 'website_security_radar_critical_alert_state';
	const SCAN_LOCK_TRANSIENT   = 'website_security_radar_scan_lock';
	const CRON_HOOK             = 'website_security_radar_daily_scan';
	const VULNERABILITY_RETRY_HOOK = 'website_security_radar_vulnerability_retry';
	const AJAX_SCAN_ACTION      = 'website_security_radar_run_scan';
	const AJAX_BASELINE_ACTION  = 'website_security_radar_create_baseline';
	const AJAX_VULNERABILITY_ACTION = 'website_security_radar_run_vulnerability_check';
	const ADMIN_NONCE_ACTION    = 'website_security_radar_admin_action';
	const AJAX_NONCE_ACTION     = 'website_security_radar_ajax_action';
	const REPORT_NONCE_ACTION   = 'website_security_radar_view_report';
	const TIMELINE_DEFAULT_LIMIT = 500;
	const SCAN_LOCK_TTL         = 10 * MINUTE_IN_SECONDS;

	public static function get_ignore_rule_types(): array {
		return array(
			'exact_path'     => __( 'Exact file path', 'website-security-radar' ),
			'folder_path'    => __( 'Folder path', 'website-security-radar' ),
			'file_extension' => __( 'File extension', 'website-security-radar' ),
			'contains_text'  => __( 'Pattern contains text', 'website-security-radar' ),
		);
	}

	public static function get_default_settings() {
		return array(
			'max_file_size'         => 2 * MB_IN_BYTES,
			'enable_scheduled_scan' => 1,
			'enable_email_alerts'   => 0,
			'alert_email'           => get_option( 'admin_email' ),
			'scan_uploads'          => 1,
			'scan_themes'           => 1,
			'scan_plugins'          => 1,
			'scan_root_files'       => 1,
			'scan_batch_size'       => 500,
			'timeline_event_limit'  => self::TIMELINE_DEFAULT_LIMIT,
			'scheduled_scan_time'   => '03:00',
			'max_baselines'         => 10,
			'enable_vulnerability_checks' => 0,
			'vulnerability_provider'      => 'mock',
			'vulnerability_api_key'       => '',
			'vulnerability_min_severity'  => 'low',
			'report_agency_name'          => '',
			'report_agency_logo_url'      => '',
			'report_footer_text'          => '',
		);
	}

	public static function get_settings() {
		$settings = get_option( self::SETTINGS_OPTION, array() );
		return wp_parse_args( is_array( $settings ) ? $settings : array(), self::get_default_settings() );
	}

	public static function normalize_relative_path( string $path ): string {
		$normalized = wp_normalize_path( $path );
		$root       = wp_normalize_path( ABSPATH );

		if ( 0 === strpos( $normalized, $root ) ) {
			$normalized = ltrim( substr( $normalized, strlen( $root ) ), '/' );
		}

		return trim( $normalized, '/' );
	}

	public static function get_safe_display_path( string $path ): string {
		$relative = self::normalize_relative_path( $path );
		return '' !== $relative ? $relative : '.';
	}

	public static function is_uploads_path( string $relative_path ): bool {
		return 0 === strpos( self::normalize_relative_path( $relative_path ), 'wp-content/uploads/' );
	}

	public static function is_plugin_path( string $relative_path ): bool {
		return 0 === strpos( self::normalize_relative_path( $relative_path ), 'wp-content/plugins/' );
	}

	public static function is_theme_path( string $relative_path ): bool {
		return 0 === strpos( self::normalize_relative_path( $relative_path ), 'wp-content/themes/' );
	}

	public static function is_vendor_or_assets_path( string $relative_path ): bool {
		$relative = self::normalize_relative_path( $relative_path );
		return false !== strpos( $relative, '/vendor/' ) || false !== strpos( $relative, '/assets/' );
	}

	public static function is_minified_file( string $relative_path ): bool {
		return (bool) preg_match( '/\.min\.[a-z0-9]+$/i', self::normalize_relative_path( $relative_path ) );
	}

	public static function is_php_file( string $relative_path ): bool {
		return 'php' === strtolower( pathinfo( self::normalize_relative_path( $relative_path ), PATHINFO_EXTENSION ) );
	}

	public static function is_javascript_file( string $relative_path ): bool {
		$extension = strtolower( pathinfo( self::normalize_relative_path( $relative_path ), PATHINFO_EXTENSION ) );
		return in_array( $extension, array( 'js', 'mjs', 'cjs' ), true );
	}

	public static function has_random_looking_filename( string $relative_path ): bool {
		$filename = strtolower( pathinfo( self::normalize_relative_path( $relative_path ), PATHINFO_FILENAME ) );

		if ( strlen( $filename ) < 10 ) {
			return false;
		}

		if ( preg_match( '/^[a-f0-9]{10,}$/', $filename ) ) {
			return true;
		}

		return (bool) preg_match( '/[a-z]{2,}\d{4,}|[0-9]{4,}[a-z]{2,}|[a-z0-9]{14,}/', $filename );
	}

	public static function get_type_label( string $type ): string {
		$map = array(
			'malware'            => __( 'Malware', 'website-security-radar' ),
			'suspicious pattern' => __( 'Suspicious Pattern', 'website-security-radar' ),
			'potential risk'     => __( 'Potential Risk', 'website-security-radar' ),
			'uploads risk'       => __( 'Uploads Risk', 'website-security-radar' ),
			'hardening'          => __( 'Hardening', 'website-security-radar' ),
			'file change'        => __( 'File Change', 'website-security-radar' ),
			'uploads issue'      => __( 'Uploads Issue', 'website-security-radar' ),
			'updates'            => __( 'Updates', 'website-security-radar' ),
			'permissions'        => __( 'Permissions', 'website-security-radar' ),
			'exposure'           => __( 'Exposure', 'website-security-radar' ),
			'vulnerability'      => __( 'Vulnerability', 'website-security-radar' ),
			'cron'               => __( 'Cron', 'website-security-radar' ),
			'user security'      => __( 'User Security', 'website-security-radar' ),
		);

		$normalized = strtolower( trim( $type ) );

		if ( isset( $map[ $normalized ] ) ) {
			return $map[ $normalized ];
		}

		return ucwords( str_replace( '-', ' ', $type ) );
	}

	public static function get_timeline_event_types(): array {
		return array(
			'manual_scan_started'       => __( 'Manual Scan Started', 'website-security-radar' ),
			'manual_scan_completed'     => __( 'Manual Scan Completed', 'website-security-radar' ),
			'scheduled_scan_completed'  => __( 'Scheduled Scan Completed', 'website-security-radar' ),
			'baseline_created'          => __( 'Baseline Created', 'website-security-radar' ),
			'new_file_detected'         => __( 'New File Detected', 'website-security-radar' ),
			'modified_file_detected'    => __( 'Modified File Detected', 'website-security-radar' ),
			'suspicious_pattern_detected' => __( 'Suspicious Pattern Detected', 'website-security-radar' ),
			'critical_issue_detected'   => __( 'Critical Issue Detected', 'website-security-radar' ),
			'issue_marked_reviewed'     => __( 'Issue Marked Reviewed', 'website-security-radar' ),
			'path_ignored'              => __( 'Path Ignored', 'website-security-radar' ),
			'settings_changed'          => __( 'Settings Changed', 'website-security-radar' ),
			'vulnerability_check_completed' => __( 'Vulnerability Check Completed', 'website-security-radar' ),
			'admin_user_created'        => __( 'Administrator User Created', 'website-security-radar' ),
			'admin_role_granted'        => __( 'Administrator Role Granted', 'website-security-radar' ),
			'admin_profile_updated'     => __( 'Administrator Profile Updated', 'website-security-radar' ),
		);
	}

	public static function get_vulnerability_provider_options(): array {
		return array(
			'mock'       => __( 'Mock Provider (Testing Only)', 'website-security-radar' ),
			'wpscan'     => __( 'WPScan Vulnerability Database (Coming Soon)', 'website-security-radar' ),
			'patchstack' => __( 'Patchstack (Coming Soon)', 'website-security-radar' ),
		);
	}

	public static function get_available_vulnerability_providers(): array {
		return array( 'mock' );
	}

	public static function is_vulnerability_provider_available( string $provider_key ): bool {
		return in_array( sanitize_key( $provider_key ), self::get_available_vulnerability_providers(), true );
	}

	public static function get_severity_levels(): array {
		return array( 'low', 'medium', 'high', 'critical' );
	}

	public static function sanitize_severity( string $severity, string $default = 'low' ): string {
		$severity = sanitize_key( $severity );

		return in_array( $severity, self::get_severity_levels(), true ) ? $severity : $default;
	}

	public static function severity_meets_minimum( string $severity, string $minimum ): bool {
		$order = array(
			'low'      => 1,
			'medium'   => 2,
			'high'     => 3,
			'critical' => 4,
		);

		return ( $order[ self::sanitize_severity( $severity ) ] ?? 0 ) >= ( $order[ self::sanitize_severity( $minimum ) ] ?? 0 );
	}

	public static function mask_api_key( string $api_key ): string {
		$api_key = trim( $api_key );

		if ( '' === $api_key ) {
			return '';
		}

		if ( strlen( $api_key ) <= 8 ) {
			return str_repeat( '*', strlen( $api_key ) );
		}

		return substr( $api_key, 0, 4 ) . str_repeat( '*', max( 4, strlen( $api_key ) - 8 ) ) . substr( $api_key, -4 );
	}

	public static function get_timeline_event_type_label( string $type ): string {
		$types = self::get_timeline_event_types();
		return $types[ $type ] ?? ucwords( str_replace( '_', ' ', $type ) );
	}

	public static function get_default_baseline_label(): string {
		return sprintf(
			/* translators: %s: current month and year. */
			__( 'After cleanup - %s', 'website-security-radar' ),
			wp_date( 'F Y' )
		);
	}

	public static function get_ignore_list() {
		$stored_rules = get_option( self::IGNORE_OPTION, array() );
		return self::normalize_ignore_rules( is_array( $stored_rules ) ? $stored_rules : array() );
	}

	public static function is_ignored_path( string $path, array $ignore_list = array() ): bool {
		$relative = self::normalize_relative_path( $path );
		$ignored  = ! empty( $ignore_list ) ? self::normalize_ignore_rules( $ignore_list ) : self::get_ignore_list();

		foreach ( $ignored as $rule ) {
			if ( self::ignore_rule_matches_path( $rule, $relative ) ) {
				return true;
			}
		}

		return false;
	}

	public static function save_ignore_rules( array $rules ): void {
		update_option( self::IGNORE_OPTION, self::normalize_ignore_rules( $rules ), false );
	}

	public static function add_ignore_rule( array $rule ): array {
		$normalized_rule = self::normalize_ignore_rule( $rule );

		if ( empty( $normalized_rule ) ) {
			return array(
				'success' => false,
				'code'    => 'invalid_rule',
			);
		}

		$rules = self::get_ignore_list();

		foreach ( $rules as $index => $existing_rule ) {
			if ( $existing_rule['id'] === $normalized_rule['id'] ) {
				$rules[ $index ] = array_merge( $existing_rule, $normalized_rule );
				self::save_ignore_rules( $rules );

				return array(
					'success' => true,
					'code'    => 'updated',
					'rule'    => $normalized_rule,
				);
			}
		}

		$rules[] = $normalized_rule;
		self::save_ignore_rules( $rules );

		return array(
			'success' => true,
			'code'    => 'added',
			'rule'    => $normalized_rule,
		);
	}

	public static function delete_ignore_rule( string $rule_id ): bool {
		$rules        = self::get_ignore_list();
		$filtered     = array_values(
			array_filter(
				$rules,
				static function ( array $rule ) use ( $rule_id ): bool {
					return $rule['id'] !== $rule_id;
				}
			)
		);
		$was_deleted = count( $filtered ) !== count( $rules );

		if ( $was_deleted ) {
			self::save_ignore_rules( $filtered );
		}

		return $was_deleted;
	}

	public static function toggle_ignore_rule( string $rule_id, bool $enabled ): bool {
		$rules   = self::get_ignore_list();
		$updated = false;

		foreach ( $rules as &$rule ) {
			if ( $rule['id'] === $rule_id ) {
				$rule['enabled'] = $enabled ? 1 : 0;
				$updated         = true;
				break;
			}
		}

		if ( $updated ) {
			self::save_ignore_rules( $rules );
		}

		return $updated;
	}

	public static function split_ignored_issues( array $issues, array $ignore_rules = array() ): array {
		$rules   = ! empty( $ignore_rules ) ? self::normalize_ignore_rules( $ignore_rules ) : self::get_ignore_list();
		$visible = array();
		$ignored = array();

		foreach ( $issues as $issue ) {
			if ( self::issue_matches_ignore_rules( $issue, $rules ) ) {
				$ignored[] = $issue;
				continue;
			}

			$visible[] = $issue;
		}

		return array(
			'visible' => $visible,
			'ignored' => $ignored,
		);
	}

	public static function issue_matches_ignore_rules( array $issue, array $ignore_rules = array() ): bool {
		$path = (string) ( $issue['path'] ?? $issue['file'] ?? '' );

		if ( '' === $path ) {
			return false;
		}

		return self::is_ignored_path( $path, $ignore_rules );
	}

	public static function get_ignore_rule_warning( array $rule ): string {
		$type  = $rule['type'] ?? '';
		$value = strtolower( (string) ( $rule['value'] ?? '' ) );

		if ( 'file_extension' === $type && 'php' === $value ) {
			return __( 'This rule ignores all PHP files and can hide serious findings.', 'website-security-radar' );
		}

		if ( 'contains_text' === $type && in_array( $value, array( 'php', 'wp-content', 'uploads' ), true ) ) {
			return __( 'This pattern is broad and may hide more findings than expected.', 'website-security-radar' );
		}

		if ( 'folder_path' === $type && in_array( $value, array( 'wp-content', 'wp-content/uploads' ), true ) ) {
			return __( 'This folder rule is broad and may hide many findings.', 'website-security-radar' );
		}

		return '';
	}

	public static function rule_requires_uploads_php_confirmation( array $rule ): bool {
		$type  = $rule['type'] ?? '';
		$value = strtolower( (string) ( $rule['value'] ?? '' ) );

		if ( 'exact_path' === $type ) {
			return self::is_uploads_path( $value ) && self::is_php_file( $value );
		}

		if ( 'folder_path' === $type ) {
			return 0 === strpos( $value, 'wp-content/uploads' );
		}

		if ( 'file_extension' === $type ) {
			return 'php' === $value;
		}

		if ( 'contains_text' === $type ) {
			return false !== strpos( $value, 'php' ) || false !== strpos( $value, 'upload' );
		}

		return false;
	}

	public static function count_ignored_matches_for_rule( array $rule, array $issues ): int {
		$count = 0;

		foreach ( $issues as $issue ) {
			$path = (string) ( $issue['path'] ?? $issue['file'] ?? '' );

			if ( '' !== $path && self::ignore_rule_matches_path( $rule, $path ) ) {
				++$count;
			}
		}

		return $count;
	}

	private static function normalize_ignore_rules( array $rules ): array {
		$normalized = array();

		foreach ( $rules as $rule ) {
			$normalized_rule = self::normalize_ignore_rule( $rule );

			if ( empty( $normalized_rule ) ) {
				continue;
			}

			$normalized[ $normalized_rule['id'] ] = $normalized_rule;
		}

		return array_values( $normalized );
	}

	private static function normalize_ignore_rule( $rule ): array {
		if ( is_string( $rule ) ) {
			$value = trim( self::normalize_relative_path( sanitize_text_field( $rule ) ), '/' );

			if ( '' === $value ) {
				return array();
			}

			$rule = array(
				'type'             => self::infer_legacy_ignore_rule_type( $value ),
				'value'            => $value,
				'enabled'          => 1,
				'allow_uploads_php'=> 0,
			);
		}

		if ( ! is_array( $rule ) ) {
			return array();
		}

		$type = sanitize_key( (string) ( $rule['type'] ?? '' ) );

		if ( ! array_key_exists( $type, self::get_ignore_rule_types() ) ) {
			return array();
		}

		$value = self::sanitize_ignore_rule_value( $type, (string) ( $rule['value'] ?? '' ) );

		if ( '' === $value ) {
			return array();
		}

		return array(
			'id'                => sanitize_key( (string) ( $rule['id'] ?? hash( 'sha256', $type . '|' . $value ) ) ),
			'type'              => $type,
			'value'             => $value,
			'enabled'           => ! empty( $rule['enabled'] ) ? 1 : 0,
			'allow_uploads_php' => ! empty( $rule['allow_uploads_php'] ) ? 1 : 0,
			'created_at'        => sanitize_text_field( (string) ( $rule['created_at'] ?? gmdate( 'c' ) ) ),
		);
	}

	private static function infer_legacy_ignore_rule_type( string $value ): string {
		return '' !== pathinfo( $value, PATHINFO_EXTENSION ) ? 'exact_path' : 'folder_path';
	}

	private static function sanitize_ignore_rule_value( string $type, string $value ): string {
		$value = sanitize_text_field( $value );

		switch ( $type ) {
			case 'exact_path':
			case 'folder_path':
				return trim( self::normalize_relative_path( $value ), '/' );
			case 'file_extension':
				return ltrim( strtolower( sanitize_key( $value ) ), '.' );
			case 'contains_text':
				return strtolower( trim( $value ) );
			default:
				return '';
		}
	}

	private static function ignore_rule_matches_path( array $rule, string $path ): bool {
		if ( empty( $rule['enabled'] ) ) {
			return false;
		}

		$relative = self::normalize_relative_path( $path );

		if ( self::is_uploads_path( $relative ) && self::is_php_file( $relative ) && empty( $rule['allow_uploads_php'] ) ) {
			return false;
		}

		switch ( $rule['type'] ?? '' ) {
			case 'exact_path':
				return $relative === $rule['value'];
			case 'folder_path':
				return $relative === $rule['value'] || 0 === strpos( $relative, trailingslashit( $rule['value'] ) );
			case 'file_extension':
				return strtolower( pathinfo( $relative, PATHINFO_EXTENSION ) ) === strtolower( (string) ( $rule['value'] ?? '' ) );
			case 'contains_text':
				return false !== strpos( strtolower( $relative ), strtolower( (string) ( $rule['value'] ?? '' ) ) );
			default:
				return false;
		}
	}

	public static function get_reviewed_results() {
		$reviewed = get_option( self::REVIEWED_OPTION, array() );
		return is_array( $reviewed ) ? $reviewed : array();
	}

	public static function mark_result_reviewed( string $issue_id ): void {
		$reviewed              = self::get_reviewed_results();
		$reviewed[ $issue_id ] = time();
		update_option( self::REVIEWED_OPTION, $reviewed, false );
	}

	public static function issue_identifier( array $issue ): string {
		$key = implode(
			'|',
			array(
				(string) ( $issue['type'] ?? '' ),
				(string) ( $issue['path'] ?? $issue['hook_name'] ?? $issue['component_slug'] ?? $issue['user_login'] ?? '' ),
				(string) ( $issue['issue'] ?? '' ),
				(string) ( $issue['line'] ?? '' ),
			)
		);

		return hash( 'sha256', $key );
	}

	public static function apply_review_status( array $issues ): array {
		$reviewed = self::get_reviewed_results();

		foreach ( $issues as &$issue ) {
			$issue['id']       = self::issue_identifier( $issue );
			$issue['reviewed'] = isset( $reviewed[ $issue['id'] ] );
		}

		return $issues;
	}

	public static function count_severity( array $issues ): array {
		$counts = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
		);

		foreach ( $issues as $issue ) {
			$severity = $issue['severity'] ?? 'low';

			if ( isset( $counts[ $severity ] ) ) {
				++$counts[ $severity ];
			}
		}

		return $counts;
	}

	public static function calculate_security_score( array $issues ): int {
		$breakdown = self::calculate_security_score_breakdown( $issues );
		return (int) ( $breakdown['score'] ?? 100 );
	}

	public static function calculate_security_score_breakdown( array $issues ): array {
		$categories = self::get_score_breakdown_categories();
		$breakdown  = array();
		$total      = 0;
		$seen       = array();

		foreach ( $categories as $key => $label ) {
			$breakdown[ $key ] = array(
				'label'          => $label,
				'deduction'      => 0,
				'issue_count'    => 0,
				'severity_counts'=> array(
					'critical' => 0,
					'high'     => 0,
					'medium'   => 0,
					'low'      => 0,
				),
			);
		}

		foreach ( $issues as $issue ) {
			$dedupe_key = self::get_score_dedupe_key( $issue );

			if ( isset( $seen[ $dedupe_key ] ) ) {
				continue;
			}

			$seen[ $dedupe_key ] = true;
			$category            = self::get_score_category( $issue );
			$severity            = strtolower( (string) ( $issue['severity'] ?? 'low' ) );
			$deduction           = self::get_score_deduction_value( $severity );

			if ( ! isset( $breakdown[ $category ] ) ) {
				continue;
			}

			$breakdown[ $category ]['deduction'] += $deduction;
			++$breakdown[ $category ]['issue_count'];

			if ( isset( $breakdown[ $category ]['severity_counts'][ $severity ] ) ) {
				++$breakdown[ $category ]['severity_counts'][ $severity ];
			}

			$total += $deduction;
		}

		return array(
			'score'                => max( 0, 100 - $total ),
			'total_deduction'      => $total,
			'deduction_per_severity' => array(
				'critical' => 20,
				'high'     => 10,
				'medium'   => 5,
				'low'      => 2,
			),
			'categories'           => $breakdown,
		);
	}

	public static function get_risk_level( int $score ): string {
		if ( $score >= 80 ) {
			return 'Safe';
		}

		if ( $score >= 50 ) {
			return 'Warning';
		}

		return 'Critical';
	}

	public static function admin_url( string $page, array $args = array() ): string {
		$args['page'] = $page;
		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

	public static function severity_label_class( string $severity ): string {
		return 'wsr-badge wsr-badge-' . sanitize_html_class( $severity );
	}

	public static function format_datetime( string $datetime ): string {
		$timestamp = strtotime( $datetime );

		if ( ! $timestamp ) {
			return __( 'Never', 'website-security-radar' );
		}

		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
	}

	public static function get_score_breakdown_categories(): array {
		return array(
			'malware'             => __( 'Malware', 'website-security-radar' ),
			'suspicious_patterns' => __( 'Suspicious Patterns', 'website-security-radar' ),
			'file_changes'        => __( 'File Changes', 'website-security-radar' ),
			'hardening'           => __( 'Hardening', 'website-security-radar' ),
			'uploads_risk'        => __( 'Uploads Risk', 'website-security-radar' ),
			'vulnerabilities'     => __( 'Vulnerabilities', 'website-security-radar' ),
			'cron'                => __( 'Cron Security', 'website-security-radar' ),
			'user_security'       => __( 'User Security', 'website-security-radar' ),
		);
	}

	public static function get_default_results(): array {
		$settings     = self::get_settings();
		$provider_key = sanitize_key( (string) ( $settings['vulnerability_provider'] ?? 'mock' ) );
		$providers    = self::get_vulnerability_provider_options();
		$breakdown    = self::calculate_security_score_breakdown( array() );

		return array(
			'scanned_at'       => '',
			'score'            => 100,
			'risk_level'       => self::get_risk_level( 100 ),
			'summary'          => array(
				'total_scanned_files'     => 0,
				'new_files'               => 0,
				'modified_files'          => 0,
				'deleted_files'           => 0,
				'suspicious_files'        => 0,
				'hardening_warnings'      => 0,
				'critical_issues'         => 0,
				'ignored_findings'        => 0,
				'cron_findings'           => 0,
				'user_security_findings'  => 0,
				'vulnerability_findings'  => 0,
			),
			'severity_counts'  => self::count_severity( array() ),
			'score_breakdown'  => $breakdown,
			'issues'           => array(),
			'baseline'         => array(
				'has_baseline' => false,
			),
			'inventory_count'       => 0,
			'vulnerability_checks'  => array(
				'enabled'                => ! empty( $settings['enable_vulnerability_checks'] ),
				'provider'               => $provider_key,
				'provider_label'         => $providers[ $provider_key ] ?? '',
				'status'                 => ! empty( $settings['enable_vulnerability_checks'] ) ? 'ready' : 'disabled',
				'last_checked'           => '',
				'vulnerabilities_found'  => 0,
				'critical_found'         => 0,
				'error_message'          => '',
			),
		);
	}

	private static function generate_realistic_demo_data(): array {
		$seed          = self::get_demo_seed();
		$settings      = self::get_settings();
		$provider_key  = sanitize_key( (string) ( $settings['vulnerability_provider'] ?? 'mock' ) );
		$providers     = self::get_vulnerability_provider_options();
		$scanned_at    = gmdate( 'c', time() - self::bounded_int( $seed, 'scanned_offset', 3 * HOUR_IN_SECONDS, 14 * HOUR_IN_SECONDS ) );
		$file_count    = self::bounded_int( $seed, 'inventory_count', 4200, 9800 );
		$new_files     = self::bounded_int( $seed, 'new_files', 2, 5 );
		$modified      = self::bounded_int( $seed, 'modified_files', 4, 8 );
		$issues        = self::get_demo_issues( $seed, $scanned_at );
		$breakdown     = self::build_demo_score_breakdown( $issues );
		$severity      = self::count_severity( $issues );
		$vuln_enabled  = ! empty( $settings['enable_vulnerability_checks'] );

		return array(
			'scanned_at'       => $scanned_at,
			'score'            => (int) $breakdown['score'],
			'risk_level'       => self::get_risk_level( (int) $breakdown['score'] ),
			'summary'          => array(
				'total_scanned_files'     => $file_count,
				'new_files'               => $new_files,
				'modified_files'          => $modified,
				'deleted_files'           => 0,
				'suspicious_files'        => self::count_demo_suspicious_files( $issues ),
				'hardening_warnings'      => self::count_demo_issues_by_type( $issues, array( 'hardening', 'updates', 'permissions', 'exposure' ) ),
				'critical_issues'         => (int) ( $severity['critical'] ?? 0 ),
				'ignored_findings'        => 0,
				'cron_findings'           => self::count_demo_issues_by_type( $issues, array( 'cron' ) ),
				'user_security_findings'  => self::count_demo_issues_by_type( $issues, array( 'user security' ) ),
				'vulnerability_findings'  => 0,
			),
			'severity_counts'  => $severity,
			'score_breakdown'  => $breakdown,
			'issues'           => $issues,
			'baseline'         => array(
				'has_baseline' => false,
			),
			'inventory_count'       => $file_count,
			'vulnerability_checks'  => array(
				'enabled'                => $vuln_enabled,
				'provider'               => $provider_key,
				'provider_label'         => $providers[ $provider_key ] ?? '',
				'status'                 => $vuln_enabled ? 'ready' : 'disabled',
				'last_checked'           => '',
				'vulnerabilities_found'  => 0,
				'critical_found'         => 0,
				'error_message'          => '',
			),
		);
	}

	private static function get_demo_issues( int $seed, string $scanned_at ): array {
		$offsets = array(
			11 * MINUTE_IN_SECONDS,
			27 * MINUTE_IN_SECONDS,
			43 * MINUTE_IN_SECONDS,
			58 * MINUTE_IN_SECONDS,
			79 * MINUTE_IN_SECONDS,
			95 * MINUTE_IN_SECONDS,
			112 * MINUTE_IN_SECONDS,
			131 * MINUTE_IN_SECONDS,
			154 * MINUTE_IN_SECONDS,
			171 * MINUTE_IN_SECONDS,
			189 * MINUTE_IN_SECONDS,
			204 * MINUTE_IN_SECONDS,
			223 * MINUTE_IN_SECONDS,
			239 * MINUTE_IN_SECONDS,
			254 * MINUTE_IN_SECONDS,
			272 * MINUTE_IN_SECONDS,
			289 * MINUTE_IN_SECONDS,
		);

		$issues = array(
			array(
				'severity'           => 'critical',
				'type'               => 'malware',
				'path'               => 'wp-content/uploads/2026/04/classic-editor-cache.php',
				'issue'              => __( 'Executable PHP file detected in uploads', 'website-security-radar' ),
				'explanation'        => __( 'A PHP file inside uploads is uncommon for normal media workflows and should be verified before the next deployment.', 'website-security-radar' ),
				'recommended_action' => __( 'Review the file contents, confirm ownership, and block PHP execution in uploads if it is not required.', 'website-security-radar' ),
				'confidence'         => 'high',
				'score'              => 96,
				'line'               => 1,
				'demo_deduction'     => 11,
			),
			array(
				'severity'           => 'critical',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/plugins/site-tools/includes/class-maintenance-importer.php',
				'issue'              => __( 'Command execution function detected in plugin code', 'website-security-radar' ),
				'explanation'        => __( 'This file references a command execution function in a plugin context where it is not usually expected.', 'website-security-radar' ),
				'recommended_action' => __( 'Inspect the change against the trusted plugin source and remove it if the call is not part of approved maintenance tooling.', 'website-security-radar' ),
				'confidence'         => 'high',
				'score'              => 94,
				'line'               => 214,
				'demo_deduction'     => 10,
			),
			array(
				'severity'           => 'critical',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/themes/astra/inc/template-hooks/about.php',
				'issue'              => __( 'Unexpected about.php file in theme code', 'website-security-radar' ),
				'explanation'        => __( 'This filename and location commonly warrant manual review because it can be used to hide unauthorized loader code.', 'website-security-radar' ),
				'recommended_action' => __( 'Compare the file against the trusted theme version and remove it if it is not part of the intended child theme changes.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 91,
				'line'               => 18,
				'demo_deduction'     => 9,
			),
			array(
				'severity'           => 'critical',
				'type'               => 'potential risk',
				'path'               => 'wp-content/uploads/2026/04/logo-preview.php',
				'issue'              => __( 'Uploads file appears to be disguised as media', 'website-security-radar' ),
				'explanation'        => __( 'The filename looks like media preview content, but the extension is executable PHP inside uploads.', 'website-security-radar' ),
				'recommended_action' => __( 'Validate the file against the original upload workflow and remove it if it was not created by a trusted process.', 'website-security-radar' ),
				'confidence'         => 'high',
				'score'              => 93,
				'line'               => 1,
				'demo_deduction'     => 10,
			),
			array(
				'severity'           => 'high',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/themes/astra/assets/js/customizer-preview.js',
				'issue'              => __( 'Use of eval() detected in JavaScript', 'website-security-radar' ),
				'explanation'        => __( 'The script uses eval(), which is risky in frontend code and should be justified or removed.', 'website-security-radar' ),
				'recommended_action' => __( 'Replace dynamic evaluation with explicit parsing or a trusted data structure where possible.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 82,
				'line'               => 88,
				'demo_deduction'     => 5,
			),
			array(
				'severity'           => 'high',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/plugins/revslider/includes/cache/render-helper.php',
				'issue'              => __( 'Suspicious encoded string chain detected', 'website-security-radar' ),
				'explanation'        => __( 'A long encoded string combined with runtime decoding can be legitimate, but it is also a common concealment pattern.', 'website-security-radar' ),
				'recommended_action' => __( 'Verify the file against the vendor package and review when the change was introduced.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 84,
				'line'               => 143,
				'demo_deduction'     => 5,
			),
			array(
				'severity'           => 'high',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/plugins/site-tools/assets/js/admin-sync.js',
				'issue'              => __( 'Obfuscated JavaScript loader pattern detected', 'website-security-radar' ),
				'explanation'        => __( 'This script uses fromCharCode-style reconstruction that deserves review in administrative tooling.', 'website-security-radar' ),
				'recommended_action' => __( 'Confirm the file belongs to a trusted release and remove the loader if the behavior is not expected.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 80,
				'line'               => 57,
				'demo_deduction'     => 4,
			),
			array(
				'severity'           => 'high',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/plugins/site-tools/includes/class-admin-post-relay.php',
				'issue'              => __( 'Unexpected admin-post relay detected', 'website-security-radar' ),
				'explanation'        => __( 'The file registers request handling logic that should be reviewed against the intended plugin feature set.', 'website-security-radar' ),
				'recommended_action' => __( 'Confirm the handler is part of approved custom code and review recent edits before promoting the release.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 79,
				'line'               => 102,
				'demo_deduction'     => 4,
			),
			array(
				'severity'           => 'medium',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/plugins/woocommerce/includes/admin/class-wc-admin-dashboard.php',
				'issue'              => __( 'Encoded payload marker detected in PHP string', 'website-security-radar' ),
				'explanation'        => __( 'A compact encoded block was found in application code and should be checked against a known-good package.', 'website-security-radar' ),
				'recommended_action' => __( 'Diff the file against the deployed package and confirm whether the encoded block is expected.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 71,
				'line'               => 308,
				'demo_deduction'     => 2,
			),
			array(
				'severity'           => 'medium',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/themes/astra-child/footer.php',
				'issue'              => __( 'Hidden iframe injection pattern detected', 'website-security-radar' ),
				'explanation'        => __( 'An iframe output pattern appears in the footer template and should be validated against expected marketing or analytics code.', 'website-security-radar' ),
				'recommended_action' => __( 'Review the footer template change and remove the injection if it was not part of a trusted site customization.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 68,
				'line'               => 44,
				'demo_deduction'     => 2,
			),
			array(
				'severity'           => 'low',
				'type'               => 'suspicious pattern',
				'path'               => 'wp-content/themes/astra-child/assets/js/debug-preview.js',
				'issue'              => __( 'Debug script still uses eval()', 'website-security-radar' ),
				'explanation'        => __( 'This looks more like leftover debug code than malware, but it should still be cleaned up before release.', 'website-security-radar' ),
				'recommended_action' => __( 'Remove or refactor the debug script so preview logic does not rely on eval().', 'website-security-radar' ),
				'confidence'         => 'low',
				'score'              => 54,
				'line'               => 12,
				'demo_deduction'     => 1,
			),
			array(
				'severity'           => 'medium',
				'type'               => 'hardening',
				'path'               => 'wp-config.php',
				'issue'              => __( 'Debug mode is enabled', 'website-security-radar' ),
				'explanation'        => __( 'Leaving debug mode enabled on a production site can expose paths and operational details.', 'website-security-radar' ),
				'recommended_action' => __( 'Disable debug display on production and keep any logging restricted to trusted administrators.', 'website-security-radar' ),
				'confidence'         => 'high',
				'score'              => 70,
				'line'               => 96,
				'demo_deduction'     => 2,
			),
			array(
				'severity'           => 'low',
				'type'               => 'hardening',
				'path'               => 'xmlrpc.php',
				'issue'              => __( 'XML-RPC remains accessible', 'website-security-radar' ),
				'explanation'        => __( 'XML-RPC may be required for some integrations, but it increases exposure if unused.', 'website-security-radar' ),
				'recommended_action' => __( 'Restrict or disable XML-RPC if the site does not rely on it for a trusted integration.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 48,
				'demo_deduction'     => 1,
			),
			array(
				'severity'           => 'low',
				'type'               => 'hardening',
				'path'               => 'wp-admin/plugin-editor.php',
				'issue'              => __( 'Theme and plugin editor access is enabled', 'website-security-radar' ),
				'explanation'        => __( 'Allowing code edits in wp-admin increases the blast radius if an administrator account is compromised.', 'website-security-radar' ),
				'recommended_action' => __( 'Disable the built-in editor on production sites after confirming your deployment workflow.', 'website-security-radar' ),
				'confidence'         => 'high',
				'score'              => 46,
				'demo_deduction'     => 1,
			),
			array(
				'severity'           => 'medium',
				'type'               => 'cron',
				'path'               => '',
				'issue'              => __( 'Suspicious cron hook interval detected', 'website-security-radar' ),
				'explanation'        => __( 'A custom cron hook is scheduled more frequently than typical content or cache maintenance jobs.', 'website-security-radar' ),
				'recommended_action' => __( 'Verify the hook owner and confirm the interval matches an approved plugin or custom integration.', 'website-security-radar' ),
				'confidence'         => 'medium',
				'score'              => 65,
				'demo_deduction'     => 2,
			),
			array(
				'severity'           => 'low',
				'type'               => 'cron',
				'path'               => '',
				'issue'              => __( 'Short custom schedule should be reviewed', 'website-security-radar' ),
				'explanation'        => __( 'A one-minute recurring schedule is not automatically unsafe, but it should be tied to a known operational need.', 'website-security-radar' ),
				'recommended_action' => __( 'Map the schedule to its owning plugin or custom code before leaving it active in production.', 'website-security-radar' ),
				'confidence'         => 'low',
				'score'              => 41,
				'demo_deduction'     => 1,
			),
			array(
				'severity'           => 'medium',
				'type'               => 'user security',
				'path'               => 'wp-admin/users.php',
				'issue'              => __( 'Recently created administrator account requires review', 'website-security-radar' ),
				'explanation'        => __( 'New administrator accounts should be confirmed against recent client or team access changes.', 'website-security-radar' ),
				'recommended_action' => __( 'Verify who created the account, when it was approved, and whether the role is still required.', 'website-security-radar' ),
				'confidence'         => 'high',
				'score'              => 67,
				'demo_deduction'     => 2,
			),
		);

		foreach ( $issues as $index => &$issue ) {
			$issue['id']          = 'demo-' . substr( hash( 'sha256', $seed . '|' . $index . '|' . $issue['issue'] ), 0, 12 );
			$issue['detected_at'] = gmdate( 'c', strtotime( $scanned_at ) - $offsets[ $index ] );
		}
		unset( $issue );

		return $issues;
	}

	private static function build_demo_score_breakdown( array $issues ): array {
		$categories = array();

		foreach ( self::get_score_breakdown_categories() as $key => $label ) {
			$categories[ $key ] = array(
				'label'           => $label,
				'deduction'       => 0,
				'issue_count'     => 0,
				'severity_counts' => array(
					'critical' => 0,
					'high'     => 0,
					'medium'   => 0,
					'low'      => 0,
				),
			);
		}

		$total = 0;

		foreach ( $issues as $issue ) {
			$category  = self::get_score_category( $issue );
			$severity  = self::sanitize_severity( (string) ( $issue['severity'] ?? 'low' ) );
			$deduction = (int) ( $issue['demo_deduction'] ?? 0 );

			if ( ! isset( $categories[ $category ] ) ) {
				continue;
			}

			$categories[ $category ]['deduction'] += $deduction;
			++$categories[ $category ]['issue_count'];
			++$categories[ $category ]['severity_counts'][ $severity ];
			$total += $deduction;
		}

		return array(
			'score'                  => max( 0, min( 100, 100 - $total ) ),
			'total_deduction'        => $total,
			'deduction_per_severity' => array(
				'critical' => 10,
				'high'     => 5,
				'medium'   => 2,
				'low'      => 1,
			),
			'categories'             => $categories,
		);
	}

	private static function count_demo_suspicious_files( array $issues ): int {
		$paths = array();

		foreach ( $issues as $issue ) {
			$type = strtolower( (string) ( $issue['type'] ?? '' ) );

			if ( ! in_array( $type, array( 'malware', 'suspicious pattern', 'potential risk' ), true ) ) {
				continue;
			}

			if ( 'suspicious pattern' === $type && 'low' === strtolower( (string) ( $issue['severity'] ?? '' ) ) ) {
				continue;
			}

			$path = self::normalize_relative_path( (string) ( $issue['path'] ?? $issue['file'] ?? '' ) );

			if ( '' !== $path ) {
				$paths[ $path ] = true;
			}
		}

		return count( $paths );
	}

	private static function count_demo_issues_by_type( array $issues, array $types ): int {
		return count(
			array_filter(
				$issues,
				static function ( array $issue ) use ( $types ): bool {
					return in_array( strtolower( (string) ( $issue['type'] ?? '' ) ), $types, true );
				}
			)
		);
	}

	private static function get_demo_seed(): int {
		$home = function_exists( 'home_url' ) ? home_url( '/' ) : 'demo';
		return abs( (int) sprintf( '%u', crc32( strtolower( (string) $home ) ) ) );
	}

	private static function bounded_int( int $seed, string $key, int $min, int $max ): int {
		if ( $max <= $min ) {
			return $min;
		}

		$value = abs( (int) sprintf( '%u', crc32( $seed . '|' . $key ) ) );
		return $min + ( $value % ( $max - $min + 1 ) );
	}

	private static function get_score_category( array $issue ): string {
		$type = strtolower( trim( (string) ( $issue['type'] ?? '' ) ) );
		$path = (string) ( $issue['path'] ?? $issue['file'] ?? '' );

		if ( '' !== $path && self::is_uploads_path( $path ) ) {
			return 'uploads_risk';
		}

		if ( 'vulnerability' === $type ) {
			return 'vulnerabilities';
		}

		if ( 'cron' === $type ) {
			return 'cron';
		}

		if ( 'user security' === $type ) {
			return 'user_security';
		}

		if ( in_array( $type, array( 'hardening', 'updates', 'permissions', 'exposure' ), true ) ) {
			return 'hardening';
		}

		if ( 'file change' === $type ) {
			return 'file_changes';
		}

		if ( 'malware' === $type ) {
			return 'malware';
		}

		return 'suspicious_patterns';
	}

	private static function get_score_deduction_value( string $severity ): int {
		switch ( $severity ) {
			case 'critical':
				return 20;
			case 'high':
				return 10;
			case 'medium':
				return 5;
			default:
				return 2;
		}
	}

	private static function get_score_dedupe_key( array $issue ): string {
		$path            = self::normalize_relative_path( (string) ( $issue['path'] ?? $issue['file'] ?? '' ) );
		$matched_patterns = array();

		if ( ! empty( $issue['matched_patterns'] ) && is_array( $issue['matched_patterns'] ) ) {
			$matched_patterns = array_map( 'sanitize_key', $issue['matched_patterns'] );
			sort( $matched_patterns, SORT_STRING );
		}

		$pattern_key = ! empty( $matched_patterns )
			? implode( ',', $matched_patterns )
			: sanitize_title( (string) ( $issue['issue'] ?? $issue['type'] ?? 'issue' ) );

		return hash(
			'sha256',
			implode(
				'|',
				array(
					self::get_score_category( $issue ),
					$path,
					$pattern_key,
				)
			)
		);
	}
}
