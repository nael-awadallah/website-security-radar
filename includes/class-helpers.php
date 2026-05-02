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
	const IGNORE_OPTION         = 'website_security_radar_ignored_paths';
	const REVIEWED_OPTION       = 'website_security_radar_reviewed_results';
	const TIMELINE_OPTION       = 'website_security_radar_timeline';
	const USER_ACTIVITY_OPTION  = 'website_security_radar_user_activity';
	const CRON_HOOK             = 'website_security_radar_daily_scan';
	const AJAX_SCAN_ACTION      = 'website_security_radar_run_scan';
	const AJAX_BASELINE_ACTION  = 'website_security_radar_create_baseline';
	const AJAX_VULNERABILITY_ACTION = 'website_security_radar_run_vulnerability_check';
	const ADMIN_NONCE_ACTION    = 'website_security_radar_admin_action';
	const AJAX_NONCE_ACTION     = 'website_security_radar_ajax_action';
	const REPORT_NONCE_ACTION   = 'website_security_radar_view_report';
	const TIMELINE_DEFAULT_LIMIT = 500;

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
			'timeline_event_limit'  => self::TIMELINE_DEFAULT_LIMIT,
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
			'mock'       => __( 'Mock Provider', 'website-security-radar' ),
			'wpscan'     => __( 'WPScan Placeholder', 'website-security-radar' ),
			'patchstack' => __( 'Patchstack Placeholder', 'website-security-radar' ),
		);
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
		return array(
			'scanned_at'       => '',
			'score'            => 100,
			'risk_level'       => 'Safe',
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
			'severity_counts'  => array(
				'critical' => 0,
				'high'     => 0,
				'medium'   => 0,
				'low'      => 0,
			),
			'score_breakdown'  => array(
				'score'                  => 100,
				'total_deduction'        => 0,
				'deduction_per_severity' => array(
					'critical' => 20,
					'high'     => 10,
					'medium'   => 5,
					'low'      => 2,
				),
				'categories'             => array(),
			),
			'issues'           => array(),
			'baseline'         => array(
				'has_baseline' => false,
			),
			'inventory_count'       => 0,
			'vulnerability_checks'  => array(
				'enabled'                => false,
				'provider'               => '',
				'provider_label'         => '',
				'status'                 => 'disabled',
				'last_checked'           => '',
				'vulnerabilities_found'  => 0,
				'critical_found'         => 0,
				'error_message'          => '',
			),
		);
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
