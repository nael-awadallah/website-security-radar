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
	const CRON_HOOK             = 'website_security_radar_daily_scan';
	const AJAX_SCAN_ACTION      = 'website_security_radar_run_scan';
	const AJAX_BASELINE_ACTION  = 'website_security_radar_create_baseline';
	const ADMIN_NONCE_ACTION    = 'website_security_radar_admin_action';
	const AJAX_NONCE_ACTION     = 'website_security_radar_ajax_action';

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
			'malware'            => 'Malware',
			'suspicious pattern' => 'Suspicious Pattern',
			'potential risk'     => 'Potential Risk',
			'hardening'          => 'Hardening',
			'file change'        => 'File Change',
			'updates'            => 'Updates',
			'permissions'        => 'Permissions',
			'exposure'           => 'Exposure',
		);

		$normalized = strtolower( trim( $type ) );

		if ( isset( $map[ $normalized ] ) ) {
			return $map[ $normalized ];
		}

		return ucwords( str_replace( '-', ' ', $type ) );
	}

	public static function get_ignore_list() {
		$paths = get_option( self::IGNORE_OPTION, array() );
		return is_array( $paths ) ? array_values( array_unique( array_filter( array_map( 'sanitize_text_field', $paths ) ) ) ) : array();
	}

	public static function is_ignored_path( string $path, array $ignore_list = array() ): bool {
		$relative = self::normalize_relative_path( $path );
		$ignored  = ! empty( $ignore_list ) ? $ignore_list : self::get_ignore_list();

		foreach ( $ignored as $ignored_path ) {
			$ignored_path = trim( wp_normalize_path( sanitize_text_field( $ignored_path ) ), '/' );

			if ( '' !== $ignored_path && 0 === strpos( $relative, $ignored_path ) ) {
				return true;
			}
		}

		return false;
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
				(string) ( $issue['path'] ?? '' ),
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
		$score = 100;

		foreach ( $issues as $issue ) {
			switch ( $issue['severity'] ?? 'low' ) {
				case 'critical':
					$score -= 20;
					break;
				case 'high':
					$score -= 10;
					break;
				case 'medium':
					$score -= 5;
					break;
				default:
					$score -= 2;
					break;
			}
		}

		return max( 0, $score );
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
}
