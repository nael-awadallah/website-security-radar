<?php
/**
 * Main plugin controller.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Plugin {
	private static ?WSR_Plugin $instance = null;
	private WSR_Settings $settings;
	private WSR_Cron $cron;
	private WSR_Admin_Page $admin_page;
	private WSR_Baseline $baseline;
	private WSR_Notifier $notifier;

	public static function get_instance(): WSR_Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {
		$this->settings   = new WSR_Settings();
		$this->cron       = new WSR_Cron();
		$this->baseline   = new WSR_Baseline();
		$this->notifier   = new WSR_Notifier();
		$this->admin_page = new WSR_Admin_Page( $this );
	}

	public function init(): void {
		$this->cron->register();
		$this->admin_page->register();

		add_action( 'admin_init', array( $this->settings, 'register' ) );
		add_action( 'wp_ajax_' . WSR_Helpers::AJAX_SCAN_ACTION, array( $this, 'handle_manual_scan_ajax' ) );
		add_action( 'wp_ajax_' . WSR_Helpers::AJAX_BASELINE_ACTION, array( $this, 'handle_create_baseline_ajax' ) );
		add_action( 'update_option_' . WSR_Helpers::SETTINGS_OPTION, array( $this, 'handle_settings_updated' ), 10, 2 );
	}

	public static function activate(): void {
		update_option( WSR_Helpers::SETTINGS_OPTION, WSR_Helpers::get_settings(), false );
		self::get_instance()->cron->maybe_schedule( WSR_Helpers::get_settings() );
	}

	public static function deactivate(): void {
		self::get_instance()->cron->clear_schedule();
	}

	public function get_latest_results(): array {
		$results = get_option( WSR_Helpers::RESULTS_OPTION, array() );

		if ( ! is_array( $results ) || empty( $results ) ) {
			return array(
				'scanned_at'       => '',
				'score'            => 100,
				'risk_level'       => 'Safe',
				'summary'          => array(
					'total_scanned_files' => 0,
					'new_files'           => 0,
					'modified_files'      => 0,
					'deleted_files'       => 0,
					'suspicious_files'    => 0,
					'hardening_warnings'  => 0,
					'critical_issues'     => 0,
				),
				'severity_counts'  => array(
					'critical' => 0,
					'high'     => 0,
					'medium'   => 0,
					'low'      => 0,
				),
				'issues'           => array(),
				'baseline'         => array(
					'has_baseline' => false,
				),
			);
		}

		return $results;
	}

	public function run_scan( bool $persist = true ): array {
		$settings    = WSR_Helpers::get_settings();
		$ignore_list = WSR_Helpers::get_ignore_list();
		$scanner     = new WSR_File_Scanner( $settings, $ignore_list );
		$inventory   = $scanner->scan();
		$baseline    = $this->baseline->compare( $inventory );
		$issues      = $this->build_change_issues( $baseline );

		$malware_scanner = new WSR_Malware_Scanner( $settings, $ignore_list );
		$issues          = array_merge( $issues, $malware_scanner->scan( $inventory ) );

		$hardening_checker = new WSR_Hardening_Checker();
		$issues            = array_merge( $issues, $hardening_checker->run( $inventory ) );
		$issues            = WSR_Helpers::apply_review_status( $issues );
		$severity_counts   = WSR_Helpers::count_severity( $issues );
		$score             = WSR_Helpers::calculate_security_score( $issues );

		$results = array(
			'scanned_at'      => gmdate( 'c' ),
			'score'           => $score,
			'risk_level'      => WSR_Helpers::get_risk_level( $score ),
			'summary'         => array(
				'total_scanned_files' => count( $inventory ),
				'new_files'           => count( $baseline['new_files'] ),
				'modified_files'      => count( $baseline['modified'] ),
				'deleted_files'       => count( $baseline['deleted'] ),
				'suspicious_files'    => count(
					array_filter(
						$issues,
						static function ( array $issue ): bool {
							$type = strtolower( (string) ( $issue['type'] ?? '' ) );
							return in_array( $type, array( 'malware', 'suspicious pattern', 'potential risk', 'file change' ), true );
						}
					)
				),
				'hardening_warnings'  => count(
					array_filter(
						$issues,
						static function ( array $issue ): bool {
							return in_array( $issue['type'] ?? '', array( 'hardening', 'updates', 'permissions', 'exposure' ), true );
						}
					)
				),
				'critical_issues'     => (int) ( $severity_counts['critical'] ?? 0 ),
			),
			'severity_counts' => $severity_counts,
			'issues'          => $issues,
			'baseline'        => $baseline,
			'inventory_count' => count( $inventory ),
		);

		if ( $persist ) {
			update_option( WSR_Helpers::RESULTS_OPTION, $results, false );
			$this->notifier->maybe_send_critical_alert( $results, $settings );
		}

		return $results;
	}

	public function create_baseline(): array {
		$settings    = WSR_Helpers::get_settings();
		$ignore_list = WSR_Helpers::get_ignore_list();
		$scanner     = new WSR_File_Scanner( $settings, $ignore_list );
		$inventory   = $scanner->scan();

		return $this->baseline->save( $inventory );
	}

	public function handle_manual_scan_ajax(): void {
		$this->assert_ajax_access();
		$results = $this->run_scan( true );
		wp_send_json_success(
			array(
				'message' => __( 'Manual scan completed.', 'website-security-radar' ),
				'results' => $results,
			)
		);
	}

	public function handle_create_baseline_ajax(): void {
		$this->assert_ajax_access();
		$baseline = $this->create_baseline();
		wp_send_json_success(
			array(
				'message'  => __( 'Baseline created.', 'website-security-radar' ),
				'baseline' => $baseline,
			)
		);
	}

	public function handle_settings_updated( $old_value, $value ): void {
		$this->cron->maybe_schedule( WSR_Helpers::get_settings() );
	}

	private function build_change_issues( array $baseline ): array {
		$issues = array();

		if ( empty( $baseline['has_baseline'] ) ) {
			return $issues;
		}

		foreach ( $baseline['new_files'] as $path ) {
			$issues[] = $this->change_issue( 'medium', $path, 'New file detected', 'This file does not exist in the saved baseline.' );
		}

		foreach ( $baseline['modified'] as $path ) {
			$issues[] = $this->change_issue( 'high', $path, 'Modified file detected', 'This file differs from the saved baseline metadata or hash.' );
		}

		foreach ( $baseline['deleted'] as $path ) {
			$issues[] = $this->change_issue( 'medium', $path, 'Deleted file detected', 'This file existed in the baseline but was not found in the current scan.' );
		}

		return $issues;
	}

	private function change_issue( string $severity, string $path, string $issue, string $explanation ): array {
		return array(
			'type'          => 'file change',
			'severity'      => $severity,
			'path'          => $path,
			'issue'         => $issue,
			'explanation'   => $explanation,
			'line'          => 0,
			'detected_at'   => gmdate( 'c' ),
			'detected_date' => gmdate( 'c' ),
		);
	}

	private function assert_ajax_access(): void {
		check_ajax_referer( WSR_Helpers::AJAX_NONCE_ACTION, 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'website-security-radar' ) ), 403 );
		}
	}
}
