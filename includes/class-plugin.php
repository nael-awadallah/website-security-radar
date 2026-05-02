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
	private WSR_Timeline $timeline;
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
		$this->timeline   = new WSR_Timeline();
		$this->notifier   = new WSR_Notifier();
		$this->admin_page = new WSR_Admin_Page( $this );
	}

	public function init(): void {
		$this->baseline->migrate();
		$this->cron->register();
		$this->admin_page->register();

		add_action( 'admin_init', array( $this->settings, 'register' ) );
		add_action( 'wp_ajax_' . WSR_Helpers::AJAX_SCAN_ACTION, array( $this, 'handle_manual_scan_ajax' ) );
		add_action( 'wp_ajax_' . WSR_Helpers::AJAX_BASELINE_ACTION, array( $this, 'handle_create_baseline_ajax' ) );
		add_action( 'update_option_' . WSR_Helpers::SETTINGS_OPTION, array( $this, 'handle_settings_updated' ), 10, 2 );
	}

	public static function activate(): void {
		update_option( WSR_Helpers::SETTINGS_OPTION, WSR_Helpers::get_settings(), false );

		if ( false === get_option( WSR_Helpers::TIMELINE_OPTION, false ) ) {
			add_option( WSR_Helpers::TIMELINE_OPTION, array(), '', false );
		}

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
					'ignored_findings'    => 0,
				),
				'severity_counts'  => array(
					'critical' => 0,
					'high'     => 0,
					'medium'   => 0,
					'low'      => 0,
				),
				'score_breakdown'   => array(
					'score'                => 100,
					'total_deduction'      => 0,
					'deduction_per_severity' => array(
						'critical' => 20,
						'high'     => 10,
						'medium'   => 5,
						'low'      => 2,
					),
					'categories'           => array(),
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
		$baseline    = $this->filter_baseline_by_ignore_rules( $this->baseline->compare( $inventory ), $ignore_list );
		$issues      = $this->build_change_issues( $baseline );

		$malware_scanner = new WSR_Malware_Scanner( $settings, $ignore_list );
		$issues          = array_merge( $issues, $malware_scanner->scan( $inventory ) );

		$hardening_checker = new WSR_Hardening_Checker();
		$issues            = array_merge( $issues, $hardening_checker->run( $inventory ) );
		$partition         = WSR_Helpers::split_ignored_issues( $issues, $ignore_list );
		$ignored_issues    = $partition['ignored'];
		$issues            = WSR_Helpers::apply_review_status( $partition['visible'] );
		$severity_counts   = WSR_Helpers::count_severity( $issues );
		$score_breakdown   = WSR_Helpers::calculate_security_score_breakdown( $issues );
		$score             = (int) ( $score_breakdown['score'] ?? 100 );

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
				'ignored_findings'    => count( $ignored_issues ),
			),
			'severity_counts' => $severity_counts,
			'score_breakdown' => $score_breakdown,
			'issues'          => $issues,
			'baseline'        => $baseline,
			'inventory_count' => count( $inventory ),
		);

		if ( $persist ) {
			update_option( WSR_Helpers::RESULTS_OPTION, $results, false );
			$this->notifier->maybe_send_critical_alert( $results, $settings );
		}

		$this->record_scan_timeline_events( $results, $persist ? 'manual' : 'scheduled' );

		return $results;
	}

	public function create_baseline( string $label = '' ): array {
		$settings    = WSR_Helpers::get_settings();
		$ignore_list = WSR_Helpers::get_ignore_list();
		$scanner     = new WSR_File_Scanner( $settings, $ignore_list );
		$inventory   = $scanner->scan();
		$baseline    = $this->baseline->save( $inventory, $label, get_current_user_id() );

		$this->timeline->add_event(
			array(
				'type'          => 'baseline_created',
				'severity'      => 'info',
				'message'       => sprintf(
					/* translators: 1: baseline label, 2: scanned files count. */
					__( 'Baseline "%1$s" created from %2$d scanned files.', 'website-security-radar' ),
					$baseline['label'],
					count( $inventory )
				),
				'actor_user_id' => get_current_user_id(),
			)
		);

		return $baseline;
	}

	public function handle_manual_scan_ajax(): void {
		$this->assert_ajax_access();
		try {
			$this->timeline->add_event(
				array(
					'type'          => 'manual_scan_started',
					'severity'      => 'info',
					'message'       => __( 'Manual scan started.', 'website-security-radar' ),
					'actor_user_id' => get_current_user_id(),
				)
			);
			$results = $this->run_scan( true );
			wp_send_json_success(
				array(
					'message' => __( 'Manual scan completed.', 'website-security-radar' ),
					'results' => $results,
				)
			);
		} catch ( Throwable $exception ) {
			wp_send_json_error(
				array(
					'message' => __( 'The scan could not be completed. Check PHP error logs for details.', 'website-security-radar' ),
				),
				500
			);
		}
	}

	public function handle_create_baseline_ajax(): void {
		$this->assert_ajax_access();
		$label = sanitize_text_field( wp_unslash( $_POST['label'] ?? '' ) );

		try {
			$baseline = $this->create_baseline( $label );
			wp_send_json_success(
				array(
					'message'  => sprintf(
						/* translators: %s: baseline label. */
						__( 'Baseline "%s" created.', 'website-security-radar' ),
						$baseline['label']
					),
					'baseline' => $baseline,
				)
			);
		} catch ( Throwable $exception ) {
			wp_send_json_error(
				array(
					'message' => __( 'The baseline could not be created. Check PHP error logs for details.', 'website-security-radar' ),
				),
				500
			);
		}
	}

	public function handle_settings_updated( $old_value, $value ): void {
		$this->cron->maybe_schedule( WSR_Helpers::get_settings() );
		$this->timeline->add_event(
			array(
				'type'          => 'settings_changed',
				'severity'      => 'info',
				'message'       => __( 'Security Radar settings were updated.', 'website-security-radar' ),
				'actor_user_id' => get_current_user_id(),
			)
		);
	}

	public function add_timeline_event( array $event ): void {
		$this->timeline->add_event( $event );
	}

	public function get_timeline_events( array $filters = array() ): array {
		return $this->timeline->get_events( $filters );
	}

	public function get_baselines(): array {
		return $this->baseline->get_all();
	}

	public function get_active_baseline(): array {
		return $this->baseline->get_active();
	}

	public function get_baseline( string $baseline_id ): array {
		return $this->baseline->get_by_id( $baseline_id );
	}

	public function set_active_baseline( string $baseline_id ): bool {
		return $this->baseline->set_active( $baseline_id );
	}

	public function delete_baseline( string $baseline_id ): bool {
		return $this->baseline->delete( $baseline_id );
	}

	private function build_change_issues( array $baseline ): array {
		$issues = array();

		if ( empty( $baseline['has_baseline'] ) ) {
			return $issues;
		}

		foreach ( $baseline['new_files'] as $path ) {
			$issues[] = $this->change_issue( 'medium', $path, __( 'New file detected', 'website-security-radar' ), __( 'This file does not exist in the saved baseline.', 'website-security-radar' ) );
		}

		foreach ( $baseline['modified'] as $path ) {
			$issues[] = $this->change_issue(
				'high',
				$path,
				__( 'Modified file detected', 'website-security-radar' ),
				__( 'This file differs from the saved baseline metadata or hash.', 'website-security-radar' ),
				array(
					'change_details' => $baseline['modified_details'][ $path ] ?? array(),
				)
			);
		}

		foreach ( $baseline['deleted'] as $path ) {
			$issues[] = $this->change_issue( 'medium', $path, __( 'Deleted file detected', 'website-security-radar' ), __( 'This file existed in the baseline but was not found in the current scan.', 'website-security-radar' ) );
		}

		return $issues;
	}

	private function change_issue( string $severity, string $path, string $issue, string $explanation, array $extra = array() ): array {
		$issue_data = array(
			'type'          => 'file change',
			'severity'      => $severity,
			'path'          => $path,
			'issue'         => $issue,
			'explanation'   => $explanation,
			'line'          => 0,
			'detected_at'   => gmdate( 'c' ),
			'detected_date' => gmdate( 'c' ),
		);

		if ( ! empty( $extra ) ) {
			$issue_data = array_merge( $issue_data, $extra );
		}

		return $issue_data;
	}

	private function assert_ajax_access(): void {
		check_ajax_referer( WSR_Helpers::AJAX_NONCE_ACTION, 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'website-security-radar' ) ), 403 );
		}
	}

	private function filter_baseline_by_ignore_rules( array $baseline, array $ignore_rules ): array {
		foreach ( array( 'new_files', 'modified', 'deleted' ) as $key ) {
			if ( empty( $baseline[ $key ] ) || ! is_array( $baseline[ $key ] ) ) {
				$baseline[ $key ] = array();
				continue;
			}

			$baseline[ $key ] = array_values(
				array_filter(
					$baseline[ $key ],
					static function ( string $path ) use ( $ignore_rules ): bool {
						return ! WSR_Helpers::is_ignored_path( $path, $ignore_rules );
					}
				)
			);
		}

		if ( ! empty( $baseline['modified_details'] ) && is_array( $baseline['modified_details'] ) ) {
			foreach ( array_keys( $baseline['modified_details'] ) as $path ) {
				if ( WSR_Helpers::is_ignored_path( $path, $ignore_rules ) ) {
					unset( $baseline['modified_details'][ $path ] );
				}
			}
		}

		return $baseline;
	}

	private function record_scan_timeline_events( array $results, string $scan_type ): void {
		$issues   = $results['issues'] ?? array();
		$summary  = $results['summary'] ?? array();
		$user_id  = 'manual' === $scan_type ? get_current_user_id() : 0;
		$event    = array(
			'type'          => 'manual' === $scan_type ? 'manual_scan_completed' : 'scheduled_scan_completed',
			'severity'      => ! empty( $summary['critical_issues'] ) ? 'critical' : 'info',
			'message'       => sprintf(
				/* translators: 1: total scanned files, 2: total issue count. */
				__( 'Scan completed. %1$d files scanned and %2$d visible issues recorded.', 'website-security-radar' ),
				(int) ( $summary['total_scanned_files'] ?? 0 ),
				count( $issues )
			),
			'actor_user_id' => $user_id,
		);
		$this->timeline->add_event( $event );

		foreach ( $results['baseline']['new_files'] ?? array() as $path ) {
			$this->timeline->add_event(
				array(
					'type'          => 'new_file_detected',
					'severity'      => 'medium',
					'message'       => __( 'New file detected during scan.', 'website-security-radar' ),
					'relative_path' => $path,
					'actor_user_id' => $user_id,
				)
			);
		}

		foreach ( $results['baseline']['modified'] ?? array() as $path ) {
			$this->timeline->add_event(
				array(
					'type'          => 'modified_file_detected',
					'severity'      => 'high',
					'message'       => __( 'Modified file detected during scan.', 'website-security-radar' ),
					'relative_path' => $path,
					'actor_user_id' => $user_id,
				)
			);
		}

		foreach ( $issues as $issue ) {
			$severity = sanitize_key( (string) ( $issue['severity'] ?? 'low' ) );
			$type     = strtolower( trim( (string) ( $issue['type'] ?? '' ) ) );
			$path     = (string) ( $issue['path'] ?? $issue['file'] ?? '' );

			if ( in_array( $type, array( 'malware', 'suspicious pattern', 'potential risk' ), true ) ) {
				$this->timeline->add_event(
					array(
						'type'          => 'suspicious_pattern_detected',
						'severity'      => $severity,
						'message'       => sanitize_text_field( (string) ( $issue['issue'] ?? __( 'Suspicious pattern detected.', 'website-security-radar' ) ) ),
						'relative_path' => $path,
						'actor_user_id' => $user_id,
					)
				);
			}

			if ( 'critical' === $severity ) {
				$this->timeline->add_event(
					array(
						'type'          => 'critical_issue_detected',
						'severity'      => 'critical',
						'message'       => sanitize_text_field( (string) ( $issue['issue'] ?? __( 'Critical issue detected.', 'website-security-radar' ) ) ),
						'relative_path' => $path,
						'actor_user_id' => $user_id,
					)
				);
			}
		}
	}
}
