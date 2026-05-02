<?php
/**
 * Admin UI.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Admin_Page {
	private WSR_Plugin $plugin;

	public function __construct( WSR_Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_post_wsr_create_baseline', array( $this, 'handle_create_baseline' ) );
		add_action( 'admin_post_wsr_set_active_baseline', array( $this, 'handle_set_active_baseline' ) );
		add_action( 'admin_post_wsr_delete_baseline', array( $this, 'handle_delete_baseline' ) );
		add_action( 'admin_post_wsr_mark_reviewed', array( $this, 'handle_mark_reviewed' ) );
		add_action( 'admin_post_wsr_ignore_path', array( $this, 'handle_ignore_path' ) );
		add_action( 'admin_post_wsr_add_ignore_rule', array( $this, 'handle_add_ignore_rule' ) );
		add_action( 'admin_post_wsr_toggle_ignore_rule', array( $this, 'handle_toggle_ignore_rule' ) );
		add_action( 'admin_post_wsr_delete_ignore_rule', array( $this, 'handle_delete_ignore_rule' ) );
		add_action( 'admin_post_wsr_reset_ignore_list', array( $this, 'handle_reset_ignore_list' ) );
	}

	public function register_menu(): void {
		$capability = 'manage_options';
		$slug       = 'website-security-radar';

		add_menu_page(
			__( 'Security Radar', 'website-security-radar' ),
			__( 'Security Radar', 'website-security-radar' ),
			$capability,
			$slug,
			array( $this, 'render_dashboard_page' ),
			'data:image/svg+xml;base64,' . base64_encode( (string) @file_get_contents( WSR_PLUGIN_DIR . 'assets/branding/icon.svg' ) ),
			58
		);

		add_submenu_page( $slug, __( 'Dashboard', 'website-security-radar' ), __( 'Dashboard', 'website-security-radar' ), $capability, $slug, array( $this, 'render_dashboard_page' ) );
		add_submenu_page( $slug, __( 'Scan Results', 'website-security-radar' ), __( 'Scan Results', 'website-security-radar' ), $capability, 'website-security-radar-results', array( $this, 'render_results_page' ) );
		add_submenu_page( $slug, __( 'Baselines', 'website-security-radar' ), __( 'Baselines', 'website-security-radar' ), $capability, 'website-security-radar-baselines', array( $this, 'render_baselines_page' ) );
		add_submenu_page( $slug, __( 'Timeline', 'website-security-radar' ), __( 'Timeline', 'website-security-radar' ), $capability, 'website-security-radar-timeline', array( $this, 'render_timeline_page' ) );
		add_submenu_page( $slug, __( 'Settings', 'website-security-radar' ), __( 'Settings', 'website-security-radar' ), $capability, 'website-security-radar-settings', array( $this, 'render_settings_page' ) );
		add_submenu_page( $slug, __( 'Ignore List', 'website-security-radar' ), __( 'Ignore List', 'website-security-radar' ), $capability, 'website-security-radar-ignore-list', array( $this, 'render_ignore_list_page' ) );
		add_submenu_page( $slug, __( 'About', 'website-security-radar' ), __( 'About / Branding', 'website-security-radar' ), $capability, 'website-security-radar-about', array( $this, 'render_about_page' ) );
	}

	public function enqueue_assets( string $hook ): void {
		if ( false === strpos( $hook, 'website-security-radar' ) ) {
			return;
		}

		wp_enqueue_style( 'wsr-admin', WSR_PLUGIN_URL . 'assets/admin.css', array(), WSR_PLUGIN_VERSION );
		wp_enqueue_script( 'wsr-admin', WSR_PLUGIN_URL . 'assets/admin.js', array( 'jquery' ), WSR_PLUGIN_VERSION, true );

		wp_localize_script(
			'wsr-admin',
			'wsrAdmin',
			array(
				'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
				'scanAction'     => WSR_Helpers::AJAX_SCAN_ACTION,
				'baselineAction' => WSR_Helpers::AJAX_BASELINE_ACTION,
				'nonce'          => wp_create_nonce( WSR_Helpers::AJAX_NONCE_ACTION ),
				'strings'        => array(
					'scanning'   => __( 'Running scan...', 'website-security-radar' ),
					'baselining' => __( 'Creating baseline...', 'website-security-radar' ),
					'showDetails'=> __( 'Details', 'website-security-radar' ),
					'hideDetails'=> __( 'Hide details', 'website-security-radar' ),
					'success'    => __( 'Action completed.', 'website-security-radar' ),
					'error'      => __( 'Request failed.', 'website-security-radar' ),
				),
			)
		);
	}

	public function render_dashboard_page(): void {
		$this->assert_capability();
		$results            = $this->plugin->get_latest_results();
		$summary            = $results['summary'] ?? array();
		$score_breakdown    = $this->normalize_score_breakdown( $results['score_breakdown'] ?? array() );
		$top_critical_issue = $this->get_top_issue( $results['issues'] ?? array(), 'critical' );
		$active_baseline    = $this->plugin->get_active_baseline();
		$settings           = WSR_Helpers::get_settings();
		$score              = (int) ( $results['score'] ?? 100 );
		$risk_level         = strtolower( (string) ( $results['risk_level'] ?? 'safe' ) );
		$recommendations    = $this->get_recommendations( $results );
		$stat_cards         = $this->get_dashboard_stat_cards( $summary );
		$scan_summary       = $this->get_dashboard_scan_summary( $results, $active_baseline, $settings );
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Dashboard', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div class="wsr-dashboard-layout">
				<div class="wsr-dashboard-main">
					<div class="wsr-card wsr-card-score wsr-card-score-<?php echo esc_attr( $risk_level ); ?>">
						<div class="wsr-score-copy">
							<div class="wsr-section-eyebrow"><?php esc_html_e( 'Security posture', 'website-security-radar' ); ?></div>
							<h2><?php esc_html_e( 'Security score', 'website-security-radar' ); ?></h2>
							<p class="wsr-risk-text"><?php echo esc_html( $results['risk_level'] ?? 'Safe' ); ?></p>
							<p class="wsr-score-summary">
								<?php
								echo esc_html(
									sprintf(
										__( 'Score impacted by: %1$d critical issues, %2$d suspicious files', 'website-security-radar' ),
										(int) ( $summary['critical_issues'] ?? 0 ),
										(int) ( $summary['suspicious_files'] ?? 0 )
									)
								);
								?>
							</p>
							<div class="wsr-score-meta">
								<span><?php echo esc_html( sprintf( __( 'Last scan: %s', 'website-security-radar' ), WSR_Helpers::format_datetime( $results['scanned_at'] ?? '' ) ) ); ?></span>
								<span><?php echo esc_html( $this->get_dashboard_trend_hint() ); ?></span>
							</div>
							<?php if ( $top_critical_issue ) : ?>
								<p class="wsr-inline-alert">
									<strong><?php esc_html_e( 'Top critical issue:', 'website-security-radar' ); ?></strong>
									<?php echo esc_html( $top_critical_issue['issue'] ); ?>
								</p>
							<?php endif; ?>
						</div>
						<div class="wsr-score-visual">
							<div class="wsr-score-ring wsr-risk-<?php echo esc_attr( $risk_level ); ?>" style="--wsr-score: <?php echo esc_attr( (string) max( 0, min( 100, $score ) ) ); ?>;">
								<span><?php echo esc_html( (string) $score ); ?></span>
								<small>/100</small>
							</div>
						</div>
					</div>
					<div class="wsr-grid wsr-grid-stats">
						<?php foreach ( $stat_cards as $card ) : ?>
							<div class="wsr-card wsr-stat-card wsr-stat-card-<?php echo esc_attr( $card['tone'] ); ?>">
								<div class="wsr-stat-icon-wrap">
									<span class="dashicons <?php echo esc_attr( $card['icon'] ); ?>" aria-hidden="true"></span>
								</div>
								<div class="wsr-stat-copy">
									<span class="wsr-stat-label"><?php echo esc_html( $card['label'] ); ?></span>
									<span class="wsr-stat-value"><?php echo esc_html( (string) $card['value'] ); ?></span>
									<span class="wsr-stat-helper"><?php echo esc_html( $card['helper'] ); ?></span>
								</div>
							</div>
						<?php endforeach; ?>
					</div>
					<div class="wsr-card">
						<div class="wsr-section-head">
							<div>
								<div class="wsr-section-eyebrow"><?php esc_html_e( 'Priority queue', 'website-security-radar' ); ?></div>
								<h2><?php esc_html_e( 'Top critical issues', 'website-security-radar' ); ?></h2>
								<p><?php esc_html_e( 'Focus on the highest-severity findings first.', 'website-security-radar' ); ?></p>
							</div>
							<a class="wsr-text-link" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-results' ) ); ?>"><?php esc_html_e( 'View all issues', 'website-security-radar' ); ?> <span aria-hidden="true">&rarr;</span></a>
						</div>
						<?php $this->render_top_issues_list( $results['issues'] ?? array() ); ?>
					</div>
					<div class="wsr-card">
						<div class="wsr-section-head">
							<div>
								<div class="wsr-section-eyebrow"><?php esc_html_e( 'Score details', 'website-security-radar' ); ?></div>
								<h2><?php esc_html_e( 'Score breakdown', 'website-security-radar' ); ?></h2>
								<p><?php echo esc_html( sprintf( __( 'Score: %1$d/100 with %2$d total deduction points.', 'website-security-radar' ), (int) ( $score_breakdown['score'] ?? 100 ), (int) ( $score_breakdown['total_deduction'] ?? 0 ) ) ); ?></p>
							</div>
						</div>
						<?php $this->render_score_breakdown_list( $score_breakdown ); ?>
					</div>
				</div>
				<div class="wsr-dashboard-sidebar">
					<div class="wsr-card">
						<div class="wsr-section-eyebrow"><?php esc_html_e( 'Recommended next steps', 'website-security-radar' ); ?></div>
						<h2><?php esc_html_e( 'Quick recommendations', 'website-security-radar' ); ?></h2>
						<div class="wsr-recommendation-list">
							<?php foreach ( $recommendations as $recommendation ) : ?>
								<div class="wsr-recommendation-card wsr-recommendation-<?php echo esc_attr( $recommendation['tone'] ); ?>">
									<div class="wsr-recommendation-icon" aria-hidden="true"><?php echo esc_html( $recommendation['icon'] ); ?></div>
									<div class="wsr-recommendation-copy">
										<strong><?php echo esc_html( $recommendation['title'] ); ?></strong>
										<p><?php echo esc_html( $recommendation['description'] ); ?></p>
									</div>
								</div>
							<?php endforeach; ?>
						</div>
					</div>
					<div class="wsr-card wsr-card-actions" data-wsr-actions-card>
						<div>
							<div class="wsr-section-eyebrow"><?php esc_html_e( 'Controls', 'website-security-radar' ); ?></div>
							<h2><?php esc_html_e( 'Actions', 'website-security-radar' ); ?></h2>
							<p><?php esc_html_e( 'Run a fresh scan or save the current trusted state as your baseline.', 'website-security-radar' ); ?></p>
						</div>
						<div class="wsr-setting-row wsr-setting-field">
							<label class="wsr-setting-heading" for="wsr-baseline-label"><?php esc_html_e( 'Baseline label', 'website-security-radar' ); ?></label>
							<input id="wsr-baseline-label" type="text" class="regular-text" value="<?php echo esc_attr( WSR_Helpers::get_default_baseline_label() ); ?>" placeholder="<?php echo esc_attr( WSR_Helpers::get_default_baseline_label() ); ?>" />
						</div>
						<div class="wsr-action-stack">
							<div class="wsr-action-item">
								<button type="button" class="button button-primary wsr-ajax-button" data-wsr-action="scan"><?php esc_html_e( 'Run Scan', 'website-security-radar' ); ?></button>
								<p><?php esc_html_e( 'Start an on-demand scan of monitored files and hardening checks.', 'website-security-radar' ); ?></p>
							</div>
							<div class="wsr-action-item">
								<button type="button" class="button button-secondary wsr-ajax-button" data-wsr-action="baseline"><?php esc_html_e( 'Create Baseline', 'website-security-radar' ); ?></button>
								<p><?php esc_html_e( 'Capture the current trusted state for future change comparisons.', 'website-security-radar' ); ?></p>
							</div>
						</div>
						<div class="wsr-card-meta">
							<span><?php echo esc_html( sprintf( __( '%d files scanned', 'website-security-radar' ), (int) ( $summary['total_scanned_files'] ?? 0 ) ) ); ?></span>
							<span><?php echo esc_html( sprintf( __( '%d active issues', 'website-security-radar' ), count( $results['issues'] ?? array() ) ) ); ?></span>
						</div>
					</div>
					<div class="wsr-card">
						<div class="wsr-section-eyebrow"><?php esc_html_e( 'Operational view', 'website-security-radar' ); ?></div>
						<h2><?php esc_html_e( 'Scan summary', 'website-security-radar' ); ?></h2>
						<div class="wsr-summary-list">
							<?php foreach ( $scan_summary as $item ) : ?>
								<div class="wsr-summary-item">
									<span class="wsr-summary-label"><?php echo esc_html( $item['label'] ); ?></span>
									<strong class="wsr-summary-value"><?php echo esc_html( $item['value'] ); ?></strong>
								</div>
							<?php endforeach; ?>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	public function render_results_page(): void {
		$this->assert_capability();
		$results                = $this->plugin->get_latest_results();
		$ignore_partition       = WSR_Helpers::split_ignored_issues( $results['issues'] ?? array() );
		$all_issues             = $ignore_partition['visible'];
		$ignored_count          = count( $ignore_partition['ignored'] );
		$issue_groups           = $this->get_issue_groups( $all_issues );
		$detail_issue           = $this->get_selected_issue( $all_issues );
		$selected_change_detail = $this->get_selected_change_detail( $all_issues );
		$filtered_issues        = $this->get_filtered_issues( $all_issues );
		$pagination             = $this->get_paginated_issues( $filtered_issues );
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Scan Results', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div id="wsr-results-content">
				<?php $this->render_issue_group_cards( $issue_groups ); ?>
				<?php if ( $selected_change_detail ) : ?>
					<?php $this->render_change_details_panel( $selected_change_detail ); ?>
				<?php endif; ?>
				<?php if ( $detail_issue ) : ?>
					<div class="wsr-card">
						<h2><?php esc_html_e( 'Issue details', 'website-security-radar' ); ?></h2>
						<p><strong><?php esc_html_e( 'Type:', 'website-security-radar' ); ?></strong> <?php echo esc_html( WSR_Helpers::get_type_label( (string) ( $detail_issue['type'] ?? '' ) ) ); ?></p>
						<?php if ( ! empty( $detail_issue['confidence'] ) ) : ?>
							<p><strong><?php esc_html_e( 'Confidence:', 'website-security-radar' ); ?></strong> <?php echo esc_html( ucfirst( (string) $detail_issue['confidence'] ) ); ?></p>
						<?php endif; ?>
						<p><strong><?php esc_html_e( 'Issue:', 'website-security-radar' ); ?></strong> <?php echo esc_html( $detail_issue['issue'] ); ?></p>
						<p><strong><?php esc_html_e( 'Path:', 'website-security-radar' ); ?></strong> <?php echo esc_html( (string) ( $detail_issue['path'] ?? $detail_issue['file'] ?? '' ) ); ?></p>
						<p><strong><?php esc_html_e( 'Explanation:', 'website-security-radar' ); ?></strong> <?php echo esc_html( $detail_issue['explanation'] ); ?></p>
						<?php if ( isset( $detail_issue['score'] ) ) : ?>
							<p><strong><?php esc_html_e( 'Score:', 'website-security-radar' ); ?></strong> <?php echo esc_html( (string) $detail_issue['score'] ); ?></p>
						<?php endif; ?>
						<?php if ( ! empty( $detail_issue['matched_patterns'] ) && is_array( $detail_issue['matched_patterns'] ) ) : ?>
							<p><strong><?php esc_html_e( 'Matched patterns:', 'website-security-radar' ); ?></strong> <?php echo esc_html( implode( ', ', array_map( 'sanitize_text_field', $detail_issue['matched_patterns'] ) ) ); ?></p>
						<?php endif; ?>
						<?php if ( ! empty( $detail_issue['context_notes'] ) && is_array( $detail_issue['context_notes'] ) ) : ?>
							<p><strong><?php esc_html_e( 'Context notes:', 'website-security-radar' ); ?></strong> <?php echo esc_html( implode( ', ', array_map( 'sanitize_text_field', $detail_issue['context_notes'] ) ) ); ?></p>
						<?php endif; ?>
						<?php if ( ! empty( $detail_issue['line'] ) ) : ?>
							<p><strong><?php esc_html_e( 'Line:', 'website-security-radar' ); ?></strong> <?php echo esc_html( (string) $detail_issue['line'] ); ?></p>
						<?php endif; ?>
					</div>
				<?php endif; ?>
				<div class="wsr-card">
					<div class="wsr-section-head">
						<div>
							<h2><?php esc_html_e( 'Issue Log', 'website-security-radar' ); ?></h2>
							<p><?php echo esc_html( sprintf( __( '%1$d matching issue(s) out of %2$d total.', 'website-security-radar' ), count( $filtered_issues ), count( $all_issues ) ) ); ?></p>
							<?php if ( $ignored_count > 0 ) : ?>
								<p><?php echo esc_html( sprintf( __( '%d finding(s) are currently hidden by ignore rules.', 'website-security-radar' ), $ignored_count ) ); ?></p>
							<?php endif; ?>
						</div>
					</div>
					<?php $this->render_issue_filters( $all_issues ); ?>
					<?php $this->render_issue_table( $pagination['items'], true ); ?>
					<?php $this->render_issue_pagination( $pagination['current_page'], $pagination['total_pages'] ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	public function render_settings_page(): void {
		$this->assert_capability();
		$settings = WSR_Helpers::get_settings();
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Settings', 'website-security-radar' ) ); ?>
			<form method="post" action="options.php">
				<?php settings_fields( 'wsr_settings_group' ); ?>
				<div class="wsr-grid wsr-grid-settings">
					<div class="wsr-card">
						<h2><?php esc_html_e( 'Scan Scope', 'website-security-radar' ); ?></h2>
						<p class="wsr-card-intro"><?php esc_html_e( 'Choose which areas are included in scans.', 'website-security-radar' ); ?></p>
						<div class="wsr-setting-list">
							<?php $this->render_toggle_setting( 'scan_plugins', __( 'Scan plugins', 'website-security-radar' ), __( 'Monitor installed plugin files for changes and suspicious patterns.', 'website-security-radar' ), $settings ); ?>
							<?php $this->render_toggle_setting( 'scan_themes', __( 'Scan themes', 'website-security-radar' ), __( 'Inspect active and inactive themes in wp-content/themes.', 'website-security-radar' ), $settings ); ?>
							<?php $this->render_toggle_setting( 'scan_uploads', __( 'Scan uploads', 'website-security-radar' ), __( 'Check the uploads directory for suspicious files, including PHP files.', 'website-security-radar' ), $settings ); ?>
							<?php $this->render_toggle_setting( 'scan_root_files', __( 'Scan root files', 'website-security-radar' ), __( 'Include key WordPress root files such as wp-config.php and .htaccess.', 'website-security-radar' ), $settings ); ?>
						</div>
					</div>
					<div class="wsr-card">
						<h2><?php esc_html_e( 'Alerts', 'website-security-radar' ); ?></h2>
						<p class="wsr-card-intro"><?php esc_html_e( 'Control email notifications for important findings.', 'website-security-radar' ); ?></p>
						<div class="wsr-setting-list">
							<?php $this->render_toggle_setting( 'enable_email_alerts', __( 'Enable email alerts', 'website-security-radar' ), __( 'Send an alert email when critical issues are found.', 'website-security-radar' ), $settings ); ?>
							<div class="wsr-setting-row wsr-setting-field">
								<label class="wsr-setting-heading" for="wsr-alert-email"><?php esc_html_e( 'Alert email', 'website-security-radar' ); ?></label>
								<input id="wsr-alert-email" type="email" class="regular-text" name="<?php echo esc_attr( WSR_Helpers::SETTINGS_OPTION ); ?>[alert_email]" value="<?php echo esc_attr( $settings['alert_email'] ); ?>" />
								<p class="description"><?php esc_html_e( 'Use the address that should receive critical issue notifications.', 'website-security-radar' ); ?></p>
							</div>
						</div>
					</div>
					<div class="wsr-card">
						<h2><?php esc_html_e( 'Performance', 'website-security-radar' ); ?></h2>
						<p class="wsr-card-intro"><?php esc_html_e( 'Keep scans lightweight on shared hosting environments.', 'website-security-radar' ); ?></p>
						<div class="wsr-setting-list">
							<div class="wsr-setting-row wsr-setting-field">
								<label class="wsr-setting-heading" for="wsr-max-file-size"><?php esc_html_e( 'Max file size to scan', 'website-security-radar' ); ?></label>
								<input id="wsr-max-file-size" type="number" class="small-text" name="<?php echo esc_attr( WSR_Helpers::SETTINGS_OPTION ); ?>[max_file_size]" value="<?php echo esc_attr( (string) $settings['max_file_size'] ); ?>" min="1024" step="1024" />
								<p class="description"><?php esc_html_e( 'Files larger than this limit are skipped for content scanning. Default: 2097152 bytes (2MB).', 'website-security-radar' ); ?></p>
							</div>
						</div>
					</div>
					<div class="wsr-card">
						<h2><?php esc_html_e( 'Scheduling', 'website-security-radar' ); ?></h2>
						<p class="wsr-card-intro"><?php esc_html_e( 'Control automatic background monitoring.', 'website-security-radar' ); ?></p>
						<div class="wsr-setting-list">
							<?php $this->render_toggle_setting( 'enable_scheduled_scan', __( 'Enable scheduled scan', 'website-security-radar' ), __( 'Run the scanner daily using WordPress cron.', 'website-security-radar' ), $settings ); ?>
						</div>
					</div>
				</div>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}

	public function render_timeline_page(): void {
		$this->assert_capability();
		$all_events = $this->plugin->get_timeline_events();
		$events     = $this->get_filtered_timeline_events( $all_events );
		$pagination = $this->get_paginated_timeline_events( $events );
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Timeline', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div class="wsr-card">
				<div class="wsr-section-head">
					<div>
						<h2><?php esc_html_e( 'Security Timeline', 'website-security-radar' ); ?></h2>
						<p><?php echo esc_html( sprintf( __( '%1$d matching event(s) out of %2$d stored.', 'website-security-radar' ), count( $events ), count( $all_events ) ) ); ?></p>
					</div>
				</div>
				<?php $this->render_timeline_filters( $all_events ); ?>
				<?php $this->render_timeline_table( $pagination['items'] ); ?>
				<?php $this->render_timeline_pagination( $pagination['current_page'], $pagination['total_pages'] ); ?>
			</div>
		</div>
		<?php
	}

	public function render_baselines_page(): void {
		$this->assert_capability();
		$baselines         = $this->plugin->get_baselines();
		$active_baseline   = $this->plugin->get_active_baseline();
		$selected_baseline = $this->get_selected_baseline( $baselines );
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Baselines', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div class="wsr-grid wsr-grid-main">
				<div class="wsr-card">
					<h2><?php esc_html_e( 'Create Baseline', 'website-security-radar' ); ?></h2>
					<p><?php esc_html_e( 'Capture a new trusted snapshot and set it as the active comparison baseline.', 'website-security-radar' ); ?></p>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<?php wp_nonce_field( WSR_Helpers::ADMIN_NONCE_ACTION ); ?>
						<input type="hidden" name="action" value="wsr_create_baseline" />
						<div class="wsr-setting-row wsr-setting-field">
							<label class="wsr-setting-heading" for="wsr-baseline-page-label"><?php esc_html_e( 'Label', 'website-security-radar' ); ?></label>
							<input id="wsr-baseline-page-label" type="text" class="regular-text" name="baseline_label" value="<?php echo esc_attr( WSR_Helpers::get_default_baseline_label() ); ?>" placeholder="<?php echo esc_attr( WSR_Helpers::get_default_baseline_label() ); ?>" />
						</div>
						<?php submit_button( __( 'Create Baseline', 'website-security-radar' ), 'primary', 'submit', false ); ?>
					</form>
				</div>
				<div class="wsr-card">
					<h2><?php esc_html_e( 'Active Baseline', 'website-security-radar' ); ?></h2>
					<?php if ( empty( $active_baseline ) ) : ?>
						<p><?php esc_html_e( 'No active baseline yet.', 'website-security-radar' ); ?></p>
					<?php else : ?>
						<p><strong><?php esc_html_e( 'Label:', 'website-security-radar' ); ?></strong> <?php echo esc_html( (string) $active_baseline['label'] ); ?></p>
						<p><strong><?php esc_html_e( 'Created:', 'website-security-radar' ); ?></strong> <?php echo esc_html( WSR_Helpers::format_datetime( (string) $active_baseline['created_at'] ) ); ?></p>
						<p><strong><?php esc_html_e( 'Files:', 'website-security-radar' ); ?></strong> <?php echo esc_html( number_format_i18n( (int) ( $active_baseline['file_count'] ?? 0 ) ) ); ?></p>
						<p><strong><?php esc_html_e( 'Hash summary:', 'website-security-radar' ); ?></strong> <code><?php echo esc_html( $this->shorten_hash( (string) ( $active_baseline['hash_summary'] ?? '' ) ) ); ?></code></p>
					<?php endif; ?>
				</div>
			</div>
			<?php if ( $selected_baseline ) : ?>
				<?php $this->render_baseline_details_panel( $selected_baseline, $active_baseline ); ?>
			<?php endif; ?>
			<div class="wsr-card">
				<h2><?php esc_html_e( 'Saved Baselines', 'website-security-radar' ); ?></h2>
				<?php $this->render_baselines_table( $baselines, $active_baseline ); ?>
			</div>
		</div>
		<?php
	}

	public function render_ignore_list_page(): void {
		$this->assert_capability();
		$ignore_rules      = WSR_Helpers::get_ignore_list();
		$latest_results    = $this->plugin->get_latest_results();
		$stored_issues     = $latest_results['issues'] ?? array();
		$ignore_partition  = WSR_Helpers::split_ignored_issues( $stored_issues, $ignore_rules );
		$active_rule_count = count(
			array_filter(
				$ignore_rules,
				static function ( array $rule ): bool {
					return ! empty( $rule['enabled'] );
				}
			)
		);
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Ignore List', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div class="wsr-grid wsr-grid-stats">
				<div class="wsr-card wsr-stat-card">
					<span class="wsr-stat-value"><?php echo esc_html( (string) count( $ignore_rules ) ); ?></span>
					<span class="wsr-stat-label"><?php esc_html_e( 'Total rules', 'website-security-radar' ); ?></span>
				</div>
				<div class="wsr-card wsr-stat-card">
					<span class="wsr-stat-value"><?php echo esc_html( (string) $active_rule_count ); ?></span>
					<span class="wsr-stat-label"><?php esc_html_e( 'Active rules', 'website-security-radar' ); ?></span>
				</div>
				<div class="wsr-card wsr-stat-card">
					<span class="wsr-stat-value"><?php echo esc_html( (string) count( $ignore_partition['ignored'] ) ); ?></span>
					<span class="wsr-stat-label"><?php esc_html_e( 'Ignored findings', 'website-security-radar' ); ?></span>
				</div>
			</div>
			<div class="wsr-card">
				<h2><?php esc_html_e( 'Add Ignore Rule', 'website-security-radar' ); ?></h2>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( WSR_Helpers::ADMIN_NONCE_ACTION ); ?>
					<input type="hidden" name="action" value="wsr_add_ignore_rule" />
					<div class="wsr-ignore-form-grid">
						<div class="wsr-filter-field">
							<label for="wsr-ignore-type"><?php esc_html_e( 'Rule type', 'website-security-radar' ); ?></label>
							<select id="wsr-ignore-type" name="ignore_type">
								<?php foreach ( WSR_Helpers::get_ignore_rule_types() as $rule_type => $label ) : ?>
									<option value="<?php echo esc_attr( $rule_type ); ?>"><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
							</select>
						</div>
						<div class="wsr-filter-field wsr-ignore-value-field">
							<label for="wsr-ignore-value"><?php esc_html_e( 'Rule value', 'website-security-radar' ); ?></label>
							<input id="wsr-ignore-value" type="text" name="ignore_value" value="" placeholder="<?php esc_attr_e( 'Example: wp-content/plugins/example/file.php', 'website-security-radar' ); ?>" />
						</div>
					</div>
					<label class="wsr-checkbox-row">
						<input type="checkbox" name="confirm_broad_rule" value="1" />
						<span><?php esc_html_e( 'I understand that broad ignore rules can hide legitimate security findings.', 'website-security-radar' ); ?></span>
					</label>
					<label class="wsr-checkbox-row">
						<input type="checkbox" name="confirm_uploads_php" value="1" />
						<span><?php esc_html_e( 'Allow this rule to ignore PHP files inside uploads if it matches them.', 'website-security-radar' ); ?></span>
					</label>
					<?php submit_button( __( 'Add Ignore Rule', 'website-security-radar' ), 'primary', 'submit', false ); ?>
				</form>
			</div>
			<div class="wsr-card">
				<h2><?php esc_html_e( 'Saved Rules', 'website-security-radar' ); ?></h2>
				<?php if ( empty( $ignore_rules ) ) : ?>
					<p><?php esc_html_e( 'No ignore rules yet.', 'website-security-radar' ); ?></p>
				<?php else : ?>
					<div class="wsr-table-wrap">
						<table class="widefat striped">
							<thead>
								<tr>
									<th><?php esc_html_e( 'Type', 'website-security-radar' ); ?></th>
									<th><?php esc_html_e( 'Value', 'website-security-radar' ); ?></th>
									<th><?php esc_html_e( 'Status', 'website-security-radar' ); ?></th>
									<th><?php esc_html_e( 'Matches', 'website-security-radar' ); ?></th>
									<th><?php esc_html_e( 'Warning', 'website-security-radar' ); ?></th>
									<th><?php esc_html_e( 'Actions', 'website-security-radar' ); ?></th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $ignore_rules as $rule ) : ?>
									<tr>
										<td><?php echo esc_html( WSR_Helpers::get_ignore_rule_types()[ $rule['type'] ] ?? $rule['type'] ); ?></td>
										<td><code class="wsr-path" title="<?php echo esc_attr( (string) $rule['value'] ); ?>"><?php echo esc_html( (string) $rule['value'] ); ?></code></td>
										<td><?php echo esc_html( ! empty( $rule['enabled'] ) ? __( 'Active', 'website-security-radar' ) : __( 'Disabled', 'website-security-radar' ) ); ?></td>
										<td><?php echo esc_html( (string) WSR_Helpers::count_ignored_matches_for_rule( $rule, $stored_issues ) ); ?></td>
										<td><?php echo esc_html( WSR_Helpers::get_ignore_rule_warning( $rule ) ?: __( 'None', 'website-security-radar' ) ); ?></td>
										<td>
											<div class="wsr-table-actions">
												<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wsr_toggle_ignore_rule&rule=' . rawurlencode( (string) $rule['id'] ) . '&enabled=' . ( ! empty( $rule['enabled'] ) ? '0' : '1' ) ), WSR_Helpers::ADMIN_NONCE_ACTION ) ); ?>"><?php echo esc_html( ! empty( $rule['enabled'] ) ? __( 'Disable', 'website-security-radar' ) : __( 'Enable', 'website-security-radar' ) ); ?></a>
												<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wsr_delete_ignore_rule&rule=' . rawurlencode( (string) $rule['id'] ) ), WSR_Helpers::ADMIN_NONCE_ACTION ) ); ?>"><?php esc_html_e( 'Delete', 'website-security-radar' ); ?></a>
											</div>
										</td>
									</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( WSR_Helpers::ADMIN_NONCE_ACTION ); ?>
					<input type="hidden" name="action" value="wsr_reset_ignore_list" />
					<?php submit_button( __( 'Reset Ignore List', 'website-security-radar' ), 'delete', 'submit', false ); ?>
				</form>
			</div>
		</div>
		<?php
	}

	public function render_about_page(): void {
		$this->assert_capability();
		$plugin_data = get_file_data(
			WSR_PLUGIN_FILE,
			array(
				'name'    => 'Plugin Name',
				'version' => 'Version',
				'author'  => 'Author',
			)
		);
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'About / Branding', 'website-security-radar' ) ); ?>
			<div class="wsr-grid wsr-grid-main">
				<div class="wsr-card">
					<div class="wsr-brand-preview">
						<img src="<?php echo esc_url( WSR_PLUGIN_URL . 'assets/branding/logo.svg' ); ?>" alt="<?php esc_attr_e( 'Website Security Radar logo', 'website-security-radar' ); ?>" class="wsr-brand-logo-preview" />
					</div>
					<h2><?php echo esc_html( $plugin_data['name'] ?: __( 'Website Security Radar', 'website-security-radar' ) ); ?></h2>
					<div class="wsr-meta-list">
						<span><?php echo esc_html( sprintf( __( 'Version %s', 'website-security-radar' ), $plugin_data['version'] ?: WSR_PLUGIN_VERSION ) ); ?></span>
						<span><?php echo esc_html( sprintf( __( 'Author: %s', 'website-security-radar' ), $plugin_data['author'] ?: __( 'Unknown', 'website-security-radar' ) ) ); ?></span>
					</div>
					<p><?php esc_html_e( 'A lightweight security intelligence plugin for agencies and site owners.', 'website-security-radar' ); ?></p>
				</div>
				<div class="wsr-card">
					<h2><?php esc_html_e( 'Brand assets', 'website-security-radar' ); ?></h2>
					<p><?php esc_html_e( 'SVG branding assets are stored in the plugin assets directory for lightweight distribution.', 'website-security-radar' ); ?></p>
					<ul class="wsr-asset-list">
						<li><code>assets/branding/icon.svg</code></li>
						<li><code>assets/branding/logo.svg</code></li>
						<li><code>assets/branding/banner.svg</code></li>
					</ul>
				</div>
			</div>
			<div class="wsr-grid wsr-grid-features">
				<div class="wsr-card">
					<h3><?php esc_html_e( 'File Monitoring', 'website-security-radar' ); ?></h3>
					<p><?php esc_html_e( 'Track new, modified, and deleted files against a trusted baseline snapshot.', 'website-security-radar' ); ?></p>
				</div>
				<div class="wsr-card">
					<h3><?php esc_html_e( 'Malware Detection', 'website-security-radar' ); ?></h3>
					<p><?php esc_html_e( 'Flag suspicious code patterns, spam indicators, and risky PHP files.', 'website-security-radar' ); ?></p>
				</div>
				<div class="wsr-card">
					<h3><?php esc_html_e( 'Hardening Insights', 'website-security-radar' ); ?></h3>
					<p><?php esc_html_e( 'Review practical WordPress hardening issues and update exposure in one place.', 'website-security-radar' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}

	public function handle_mark_reviewed(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$issue_id = sanitize_text_field( wp_unslash( $_GET['issue'] ?? '' ) );

		if ( '' !== $issue_id ) {
			WSR_Helpers::mark_result_reviewed( $issue_id );
			$issue = $this->find_issue_by_id( $issue_id );
			$this->plugin->add_timeline_event(
				array(
					'type'          => 'issue_marked_reviewed',
					'severity'      => 'info',
					'message'       => sanitize_text_field( (string) ( $issue['issue'] ?? __( 'An issue was marked as reviewed.', 'website-security-radar' ) ) ),
					'relative_path' => (string) ( $issue['path'] ?? $issue['file'] ?? '' ),
					'actor_user_id' => get_current_user_id(),
				)
			);
		}

		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-results', array( 'wsr_notice' => 'reviewed' ) ) );
		exit;
	}

	public function handle_create_baseline(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$label    = sanitize_text_field( wp_unslash( $_POST['baseline_label'] ?? '' ) );
		$baseline = $this->plugin->create_baseline( $label );

		wp_safe_redirect(
			WSR_Helpers::admin_url(
				'website-security-radar-baselines',
				array(
					'wsr_notice' => 'baseline_created',
					'baseline'   => $baseline['id'],
				)
			)
		);
		exit;
	}

	public function handle_set_active_baseline(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$baseline_id = sanitize_key( wp_unslash( $_GET['baseline'] ?? '' ) );
		$notice      = $this->plugin->set_active_baseline( $baseline_id ) ? 'baseline_activated' : 'baseline_invalid';

		wp_safe_redirect(
			WSR_Helpers::admin_url(
				'website-security-radar-baselines',
				array(
					'wsr_notice' => $notice,
					'baseline'   => $baseline_id,
				)
			)
		);
		exit;
	}

	public function handle_delete_baseline(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$baseline_id = sanitize_key( wp_unslash( $_GET['baseline'] ?? '' ) );
		$notice      = $this->plugin->delete_baseline( $baseline_id ) ? 'baseline_deleted' : 'baseline_invalid';

		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-baselines', array( 'wsr_notice' => $notice ) ) );
		exit;
	}

	public function handle_ignore_path(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$path = sanitize_text_field( wp_unslash( $_GET['path'] ?? '' ) );

		if ( '' !== $path ) {
			if ( WSR_Helpers::rule_requires_uploads_php_confirmation( array( 'type' => 'exact_path', 'value' => $path ) ) ) {
				wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignore_uploads_confirm' ) ) );
				exit;
			}

			$rule = array(
				'type'              => 'exact_path',
				'value'             => $path,
				'enabled'           => 1,
				'allow_uploads_php' => 0,
			);

			WSR_Helpers::add_ignore_rule( $rule );
			$this->plugin->add_timeline_event(
				array(
					'type'          => 'path_ignored',
					'severity'      => 'low',
					'message'       => __( 'A path was added to the ignore list.', 'website-security-radar' ),
					'relative_path' => $rule['value'],
					'actor_user_id' => get_current_user_id(),
				)
			);
		}

		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignored' ) ) );
		exit;
	}

	public function handle_add_ignore_rule(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$rule = array(
			'type'              => sanitize_key( wp_unslash( $_POST['ignore_type'] ?? '' ) ),
			'value'             => sanitize_text_field( wp_unslash( $_POST['ignore_value'] ?? '' ) ),
			'enabled'           => 1,
			'allow_uploads_php' => ! empty( $_POST['confirm_uploads_php'] ) ? 1 : 0,
		);
		$warning = WSR_Helpers::get_ignore_rule_warning( $rule );

		if ( '' !== $warning && empty( $_POST['confirm_broad_rule'] ) ) {
			wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignore_warning' ) ) );
			exit;
		}

		if ( WSR_Helpers::rule_requires_uploads_php_confirmation( $rule ) && empty( $_POST['confirm_uploads_php'] ) ) {
			wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignore_uploads_confirm' ) ) );
			exit;
		}

		$result = WSR_Helpers::add_ignore_rule( $rule );

		if ( ! empty( $result['success'] ) ) {
			$this->plugin->add_timeline_event(
				array(
					'type'          => 'path_ignored',
					'severity'      => 'low',
					'message'       => __( 'An ignore rule was saved.', 'website-security-radar' ),
					'relative_path' => (string) ( $result['rule']['value'] ?? '' ),
					'actor_user_id' => get_current_user_id(),
				)
			);
		}

		$notice = ! empty( $result['success'] ) ? 'ignored' : 'ignore_invalid';
		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => $notice ) ) );
		exit;
	}

	public function handle_toggle_ignore_rule(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$rule_id  = sanitize_key( wp_unslash( $_GET['rule'] ?? '' ) );
		$enabled  = '1' === sanitize_text_field( wp_unslash( $_GET['enabled'] ?? '0' ) );

		WSR_Helpers::toggle_ignore_rule( $rule_id, $enabled );
		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignore_toggled' ) ) );
		exit;
	}

	public function handle_delete_ignore_rule(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$rule_id = sanitize_key( wp_unslash( $_GET['rule'] ?? '' ) );
		WSR_Helpers::delete_ignore_rule( $rule_id );
		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignore_deleted' ) ) );
		exit;
	}

	public function handle_reset_ignore_list(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );
		delete_option( WSR_Helpers::IGNORE_OPTION );
		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'reset' ) ) );
		exit;
	}

	private function render_header( string $title ): void {
		$icon_url = WSR_PLUGIN_URL . 'assets/branding/icon.svg';
		?>
		<div class="wsr-header">
			<div class="wsr-brand-lockup">
				<img src="<?php echo esc_url( $icon_url ); ?>" alt="<?php esc_attr_e( 'Website Security Radar', 'website-security-radar' ); ?>" class="wsr-logo" />
				<div class="wsr-brand-copy">
					<strong><?php esc_html_e( 'Security Radar', 'website-security-radar' ); ?></strong>
					<span><?php esc_html_e( 'Malware Scanner · File Monitor · Hardening', 'website-security-radar' ); ?></span>
				</div>
			</div>
			<div class="wsr-header-copy">
				<h1 class="wsr-page-title"><?php echo esc_html( $title ); ?></h1>
				<p class="wsr-header-tagline"><?php esc_html_e( 'Security intelligence for modern WordPress operations.', 'website-security-radar' ); ?></p>
			</div>
		</div>
		<?php
	}

	private function render_toggle_setting( string $key, string $label, string $description, array $settings ): void {
		?>
		<div class="wsr-setting-row">
			<div>
				<label class="wsr-setting-heading" for="wsr-setting-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label ); ?></label>
				<p class="description"><?php echo esc_html( $description ); ?></p>
			</div>
			<label class="wsr-toggle" for="wsr-setting-<?php echo esc_attr( $key ); ?>">
				<input id="wsr-setting-<?php echo esc_attr( $key ); ?>" type="checkbox" name="<?php echo esc_attr( WSR_Helpers::SETTINGS_OPTION ); ?>[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $settings[ $key ] ) ); ?> />
				<span class="wsr-toggle-ui" aria-hidden="true"></span>
				<span class="screen-reader-text"><?php echo esc_html( $label ); ?></span>
			</label>
		</div>
		<?php
	}

	private function render_issue_table( array $issues, bool $is_full_table = false ): void {
		if ( empty( $issues ) ) {
			echo '<p>' . esc_html__( 'No issues recorded yet.', 'website-security-radar' ) . '</p>';
			return;
		}
		?>
		<div class="wsr-table-wrap<?php echo $is_full_table ? ' wsr-table-wrap-full' : ''; ?>">
			<table class="widefat striped wsr-issues-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Type', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Severity', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'File / Path', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Issue', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Explanation', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Detected date', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'website-security-radar' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $issues as $issue ) : ?>
						<tr>
							<td><span class="wsr-type-pill"><?php echo esc_html( WSR_Helpers::get_type_label( (string) ( $issue['type'] ?? '' ) ) ); ?></span></td>
							<td><span class="<?php echo esc_attr( WSR_Helpers::severity_label_class( (string) $issue['severity'] ) ); ?>"><?php echo esc_html( ucfirst( (string) $issue['severity'] ) ); ?></span><?php if ( ! empty( $issue['confidence'] ) ) : ?><span class="wsr-confidence"><?php echo esc_html( ucfirst( (string) $issue['confidence'] ) ); ?></span><?php endif; ?></td>
							<td>
								<?php $display_path = (string) ( $issue['path'] ?? $issue['file'] ?? '' ); ?>
								<code class="wsr-path" title="<?php echo esc_attr( $display_path ); ?>"><?php echo esc_html( $display_path ); ?></code>
							</td>
							<td><?php echo esc_html( (string) $issue['issue'] ); ?></td>
							<td><?php echo esc_html( (string) $issue['explanation'] ); ?></td>
							<td><?php echo esc_html( WSR_Helpers::format_datetime( (string) $issue['detected_at'] ) ); ?></td>
							<td>
								<div class="wsr-table-actions">
									<a class="button button-small" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-results', array( 'issue' => $issue['id'] ) ) ); ?>"><?php esc_html_e( 'View details', 'website-security-radar' ); ?></a>
									<?php if ( $this->issue_has_change_details( $issue ) ) : ?>
										<a class="button button-small" href="<?php echo esc_url( $this->get_change_details_url( $issue ) ); ?>"><?php esc_html_e( 'View change details', 'website-security-radar' ); ?></a>
									<?php endif; ?>
									<?php if ( empty( $issue['reviewed'] ) ) : ?>
										<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wsr_mark_reviewed&issue=' . rawurlencode( (string) $issue['id'] ) ), WSR_Helpers::ADMIN_NONCE_ACTION ) ); ?>"><?php esc_html_e( 'Mark as reviewed', 'website-security-radar' ); ?></a>
									<?php endif; ?>
									<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wsr_ignore_path&path=' . rawurlencode( (string) $issue['path'] ) ), WSR_Helpers::ADMIN_NONCE_ACTION ) ); ?>"><?php esc_html_e( 'Ignore path', 'website-security-radar' ); ?></a>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	private function get_selected_issue( array $issues ): ?array {
		$issue_id = sanitize_text_field( wp_unslash( $_GET['issue'] ?? '' ) );

		if ( '' === $issue_id ) {
			return null;
		}

		foreach ( $issues as $issue ) {
			if ( $issue_id === ( $issue['id'] ?? '' ) ) {
				return $issue;
			}
		}

		return null;
	}

	private function get_selected_baseline( array $baselines ): ?array {
		$baseline_id = sanitize_key( wp_unslash( $_GET['baseline'] ?? '' ) );

		if ( '' === $baseline_id ) {
			return ! empty( $baselines[0] ) ? $baselines[0] : null;
		}

		foreach ( $baselines as $baseline ) {
			if ( $baseline_id === ( $baseline['id'] ?? '' ) ) {
				return $baseline;
			}
		}

		return null;
	}

	private function normalize_score_breakdown( array $score_breakdown ): array {
		$categories = array();

		foreach ( WSR_Helpers::get_score_breakdown_categories() as $key => $label ) {
			$current            = $score_breakdown['categories'][ $key ] ?? array();
			$categories[ $key ] = array(
				'label'           => $current['label'] ?? $label,
				'deduction'       => (int) ( $current['deduction'] ?? 0 ),
				'issue_count'     => (int) ( $current['issue_count'] ?? 0 ),
				'severity_counts' => wp_parse_args(
					is_array( $current['severity_counts'] ?? null ) ? $current['severity_counts'] : array(),
					array(
						'critical' => 0,
						'high'     => 0,
						'medium'   => 0,
						'low'      => 0,
					)
				),
			);
		}

		return array(
			'score'                => (int) ( $score_breakdown['score'] ?? 100 ),
			'total_deduction'      => (int) ( $score_breakdown['total_deduction'] ?? 0 ),
			'deduction_per_severity' => wp_parse_args(
				is_array( $score_breakdown['deduction_per_severity'] ?? null ) ? $score_breakdown['deduction_per_severity'] : array(),
				array(
					'critical' => 20,
					'high'     => 10,
					'medium'   => 5,
					'low'      => 2,
				)
			),
			'categories'           => $categories,
		);
	}

	private function find_issue_by_id( string $issue_id ): ?array {
		$results = $this->plugin->get_latest_results();

		foreach ( $results['issues'] ?? array() as $issue ) {
			if ( $issue_id === ( $issue['id'] ?? '' ) ) {
				return $issue;
			}
		}

		return null;
	}

	private function format_user_label( int $user_id ): string {
		if ( $user_id < 1 ) {
			return __( 'System', 'website-security-radar' );
		}

		$user = get_userdata( $user_id );

		if ( ! $user ) {
			return sprintf(
				/* translators: %d: user id. */
				__( 'User #%d', 'website-security-radar' ),
				$user_id
			);
		}

		return $user->display_name;
	}

	private function shorten_hash( string $hash ): string {
		$hash = sanitize_text_field( $hash );

		if ( strlen( $hash ) <= 16 ) {
			return $hash;
		}

		return substr( $hash, 0, 16 ) . '...';
	}

	private function format_baseline_scan_scope( array $scan_scope ): string {
		$labels = array(
			'scan_plugins'    => __( 'Plugins', 'website-security-radar' ),
			'scan_themes'     => __( 'Themes', 'website-security-radar' ),
			'scan_uploads'    => __( 'Uploads', 'website-security-radar' ),
			'scan_root_files' => __( 'Root files', 'website-security-radar' ),
		);
		$enabled = array();

		foreach ( $labels as $key => $label ) {
			if ( ! empty( $scan_scope[ $key ] ) ) {
				$enabled[] = $label;
			}
		}

		return empty( $enabled ) ? __( 'No scope metadata recorded', 'website-security-radar' ) : implode( ', ', $enabled );
	}

	private function format_baseline_extensions( array $extensions ): string {
		$items = array();

		foreach ( $extensions as $extension => $count ) {
			$label   = 'none' === $extension ? __( 'No extension', 'website-security-radar' ) : strtoupper( sanitize_text_field( (string) $extension ) );
			$items[] = sprintf( '%s (%s)', $label, number_format_i18n( (int) $count ) );
		}

		return implode( ', ', $items );
	}

	private function format_score_breakdown_severity_counts( array $severity_counts ): string {
		$parts = array();

		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $severity ) {
			$count = (int) ( $severity_counts[ $severity ] ?? 0 );

			if ( $count > 0 ) {
				$parts[] = sprintf( '%s: %d', ucfirst( $severity ), $count );
			}
		}

		return empty( $parts ) ? __( 'No counted issues in this category.', 'website-security-radar' ) : implode( ', ', $parts );
	}

	private function get_breakdown_category_severity( array $category ): string {
		$counts = is_array( $category['severity_counts'] ?? null ) ? $category['severity_counts'] : array();

		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $severity ) {
			if ( ! empty( $counts[ $severity ] ) ) {
				return $severity;
			}
		}

		return 'info';
	}

	private function get_score_breakdown_recommendation( string $category_key, array $category ): string {
		if ( empty( $category['issue_count'] ) ) {
			return __( 'No action needed in this category right now.', 'website-security-radar' );
		}

		switch ( $category_key ) {
			case 'malware':
				return __( 'Investigate malware indicators first and confirm affected files against a trusted source.', 'website-security-radar' );
			case 'suspicious_patterns':
				return __( 'Review flagged patterns in context and confirm whether they belong to trusted plugin or theme code.', 'website-security-radar' );
			case 'file_changes':
				return __( 'Compare changed files against your deployment, version control, or known-good backup before accepting them.', 'website-security-radar' );
			case 'hardening':
				return __( 'Address configuration and update findings to reduce overall attack surface.', 'website-security-radar' );
			case 'uploads_risk':
				return __( 'Audit executable or suspicious uploads immediately and prevent unsafe file execution inside uploads.', 'website-security-radar' );
			default:
				return __( 'Review this category and confirm whether the findings are expected.', 'website-security-radar' );
		}
	}

	private function get_selected_change_detail( array $issues ): ?array {
		$issue_id = sanitize_text_field( wp_unslash( $_GET['change_details'] ?? '' ) );
		$nonce    = sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) );

		if ( '' === $issue_id || '' === $nonce ) {
			return null;
		}

		if ( ! wp_verify_nonce( $nonce, 'wsr_view_change_details_' . $issue_id ) ) {
			return null;
		}

		foreach ( $issues as $issue ) {
			if ( $issue_id !== ( $issue['id'] ?? '' ) ) {
				continue;
			}

			if ( ! $this->issue_has_change_details( $issue ) ) {
				return array(
					'available' => false,
					'issue'     => $issue,
					'details'   => array(),
				);
			}

			return array(
				'available' => true,
				'issue'     => $issue,
				'details'   => $this->normalize_change_details( $issue ),
			);
		}

		return null;
	}

	private function get_dashboard_trend_hint(): string {
		return __( 'Compared to last scan: unavailable', 'website-security-radar' );
	}

	private function get_dashboard_stat_cards( array $summary ): array {
		return array(
			array(
				'label'  => __( 'Files scanned', 'website-security-radar' ),
				'value'  => (int) ( $summary['total_scanned_files'] ?? 0 ),
				'helper' => __( 'Coverage across monitored WordPress paths.', 'website-security-radar' ),
				'icon'   => 'dashicons-search',
				'tone'   => 'neutral',
			),
			array(
				'label'  => __( 'Suspicious files', 'website-security-radar' ),
				'value'  => (int) ( $summary['suspicious_files'] ?? 0 ),
				'helper' => __( 'Potential malware, risky patterns, or unexpected file changes.', 'website-security-radar' ),
				'icon'   => 'dashicons-warning',
				'tone'   => ! empty( $summary['suspicious_files'] ) ? 'warning' : 'safe',
			),
			array(
				'label'  => __( 'Critical issues', 'website-security-radar' ),
				'value'  => (int) ( $summary['critical_issues'] ?? 0 ),
				'helper' => __( 'Immediate review recommended before the next deployment or login cycle.', 'website-security-radar' ),
				'icon'   => 'dashicons-shield-alt',
				'tone'   => ! empty( $summary['critical_issues'] ) ? 'critical' : 'safe',
			),
			array(
				'label'  => __( 'Hardening warnings', 'website-security-radar' ),
				'value'  => (int) ( $summary['hardening_warnings'] ?? 0 ),
				'helper' => __( 'Configuration gaps that weaken the overall site posture.', 'website-security-radar' ),
				'icon'   => 'dashicons-lock',
				'tone'   => ! empty( $summary['hardening_warnings'] ) ? 'warning' : 'safe',
			),
		);
	}

	private function get_dashboard_scan_summary( array $results, array $active_baseline, array $settings ): array {
		$summary = $results['summary'] ?? array();

		return array(
			array(
				'label' => __( 'Latest scan', 'website-security-radar' ),
				'value' => WSR_Helpers::format_datetime( $results['scanned_at'] ?? '' ),
			),
			array(
				'label' => __( 'Risk level', 'website-security-radar' ),
				'value' => (string) ( $results['risk_level'] ?? __( 'Safe', 'website-security-radar' ) ),
			),
			array(
				'label' => __( 'Active baseline', 'website-security-radar' ),
				'value' => ! empty( $active_baseline['label'] ) ? (string) $active_baseline['label'] : __( 'Not configured', 'website-security-radar' ),
			),
			array(
				'label' => __( 'Scheduled scans', 'website-security-radar' ),
				'value' => ! empty( $settings['enable_scheduled_scan'] ) ? __( 'Enabled', 'website-security-radar' ) : __( 'Disabled', 'website-security-radar' ),
			),
			array(
				'label' => __( 'Deduction points', 'website-security-radar' ),
				'value' => sprintf( __( '%d points', 'website-security-radar' ), (int) ( $results['score_breakdown']['total_deduction'] ?? 0 ) ),
			),
			array(
				'label' => __( 'Ignored findings', 'website-security-radar' ),
				'value' => sprintf( __( '%d items', 'website-security-radar' ), (int) ( $summary['ignored_findings'] ?? 0 ) ),
			),
		);
	}

	private function get_recommendations( array $results ): array {
		$recommendations = array();
		$summary         = $results['summary'] ?? array();
		$top_issue       = $this->get_top_issue( $results['issues'] ?? array() );
		$settings        = WSR_Helpers::get_settings();

		if ( ! empty( $summary['critical_issues'] ) ) {
			$recommendations[] = array(
				'icon'        => '!',
				'tone'        => 'critical',
				'title'       => __( 'Review critical issues', 'website-security-radar' ),
				'description' => __( 'Triage the highest-severity findings first and confirm whether the affected files are expected.', 'website-security-radar' ),
			);
		}

		if ( $top_issue ) {
			$recommendations[] = array(
				'icon'        => '>',
				'tone'        => 'warning',
				'title'       => __( 'Prioritize the top finding', 'website-security-radar' ),
				'description' => sprintf(
					/* translators: %s: issue label. */
					__( 'Start with: %s.', 'website-security-radar' ),
					$top_issue['issue']
				),
			);
		}

		if ( ! empty( $summary['modified_files'] ) ) {
			$recommendations[] = array(
				'icon'        => '~',
				'tone'        => 'warning',
				'title'       => __( 'Verify modified files', 'website-security-radar' ),
				'description' => __( 'Compare changed files against your deployment source or backup before marking them as trusted.', 'website-security-radar' ),
			);
		}

		if ( empty( $results['baseline']['has_baseline'] ?? false ) ) {
			$recommendations[] = array(
				'icon'        => '+',
				'tone'        => 'warning',
				'title'       => __( 'Create a baseline', 'website-security-radar' ),
				'description' => __( 'Save a clean snapshot after validation so future scans can separate expected changes from real drift.', 'website-security-radar' ),
			);
		}

		if ( empty( $settings['enable_scheduled_scan'] ) ) {
			$recommendations[] = array(
				'icon'        => '*',
				'tone'        => 'warning',
				'title'       => __( 'Enable scheduled scans', 'website-security-radar' ),
				'description' => __( 'Automatic daily scans keep your monitoring current between manual reviews.', 'website-security-radar' ),
			);
		}

		if ( empty( $recommendations ) ) {
			$recommendations[] = array(
				'icon'        => 'o',
				'tone'        => 'safe',
				'title'       => __( 'Monitoring looks healthy', 'website-security-radar' ),
				'description' => __( 'Scheduled scans are enabled and no urgent follow-up actions are currently required.', 'website-security-radar' ),
			);
		}

		return array_slice( $recommendations, 0, 4 );
	}

	private function render_top_issues_list( array $issues ): void {
		$top_issues = $this->get_top_five_issues( $issues );

		if ( empty( $top_issues ) ) {
			?>
			<div class="wsr-empty-state">
				<span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
				<div>
					<strong><?php esc_html_e( 'No urgent issues detected', 'website-security-radar' ); ?></strong>
					<p><?php esc_html_e( 'Critical and high-priority findings will appear here after future scans.', 'website-security-radar' ); ?></p>
				</div>
			</div>
			<?php
			return;
		}
		?>
		<div class="wsr-top-issues">
			<?php foreach ( $top_issues as $issue ) : ?>
				<?php
				$display_path = WSR_Helpers::get_safe_display_path( (string) ( $issue['path'] ?? $issue['file'] ?? '' ) );
				$detail_id    = 'wsr-issue-detail-' . sanitize_html_class( (string) ( $issue['id'] ?? md5( $display_path ) ) );
				?>
				<div class="wsr-top-issue">
					<div class="wsr-top-issue-main">
						<div class="wsr-top-issue-head">
							<span class="<?php echo esc_attr( WSR_Helpers::severity_label_class( (string) $issue['severity'] ) ); ?>" title="<?php echo esc_attr( ucfirst( (string) $issue['severity'] ) . ' severity' ); ?>"><?php echo esc_html( ucfirst( (string) $issue['severity'] ) ); ?></span>
							<span class="wsr-type-pill"><?php echo esc_html( WSR_Helpers::get_type_label( (string) ( $issue['type'] ?? '' ) ) ); ?></span>
						</div>
						<strong><?php echo esc_html( (string) $issue['issue'] ); ?></strong>
						<code class="wsr-path" title="<?php echo esc_attr( $display_path ); ?>"><?php echo esc_html( $display_path ); ?></code>
						<p><?php echo esc_html( (string) $issue['explanation'] ); ?></p>
						<div id="<?php echo esc_attr( $detail_id ); ?>" class="wsr-top-issue-detail" hidden>
							<?php if ( ! empty( $issue['confidence'] ) ) : ?>
								<p><?php echo esc_html( sprintf( __( 'Confidence: %s', 'website-security-radar' ), ucfirst( (string) $issue['confidence'] ) ) ); ?></p>
							<?php endif; ?>
							<?php if ( ! empty( $issue['detected_at'] ) ) : ?>
								<p><?php echo esc_html( sprintf( __( 'Detected: %s', 'website-security-radar' ), WSR_Helpers::format_datetime( (string) $issue['detected_at'] ) ) ); ?></p>
							<?php endif; ?>
							<?php if ( isset( $issue['score'] ) ) : ?>
								<p><?php echo esc_html( sprintf( __( 'Signal score: %d', 'website-security-radar' ), (int) $issue['score'] ) ); ?></p>
							<?php endif; ?>
						</div>
					</div>
					<div class="wsr-top-issue-actions">
						<button type="button" class="button button-secondary button-small wsr-issue-toggle" data-wsr-toggle-target="<?php echo esc_attr( $detail_id ); ?>" aria-expanded="false"><?php esc_html_e( 'Details', 'website-security-radar' ); ?></button>
						<a class="button button-small" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-results', array( 'issue' => $issue['id'] ) ) ); ?>"><?php esc_html_e( 'View', 'website-security-radar' ); ?></a>
					</div>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private function render_change_details_panel( array $selected_change_detail ): void {
		$issue      = $selected_change_detail['issue'] ?? array();
		$is_ready   = ! empty( $selected_change_detail['available'] );
		$details    = $selected_change_detail['details'] ?? array();
		$close_url  = WSR_Helpers::admin_url( 'website-security-radar-results', $this->get_results_query_args() );
		?>
		<div class="wsr-card wsr-change-details-panel" id="wsr-change-details-panel" tabindex="-1">
			<div class="wsr-section-head">
				<div>
					<h2><?php esc_html_e( 'File change details', 'website-security-radar' ); ?></h2>
					<p><?php echo esc_html( (string) ( $issue['issue'] ?? __( 'Modified file detected', 'website-security-radar' ) ) ); ?></p>
				</div>
				<a class="button button-secondary" href="<?php echo esc_url( $close_url ); ?>"><?php esc_html_e( 'Close', 'website-security-radar' ); ?></a>
			</div>
			<?php if ( $is_ready ) : ?>
				<div class="wsr-change-meta-grid">
					<?php $this->render_change_detail_item( __( 'Relative path', 'website-security-radar' ), $details['relative_path'] ?? '' ); ?>
					<?php $this->render_change_detail_item( __( 'File extension', 'website-security-radar' ), $details['extension'] ?? '' ); ?>
					<?php $this->render_change_detail_item( __( 'Old hash', 'website-security-radar' ), $details['old']['hash'] ?? '' ); ?>
					<?php $this->render_change_detail_item( __( 'New hash', 'website-security-radar' ), $details['new']['hash'] ?? '' ); ?>
					<?php $this->render_change_detail_item( __( 'Old modified time', 'website-security-radar' ), $this->format_file_timestamp( $details['old']['modified'] ?? 0 ) ); ?>
					<?php $this->render_change_detail_item( __( 'New modified time', 'website-security-radar' ), $this->format_file_timestamp( $details['new']['modified'] ?? 0 ) ); ?>
					<?php $this->render_change_detail_item( __( 'Old size', 'website-security-radar' ), $this->format_file_size( $details['old']['size'] ?? null ) ); ?>
					<?php $this->render_change_detail_item( __( 'New size', 'website-security-radar' ), $this->format_file_size( $details['new']['size'] ?? null ) ); ?>
				</div>
				<div class="wsr-change-diff-note">
					<strong><?php esc_html_e( 'Content diff', 'website-security-radar' ); ?>:</strong>
					<?php echo esc_html( ! empty( $details['content_diff']['enabled'] ) ? __( 'Available', 'website-security-radar' ) : __( 'Disabled by default. Only metadata is stored in the baseline.', 'website-security-radar' ) ); ?>
				</div>
			<?php else : ?>
				<p><?php esc_html_e( 'Change details are not available for this result. Older scan results may not include baseline metadata for modified files. Run a new scan to populate these fields.', 'website-security-radar' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_change_detail_item( string $label, string $value ): void {
		?>
		<div class="wsr-change-meta-item">
			<span class="wsr-change-meta-label"><?php echo esc_html( $label ); ?></span>
			<code class="wsr-change-meta-value"><?php echo esc_html( '' !== $value ? $value : __( 'Not available', 'website-security-radar' ) ); ?></code>
		</div>
		<?php
	}

	private function render_issue_group_cards( array $groups ): void {
		$current_type = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		?>
		<div class="wsr-grid wsr-grid-group-summary">
			<?php foreach ( $groups as $group ) : ?>
				<?php
				$is_active = strtolower( $current_type ) === strtolower( (string) $group['filter_value'] );
				$card_url  = WSR_Helpers::admin_url(
					'website-security-radar-results',
					array_merge( $this->get_results_query_args( true ), array( 'type' => $group['filter_value'] ) )
				);

				if ( $is_active ) {
					$reset_args = $this->get_results_query_args( true );
					unset( $reset_args['type'] );
					$card_url = WSR_Helpers::admin_url( 'website-security-radar-results', $reset_args );
				}
				?>
				<a class="wsr-card wsr-group-card<?php echo $is_active ? ' is-active' : ''; ?>" href="<?php echo esc_url( $card_url ); ?>" data-wsr-card-url="<?php echo esc_url( $card_url ); ?>">
					<div class="wsr-group-card-head">
						<span class="wsr-group-card-title"><?php echo esc_html( $group['label'] ); ?></span>
						<?php if ( ! empty( $group['highest_severity'] ) ) : ?>
							<span class="<?php echo esc_attr( WSR_Helpers::severity_label_class( (string) $group['highest_severity'] ) ); ?>"><?php echo esc_html( ucfirst( (string) $group['highest_severity'] ) ); ?></span>
						<?php else : ?>
							<span class="wsr-badge wsr-badge-low"><?php esc_html_e( 'None', 'website-security-radar' ); ?></span>
						<?php endif; ?>
					</div>
					<div class="wsr-group-card-count"><?php echo esc_html( (string) ( $group['count'] ?? 0 ) ); ?></div>
					<p class="wsr-group-card-copy"><?php echo esc_html( (string) ( $group['description'] ?? '' ) ); ?></p>
				</a>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private function render_issue_filters( array $issues ): void {
		$selected_severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$selected_type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		$selected_path     = sanitize_text_field( wp_unslash( $_GET['path_search'] ?? '' ) );
		$selected_from     = $this->sanitize_date_input( wp_unslash( $_GET['date_from'] ?? '' ) );
		$selected_to       = $this->sanitize_date_input( wp_unslash( $_GET['date_to'] ?? '' ) );
		$selected_status   = sanitize_text_field( wp_unslash( $_GET['review_status'] ?? '' ) );
		$type_options      = $this->get_issue_type_options( $issues );
		?>
		<form method="get" class="wsr-filter-bar" id="wsr-filter-form">
			<input type="hidden" name="page" value="website-security-radar-results" />
			<div class="wsr-filter-field">
				<label for="wsr-filter-severity"><?php esc_html_e( 'Severity', 'website-security-radar' ); ?></label>
				<select id="wsr-filter-severity" name="severity">
					<option value=""><?php esc_html_e( 'All severities', 'website-security-radar' ); ?></option>
					<?php foreach ( array( 'critical', 'high', 'medium', 'low' ) as $severity ) : ?>
						<option value="<?php echo esc_attr( $severity ); ?>" <?php selected( $selected_severity, $severity ); ?>><?php echo esc_html( ucfirst( $severity ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<div class="wsr-filter-field">
				<label for="wsr-filter-type"><?php esc_html_e( 'Type', 'website-security-radar' ); ?></label>
				<select id="wsr-filter-type" name="type">
					<option value=""><?php esc_html_e( 'All types', 'website-security-radar' ); ?></option>
					<?php foreach ( $type_options as $type ) : ?>
						<option value="<?php echo esc_attr( $type ); ?>" <?php selected( $selected_type, $type ); ?>><?php echo esc_html( WSR_Helpers::get_type_label( $type ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<div class="wsr-filter-field">
				<label for="wsr-filter-path"><?php esc_html_e( 'Path search', 'website-security-radar' ); ?></label>
				<input id="wsr-filter-path" type="search" name="path_search" value="<?php echo esc_attr( $selected_path ); ?>" placeholder="<?php esc_attr_e( 'Search file paths', 'website-security-radar' ); ?>" />
			</div>
			<div class="wsr-filter-field">
				<label for="wsr-filter-date-from"><?php esc_html_e( 'Date from', 'website-security-radar' ); ?></label>
				<input id="wsr-filter-date-from" type="date" name="date_from" value="<?php echo esc_attr( $selected_from ); ?>" />
			</div>
			<div class="wsr-filter-field">
				<label for="wsr-filter-date-to"><?php esc_html_e( 'Date to', 'website-security-radar' ); ?></label>
				<input id="wsr-filter-date-to" type="date" name="date_to" value="<?php echo esc_attr( $selected_to ); ?>" />
			</div>
			<div class="wsr-filter-field">
				<label for="wsr-filter-review-status"><?php esc_html_e( 'Reviewed status', 'website-security-radar' ); ?></label>
				<select id="wsr-filter-review-status" name="review_status">
					<option value=""><?php esc_html_e( 'All statuses', 'website-security-radar' ); ?></option>
					<option value="active" <?php selected( $selected_status, 'active' ); ?>><?php esc_html_e( 'Active', 'website-security-radar' ); ?></option>
					<option value="reviewed" <?php selected( $selected_status, 'reviewed' ); ?>><?php esc_html_e( 'Reviewed', 'website-security-radar' ); ?></option>
					<option value="ignored" <?php selected( $selected_status, 'ignored' ); ?>><?php esc_html_e( 'Ignored', 'website-security-radar' ); ?></option>
				</select>
			</div>
			<div class="wsr-filter-actions">
				<button type="submit" class="button"><?php esc_html_e( 'Filter', 'website-security-radar' ); ?></button>
				<a class="button button-link" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-results' ) ); ?>" id="wsr-reset-filters"><?php esc_html_e( 'Reset filters', 'website-security-radar' ); ?></a>
			</div>
		</form>
		<?php
	}

	private function render_issue_pagination( int $current_page, int $total_pages ): void {
		if ( $total_pages < 2 ) {
			return;
		}

		$page_url = remove_query_arg( 'paged', WSR_Helpers::admin_url( 'website-security-radar-results', $this->get_results_query_args() ) );
		echo '<div class="tablenav"><div class="tablenav-pages">';
		echo wp_kses_post(
			paginate_links(
				array(
					'base'      => add_query_arg( 'paged', '%#%', $page_url ),
					'format'    => '',
					'current'   => $current_page,
					'total'     => $total_pages,
					'prev_text' => __( '&laquo;', 'website-security-radar' ),
					'next_text' => __( '&raquo;', 'website-security-radar' ),
				)
			)
		);
		echo '</div></div>';
	}

	private function render_timeline_filters( array $events ): void {
		$selected_severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$selected_type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		$type_options      = $this->get_timeline_type_options( $events );
		?>
		<form method="get" class="wsr-filter-bar">
			<input type="hidden" name="page" value="website-security-radar-timeline" />
			<div class="wsr-filter-field">
				<label for="wsr-timeline-filter-type"><?php esc_html_e( 'Event type', 'website-security-radar' ); ?></label>
				<select id="wsr-timeline-filter-type" name="type">
					<option value=""><?php esc_html_e( 'All event types', 'website-security-radar' ); ?></option>
					<?php foreach ( $type_options as $type ) : ?>
						<option value="<?php echo esc_attr( $type ); ?>" <?php selected( $selected_type, $type ); ?>><?php echo esc_html( WSR_Helpers::get_timeline_event_type_label( $type ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<div class="wsr-filter-field">
				<label for="wsr-timeline-filter-severity"><?php esc_html_e( 'Severity', 'website-security-radar' ); ?></label>
				<select id="wsr-timeline-filter-severity" name="severity">
					<option value=""><?php esc_html_e( 'All severities', 'website-security-radar' ); ?></option>
					<?php foreach ( array( 'critical', 'high', 'medium', 'low', 'info' ) as $severity ) : ?>
						<option value="<?php echo esc_attr( $severity ); ?>" <?php selected( $selected_severity, $severity ); ?>><?php echo esc_html( ucfirst( $severity ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<div class="wsr-filter-actions">
				<button type="submit" class="button"><?php esc_html_e( 'Filter', 'website-security-radar' ); ?></button>
				<a class="button button-link" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-timeline' ) ); ?>"><?php esc_html_e( 'Reset filters', 'website-security-radar' ); ?></a>
			</div>
		</form>
		<?php
	}

	private function render_timeline_table( array $events ): void {
		if ( empty( $events ) ) {
			echo '<p>' . esc_html__( 'No timeline events recorded yet.', 'website-security-radar' ) . '</p>';
			return;
		}
		?>
		<div class="wsr-table-wrap wsr-table-wrap-full">
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Event', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Severity', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Message', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Relative path', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Actor', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Timestamp', 'website-security-radar' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $events as $event ) : ?>
						<tr>
							<td><span class="wsr-type-pill"><?php echo esc_html( WSR_Helpers::get_timeline_event_type_label( (string) $event['type'] ) ); ?></span></td>
							<td><span class="<?php echo esc_attr( WSR_Helpers::severity_label_class( (string) $event['severity'] ) ); ?>"><?php echo esc_html( ucfirst( (string) $event['severity'] ) ); ?></span></td>
							<td><?php echo esc_html( (string) $event['message'] ); ?></td>
							<td>
								<?php if ( ! empty( $event['relative_path'] ) ) : ?>
									<code class="wsr-path"><?php echo esc_html( (string) $event['relative_path'] ); ?></code>
								<?php else : ?>
									<?php esc_html_e( 'N/A', 'website-security-radar' ); ?>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $this->get_timeline_actor_label( $event ) ); ?></td>
							<td><?php echo esc_html( WSR_Helpers::format_datetime( (string) $event['timestamp'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	private function render_baselines_table( array $baselines, array $active_baseline ): void {
		if ( empty( $baselines ) ) {
			echo '<p>' . esc_html__( 'No baselines recorded yet.', 'website-security-radar' ) . '</p>';
			return;
		}
		?>
		<div class="wsr-table-wrap wsr-table-wrap-full">
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Label', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Created', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Created by', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'File count', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Hash summary', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Status', 'website-security-radar' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'website-security-radar' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $baselines as $baseline ) : ?>
						<?php $is_active = ( $active_baseline['id'] ?? '' ) === ( $baseline['id'] ?? '' ); ?>
						<tr>
							<td><?php echo esc_html( (string) ( $baseline['label'] ?? '' ) ); ?></td>
							<td><?php echo esc_html( WSR_Helpers::format_datetime( (string) ( $baseline['created_at'] ?? '' ) ) ); ?></td>
							<td><?php echo esc_html( $this->format_user_label( (int) ( $baseline['created_by_user_id'] ?? 0 ) ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( (int) ( $baseline['file_count'] ?? 0 ) ) ); ?></td>
							<td><code><?php echo esc_html( $this->shorten_hash( (string) ( $baseline['hash_summary'] ?? '' ) ) ); ?></code></td>
							<td><?php echo $is_active ? esc_html__( 'Active', 'website-security-radar' ) : esc_html__( 'Stored', 'website-security-radar' ); ?></td>
							<td>
								<div class="wsr-table-actions">
									<a class="button button-small" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-baselines', array( 'baseline' => $baseline['id'] ) ) ); ?>"><?php esc_html_e( 'View details', 'website-security-radar' ); ?></a>
									<?php if ( ! $is_active ) : ?>
										<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wsr_set_active_baseline&baseline=' . rawurlencode( (string) $baseline['id'] ) ), WSR_Helpers::ADMIN_NONCE_ACTION ) ); ?>"><?php esc_html_e( 'Set active', 'website-security-radar' ); ?></a>
									<?php endif; ?>
									<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wsr_delete_baseline&baseline=' . rawurlencode( (string) $baseline['id'] ) ), WSR_Helpers::ADMIN_NONCE_ACTION ) ); ?>" onclick="return window.confirm('<?php echo esc_js( __( 'Delete this baseline?', 'website-security-radar' ) ); ?>');"><?php esc_html_e( 'Delete', 'website-security-radar' ); ?></a>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	private function render_baseline_details_panel( array $baseline, array $active_baseline ): void {
		$metadata = is_array( $baseline['metadata'] ?? null ) ? $baseline['metadata'] : array();
		?>
		<div class="wsr-card">
			<h2><?php esc_html_e( 'Baseline Details', 'website-security-radar' ); ?></h2>
			<p><strong><?php esc_html_e( 'Label:', 'website-security-radar' ); ?></strong> <?php echo esc_html( (string) ( $baseline['label'] ?? '' ) ); ?></p>
			<p><strong><?php esc_html_e( 'Status:', 'website-security-radar' ); ?></strong> <?php echo esc_html( ( $active_baseline['id'] ?? '' ) === ( $baseline['id'] ?? '' ) ? __( 'Active', 'website-security-radar' ) : __( 'Stored', 'website-security-radar' ) ); ?></p>
			<p><strong><?php esc_html_e( 'Created:', 'website-security-radar' ); ?></strong> <?php echo esc_html( WSR_Helpers::format_datetime( (string) ( $baseline['created_at'] ?? '' ) ) ); ?></p>
			<p><strong><?php esc_html_e( 'Created by:', 'website-security-radar' ); ?></strong> <?php echo esc_html( $this->format_user_label( (int) ( $baseline['created_by_user_id'] ?? 0 ) ) ); ?></p>
			<p><strong><?php esc_html_e( 'File count:', 'website-security-radar' ); ?></strong> <?php echo esc_html( number_format_i18n( (int) ( $baseline['file_count'] ?? 0 ) ) ); ?></p>
			<p><strong><?php esc_html_e( 'Hash summary:', 'website-security-radar' ); ?></strong> <code><?php echo esc_html( (string) ( $baseline['hash_summary'] ?? '' ) ); ?></code></p>
			<?php if ( ! empty( $metadata['scan_scope'] ) && is_array( $metadata['scan_scope'] ) ) : ?>
				<p><strong><?php esc_html_e( 'Scan scope:', 'website-security-radar' ); ?></strong> <?php echo esc_html( $this->format_baseline_scan_scope( $metadata['scan_scope'] ) ); ?></p>
			<?php endif; ?>
			<?php if ( isset( $metadata['max_file_size'] ) ) : ?>
				<p><strong><?php esc_html_e( 'Max file size:', 'website-security-radar' ); ?></strong> <?php echo esc_html( number_format_i18n( (int) $metadata['max_file_size'] ) ); ?></p>
			<?php endif; ?>
			<?php if ( ! empty( $metadata['extensions'] ) && is_array( $metadata['extensions'] ) ) : ?>
				<p><strong><?php esc_html_e( 'Top file extensions:', 'website-security-radar' ); ?></strong> <?php echo esc_html( $this->format_baseline_extensions( $metadata['extensions'] ) ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_score_breakdown_list( array $score_breakdown ): void {
		$categories = $score_breakdown['categories'] ?? array();

		if ( empty( $categories ) || ! is_array( $categories ) ) {
			echo '<p>' . esc_html__( 'No score deductions recorded for the latest scan.', 'website-security-radar' ) . '</p>';
			return;
		}
		?>
		<div class="wsr-top-issues">
			<?php foreach ( $categories as $key => $category ) : ?>
				<div class="wsr-top-issue">
					<div class="wsr-top-issue-main">
						<div class="wsr-top-issue-head">
							<span class="wsr-type-pill"><?php echo esc_html( (string) ( $category['label'] ?? $key ) ); ?></span>
							<span class="<?php echo esc_attr( WSR_Helpers::severity_label_class( $this->get_breakdown_category_severity( $category ) ) ); ?>"><?php echo esc_html( sprintf( __( '-%d points', 'website-security-radar' ), (int) ( $category['deduction'] ?? 0 ) ) ); ?></span>
						</div>
						<strong><?php echo esc_html( sprintf( __( '%d counted issue(s)', 'website-security-radar' ), (int) ( $category['issue_count'] ?? 0 ) ) ); ?></strong>
						<p><?php echo esc_html( $this->format_score_breakdown_severity_counts( $category['severity_counts'] ?? array() ) ); ?></p>
						<p><?php echo esc_html( $this->get_score_breakdown_recommendation( (string) $key, $category ) ); ?></p>
					</div>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private function render_timeline_pagination( int $current_page, int $total_pages ): void {
		if ( $total_pages < 2 ) {
			return;
		}

		$page_url = remove_query_arg( 'paged', WSR_Helpers::admin_url( 'website-security-radar-timeline', $this->get_timeline_query_args() ) );
		echo '<div class="tablenav"><div class="tablenav-pages">';
		echo wp_kses_post(
			paginate_links(
				array(
					'base'      => add_query_arg( 'paged', '%#%', $page_url ),
					'format'    => '',
					'current'   => $current_page,
					'total'     => $total_pages,
					'prev_text' => __( '&laquo;', 'website-security-radar' ),
					'next_text' => __( '&raquo;', 'website-security-radar' ),
				)
			)
		);
		echo '</div></div>';
	}

	private function get_filtered_issues( array $issues ): array {
		$selected_severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$selected_type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		$selected_path     = sanitize_text_field( wp_unslash( $_GET['path_search'] ?? '' ) );
		$selected_from     = $this->sanitize_date_input( wp_unslash( $_GET['date_from'] ?? '' ) );
		$selected_to       = $this->sanitize_date_input( wp_unslash( $_GET['date_to'] ?? '' ) );
		$selected_status   = sanitize_text_field( wp_unslash( $_GET['review_status'] ?? '' ) );

		return array_values(
			array_filter(
				$issues,
				function ( array $issue ) use ( $selected_severity, $selected_type, $selected_path, $selected_from, $selected_to, $selected_status ): bool {
					if ( '' !== $selected_severity && ( $issue['severity'] ?? '' ) !== $selected_severity ) {
						return false;
					}

					if ( '' !== $selected_type && ! $this->issue_matches_group_filter( $issue, $selected_type ) ) {
						return false;
					}

					if ( '' !== $selected_path && ! $this->issue_matches_path_search( $issue, $selected_path ) ) {
						return false;
					}

					if ( ! $this->issue_matches_date_range( $issue, $selected_from, $selected_to ) ) {
						return false;
					}

					if ( '' !== $selected_status && ! $this->issue_matches_review_status( $issue, $selected_status ) ) {
						return false;
					}

					return true;
				}
			)
		);
	}

	private function get_filtered_timeline_events( array $events ): array {
		$selected_severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$selected_type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );

		return array_values(
			array_filter(
				$events,
				static function ( array $event ) use ( $selected_severity, $selected_type ): bool {
					if ( '' !== $selected_severity && ( $event['severity'] ?? '' ) !== $selected_severity ) {
						return false;
					}

					if ( '' !== $selected_type && ( $event['type'] ?? '' ) !== $selected_type ) {
						return false;
					}

					return true;
				}
			)
		);
	}

	private function get_paginated_issues( array $issues ): array {
		$per_page     = 10;
		$total_items  = count( $issues );
		$total_pages  = max( 1, (int) ceil( $total_items / $per_page ) );
		$current_page = max( 1, absint( $_GET['paged'] ?? 1 ) );
		$current_page = min( $current_page, $total_pages );
		$offset       = ( $current_page - 1 ) * $per_page;

		return array(
			'items'        => array_slice( $issues, $offset, $per_page ),
			'current_page' => $current_page,
			'total_pages'  => $total_pages,
		);
	}

	private function get_paginated_timeline_events( array $events ): array {
		$per_page     = 20;
		$total_items  = count( $events );
		$total_pages  = max( 1, (int) ceil( $total_items / $per_page ) );
		$current_page = max( 1, absint( $_GET['paged'] ?? 1 ) );
		$current_page = min( $current_page, $total_pages );
		$offset       = ( $current_page - 1 ) * $per_page;

		return array(
			'items'        => array_slice( $events, $offset, $per_page ),
			'current_page' => $current_page,
			'total_pages'  => $total_pages,
		);
	}

	private function get_top_issue( array $issues, string $severity = '' ): ?array {
		$sorted = $this->sort_issues_by_priority( $issues );

		foreach ( $sorted as $issue ) {
			if ( '' === $severity || $severity === ( $issue['severity'] ?? '' ) ) {
				return $issue;
			}
		}

		return null;
	}

	private function get_top_five_issues( array $issues ): array {
		$sorted = $this->sort_issues_by_priority( $issues );
		$top    = array();

		foreach ( $sorted as $issue ) {
			if ( in_array( $issue['severity'] ?? '', array( 'critical', 'high' ), true ) ) {
				$top[] = $issue;
			}

			if ( count( $top ) >= 5 ) {
				break;
			}
		}

		return $top;
	}

	private function sort_issues_by_priority( array $issues ): array {
		$order = array(
			'critical' => 4,
			'high'     => 3,
			'medium'   => 2,
			'low'      => 1,
		);

		usort(
			$issues,
			static function ( array $left, array $right ) use ( $order ): int {
				$left_score  = $order[ $left['severity'] ?? 'low' ] ?? 0;
				$right_score = $order[ $right['severity'] ?? 'low' ] ?? 0;

				if ( $left_score === $right_score ) {
					return strcmp( (string) ( $right['detected_at'] ?? '' ), (string) ( $left['detected_at'] ?? '' ) );
				}

				return $right_score <=> $left_score;
			}
		);

		return $issues;
	}

	private function get_issue_type_options( array $issues ): array {
		return array(
			'malware',
			'suspicious pattern',
			'potential risk',
			'file change',
			'hardening',
		);
	}

	private function get_results_query_args( bool $reset_paged = false ): array {
		$args = array();

		$severity      = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$type          = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		$path_search   = sanitize_text_field( wp_unslash( $_GET['path_search'] ?? '' ) );
		$date_from     = $this->sanitize_date_input( wp_unslash( $_GET['date_from'] ?? '' ) );
		$date_to       = $this->sanitize_date_input( wp_unslash( $_GET['date_to'] ?? '' ) );
		$review_status = sanitize_text_field( wp_unslash( $_GET['review_status'] ?? '' ) );
		$paged         = absint( $_GET['paged'] ?? 0 );

		if ( '' !== $severity ) {
			$args['severity'] = $severity;
		}

		if ( '' !== $type ) {
			$args['type'] = $type;
		}

		if ( '' !== $path_search ) {
			$args['path_search'] = $path_search;
		}

		if ( '' !== $date_from ) {
			$args['date_from'] = $date_from;
		}

		if ( '' !== $date_to ) {
			$args['date_to'] = $date_to;
		}

		if ( in_array( $review_status, array( 'active', 'reviewed', 'ignored' ), true ) ) {
			$args['review_status'] = $review_status;
		}

		if ( ! $reset_paged && $paged > 1 ) {
			$args['paged'] = $paged;
		}

		return $args;
	}

	private function get_timeline_query_args( bool $reset_paged = false ): array {
		$args     = array();
		$severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		$paged    = absint( $_GET['paged'] ?? 0 );

		if ( '' !== $severity ) {
			$args['severity'] = $severity;
		}

		if ( '' !== $type ) {
			$args['type'] = $type;
		}

		if ( ! $reset_paged && $paged > 1 ) {
			$args['paged'] = $paged;
		}

		return $args;
	}

	private function get_issue_groups( array $issues ): array {
		$definitions = $this->get_issue_group_definitions();
		$groups      = array();

		foreach ( $definitions as $group_key => $definition ) {
			$matching_issues = array_values(
				array_filter(
					$issues,
					function ( array $issue ) use ( $group_key ): bool {
						return $this->issue_matches_group_filter( $issue, $group_key );
					}
				)
			);

			$groups[] = array(
				'key'              => $group_key,
				'label'            => $definition['label'],
				'description'      => $definition['description'],
				'filter_value'     => $group_key,
				'count'            => count( $matching_issues ),
				'highest_severity' => $this->get_highest_severity( $matching_issues ),
			);
		}

		return $groups;
	}

	private function get_issue_group_definitions(): array {
		return array(
			'malware'            => array(
				'label'       => __( 'Malware', 'website-security-radar' ),
				'description' => __( 'Detected malware signatures or clearly malicious code patterns.', 'website-security-radar' ),
			),
			'suspicious pattern' => array(
				'label'       => __( 'Suspicious Pattern', 'website-security-radar' ),
				'description' => __( 'Findings that look risky and need manual verification.', 'website-security-radar' ),
			),
			'potential risk'     => array(
				'label'       => __( 'Potential Risk', 'website-security-radar' ),
				'description' => __( 'Files or code behaviors that may be legitimate but deserve review.', 'website-security-radar' ),
			),
			'file change'        => array(
				'label'       => __( 'File Change', 'website-security-radar' ),
				'description' => __( 'New, modified, or deleted files compared with the trusted baseline.', 'website-security-radar' ),
			),
			'hardening'          => array(
				'label'       => __( 'Hardening', 'website-security-radar' ),
				'description' => __( 'Configuration and exposure checks that improve overall site security.', 'website-security-radar' ),
			),
			'uploads issue'      => array(
				'label'       => __( 'Uploads Issue', 'website-security-radar' ),
				'description' => __( 'Issues related to files inside uploads or uploads-specific execution risk.', 'website-security-radar' ),
			),
		);
	}

	private function issue_matches_group_filter( array $issue, string $group_key ): bool {
		$group_key  = strtolower( trim( $group_key ) );
		$issue_type = strtolower( trim( (string) ( $issue['type'] ?? '' ) ) );

		if ( 'uploads issue' === $group_key ) {
			return $this->is_uploads_issue( $issue );
		}

		if ( 'hardening' === $group_key ) {
			return in_array( $issue_type, array( 'hardening', 'updates', 'permissions', 'exposure' ), true );
		}

		return $issue_type === $group_key;
	}

	private function is_uploads_issue( array $issue ): bool {
		$path = (string) ( $issue['path'] ?? $issue['file'] ?? '' );

		if ( '' !== $path && WSR_Helpers::is_uploads_path( $path ) ) {
			return true;
		}

		$issue_text       = strtolower( (string) ( $issue['issue'] ?? '' ) );
		$explanation_text = strtolower( (string) ( $issue['explanation'] ?? '' ) );

		if ( false !== strpos( $issue_text, 'uploads' ) || false !== strpos( $explanation_text, 'uploads' ) ) {
			return true;
		}

		if ( ! empty( $issue['context_notes'] ) && is_array( $issue['context_notes'] ) ) {
			foreach ( $issue['context_notes'] as $note ) {
				if ( false !== strpos( strtolower( sanitize_text_field( (string) $note ) ), 'uploads' ) ) {
					return true;
				}
			}
		}

		return false;
	}

	private function get_highest_severity( array $issues ): string {
		$order = array(
			'critical' => 4,
			'high'     => 3,
			'medium'   => 2,
			'low'      => 1,
		);
		$highest = '';
		$score   = 0;

		foreach ( $issues as $issue ) {
			$current = strtolower( (string) ( $issue['severity'] ?? '' ) );
			$value   = $order[ $current ] ?? 0;

			if ( $value > $score ) {
				$score   = $value;
				$highest = $current;
			}
		}

		return $highest;
	}

	private function issue_matches_path_search( array $issue, string $path_search ): bool {
		$display_path = strtolower( (string) ( $issue['path'] ?? $issue['file'] ?? '' ) );
		return false !== strpos( $display_path, strtolower( $path_search ) );
	}

	private function issue_matches_date_range( array $issue, string $date_from, string $date_to ): bool {
		if ( '' === $date_from && '' === $date_to ) {
			return true;
		}

		$timestamp = strtotime( (string) ( $issue['detected_at'] ?? $issue['detected_date'] ?? '' ) );

		if ( ! $timestamp ) {
			return false;
		}

		if ( '' !== $date_from ) {
			$from_timestamp = strtotime( $date_from . ' 00:00:00' );

			if ( $from_timestamp && $timestamp < $from_timestamp ) {
				return false;
			}
		}

		if ( '' !== $date_to ) {
			$to_timestamp = strtotime( $date_to . ' 23:59:59' );

			if ( $to_timestamp && $timestamp > $to_timestamp ) {
				return false;
			}
		}

		return true;
	}

	private function issue_matches_review_status( array $issue, string $review_status ): bool {
		$is_reviewed = ! empty( $issue['reviewed'] );
		$is_ignored  = $this->issue_is_ignored( $issue );

		if ( 'reviewed' === $review_status ) {
			return $is_reviewed;
		}

		if ( 'ignored' === $review_status ) {
			return $is_ignored;
		}

		if ( 'active' === $review_status ) {
			return ! $is_reviewed && ! $is_ignored;
		}

		return true;
	}

	private function issue_is_ignored( array $issue ): bool {
		$path = (string) ( $issue['path'] ?? $issue['file'] ?? '' );

		if ( '' === $path ) {
			return false;
		}

		return WSR_Helpers::is_ignored_path( $path );
	}

	private function sanitize_date_input( $value ): string {
		$value = sanitize_text_field( (string) $value );

		if ( '' === $value ) {
			return '';
		}

		$timestamp = strtotime( $value );

		if ( ! $timestamp ) {
			return '';
		}

		return gmdate( 'Y-m-d', $timestamp );
	}

	private function get_timeline_type_options( array $events ): array {
		$types = array_keys( WSR_Helpers::get_timeline_event_types() );

		foreach ( $events as $event ) {
			$type = sanitize_key( (string) ( $event['type'] ?? '' ) );

			if ( '' !== $type && ! in_array( $type, $types, true ) ) {
				$types[] = $type;
			}
		}

		return $types;
	}

	private function get_timeline_actor_label( array $event ): string {
		return $this->format_user_label( absint( $event['actor_user_id'] ?? 0 ) );
	}

	private function issue_has_change_details( array $issue ): bool {
		if ( 'file change' !== strtolower( (string) ( $issue['type'] ?? '' ) ) ) {
			return false;
		}

		if ( 'Modified file detected' !== (string) ( $issue['issue'] ?? '' ) ) {
			return false;
		}

		return true;
	}

	private function get_change_details_url( array $issue ): string {
		$issue_id = (string) ( $issue['id'] ?? '' );

		return wp_nonce_url(
			WSR_Helpers::admin_url(
				'website-security-radar-results',
				array_merge(
					$this->get_results_query_args(),
					array(
						'change_details' => $issue_id,
					)
				)
			),
			'wsr_view_change_details_' . $issue_id
		);
	}

	private function normalize_change_details( array $issue ): array {
		$details = $issue['change_details'] ?? array();
		$path    = WSR_Helpers::get_safe_display_path( (string) ( $issue['path'] ?? '' ) );

		return array(
			'relative_path' => sanitize_text_field( (string) ( $details['relative_path'] ?? $path ) ),
			'extension'     => sanitize_text_field(
				(string) (
					$details['extension']
					?? pathinfo( $path, PATHINFO_EXTENSION )
				)
			),
			'old'           => array(
				'hash'     => sanitize_text_field( (string) ( $details['old']['hash'] ?? '' ) ),
				'modified' => isset( $details['old']['modified'] ) ? (int) $details['old']['modified'] : 0,
				'size'     => isset( $details['old']['size'] ) ? (int) $details['old']['size'] : null,
			),
			'new'           => array(
				'hash'     => sanitize_text_field( (string) ( $details['new']['hash'] ?? '' ) ),
				'modified' => isset( $details['new']['modified'] ) ? (int) $details['new']['modified'] : 0,
				'size'     => isset( $details['new']['size'] ) ? (int) $details['new']['size'] : null,
			),
			'content_diff'  => array(
				'enabled'   => ! empty( $details['content_diff']['enabled'] ),
				'available' => ! empty( $details['content_diff']['available'] ),
				'chunks'    => array(),
			),
		);
	}

	private function format_file_timestamp( int $timestamp ): string {
		if ( $timestamp <= 0 ) {
			return __( 'Not available', 'website-security-radar' );
		}

		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
	}

	private function format_file_size( $size ): string {
		if ( null === $size || $size < 0 ) {
			return __( 'Not available', 'website-security-radar' );
		}

		return sprintf(
			/* translators: %s: file size in bytes. */
			__( '%s bytes', 'website-security-radar' ),
			number_format_i18n( (int) $size )
		);
	}

	private function render_notices(): void {
		$notice = sanitize_text_field( wp_unslash( $_GET['wsr_notice'] ?? '' ) );

		if ( '' === $notice ) {
			return;
		}

		$messages = array(
			'baseline_created'       => array(
				'message' => __( 'Baseline created.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'baseline_activated'     => array(
				'message' => __( 'Active baseline updated.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'baseline_deleted'       => array(
				'message' => __( 'Baseline deleted.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'baseline_invalid'       => array(
				'message' => __( 'The selected baseline could not be processed.', 'website-security-radar' ),
				'class'   => 'notice-error',
			),
			'reviewed'               => array(
				'message' => __( 'Issue marked as reviewed.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'ignored'                => array(
				'message' => __( 'Ignore rule saved.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'reset'                  => array(
				'message' => __( 'Ignore list reset.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'ignore_toggled'         => array(
				'message' => __( 'Ignore rule updated.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'ignore_deleted'         => array(
				'message' => __( 'Ignore rule deleted.', 'website-security-radar' ),
				'class'   => 'notice-success',
			),
			'ignore_warning'         => array(
				'message' => __( 'Broad ignore rules require confirmation before they can be saved.', 'website-security-radar' ),
				'class'   => 'notice-warning',
			),
			'ignore_uploads_confirm' => array(
				'message' => __( 'Ignoring uploads PHP requires explicit confirmation.', 'website-security-radar' ),
				'class'   => 'notice-warning',
			),
			'ignore_invalid'         => array(
				'message' => __( 'The ignore rule could not be saved. Check the type and value.', 'website-security-radar' ),
				'class'   => 'notice-error',
			),
		);

		if ( ! isset( $messages[ $notice ] ) ) {
			return;
		}

		echo '<div class="notice ' . esc_attr( $messages[ $notice ]['class'] ) . ' is-dismissible"><p>' . esc_html( $messages[ $notice ]['message'] ) . '</p></div>';
	}

	private function assert_capability(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'website-security-radar' ) );
		}
	}
}
