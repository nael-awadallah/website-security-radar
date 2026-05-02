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
		add_action( 'admin_post_wsr_mark_reviewed', array( $this, 'handle_mark_reviewed' ) );
		add_action( 'admin_post_wsr_ignore_path', array( $this, 'handle_ignore_path' ) );
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
		$top_critical_issue = $this->get_top_issue( $results['issues'] ?? array(), 'critical' );
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Dashboard', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div class="wsr-grid wsr-grid-main">
				<div class="wsr-card wsr-card-score">
					<div class="wsr-score-ring wsr-risk-<?php echo esc_attr( strtolower( $results['risk_level'] ?? 'safe' ) ); ?>">
						<span><?php echo esc_html( (string) ( $results['score'] ?? 100 ) ); ?></span>
					</div>
					<div>
						<h2><?php esc_html_e( 'Security score', 'website-security-radar' ); ?></h2>
						<p class="wsr-risk-text"><?php echo esc_html( $results['risk_level'] ?? 'Safe' ); ?></p>
						<p><?php echo esc_html( sprintf( __( 'Last scan: %s', 'website-security-radar' ), WSR_Helpers::format_datetime( $results['scanned_at'] ?? '' ) ) ); ?></p>
						<?php if ( $top_critical_issue ) : ?>
							<p class="wsr-inline-alert">
								<strong><?php esc_html_e( 'Top critical issue:', 'website-security-radar' ); ?></strong>
								<?php echo esc_html( $top_critical_issue['issue'] ); ?>
							</p>
						<?php endif; ?>
					</div>
				</div>
				<div class="wsr-card wsr-card-actions">
					<h2><?php esc_html_e( 'Actions', 'website-security-radar' ); ?></h2>
					<p><?php esc_html_e( 'Run an on-demand scan or refresh the known-good baseline.', 'website-security-radar' ); ?></p>
					<div class="wsr-actions">
						<button type="button" class="button button-primary wsr-ajax-button" data-wsr-action="scan"><?php esc_html_e( 'Manual Scan', 'website-security-radar' ); ?></button>
						<button type="button" class="button wsr-ajax-button" data-wsr-action="baseline"><?php esc_html_e( 'Create Baseline', 'website-security-radar' ); ?></button>
					</div>
					<div class="wsr-card-meta">
						<span><?php echo esc_html( sprintf( __( '%d files scanned', 'website-security-radar' ), (int) ( $summary['total_scanned_files'] ?? 0 ) ) ); ?></span>
						<span><?php echo esc_html( sprintf( __( '%d active issues', 'website-security-radar' ), count( $results['issues'] ?? array() ) ) ); ?></span>
					</div>
				</div>
			</div>
			<div class="wsr-grid wsr-grid-stats">
				<?php
				$cards = array(
					'total_scanned_files' => __( 'Total scanned files', 'website-security-radar' ),
					'new_files'           => __( 'New files', 'website-security-radar' ),
					'modified_files'      => __( 'Modified files', 'website-security-radar' ),
					'deleted_files'       => __( 'Deleted files', 'website-security-radar' ),
					'suspicious_files'    => __( 'Suspicious files', 'website-security-radar' ),
					'hardening_warnings'  => __( 'Hardening warnings', 'website-security-radar' ),
					'critical_issues'     => __( 'Critical issues', 'website-security-radar' ),
				);

				foreach ( $cards as $key => $label ) :
					?>
					<div class="wsr-card wsr-stat-card">
						<span class="wsr-stat-value"><?php echo esc_html( (string) ( $summary[ $key ] ?? 0 ) ); ?></span>
						<span class="wsr-stat-label"><?php echo esc_html( $label ); ?></span>
					</div>
				<?php endforeach; ?>
			</div>
			<div class="wsr-grid wsr-grid-main">
				<div class="wsr-card">
					<h2><?php esc_html_e( 'Quick recommendations', 'website-security-radar' ); ?></h2>
					<ul class="wsr-compact-list">
						<?php foreach ( $this->get_recommendations( $results ) as $recommendation ) : ?>
							<li><?php echo esc_html( $recommendation ); ?></li>
						<?php endforeach; ?>
					</ul>
				</div>
				<div class="wsr-card">
					<h2><?php esc_html_e( 'Top 5 Critical Issues', 'website-security-radar' ); ?></h2>
					<?php $this->render_top_issues_list( $results['issues'] ?? array() ); ?>
				</div>
			</div>
		</div>
		<?php
	}

	public function render_results_page(): void {
		$this->assert_capability();
		$results         = $this->plugin->get_latest_results();
		$all_issues      = $results['issues'] ?? array();
		$detail_issue    = $this->get_selected_issue( $all_issues );
		$filtered_issues = $this->get_filtered_issues( $all_issues );
		$pagination      = $this->get_paginated_issues( $filtered_issues );
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Scan Results', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
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
					</div>
				</div>
				<?php $this->render_issue_filters( $all_issues ); ?>
				<?php $this->render_issue_table( $pagination['items'], true ); ?>
				<?php $this->render_issue_pagination( $pagination['current_page'], $pagination['total_pages'] ); ?>
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

	public function render_ignore_list_page(): void {
		$this->assert_capability();
		$ignored_paths = WSR_Helpers::get_ignore_list();
		?>
		<div class="wrap wsr-wrap">
			<?php $this->render_header( __( 'Ignore List', 'website-security-radar' ) ); ?>
			<?php $this->render_notices(); ?>
			<div class="wsr-card">
				<?php if ( empty( $ignored_paths ) ) : ?>
					<p><?php esc_html_e( 'No ignored paths yet.', 'website-security-radar' ); ?></p>
				<?php else : ?>
					<ul class="wsr-list">
						<?php foreach ( $ignored_paths as $ignored_path ) : ?>
							<li><code><?php echo esc_html( $ignored_path ); ?></code></li>
						<?php endforeach; ?>
					</ul>
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
		}

		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-results', array( 'wsr_notice' => 'reviewed' ) ) );
		exit;
	}

	public function handle_ignore_path(): void {
		$this->assert_capability();
		check_admin_referer( WSR_Helpers::ADMIN_NONCE_ACTION );

		$path        = sanitize_text_field( wp_unslash( $_GET['path'] ?? '' ) );
		$ignore_list = WSR_Helpers::get_ignore_list();

		if ( '' !== $path ) {
			$ignore_list[] = trim( wp_normalize_path( $path ), '/' );
			update_option( WSR_Helpers::IGNORE_OPTION, array_values( array_unique( $ignore_list ) ), false );
		}

		wp_safe_redirect( WSR_Helpers::admin_url( 'website-security-radar-ignore-list', array( 'wsr_notice' => 'ignored' ) ) );
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
		$logo_url = WSR_PLUGIN_URL . 'assets/branding/logo.svg';
		?>
		<div class="wsr-header">
			<img src="<?php echo esc_url( $logo_url ); ?>" alt="<?php esc_attr_e( 'Website Security Radar', 'website-security-radar' ); ?>" class="wsr-logo" />
			<div class="wsr-header-copy">
				<h1><?php echo esc_html( $title ); ?></h1>
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

	private function get_recommendations( array $results ): array {
		$recommendations = array();
		$summary         = $results['summary'] ?? array();
		$top_issue       = $this->get_top_issue( $results['issues'] ?? array() );

		if ( ! empty( $summary['critical_issues'] ) ) {
			$recommendations[] = __( 'Review critical issues first and confirm whether affected files are expected.', 'website-security-radar' );
		}

		if ( $top_issue ) {
			$recommendations[] = sprintf(
				/* translators: %s: issue label. */
				__( 'Prioritize: %s.', 'website-security-radar' ),
				$top_issue['issue']
			);
		}

		if ( ! empty( $summary['modified_files'] ) ) {
			$recommendations[] = __( 'Compare modified files against your deployment or backup source of truth.', 'website-security-radar' );
		}

		if ( empty( $results['baseline']['has_baseline'] ?? false ) ) {
			$recommendations[] = __( 'Create a baseline after confirming the current site state is trusted.', 'website-security-radar' );
		}

		if ( empty( $recommendations ) ) {
			$recommendations[] = __( 'Keep scheduled scans enabled and review updates regularly.', 'website-security-radar' );
		}

		return $recommendations;
	}

	private function render_top_issues_list( array $issues ): void {
		$top_issues = $this->get_top_five_issues( $issues );

		if ( empty( $top_issues ) ) {
			echo '<p>' . esc_html__( 'No critical or high-priority issues recorded yet.', 'website-security-radar' ) . '</p>';
			return;
		}
		?>
		<div class="wsr-top-issues">
			<?php foreach ( $top_issues as $issue ) : ?>
				<div class="wsr-top-issue">
					<div class="wsr-top-issue-main">
						<div class="wsr-top-issue-head">
							<span class="<?php echo esc_attr( WSR_Helpers::severity_label_class( (string) $issue['severity'] ) ); ?>"><?php echo esc_html( ucfirst( (string) $issue['severity'] ) ); ?></span>
							<span class="wsr-type-pill"><?php echo esc_html( WSR_Helpers::get_type_label( (string) ( $issue['type'] ?? '' ) ) ); ?></span>
						</div>
						<strong><?php echo esc_html( (string) $issue['issue'] ); ?></strong>
						<?php $display_path = (string) ( $issue['path'] ?? $issue['file'] ?? '' ); ?>
						<code class="wsr-path" title="<?php echo esc_attr( $display_path ); ?>"><?php echo esc_html( $display_path ); ?></code>
						<p><?php echo esc_html( (string) $issue['explanation'] ); ?></p>
					</div>
					<a class="button button-small" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-results', array( 'issue' => $issue['id'] ) ) ); ?>"><?php esc_html_e( 'View', 'website-security-radar' ); ?></a>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private function render_issue_filters( array $issues ): void {
		$selected_severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$selected_type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );
		$type_options      = $this->get_issue_type_options( $issues );
		?>
		<form method="get" class="wsr-filter-bar">
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
			<div class="wsr-filter-actions">
				<button type="submit" class="button"><?php esc_html_e( 'Filter', 'website-security-radar' ); ?></button>
				<a class="button button-link" href="<?php echo esc_url( WSR_Helpers::admin_url( 'website-security-radar-results' ) ); ?>"><?php esc_html_e( 'Reset', 'website-security-radar' ); ?></a>
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

	private function get_filtered_issues( array $issues ): array {
		$selected_severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$selected_type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );

		return array_values(
			array_filter(
				$issues,
				static function ( array $issue ) use ( $selected_severity, $selected_type ): bool {
					if ( '' !== $selected_severity && ( $issue['severity'] ?? '' ) !== $selected_severity ) {
						return false;
					}

					if ( '' !== $selected_type && strtolower( (string) ( $issue['type'] ?? '' ) ) !== strtolower( $selected_type ) ) {
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
		$types = array();

		foreach ( $issues as $issue ) {
			if ( ! empty( $issue['type'] ) ) {
				$types[] = strtolower( (string) $issue['type'] );
			}
		}

		$types = array_values( array_unique( array_merge( array( 'malware', 'suspicious pattern', 'potential risk' ), $types ) ) );
		sort( $types );

		return $types;
	}

	private function get_results_query_args(): array {
		$args = array();

		$severity = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
		$type     = sanitize_text_field( wp_unslash( $_GET['type'] ?? '' ) );

		if ( '' !== $severity ) {
			$args['severity'] = $severity;
		}

		if ( '' !== $type ) {
			$args['type'] = $type;
		}

		return $args;
	}

	private function render_notices(): void {
		$notice = sanitize_text_field( wp_unslash( $_GET['wsr_notice'] ?? '' ) );

		if ( '' === $notice ) {
			return;
		}

		$messages = array(
			'reviewed' => __( 'Issue marked as reviewed.', 'website-security-radar' ),
			'ignored'  => __( 'Path added to ignore list.', 'website-security-radar' ),
			'reset'    => __( 'Ignore list reset.', 'website-security-radar' ),
		);

		if ( ! isset( $messages[ $notice ] ) ) {
			return;
		}

		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $messages[ $notice ] ) . '</p></div>';
	}

	private function assert_capability(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'website-security-radar' ) );
		}
	}
}
