<?php
/**
 * Client report renderer.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Report {
	private WSR_Plugin $plugin;

	public function __construct( WSR_Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function get_report_url(): string {
		return wp_nonce_url(
			WSR_Helpers::admin_url( 'website-security-radar-report' ),
			WSR_Helpers::REPORT_NONCE_ACTION
		);
	}

	public function validate_request(): void {
		$nonce = sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) );

		if ( '' === $nonce || ! wp_verify_nonce( $nonce, WSR_Helpers::REPORT_NONCE_ACTION ) ) {
			wp_die( esc_html__( 'Invalid report link.', 'website-security-radar' ) );
		}
	}

	public function render_page(): void {
		$settings      = WSR_Helpers::get_settings();
		$results       = $this->plugin->get_latest_results();
		$summary       = $results['summary'] ?? array();
		$top_issues    = $this->get_top_issues( $results['issues'] ?? array() );
		$plugin_data   = get_file_data( WSR_PLUGIN_FILE, array( 'version' => 'Version' ) );
		$agency_name   = sanitize_text_field( (string) ( $settings['report_agency_name'] ?? '' ) );
		$agency_logo   = esc_url( (string) ( $settings['report_agency_logo_url'] ?? '' ) );
		$footer_text   = sanitize_textarea_field( (string) ( $settings['report_footer_text'] ?? '' ) );
		$vuln_summary  = $results['vulnerability_checks'] ?? array();
		$issue_counts  = $this->get_issue_type_counts( $results['issues'] ?? array() );
		?>
		<div class="wrap wsr-wrap wsr-report-wrap">
			<style>
				.wsr-report-sheet{max-width:1100px;margin:24px auto;background:#fff;padding:32px;color:#1d2327}
				.wsr-report-head,.wsr-report-grid,.wsr-report-summary,.wsr-report-sections{display:grid;gap:16px}
				.wsr-report-head{grid-template-columns:1fr auto;align-items:start}
				.wsr-report-brand{display:flex;gap:16px;align-items:center}
				.wsr-report-brand img{max-height:64px;max-width:180px}
				.wsr-report-grid{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
				.wsr-report-card,.wsr-report-section{border:1px solid #dcdcde;border-radius:12px;padding:18px;background:#fff}
				.wsr-report-section h2{margin-top:0}
				.wsr-report-meta{color:#50575e}
				.wsr-report-list{margin:0;padding-left:18px}
				.wsr-report-footer{margin-top:24px;color:#50575e}
				@media print{.notice,.wrap>h1,.wrap>.wsr-page-header,.wsr-report-actions{display:none!important}.wsr-report-sheet{margin:0;max-width:none;padding:0}.wsr-report-card,.wsr-report-section{break-inside:avoid}}
			</style>
			<div class="wsr-report-actions">
				<a class="button" href="#" onclick="window.print(); return false;"><?php esc_html_e( 'Print / Save as PDF', 'website-security-radar' ); ?></a>
			</div>
			<div class="wsr-report-sheet">
				<div class="wsr-report-head">
					<div>
						<div class="wsr-report-brand">
							<?php if ( $agency_logo ) : ?>
								<img src="<?php echo esc_url( $agency_logo ); ?>" alt="<?php esc_attr_e( 'Agency logo', 'website-security-radar' ); ?>" />
							<?php endif; ?>
							<div>
								<h1><?php echo esc_html( get_bloginfo( 'name' ) ); ?></h1>
								<p class="wsr-report-meta"><?php echo esc_html( home_url( '/' ) ); ?></p>
								<?php if ( '' !== $agency_name ) : ?>
									<p class="wsr-report-meta"><?php echo esc_html( $agency_name ); ?></p>
								<?php endif; ?>
							</div>
						</div>
					</div>
					<div class="wsr-report-meta">
						<p><strong><?php esc_html_e( 'Report date:', 'website-security-radar' ); ?></strong> <?php echo esc_html( wp_date( get_option( 'date_format' ) ) ); ?></p>
						<p><strong><?php esc_html_e( 'Last scan date:', 'website-security-radar' ); ?></strong> <?php echo esc_html( WSR_Helpers::format_datetime( (string) ( $results['scanned_at'] ?? '' ) ) ); ?></p>
						<p><strong><?php esc_html_e( 'Plugin version:', 'website-security-radar' ); ?></strong> <?php echo esc_html( (string) ( $plugin_data['version'] ?? WSR_PLUGIN_VERSION ) ); ?></p>
					</div>
				</div>
				<div class="wsr-report-grid">
					<div class="wsr-report-card">
						<strong><?php esc_html_e( 'Security score', 'website-security-radar' ); ?></strong>
						<p><?php echo esc_html( (string) ( $results['score'] ?? 100 ) ); ?>/100</p>
					</div>
					<div class="wsr-report-card">
						<strong><?php esc_html_e( 'Risk level', 'website-security-radar' ); ?></strong>
						<p><?php echo esc_html( (string) ( $results['risk_level'] ?? __( 'Safe', 'website-security-radar' ) ) ); ?></p>
					</div>
					<div class="wsr-report-card">
						<strong><?php esc_html_e( 'Critical issues', 'website-security-radar' ); ?></strong>
						<p><?php echo esc_html( (string) ( $summary['critical_issues'] ?? 0 ) ); ?></p>
					</div>
					<div class="wsr-report-card">
						<strong><?php esc_html_e( 'Files scanned', 'website-security-radar' ); ?></strong>
						<p><?php echo esc_html( number_format_i18n( (int) ( $summary['total_scanned_files'] ?? 0 ) ) ); ?></p>
					</div>
				</div>
				<div class="wsr-report-sections">
					<div class="wsr-report-section">
						<h2><?php esc_html_e( 'Summary stats', 'website-security-radar' ); ?></h2>
						<ul class="wsr-report-list">
							<li><?php echo esc_html( sprintf( __( 'Vulnerability findings: %d', 'website-security-radar' ), (int) ( $summary['vulnerability_findings'] ?? 0 ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Cron security findings: %d', 'website-security-radar' ), (int) ( $summary['cron_findings'] ?? 0 ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'User security findings: %d', 'website-security-radar' ), (int) ( $summary['user_security_findings'] ?? 0 ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Hardening warnings: %d', 'website-security-radar' ), (int) ( $summary['hardening_warnings'] ?? 0 ) ) ); ?></li>
						</ul>
					</div>
					<div class="wsr-report-section">
						<h2><?php esc_html_e( 'Vulnerability summary', 'website-security-radar' ); ?></h2>
						<ul class="wsr-report-list">
							<li><?php echo esc_html( sprintf( __( 'Status: %s', 'website-security-radar' ), (string) ( $vuln_summary['status'] ?? __( 'Disabled', 'website-security-radar' ) ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Provider: %s', 'website-security-radar' ), (string) ( $vuln_summary['provider_label'] ?? __( 'Not configured', 'website-security-radar' ) ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Last checked: %s', 'website-security-radar' ), WSR_Helpers::format_datetime( (string) ( $vuln_summary['last_checked'] ?? '' ) ) ) ); ?></li>
						</ul>
					</div>
					<div class="wsr-report-section">
						<h2><?php esc_html_e( 'Top critical/high issues', 'website-security-radar' ); ?></h2>
						<?php if ( empty( $top_issues ) ) : ?>
							<p><?php esc_html_e( 'No critical or high issues are currently recorded.', 'website-security-radar' ); ?></p>
						<?php else : ?>
							<ul class="wsr-report-list">
								<?php foreach ( $top_issues as $issue ) : ?>
									<li><?php echo esc_html( sprintf( '%s (%s)', (string) ( $issue['issue'] ?? '' ), ucfirst( (string) ( $issue['severity'] ?? 'low' ) ) ) ); ?></li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>
					<div class="wsr-report-section">
						<h2><?php esc_html_e( 'Scan scope', 'website-security-radar' ); ?></h2>
						<ul class="wsr-report-list">
							<li><?php echo esc_html( sprintf( __( 'Plugins: %s', 'website-security-radar' ), ! empty( $settings['scan_plugins'] ) ? __( 'Included', 'website-security-radar' ) : __( 'Excluded', 'website-security-radar' ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Themes: %s', 'website-security-radar' ), ! empty( $settings['scan_themes'] ) ? __( 'Included', 'website-security-radar' ) : __( 'Excluded', 'website-security-radar' ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Uploads: %s', 'website-security-radar' ), ! empty( $settings['scan_uploads'] ) ? __( 'Included', 'website-security-radar' ) : __( 'Excluded', 'website-security-radar' ) ) ); ?></li>
							<li><?php echo esc_html( sprintf( __( 'Root files: %s', 'website-security-radar' ), ! empty( $settings['scan_root_files'] ) ? __( 'Included', 'website-security-radar' ) : __( 'Excluded', 'website-security-radar' ) ) ); ?></li>
						</ul>
					</div>
					<div class="wsr-report-section">
						<h2><?php esc_html_e( 'Issue category summary', 'website-security-radar' ); ?></h2>
						<ul class="wsr-report-list">
							<?php foreach ( $issue_counts as $label => $count ) : ?>
								<li><?php echo esc_html( sprintf( '%s: %d', $label, $count ) ); ?></li>
							<?php endforeach; ?>
						</ul>
					</div>
					<div class="wsr-report-section">
						<h2><?php esc_html_e( 'Hardening recommendations', 'website-security-radar' ); ?></h2>
						<ul class="wsr-report-list">
							<li><?php esc_html_e( 'Review all critical and high findings before the next deployment or admin access change.', 'website-security-radar' ); ?></li>
							<li><?php esc_html_e( 'Confirm recent administrator changes and remove unused elevated accounts.', 'website-security-radar' ); ?></li>
							<li><?php esc_html_e( 'Validate unexpected cron hooks and short intervals against trusted plugins or custom code.', 'website-security-radar' ); ?></li>
							<li><?php esc_html_e( 'Keep WordPress core, plugins, and themes patched after compatibility review.', 'website-security-radar' ); ?></li>
						</ul>
					</div>
				</div>
				<div class="wsr-report-footer">
					<p><?php esc_html_e( 'This report is based on automated checks and should be reviewed by a qualified developer or security professional.', 'website-security-radar' ); ?></p>
					<?php if ( '' !== $footer_text ) : ?>
						<p><?php echo esc_html( $footer_text ); ?></p>
					<?php endif; ?>
				</div>
			</div>
		</div>
		<?php
	}

	private function get_top_issues( array $issues ): array {
		$issues = array_values(
			array_filter(
				$issues,
				static function ( array $issue ): bool {
					return in_array( (string) ( $issue['severity'] ?? '' ), array( 'critical', 'high' ), true );
				}
			)
		);

		usort(
			$issues,
			static function ( array $left, array $right ): int {
				$order = array( 'critical' => 2, 'high' => 1 );

				return ( $order[ $right['severity'] ?? 'high' ] ?? 0 ) <=> ( $order[ $left['severity'] ?? 'high' ] ?? 0 );
			}
		);

		return array_slice( $issues, 0, 5 );
	}

	private function get_issue_type_counts( array $issues ): array {
		$counts = array();

		foreach ( $issues as $issue ) {
			$label = WSR_Helpers::get_type_label( (string) ( $issue['type'] ?? '' ) );

			if ( ! isset( $counts[ $label ] ) ) {
				$counts[ $label ] = 0;
			}

			++$counts[ $label ];
		}

		return $counts;
	}
}
