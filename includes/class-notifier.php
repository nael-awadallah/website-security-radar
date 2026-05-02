<?php
/**
 * Notifications.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Notifier {
	public function maybe_send_critical_alert( array $results, array $settings ): void {
		if ( empty( $settings['enable_email_alerts'] ) || empty( $settings['alert_email'] ) ) {
			return;
		}

		$severity_counts = $results['severity_counts'] ?? array();
		$critical_count  = (int) ( $severity_counts['critical'] ?? 0 );

		if ( $critical_count < 1 ) {
			return;
		}

		$high_count = (int) ( $severity_counts['high'] ?? 0 );
		$subject    = sprintf( '[%s] Security Radar alert', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		$body       = implode(
			"\n",
			array(
				sprintf( 'Website: %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
				sprintf( 'Security score: %d', (int) ( $results['score'] ?? 0 ) ),
				sprintf( 'Critical issues: %d', $critical_count ),
				sprintf( 'High issues: %d', $high_count ),
				sprintf( 'Dashboard: %s', WSR_Helpers::admin_url( 'website-security-radar' ) ),
			)
		);

		wp_mail( sanitize_email( $settings['alert_email'] ), $subject, $body );
	}
}
