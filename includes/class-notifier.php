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
		$subject    = sprintf(
			/* translators: %s: site name. */
			__( '[%s] Security Radar alert', 'website-security-radar' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);
		$body       = implode(
			"\n",
			array(
				sprintf( __( 'Website: %s', 'website-security-radar' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
				sprintf( __( 'Security score: %d', 'website-security-radar' ), (int) ( $results['score'] ?? 0 ) ),
				sprintf( __( 'Critical issues: %d', 'website-security-radar' ), $critical_count ),
				sprintf( __( 'High issues: %d', 'website-security-radar' ), $high_count ),
				sprintf( __( 'Dashboard: %s', 'website-security-radar' ), WSR_Helpers::admin_url( 'website-security-radar' ) ),
			)
		);

		wp_mail( sanitize_email( $settings['alert_email'] ), $subject, $body );
	}
}
