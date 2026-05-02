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
	private const ALERT_COOLDOWN = DAY_IN_SECONDS;

	public function maybe_send_critical_alert( array $results, array $settings ): void {
		if ( empty( $settings['enable_email_alerts'] ) || empty( $settings['alert_email'] ) ) {
			return;
		}

		$severity_counts = $results['severity_counts'] ?? array();
		$critical_count  = (int) ( $severity_counts['critical'] ?? 0 );

		if ( $critical_count < 1 ) {
			return;
		}

		$fingerprint = $this->critical_fingerprint( $results['issues'] ?? array() );
		$state       = get_option( WSR_Helpers::CRITICAL_ALERT_STATE_OPTION, array() );
		$last_time   = is_array( $state ) ? (int) ( $state['sent_at'] ?? 0 ) : 0;
		$last_count  = is_array( $state ) ? (int) ( $state['critical_count'] ?? 0 ) : 0;
		$last_hash   = is_array( $state ) ? (string) ( $state['fingerprint'] ?? '' ) : '';

		if ( $fingerprint === $last_hash && $critical_count <= $last_count && ( time() - $last_time ) < self::ALERT_COOLDOWN ) {
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

		$sent = wp_mail( sanitize_email( $settings['alert_email'] ), $subject, $body );

		if ( $sent ) {
			update_option(
				WSR_Helpers::CRITICAL_ALERT_STATE_OPTION,
				array(
					'fingerprint'    => $fingerprint,
					'critical_count' => $critical_count,
					'sent_at'        => time(),
				),
				false
			);
			return;
		}

		( new WSR_Timeline() )->add_event(
			array(
				'type'     => 'critical_issue_detected',
				'severity' => 'critical',
				'message'  => __( 'Critical alert email could not be sent.', 'website-security-radar' ),
			)
		);
	}

	private function critical_fingerprint( array $issues ): string {
		$ids = array();

		foreach ( $issues as $issue ) {
			if ( 'critical' !== (string) ( $issue['severity'] ?? '' ) ) {
				continue;
			}

			$ids[] = WSR_Helpers::issue_identifier( $issue );
		}

		sort( $ids, SORT_STRING );

		return hash( 'sha256', implode( '|', $ids ) );
	}
}
