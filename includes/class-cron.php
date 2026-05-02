<?php
/**
 * Cron support.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Cron {
	public function register(): void {
		add_action( WSR_Helpers::CRON_HOOK, array( $this, 'run_scheduled_scan' ) );
		add_action( WSR_Helpers::VULNERABILITY_RETRY_HOOK, array( $this, 'run_vulnerability_retry' ) );
	}

	public function maybe_schedule( array $settings ): void {
		if ( ! empty( $settings['enable_scheduled_scan'] ) ) {
			$next = wp_next_scheduled( WSR_Helpers::CRON_HOOK );

			if ( $next ) {
				wp_unschedule_event( $next, WSR_Helpers::CRON_HOOK );
			}

			wp_schedule_event( $this->get_next_scan_timestamp( (string) ( $settings['scheduled_scan_time'] ?? '03:00' ) ), 'daily', WSR_Helpers::CRON_HOOK );
			return;
		}

		$this->clear_schedule();
	}

	public function clear_schedule(): void {
		$timestamp = wp_next_scheduled( WSR_Helpers::CRON_HOOK );

		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, WSR_Helpers::CRON_HOOK );
		}
	}

	public function run_scheduled_scan(): void {
		WSR_Plugin::get_instance()->run_scan( true, 'scheduled', true );
	}

	public function run_vulnerability_retry(): void {
		WSR_Plugin::get_instance()->run_vulnerability_check( true, 1 );
	}

	private function get_next_scan_timestamp( string $time ): int {
		if ( ! preg_match( '/^([01]\d|2[0-3]):([0-5]\d)$/', $time, $matches ) ) {
			$time = '03:00';
			preg_match( '/^([01]\d|2[0-3]):([0-5]\d)$/', $time, $matches );
		}

		$timezone  = wp_timezone();
		$scheduled = new DateTimeImmutable( 'now', $timezone );
		$scheduled = $scheduled->setTime( (int) $matches[1], (int) $matches[2] );

		if ( $scheduled->getTimestamp() <= time() ) {
			$scheduled = $scheduled->modify( '+1 day' );
		}

		return $scheduled->getTimestamp();
	}
}
