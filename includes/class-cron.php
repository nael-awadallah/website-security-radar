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
	}

	public function maybe_schedule( array $settings ): void {
		if ( ! empty( $settings['enable_scheduled_scan'] ) ) {
			if ( ! wp_next_scheduled( WSR_Helpers::CRON_HOOK ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', WSR_Helpers::CRON_HOOK );
			}

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
		WSR_Plugin::get_instance()->run_scan( false );
	}
}
