<?php
/**
 * Cron scanner.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Cron_Scanner {
	private array $suspicious_keywords = array( 'eval', 'shell', 'backdoor', 'inject', 'spam', 'mailer', 'redirect', 'hidden' );

	public function scan(): array {
		if ( ! function_exists( '_get_cron_array' ) ) {
			return array();
		}

		$cron_array = _get_cron_array();

		if ( empty( $cron_array ) || ! is_array( $cron_array ) ) {
			return array();
		}

		$issues            = array();
		$schedules         = wp_get_schedules();
		$known_hook_prefix = $this->get_known_hook_prefixes();
		$now               = time();

		foreach ( $cron_array as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( $hooks as $hook_name => $events ) {
				if ( ! is_array( $events ) ) {
					continue;
				}

				foreach ( $events as $event ) {
					$schedule_name = sanitize_key( (string) ( $event['schedule'] ?? '' ) );
					$interval      = absint( $event['interval'] ?? 0 );
					$next_run      = is_numeric( $timestamp ) ? (int) $timestamp : 0;

					if ( $this->has_suspicious_keyword( $hook_name ) ) {
						$issues[] = $this->issue(
							'high',
							'high',
							$hook_name,
							$schedule_name,
							$next_run,
							__( 'Cron hook name contains suspicious keywords.', 'website-security-radar' ),
							__( 'Review recommended. This hook name resembles patterns often used by compromised code or spam jobs.', 'website-security-radar' )
						);
					}

					if ( $interval > 0 && $interval < MINUTE_IN_SECONDS * 5 ) {
						$issues[] = $this->issue(
							'medium',
							'medium',
							$hook_name,
							$schedule_name,
							$next_run,
							__( 'Cron event runs very frequently.', 'website-security-radar' ),
							__( 'Review recommended. Frequent cron execution can be legitimate, but unusual repetition can also indicate abusive automation.', 'website-security-radar' )
						);
					}

					if ( '' !== $schedule_name && ! isset( $schedules[ $schedule_name ] ) ) {
						$issues[] = $this->issue(
							'medium',
							'medium',
							$hook_name,
							$schedule_name,
							$next_run,
							__( 'Cron event uses an unknown schedule.', 'website-security-radar' ),
							__( 'Review recommended. The event references a schedule that is not currently registered.', 'website-security-radar' )
						);
					}

					if ( $interval > 0 && $interval < HOUR_IN_SECONDS && ! in_array( $schedule_name, array( 'hourly', 'twicedaily', 'daily', 'weekly' ), true ) ) {
						$issues[] = $this->issue(
							'low',
							'medium',
							$hook_name,
							$schedule_name,
							$next_run,
							__( 'Cron event uses a custom short interval.', 'website-security-radar' ),
							__( 'Review recommended. Custom intervals are not always risky, but short recurring schedules deserve verification.', 'website-security-radar' )
						);
					}

					if ( ! $this->looks_like_known_hook( $hook_name, $known_hook_prefix ) && $this->looks_random_or_obscured( $hook_name ) ) {
						$issues[] = $this->issue(
							'medium',
							'low',
							$hook_name,
							$schedule_name,
							$next_run,
							__( 'Unknown cron hook with unusual naming pattern.', 'website-security-radar' ),
							__( 'Review recommended. This hook does not look like a common WordPress or plugin schedule name.', 'website-security-radar' )
						);
					}

					if ( $next_run > 0 && $next_run < ( $now - DAY_IN_SECONDS ) ) {
						$issues[] = $this->issue(
							'low',
							'low',
							$hook_name,
							$schedule_name,
							$next_run,
							__( 'Cron event has a stale next run time.', 'website-security-radar' ),
							__( 'Review recommended. Old cron entries can indicate abandoned jobs or broken scheduling.', 'website-security-radar' )
						);
					}
				}
			}
		}

		return WSR_Helpers::apply_review_status( $this->dedupe_issues( $issues ) );
	}

	private function issue( string $severity, string $confidence, string $hook_name, string $schedule, int $next_run, string $issue, string $explanation ): array {
		return array(
			'type'               => 'cron',
			'severity'           => $severity,
			'confidence'         => $confidence,
			'path'               => '',
			'hook_name'          => sanitize_text_field( $hook_name ),
			'schedule'           => sanitize_text_field( $schedule ),
			'next_run'           => $next_run > 0 ? gmdate( 'c', $next_run ) : '',
			'issue'              => $issue,
			'explanation'        => $explanation,
			'recommended_action' => __( 'Review the responsible plugin or custom code before changing or removing cron events.', 'website-security-radar' ),
			'detected_at'        => gmdate( 'c' ),
			'detected_date'      => gmdate( 'c' ),
			'line'               => 0,
		);
	}

	private function dedupe_issues( array $issues ): array {
		$unique = array();

		foreach ( $issues as $issue ) {
			$key = hash(
				'sha256',
				implode(
					'|',
					array(
						(string) ( $issue['hook_name'] ?? '' ),
						(string) ( $issue['schedule'] ?? '' ),
						(string) ( $issue['issue'] ?? '' ),
					)
				)
			);

			$unique[ $key ] = $issue;
		}

		return array_values( $unique );
	}

	private function has_suspicious_keyword( string $hook_name ): bool {
		$hook_name = strtolower( $hook_name );

		foreach ( $this->suspicious_keywords as $keyword ) {
			if ( false !== strpos( $hook_name, $keyword ) ) {
				return true;
			}
		}

		return false;
	}

	private function looks_like_known_hook( string $hook_name, array $known_prefixes ): bool {
		$hook_name = strtolower( $hook_name );

		if ( 0 === strpos( $hook_name, 'wp_' ) || 0 === strpos( $hook_name, 'do_pings' ) ) {
			return true;
		}

		foreach ( $known_prefixes as $prefix ) {
			if ( '' !== $prefix && 0 === strpos( $hook_name, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	private function looks_random_or_obscured( string $hook_name ): bool {
		$hook_name = strtolower( $hook_name );

		if ( preg_match( '/[a-f0-9]{12,}/', $hook_name ) ) {
			return true;
		}

		return (bool) preg_match( '/[a-z0-9]{18,}/', str_replace( array( '_', '-' ), '', $hook_name ) );
	}

	private function get_known_hook_prefixes(): array {
		$prefixes = array( 'action_scheduler_', 'woocommerce_', 'wp_version_check', 'wp_update_' );

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();

		foreach ( array_keys( $plugins ) as $plugin_file ) {
			$slug = strtolower( dirname( $plugin_file ) );

			if ( '.' === $slug || '' === $slug ) {
				$slug = strtolower( basename( $plugin_file, '.php' ) );
			}

			$prefixes[] = sanitize_key( str_replace( '-', '_', $slug ) ) . '_';
		}

		return array_unique( array_filter( $prefixes ) );
	}
}
