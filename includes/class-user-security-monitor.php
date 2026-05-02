<?php
/**
 * User security monitor.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_User_Security_Monitor {
	public function register(): void {
		add_action( 'user_register', array( $this, 'handle_user_register' ), 10, 1 );
		add_action( 'set_user_role', array( $this, 'handle_set_user_role' ), 10, 3 );
		add_action( 'profile_update', array( $this, 'handle_profile_update' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'handle_login' ), 10, 2 );
	}

	public function scan(): array {
		$issues = array();
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
			)
		);

		$admin_count = is_array( $admins ) ? count( $admins ) : 0;

		if ( $admin_count > 3 ) {
			$issues[] = $this->issue(
				'medium',
				'medium',
				__( 'Unexpected number of administrator accounts', 'website-security-radar' ),
				sprintf( __( 'The site currently has %d administrator accounts.', 'website-security-radar' ), $admin_count ),
				__( 'Review administrator accounts and remove any access that is no longer required.', 'website-security-radar' )
			);
		}

		foreach ( $admins as $admin ) {
			$user_login = sanitize_user( (string) $admin->user_login, true );
			$user_email = sanitize_email( (string) $admin->user_email );
			$registered = strtotime( (string) $admin->user_registered );

			if ( in_array( strtolower( $user_login ), array( 'admin', 'test', 'support', 'wpadmin' ), true ) ) {
				$issues[] = $this->issue(
					'medium',
					'medium',
					__( 'Administrator account uses a weak-looking username', 'website-security-radar' ),
					sprintf( __( 'The administrator username "%s" is commonly targeted or reused.', 'website-security-radar' ), $user_login ),
					__( 'Review whether this account is still needed and consider replacing it with a less predictable login.', 'website-security-radar' ),
					$admin
				);
			}

			if ( $registered && $registered >= ( time() - DAY_IN_SECONDS * 7 ) ) {
				$issues[] = $this->issue(
					'medium',
					'medium',
					__( 'Recently registered administrator account', 'website-security-radar' ),
					sprintf( __( 'The administrator account "%s" was created recently.', 'website-security-radar' ), $user_login ),
					__( 'Confirm that this administrator account creation was expected.', 'website-security-radar' ),
					$admin
				);
			}

			$last_login = $this->get_last_login_timestamp( $admin->ID );

			if ( $last_login > 0 && $last_login < ( time() - DAY_IN_SECONDS * 180 ) ) {
				$issues[] = $this->issue(
					'low',
					'low',
					__( 'Inactive administrator account', 'website-security-radar' ),
					sprintf( __( 'The administrator account "%s" has not logged in recently according to available login metadata.', 'website-security-radar' ), $user_login ),
					__( 'Review unused administrator accounts and downgrade or remove access where appropriate.', 'website-security-radar' ),
					$admin
				);
			}

			if ( $this->has_suspicious_email_domain( $user_email ) ) {
				$issues[] = $this->issue(
					'low',
					'low',
					__( 'Administrator email domain may need review', 'website-security-radar' ),
					sprintf( __( 'The administrator account "%s" uses an email domain that may not match expected business domains.', 'website-security-radar' ), $user_login ),
					__( 'Review recommended. Confirm the email address belongs to a trusted administrator.', 'website-security-radar' ),
					$admin
				);
			}
		}

		foreach ( $this->get_recent_activity_events() as $event ) {
			if ( 'admin_created' === ( $event['type'] ?? '' ) ) {
				$issues[] = $this->issue(
					'high',
					'high',
					__( 'New administrator account recorded', 'website-security-radar' ),
					__( 'A new administrator account was created recently.', 'website-security-radar' ),
					__( 'Verify the account creation and remove or downgrade access if it was not expected.', 'website-security-radar' ),
					null,
					$event
				);
			}

			if ( 'admin_role_granted' === ( $event['type'] ?? '' ) ) {
				$issues[] = $this->issue(
					'high',
					'high',
					__( 'Administrator role granted recently', 'website-security-radar' ),
					__( 'A user was promoted to administrator recently.', 'website-security-radar' ),
					__( 'Confirm that the role change was intentional and performed by a trusted administrator.', 'website-security-radar' ),
					null,
					$event
				);
			}
		}

		return WSR_Helpers::apply_review_status( $this->dedupe_issues( $issues ) );
	}

	public function handle_user_register( int $user_id ): void {
		$user = get_userdata( $user_id );

		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}

		$this->record_event( 'admin_created', $user_id );
		$this->timeline_event(
			'admin_user_created',
			'high',
			__( 'A new administrator user was created.', 'website-security-radar' ),
			$user_id
		);
	}

	public function handle_set_user_role( int $user_id, string $role, array $old_roles ): void {
		if ( 'administrator' !== $role || in_array( 'administrator', $old_roles, true ) ) {
			return;
		}

		$this->record_event( 'admin_role_granted', $user_id );
		$this->timeline_event(
			'admin_role_granted',
			'high',
			__( 'A user role was changed to administrator.', 'website-security-radar' ),
			$user_id
		);
	}

	public function handle_profile_update( int $user_id, WP_User $old_user_data ): void {
		$user = get_userdata( $user_id );

		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}

		update_user_meta( $user_id, 'wsr_last_admin_activity', time() );

		$this->record_event( 'admin_profile_updated', $user_id );
		$this->timeline_event(
			'admin_profile_updated',
			'info',
			__( 'An administrator profile was updated.', 'website-security-radar' ),
			$user_id
		);
	}

	public function handle_login( string $user_login, WP_User $user ): void {
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}

		update_user_meta( $user->ID, 'wsr_last_login', time() );
	}

	private function issue( string $severity, string $confidence, string $issue, string $explanation, string $recommended_action, ?WP_User $user = null, array $event = array() ): array {
		$user_login = '';

		if ( $user ) {
			$user_login = sanitize_user( (string) $user->user_login, true );
		} elseif ( ! empty( $event['user_login'] ) ) {
			$user_login = sanitize_user( (string) $event['user_login'], true );
		}

		return array(
			'type'               => 'user security',
			'severity'           => $severity,
			'confidence'         => $confidence,
			'path'               => '',
			'user_login'         => $user_login,
			'user_identifier'    => $this->mask_user_identifier( $user_login ),
			'issue'              => $issue,
			'explanation'        => $explanation,
			'recommended_action' => $recommended_action,
			'detected_at'        => gmdate( 'c' ),
			'detected_date'      => gmdate( 'c' ),
			'line'               => 0,
		);
	}

	private function record_event( string $type, int $user_id ): void {
		$events   = get_option( WSR_Helpers::USER_ACTIVITY_OPTION, array() );
		$user     = get_userdata( $user_id );
		$events[] = array(
			'type'       => sanitize_key( $type ),
			'user_id'    => $user_id,
			'user_login' => $user ? sanitize_user( (string) $user->user_login, true ) : '',
			'timestamp'  => gmdate( 'c' ),
		);

		if ( count( $events ) > 100 ) {
			$events = array_slice( $events, -100 );
		}

		update_option( WSR_Helpers::USER_ACTIVITY_OPTION, $events, false );
	}

	private function timeline_event( string $type, string $severity, string $message, int $user_id ): void {
		WSR_Plugin::get_instance()->add_timeline_event(
			array(
				'type'          => $type,
				'severity'      => $severity,
				'message'       => $message,
				'actor_user_id' => $user_id,
			)
		);
	}

	private function get_recent_activity_events(): array {
		$events = get_option( WSR_Helpers::USER_ACTIVITY_OPTION, array() );

		if ( ! is_array( $events ) ) {
			return array();
		}

		return array_values(
			array_filter(
				$events,
				static function ( $event ): bool {
					if ( ! is_array( $event ) ) {
						return false;
					}

					$timestamp = strtotime( (string) ( $event['timestamp'] ?? '' ) );

					return $timestamp && $timestamp >= ( time() - DAY_IN_SECONDS * 7 );
				}
			)
		);
	}

	private function dedupe_issues( array $issues ): array {
		$unique = array();

		foreach ( $issues as $issue ) {
			$key            = WSR_Helpers::issue_identifier( $issue );
			$unique[ $key ] = $issue;
		}

		return array_values( $unique );
	}

	private function mask_user_identifier( string $user_login ): string {
		$user_login = trim( $user_login );

		if ( '' === $user_login ) {
			return '';
		}

		if ( strlen( $user_login ) <= 2 ) {
			return substr( $user_login, 0, 1 ) . '*';
		}

		return substr( $user_login, 0, 1 ) . str_repeat( '*', max( 1, strlen( $user_login ) - 2 ) ) . substr( $user_login, -1 );
	}

	private function has_suspicious_email_domain( string $email ): bool {
		if ( '' === $email || false === strpos( $email, '@' ) ) {
			return false;
		}

		$domain      = strtolower( substr( strrchr( $email, '@' ), 1 ) );
		$site_domain = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );

		if ( '' === $domain || '' === $site_domain ) {
			return false;
		}

		if ( $domain === $site_domain || str_ends_with( $domain, '.' . $site_domain ) ) {
			return false;
		}

		return in_array( $domain, array( 'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com' ), true );
	}

	private function get_last_login_timestamp( int $user_id ): int {
		foreach ( array( 'wsr_last_login', 'last_login', 'wp-last-login', 'last_login_timestamp' ) as $meta_key ) {
			$value = get_user_meta( $user_id, $meta_key, true );

			if ( is_numeric( $value ) ) {
				return (int) $value;
			}

			if ( is_string( $value ) ) {
				$timestamp = strtotime( $value );

				if ( $timestamp ) {
					return $timestamp;
				}
			}
		}

		return 0;
	}
}
