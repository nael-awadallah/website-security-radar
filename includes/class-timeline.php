<?php
/**
 * Timeline event storage.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Timeline {
	public function get_events( array $filters = array() ): array {
		$events = get_option( WSR_Helpers::TIMELINE_OPTION, array() );

		if ( ! is_array( $events ) ) {
			$events = array();
		}

		$events = array_values(
			array_filter(
				array_map( array( $this, 'normalize_event' ), $events )
			)
		);

		$type     = sanitize_key( (string) ( $filters['type'] ?? '' ) );
		$severity = sanitize_key( (string) ( $filters['severity'] ?? '' ) );

		if ( '' === $type && '' === $severity ) {
			return $events;
		}

		return array_values(
			array_filter(
				$events,
				static function ( array $event ) use ( $type, $severity ): bool {
					if ( '' !== $type && $event['type'] !== $type ) {
						return false;
					}

					if ( '' !== $severity && $event['severity'] !== $severity ) {
						return false;
					}

					return true;
				}
			)
		);
	}

	public function add_event( array $event ): void {
		$normalized = $this->normalize_event( $event );

		if ( empty( $normalized ) ) {
			return;
		}

		$events   = $this->get_events();
		array_unshift( $events, $normalized );
		$settings = WSR_Helpers::get_settings();
		$limit    = min(
			WSR_Helpers::TIMELINE_DEFAULT_LIMIT,
			max( 1, absint( $settings['timeline_event_limit'] ?? WSR_Helpers::TIMELINE_DEFAULT_LIMIT ) )
		);

		if ( count( $events ) > $limit ) {
			$events = array_slice( $events, 0, $limit );
		}

		update_option( WSR_Helpers::TIMELINE_OPTION, $events, false );
	}

	private function normalize_event( $event ): array {
		if ( ! is_array( $event ) ) {
			return array();
		}

		$type = sanitize_key( (string) ( $event['type'] ?? '' ) );

		if ( '' === $type ) {
			return array();
		}

		$severity = sanitize_key( (string) ( $event['severity'] ?? 'info' ) );

		if ( ! in_array( $severity, array( 'critical', 'high', 'medium', 'low', 'info' ), true ) ) {
			$severity = 'info';
		}

		$relative_path = '';

		if ( isset( $event['relative_path'] ) && '' !== (string) $event['relative_path'] ) {
			$relative_path = WSR_Helpers::normalize_relative_path( sanitize_text_field( (string) $event['relative_path'] ) );
		}

		return array(
			'id'            => sanitize_key( (string) ( $event['id'] ?? wp_generate_uuid4() ) ),
			'type'          => $type,
			'severity'      => $severity,
			'message'       => sanitize_text_field( (string) ( $event['message'] ?? '' ) ),
			'relative_path' => $relative_path,
			'timestamp'     => sanitize_text_field( (string) ( $event['timestamp'] ?? gmdate( 'c' ) ) ),
			'actor_user_id' => isset( $event['actor_user_id'] ) && '' !== (string) $event['actor_user_id'] ? absint( $event['actor_user_id'] ) : 0,
		);
	}
}
