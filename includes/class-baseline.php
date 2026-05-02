<?php
/**
 * Baseline comparison.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Baseline {
	private const STORE_VERSION = 2;

	public function migrate(): array {
		$store = get_option( WSR_Helpers::BASELINE_OPTION, array() );

		if ( $this->is_store_format( $store ) ) {
			return $store;
		}

		$migrated = $this->migrate_legacy_store( $store );

		if ( ! empty( $migrated['baselines'] ) ) {
			update_option( WSR_Helpers::BASELINE_OPTION, $migrated, false );
		}

		return $migrated;
	}

	public function get(): array {
		$active = $this->get_active();

		if ( empty( $active ) ) {
			return array();
		}

		return array(
			'id'                 => $active['id'],
			'label'              => $active['label'],
			'created_at'         => $active['created_at'],
			'created_by_user_id' => $active['created_by_user_id'],
			'file_count'         => $active['file_count'],
			'hash_summary'       => $active['hash_summary'],
			'metadata'           => $active['metadata'],
			'files'              => $active['files'],
		);
	}

	public function get_all(): array {
		$store     = $this->get_store();
		$baselines = array_values( $store['baselines'] ?? array() );

		usort(
			$baselines,
			static function ( array $left, array $right ): int {
				return strcmp( (string) ( $right['created_at'] ?? '' ), (string) ( $left['created_at'] ?? '' ) );
			}
		);

		return $baselines;
	}

	public function get_active(): array {
		$store      = $this->get_store();
		$active_id  = sanitize_key( (string) ( $store['active_id'] ?? '' ) );
		$baselines  = $store['baselines'] ?? array();

		if ( '' !== $active_id && isset( $baselines[ $active_id ] ) ) {
			return $baselines[ $active_id ];
		}

		if ( empty( $baselines ) ) {
			return array();
		}

		$first = reset( $baselines );

		return is_array( $first ) ? $first : array();
	}

	public function get_by_id( string $baseline_id ): array {
		$store       = $this->get_store();
		$baseline_id = sanitize_key( $baseline_id );

		if ( '' === $baseline_id ) {
			return array();
		}

		return $store['baselines'][ $baseline_id ] ?? array();
	}

	public function save( array $inventory, string $label = '', int $user_id = 0 ): array {
		$store      = $this->get_store();
		$created_at = gmdate( 'c' );
		$baseline   = array(
			'id'                 => sanitize_key( wp_generate_uuid4() ),
			'label'              => $this->sanitize_label( $label ),
			'created_at'         => $created_at,
			'created_by_user_id' => absint( $user_id ),
			'file_count'         => count( $inventory ),
			'hash_summary'       => $this->build_hash_summary( $inventory ),
			'metadata'           => $this->build_metadata( $inventory ),
			'files'              => $inventory,
		);

		$store['version']                 = self::STORE_VERSION;
		$store['active_id']               = $baseline['id'];
		$store['baselines'][ $baseline['id'] ] = $baseline;
		$store                            = $this->enforce_baseline_limit( $store );

		update_option( WSR_Helpers::BASELINE_OPTION, $store, false );

		return $baseline;
	}

	public function set_active( string $baseline_id ): bool {
		$store       = $this->get_store();
		$baseline_id = sanitize_key( $baseline_id );

		if ( '' === $baseline_id || empty( $store['baselines'][ $baseline_id ] ) ) {
			return false;
		}

		$store['active_id'] = $baseline_id;
		update_option( WSR_Helpers::BASELINE_OPTION, $store, false );

		return true;
	}

	public function delete( string $baseline_id ): bool {
		$store       = $this->get_store();
		$baseline_id = sanitize_key( $baseline_id );

		if ( '' === $baseline_id || empty( $store['baselines'][ $baseline_id ] ) ) {
			return false;
		}

		unset( $store['baselines'][ $baseline_id ] );

		if ( empty( $store['baselines'] ) ) {
			$store['active_id'] = '';
		} elseif ( $baseline_id === ( $store['active_id'] ?? '' ) ) {
			$store['active_id'] = $this->get_latest_baseline_id( $store['baselines'] );
		}

		update_option( WSR_Helpers::BASELINE_OPTION, $store, false );

		return true;
	}

	public function compare( array $inventory ): array {
		$baseline         = $this->get_active();
		$baseline_files   = $baseline['files'] ?? array();
		$new_files        = array();
		$modified_files   = array();
		$modified_details = array();
		$deleted_files    = array();

		foreach ( $inventory as $path => $file_data ) {
			if ( ! isset( $baseline_files[ $path ] ) ) {
				$new_files[] = $path;
				continue;
			}

			$baseline_file = $baseline_files[ $path ];
			$current_hash  = $file_data['hash'] ?? '';
			$stored_hash   = $baseline_file['hash'] ?? '';

			if ( '' !== $current_hash && '' !== $stored_hash ) {
				if ( $current_hash !== $stored_hash ) {
					$modified_files[]          = $path;
					$modified_details[ $path ] = $this->build_modified_file_details( $path, $baseline_file, $file_data );
				}

				continue;
			}

			if (
				(int) ( $baseline_file['modified'] ?? 0 ) !== (int) $file_data['modified'] ||
				(int) ( $baseline_file['size'] ?? 0 ) !== (int) $file_data['size']
			) {
				$modified_files[]          = $path;
				$modified_details[ $path ] = $this->build_modified_file_details( $path, $baseline_file, $file_data );
			}
		}

		foreach ( $baseline_files as $path => $file_data ) {
			if ( ! $this->is_path_in_current_scan_scope( (string) $path ) ) {
				continue;
			}

			if ( ! isset( $inventory[ $path ] ) ) {
				$deleted_files[] = $path;
			}
		}

		return array(
			'has_baseline'        => ! empty( $baseline_files ),
			'baseline_id'         => sanitize_key( (string) ( $baseline['id'] ?? '' ) ),
			'label'               => sanitize_text_field( (string) ( $baseline['label'] ?? '' ) ),
			'created_at'          => sanitize_text_field( (string) ( $baseline['created_at'] ?? '' ) ),
			'created_by_user_id'  => absint( $baseline['created_by_user_id'] ?? 0 ),
			'file_count'          => absint( $baseline['file_count'] ?? 0 ),
			'hash_summary'        => sanitize_text_field( (string) ( $baseline['hash_summary'] ?? '' ) ),
			'metadata'            => is_array( $baseline['metadata'] ?? null ) ? $baseline['metadata'] : array(),
			'new_files'           => $new_files,
			'modified'            => $modified_files,
			'modified_details'    => $modified_details,
			'deleted'             => $deleted_files,
		);
	}

	public function compare_path( string $path, array $inventory ): array {
		$path       = WSR_Helpers::normalize_relative_path( $path );
		$comparison = $this->compare( $inventory );

		if ( '' === $path ) {
			return $comparison;
		}

		$comparison['new_files'] = array_values(
			array_filter(
				$comparison['new_files'],
				static function ( string $candidate ) use ( $path ): bool {
					return WSR_Helpers::normalize_relative_path( $candidate ) === $path;
				}
			)
		);
		$comparison['modified'] = array_values(
			array_filter(
				$comparison['modified'],
				static function ( string $candidate ) use ( $path ): bool {
					return WSR_Helpers::normalize_relative_path( $candidate ) === $path;
				}
			)
		);
		$comparison['modified_details'] = array_intersect_key( $comparison['modified_details'], array_flip( $comparison['modified'] ) );

		if ( empty( $inventory ) ) {
			$active_files = $this->get_active()['files'] ?? array();
			$comparison['deleted'] = isset( $active_files[ $path ] ) ? array( $path ) : array();
		} else {
			$comparison['deleted'] = array_values(
				array_filter(
					$comparison['deleted'],
					static function ( string $candidate ) use ( $path ): bool {
						return WSR_Helpers::normalize_relative_path( $candidate ) === $path;
					}
				)
			);
		}

		return $comparison;
	}

	private function get_store(): array {
		$store = $this->migrate();

		if ( ! $this->is_store_format( $store ) ) {
			return $this->empty_store();
		}

		$version = isset( $store['version'] ) ? absint( $store['version'] ) : 1;

		if ( $version > self::STORE_VERSION || $version < 1 ) {
			if ( function_exists( 'error_log' ) ) {
				error_log( 'Website Security Radar baseline store version is unsupported.' );
			}

			return $this->empty_store();
		}

		$store['version'] = self::STORE_VERSION;

		if ( empty( $store['active_id'] ) && ! empty( $store['baselines'] ) ) {
			$store['active_id'] = $this->get_latest_baseline_id( $store['baselines'] );
			update_option( WSR_Helpers::BASELINE_OPTION, $store, false );
		}

		return $store;
	}

	private function is_store_format( $store ): bool {
		return is_array( $store ) && isset( $store['baselines'] ) && is_array( $store['baselines'] ) && array_key_exists( 'active_id', $store );
	}

	private function migrate_legacy_store( $store ): array {
		$migrated = $this->empty_store();

		if ( ! is_array( $store ) || empty( $store['files'] ) || ! is_array( $store['files'] ) ) {
			return $migrated;
		}

		$baseline = array(
			'id'                 => sanitize_key( wp_generate_uuid4() ),
			'label'              => sprintf(
				/* translators: %s: month and year. */
				__( 'Imported baseline - %s', 'website-security-radar' ),
				wp_date( 'F Y', strtotime( (string) ( $store['created_at'] ?? gmdate( 'c' ) ) ) )
			),
			'created_at'         => sanitize_text_field( (string) ( $store['created_at'] ?? gmdate( 'c' ) ) ),
			'created_by_user_id' => 0,
			'file_count'         => count( $store['files'] ),
			'hash_summary'       => $this->build_hash_summary( $store['files'] ),
			'metadata'           => array(
				'migrated_legacy_baseline' => 1,
			),
			'files'              => $store['files'],
		);

		$migrated['active_id']               = $baseline['id'];
		$migrated['baselines'][ $baseline['id'] ] = $baseline;

		return $migrated;
	}

	private function empty_store(): array {
		return array(
			'version'   => self::STORE_VERSION,
			'active_id' => '',
			'baselines' => array(),
		);
	}

	private function enforce_baseline_limit( array $store ): array {
		$settings = WSR_Helpers::get_settings();
		$limit    = min( 50, max( 1, absint( $settings['max_baselines'] ?? 10 ) ) );

		if ( count( $store['baselines'] ?? array() ) <= $limit ) {
			return $store;
		}

		$baselines = array_values( $store['baselines'] );
		usort(
			$baselines,
			static function ( array $left, array $right ): int {
				return strcmp( (string) ( $left['created_at'] ?? '' ), (string) ( $right['created_at'] ?? '' ) );
			}
		);

		foreach ( $baselines as $baseline ) {
			if ( count( $store['baselines'] ) <= $limit ) {
				break;
			}

			$id = sanitize_key( (string) ( $baseline['id'] ?? '' ) );

			if ( '' === $id || $id === ( $store['active_id'] ?? '' ) ) {
				continue;
			}

			unset( $store['baselines'][ $id ] );
		}

		return $store;
	}

	private function sanitize_label( string $label ): string {
		$label = sanitize_text_field( $label );
		return '' !== $label ? $label : WSR_Helpers::get_default_baseline_label();
	}

	private function get_latest_baseline_id( array $baselines ): string {
		usort(
			$baselines,
			static function ( array $left, array $right ): int {
				return strcmp( (string) ( $right['created_at'] ?? '' ), (string) ( $left['created_at'] ?? '' ) );
			}
		);

		return sanitize_key( (string) ( $baselines[0]['id'] ?? '' ) );
	}

	private function build_hash_summary( array $inventory ): string {
		$rows = array();

		foreach ( $inventory as $path => $file_data ) {
			$rows[] = implode(
				'|',
				array(
					WSR_Helpers::normalize_relative_path( (string) $path ),
					sanitize_text_field( (string) ( $file_data['hash'] ?? '' ) ),
					(int) ( $file_data['modified'] ?? 0 ),
					(int) ( $file_data['size'] ?? 0 ),
				)
			);
		}

		sort( $rows, SORT_STRING );

		return hash( 'sha256', implode( "\n", $rows ) );
	}

	private function build_metadata( array $inventory ): array {
		$settings         = WSR_Helpers::get_settings();
		$extension_counts = array();

		foreach ( $inventory as $file_data ) {
			$extension = strtolower( (string) ( $file_data['extension'] ?? '' ) );
			$key       = '' !== $extension ? $extension : 'none';

			if ( ! isset( $extension_counts[ $key ] ) ) {
				$extension_counts[ $key ] = 0;
			}

			++$extension_counts[ $key ];
		}

		arsort( $extension_counts, SORT_NUMERIC );

		return array(
			'scan_scope' => array(
				'scan_uploads'    => ! empty( $settings['scan_uploads'] ) ? 1 : 0,
				'scan_themes'     => ! empty( $settings['scan_themes'] ) ? 1 : 0,
				'scan_plugins'    => ! empty( $settings['scan_plugins'] ) ? 1 : 0,
				'scan_root_files' => ! empty( $settings['scan_root_files'] ) ? 1 : 0,
			),
			'max_file_size' => absint( $settings['max_file_size'] ?? 0 ),
			'extensions'    => array_slice( $extension_counts, 0, 12, true ),
		);
	}

	private function is_path_in_current_scan_scope( string $path ): bool {
		$settings = WSR_Helpers::get_settings();
		$path     = WSR_Helpers::normalize_relative_path( $path );

		if ( WSR_Helpers::is_uploads_path( $path ) ) {
			return ! empty( $settings['scan_uploads'] );
		}

		if ( WSR_Helpers::is_plugin_path( $path ) ) {
			return ! empty( $settings['scan_plugins'] );
		}

		if ( WSR_Helpers::is_theme_path( $path ) ) {
			return ! empty( $settings['scan_themes'] );
		}

		return ! empty( $settings['scan_root_files'] ) && in_array(
			$path,
			array(
				'index.php',
				'wp-config.php',
				'.htaccess',
				'wp-blog-header.php',
				'wp-load.php',
			),
			true
		);
	}

	private function build_modified_file_details( string $path, array $baseline_file, array $current_file ): array {
		$relative_path = WSR_Helpers::get_safe_display_path( $path );
		$extension     = $current_file['extension'] ?? $baseline_file['extension'] ?? strtolower( pathinfo( $relative_path, PATHINFO_EXTENSION ) );

		return array(
			'relative_path' => $relative_path,
			'extension'     => sanitize_text_field( (string) $extension ),
			'old'           => array(
				'hash'     => sanitize_text_field( (string) ( $baseline_file['hash'] ?? '' ) ),
				'modified' => isset( $baseline_file['modified'] ) ? (int) $baseline_file['modified'] : 0,
				'size'     => isset( $baseline_file['size'] ) ? (int) $baseline_file['size'] : 0,
			),
			'new'           => array(
				'hash'     => sanitize_text_field( (string) ( $current_file['hash'] ?? '' ) ),
				'modified' => isset( $current_file['modified'] ) ? (int) $current_file['modified'] : 0,
				'size'     => isset( $current_file['size'] ) ? (int) $current_file['size'] : 0,
			),
			'content_diff'  => array(
				'enabled'   => false,
				'available' => false,
				'chunks'    => array(),
			),
		);
	}
}
