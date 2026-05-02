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
	public function get(): array {
		$baseline = get_option( WSR_Helpers::BASELINE_OPTION, array() );
		return is_array( $baseline ) ? $baseline : array();
	}

	public function save( array $inventory ): array {
		$baseline = array(
			'created_at' => gmdate( 'c' ),
			'files'      => $inventory,
		);

		update_option( WSR_Helpers::BASELINE_OPTION, $baseline, false );

		return $baseline;
	}

	public function compare( array $inventory ): array {
		$baseline         = $this->get();
		$baseline_files   = $baseline['files'] ?? array();
		$new_files        = array();
		$modified_files   = array();
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
					$modified_files[] = $path;
				}

				continue;
			}

			if (
				(int) ( $baseline_file['modified'] ?? 0 ) !== (int) $file_data['modified'] ||
				(int) ( $baseline_file['size'] ?? 0 ) !== (int) $file_data['size']
			) {
				$modified_files[] = $path;
			}
		}

		foreach ( $baseline_files as $path => $file_data ) {
			if ( ! isset( $inventory[ $path ] ) ) {
				$deleted_files[] = $path;
			}
		}

		return array(
			'has_baseline' => ! empty( $baseline_files ),
			'created_at'   => $baseline['created_at'] ?? '',
			'new_files'    => $new_files,
			'modified'     => $modified_files,
			'deleted'      => $deleted_files,
		);
	}
}
