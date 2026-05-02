<?php
/**
 * File inventory scanner.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_File_Scanner {
	private array $settings;
	private array $ignore_list;
	private int $processed_files = 0;

	public function __construct( array $settings, array $ignore_list ) {
		$this->settings    = $settings;
		$this->ignore_list = $ignore_list;
	}

	public function scan(): array {
		$inventory = array();
		$this->processed_files = 0;
		$this->record_progress( 'running', __( 'Preparing scan roots.', 'website-security-radar' ) );

		foreach ( $this->get_scan_roots() as $root ) {
			if ( is_file( $root ) ) {
				$file_data = $this->build_file_entry( $root );

				if ( $file_data ) {
					$inventory[ $file_data['path'] ] = $file_data;
					++$this->processed_files;
					$this->maybe_record_batch_progress( $file_data['path'] );
				}

				continue;
			}

			if ( is_dir( $root ) ) {
				$this->scan_directory( $root, $inventory );
			}
		}

		ksort( $inventory );
		$this->record_progress( 'inventory_complete', __( 'File inventory completed.', 'website-security-radar' ), count( $inventory ) );

		return $inventory;
	}

	public function scan_path( string $relative_path ): array {
		$relative_path = WSR_Helpers::normalize_relative_path( $relative_path );

		if ( '' === $relative_path || false !== strpos( $relative_path, '..' ) || $this->should_skip_path( $relative_path ) ) {
			return array();
		}

		$absolute_path = wp_normalize_path( ABSPATH . ltrim( $relative_path, '/' ) );

		if ( ! is_file( $absolute_path ) ) {
			return array();
		}

		$file_data = $this->build_file_entry( $absolute_path );

		return $file_data ? array( $file_data['path'] => $file_data ) : array();
	}

	private function get_scan_roots(): array {
		$roots = array();

		if ( ! empty( $this->settings['scan_plugins'] ) ) {
			$roots[] = WP_CONTENT_DIR . '/plugins';
		}

		if ( ! empty( $this->settings['scan_themes'] ) ) {
			$roots[] = WP_CONTENT_DIR . '/themes';
		}

		if ( ! empty( $this->settings['scan_uploads'] ) ) {
			$roots[] = WP_CONTENT_DIR . '/uploads';
		}

		if ( ! empty( $this->settings['scan_root_files'] ) ) {
			$roots = array_merge(
				$roots,
				array(
					ABSPATH . 'index.php',
					ABSPATH . 'wp-config.php',
					ABSPATH . '.htaccess',
					ABSPATH . 'wp-blog-header.php',
					ABSPATH . 'wp-load.php',
				)
			);
		}

		return array_unique( $roots );
	}

	private function scan_directory( string $directory, array &$inventory ): void {
		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator(
					$directory,
					FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
				)
			);
		} catch ( Exception $exception ) {
			return;
		}

		foreach ( $iterator as $file ) {
			if ( ! $file instanceof SplFileInfo || ! $file->isFile() ) {
				continue;
			}

			$pathname = wp_normalize_path( $file->getPathname() );

			if ( $this->should_skip_path( $pathname ) ) {
				continue;
			}

			$file_data = $this->build_file_entry( $pathname );

			if ( $file_data ) {
				$inventory[ $file_data['path'] ] = $file_data;
				++$this->processed_files;
				$this->maybe_record_batch_progress( $file_data['path'] );
			}
		}
	}

	private function should_skip_path( string $path ): bool {
		$relative = WSR_Helpers::normalize_relative_path( $path );

		if ( WSR_Helpers::is_ignored_path( $relative, $this->ignore_list ) ) {
			return true;
		}

		$skip_paths = array(
			'wp-content/cache',
			'wp-content/backups',
			'wp-content/upgrade',
			'wp-content/uploads/backup',
			'node_modules',
			'vendor',
			'.git',
		);

		foreach ( $skip_paths as $skip_path ) {
			if ( false !== strpos( $relative, $skip_path ) ) {
				return true;
			}
		}

		return false;
	}

	private function build_file_entry( string $file ): ?array {
		if ( ! is_readable( $file ) || ! is_file( $file ) ) {
			return null;
		}

		$relative_path = WSR_Helpers::normalize_relative_path( $file );
		$size          = (int) filesize( $file );

		return array(
			'path'      => $relative_path,
			'size'      => $size,
			'modified'  => (int) filemtime( $file ),
			'hash'      => $this->should_hash_file( $file, $size ) ? hash_file( 'sha256', $file ) : '',
			'extension' => strtolower( pathinfo( $file, PATHINFO_EXTENSION ) ),
			'perms'     => substr( sprintf( '%o', (int) fileperms( $file ) ), -4 ),
		);
	}

	private function should_hash_file( string $file, int $size ): bool {
		if ( $size > (int) $this->settings['max_file_size'] ) {
			return false;
		}

		return is_readable( $file );
	}

	private function maybe_record_batch_progress( string $path ): void {
		$batch_size = min( 2000, max( 100, absint( $this->settings['scan_batch_size'] ?? 500 ) ) );

		if ( 0 !== $this->processed_files % $batch_size ) {
			return;
		}

		$this->record_progress(
			'running',
			sprintf(
				/* translators: %d: processed file count. */
				__( 'Scanned %d files so far.', 'website-security-radar' ),
				$this->processed_files
			),
			$this->processed_files,
			$path
		);
	}

	private function record_progress( string $status, string $message, int $processed = 0, string $path = '' ): void {
		update_option(
			WSR_Helpers::SCAN_STATUS_OPTION,
			array(
				'status'          => sanitize_key( $status ),
				'message'         => sanitize_text_field( $message ),
				'processed_files' => $processed,
				'current_path'    => WSR_Helpers::get_safe_display_path( $path ),
				'updated_at'      => gmdate( 'c' ),
			),
			false
		);
	}
}
