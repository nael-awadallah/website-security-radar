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

	public function __construct( array $settings, array $ignore_list ) {
		$this->settings    = $settings;
		$this->ignore_list = $ignore_list;
	}

	public function scan(): array {
		$inventory = array();

		foreach ( $this->get_scan_roots() as $root ) {
			if ( is_file( $root ) ) {
				$file_data = $this->build_file_entry( $root );

				if ( $file_data ) {
					$inventory[ $file_data['path'] ] = $file_data;
				}

				continue;
			}

			if ( is_dir( $root ) ) {
				$this->scan_directory( $root, $inventory );
			}
		}

		ksort( $inventory );

		return $inventory;
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
}
