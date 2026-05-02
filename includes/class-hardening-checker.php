<?php
/**
 * Hardening checks.
 *
 * @package WebsiteSecurityRadar
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WSR_Hardening_Checker {
	public function run( array $inventory ): array {
		$issues = array();

		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$issues[] = $this->issue( 'medium', 'Hardening', 'wp-config.php', __( 'DISALLOW_FILE_EDIT is not enabled', 'website-security-radar' ), __( 'Disable plugin and theme file editing in wp-admin to reduce post-compromise abuse.', 'website-security-radar' ) );
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$issues[] = $this->issue( 'medium', 'Hardening', 'wp-config.php', __( 'WP_DEBUG is enabled', 'website-security-radar' ), __( 'Debug mode can expose sensitive details on production sites.', 'website-security-radar' ) );
		}

		if ( file_exists( ABSPATH . 'xmlrpc.php' ) ) {
			$issues[] = $this->issue( 'low', 'Hardening', 'xmlrpc.php', __( 'XML-RPC is present', 'website-security-radar' ), __( 'If not needed, confirm server rules or a plugin are blocking public XML-RPC access.', 'website-security-radar' ) );
		}

		if ( ! $this->root_htaccess_disables_indexes() ) {
			$issues[] = $this->issue( 'medium', 'Hardening', '.htaccess', __( 'Directory listing protection not detected', 'website-security-radar' ), __( 'Add an explicit `Options -Indexes` rule at the web root if your server supports it.', 'website-security-radar' ) );
		}

		$admin_count = $this->get_admin_count();
		if ( $admin_count > 3 ) {
			$issues[] = $this->issue( 'low', 'Hardening', 'Users', __( 'Multiple administrator accounts detected', 'website-security-radar' ), sprintf( __( 'The site currently has %d administrator accounts. Review whether all of them are expected.', 'website-security-radar' ), $admin_count ) );
		}

		if ( $this->is_core_outdated() ) {
			$issues[] = $this->issue( 'high', 'Updates', 'WordPress Core', __( 'WordPress core update available', 'website-security-radar' ), __( 'Apply available WordPress core updates after validation.', 'website-security-radar' ) );
		}

		$plugin_updates = $this->count_plugin_updates();
		if ( $plugin_updates > 0 ) {
			$issues[] = $this->issue( 'medium', 'Updates', 'Plugins', __( 'Plugin updates available', 'website-security-radar' ), sprintf( __( '%d installed plugin(s) have updates available.', 'website-security-radar' ), $plugin_updates ) );
		}

		$theme_updates = $this->count_theme_updates();
		if ( $theme_updates > 0 ) {
			$issues[] = $this->issue( 'medium', 'Updates', 'Themes', __( 'Theme updates available', 'website-security-radar' ), sprintf( __( '%d installed theme(s) have updates available.', 'website-security-radar' ), $theme_updates ) );
		}

		foreach ( array( 'wp-config.php', '.htaccess' ) as $sensitive_file ) {
			$absolute_path = ABSPATH . $sensitive_file;

			if ( file_exists( $absolute_path ) && $this->is_world_writable( $absolute_path ) ) {
				$issues[] = $this->issue( 'critical', 'Permissions', $sensitive_file, sprintf( __( '%s is world writable', 'website-security-radar' ), $sensitive_file ), __( 'Sensitive root files should not be writable by everyone.', 'website-security-radar' ) );
			}
		}

		foreach ( $inventory as $file ) {
			$path = $file['path'] ?? '';

			if ( '0777' === ( $file['perms'] ?? '' ) && 'php' === strtolower( $file['extension'] ?? '' ) ) {
				$issues[] = $this->issue( 'high', 'Permissions', $path, __( 'PHP file has 0777 permissions', 'website-security-radar' ), __( 'PHP files should not be world writable on production sites.', 'website-security-radar' ) );
			}
		}

		foreach ( $this->find_public_backup_files() as $backup_file ) {
			$issues[] = $this->issue( 'high', 'Exposure', $backup_file, __( 'Public backup file detected', 'website-security-radar' ), __( 'Backup archives in the web root can expose the full website if downloaded.', 'website-security-radar' ) );
		}

		return $issues;
	}

	private function issue( string $severity, string $type, string $path, string $issue, string $explanation ): array {
		return array(
			'type'          => strtolower( $type ),
			'severity'      => $severity,
			'path'          => $path,
			'issue'         => $issue,
			'explanation'   => $explanation,
			'line'          => 0,
			'detected_at'   => gmdate( 'c' ),
			'detected_date' => gmdate( 'c' ),
		);
	}

	private function root_htaccess_disables_indexes(): bool {
		$file = ABSPATH . '.htaccess';

		if ( ! is_readable( $file ) ) {
			return false;
		}

		$contents = @file_get_contents( $file );

		return false !== $contents && false !== stripos( $contents, 'Options -Indexes' );
	}

	private function get_admin_count(): int {
		$users = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
			)
		);

		return is_array( $users ) ? count( $users ) : 0;
	}

	private function is_core_outdated(): bool {
		$updates = get_site_transient( 'update_core' );
		return ! empty( $updates->updates ) && ! empty( $updates->updates[0]->response ) && 'latest' !== $updates->updates[0]->response;
	}

	private function count_plugin_updates(): int {
		$updates = get_site_transient( 'update_plugins' );
		return ! empty( $updates->response ) && is_array( $updates->response ) ? count( $updates->response ) : 0;
	}

	private function count_theme_updates(): int {
		$updates = get_site_transient( 'update_themes' );
		return ! empty( $updates->response ) && is_array( $updates->response ) ? count( $updates->response ) : 0;
	}

	private function is_world_writable( string $file ): bool {
		$perms = @fileperms( $file );

		if ( false === $perms ) {
			return false;
		}

		return 0 !== ( $perms & 0x0002 );
	}

	private function find_public_backup_files(): array {
		$matches    = array();
		$extensions = array( 'zip', 'sql', 'tar', 'gz', 'bak', 'old' );

		foreach ( $extensions as $extension ) {
			$files = glob( ABSPATH . '*.' . $extension );

			if ( is_array( $files ) ) {
				foreach ( $files as $file ) {
					$matches[] = WSR_Helpers::normalize_relative_path( $file );
				}
			}
		}

		return array_unique( $matches );
	}
}
