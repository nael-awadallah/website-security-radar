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

		if ( ! defined( 'DISALLOW_FILE_MODS' ) || ! DISALLOW_FILE_MODS ) {
			$issues[] = $this->issue( 'low', 'Hardening', 'wp-config.php', __( 'DISALLOW_FILE_MODS is not enabled', 'website-security-radar' ), __( 'Consider disabling plugin/theme installation and updates from wp-admin on managed production sites with a deployment workflow.', 'website-security-radar' ) );
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$issues[] = $this->issue( 'medium', 'Hardening', 'wp-config.php', __( 'WP_DEBUG is enabled', 'website-security-radar' ), __( 'Debug mode can expose sensitive details on production sites.', 'website-security-radar' ) );
		}

		if ( file_exists( WP_CONTENT_DIR . '/debug.log' ) ) {
			$issues[] = $this->issue( 'high', 'Exposure', 'wp-content/debug.log', __( 'Debug log file exists in wp-content', 'website-security-radar' ), __( 'Public debug logs can expose paths, emails, tokens, or database details if the web server allows downloads.', 'website-security-radar' ) );
		}

		if ( file_exists( ABSPATH . 'xmlrpc.php' ) ) {
			$issues[] = $this->issue( 'low', 'Hardening', 'xmlrpc.php', __( 'XML-RPC is present', 'website-security-radar' ), __( 'If not needed, confirm server rules or a plugin are blocking public XML-RPC access.', 'website-security-radar' ) );
		}

		foreach ( array( 'wp-admin/install.php', 'wp-admin/upgrade.php' ) as $install_file ) {
			if ( file_exists( ABSPATH . $install_file ) ) {
				$issues[] = $this->issue( 'low', 'Exposure', $install_file, __( 'WordPress install or upgrade endpoint is present', 'website-security-radar' ), __( 'These files are normal in WordPress core, but production sites should confirm public access is restricted by WordPress/server controls.', 'website-security-radar' ) );
			}
		}

		if ( $this->rest_user_route_is_publicly_registered() ) {
			$issues[] = $this->issue( 'low', 'Exposure', 'wp-json/wp/v2/users', __( 'REST users route is registered', 'website-security-radar' ), __( 'User enumeration may be possible if no authentication, firewall, or REST restriction is applied.', 'website-security-radar' ) );
		}

		if ( ! $this->uploads_php_execution_appears_blocked() ) {
			$issues[] = $this->issue( 'medium', 'Hardening', 'wp-content/uploads', __( 'Uploads PHP execution block not detected', 'website-security-radar' ), __( 'Add server rules to prevent PHP execution in uploads unless the site has a documented need for it.', 'website-security-radar' ) );
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

		foreach ( $this->get_missing_security_headers() as $header ) {
			$issues[] = $this->issue( 'low', 'Hardening', home_url( '/' ), sprintf( __( 'Security header missing: %s', 'website-security-radar' ), $header ), __( 'Review response headers and add this control at the server, CDN, or application layer if compatible with the site.', 'website-security-radar' ) );
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

	private function uploads_php_execution_appears_blocked(): bool {
		$checks = array(
			WP_CONTENT_DIR . '/uploads/.htaccess' => array( 'deny from all', 'require all denied', 'sethandler none', 'php_flag engine off' ),
			WP_CONTENT_DIR . '/uploads/web.config' => array( 'requestFiltering', 'fileExtensions', '.php' ),
			WP_CONTENT_DIR . '/uploads/nginx.conf' => array( 'deny all', 'location' ),
		);

		foreach ( $checks as $file => $needles ) {
			if ( ! is_readable( $file ) ) {
				continue;
			}

			$contents = strtolower( (string) @file_get_contents( $file ) );

			foreach ( $needles as $needle ) {
				if ( false !== strpos( $contents, strtolower( $needle ) ) ) {
					return true;
				}
			}
		}

		return false;
	}

	private function rest_user_route_is_publicly_registered(): bool {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return false;
		}

		$routes = rest_get_server()->get_routes();

		return isset( $routes['/wp/v2/users'] ) || isset( $routes['/wp/v2/users/(?P<id>[\d]+)'] );
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
		$extensions = array( 'zip', 'sql', 'tar', 'gz', 'bak', 'old', '7z', 'rar', 'tgz', 'bz2' );

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

	private function get_missing_security_headers(): array {
		$response = wp_remote_head(
			home_url( '/' ),
			array(
				'timeout'     => 5,
				'redirection' => 2,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array();
		}

		$required = array(
			'x-frame-options'           => 'X-Frame-Options',
			'x-content-type-options'    => 'X-Content-Type-Options',
			'referrer-policy'           => 'Referrer-Policy',
			'content-security-policy'   => 'Content-Security-Policy',
			'strict-transport-security' => 'Strict-Transport-Security',
		);
		$missing = array();

		foreach ( $required as $header_key => $header_label ) {
			if ( '' === (string) wp_remote_retrieve_header( $response, $header_key ) ) {
				$missing[] = $header_label;
			}
		}

		return $missing;
	}
}
