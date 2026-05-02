=== Website Security Radar — Malware Scanner, File Monitor & Hardening Check ===
Contributors: nael2015
Tags: security, malware scanner, wordpress security, file monitor, hardening, file integrity, security dashboard
Requires at least: 6.2
Tested up to: 6.8
Requires PHP: 8.0
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Website Security Radar is a lightweight WordPress security plugin that monitors file changes, detects suspicious code patterns, and provides clear hardening insights -- without automatic file modifications and with all remote checks disabled by default.

== Description ==

Website Security Radar helps you understand what is happening inside your WordPress installation -- without complexity or heavy resource usage.

It is designed for developers, agencies, and site owners who want a clean and transparent security dashboard.

Unlike many security plugins, this tool focuses on **visibility and control**, not automated actions.

== Key Features ==

**File Integrity Monitoring**
* Scan plugins, themes, uploads, and critical WordPress core files
* Detect new, modified, and deleted files
* Compare against a trusted baseline snapshot

**Malware Pattern Detection**
* Identify suspicious PHP, JS, and HTML patterns
* Detect obfuscated code, injected scripts, and common spam indicators
* Detect hidden backdoor heuristics such as uploads PHP, disguised image shells, and suspicious backdoor filenames
* Highlight risky files with severity levels

**Security Hardening Checks**
* Detect common WordPress misconfigurations
* Review debug settings, XML-RPC exposure, file permissions, and more
* Provide actionable recommendations

**Optional Vulnerability Checks**
* Disabled by default and fully opt-in
* Check installed WordPress core, plugins, and themes against the selected provider
* Only send component slugs and versions when enabled

**Operational Review**
* Review suspicious cron hooks and unusually frequent schedules
* Monitor risky administrator account activity
* Export a client-friendly print report that can be saved as PDF

**Security Dashboard**
* Simple and clear security score
* Overview of detected issues
* Prioritized recommendations for improvement

**Alerts & Monitoring**
* Manual scan via AJAX
* Daily scheduled scans using WP-Cron
* Email alerts for critical issues

**Baseline System**
* Create a trusted snapshot of your website
* Track changes over time
* Reduce false positives

**Triage Workflow**
* Mark findings as reviewed
* Ignore known-safe files or paths
* Keep your results clean and actionable

== What Makes It Different ==

* No hidden remote requests
* No data collection or tracking
* No automatic file changes or risky cleanup actions
* Lightweight and developer-friendly
* Designed for transparency and control

== Who Is This For ==

* WordPress developers and freelancers
* Agencies managing multiple websites
* Site owners who want visibility into file changes
* Anyone who prefers manual control over automated security tools

== Important Notes ==

* This plugin does not remove malware automatically
* It does not modify or delete files
* It focuses on detection, monitoring, and reporting

== Installation ==

1. Upload the `website-security-radar` folder to `/wp-content/plugins/`.
2. Activate the plugin through the WordPress Plugins screen.
3. Open `Security Radar` in wp-admin.
4. Run your first scan.
5. Create a baseline once your site is in a trusted state.

== FAQ ==

= Does this plugin remove malware automatically? =

No. This plugin is designed for detection and analysis only.

= Does it send data to external services? =

By default, no. All scanning is performed locally within your WordPress installation unless you explicitly enable vulnerability checks.

= Does this plugin collect data or track users? =

No. The plugin does not track users, does not phone home, and does not send file contents or user data to external services.

= Are remote checks enabled by default? =

No. Vulnerability checks are disabled unless enabled.

= What data is sent when vulnerability checks are enabled? =

Only the WordPress core version plus installed plugin and theme slugs and versions are sent to the selected provider. File contents, user data, database data, and absolute server paths are never sent.

= Does it scan large files? =

Files larger than the configured size limit are skipped for content scanning to maintain performance.

= Can it break my website? =

No. The plugin does not modify files or configurations automatically.

== Changelog ==

= 1.1.0 =
* Added optional vulnerability check integration with explicit opt-in, provider selection, privacy notice, masked API key display, and manual AJAX trigger.
* Added cron hook review checks and suspicious administrator activity monitoring.
* Added a print-friendly client security report export with white-label settings.

= 1.0.0 =
* Initial release with file scanning, baseline comparison, malware detection, hardening checks, scheduled scans, alerts, and dashboard UI.
* Added hidden backdoor heuristics for suspicious filenames, uploads PHP, disguised image shells, recent root PHP changes, and small obfuscated droppers.
