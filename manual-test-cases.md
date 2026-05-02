# Website Security Radar Manual Test Cases

Use these cases to validate the backdoor heuristics after running a manual scan in a non-production environment.

## Expected detections

1. `wp-content/uploads/2026/05/radio.php`
Expected:
- `Uploads Risk` or `Malware`
- `critical`
- `high` confidence
- Matched patterns include `uploads_php`, `php_in_date_or_image_folder`, `known_backdoor_filename`

2. `wp-content/uploads/2026/05/banner.jpg` containing `<?php eval(base64_decode(...)); ?>`
Expected:
- `Uploads Risk`
- `critical`
- `high` confidence
- Matched patterns include `disguised_image_php`

3. `wp-content/uploads/images/about.php`
Expected:
- `Suspicious Pattern` or `Malware` depending on contents
- `high` or above
- Matched patterns include `php_in_date_or_image_folder`, `suspicious_about_php`

4. `/shell.php` created or modified within the last 7 days
Expected:
- `Suspicious Pattern` or `Malware` depending on contents
- `high` or above
- Matched patterns include `known_backdoor_filename`, `recent_root_php`

5. `wp-content/plugins/some-plugin/a9f3d1c8ee.php` with `base64_decode()` and `eval()`
Expected:
- `Malware`
- `critical`
- Matched patterns include `random_php_filename`, `small_obfuscated_php`, `php_base64_decode`, `php_eval`

6. `wp-content/plugins/advanced-custom-fields-pro/assets/images/field-type-previews/field-preview-file.png` containing only a PHP marker
Expected:
- `Potential Risk`
- `low` or `medium`
- `low` confidence
- Not `critical`
- Context notes mention known plugin asset context

7. Unknown PHP file containing `eval(base64_decode(gzinflate(...)))`
Expected:
- `Malware`
- `critical`
- `high` confidence
- Matched patterns include `php_eval`, `php_base64_decode`, `php_gzinflate`

## Expected non-detections

1. `wp-includes/class-wp-cache.php`
Expected:
- Not flagged as a backdoor based on filename alone

2. `wp-admin/about.php`
Expected:
- Not flagged as a backdoor based on filename alone

3. Legitimate plugin or theme asset with only JavaScript `eval()` in a minified vendor file
Expected:
- `Potential Risk`
- `low` or `medium`
- `low` confidence

4. Normal media files in uploads without PHP tags
Expected:
- No disguised image detection

5. Known plugin file unchanged since baseline with one weak indicator
Expected:
- Downgraded to `Potential Risk` or ignored by existing duplicate/minified logic
- `low` confidence when reported

## New feature checks

Notes:
- API keys are stored in the WordPress database. Only administrators should have database access.
- Scheduled scans need WP-Cron or a server cron job that calls wp-cron.php.
- Very large sites may require higher PHP limits or future chunked scanning.
- Multisite scans run per site in this version; no network dashboard is available.

1. Enable vulnerability checks with `Mock Provider`
Expected:
- No remote request is required
- The dashboard shows `Ready` before the first check
- Clicking `Run Vulnerability Check` stores a `Vulnerability Checks` status block

2. Try to select `WPScan Vulnerability Database`
Expected:
- Provider option is disabled in the UI
- If submitted manually, settings fall back to an available provider or show `Provider not available yet`

3. Select `Patchstack`
Expected:
- Provider option is disabled in the UI
- No remote request is sent

4. Register a cron event with a suspicious hook like `hidden_mailer_eval`
Expected:
- `Cron`
- `high`
- Explanation says `Review recommended`

5. Create or promote a user to administrator
Expected:
- Timeline records the event
- Scan results include `User Security` findings for recent admin creation or promotion

6. Open `Export Client Report`
Expected:
- Report renders in HTML
- No absolute server paths or file contents are shown
- Browser print dialog can save it as PDF

7. Use the results page workflow controls
Expected:
- `Confidence` and `New since last scan` filters update results
- `Export CSV` downloads the filtered findings
- `Rescan path` updates findings for the selected path without reporting unrelated baseline files as deleted
