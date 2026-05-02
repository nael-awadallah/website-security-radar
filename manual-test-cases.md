# Website Security Radar Manual Test Cases

Use these cases to validate the backdoor heuristics after running a manual scan in a non-production environment.

## Expected detections

1. `wp-content/uploads/2026/05/radio.php`
Expected:
- `Malware`
- `critical`
- Matched patterns include `uploads_php`, `php_in_date_or_image_folder`, `known_backdoor_filename`

2. `wp-content/uploads/2026/05/banner.jpg` containing `<?php eval(base64_decode(...)); ?>`
Expected:
- `Malware`
- `critical`
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

## Expected non-detections

1. `wp-includes/class-wp-cache.php`
Expected:
- Not flagged as a backdoor based on filename alone

2. `wp-admin/about.php`
Expected:
- Not flagged as a backdoor based on filename alone

3. Legitimate plugin or theme asset with only JavaScript `eval()` in a minified vendor file
Expected:
- Existing low-confidence logic remains in place

4. Normal media files in uploads without PHP tags
Expected:
- No disguised image detection
