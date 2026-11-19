## [0.1.9] - 2026-11-19

- Ensure the centered scan loading dialog and animated progress bar paint before navigating to the refreshed dashboard.
- Prevent repeated clicks while the server scan is starting.

## [0.1.8] - 2026-11-19

- Fix malformed PHP array syntax and mismatched quotation marks in Turkish, English and Arabic translation files.
- Extend CI PHP syntax validation to include all language files.

## [0.1.7] - 2026-11-19

- Fix the dashboard Blade ParseError caused by an incorrectly escaped Carbon class reference.

## [0.1.6] - 2026-11-19

- Replace Gate-based dashboard authorization with the `ServerSecurityUpdateMonitor::auth()` callback API.
- Add an illustrative dashboard preview image to the README.

## [0.1.5] - 2026-11-19

- Add light, dark and system appearance preferences.
- Add six dashboard languages with session-based language selection.
- Add dashboard authorization configuration.

# Changelog

## v0.1.4 - 2026-11-19

- Show a centered loading dialog with an animated progress bar while manually refreshing the server package scan.


## v0.1.3 - 2026-11-19

- Reduce the corner radius of the red/yellow package type and importance badges for a less pill-shaped appearance.


## v0.1.2 - 2026-11-19

- Add a dedicated `server-security-update-monitor-assets` publish tag.
- Publish the dashboard stylesheet to `public/vendor/server-security-update-monitor` and load it from the published asset path.
- Document both configuration and asset publishing commands in the README.


## v0.1.1 - 2026-11-19

- Add Laravel 13 compatibility for all Illuminate runtime dependencies.
- Update package development dependencies to support Orchestra Testbench 11 and PHPUnit 13.
- Publish the Laravel 13 compatibility fix as v0.1.1.


## v0.1.0 - 2026-11-19

- Do not infer High or Normal vulnerability severity from APT repository suites.
- Display severity as unknown until a trusted advisory is matched to the package and fixed version.

- Initial APT-based server package update monitor.
- Dashboard summary and package update table.
- Read-only Artisan scan command and cached results.
- Initial security-pocket detection from APT repository metadata.


