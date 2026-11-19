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

