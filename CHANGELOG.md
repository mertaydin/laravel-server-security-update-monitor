# Changelog

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
