## Unreleased

- Run DNF5, DNF4 and YUM update/advisory queries with `--cacheonly`, allowing read-only scans under an unprivileged PHP-FPM account without refreshing package metadata.
- Expand native integration tests to run as a dedicated unprivileged user on Ubuntu 24.04, Debian 12, Fedora DNF5 and Rocky Linux 9 DNF4.
- Validate the exact APT sudoers boundary: allow only `/usr/bin/apt-get update`, verify the command with `visudo`, and assert that `apt-get upgrade` remains denied.
- Verify dpkg source-package metadata fields and the documented DNF5 extended advisory JSON schema.
- Document that DNF/YUM repository metadata must be refreshed separately by a privileged maintenance task.

## v0.2.6 - 2026-11-21

- Resolve OSV querybatch IDs to full vulnerability records, follow pagination and fetch each unique record once.
- Use release-scoped OSV ecosystems for Ubuntu LTS and Debian, and query the installed source-package version from dpkg metadata.
- Evaluate the complete ordered OSV version-event ranges with dpkg semantics before marking an APT candidate as fixed.
- Preserve Ubuntu priority labels, including Negligible, and keep OSV advisory IDs and links aligned.
- Add DNF5 JSON check-upgrade parsing and CVE-enabled advisory retrieval.
- Match DNF4/DNF5 security advisories against the exact candidate NEVRA and architecture; correct Fedora advisory URLs.
- Add native package-manager integration coverage for Ubuntu 24.04, Debian 12, Fedora DNF5 and Rocky Linux 9 DNF4.

## v0.2.5 - 2026-11-21

- Fix DNF/YUM executable discovery using the configured binary paths.
- Fetch full Git history in the security workflow so changed-file formatting checks can compare the base commit reliably.

## v0.2.4 - 2026-11-20

- Enrich Ubuntu and Debian APT package updates with OSV vulnerability records, CVE aliases and source references.
- Require an OSV fixed-version match against the APT candidate version before attaching a vulnerability record to an update.
- Parse DNF5 JSON security advisories and DNF4/YUM updateinfo details, including advisory IDs, CVEs and vendor severity.
- Add severity mapping for Critical, Important/High, Moderate/Medium and Low while preserving Unknown when source metadata is incomplete.
- Expand the dashboard with advisory/CVE links, package search, update-type filters and severity filters.
- Add parser regression tests and document the supported advisory data sources.

## v0.2.3 - 2026-11-19

- Show a hand cursor when hovering dashboard action buttons, including the APT package-list update button.
- Keep disabled action buttons visually non-interactive.

## v0.2.2 - 2026-11-19

- Add the shared security CI baseline: Composer audit, PHPStan/Larastan, changed-file Pint checks, PHP syntax validation, and automated tests.
- Add weekly Dependabot updates and resilient Composer dependency resolution.

## v0.2.1 - 2026-11-19

- Add security CI with Composer vulnerability auditing, PHPStan/Larastan analysis, Pint checks, PHP syntax validation, and automated tests.
- Add weekly Dependabot updates for Composer dependencies and GitHub Actions.

## v0.1.16 - 2026-11-19

- Add automated browser capture of the live server security dashboard and update the README screenshot.

## [0.1.15] - 2026-11-19

- Show the centered loading modal and animated progress bar before submitting the separate APT package-list refresh action.
- Display localized progress text and prevent duplicate refresh submissions.

## [0.1.14] - 2026-11-19

- Stop refreshing APT metadata during the normal Check now scan.
- Add a separate dashboard action to run `apt-get update` on demand, with progress feedback and result messages.
- Invalidate cached scan results after a successful metadata refresh.

## [0.1.13] - 2026-11-19

- Refresh APT package indexes with exactly `apt-get update` before each uncached APT scan.
- Add configurable APT metadata refresh and timeout settings.
- Support non-root PHP processes through non-interactive sudo, requiring a narrowly scoped sudoers rule; never run upgrade or install commands.

## [0.1.12] - 2026-11-19

- Add automatic Linux package-manager detection for Debian/Ubuntu APT and Fedora/RHEL-family DNF/YUM.
- Add read-only DNF/YUM update scanning, installed RPM version lookup and vendor security-advisory matching.
- Support DNF5 executable detection.
- Show the detected package-manager name in the dashboard and update the Artisan scan command.
- Document DNF/YUM support, configuration and read-only behavior; keep Alpine APK support planned.

## [0.1.11] - 2026-11-19

- Move language, theme and manual-scan interactions into a separately published JavaScript asset instead of inline Blade scripts.
- Load the external script with a versioned URL so deployments cannot silently keep using stale inline behavior.
- Add a Node.js syntax check for the dashboard JavaScript to CI.

## [0.1.10] - 2026-11-19

- Fix language switching by replacing the inline onchange handler with a registered JavaScript event listener.
- Fix light/dark/system theme switching and make localStorage failures non-blocking.
- Version the dashboard stylesheet URL to prevent stale published CSS from being reused.

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


