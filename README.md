# Laravel Server Security Update Monitor

A Laravel dashboard for Linux server package updates and security patches. The first supported package manager is APT on Debian and Ubuntu.

[![Tests](https://github.com/mertaydin/laravel-server-security-update-monitor/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/mertaydin/laravel-server-security-update-monitor/actions/workflows/tests.yml)
[![License](https://img.shields.io/github/license/mertaydin/laravel-server-security-update-monitor)](LICENSE)

## Dashboard

The dashboard provides an at-a-glance view of pending updates and a package table with installed version, candidate version, repository suite, update classification and severity status.

- Total pending package updates.
- Security-repository updates, separated from routine updates.
- Installed and candidate package versions.
- Security updates sorted before routine updates.
- A manual scan action and cached scan results.
- An Artisan command for scheduled or manual scans.

## Requirements

- PHP 8.2+
- Laravel 10, 11, 12 or 13
- Debian or Ubuntu with APT and dpkg-query
- The PHP process must be allowed to execute read-only package inspection commands.

## Installation

```bash
composer require mertaydin/laravel-server-security-update-monitor
php artisan vendor:publish --tag=server-security-update-monitor-config
php artisan vendor:publish --tag=server-security-update-monitor-assets
```

Open `/server-security-monitor` while authenticated. The default route middleware is `web` and `auth`; add an application-specific administrator check or network restriction before exposing operational details.

## Scan

Run a scan manually:

```bash
php artisan server-security-monitor:check
```

The dashboard also scans when no cached snapshot exists. Use your normal server maintenance process to refresh APT package indexes (for example, `apt-get update`). This package does not refresh package indexes automatically.

## Security classification and severity

A package is marked as a security update only when the suite shown by APT matches the configured security suite patterns (by default, `-security` or `/security`). A newer package version alone is not treated as evidence of a vulnerability.

**Severity is intentionally shown as unknown in this initial release.** APT's upgrade list does not provide reliable CVSS scores or vendor advisory severity. The package will not label every security-pocket update as Critical or High without matching an authoritative advisory to the package and fixed version. CVE/USN/DSA enrichment is planned.

## Package manager support

| Package manager | Status |
| --- | --- |
| APT (Debian/Ubuntu) | Initial support |
| DNF/YUM | Planned |
| APK | Planned |

## Configuration

The published `config/server-security-update-monitor.php` file controls:

| Key | Default | Description |
| --- | --- | --- |
| `route.enabled` | `true` | Registers the dashboard route. |
| `route.prefix` | `server-security-monitor` | Dashboard URL prefix. |
| `route.middleware` | `web, auth` | Middleware protecting the dashboard. |
| `cache.key` | `server-security-update-monitor.packages` | Cached scan key. |
| `cache.seconds` | `900` | Cached snapshot lifetime. |
| `command_timeout` | `30` | APT command timeout in seconds. |
| `apt.enabled` | `true` | Enables APT scanning. |
| `apt.security_suites` | `-security, /security` | Suite patterns considered security repositories. |

## Safety

- Read-only package inspection only.
- Does not run `apt-get update`, `apt upgrade`, `apt install`, or `dpkg -i`.
- Does not install, remove, or upgrade packages.
- Does not infer CVSS severity from repository names or version numbers.

## License

MIT. See [LICENSE](LICENSE).

## Support

- [Changelog](CHANGELOG.md)
- [GitHub releases](https://github.com/mertaydin/laravel-server-security-update-monitor/releases)
- [Issues](https://github.com/mertaydin/laravel-server-security-update-monitor/issues)
