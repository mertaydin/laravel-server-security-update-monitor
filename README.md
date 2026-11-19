# Laravel Server Security Update Monitor

A Laravel dashboard for Linux server package updates and security patches.

**Initial target:** Debian/Ubuntu servers using APT. This package is read-only and never installs or upgrades packages.

## Features
- Dashboard summary cards for pending and security updates.
- Installed and candidate package versions.
- Security classification from APT repository metadata, not version-number guesses.
- Severity labels: Critical, High, Normal and Low (initial implementation uses conservative High/Normal labels).
- Manual refresh, cached scan results and an Artisan scan command.

## Requirements
- PHP 8.2+
- Laravel 10, 11 or 12
- Debian/Ubuntu with APT, dpkg-query and permission to execute read-only inspection commands.

## Installation
```bash
composer require mertaydin/laravel-server-security-update-monitor
php artisan vendor:publish --tag=server-security-update-monitor-config
```

Open /server-security-monitor while authenticated. Protect this route with your application's authentication and authorization middleware.

## Scan
```bash
php artisan server-security-monitor:check
```

Run apt-get update separately through your normal maintenance process so repository metadata stays current.

## Security classification
An update is marked as security-related only when its APT suite/origin matches configured security pockets (for example, Ubuntu's -security). A newer version alone is not evidence of a vulnerability. CVE/vendor advisory enrichment and exact Critical/High/Normal/Low scoring are planned follow-up work.

## Package managers
| Manager | Status |
|---|---|
| APT (Debian/Ubuntu) | Initial target |
| DNF/YUM | Planned |
| APK | Planned |

## License
MIT
