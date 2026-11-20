<?php

namespace MertAydin\ServerSecurityUpdateMonitor;

use Illuminate\Support\Facades\Process;
use RuntimeException;

class AptUpdateScanner
{
    public function scan(): array
    {
        if (PHP_OS_FAMILY !== 'Linux' || ! is_executable('/usr/bin/apt-get')) {
            throw new RuntimeException('APT package manager is not available on this server.');
        }

        $result = Process::timeout((int) config('server-security-update-monitor.command_timeout', 30))
            ->run('apt list --upgradable 2>/dev/null');

        if (! $result->successful()) {
            throw new RuntimeException('Unable to read APT upgrade list: '.$result->errorOutput());
        }

        $packages = [];
        foreach (preg_split('/\r?\n/', trim($result->output())) as $line) {
            if ($line === '' || str_starts_with($line, 'Listing...')) {
                continue;
            }

            if (! preg_match('/^([^\/]+)\/([^\s]+)\s+([^\s]+)\s+([^\s]+)/', $line, $matches)) {
                continue;
            }

            $name = $matches[1];
            $suite = $matches[2];
            $security = $this->isSecuritySuite($suite);
            $installed = Process::timeout(10)->run([
                '/usr/bin/dpkg-query', '-W', '-f=${Version}', '--', $name,
            ]);
            $source = Process::timeout(10)->run([
                '/usr/bin/dpkg-query', '-W', '-f=${source:Package}', '--', $name,
            ]);

            $packages[] = [
                'name' => $name,
                'source_package' => $source->successful() && trim($source->output()) !== '' ? trim($source->output()) : $name,
                'installed_version' => $installed->successful() ? trim($installed->output()) : null,
                'candidate_version' => $matches[3],
                'architecture' => $matches[4],
                'repository' => $suite,
                'is_security' => $security,
                'severity' => 'unknown',
                'severity_label' => $security ? 'Security update; severity not verified' : 'Unknown',
                'type' => $security ? 'Security update' : 'Package update',
                'advisory_ids' => [],
                'cves' => [],
                'advisory_urls' => [],
                'advisory_source' => null,
            ];
        }

        $this->enrichWithOsv($packages);

        usort($packages, fn ($a, $b) => [$b['is_security'], $a['name']] <=> [$a['is_security'], $b['name']]);

        return [
            'host' => gethostname() ?: 'unknown',
            'package_manager' => 'APT',
            'checked_at' => now()->toIso8601String(),
            'total_updates' => count($packages),
            'security_updates' => count(array_filter($packages, fn ($package) => $package['is_security'])),
            'packages' => $packages,
        ];
    }

    /**
     * Enrich installed package versions with Ubuntu/Debian OSV records.
     * A network or feed failure is non-fatal; repository classification remains available.
     */
    private function enrichWithOsv(array &$packages): void
    {
        if (! config('server-security-update-monitor.apt.osv.enabled', true) || $packages === []) {
            return;
        }

        $os = is_readable('/etc/os-release') ? parse_ini_file('/etc/os-release', false, INI_SCANNER_RAW) : [];
        $id = strtolower((string) ($os['ID'] ?? ''));
        $version = (string) ($os['VERSION_ID'] ?? '');
        $ecosystem = null;

        if ($id === 'ubuntu' && preg_match('/^\d+\.\d+$/', $version)) {
            $ecosystem = 'Ubuntu-'.$version;
        } elseif ($id === 'debian' && preg_match('/^(\d+)/', $version, $matches)) {
            $ecosystem = 'Debian';
            $version = $matches[1];
        }

        if ($ecosystem === null) {
            return;
        }

        $queries = [];
        $packageIndexes = [];
        foreach ($packages as $index => $package) {
            if (empty($package['installed_version'])) {
                continue;
            }

            $queries[] = [
                'package' => ['name' => $package['source_package'], 'ecosystem' => $ecosystem],
                'version' => $package['installed_version'],
            ];
            $packageIndexes[] = $index;
        }

        if ($queries === []) {
            return;
        }

        $timeout = max(1, (int) config('server-security-update-monitor.apt.osv.timeout', 5));
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nAccept: application/json\r\nUser-Agent: Laravel-Server-Security-Update-Monitor\r\n",
                'content' => json_encode(['queries' => $queries], JSON_THROW_ON_ERROR),
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents('https://api.osv.dev/v1/querybatch', false, $context);
        if (! is_string($response)) {
            return;
        }

        $decoded = json_decode($response, true);
        if (! is_array($decoded) || ! is_array($decoded['results'] ?? null)) {
            return;
        }

        foreach ($packageIndexes as $queryIndex => $packageIndex) {
            $vulnerabilities = $decoded['results'][$queryIndex]['vulns'] ?? [];
            foreach (is_array($vulnerabilities) ? $vulnerabilities : [] as $vulnerability) {
                if (! is_array($vulnerability)) {
                    continue;
                }

                $id = (string) ($vulnerability['id'] ?? '');
                $aliases = array_values(array_filter((array) ($vulnerability['aliases'] ?? []), fn ($alias) => preg_match('/^CVE-\d{4}-\d{4,}$/i', (string) $alias) === 1));
                $cves = array_values(array_unique(array_merge(
                    preg_match('/^CVE-\d{4}-\d{4,}$/i', $id) ? [strtoupper($id)] : [],
                    array_map('strtoupper', $aliases)
                )));

                if (! $this->candidateFixesVulnerability($packages[$packageIndex]['candidate_version'], $vulnerability)) {
                    continue;
                }

                $priority = 'unknown';
                foreach ((array) ($vulnerability['severity'] ?? []) as $severity) {
                    if (is_array($severity) && strtoupper((string) ($severity['type'] ?? '')) === 'UBUNTU') {
                        $priority = $this->normalizeSeverity((string) ($severity['score'] ?? ''));
                        break;
                    }
                }

                $references = [];
                foreach ((array) ($vulnerability['references'] ?? []) as $reference) {
                    if (is_array($reference) && filter_var($reference['url'] ?? null, FILTER_VALIDATE_URL)) {
                        $references[] = $reference['url'];
                    }
                }

                $packages[$packageIndex]['is_security'] = true;
                $packages[$packageIndex]['type'] = 'Security update';
                $packages[$packageIndex]['advisory_source'] = 'OSV';
                $packages[$packageIndex]['advisory_ids'] = array_values(array_unique(array_merge(
                    $packages[$packageIndex]['advisory_ids'],
                    $id !== '' ? [$id] : []
                )));
                $packages[$packageIndex]['cves'] = array_values(array_unique(array_merge($packages[$packageIndex]['cves'], $cves)));
                $packages[$packageIndex]['advisory_urls'] = array_values(array_unique(array_merge($packages[$packageIndex]['advisory_urls'], $references)));

                if ($priority !== 'unknown') {
                    $packages[$packageIndex]['severity'] = $priority;
                    $packages[$packageIndex]['severity_label'] = ucfirst($priority).' (Ubuntu)';
                }
            }
        }
    }

    private function candidateFixesVulnerability(string $candidateVersion, array $vulnerability): bool
    {
        $fixedVersions = [];

        foreach ((array) ($vulnerability['affected'] ?? []) as $affected) {
            foreach ((array) ($affected['ranges'] ?? []) as $range) {
                foreach ((array) ($range['events'] ?? []) as $event) {
                    if (isset($event['fixed']) && is_string($event['fixed']) && $event['fixed'] !== '') {
                        $fixedVersions[] = $event['fixed'];
                    }
                }
            }
        }

        if ($fixedVersions === []) {
            return false;
        }

        foreach (array_unique($fixedVersions) as $fixedVersion) {
            $comparison = Process::timeout(5)->run([
                '/usr/bin/dpkg', '--compare-versions', $candidateVersion, 'ge', $fixedVersion,
            ]);

            if ($comparison->successful()) {
                return true;
            }
        }

        return false;
    }

    private function normalizeSeverity(string $severity): string
    {
        return match (strtolower(trim($severity))) {
            'critical' => 'critical',
            'high' => 'high',
            'medium' => 'medium',
            'low' => 'low',
            default => 'unknown',
        };
    }

    private function isSecuritySuite(string $suite): bool
    {
        foreach ((array) config('server-security-update-monitor.apt.security_suites', ['-security', '/security']) as $needle) {
            if ($needle !== '' && str_contains(strtolower($suite), strtolower($needle))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Refresh APT metadata only. This deliberately never upgrades or installs packages.
     */
    public function updatePackageLists(): void
    {
        $command = ['/usr/bin/apt-get', 'update'];

        // PHP-FPM/Artisan commonly run as www-data. Permit only this exact command
        // through a narrowly scoped sudoers rule; never fall back to interactive sudo.
        if (! function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            $command = ['/usr/bin/sudo', '-n', ...$command];
        }

        $result = Process::timeout((int) config('server-security-update-monitor.apt.update_timeout', 300))
            ->run($command);

        if (! $result->successful()) {
            $details = trim($result->errorOutput() ?: $result->output());
            throw new RuntimeException('Unable to run apt-get update. Ensure the PHP process has permission to execute only /usr/bin/apt-get update. '.$details);
        }
    }
}
