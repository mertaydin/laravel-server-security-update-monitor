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
                '/usr/bin/dpkg-query', '-W', '-f=${Version}\\t${source:Package}\\t${source:Version}', '--', $name,
            ]);
            $metadata = preg_split('/\\t/', trim($installed->output()));
            $installedVersion = $installed->successful() && ! empty($metadata[0]) ? $metadata[0] : null;
            $sourcePackage = ! empty($metadata[1]) ? $metadata[1] : $name;
            $sourceVersion = ! empty($metadata[2]) ? $metadata[2] : $installedVersion;

            $packages[] = [
                'name' => $name,
                'source_package' => $sourcePackage,
                'source_version' => $sourceVersion,
                'installed_version' => $installedVersion,
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
                'reference_urls' => [],
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

        if ($id === 'ubuntu') {
            $ecosystem = $this->ubuntuOsvEcosystem($version);
        } elseif ($id === 'debian') {
            $ecosystem = $this->debianOsvEcosystem($version);
        }

        if ($ecosystem === null) {
            return;
        }

        $queries = [];
        $packageIndexes = [];
        foreach ($packages as $index => $package) {
            if (empty($package['installed_version']) || empty($package['source_package'])) {
                continue;
            }

            $queries[] = [
                'package' => ['name' => $package['source_package'], 'ecosystem' => $ecosystem],
                'version' => $package['source_version'] ?: $package['installed_version'],
            ];
            $packageIndexes[] = $index;
        }

        if ($queries === []) {
            return;
        }

        $timeout = max(1, (int) config('server-security-update-monitor.apt.osv.timeout', 5));
        $idsByPackage = [];
        $pending = [];

        // OSV querybatch accepts at most 1,000 queries. Keep each request bounded.
        foreach (array_chunk($queries, 500) as $chunkIndex => $chunk) {
            $indexes = array_slice($packageIndexes, $chunkIndex * 500, count($chunk));
            $this->collectOsvIds($chunk, $indexes, $timeout, $idsByPackage);
        }

        if ($idsByPackage === []) {
            return;
        }

        // querybatch intentionally returns only vulnerability IDs and modified timestamps.
        // Fetch each unique record once to obtain affected ranges, aliases, severity and references.
        $details = [];
        $allIds = array_values(array_unique(array_merge(...array_values($idsByPackage))));
        foreach ($allIds as $id) {
            $detail = $this->fetchOsvVulnerability($id, $timeout);
            if ($detail !== null) {
                $details[$id] = $detail;
            }
        }

        foreach ($idsByPackage as $packageIndex => $ids) {
            foreach ($ids as $id) {
                $vulnerability = $details[$id] ?? null;
                if (! is_array($vulnerability)) {
                    continue;
                }

                $package = $packages[$packageIndex];
                if (! $this->candidateFixesVulnerability(
                    $package['source_package'],
                    $ecosystem,
                    $package['candidate_version'],
                    $vulnerability
                )) {
                    continue;
                }

                $vulnerabilityId = (string) ($vulnerability['id'] ?? $id);
                $aliases = array_values(array_filter((array) ($vulnerability['aliases'] ?? []), fn ($alias) => preg_match('/^CVE-\d{4}-\d{4,}$/i', (string) $alias) === 1));
                $cves = array_values(array_unique(array_merge(
                    preg_match('/^CVE-\d{4}-\d{4,}$/i', $vulnerabilityId) ? [strtoupper($vulnerabilityId)] : [],
                    array_map('strtoupper', $aliases)
                )));

                $priority = $this->normalizeSeverity((string) (
                    $vulnerability['database_specific']['severity']
                    ?? $vulnerability['database_specific']['ubuntu_priority']
                    ?? ''
                ));

                $ubuntuPriority = '';
                foreach ((array) ($vulnerability['severity'] ?? []) as $severity) {
                    if (is_array($severity) && strtoupper((string) ($severity['type'] ?? '')) === 'UBUNTU') {
                        $ubuntuPriority = (string) ($severity['score'] ?? '');
                        $priority = $this->normalizeSeverity($ubuntuPriority);
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
                if ($vulnerabilityId !== '' && ! in_array($vulnerabilityId, $packages[$packageIndex]['advisory_ids'], true)) {
                    $packages[$packageIndex]['advisory_ids'][] = $vulnerabilityId;
                    $packages[$packageIndex]['advisory_urls'][] = 'https://osv.dev/vulnerability/'.rawurlencode($vulnerabilityId);
                }
                $packages[$packageIndex]['cves'] = array_values(array_unique(array_merge($packages[$packageIndex]['cves'], $cves)));
                $packages[$packageIndex]['reference_urls'] = array_values(array_unique(array_merge($packages[$packageIndex]['reference_urls'], $references)));

                if ($priority !== 'unknown') {
                    $packages[$packageIndex]['severity'] = $priority;
                    $packages[$packageIndex]['severity_label'] = strtolower($ubuntuPriority) === 'negligible'
                        ? 'Negligible'
                        : ucfirst($priority);
                }
            }
        }
    }

    /**
     * Collect OSV vulnerability IDs, following per-query pagination tokens.
     *
     * @param  array<int, array<string, mixed>>  $queries
     * @param  array<int, int>  $packageIndexes
     * @param  array<int, array<int, string>>  $idsByPackage
     */
    private function collectOsvIds(array $queries, array $packageIndexes, int $timeout, array &$idsByPackage): void
    {
        $pending = [];
        foreach ($queries as $offset => $query) {
            $pending[] = ['query' => $query, 'index' => $packageIndexes[$offset]];
        }

        while ($pending !== []) {
            $batch = array_splice($pending, 0, 500);
            $payload = ['queries' => array_map(
                static fn ($item) => $item['query'] + (isset($item['page_token']) ? ['page_token' => $item['page_token']] : []),
                $batch
            )];
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => "Content-Type: application/json\r\nAccept: application/json\r\nUser-Agent: Laravel-Server-Security-Update-Monitor\r\n",
                    'content' => json_encode($payload, JSON_THROW_ON_ERROR),
                    'timeout' => $timeout,
                    'ignore_errors' => true,
                ],
            ]);
            $response = @file_get_contents('https://api.osv.dev/v1/querybatch', false, $context);
            if (! is_string($response)) {
                continue;
            }

            $decoded = json_decode($response, true);
            if (! is_array($decoded) || ! is_array($decoded['results'] ?? null)) {
                continue;
            }

            foreach ($batch as $offset => $item) {
                $result = $decoded['results'][$offset] ?? [];
                foreach ((array) ($result['vulns'] ?? []) as $vulnerability) {
                    if (is_array($vulnerability) && ! empty($vulnerability['id'])) {
                        $idsByPackage[$item['index']][] = (string) $vulnerability['id'];
                    }
                }

                if (! empty($result['next_page_token'])) {
                    $pending[] = [
                        'query' => $item['query'],
                        'index' => $item['index'],
                        'page_token' => (string) $result['next_page_token'],
                    ];
                }
            }
        }

        foreach ($idsByPackage as $index => $ids) {
            $idsByPackage[$index] = array_values(array_unique($ids));
        }
    }

    private function fetchOsvVulnerability(string $id, int $timeout): ?array
    {
        if (! preg_match('/^[A-Za-z0-9._:-]+$/', $id)) {
            return null;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: application/json\r\nUser-Agent: Laravel-Server-Security-Update-Monitor\r\n",
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);
        $response = @file_get_contents('https://api.osv.dev/v1/vulns/'.rawurlencode($id), false, $context);
        if (! is_string($response)) {
            return null;
        }

        $decoded = json_decode($response, true);

        return is_array($decoded) ? $decoded : null;
    }

    private function debianOsvEcosystem(string $version): ?string
    {
        if (! preg_match('/^(\d+)/', $version, $matches)) {
            return null;
        }

        return 'Debian:'.$matches[1];
    }

    private function ubuntuOsvEcosystem(string $version): ?string
    {
        if (! preg_match('/^\d+\.\d+$/', $version)) {
            return null;
        }

        // Ubuntu's OSV ecosystem identifiers explicitly mark LTS releases.
        $ltsReleases = ['14.04', '16.04', '18.04', '20.04', '22.04', '24.04', '26.04'];

        return 'Ubuntu:'.$version.(in_array($version, $ltsReleases, true) ? ':LTS' : '');
    }

    private function candidateFixesVulnerability(string $packageName, string $ecosystem, string $candidateVersion, array $vulnerability): bool
    {
        $matchedPackage = false;
        $candidateResolved = false;

        foreach ((array) ($vulnerability['affected'] ?? []) as $affected) {
            $affectedPackage = $affected['package'] ?? [];
            if (($affectedPackage['name'] ?? null) !== $packageName || ($affectedPackage['ecosystem'] ?? null) !== $ecosystem) {
                continue;
            }

            $matchedPackage = true;

            if (in_array($candidateVersion, (array) ($affected['versions'] ?? []), true)) {
                return false;
            }

            foreach ((array) ($affected['ranges'] ?? []) as $range) {
                if (strtoupper((string) ($range['type'] ?? '')) !== 'ECOSYSTEM') {
                    continue;
                }

                $rangeAffected = false;
                $rangeResolved = false;

                foreach ((array) ($range['events'] ?? []) as $event) {
                    if (isset($event['introduced']) && is_string($event['introduced'])) {
                        $rangeAffected = $this->dpkgVersionCompare($candidateVersion, 'ge', $event['introduced']);
                    } elseif (isset($event['fixed']) && is_string($event['fixed'])) {
                        if ($this->dpkgVersionCompare($candidateVersion, 'ge', $event['fixed'])) {
                            $rangeAffected = false;
                            $rangeResolved = true;
                        }
                    } elseif (isset($event['last_affected']) && is_string($event['last_affected'])) {
                        if ($this->dpkgVersionCompare($candidateVersion, 'gt', $event['last_affected'])) {
                            $rangeAffected = false;
                            $rangeResolved = true;
                        }
                    }
                }

                if ($rangeAffected) {
                    return false;
                }

                $candidateResolved = $candidateResolved || $rangeResolved;
            }
        }

        return $matchedPackage && $candidateResolved;
    }

    private function dpkgVersionCompare(string $left, string $operator, string $right): bool
    {
        $comparison = Process::timeout(5)->run([
            '/usr/bin/dpkg', '--compare-versions', $left, $operator, $right,
        ]);

        return $comparison->successful();
    }

    private function normalizeSeverity(string $severity): string
    {
        return match (strtolower(trim($severity))) {
            'critical' => 'critical',
            'important', 'high' => 'high',
            'moderate', 'medium' => 'medium',
            'low', 'unimportant', 'negligible' => 'low',
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
