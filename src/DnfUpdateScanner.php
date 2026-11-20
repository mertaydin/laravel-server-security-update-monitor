<?php

namespace MertAydin\ServerSecurityUpdateMonitor;

use Illuminate\Support\Facades\Process;
use RuntimeException;

class DnfUpdateScanner
{
    private function binary(): ?string
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            return null;
        }

        foreach ((array) config('server-security-update-monitor.dnf.binaries', [
            '/usr/bin/dnf', '/usr/bin/dnf5', '/usr/bin/yum',
            '/bin/dnf', '/bin/dnf5', '/bin/yum',
        ]) as $binary) {
            if (is_string($binary) && $binary !== '' && is_executable($binary)) {
                return $binary;
            }
        }

        return null;
    }

    public function scan(): array
    {
        $binary = $this->binary();

        if ($binary === null) {
            throw new RuntimeException('DNF/YUM package manager is not available on this server.');
        }

        $timeout = (int) config('server-security-update-monitor.command_timeout', 30);
        $jsonResult = Process::timeout($timeout)->run([$binary, '-q', '--cacheonly', 'check-upgrade', '--json']);
        $jsonPackages = null;

        // DNF5 exposes a documented machine-readable check-upgrade format.
        if (in_array($jsonResult->exitCode(), [0, 100], true)) {
            $decoded = json_decode($jsonResult->output(), true);
            if (is_array($decoded)) {
                $jsonPackages = self::parseDnf5UpgradeJson($jsonResult->output());
            }
        }

        if ($jsonPackages === null) {
            $result = Process::timeout($timeout)->run([$binary, '-q', '--cacheonly', 'check-update']);

            // DNF4/YUM return 100 when updates are available.
            if (! in_array($result->exitCode(), [0, 100], true)) {
                throw new RuntimeException('Unable to read DNF/YUM update list: '.trim($result->errorOutput().' '.$result->output()));
            }
            $lines = preg_split('/\r?\n/', $result->output());
        }

        $advisories = $this->advisories($binary, $timeout);
        $packages = [];

        if ($jsonPackages !== null) {
            foreach ($jsonPackages as $row) {
                $name = $row['name'];
                $advisory = self::matchingAdvisory($advisories[$name] ?? [], $name, $row['version'], $row['architecture']);
                $installed = Process::timeout(10)->run([
                    'rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', '--', $name,
                ]);
                $packages[] = [
                    'name' => $name,
                    'installed_version' => $installed->successful() ? trim($installed->output()) : null,
                    'candidate_version' => $row['version'],
                    'architecture' => $row['architecture'],
                    'repository' => $row['repository'],
                    'is_security' => ! empty($advisory),
                    'severity' => $advisory['severity'] ?? 'unknown',
                    'severity_label' => $advisory['severity_label'] ?? 'Unknown',
                    'type' => ! empty($advisory) ? 'Security update' : 'Package update',
                    'advisory_ids' => $advisory['advisory_ids'] ?? [],
                    'cves' => $advisory['cves'] ?? [],
                    'advisory_urls' => $advisory['advisory_urls'] ?? [],
                    'advisory_source' => ! empty($advisory) ? 'DNF/YUM updateinfo' : null,
                ];
            }
        } else {
            foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, 'Last metadata expiration check')
                || str_starts_with($line, 'Obsoleting Packages')) {
                continue;
            }

            if (! preg_match('/^(.+)\.([A-Za-z0-9_]+)\s+(\S+)\s+(\S+)$/', $line, $matches)) {
                continue;
            }

            $name = $matches[1];
            $advisory = self::matchingAdvisory($advisories[$name] ?? [], $name, $matches[3], $matches[2]);
            $installed = Process::timeout(10)->run([
                'rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', '--', $name,
            ]);

            $packages[] = [
                'name' => $name,
                'installed_version' => $installed->successful() ? trim($installed->output()) : null,
                'candidate_version' => $matches[3],
                'architecture' => $matches[2],
                'repository' => $matches[4],
                'is_security' => ! empty($advisory),
                'severity' => $advisory['severity'] ?? 'unknown',
                'severity_label' => $advisory['severity_label'] ?? 'Unknown',
                'type' => ! empty($advisory) ? 'Security update' : 'Package update',
                'advisory_ids' => $advisory['advisory_ids'] ?? [],
                'cves' => $advisory['cves'] ?? [],
                'advisory_urls' => $advisory['advisory_urls'] ?? [],
                'advisory_source' => ! empty($advisory) ? 'DNF/YUM updateinfo' : null,
            ];
            }
        }

        usort($packages, fn ($a, $b) => [$b['is_security'], $a['name']] <=> [$a['is_security'], $b['name']]);

        return [
            'host' => gethostname() ?: 'unknown',
            'package_manager' => strtoupper(basename($binary)),
            'checked_at' => now()->toIso8601String(),
            'total_updates' => count($packages),
            'security_updates' => count(array_filter($packages, fn ($package) => $package['is_security'])),
            'packages' => $packages,
        ];
    }

    /**
     * Parse DNF5's documented check-upgrade --json output.
     *
     * @return array<int, array{name: string, version: string, architecture: string, repository: string}>
     */
    public static function parseDnf5UpgradeJson(string $json): array
    {
        $sections = json_decode($json, true);
        if (! is_array($sections)) {
            return [];
        }

        $packages = [];
        foreach ($sections as $section => $rows) {
            if (str_contains(strtolower((string) $section), 'obsolet') || ! is_array($rows)) {
                continue;
            }

            foreach ($rows as $row) {
                if (! is_array($row)) {
                    continue;
                }

                $name = (string) ($row['name'] ?? '');
                $version = (string) ($row['evr'] ?? '');
                $architecture = (string) ($row['arch'] ?? '');
                $repository = (string) ($row['repository'] ?? '');
                if ($name === '' || $version === '' || $architecture === '') {
                    continue;
                }

                $packages[] = [
                    'name' => $name,
                    'version' => $version,
                    'architecture' => $architecture,
                    'repository' => $repository,
                ];
            }
        }

        return $packages;
    }

    /**
     * Parse the documented DNF5 JSON advisory list format.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function parseAdvisoryJson(string $json): array
    {
        $rows = json_decode($json, true);

        if (! is_array($rows)) {
            return [];
        }

        $packages = [];

        foreach ($rows as $row) {
            if (! is_array($row)) {
                continue;
            }

            $type = strtolower((string) ($row['type'] ?? $row['advisory_type'] ?? ''));
            if ($type !== 'security') {
                continue;
            }

            $nevra = (string) ($row['nevra'] ?? '');
            $name = self::packageNameFromNevra($nevra);
            if ($name === null) {
                continue;
            }

            $severity = self::normalizeSeverity((string) ($row['severity'] ?? $row['advisory_severity'] ?? ''));
            $id = (string) ($row['name'] ?? $row['advisory_name'] ?? '');
            $cves = [];

            foreach ((array) ($row['references'] ?? []) as $reference) {
                $referenceId = is_array($reference) ? (string) ($reference['reference_id'] ?? $reference['id'] ?? '') : (string) $reference;
                if (preg_match('/^CVE-\d{4}-\d{4,}$/i', $referenceId)) {
                    $cves[] = strtoupper($referenceId);
                }
            }

            self::mergeAdvisory($packages, $name, $id, $severity, $cves, $nevra);
        }

        return $packages;
    }

    /**
     * Parse the human-readable DNF4/YUM updateinfo info output.
     *
     * @return array<string, array<string, mixed>>
     */
    public static function parseAdvisoryInfo(string $output): array
    {
        $packages = [];
        $current = ['id' => '', 'type' => '', 'severity' => '', 'cves' => [], 'nevras' => []];

        $flush = static function () use (&$packages, &$current): void {
            if (strtolower($current['type']) === 'security') {
                foreach ($current['nevras'] as $nevra) {
                    $name = self::packageNameFromNevra($nevra);
                    if ($name !== null) {
                        self::mergeAdvisory($packages, $name, $current['id'], self::normalizeSeverity($current['severity']), $current['cves'], $nevra);
                    }
                }
            }
            $current = ['id' => '', 'type' => '', 'severity' => '', 'cves' => [], 'nevras' => []];
        };

        foreach (preg_split('/\r?\n/', $output) as $line) {
            if (preg_match('/^\s*Update ID\s*:\s*(\S+)/i', $line, $m)) {
                $flush();
                $current['id'] = $m[1];
            } elseif (preg_match('/^\s*Type\s*:\s*(\S+)/i', $line, $m)) {
                $current['type'] = strtolower($m[1]);
            } elseif (preg_match('/^\s*Severity\s*:\s*(.+)$/i', $line, $m)) {
                $current['severity'] = trim($m[1]);
            } elseif (preg_match_all('/CVE-\d{4}-\d{4,}/i', $line, $m)) {
                $current['cves'] = array_merge($current['cves'], array_map('strtoupper', $m[0]));
            } elseif (preg_match('/^\s*(?:\*\s*)?Packages\s*:\s*(.*)$/i', $line, $m)) {
                $current['nevras'] = array_merge($current['nevras'], self::extractNevras($m[1]));
            } elseif (preg_match('/^\s*\*\s*(\S+\.\S+)\s*$/', $line, $m)) {
                $current['nevras'][] = $m[1];
            }
        }

        $flush();

        return $packages;
    }

    private function advisories(string $binary, int $timeout): array
    {
        // DNF5 documents this JSON output, including advisory ID, severity, NEVRA and CVE references.
        $json = Process::timeout($timeout)->run([$binary, '-q', '--cacheonly', 'advisory', 'list', '--json', '--security', '--with-cve']);
        if ($json->successful()) {
            $parsed = self::parseAdvisoryJson($json->output());
            if ($parsed !== []) {
                return $parsed;
            }
        }

        // DNF4/YUM and older DNF5 compatibility path.
        $info = Process::timeout($timeout)->run([$binary, '-q', '--cacheonly', 'updateinfo', 'info', '--available', '--security']);

        return $info->successful() ? self::parseAdvisoryInfo($info->output()) : [];
    }

    private static function matchingAdvisory(array $advisory, string $packageName, string $candidateVersion, string $architecture): array
    {
        if ($advisory === [] || empty($advisory['nevras'])) {
            return [];
        }

        foreach ($advisory['nevras'] as $nevra) {
            if (self::packageNameFromNevra((string) $nevra) !== $packageName) {
                continue;
            }

            $separator = strrpos((string) $nevra, '.');
            if ($separator === false || substr((string) $nevra, $separator + 1) !== $architecture) {
                continue;
            }

            $evr = substr((string) $nevra, strlen($packageName) + 1, $separator - strlen($packageName) - 1);
            $normalizeEpoch = static fn (string $version): string => str_starts_with($version, '0:') ? substr($version, 2) : $version;

            if ($normalizeEpoch($evr) === $normalizeEpoch($candidateVersion)) {
                return $advisory;
            }
        }

        return [];
    }

    private static function mergeAdvisory(array &$packages, string $name, string $id, string $severity, array $cves, string $nevra = ''): void
    {
        $packages[$name] ??= ['severity' => 'unknown', 'severity_label' => 'Unknown', 'advisory_ids' => [], 'cves' => [], 'advisory_urls' => [], 'nevras' => []];

        if ($id !== '' && ! in_array($id, $packages[$name]['advisory_ids'], true)) {
            $packages[$name]['advisory_ids'][] = $id;
            // Keep one URL slot per advisory ID so dashboard indexes cannot drift.
            $packages[$name]['advisory_urls'][] = self::advisoryUrl($id);
        }

        if ($nevra !== '' && ! in_array($nevra, $packages[$name]['nevras'], true)) {
            $packages[$name]['nevras'][] = $nevra;
        }

        $packages[$name]['cves'] = array_values(array_unique(array_merge($packages[$name]['cves'], $cves)));

        $rank = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'unknown' => 0];
        if (($rank[$severity] ?? 0) > ($rank[$packages[$name]['severity']] ?? 0)) {
            $packages[$name]['severity'] = $severity;
            $packages[$name]['severity_label'] = ucfirst($severity);
        }
    }

    private static function advisoryUrl(string $id): ?string
    {
        if (preg_match('/^FEDORA-\\d{4}-/i', $id)) {
            return 'https://bodhi.fedoraproject.org/updates/'.rawurlencode($id);
        }

        if (preg_match('/^(RHSA|RLSA)-/i', $id)) {
            return 'https://access.redhat.com/errata/'.rawurlencode($id);
        }

        if (preg_match('/^ALAS-/', $id)) {
            return 'https://alas.aws.amazon.com/'.rawurlencode($id).'.html';
        }

        return null;
    }

    private static function normalizeSeverity(string $severity): string
    {
        return match (strtolower(trim($severity))) {
            'critical' => 'critical',
            'important', 'high' => 'high',
            'moderate', 'medium' => 'medium',
            'low' => 'low',
            default => 'unknown',
        };
    }

    private static function packageNameFromNevra(string $nevra): ?string
    {
        // NEVRA: name-[epoch:]version-release.arch; the package name may contain hyphens.
        if (! preg_match('/^(.+)-(?:(?:\d+):)?[^-]+-[^-]+\.[A-Za-z0-9_]+$/', $nevra, $matches)) {
            return null;
        }

        return $matches[1];
    }

    private static function extractNevras(string $value): array
    {
        preg_match_all('/[A-Za-z0-9_+.-]+-[^-\s]+-[^-\s]+\.[A-Za-z0-9_]+/', $value, $matches);

        return $matches[0] ?? [];
    }
}
