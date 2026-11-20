<?php

namespace MertAydin\ServerSecurityUpdateMonitor;

use Illuminate\Support\Facades\Process;
use RuntimeException;

class DnfUpdateScanner
{
    public function scan(): array
    {
        $binary = $this->binary();

        if ($binary === null) {
            throw new RuntimeException('DNF/YUM package manager is not available on this server.');
        }

        $timeout = (int) config('server-security-update-monitor.command_timeout', 30);
        $result = Process::timeout($timeout)->run([$binary, '-q', 'check-update']);

        // DNF/YUM return 100 when updates are available.
        if (! in_array($result->exitCode(), [0, 100], true)) {
            throw new RuntimeException('Unable to read DNF/YUM update list: '.trim($result->errorOutput().' '.$result->output()));
        }

        $advisories = $this->advisories($binary, $timeout);
        $packages = [];

        foreach (preg_split('/\r?\n/', $result->output()) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, 'Last metadata expiration check')
                || str_starts_with($line, 'Obsoleting Packages')) {
                continue;
            }

            if (! preg_match('/^(.+)\.([A-Za-z0-9_]+)\s+(\S+)\s+(\S+)$/', $line, $matches)) {
                continue;
            }

            $name = $matches[1];
            $advisory = $advisories[$name] ?? [];
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

            self::mergeAdvisory($packages, $name, $id, $severity, $cves);
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
                        self::mergeAdvisory($packages, $name, $current['id'], self::normalizeSeverity($current['severity']), $current['cves']);
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
        $json = Process::timeout($timeout)->run([$binary, '-q', 'advisory', 'list', '--json', '--security']);
        if ($json->successful()) {
            $parsed = self::parseAdvisoryJson($json->output());
            if ($parsed !== []) {
                return $parsed;
            }
        }

        // DNF4/YUM and older DNF5 compatibility path.
        $info = Process::timeout($timeout)->run([$binary, '-q', 'updateinfo', 'info', '--available', '--security']);

        return $info->successful() ? self::parseAdvisoryInfo($info->output()) : [];
    }

    private static function mergeAdvisory(array &$packages, string $name, string $id, string $severity, array $cves): void
    {
        $packages[$name] ??= ['severity' => 'unknown', 'severity_label' => 'Unknown', 'advisory_ids' => [], 'cves' => [], 'advisory_urls' => []];

        if ($id !== '' && ! in_array($id, $packages[$name]['advisory_ids'], true)) {
            $packages[$name]['advisory_ids'][] = $id;
            $url = self::advisoryUrl($id);
            if ($url !== null) {
                $packages[$name]['advisory_urls'][] = $url;
            }
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
