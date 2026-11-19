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

        // DNF/YUM use exit code 100 to indicate that updates are available.
        if (! in_array($result->exitCode(), [0, 100], true)) {
            throw new RuntimeException('Unable to read DNF/YUM update list: '.trim($result->errorOutput().' '.$result->output()));
        }

        $securityPackages = $this->securityPackageNames($binary, $timeout);
        $packages = [];

        foreach (preg_split('/\r?\n/', $result->output()) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, 'Last metadata expiration check')
                || str_starts_with($line, 'Obsoleting Packages')) {
                continue;
            }

            // DNF/YUM check-update rows: package.arch version repository.
            if (! preg_match('/^(.+)\.([A-Za-z0-9_]+)\s+(\S+)\s+(\S+)$/', $line, $matches)) {
                continue;
            }

            $name = $matches[1];
            $security = isset($securityPackages[$name]);
            $installed = Process::timeout(10)->run([
                'rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', '--', $name,
            ]);

            $packages[] = [
                'name' => $name,
                'installed_version' => $installed->successful() ? trim($installed->output()) : null,
                'candidate_version' => $matches[3],
                'architecture' => $matches[2],
                'repository' => $matches[4],
                'is_security' => $security,
                'severity' => 'unknown',
                'severity_label' => $security ? 'Security update; severity not verified' : 'No security advisory matched',
                'type' => $security ? 'Security update' : 'Package update',
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

    private function binary(): ?string
    {
        foreach ((array) config('server-security-update-monitor.dnf.binaries', ['/usr/bin/dnf', '/usr/bin/yum', '/bin/dnf', '/bin/yum']) as $binary) {
            if (is_string($binary) && is_executable($binary)) {
                return $binary;
            }
        }

        return null;
    }

    /**
     * Return package names included in vendor-provided security advisories.
     * If advisory metadata is unavailable, classify no packages as security updates.
     */
    private function securityPackageNames(string $binary, int $timeout): array
    {
        $result = Process::timeout($timeout)->run([$binary, '-q', 'updateinfo', 'list', '--available', '--security']);

        if (! $result->successful()) {
            return [];
        }

        $names = [];

        foreach (preg_split('/\r?\n/', $result->output()) as $line) {
            foreach (preg_split('/\s+/', trim($line)) as $token) {
                $name = $this->packageNameFromNevra($token);

                if ($name !== null) {
                    $names[$name] = true;
                }
            }
        }

        return $names;
    }

    private function packageNameFromNevra(string $nevra): ?string
    {
        // DNF updateinfo lists package NEVRAs as name-[epoch:]version-release.arch.
        if (! preg_match('/^(.+)-(?:(?:\d+):)?([^-]+)-([^-]+)\.([A-Za-z0-9_]+)$/', $nevra, $matches)) {
            return null;
        }

        return $matches[1];
    }
}
