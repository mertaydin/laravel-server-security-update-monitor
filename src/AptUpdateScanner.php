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
            $installed = Process::timeout(10)->run('dpkg-query -W -f=${Version} '.escapeshellarg($name).' 2>/dev/null');

            $packages[] = [
                'name' => $name,
                'installed_version' => $installed->successful() ? trim($installed->output()) : null,
                'candidate_version' => $matches[3],
                'architecture' => $matches[4],
                'repository' => $suite,
                'is_security' => $security,
                'severity' => $security ? 'high' : 'normal',
                'severity_label' => $security ? 'High' : 'Normal',
                'type' => $security ? 'Security update' : 'Package update',
            ];
        }

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

    private function isSecuritySuite(string $suite): bool
    {
        foreach ((array) config('server-security-update-monitor.apt.security_suites', ['-security', '/security']) as $needle) {
            if ($needle !== '' && str_contains(strtolower($suite), strtolower($needle))) {
                return true;
            }
        }

        return false;
    }
}
