<?php

namespace MertAydin\ServerSecurityUpdateMonitor;

use RuntimeException;

class SystemUpdateScanner
{
    public function __construct(
        private readonly AptUpdateScanner $apt,
        private readonly DnfUpdateScanner $dnf,
    ) {}

    public function scan(): array
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            throw new RuntimeException('The server update monitor currently supports Linux only.');
        }

        $os = $this->operatingSystem();

        if ($this->isAlpine($os) && $this->hasExecutable(['/sbin/apk', '/usr/sbin/apk', '/bin/apk'])) {
            throw new RuntimeException('APK package manager was detected, but APK scanning is not enabled yet.');
        }

        if (config('server-security-update-monitor.dnf.enabled', true) && $this->isRpmFamily($os) && $this->hasExecutable((array) config('server-security-update-monitor.dnf.binaries', ['/usr/bin/dnf', '/usr/bin/yum', '/bin/dnf', '/bin/yum']))) {
            return $this->dnf->scan();
        }

        if (config('server-security-update-monitor.apt.enabled', true) && $this->isDebianFamily($os) && is_executable('/usr/bin/apt-get')) {
            return $this->apt->scan();
        }

        // Fall back to executable package managers when the distribution ID is custom.
        if (config('server-security-update-monitor.dnf.enabled', true) && $this->hasExecutable((array) config('server-security-update-monitor.dnf.binaries', ['/usr/bin/dnf', '/usr/bin/yum', '/bin/dnf', '/bin/yum']))) {
            return $this->dnf->scan();
        }

        if (config('server-security-update-monitor.apt.enabled', true) && is_executable('/usr/bin/apt-get')) {
            return $this->apt->scan();
        }

        throw new RuntimeException('No supported package manager was detected. Supported managers: APT and DNF/YUM.');
    }

    private function operatingSystem(): array
    {
        $values = [];

        if (is_readable('/etc/os-release')) {
            $parsed = parse_ini_file('/etc/os-release', false, INI_SCANNER_RAW);

            if (is_array($parsed)) {
                $values = [
                    'id' => strtolower(trim((string) ($parsed['ID'] ?? ''))),
                    'like' => strtolower(trim((string) ($parsed['ID_LIKE'] ?? ''))),
                ];
            }
        }

        return $values;
    }

    private function isAlpine(array $os): bool
    {
        return ($os['id'] ?? '') === 'alpine';
    }

    private function isDebianFamily(array $os): bool
    {
        $ids = trim(($os['id'] ?? '').' '.($os['like'] ?? ''));

        return preg_match('/\b(debian|ubuntu|linuxmint|pop)\b/', $ids) === 1;
    }

    private function isRpmFamily(array $os): bool
    {
        $ids = trim(($os['id'] ?? '').' '.($os['like'] ?? ''));

        return preg_match('/\b(fedora|rhel|redhat|centos|rocky|almalinux|ol|amzn|mariner)\b/', $ids) === 1;
    }

    private function hasExecutable(array $paths): bool
    {
        foreach ($paths as $path) {
            if (is_string($path) && is_executable($path)) {
                return true;
            }
        }

        return false;
    }
}
