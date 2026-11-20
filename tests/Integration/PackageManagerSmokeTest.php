<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Tests\Integration;

use Illuminate\Support\Facades\Process;
use MertAydin\ServerSecurityUpdateMonitor\AptUpdateScanner;
use MertAydin\ServerSecurityUpdateMonitor\DnfUpdateScanner;
use MertAydin\ServerSecurityUpdateMonitor\ServerSecurityUpdateMonitorServiceProvider;
use Orchestra\Testbench\TestCase;

class PackageManagerSmokeTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [ServerSecurityUpdateMonitorServiceProvider::class];
    }

    public function test_native_package_manager_can_produce_a_valid_scan_snapshot(): void
    {
        config()->set('server-security-update-monitor.command_timeout', 120);
        config()->set('server-security-update-monitor.apt.osv.enabled', false);

        if (is_executable('/usr/bin/apt-get')) {
            $metadata = Process::run([
                '/usr/bin/dpkg-query',
                '-W',
                '-f=${Version}\\t${source:Package}\\t${source:Version}',
                '--',
                'bash',
            ]);
            $this->assertTrue($metadata->successful());
            $this->assertGreaterThanOrEqual(2, count(explode("\t", trim($metadata->output()))));

            $snapshot = (new AptUpdateScanner)->scan();
            $this->assertSame('APT', $snapshot['package_manager']);
        } elseif (is_executable('/usr/bin/dnf') || is_executable('/usr/bin/dnf5') || is_executable('/usr/bin/yum')) {
            $snapshot = (new DnfUpdateScanner)->scan();
            $this->assertContains($snapshot['package_manager'], ['DNF', 'DNF5', 'YUM']);
        } else {
            $this->markTestSkipped('No supported native package manager is installed in this environment.');
        }

        $this->assertArrayHasKey('host', $snapshot);
        $this->assertArrayHasKey('checked_at', $snapshot);
        $this->assertArrayHasKey('packages', $snapshot);
        $this->assertSame(count($snapshot['packages']), $snapshot['total_updates']);
        $this->assertSame(
            count(array_filter($snapshot['packages'], static fn (array $package): bool => $package['is_security'])),
            $snapshot['security_updates']
        );
    }
}
