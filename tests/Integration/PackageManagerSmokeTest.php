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
            if (getenv('RUN_PRIVILEGE_INTEGRATION') === '1') {
                $this->assertNotSame(0, posix_geteuid(), 'Privilege integration must run as an unprivileged user.');
                (new AptUpdateScanner)->updatePackageLists();
            }

            $metadata = Process::run([
                '/usr/bin/dpkg-query',
                '-W',
                '-f=${Version}\\t${source:Package}\\t${source:Version}',
                '--',
                'bash',
            ]);
            $this->assertTrue($metadata->successful());
            $metadataFields = explode("\t", trim($metadata->output()));
            $this->assertCount(3, $metadataFields, 'dpkg-query must return version, source package and source version as separate fields.');
            $this->assertNotSame('', $metadataFields[1]);
            $this->assertNotSame('', $metadataFields[2]);

            $snapshot = (new AptUpdateScanner)->scan();
            $this->assertSame('APT', $snapshot['package_manager']);
        } elseif (is_executable('/usr/bin/dnf') || is_executable('/usr/bin/dnf5') || is_executable('/usr/bin/yum')) {
            $snapshot = (new DnfUpdateScanner)->scan();
            $this->assertContains($snapshot['package_manager'], ['DNF', 'DNF5', 'YUM']);

            $binary = is_executable('/usr/bin/dnf') ? '/usr/bin/dnf' : (is_executable('/usr/bin/dnf5') ? '/usr/bin/dnf5' : '/usr/bin/yum');
            $advisories = Process::run([$binary, '-q', '--cacheonly', 'advisory', 'list', '--json', '--security', '--with-cve']);
            if (! $advisories->successful()) {
                $advisories = Process::run([$binary, '-q', '--cacheonly', 'updateinfo', 'info', '--available', '--security']);
            }
            $this->assertTrue(
                $advisories->successful(),
                'The native package manager could not read cached security advisory metadata: '.$advisories->errorOutput()
            );
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
