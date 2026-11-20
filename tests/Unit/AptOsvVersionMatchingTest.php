<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Tests\Unit;

use MertAydin\ServerSecurityUpdateMonitor\AptUpdateScanner;
use MertAydin\ServerSecurityUpdateMonitor\ServerSecurityUpdateMonitorServiceProvider;
use Orchestra\Testbench\TestCase;

class AptOsvVersionMatchingTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [ServerSecurityUpdateMonitorServiceProvider::class];
    }

    public function test_candidate_must_be_outside_every_osv_affected_version_interval(): void
    {
        $vulnerability = [
            'affected' => [[
                'package' => [
                    'name' => 'openssl',
                    'ecosystem' => 'Ubuntu:24.04:LTS',
                ],
                'ranges' => [[
                    'type' => 'ECOSYSTEM',
                    'events' => [
                        ['introduced' => '0'],
                        ['fixed' => '1.5'],
                        ['introduced' => '2.0'],
                        ['fixed' => '2.5'],
                    ],
                ]],
            ]],
        ];

        $method = new \ReflectionMethod(AptUpdateScanner::class, 'candidateFixesVulnerability');
        $scanner = new AptUpdateScanner;

        $this->assertFalse($method->invoke($scanner, 'openssl', 'Ubuntu:24.04:LTS', '1.0', $vulnerability));
        $this->assertTrue($method->invoke($scanner, 'openssl', 'Ubuntu:24.04:LTS', '1.7', $vulnerability));
        $this->assertFalse($method->invoke($scanner, 'openssl', 'Ubuntu:24.04:LTS', '2.1', $vulnerability));
        $this->assertTrue($method->invoke($scanner, 'openssl', 'Ubuntu:24.04:LTS', '2.6', $vulnerability));
        $this->assertFalse($method->invoke($scanner, 'libssl3', 'Ubuntu:24.04:LTS', '2.6', $vulnerability));
    }
}
