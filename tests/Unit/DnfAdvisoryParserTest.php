<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Tests\Unit;

use MertAydin\ServerSecurityUpdateMonitor\DnfUpdateScanner;
use PHPUnit\Framework\TestCase;

class DnfAdvisoryParserTest extends TestCase
{
    public function test_it_parses_dnf5_json_security_advisories(): void
    {
        $json = json_encode([
            [
                'name' => 'RHSA-2026:1234',
                'type' => 'security',
                'severity' => 'Critical',
                'nevra' => 'openssl-libs-1:3.2.2-6.el9_5.x86_64',
                'references' => [
                    ['reference_id' => 'CVE-2026-12345'],
                ],
            ],
            [
                'name' => 'FEDORA-2026-1234',
                'type' => 'bugfix',
                'severity' => 'Low',
                'nevra' => 'curl-0:8.5.0-1.fc40.x86_64',
                'references' => [],
            ],
        ], JSON_THROW_ON_ERROR);

        $result = DnfUpdateScanner::parseAdvisoryJson($json);

        $this->assertArrayHasKey('openssl-libs', $result);
        $this->assertSame('critical', $result['openssl-libs']['severity']);
        $this->assertSame(['RHSA-2026:1234'], $result['openssl-libs']['advisory_ids']);
        $this->assertSame(['CVE-2026-12345'], $result['openssl-libs']['cves']);
        $this->assertArrayNotHasKey('curl', $result);
    }

    public function test_it_parses_dnf4_updateinfo_security_blocks(): void
    {
        $output = <<<'OUTPUT'
Update ID : RHSA-2026:9876
    Type       : security
    Severity   : Important
    Description: Security update
    Updated    : 2026-11-20
    CVEs       : CVE-2026-11111
    Packages   : openssl-libs-1:3.2.2-6.el9_5.x86_64
OUTPUT;

        $result = DnfUpdateScanner::parseAdvisoryInfo($output);

        $this->assertArrayHasKey('openssl-libs', $result);
        $this->assertSame('high', $result['openssl-libs']['severity']);
        $this->assertSame(['CVE-2026-11111'], $result['openssl-libs']['cves']);
    }

    public function test_unknown_advisory_severity_is_not_guessed(): void
    {
        $json = json_encode([[
            'name' => 'VENDOR-123',
            'type' => 'security',
            'severity' => 'Unspecified',
            'nevra' => 'kernel-core-0:6.12.0-1.x86_64',
            'references' => [],
        ]], JSON_THROW_ON_ERROR);

        $result = DnfUpdateScanner::parseAdvisoryJson($json);

        $this->assertSame('unknown', $result['kernel-core']['severity']);
    }
}
