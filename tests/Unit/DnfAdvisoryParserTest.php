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
        $this->assertSame(['VENDOR-123'], $result['kernel-core']['advisory_ids']);
        $this->assertSame([null], $result['kernel-core']['advisory_urls']);
    }

    public function test_it_parses_dnf5_check_upgrade_json_and_ignores_obsoletes(): void
    {
        $json = json_encode([
            'Available Upgrades' => [
                ['name' => 'openssl-libs', 'arch' => 'x86_64', 'evr' => '1:3.2.2-6.el9_5', 'repository' => 'baseos'],
                ['name' => 'curl', 'arch' => 'x86_64', 'evr' => '8.5.0-1.el9', 'repository' => 'appstream'],
            ],
            'Obsoleting Packages' => [
                ['name' => 'replacement', 'arch' => 'x86_64', 'evr' => '1.0-1', 'repository' => 'baseos'],
            ],
        ], JSON_THROW_ON_ERROR);

        $result = DnfUpdateScanner::parseDnf5UpgradeJson($json);

        $this->assertCount(2, $result);
        $this->assertSame('openssl-libs', $result[0]['name']);
        $this->assertSame('1:3.2.2-6.el9_5', $result[0]['version']);
        $this->assertSame('x86_64', $result[0]['architecture']);
        $this->assertSame('baseos', $result[0]['repository']);
    }

    public function test_it_builds_fedora_advisory_links(): void
    {
        $json = json_encode([[
            'name' => 'FEDORA-2026-1234',
            'type' => 'security',
            'severity' => 'Important',
            'nevra' => 'openssl-libs-0:3.2.2-6.fc43.x86_64',
            'references' => [
                ['reference_id' => 'CVE-2026-12345'],
            ],
        ]], JSON_THROW_ON_ERROR);

        $result = DnfUpdateScanner::parseAdvisoryJson($json);

        $this->assertSame(
            ['https://bodhi.fedoraproject.org/updates/FEDORA-2026-1234'],
            $result['openssl-libs']['advisory_urls']
        );
    }

    public function test_it_matches_security_advisories_to_the_exact_candidate_nevra(): void
    {
        $json = json_encode([[
            'name' => 'RHSA-2026:1234',
            'type' => 'security',
            'severity' => 'Critical',
            'nevra' => 'openssl-libs-1:3.2.2-6.el9_5.x86_64',
            'references' => [],
        ]], JSON_THROW_ON_ERROR);

        $advisories = DnfUpdateScanner::parseAdvisoryJson($json);
        $method = new \ReflectionMethod(DnfUpdateScanner::class, 'matchingAdvisory');

        $matched = $method->invoke(null, $advisories['openssl-libs'], 'openssl-libs', '1:3.2.2-6.el9_5', 'x86_64');
        $mismatched = $method->invoke(null, $advisories['openssl-libs'], 'openssl-libs', '1:3.2.2-5.el9_5', 'x86_64');
        $wrongArchitecture = $method->invoke(null, $advisories['openssl-libs'], 'openssl-libs', '1:3.2.2-6.el9_5', 'aarch64');

        $this->assertNotEmpty($matched);
        $this->assertSame([], $mismatched);
        $this->assertSame([], $wrongArchitecture);
    }

    public function test_it_parses_the_documented_dnf5_extended_json_field_names(): void
    {
        $json = json_encode([[
            'advisory_name' => 'FEDORA-2026-abcdef1234',
            'advisory_type' => 'security',
            'advisory_severity' => 'Important',
            'nevra' => 'openssl-libs-0:3.2.2-6.fc43.x86_64',
            'references' => [
                ['reference_id' => 'CVE-2026-12345', 'reference_type' => 'cve'],
            ],
        ]], JSON_THROW_ON_ERROR);

        $result = DnfUpdateScanner::parseAdvisoryJson($json);

        $this->assertSame(['FEDORA-2026-abcdef1234'], $result['openssl-libs']['advisory_ids']);
        $this->assertSame('high', $result['openssl-libs']['severity']);
        $this->assertSame(['CVE-2026-12345'], $result['openssl-libs']['cves']);
        $this->assertSame(
            ['https://bodhi.fedoraproject.org/updates/FEDORA-2026-abcdef1234'],
            $result['openssl-libs']['advisory_urls']
        );
    }
}
