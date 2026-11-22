<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Tests\Unit;

use MertAydin\ServerSecurityUpdateMonitor\AptUpdateScanner;
use PHPUnit\Framework\TestCase;

class AptOsvEcosystemTest extends TestCase
{
    public function test_ubuntu_lts_releases_use_the_canonical_osv_ecosystem_name(): void
    {
        $method = new \ReflectionMethod(AptUpdateScanner::class, 'ubuntuOsvEcosystem');

        $this->assertSame('Ubuntu:22.04:LTS', $method->invoke(new AptUpdateScanner, '22.04'));
        $this->assertSame('Ubuntu:24.04:LTS', $method->invoke(new AptUpdateScanner, '24.04'));
        $this->assertSame('Ubuntu:26.04:LTS', $method->invoke(new AptUpdateScanner, '26.04'));
    }

    public function test_ubuntu_interim_releases_do_not_get_an_lts_suffix(): void
    {
        $method = new \ReflectionMethod(AptUpdateScanner::class, 'ubuntuOsvEcosystem');

        $this->assertSame('Ubuntu:25.04', $method->invoke(new AptUpdateScanner, '25.04'));
        $this->assertNull($method->invoke(new AptUpdateScanner, '24'));
    }

    public function test_ubuntu_negligible_priority_is_retained_as_the_lowest_filter_bucket(): void
    {
        $method = new \ReflectionMethod(AptUpdateScanner::class, 'normalizeSeverity');

        $this->assertSame('low', $method->invoke(new AptUpdateScanner, 'negligible'));
    }

    public function test_debian_osv_ecosystem_is_scoped_to_the_major_release(): void
    {
        $method = new \ReflectionMethod(AptUpdateScanner::class, 'debianOsvEcosystem');

        $this->assertSame('Debian:12', $method->invoke(new AptUpdateScanner, '12'));
        $this->assertSame('Debian:13', $method->invoke(new AptUpdateScanner, '13.1'));
        $this->assertNull($method->invoke(new AptUpdateScanner, 'sid'));
    }
}
