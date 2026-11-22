<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Tests\Unit;

use Illuminate\Http\Request;
use MertAydin\ServerSecurityUpdateMonitor\Services\DashboardAuthorizer;
use PHPUnit\Framework\TestCase;

class DashboardAuthorizerTest extends TestCase
{
    public function test_access_is_denied_until_an_authorization_callback_is_registered(): void
    {
        $authorizer = new DashboardAuthorizer;

        $this->assertFalse($authorizer->allows(Request::create('/server-security-monitor')));

        $authorizer->auth(static fn (): bool => true);

        $this->assertTrue($authorizer->allows(Request::create('/server-security-monitor')));
    }

    public function test_authorization_callback_can_deny_access(): void
    {
        $authorizer = new DashboardAuthorizer;
        $authorizer->auth(static fn (): bool => false);

        $this->assertFalse($authorizer->allows(Request::create('/server-security-monitor')));
    }
}
