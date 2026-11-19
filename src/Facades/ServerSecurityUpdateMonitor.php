<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Facades;

use Illuminate\Support\Facades\Facade;
use MertAydin\ServerSecurityUpdateMonitor\Services\DashboardAuthorizer;

/**
 * @method static void auth(callable $callback)
 *
 * @see DashboardAuthorizer
 */
class ServerSecurityUpdateMonitor extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return DashboardAuthorizer::class;
    }
}
