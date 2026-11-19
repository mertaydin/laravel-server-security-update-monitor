<?php

return [
    'route' => [
        'enabled' => true,
        'prefix' => 'server-security-monitor',
        'middleware' => ['web', 'auth'],
    ],
    'authorization' => [
        'gate' => 'viewServerSecurityUpdateMonitor',
    ],
    'cache' => [
        'key' => 'server-security-update-monitor.packages',
        'seconds' => 900,
    ],
    'command_timeout' => 30,
    'apt' => [
        'enabled' => true,
        'security_suites' => ['-security', '/security'],
    ],
];
