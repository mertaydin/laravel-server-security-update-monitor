<?php

return [
    'route' => [
        'enabled' => true,
        'prefix' => 'server-security-monitor',
        'middleware' => ['web', 'auth'],
    ],
    'cache' => [
        'key' => 'server-security-update-monitor.packages',
        'seconds' => 900,
    ],
    'command_timeout' => 30,
    'apt' => [
        'enabled' => true,
        'update_timeout' => 300,
        'security_suites' => ['-security', '/security'],
    ],
    'dnf' => [
        'enabled' => true,
        'binaries' => ['/usr/bin/dnf', '/usr/bin/dnf5', '/usr/bin/yum', '/bin/dnf', '/bin/dnf5', '/bin/yum'],
    ],
    'apk' => [
        'enabled' => true,
        'binary' => '/sbin/apk',
    ],
];
