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
        'security_suites' => ['-security', '/security'],
    ],
    'dnf' => [
        'enabled' => true,
        'binaries' => ['/usr/bin/dnf', '/usr/bin/yum', '/bin/dnf', '/bin/yum'],
    ],
    'apk' => [
        'enabled' => true,
        'binary' => '/sbin/apk',
    ],
];
