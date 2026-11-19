<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use MertAydin\ServerSecurityUpdateMonitor\SystemUpdateScanner;

class CheckUpdatesCommand extends Command
{
    protected $signature = 'server-security-monitor:check';
    protected $description = 'Scan the system package manager for available package and security updates';

    public function handle(SystemUpdateScanner $scanner): int
    {
        try {
            $data = $scanner->scan();
            Cache::put(config('server-security-update-monitor.cache.key'), $data, (int) config('server-security-update-monitor.cache.seconds', 900));
            $this->info("Scan completed: {$data['total_updates']} updates, {$data['security_updates']} security updates.");
            return self::SUCCESS;
        } catch (\Throwable $exception) {
            $this->error($exception->getMessage());
            return self::FAILURE;
        }
    }
}
