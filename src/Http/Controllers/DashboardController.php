<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use MertAydin\ServerSecurityUpdateMonitor\AptUpdateScanner;

class DashboardController extends Controller
{
    public function __invoke(AptUpdateScanner $scanner)
    {
        $key = config('server-security-update-monitor.cache.key');
        $data = request()->boolean('refresh') ? null : Cache::get($key);

        if (! is_array($data)) {
            try {
                $data = $scanner->scan();
                Cache::put($key, $data, (int) config('server-security-update-monitor.cache.seconds', 900));
            } catch (\Throwable $exception) {
                $data = [
                    'host' => gethostname() ?: 'unknown',
                    'package_manager' => 'APT',
                    'checked_at' => null,
                    'total_updates' => 0,
                    'security_updates' => 0,
                    'packages' => [],
                    'error' => $exception->getMessage(),
                ];
            }
        }

        return view('server-security-update-monitor::dashboard', compact('data'));
    }
}
