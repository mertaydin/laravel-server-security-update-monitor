<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use MertAydin\ServerSecurityUpdateMonitor\AptUpdateScanner;
use MertAydin\ServerSecurityUpdateMonitor\SystemUpdateScanner;

class DashboardController extends Controller
{
    public function __invoke(SystemUpdateScanner $scanner)
    {
        $locale = session('server_security_update_monitor_locale', config('app.locale', 'en'));
        $supported = ['tr', 'en', 'ar', 'es', 'hi', 'zh_CN'];
        if (! in_array($locale, $supported, true)) {
            $locale = 'en';
        }
        app()->setLocale($locale);

        $key = config('server-security-update-monitor.cache.key');
        $data = request()->boolean('refresh') ? null : Cache::get($key);

        if (! is_array($data)) {
            try {
                $data = $scanner->scan();
                Cache::put($key, $data, (int) config('server-security-update-monitor.cache.seconds', 900));
            } catch (\Throwable $exception) {
                $data = [
                    'host' => gethostname() ?: 'unknown',
                    'package_manager' => 'Unknown',
                    'checked_at' => null,
                    'total_updates' => 0,
                    'security_updates' => 0,
                    'packages' => [],
                    'error' => $exception->getMessage(),
                ];
            }
        }

        return view('server-security-update-monitor::dashboard', compact('data', 'locale'));
    }

    public function updatePackageLists(AptUpdateScanner $scanner)
    {
        try {
            $scanner->updatePackageLists();

            return redirect()->route('server-security-update-monitor.dashboard')->with('apt_update_status', 'success');
        } catch (\Throwable $exception) {
            return redirect()->route('server-security-update-monitor.dashboard')
                ->with('apt_update_status', 'error')->with('apt_update_error', $exception->getMessage());
        }
    }

    public function language()
    {
        $locale = request()->validate(['locale' => ['required', 'in:tr,en,ar,es,hi,zh_CN']])['locale'];
        session(['server_security_update_monitor_locale' => $locale]);

        return redirect()->route('server-security-update-monitor.dashboard');
    }
}
