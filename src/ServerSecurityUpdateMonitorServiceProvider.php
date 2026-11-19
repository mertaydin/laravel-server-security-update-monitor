<?php

namespace MertAydin\ServerSecurityUpdateMonitor;

use Illuminate\Support\ServiceProvider;
use MertAydin\ServerSecurityUpdateMonitor\Console\CheckUpdatesCommand;

class ServerSecurityUpdateMonitorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/server-security-update-monitor.php', 'server-security-update-monitor');
        $this->app->singleton(AptUpdateScanner::class);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/server-security-update-monitor.php' => config_path('server-security-update-monitor.php'),
        ], 'server-security-update-monitor-config');

        if ($this->app->runningInConsole()) {
            $this->commands([CheckUpdatesCommand::class]);
        }

        if (config('server-security-update-monitor.route.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        }

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'server-security-update-monitor');
    }
}
