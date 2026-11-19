<?php

use Illuminate\Support\Facades\Route;
use MertAydin\ServerSecurityUpdateMonitor\Http\Controllers\DashboardController;
use MertAydin\ServerSecurityUpdateMonitor\Http\Middleware\AuthorizeDashboard;

Route::middleware(array_merge(config('server-security-update-monitor.route.middleware', ['web', 'auth']), [AuthorizeDashboard::class]))
    ->prefix(config('server-security-update-monitor.route.prefix', 'server-security-monitor'))
    ->group(function () {
        Route::get('/', DashboardController::class)->name('server-security-update-monitor.dashboard');
        Route::post('/apt/update', [DashboardController::class, 'updatePackageLists'])->name('server-security-update-monitor.apt-update');
        Route::post('/language', [DashboardController::class, 'language'])->name('server-security-update-monitor.language');
    });
