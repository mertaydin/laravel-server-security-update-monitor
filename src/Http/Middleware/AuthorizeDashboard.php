<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Gate;
use Illuminate\Http\Request;

class AuthorizeDashboard
{
    public function handle(Request $request, Closure $next)
    {
        $ability = config('server-security-update-monitor.authorization.gate', 'viewServerSecurityUpdateMonitor');

        if (Gate::has($ability)) {
            Gate::authorize($ability);
        }

        return $next($request);
    }
}
