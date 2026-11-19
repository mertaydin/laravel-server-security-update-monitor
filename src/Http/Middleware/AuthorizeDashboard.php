<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use MertAydin\ServerSecurityUpdateMonitor\Services\DashboardAuthorizer;
use Symfony\Component\HttpFoundation\Response;

class AuthorizeDashboard
{
    public function __construct(private readonly DashboardAuthorizer $authorizer) {}

    public function handle(Request $request, Closure $next): Response
    {
        abort_unless($this->authorizer->allows($request), 403);

        return $next($request);
    }
}
