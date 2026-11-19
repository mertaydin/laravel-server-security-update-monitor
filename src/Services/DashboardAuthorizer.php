<?php

namespace MertAydin\ServerSecurityUpdateMonitor\Services;

use Closure;
use Illuminate\Http\Request;

class DashboardAuthorizer
{
    private ?Closure $callback = null;

    public function auth(callable $callback): void
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function allows(Request $request): bool
    {
        return $this->callback === null || (bool) ($this->callback)($request);
    }
}
