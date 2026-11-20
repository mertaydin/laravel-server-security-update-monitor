<!doctype html>
<html lang="{{ str_replace('_', '-', $locale) }}" dir="{{ $locale === 'ar' ? 'rtl' : 'ltr' }}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light">
<title>{{ __('server-security-update-monitor::messages.title') }}</title>
<link rel="stylesheet" href="{{ asset('vendor/server-security-update-monitor/css/dashboard.css') }}?v=0.2.4">
<script src="{{ asset('vendor/server-security-update-monitor/js/dashboard.js') }}?v=0.2.4" defer></script>
</head>
<body><main class="wrap">
<header class="top"><div><div class="eyebrow">SERVER HEALTH / SECURITY</div><h1 class="title">{{ __('server-security-update-monitor::messages.title') }}</h1><div class="sub">{{ $data['host'] ?? 'Server' }} · {{ $data['package_manager'] ?? 'APT' }} · {{ __('server-security-update-monitor::messages.last_checked') }}: {{ !empty($data['checked_at']) ? \Illuminate\Support\Carbon::parse($data['checked_at'])->format('d.m.Y H:i:s') : __('server-security-update-monitor::messages.not_checked') }}</div></div><div class="toolbar">
<form id="language-form" method="POST" action="{{ route('server-security-update-monitor.language') }}">@csrf<select id="language-select" name="locale" aria-label="{{ __('server-security-update-monitor::messages.language') }}">@foreach (['tr'=>'Türkçe','en'=>'English','ar'=>'العربية','es'=>'Español','hi'=>'हिन्दी','zh_CN'=>'简体中文'] as $code=>$label)<option value="{{ $code }}" @selected($locale===$code)>{{ $label }}</option>@endforeach</select></form>
<select id="theme-select" aria-label="{{ __('server-security-update-monitor::messages.theme') }}"><option value="system">{{ __('server-security-update-monitor::messages.system') }}</option><option value="light">{{ __('server-security-update-monitor::messages.light') }}</option><option value="dark">{{ __('server-security-update-monitor::messages.dark') }}</option></select>
<a class="btn" id="refresh-dashboard" href="{{ route('server-security-update-monitor.dashboard', ['refresh' => 1]) }}">↻ {{ __('server-security-update-monitor::messages.refresh') }}</a>
@if(($data['package_manager'] ?? '') === 'APT')<form id="apt-update-form" method="POST" action="{{ route('server-security-update-monitor.apt-update') }}">@csrf<button class="btn" type="submit" id="apt-update-button">↻ {{ __('server-security-update-monitor::messages.update_package_lists') }}</button></form>@endif
</div></header>
<section class="grid">
<article class="card blue"><div class="label">{{ __('server-security-update-monitor::messages.pending') }}</div><div class="metric">{{ $data['total_updates'] ?? 0 }}</div></article>
<article class="card red"><div class="label">{{ __('server-security-update-monitor::messages.security') }}</div><div class="metric">{{ $data['security_updates'] ?? 0 }}</div></article>
<article class="card amber"><div class="label">{{ __('server-security-update-monitor::messages.normal') }}</div><div class="metric">{{ max(0, ($data['total_updates'] ?? 0) - ($data['security_updates'] ?? 0)) }}</div></article>
<article class="card green"><div class="label">{{ __('server-security-update-monitor::messages.package_manager') }}</div><div class="metric" style="font-size:25px">{{ $data['package_manager'] ?? '—' }}</div></article>
</section>
@if(session('apt_update_status') === 'success')<div class="notice">{{ __('server-security-update-monitor::messages.apt_update_success') }}</div>@elseif(session('apt_update_status') === 'error')<div class="error"><strong>{{ __('server-security-update-monitor::messages.apt_update_failed') }}</strong> {{ session('apt_update_error') }}</div>@endif
@if(!empty($data['error']))<div class="error"><strong>{{ __('server-security-update-monitor::messages.scan_failed') }}</strong> {{ $data['error'] }}</div>@endif
<section class="panel"><div class="panel-head"><h2>{{ __('server-security-update-monitor::messages.packages_heading') }}</h2><span class="muted">{{ count($data['packages'] ?? []) }} {{ __('server-security-update-monitor::messages.packages') }}</span></div>
@if(empty($data['packages']))<div class="empty">{{ __('server-security-update-monitor::messages.empty') }}</div>@else
<div class="table-filters">
<input id="package-search" type="search" placeholder="{{ __('server-security-update-monitor::messages.search_packages') }}" aria-label="{{ __('server-security-update-monitor::messages.search_packages') }}">
<select id="security-filter" aria-label="{{ __('server-security-update-monitor::messages.filter_updates') }}"><option value="all">{{ __('server-security-update-monitor::messages.filter_all') }}</option><option value="security">{{ __('server-security-update-monitor::messages.filter_security') }}</option><option value="normal">{{ __('server-security-update-monitor::messages.filter_normal') }}</option></select>
<select id="severity-filter" aria-label="{{ __('server-security-update-monitor::messages.filter_severity') }}"><option value="all">{{ __('server-security-update-monitor::messages.filter_severity_all') }}</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">{{ __('server-security-update-monitor::messages.unknown') }}</option></select>
</div>
<div class="table-wrap"><table><thead><tr><th>{{ __('server-security-update-monitor::messages.package') }}</th><th>{{ __('server-security-update-monitor::messages.installed') }}</th><th>{{ __('server-security-update-monitor::messages.candidate') }}</th><th>{{ __('server-security-update-monitor::messages.repository') }}</th><th>{{ __('server-security-update-monitor::messages.type') }}</th><th>{{ __('server-security-update-monitor::messages.severity') }}</th><th>{{ __('server-security-update-monitor::messages.advisories') }}</th><th>{{ __('server-security-update-monitor::messages.cves') }}</th></tr></thead><tbody id="package-table-body">
@foreach($data['packages'] as $package)
<tr data-package="{{ strtolower($package['name'].' '.($package['repository'] ?? '').' '.implode(' ', $package['cves'] ?? []).' '.implode(' ', $package['advisory_ids'] ?? [])) }}" data-security="{{ !empty($package['is_security']) ? 'security' : 'normal' }}" data-severity="{{ $package['severity'] ?? 'unknown' }}">
<td class="pkg">{{ $package['name'] }}</td><td class="muted">{{ $package['installed_version'] ?? '—' }}</td><td>{{ $package['candidate_version'] }}</td><td class="muted">{{ $package['repository'] }}</td>
<td><span class="pill {{ !empty($package['is_security']) ? 'security' : 'normal' }}">{{ $package['type'] }}</span></td>
<td><span class="pill severity-{{ $package['severity'] ?? 'unknown' }}">{{ $package['severity_label'] ?? __('server-security-update-monitor::messages.unknown') }}</span></td>
<td>@forelse(($package['advisory_ids'] ?? []) as $index=>$advisory)<a class="reference-link" href="{{ $package['advisory_urls'][$index] ?? '#' }}" target="_blank" rel="noopener noreferrer">{{ $advisory }}</a>@empty<span class="muted">—</span>@endforelse</td>
<td>@forelse(($package['cves'] ?? []) as $cve)<a class="reference-link" href="https://nvd.nist.gov/vuln/detail/{{ rawurlencode($cve) }}" target="_blank" rel="noopener noreferrer">{{ $cve }}</a>@empty<span class="muted">—</span>@endforelse</td>
</tr>
@endforeach
</tbody></table></div><div class="empty" id="no-filter-results" hidden>{{ __('server-security-update-monitor::messages.no_filter_results') }}</div>
@endif</section>
<p class="sub" style="margin-top:18px;font-size:12px">{{ __('server-security-update-monitor::messages.disclaimer') }}</p>
</main>
<div class="loading-overlay" id="scan-loading" aria-hidden="true" data-update-title="{{ __('server-security-update-monitor::messages.updating_package_lists') }}" data-update-help="{{ __('server-security-update-monitor::messages.updating_package_lists_help') }}" role="status" aria-live="polite"><div class="loading-dialog"><div class="loading-spinner"></div><h2>{{ __('server-security-update-monitor::messages.scanning') }}</h2><p>{{ __('server-security-update-monitor::messages.scanning_help') }}</p><div class="loading-track"><span></span></div></div></div>
</body></html>