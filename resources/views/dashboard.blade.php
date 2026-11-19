<!doctype html>
<html lang="{{ str_replace('_', '-', $locale) }}" dir="{{ $locale === 'ar' ? 'rtl' : 'ltr' }}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light">
<title>{{ __('server-security-update-monitor::messages.title') }}</title>
<link rel="stylesheet" href="{{ asset('vendor/server-security-update-monitor/css/dashboard.css') }}">
<script>
(function(){try{var t=localStorage.getItem('ssum-theme')||'system';var d=t==='dark'||(t==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=d?'dark':'light';}catch(e){document.documentElement.dataset.theme='dark';}})();
</script>
</head>
<body><main class="wrap">
<header class="top"><div><div class="eyebrow">SERVER HEALTH / SECURITY</div><h1 class="title">{{ __('server-security-update-monitor::messages.title') }}</h1><div class="sub">{{ $data['host'] ?? 'Server' }} · {{ $data['package_manager'] ?? 'APT' }} · {{ __('server-security-update-monitor::messages.last_checked') }}: {{ !empty($data['checked_at']) ? \\Illuminate\\Support\\Carbon::parse($data['checked_at'])->format('d.m.Y H:i:s') : __('server-security-update-monitor::messages.not_checked') }}</div></div><div class="toolbar">
<form method="POST" action="{{ route('server-security-update-monitor.language') }}">@csrf<select name="locale" aria-label="{{ __('server-security-update-monitor::messages.language') }}" onchange="this.form.submit()">@foreach (['tr'=>'Türkçe','en'=>'English','ar'=>'العربية','es'=>'Español','hi'=>'हिन्दी','zh_CN'=>'简体中文'] as $code=>$label)<option value="{{ $code }}" @selected($locale===$code)>{{ $label }}</option>@endforeach</select></form>
<select id="theme-select" aria-label="{{ __('server-security-update-monitor::messages.theme') }}"><option value="system">{{ __('server-security-update-monitor::messages.system') }}</option><option value="light">{{ __('server-security-update-monitor::messages.light') }}</option><option value="dark">{{ __('server-security-update-monitor::messages.dark') }}</option></select>
<a class="btn" id="refresh-dashboard" href="{{ route('server-security-update-monitor.dashboard', ['refresh' => 1]) }}">↻ {{ __('server-security-update-monitor::messages.refresh') }}</a></div></header>
<section class="grid">
<article class="card blue"><div class="label">{{ __('server-security-update-monitor::messages.pending') }}</div><div class="metric">{{ $data['total_updates'] ?? 0 }}</div></article>
<article class="card red"><div class="label">{{ __('server-security-update-monitor::messages.security') }}</div><div class="metric">{{ $data['security_updates'] ?? 0 }}</div></article>
<article class="card amber"><div class="label">{{ __('server-security-update-monitor::messages.normal') }}</div><div class="metric">{{ max(0, ($data['total_updates'] ?? 0) - ($data['security_updates'] ?? 0)) }}</div></article>
<article class="card green"><div class="label">{{ __('server-security-update-monitor::messages.package_manager') }}</div><div class="metric" style="font-size:25px">APT</div></article>
</section>
@if(!empty($data['error']))<div class="error"><strong>{{ __('server-security-update-monitor::messages.scan_failed') }}</strong> {{ $data['error'] }}</div>@endif
<section class="panel"><div class="panel-head"><h2>{{ __('server-security-update-monitor::messages.packages_heading') }}</h2><span class="muted">{{ count($data['packages'] ?? []) }} {{ __('server-security-update-monitor::messages.packages') }}</span></div>
@if(empty($data['packages']))<div class="empty">{{ __('server-security-update-monitor::messages.empty') }}</div>@else
<div class="table-wrap"><table><thead><tr><th>{{ __('server-security-update-monitor::messages.package') }}</th><th>{{ __('server-security-update-monitor::messages.installed') }}</th><th>{{ __('server-security-update-monitor::messages.candidate') }}</th><th>{{ __('server-security-update-monitor::messages.repository') }}</th><th>{{ __('server-security-update-monitor::messages.type') }}</th><th>{{ __('server-security-update-monitor::messages.severity') }}</th></tr></thead><tbody>
@foreach($data['packages'] as $package)<tr><td class="pkg">{{ $package['name'] }}</td><td class="muted">{{ $package['installed_version'] ?? '—' }}</td><td>{{ $package['candidate_version'] }}</td><td class="muted">{{ $package['repository'] }}</td><td><span class="pill {{ $package['is_security'] ? 'security' : 'normal' }}">{{ $package['type'] }}</span></td><td><span class="pill {{ $package['is_security'] ? 'security' : 'normal' }}">{{ $package['severity_label'] }}</span></td></tr>@endforeach
</tbody></table></div>@endif</section>
<p class="sub" style="margin-top:18px;font-size:12px">{{ __('server-security-update-monitor::messages.disclaimer') }}</p>
</main>
<div class="loading-overlay" id="scan-loading" aria-hidden="true" role="status" aria-live="polite"><div class="loading-dialog"><div class="loading-spinner"></div><h2>{{ __('server-security-update-monitor::messages.scanning') }}</h2><p>{{ __('server-security-update-monitor::messages.scanning_help') }}</p><div class="loading-track"><span></span></div></div></div>
<script>
(function(){
const theme=document.getElementById('theme-select');const saved=localStorage.getItem('ssum-theme')||'system';theme.value=saved;
theme.addEventListener('change',function(){localStorage.setItem('ssum-theme',this.value);const dark=this.value==='dark'||(this.value==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.dataset.theme=dark?'dark':'light';});
document.getElementById('refresh-dashboard')?.addEventListener('click',function(e){e.preventDefault();document.getElementById('scan-loading')?.classList.add('is-visible');window.location.assign(this.href);});
})();
</script>
</body></html>