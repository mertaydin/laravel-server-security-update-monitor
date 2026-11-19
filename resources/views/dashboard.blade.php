<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server Security Update Monitor</title>
<link rel="stylesheet" href="{{ asset('vendor/server-security-update-monitor/css/dashboard.css') }}">
</head>
<body><main class="wrap">
<header class="top"><div><div class="eyebrow">SERVER HEALTH / SECURITY</div><h1 class="title">Güncelleme Merkezi</h1><div class="sub">{{ $data['host'] ?? 'Server' }} · {{ $data['package_manager'] ?? 'APT' }} · Son kontrol: {{ !empty($data['checked_at']) ? \Illuminate\Support\Carbon::parse($data['checked_at'])->format('d.m.Y H:i:s') : 'Henüz yapılmadı' }}</div></div><a class="btn" id="refresh-dashboard" href="{{ route('server-security-update-monitor.dashboard', ['refresh' => 1]) }}">↻ Şimdi kontrol et</a></header>
<section class="grid">
<article class="card blue"><div class="label">BEKLEYEN GÜNCELLEME</div><div class="metric">{{ $data['total_updates'] ?? 0 }}</div></article>
<article class="card red"><div class="label">GÜVENLİK GÜNCELLEMESİ</div><div class="metric">{{ $data['security_updates'] ?? 0 }}</div></article>
<article class="card amber"><div class="label">NORMAL GÜNCELLEME</div><div class="metric">{{ max(0, ($data['total_updates'] ?? 0) - ($data['security_updates'] ?? 0)) }}</div></article>
<article class="card green"><div class="label">PAKET YÖNETİCİSİ</div><div class="metric" style="font-size:25px">APT</div></article>
</section>
@if(!empty($data['error']))<div class="error"><strong>Tarama yapılamadı:</strong> {{ $data['error'] }}</div>@endif
<section class="panel"><div class="panel-head"><h2>Güncelleme bekleyen paketler</h2><span class="muted">{{ count($data['packages'] ?? []) }} paket</span></div>
@if(empty($data['packages']))<div class="empty">Bekleyen paket güncellemesi bulunamadı.</div>@else
<div class="table-wrap"><table><thead><tr><th>Paket</th><th>Kurulu sürüm</th><th>Yeni sürüm</th><th>Kaynak</th><th>Tür</th><th>Önem</th></tr></thead><tbody>
@foreach($data['packages'] as $package)<tr><td class="pkg">{{ $package['name'] }}</td><td class="muted">{{ $package['installed_version'] ?? '—' }}</td><td>{{ $package['candidate_version'] }}</td><td class="muted">{{ $package['repository'] }}</td><td><span class="pill {{ $package['is_security'] ? 'security' : 'normal' }}">{{ $package['type'] }}</span></td><td><span class="pill {{ $package['is_security'] ? 'security' : 'normal' }}">{{ $package['severity_label'] }}</span></td></tr>@endforeach
</tbody></table></div>@endif</section>
<p class="sub" style="margin-top:18px;font-size:12px">Güvenlik sınıflandırması APT depo metaverisine dayanır. CVE/USN/DSA eşleşmesi yapılmadıkça önem derecesi bilinmiyor gösterilir. Paket yükseltmeleri bu panelden otomatik uygulanmaz.</p>
</main>
<div class="loading-overlay" id="scan-loading" aria-hidden="true" role="status" aria-live="polite"><div class="loading-dialog"><div class="loading-spinner"></div><h2>Sunucu kontrol ediliyor</h2><p>Paketler ve güvenlik güncellemeleri taranıyor. Lütfen bekleyin.</p><div class="loading-track"><span></span></div></div></div>
<script>
document.getElementById("refresh-dashboard")?.addEventListener("click", function (event) {
    event.preventDefault();
    const overlay = document.getElementById("scan-loading");
    if (overlay) {
        overlay.classList.add("is-visible");
        overlay.setAttribute("aria-hidden", "false");
    }
    this.setAttribute("aria-disabled", "true");
    window.location.assign(this.href);
});
</script>
</body></html>
