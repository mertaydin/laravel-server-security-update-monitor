<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server Security Update Monitor</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121d32;--line:#293953;--muted:#93a5c1;--text:#edf3ff;--red:#ff5364;--amber:#f6b94b;--green:#39c98a;--blue:#69a8ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#1a2d4d 0,transparent 36%),var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,sans-serif}.wrap{max-width:1440px;margin:auto;padding:34px 26px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:26px}.eyebrow{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.16em}.title{font-size:30px;font-weight:800;letter-spacing:-.04em;margin:4px 0}.sub{color:var(--muted)}.btn{border:1px solid #36517b;background:#1b3152;color:#fff;border-radius:10px;padding:11px 16px;text-decoration:none;font-weight:700}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:22px 0}.card,.panel{background:linear-gradient(145deg,#17243c,#10192b);border:1px solid var(--line);border-radius:16px;box-shadow:0 14px 38px #0002}.card{padding:20px}.metric{font-size:32px;font-weight:800}.label{color:var(--muted);font-size:11px;font-weight:800;letter-spacing:.08em}.red{color:var(--red)}.amber{color:var(--amber)}.green{color:var(--green)}.blue{color:var(--blue)}.panel{overflow:hidden;margin-top:20px}.panel-head{padding:19px 22px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between}.panel h2{font-size:16px;margin:0}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:14px 18px;border-bottom:1px solid #243149}th{font-size:11px;color:var(--muted);text-transform:uppercase}td{font-size:13px}.pkg{font-weight:750}.muted{color:var(--muted)}.pill{display:inline-flex;border-radius:99px;padding:4px 9px;font-size:11px;font-weight:800;background:#26354d}.security{background:#54232e;color:#ff9aa5}.normal{background:#4a3920;color:#ffd58b}.empty{padding:34px;text-align:center;color:var(--muted)}.error{margin-top:18px;padding:14px 17px;border:1px solid #8b3442;background:#3a1d29;border-radius:12px;color:#ffb6bf}@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.top{align-items:flex-start;flex-direction:column}}@media(max-width:480px){.wrap{padding:22px 14px}.card{padding:14px}.metric{font-size:25px}}
</style>
</head>
<body><main class="wrap">
<header class="top"><div><div class="eyebrow">SERVER HEALTH / SECURITY</div><h1 class="title">Güncelleme Merkezi</h1><div class="sub">{{ $data['host'] ?? 'Server' }} · {{ $data['package_manager'] ?? 'APT' }} · Son kontrol: {{ !empty($data['checked_at']) ? \Illuminate\Support\Carbon::parse($data['checked_at'])->format('d.m.Y H:i:s') : 'Henüz yapılmadı' }}</div></div><a class="btn" href="{{ route('server-security-update-monitor.dashboard', ['refresh' => 1]) }}">↻ Şimdi kontrol et</a></header>
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
<p class="sub" style="margin-top:18px;font-size:12px">Güvenlik sınıflandırması APT depo metaverisine dayanır. Paket yükseltmeleri bu panelden otomatik uygulanmaz.</p>
</main></body></html>
