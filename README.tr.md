# Laravel Server Security Update Monitor

Linux sunucularındaki paket güncellemelerini ve güvenlik yamalarını izlemek için Laravel paneli. Debian/Ubuntu üzerinde APT, Fedora, RHEL uyumlu dağıtımlar ve Amazon Linux üzerinde DNF/YUM paket yöneticisini otomatik algılar.

[![Tests](https://github.com/mertaydin/laravel-server-security-update-monitor/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/mertaydin/laravel-server-security-update-monitor/actions/workflows/tests.yml)
[![License](https://img.shields.io/github/license/mertaydin/laravel-server-security-update-monitor)](LICENSE)

## Panel ekran görüntüsü

Ekran görüntüsü GitHub Actions tarafından geçici bir Laravel uygulamasında paketin gerçek panelinden otomatik olarak yeniden alınır.

<p align="center">
  <img src="docs/images/dashboard-screenshot.png" alt="Laravel Server Security Update Monitor panel önizlemesi" width="100%">
</p>

> Önizlemede örnek paket verileri kullanılır; canlı panel sunucunuzdan toplanan değerleri gösterir.

## Panel

Panel, bekleyen güncellemeleri ve kurulu sürüm, aday sürüm, depo suite bilgisi, güncelleme sınıflandırması ve önem durumunu içeren paket tablosunu özet olarak sunar.

- Toplam bekleyen paket güncellemesi.
- Rutin güncellemelerden ayrı gösterilen güvenlik deposu güncellemeleri.
- Kurulu ve aday paket sürümleri.
- Güvenlik güncellemelerinin rutin güncellemelerden önce sıralanması.
- Manuel tarama işlemi ve önbelleğe alınmış tarama sonuçları.
- Türkçe, İngilizce, Arapça, İspanyolca, Hintçe ve Basitleştirilmiş Çince olmak üzere altı panel dili.
- Tarayıcıda saklanan tercihle açık, koyu ve sistem görünüm modları.
- Zamanlanmış veya manuel taramalar için Artisan komutu.

## Gereksinimler

- PHP 8.2+
- Laravel 10, 11, 12 veya 13
- APT ve dpkg-query bulunan Debian/Ubuntu veya DNF/YUM ve RPM bulunan Fedora/RHEL uyumlu/Amazon Linux.
- PHP süreci paket inceleme komutlarını çalıştırabilmelidir. APT taramaları salt okunurdur ve sunucudaki mevcut yerel paket indekslerini kullanır. APT indekslerini yenilemek ayrı bir panel işlemidir; PHP root olmayan kullanıcıyla çalışıyorsa yalnızca `/usr/bin/apt-get update` için dar kapsamlı parolasız sudo izni verin.

## Kurulum

```bash
composer require mertaydin/laravel-server-security-update-monitor
php artisan vendor:publish --tag=server-security-update-monitor-config
php artisan vendor:publish --tag=server-security-update-monitor-assets
```

Kimliği doğrulanmış olarak `/server-security-monitor` adresini açın. Varsayılan rota middleware'i `web` ve `auth` şeklindedir. Operasyonel ayrıntıları açmadan önce uygulamaya özel yönetici kontrolü veya ağ kısıtlaması ekleyin.

## Dil ve görünüm

Panel Türkçe, İngilizce, Arapça, İspanyolca, Hintçe ve Basitleştirilmiş Çince dillerini destekler. Dil seçimi mevcut oturumda saklanır. Görünüm açık, koyu ve sistem temalarını destekler; tercih mevcut tarayıcıda saklanır.

## Erişim kontrolü

Panel varsayılan olarak `web` ve `auth` middleware'lerini kullanır. `app/Providers/AppServiceProvider.php` içinde uygulamaya özel yetkilendirme callback'i ekleyin:

```php
use Illuminate\Http\Request;
use MertAydin\ServerSecurityUpdateMonitor\Facades\ServerSecurityUpdateMonitor;

public function boot(): void
{
    ServerSecurityUpdateMonitor::auth(function (Request $request) {
        return $request->user()
            && $request->user()->hasRole('SuperAdmin');
    });
}
```

Erişime izin vermek için `true`, HTTP 403 yanıtı için `false` döndürün. Callback mevcut isteği alır; callback yoksa yapılandırılmış `web` ve `auth` middleware'leri geçerli kalır.

## Tarama

Manuel tarama başlatın:

```bash
php artisan server-security-monitor:check
```

**Şimdi Kontrol Et** işlemi sunucuda zaten bulunan paket indekslerini kullanır ve `apt-get update` çalıştırmaz. APT sistemlerinde depo metadata bilgilerini yenilemek istediğinizde ayrı **Paket Listelerini Güncelle** panel düğmesini kullanın. Yenileme bağımsız olarak tamamlanır; ardından yeni metadata ile tarama yapmak için **Şimdi Kontrol Et** seçeneğini kullanın.

## Güvenlik sınıflandırması ve önem derecesi

APT paketleri yalnızca depo suite bilgisi yapılandırılmış güvenlik suite kalıplarıyla (varsayılan olarak `-security` veya `/security`) eşleştiğinde güvenlik güncellemesi olarak işaretlenir. DNF/YUM paketleri yalnızca paket yöneticisinin kullanılabilir güvenlik duyuruları listesinde (`updateinfo list --available --security`) yer alıyorsa güvenlik güncellemesi sayılır. Duyuru metadata bilgisi okunamazsa paketlerin güvenlik güncellemesi olduğu tahmin edilmez. Daha yeni bir paket sürümü tek başına güvenlik açığı kanıtı değildir.

**İlk sürümde önem derecesi özellikle bilinmiyor olarak gösterilir.** APT yükseltme listesi güvenilir CVSS puanları veya üretici duyuru önem derecesi sağlamaz. Paket, yetkili bir duyuru ile paket ve düzeltilmiş sürüm eşleştirilmeden güvenlik deposundaki her güncellemeyi Critical veya High olarak etiketlemez. CVE/USN/DSA zenginleştirmesi planlanmaktadır.

## Paket yöneticisi desteği

| Paket yöneticisi | Durum |
| --- | --- |
| APT (Debian/Ubuntu) | İlk destek |
| DNF/YUM | Planlandı |
| APK | Planlandı |

## Yapılandırma

Yayımlanan `config/server-security-update-monitor.php` dosyası şu seçenekleri kontrol eder:

| Anahtar | Varsayılan | Açıklama |
| --- | --- | --- |
| `route.enabled` | `true` | Panel rotasını kaydeder. |
| `route.prefix` | `server-security-monitor` | Panel URL öneki. |
| `route.middleware` | `web, auth` | Paneli koruyan middleware. |
| `cache.key` | `server-security-update-monitor.packages` | Önbelleğe alınan tarama anahtarı. |
| `cache.seconds` | `900` | Anlık görüntünün önbellekte kalma süresi. |
| `command_timeout` | `30` | APT komutu zaman aşımı (saniye). |
| `apt.enabled` | `true` | APT taramasını etkinleştirir. |
| `apt.update_timeout` | `300` | Paneldeki manuel `apt-get update` işlemi için izin verilen en uzun süre (saniye). |
| `apt.security_suites` | `-security, /security` | Güvenlik deposu kabul edilen suite kalıpları. |
| `dnf.enabled` | `true` | DNF/YUM otomatik algılamasını etkinleştirir. |
| `dnf.binaries` | `/usr/bin/dnf`, `/usr/bin/yum`, `/bin/dnf`, `/bin/yum` | DNF/YUM çalıştırılabilir dosya adayları. |
| `apk.enabled` | `true` | Planlanan Alpine APK tarayıcısı için ayrılmıştır. |

## Güvenlik

- Yalnızca salt okunur paket incelemesi yapılır.
- APT metadata yenilemesi yalnızca ayrı panel işlemi açıkça seçildiğinde çalışır. Tarama hiçbir zaman `apt-get update` çalıştırmaz. Yenileme işlemi yalnızca `apt-get update` komutunu çalıştırır; `apt upgrade`, `apt install`, `dnf upgrade`, `yum update`, `apk upgrade` veya herhangi bir paket kurma/kaldırma komutunu çalıştırmaz.
- Paket kurmaz, kaldırmaz veya yükseltmez.
- Depo adlarından veya sürüm numaralarından CVSS önem derecesi çıkarımı yapmaz.

## Lisans

[LICENSE](LICENSE) dosyasına bakın. MIT.

## Destek

- [Değişiklik günlüğü](CHANGELOG.md)
- [GitHub sürümleri](https://github.com/mertaydin/laravel-server-security-update-monitor/releases)
- [Sorunlar](https://github.com/mertaydin/laravel-server-security-update-monitor/issues)
