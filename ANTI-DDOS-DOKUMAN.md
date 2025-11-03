# Anti-DDoS Koruması Dokümantasyonu

## 📋 İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Sistem Mimarisi](#sistem-mimarisi)
3. [ASN Kontrolü](#asn-kontrolü)
4. [Bad ASN Listesi](#bad-asn-listesi)
5. [Güvenlik Doğrulama Sayfası](#güvenlik-doğrulama-sayfası)
6. [Cookie Bypass Sistemi](#cookie-bypass-sistemi)
7. [API Endpoints](#api-endpoints)
8. [Rate Limiting](#rate-limiting)
9. [Konsol Logları](#konsol-logları)
10. [Yapılandırma](#yapılandırma)
11. [Versiyon Notları](#versiyon-notları)

---

## 🎯 Genel Bakış

Akar Stresser platformu, çok katmanlı bir anti-DDoS koruma sistemi ile korunmaktadır. Sistem, şüpheli ASN'lerden gelen trafiği tespit eder, kullanıcıları bir güvenlik doğrulama sayfasından geçirir ve bot trafiğini filtreler.

### Ana Özellikler

- ✅ **ASN Tabanlı Filtreleme**: IP adreslerinden ASN bilgisi alınarak şüpheli ağlar tespit edilir
- ✅ **Bad ASN Veritabanı**: 600+ bilinen kötü ASN (VPN, Proxy, Botnet, Tor Exit Node) listesi
- ✅ **Güvenlik Doğrulama Sayfası**: Tüm kullanıcılar 5 saniye doğrulamadan geçer
- ✅ **Session Cookie Bypass**: Doğrulanmış kullanıcılar için tarayıcı kapanana kadar bypass
- ✅ **IP Değişikliği Kontrolü**: IP değiştiğinde otomatik yeniden doğrulama
- ✅ **ASN Değişikliği Kontrolü**: ASN değiştiğinde otomatik yeniden doğrulama
- ✅ **VPN Tespiti**: Bad ASN tespit edildiğinde cookie'ler temizlenir ve yeniden doğrulama yapılır
- ✅ **Validation Endpoint**: Browser fingerprinting ve bot detection verileri toplanır
- ✅ **Rate Limiting**: ASN lookup için API rate limiting

---

## 🏗️ Sistem Mimarisi

```
┌─────────────────┐
│   Kullanıcı     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Express Server  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│  checkASNMiddleware         │
│  1. Statik dosya kontrolü   │
│  2. IP tespiti              │
│  3. ASN lookup               │
│  4. Bad ASN kontrolü        │
│  5. Cookie kontrolü          │
│     - IP eşleşmesi           │
│     - ASN eşleşmesi          │
└────────┬────────────────────┘
         │
    ┌────┴────┐
    │        │
    ▼        ▼
 Bad     Cookie
 ASN?    Var?
    │        │
    │    ┌───┴───┐
    │    │       │
    ▼    ▼       ▼
  js.ejs IP    ASN
  (5sn)  Aynı? Farklı?
    │    │       │
    │    │       │
    │    ▼       ▼
    │    js.ejs js.ejs
    │    (5sn)  (5sn)
    │    │       │
    └────┴───────┘
         │
         ▼
    Cookie Set
    (IP + ASN)
         │
         ▼
    Normal Sayfalar
```

---

## 🔍 ASN Kontrolü

### ASN Nedir?

ASN (Autonomous System Number), internet servis sağlayıcılarının ve büyük ağların benzersiz tanımlayıcısıdır. Her IP adresi bir ASN'ye aittir.

### Nasıl Çalışır?

1. **IP Adresi Tespiti**: Her gelen request için kullanıcının IP adresi alınır
2. **ASN Lookup**: `ip-api.com` servisi kullanılarak IP'den ASN bilgisi alınır
3. **Bad ASN Kontrolü**: ASN numarası `bad_asns.json` dosyasındaki listede kontrol edilir
4. **Kayıt**: Bad ASN tespit edilirse console'a loglanır

### Kod Yapısı

```javascript
// index.js içinde
async function getASNFromIP(ip) {
    // Cache kontrolü (24 saat)
    // Rate limiting (1 saniye bekle)
    // ip-api.com'dan ASN bilgisi al
    // "AS12345" formatından "12345" çıkar
    // Cache'e kaydet
    return asn;
}
```

### Cache Mekanizması

- **Cache Süresi**: 24 saat
- **Rate Limiting**: Request'ler arası 1 saniye bekle
- **Timeout**: 2 saniye
- **Localhost/Private IP**: Kontrol edilmez (otomatik bypass)

---

## 📋 Bad ASN Listesi

### Dosya: `bad_asns.json`

Bu dosya, bilinen kötü amaçlı ASN'leri içerir:

- **VPN Servisleri**: ExpressVPN, NordVPN, Surfshark vb.
- **Proxy Servisleri**: Tüm proxy sağlayıcıları
- **Botnet Ağları**: Bilinen botnet ASN'leri
- **Tor Exit Nodes**: Tor ağı çıkış noktaları
- **Hosting Şirketleri**: Şüpheli hosting sağlayıcıları
- **Bulut Servisleri**: Kötüye kullanılan bulut servisleri

### Toplam ASN Sayısı

- **600+** farklı kötü ASN numarası
- Günlük otomatik güncelleme kontrolü
- 5 dakika cache süresi

### Dosya Formatı

```json
[
  "AS16276",
  "AS14061",
  "AS20940",
  ...
]
```

---

## 🛡️ Güvenlik Doğrulama Sayfası

### Sayfa: `views/js.ejs`

Tüm kullanıcılar (bad ASN olsun olmasın) bu sayfadan geçer.

### Çalışma Mantığı

1. **Sayfa Yükleme**: Kullanıcı siteye geldiğinde `js.ejs` gösterilir
2. **Cookie Set Etme**: Sayfa yüklendiğinde hemen `asn_bypass=1` cookie'si set edilir
3. **Countdown**: 5 saniye geri sayım başlar
4. **Yönlendirme**: Countdown bitince ana sayfaya yönlendirilir
5. **Cookie Süresi**: 10 dakika geçerlidir

### JavaScript Kodu

```javascript
// Cookie hemen set edilir
setCookie(); // asn_bypass=1 (10 dakika)

// 5 saniye countdown
var timer = setInterval(function() {
    countdown--;
    if (countdown <= 0) {
        window.location.href = '/';
    }
}, 1000);

// Fallback: 10 saniye sonra zorla yönlendir
setTimeout(function() {
    if (!redirected) {
        window.location.href = '/';
    }
}, 10000);
```

### SEO Optimizasyonu

- Meta tags (title, description, keywords)
- Open Graph tags
- Twitter Card tags
- Canonical URL
- Hreflang (TR/EN)

---

## 🍪 Cookie Bypass Sistemi

### Cookie'ler

#### 1. Ana Cookie: `asn_bypass`
**Değer**: `1`  
**Süre**: Session cookie (tarayıcı kapanana kadar geçerli, expires yok)  
**Path**: `/`  
**SameSite**: `Lax`

#### 2. IP Cookie: `asn_bypass_ip`
**Değer**: Mevcut IP adresi (örn: `139.28.176.106`)  
**Süre**: Session cookie  
**Path**: `/`  
**SameSite**: `Lax`  
**Amaç**: IP değişikliği kontrolü için

#### 3. ASN Cookie: `asn_bypass_asn`
**Değer**: Mevcut ASN numarası (örn: `9009`)  
**Süre**: Session cookie  
**Path**: `/`  
**SameSite**: `Lax`  
**Amaç**: ASN değişikliği kontrolü için

### Nasıl Çalışır?

1. Kullanıcı `js.ejs` sayfasına gelir
2. Cookie otomatik set edilir (`asn_bypass=1`)
3. IP bilgisi `/api/get-ip` endpoint'inden alınır (senkron)
4. IP ve ASN cookie'leri set edilir
5. Sonraki request'lerde middleware cookie'yi kontrol eder:
   - **Cookie ve IP aynı** → ✅ Normal sayfalara erişim verilir
   - **Cookie var ama IP bilgisi yok** → ⚠️ `js.ejs` sayfasına yönlendirilir
   - **Cookie var ama IP farklı** → ⚠️ Cookie'ler temizlenir, `js.ejs` sayfasına yönlendirilir
   - **Cookie var ama ASN farklı** → ⚠️ Cookie'ler temizlenir, `js.ejs` sayfasına yönlendirilir
   - **Cookie yok** → ⚠️ `js.ejs` sayfasına yönlendirilir

### Middleware Kontrolü

```javascript
// index.js içinde
async function checkASNMiddleware(req, res, next) {
    // Bad ASN kontrolü önce (VPN açıldığında)
    if (isBadASN) {
        res.clearCookie('asn_bypass');
        res.clearCookie('asn_bypass_ip');
        res.clearCookie('asn_bypass_asn');
        return res.render('js', { forceDeleteCookie: true });
    }
    
    // Cookie kontrolü
    const hasBypassCookie = (req.cookies && req.cookies.asn_bypass === '1') || 
                            cookieHeader.includes('asn_bypass=1');
    
    if (hasBypassCookie) {
        const cookieIP = req.cookies.asn_bypass_ip;
        const currentIP = ip;
        
        // IP değişikliği kontrolü
        if (!cookieIP || cookieIP !== currentIP) {
            // Cookie'leri temizle ve js sayfasına yönlendir
            res.clearCookie('asn_bypass');
            res.clearCookie('asn_bypass_ip');
            res.clearCookie('asn_bypass_asn');
            return res.render('js', {});
        }
        
        // ASN değişikliği kontrolü
        if (cookieASN && asn && cookieASN !== asn) {
            // Cookie'leri temizle ve js sayfasına yönlendir
            return res.render('js', {});
        }
        
        return next(); // Bypass, normal sayfaya geç
    }
    
    // Cookie yoksa js.ejs göster
    return res.render('js', {});
}
```

### IP Değişikliği Kontrolü

**Amaç**: Kullanıcı IP değiştirdiğinde (VPN, proxy, ağ değişikliği) yeniden doğrulama yapmak.

**Mekanizma**:
1. Cookie set edilirken mevcut IP cookie'ye yazılır
2. Her request'te cookie'deki IP ile mevcut IP karşılaştırılır
3. IP farklıysa tüm cookie'ler temizlenir ve js sayfasına yönlendirilir

**Konsol Logları**:
```
✅ Cookie ve IP eşleşiyor - Cookie IP: 139.28.176.106, Mevcut IP: 139.28.176.106 - Bypass ediliyor
⚠️ IP değişti! Cookie IP: 139.28.176.106, Mevcut IP: 94.137.180.107 - Cookie geçersiz kılınıyor
```

### ASN Değişikliği Kontrolü

**Amaç**: Aynı IP'den farklı ASN gelirse (ağ değişikliği) yeniden doğrulama yapmak.

**Mekanizma**:
1. Cookie set edilirken mevcut ASN cookie'ye yazılır
2. Her request'te cookie'deki ASN ile mevcut ASN karşılaştırılır
3. ASN farklıysa tüm cookie'ler temizlenir ve js sayfasına yönlendirilir

**Konsol Logları**:
```
⚠️ ASN değişti! Cookie ASN: 9009, Mevcut ASN: 16010 - Cookie geçersiz kılınıyor
```

### Cookie Kontrol Noktaları

- ✅ Request header'dan (`req.headers.cookie`)
- ✅ Parsed cookie'den (`req.cookies`)
- ✅ IP cookie kontrolü (`asn_bypass_ip`)
- ✅ ASN cookie kontrolü (`asn_bypass_asn`)
- ✅ Her iki kaynak kontrol edilir (garanti için)

---

## 📊 API Endpoints

### Endpoint: `GET /api/get-ip`

**Amaç**: Mevcut IP ve ASN bilgisini döndürür (cookie set etmek için)

**Response**:
```json
{
    "ip": "139.28.176.106",
    "asn": "9009"
}
```

**Kullanım**: 
- `js.ejs` sayfasında cookie set edilirken senkron olarak çağrılır
- XMLHttpRequest (senkron) kullanılır (cookie set edilmeden yönlendirme yapılmasını önlemek için)

**Kod Örneği**:
```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/api/get-ip', false); // false = senkron
xhr.send();
var data = JSON.parse(xhr.responseText);
// IP ve ASN cookie'leri set edilir
```

### Endpoint: `POST /api/validate`

Bu endpoint, browser fingerprinting ve bot detection verilerini toplar.

### Gönderilen Veriler

```javascript
{
    fingerprint: {
        screen: { width, height, colorDepth },
        timezone, language, platform,
        userAgent, cookieEnabled,
        hardwareConcurrency, deviceMemory,
        webdriver,
        canvas, webgl, audio,
        fonts, localStorage, sessionStorage,
        indexedDB, worker, battery, connection
    },
    mouseMovements: number,
    keyPresses: number,
    touchEvents: number,
    performance: { ... },
    proofOfWork: { nonce, time, hash },
    honeypotFilled: boolean,
    isInIframe: boolean,
    botDetection: {
        chrome, phantom, selenium,
        puppeteer, headless, automation
    },
    timestamp: number,
    referrer: string,
    viewport: { width, height },
    devicePixelRatio: number
}
```

### Validation Mantığı

**Dosya**: `validate.js`

```javascript
function validateBrowserData(validationData) {
    // Sadece loglama yapılır, erişim engellenmez (fail-open)
    // Bot detection sonuçları loglanır
    // Her zaman valid: true döner
    return { valid: true, reason: 'logging only' };
}
```

### Loglama

- Her validation request `logs.json` dosyasına kaydedilir
- Son 1000 validation kaydı saklanır
- Console'a detaylı log yazılır

---

## ⚡ Rate Limiting

### ASN Lookup Rate Limiting

**Gerekçe**: `ip-api.com` API'sinin rate limit'i var.

**Mekanizma**:
- Request'ler arası **1 saniye** bekleme
- Her IP için **24 saat** cache
- **2 saniye** timeout
- **429 (Too Many Requests)** hataları sessizce ignore edilir

### Cache Yapısı

```javascript
const asnCache = new Map(); // { ip: { asn: string, timestamp: number } }
const ASN_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 saat
const ASN_RATE_LIMIT_DELAY = 1000; // 1 saniye
```

---

## 📝 Konsol Logları

### ASN Kontrolü Logları

```
🔍 Request geldi - IP: 139.28.176.106, Path: /
🔍 ASN bilgisi alındı: 9009 - IP: 139.28.176.106
🔍 Localhost/Private IP tespit edildi: 127.0.0.1 - ASN kontrol edilmedi
🚫 Bad ASN tespit edildi: 12345 (12345) - IP: 1.2.3.4
📋 Bad ASN listesi güncellendi: 600 ASN bulundu
⚠️ VPN/Bad ASN tespit edildi, cookie temizleniyor - IP: 1.2.3.4
⚠️ VPN/Bad ASN tespit edildi, js sayfasına yönlendiriliyor - IP: 1.2.3.4
```

### Cookie Kontrolü Logları

```
✅ Cookie ve IP eşleşiyor - Cookie IP: 139.28.176.106, Mevcut IP: 139.28.176.106 - Bypass ediliyor
⚠️ IP değişti! Cookie IP: 139.28.176.106, Mevcut IP: 94.137.180.107 - Cookie geçersiz kılınıyor
⚠️ Cookie var ama IP bilgisi yok, js sayfasına yönlendiriliyor - IP: 139.28.176.106
⚠️ ASN değişti! Cookie ASN: 9009, Mevcut ASN: 16010 - Cookie geçersiz kılınıyor
📄 Cookie yok, js sayfasına yönlendiriliyor
```

### Validation Logları

```
🔒 Validation Request: { ip, userAgent, valid, reason, botDetection }
🔒 Validation Data arka planda gönderiliyor...
🔒 Validation Response: { success, valid, reason, message }
```

---

## ⚙️ Yapılandırma

### index.js İçindeki Sabitler

```javascript
// Dosya yolu
const BAD_ASNS_FILE = './bad_asns.json';

// Cache süreleri
const ASN_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 saat
const BAD_ASN_CACHE_DURATION = 5 * 60 * 1000; // 5 dakika

// Rate limiting
const ASN_RATE_LIMIT_DELAY = 1000; // 1 saniye

// API timeout
const ASN_API_TIMEOUT = 2000; // 2 saniye
```

### js.ejs İçindeki Süreler

```javascript
var countdown = 5; // Saniye
var fallbackTimeout = 10000; // 10 saniye
// Cookie süresi: Session cookie (expires yok - tarayıcı kapanana kadar geçerli)
```

---

## 🔧 Sorun Giderme

### Cookie Set Edilmiyor

**Kontrol Listesi**:
1. Browser'da cookie'ler etkin mi?
2. HTTPS kullanıyorsanız `Secure` flag gerekli (şu anda yok, HTTP için)
3. Cookie path doğru mu? (`/`)
4. SameSite policy uygun mu? (`Lax`)
5. `/api/get-ip` endpoint'i çalışıyor mu?
6. IP cookie'si set ediliyor mu? (Console'da kontrol edin)

### IP Değişikliği Tespit Edilmiyor

**Kontrol Listesi**:
1. `asn_bypass_ip` cookie'si set ediliyor mu?
2. Cookie'deki IP ile mevcut IP eşleşiyor mu?
3. Console loglarını kontrol edin: `⚠️ IP değişti!` mesajı görünüyor mu?
4. IP cookie'si doğru formatda mı? (sadece IP adresi, başka karakter yok)

### ASN Değişikliği Tespit Edilmiyor

**Kontrol Listesi**:
1. `asn_bypass_asn` cookie'si set ediliyor mu?
2. Cookie'deki ASN ile mevcut ASN eşleşiyor mu?
3. ASN bilgisi API'den geliyor mu?
4. Console loglarını kontrol edin: `⚠️ ASN değişti!` mesajı görünüyor mu?

### ASN Bilgisi Alınamıyor

**Nedenleri**:
- ip-api.com rate limit'e takıldı
- Network timeout
- API servisi çalışmıyor

**Çözüm**:
- Cache mekanizması devreye girer
- Timeout sonrası null döner (sistem devam eder)

### Validation Endpoint Yanıt Vermiyor

**Durum**: Validation endpoint çalışmıyorsa sayfa yine de çalışır
**Neden**: Fail-open yaklaşımı (validation opsiyonel)

### Sayfa Takılıyor

**Kontrol**:
1. Browser console'u açın
2. JavaScript hatalarını kontrol edin
3. Network tab'inde request'leri kontrol edin
4. Cookie'nin set edilip edilmediğini kontrol edin

---

## 📚 Dosya Yapısı

```
akarstresserdiscordbot/
├── index.js              # Ana server, middleware, routes
├── validate.js           # Validation fonksiyonları
├── bad_asns.json        # Bad ASN listesi
├── logs.json            # Validation logları
├── views/
│   └── js.ejs           # Güvenlik doğrulama sayfası
└── .htaccess            # URL rewriting ve erişim kontrolü
```

---

## 🚀 Geliştirme Notları

### Yeni Özellikler (Son Güncelleme)

1. ✅ **IP Takibi**: Her kullanıcının IP'si cookie'de saklanıyor
2. ✅ **ASN Takibi**: Her kullanıcının ASN'i cookie'de saklanıyor
3. ✅ **IP Değişikliği Kontrolü**: IP değiştiğinde otomatik yeniden doğrulama
4. ✅ **ASN Değişikliği Kontrolü**: ASN değiştiğinde otomatik yeniden doğrulama
5. ✅ **Session Cookie**: Cookie'ler tarayıcı kapanana kadar geçerli
6. ✅ **VPN Tespiti**: Bad ASN tespit edildiğinde cookie'ler temizleniyor
7. ✅ **Senkron IP Alma**: Cookie set edilmeden yönlendirme yapılmasını önler

### Gelecek İyileştirmeler

1. **CAPTCHA Entegrasyonu**: Şüpheli kullanıcılar için CAPTCHA
2. **Geolocation Kontrolü**: IP konumuna göre filtreleme
3. **Rate Limiting**: Per-IP request limit
4. **Honeypot Geliştirme**: Daha gelişmiş bot detection
5. **Machine Learning**: Anormal trafik tespiti
6. **Cookie Encryption**: Cookie'lerdeki IP/ASN bilgilerini şifreleme

### Performans Optimizasyonları

- ASN cache'i Redis'e taşınabilir
- Bad ASN listesi database'de saklanabilir
- Validation endpoint için queue sistemi

---

## 📞 Destek

Sorularınız için:
- Console loglarını kontrol edin
- Browser DevTools Network tab'ını inceleyin
- Server loglarını takip edin

---

**Son Güncelleme**: 2024  
**Versiyon**: 2.0

---

## 📝 Versiyon Notları

### v2.0 (2024)
- ✅ IP ve ASN cookie takibi eklendi
- ✅ IP değişikliği kontrolü eklendi
- ✅ ASN değişikliği kontrolü eklendi
- ✅ Session cookie desteği (tarayıcı kapanana kadar geçerli)
- ✅ VPN açıldığında otomatik cookie temizleme
- ✅ `/api/get-ip` endpoint'i eklendi
- ✅ Senkron IP alma mekanizması

### v1.0 (2024)
- ✅ ASN tabanlı filtreleme
- ✅ Bad ASN veritabanı
- ✅ Güvenlik doğrulama sayfası (js.ejs)
- ✅ Cookie bypass sistemi
- ✅ Validation endpoint

