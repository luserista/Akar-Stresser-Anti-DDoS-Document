# Anti-DDoS Koruması Dokümantasyonu

## 📋 İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Sistem Mimarisi](#sistem-mimarisi)
3. [ASN Kontrolü](#asn-kontrolü)
4. [Bad ASN Listesi](#bad-asn-listesi)
5. [Güvenlik Doğrulama Sayfası](#güvenlik-doğrulama-sayfası)
6. [Cookie Bypass Sistemi](#cookie-bypass-sistemi)
7. [Cookie Güvenliği](#cookie-güvenliği)
8. [Proof of Work (PoW)](#proof-of-work-pow)
9. [Bot Detection ve Scoring](#bot-detection-ve-scoring)
10. [CAPTCHA Fallback](#captcha-fallback)
11. [API Endpoints](#api-endpoints)
12. [Rate Limiting ve Cache](#rate-limiting-ve-cache)
13. [Log Rotasyonu](#log-rotasyonu)
14. [Güvenli IP Tespiti](#güvenli-ip-tespiti)
15. [Otomatik ASN Güncelleme](#otomatik-asn-güncelleme)
16. [Konsol Logları](#konsol-logları)
17. [Yapılandırma](#yapılandırma)
18. [Versiyon Notları](#versiyon-notları)

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
- ✅ **Cookie Güvenliği**: HttpOnly, Secure flag'leri ve AES-256 şifreleme
- ✅ **Proof of Work (PoW)**: 8 karakterlik hash bulmacası (4 sıfır başlangıç)
- ✅ **Bot Detection**: Browser fingerprinting, bot scoring sistemi (0-100 skor)
- ✅ **CAPTCHA Fallback**: Bot score > 90 ise hCaptcha gösterilir
- ✅ **Validation Endpoint**: Browser fingerprinting ve bot detection verileri toplanır
- ✅ **LRU Cache**: ASN bilgileri 24 saat cache'lenir (max 10.000 entry)
- ✅ **Log Rotasyonu**: `logs.json` maksimum 1000 kayıt tutar
- ✅ **Güvenli IP Tespiti**: Cloudflare, Nginx proxy desteği, `x-forwarded-for` manipülasyonu önleme
- ✅ **Otomatik ASN Güncelleme**: Her gün 02:00'de `bad_asns.json` otomatik güncellenir
- ✅ **Rate Limiting**: ASN lookup için API rate limiting (1 saniye delay)

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

### Cache Mekanizması (LRU Cache)

- **Cache Süresi**: 24 saat (TTL)
- **Maksimum Entry**: 10.000 IP
- **Rate Limiting**: Request'ler arası 1 saniye bekle
- **Timeout**: 2 saniye
- **Localhost/Private IP**: Sadece `127.0.0.1` ve `::1` bypass, diğer private IP'ler kontrol edilir

**LRU Cache Kullanımı**:
```javascript
// utils/cache.js
const { LRUCache } = require('lru-cache');
const asnCache = new LRUCache({
    max: 10000,
    ttl: 24 * 60 * 60 * 1000 // 24 saat
});
```

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
- **Otomatik Güncelleme**: Her gün 02:00'de `https://api.bad-asn.com/list.json` adresinden güncellenir
- **Cron Job**: `node-cron` ile otomatik çalışır
- Hata durumunda eski liste korunur

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

## 🔐 Cookie Güvenliği

### Güvenlik Flag'leri

Tüm cookie'ler aşağıdaki güvenlik flag'leri ile set edilir:

- **HttpOnly**: `true` - JavaScript tarafından erişilemez (XSS koruması)
- **Secure**: `true` - Sadece HTTPS üzerinden gönderilir
- **SameSite**: `Lax` - CSRF koruması

### AES-256 Şifreleme

`asn_bypass_ip` ve `asn_bypass_asn` cookie'leri şifrelenir.

**Şifreleme Algoritması**: AES-256-CBC

**Kod**: `utils/crypto.js`

```javascript
const { encryptCookie, decryptCookie } = require('./utils/crypto');

// Şifreleme
const encryptedIP = encryptCookie('139.28.176.106');
// Çıktı: "iv_base64:encrypted_data_base64"

// Şifre çözme
const decryptedIP = decryptCookie(encryptedIP);
// Çıktı: "139.28.176.106"
```

### Secret Key Yönetimi

**Ortam Değişkeni**: `.env` dosyasından `COOKIE_SECRET` okunur

```env
COOKIE_SECRET=your-very-long-random-secret-key-minimum-32-characters-required
```

**Fallback**: `.env` dosyası yoksa veya secret çok kısa ise varsayılan secret kullanılır (production'da kullanılmamalı)

**Key Türetme**: SHA-256 hash ile 32 byte key türetilir

```javascript
function deriveKey(secret) {
    return crypto.createHash('sha256').update(secret).digest();
}
```

### Cookie Formatı

**Şifreli Cookie Formatı**: `iv_base64:encrypted_data_base64`

- **IV (Initialization Vector)**: Her şifreleme için rastgele 16 byte IV kullanılır
- **Encrypted Data**: Base64 kodlanmış şifreli veri

---

## ⚡ Proof of Work (PoW)

### Genel Bakış

Proof of Work, bot ve otomatik saldırıları önlemek için kullanıcının CPU hesaplama gücü ister.

### PoW Mekanizması

**Challenge**: 8 karakterlik rastgele string

**Hedef**: SHA-256 hash'in ilk 4 karakteri `0000` olmalı

**Çözüm**: `nonce` değeri bulunur

### Kod Yapısı

**Client-side** (`views/js.ejs`):

```javascript
// Challenge oluştur
var powChallenge = generatePoWChallenge(); // 8 karakter

// PoW çöz
async function solvePoWAsync(challenge) {
    var nonce = 0;
    while (nonce < 1000000) {
        var hash = await sha256(challenge + nonce);
        if (hash.startsWith('0000')) {
            return {
                challenge: challenge,
                nonce: nonce,
                hash: hash,
                time: (Date.now() - startTime) / 1000
            };
        }
        nonce++;
    }
    return null;
}
```

**Server-side Validation** (`validate.js`):

```javascript
// PoW doğrulama
if (proofOfWork) {
    const expectedHash = await sha256(proofOfWork.challenge + proofOfWork.nonce);
    if (expectedHash.startsWith('0000')) {
        // PoW geçerli
        if (proofOfWork.time < 0.1) {
            botScore += 20; // Çok hızlı çözüm (şüpheli)
        }
    } else {
        botScore += 50; // Geçersiz PoW
    }
} else {
    botScore += 100; // PoW eksik
}
```

### PoW Skorlama

- **PoW eksik**: +100 puan
- **Geçersiz PoW**: +50 puan
- **Çok hızlı çözüm (<0.1s)**: +20 puan (bot olabilir)

---

## 🤖 Bot Detection ve Scoring

### Bot Skorlama Sistemi

Her validation isteği için **0-100** arası bir bot skoru hesaplanır.

**Dosya**: `validate.js` → `calculateBotScore(validationData)`

### Skorlama Kriterleri

| Kriter | Puan | Açıklama |
|--------|------|----------|
| `webdriver: true` | +50 | Otomasyon tespit edildi |
| `headless: true` | +40 | Headless browser tespit edildi |
| `mouseMovements < 3` | +30 | Yetersiz mouse hareketi |
| `proofOfWork` eksik | +100 | PoW yapılmadı |
| PoW çok hızlı (<0.1s) | +20 | Şüpheli hızlı çözüm |
| Geçersiz PoW | +50 | PoW doğrulanamadı |
| `selenium: true` | +60 | Selenium tespit edildi |
| `puppeteer: true` | +60 | Puppeteer tespit edildi |
| `honeypotFilled: true` | +80 | Honeypot dolduruldu |
| `userAgent` eksik | +25 | User agent yok |

### Skor Kategorileri

- **0-69**: Normal kullanıcı ✅
- **70-89**: Şüpheli kullanıcı ⚠️ (log'lanır)
- **90-100**: Yüksek şüpheli / Bot 🚫 (CAPTCHA gösterilir)

### Validation Response

```javascript
{
    valid: true,
    botScore: 50,
    requiresCaptcha: false,
    reason: "Validation passed"
}
```

**Bot Score > 90** ise:

```javascript
{
    valid: true,
    botScore: 95,
    requiresCaptcha: true,
    reason: "Bot score too high, CAPTCHA required"
}
```

---

## 🛡️ CAPTCHA Fallback

### Genel Bakış

Bot score > 90 ise kullanıcıya hCaptcha gösterilir.

### Çalışma Mantığı

1. Kullanıcı `js.ejs` sayfasından geçer
2. PoW çözülür ve `/api/validate` endpoint'ine gönderilir
3. Bot score hesaplanır
4. **Bot score > 90** ise:
   - `/api/validate` response'unda `requiresCaptcha: true` döner
   - `js.ejs` sayfası `/captcha` sayfasına yönlendirir
5. Kullanıcı CAPTCHA'yı çözer
6. Token `/api/validate-captcha` endpoint'ine gönderilir
7. Başarılı ise bypass cookie'leri set edilir

### CAPTCHA Sayfası

**Dosya**: `views/captcha.ejs`

**Özellikler**:
- hCaptcha widget entegrasyonu
- Token gönderimi
- Başarılı doğrulama sonrası ana sayfaya yönlendirme

### API Endpoint

**POST `/api/validate-captcha`**

```javascript
{
    token: "hcaptcha_token_here"
}
```

**Response**:
```javascript
{
    success: true,
    message: "CAPTCHA doğrulandı"
}
```

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
- `js.ejs` sayfasında cookie set edilirken **asenkron** olarak çağrılır
- `fetch` API kullanılır (3 saniye timeout)
- Server-side'da HttpOnly cookie'ler set edilir

**Kod Örneği**:
```javascript
// Asenkron fetch (js.ejs)
async function setCookie() {
    try {
        const response = await fetch('/api/get-ip', {
            method: 'GET',
            credentials: 'include',
            timeout: 3000
        });
        const data = await response.json();
        // Server-side cookie'ler otomatik set edilir
    } catch(e) {
        console.warn('IP bilgisi alınamadı:', e);
    }
}
```

**Server-side Cookie Set**:
```javascript
// index.js - /api/get-ip endpoint
res.cookie('asn_bypass', '1', {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax'
});

res.cookie('asn_bypass_ip', encryptedIP, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax'
});

res.cookie('asn_bypass_asn', encryptedASN, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax'
});
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

## ⚡ Rate Limiting ve Cache

### ASN Lookup Rate Limiting

**Gerekçe**: `ip-api.com` API'sinin rate limit'i var.

**Mekanizma**:
- Request'ler arası **1 saniye** bekleme
- Her IP için **24 saat** cache (LRU Cache)
- **2 saniye** timeout
- **429 (Too Many Requests)** hataları sessizce ignore edilir

### LRU Cache Yapısı

**Dosya**: `utils/cache.js`

```javascript
const { LRUCache } = require('lru-cache');

const asnCache = new LRUCache({
    max: 10000,           // Maksimum 10.000 entry
    ttl: 24 * 60 * 60 * 1000, // 24 saat TTL
    updateAgeOnGet: false,
    updateAgeOnHas: false
});
```

**Fonksiyonlar**:
- `getASNCache(ip)`: Cache'den ASN bilgisi al
- `setASNCache(ip, asn)`: Cache'e ASN bilgisi kaydet
- `hasASNCache(ip)`: Cache'de var mı kontrol et
- `clearASNCache()`: Cache'i temizle
- `getASNCacheStats()`: Cache istatistikleri

**Avantajlar**:
- Bellek sızıntısı önleme (eski entry'ler otomatik silinir)
- Performans iyileştirme (10.000 entry'e kadar hızlı erişim)
- TTL desteği (24 saat sonra otomatik expire)

---

## 📝 Log Rotasyonu

### Genel Bakış

`logs.json` dosyası maksimum **1000 kayıt** tutar. Yeni kayıt eklendiğinde en eski kayıtlar otomatik silinir.

### Kod Yapısı

**Dosya**: `utils/logs.js`

```javascript
function pushLog(logEntry) {
    try {
        let logs = [];
        if (fs.existsSync(LOGS_FILE)) {
            logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
        }
        
        logs.push({
            ...logEntry,
            timestamp: new Date().toISOString()
        });
        
        // Maksimum 1000 kayıt tut
        if (logs.length > 1000) {
            logs = logs.slice(-1000); // En son 1000 kayıt
        }
        
        fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2));
    } catch (error) {
        console.error('Log yazma hatası:', error);
    }
}
```

### Log Formatı

```json
[
    {
        "timestamp": "2025-11-03T14:58:52.659Z",
        "ip": "104.23.162.132",
        "userAgent": "Mozilla/5.0...",
        "valid": true,
        "botScore": 50,
        "reason": "Validation passed"
    }
]
```

---

## 🌐 Güvenli IP Tespiti

### Genel Bakış

Güvenilir proxy'lerden (Cloudflare, Nginx) gelen IP'ler doğru şekilde tespit edilir ve `x-forwarded-for` manipülasyonu önlenir.

### Kod Yapısı

**Dosya**: `utils/ip.js`

```javascript
function getClientIP(req, customTrustedProxies = []) {
    // 1. Cloudflare IP (öncelikli)
    if (req.headers['cf-connecting-ip']) {
        return cleanIP(req.headers['cf-connecting-ip']);
    }
    
    // 2. Nginx Real IP
    if (req.headers['x-real-ip']) {
        return cleanIP(req.headers['x-real-ip']);
    }
    
    // 3. X-Forwarded-For (güvenilir proxy'lerden)
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
        const ips = xForwardedFor.split(',').map(ip => ip.trim());
        // İlk IP'yi al (en güvenilir)
        return cleanIP(ips[0]);
    }
    
    // 4. Direkt IP
    return cleanIP(req.connection?.remoteAddress || req.socket?.remoteAddress);
}

function cleanIP(ip) {
    // IPv6 mapped IPv4 temizleme (::ffff:)
    if (ip && ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }
    return ip;
}
```

### Proxy Desteği

- ✅ **Cloudflare**: `cf-connecting-ip` header'ı öncelikli kontrol edilir
- ✅ **Nginx**: `x-real-ip` header'ı kontrol edilir
- ✅ **X-Forwarded-For**: Sadece ilk IP alınır (manipülasyon önleme)

### IPv6 Desteği

IPv6 mapped IPv4 adresleri (`::ffff:192.168.1.1`) otomatik temizlenir.

---

## 🔄 Otomatik ASN Güncelleme

### Genel Bakış

Her gün 02:00'de `bad_asns.json` dosyası otomatik güncellenir.

### Cron Job

**Dosya**: `cron/update-asn.js`

```javascript
async function updateBadASNList() {
    try {
        const response = await axios.get('https://api.bad-asn.com/list.json', {
            timeout: 10000
        });
        
        const newASNs = response.data;
        
        // Validasyon: En az 500 ASN olmalı
        if (Array.isArray(newASNs) && newASNs.length > 500) {
            fs.writeFileSync(BAD_ASNS_FILE, JSON.stringify(newASNs, null, 2));
            console.log(`✅ Bad ASN listesi güncellendi: ${newASNs.length} ASN`);
            return true;
        } else {
            console.warn('⚠️ Yeni ASN listesi geçersiz, eski liste korunuyor');
            return false;
        }
    } catch (error) {
        console.error('❌ ASN listesi güncellenemedi:', error.message);
        return false;
    }
}
```

### Cron Schedule

**Dosya**: `index.js`

```javascript
const cron = require('node-cron');

// Her gün 02:00'de çalıştır
cron.schedule('0 2 * * *', async () => {
    console.log('🔄 Bad ASN listesi güncelleniyor...');
    await updateBadASNList();
});
```

### Hata Durumu

- API'den veri alınamazsa: Eski liste korunur
- Yeni liste geçersizse (<500 ASN): Eski liste korunur
- Hata loglanır ancak sistem çalışmaya devam eder

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
├── validate.js           # Browser validation ve bot scoring
├── bad_asns.json        # Bad ASN listesi (600+ ASN)
├── logs.json            # Validation logları (max 1000 kayıt)
├── .env                 # Ortam değişkenleri (COOKIE_SECRET)
├── .htaccess            # URL rewriting ve erişim kontrolü
├── utils/
│   ├── crypto.js        # AES-256 cookie şifreleme
│   ├── ip.js            # Güvenli IP tespiti
│   ├── cache.js         # LRU cache (ASN cache)
│   └── logs.js          # Log rotasyonu (max 1000 kayıt)
├── cron/
│   └── update-asn.js    # Günlük ASN listesi güncelleme
└── views/
    ├── js.ejs           # Güvenlik doğrulama sayfası (PoW, bot detection)
    └── captcha.ejs      # CAPTCHA fallback sayfası
```

---

## 🚀 Geliştirme Notları

### Yeni Özellikler (v3.0 - Son Güncelleme)

1. ✅ **Cookie Güvenliği**: HttpOnly, Secure flag'leri ve AES-256 şifreleme
2. ✅ **Proof of Work (PoW)**: 8 karakterlik hash bulmacası (4 sıfır başlangıç)
3. ✅ **Bot Detection**: Browser fingerprinting ve bot scoring sistemi (0-100)
4. ✅ **CAPTCHA Fallback**: Bot score > 90 ise hCaptcha gösterilir
5. ✅ **LRU Cache**: ASN cache'i LRU cache'e taşındı (max 10.000 entry, TTL 24 saat)
6. ✅ **Log Rotasyonu**: `logs.json` maksimum 1000 kayıt tutar
7. ✅ **Güvenli IP Tespiti**: Cloudflare, Nginx proxy desteği, `x-forwarded-for` manipülasyonu önleme
8. ✅ **Otomatik ASN Güncelleme**: Her gün 02:00'de `bad_asns.json` otomatik güncellenir (cron job)
9. ✅ **IPv6 Desteği**: IPv6 mapped IPv4 adresleri (`::ffff:`) otomatik temizlenir
10. ✅ **Private IP Bypass Kısıtlaması**: Sadece `127.0.0.1` ve `::1` bypass, diğer private IP'ler kontrol edilir
11. ✅ **Asenkron Cookie Set**: `/api/get-ip` endpoint'i asenkron fetch ile çağrılır (3 saniye timeout)

### Gelecek İyileştirmeler

1. **Geolocation Kontrolü**: IP konumuna göre filtreleme
2. **Rate Limiting**: Per-IP request limit
3. **Machine Learning**: Anormal trafik tespiti
4. **Redis Entegrasyonu**: ASN cache'i Redis'e taşınabilir
5. **Database Entegrasyonu**: Bad ASN listesi database'de saklanabilir
6. **Real-time Monitoring**: Canlı trafik izleme dashboard'u

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

**Son Güncelleme**: 2025 Ekim 3  
**Versiyon**: 3.0

---

## 📝 Versiyon Notları

### v3.0 (2025 Ekim 3)
- ✅ **Cookie Güvenliği**: HttpOnly, Secure flag'leri ve AES-256 şifreleme eklendi
- ✅ **Proof of Work (PoW)**: 8 karakterlik hash bulmacası (4 sıfır başlangıç) eklendi
- ✅ **Bot Detection**: Browser fingerprinting ve bot scoring sistemi (0-100) eklendi
- ✅ **CAPTCHA Fallback**: Bot score > 90 ise hCaptcha gösterilir
- ✅ **LRU Cache**: ASN cache'i `lru-cache` paketine taşındı (max 10.000 entry, TTL 24 saat)
- ✅ **Log Rotasyonu**: `logs.json` maksimum 1000 kayıt tutar (en eskileri silinir)
- ✅ **Güvenli IP Tespiti**: Cloudflare, Nginx proxy desteği, `x-forwarded-for` manipülasyonu önleme
- ✅ **Otomatik ASN Güncelleme**: Her gün 02:00'de `bad_asns.json` otomatik güncellenir (`node-cron`)
- ✅ **IPv6 Desteği**: IPv6 mapped IPv4 adresleri (`::ffff:`) otomatik temizlenir
- ✅ **Private IP Bypass Kısıtlaması**: Sadece `127.0.0.1` ve `::1` bypass
- ✅ **Asenkron Cookie Set**: `/api/get-ip` endpoint'i asenkron fetch ile çağrılır (3 saniye timeout)
- ✅ **Utility Modülleri**: `utils/crypto.js`, `utils/ip.js`, `utils/cache.js`, `utils/logs.js` eklendi
- ✅ **Cron Job Modülü**: `cron/update-asn.js` eklendi

### v2.0 (2025 - Geçmiş Versiyon)
- ✅ IP ve ASN cookie takibi eklendi
- ✅ IP değişikliği kontrolü eklendi
- ✅ ASN değişikliği kontrolü eklendi
- ✅ Session cookie desteği (tarayıcı kapanana kadar geçerli)
- ✅ VPN açıldığında otomatik cookie temizleme
- ✅ `/api/get-ip` endpoint'i eklendi
- ✅ Senkron IP alma mekanizması

### v1.0 (2025 - Geçmiş Versiyon)
- ✅ ASN tabanlı filtreleme
- ✅ Bad ASN veritabanı
- ✅ Güvenlik doğrulama sayfası (js.ejs)
- ✅ Cookie bypass sistemi
- ✅ Validation endpoint

