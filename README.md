# 😎 YourVPNDead (твой ВПН мёртв) — теперь ты знаешь об этом
<img width="400" alt="image" src="https://github.com/user-attachments/assets/21bb2e1e-6669-4dbc-8062-e5eec43003a7" />

**Самопроверка на обнаружение VPN/прокси на Android**

Демонстрирует, какую информацию о вашем VPN может получить ЛЮБОЕ приложение на устройстве — без root, без специальных разрешений, используя только стандартные API Android.

## Зачем это нужно

В 2024-2026 годах Роскомнадзор и Минцифры активно развивают методы обнаружения VPN на устройствах граждан. Методичка Минцифры описывает проверки, которые могут выполняться приложениями, имеющими доступ к устройству (банковские приложения, приложения госуслуг, маркетплейсы с обязательными SDK).

**Это приложение показывает вам то же самое, что видит потенциальный шпион** — чтобы вы могли защититься.

### Контекст угрозы

- **Яндекс.Метрика** с 2017 года отправляет HTTP-запросы на localhost ([исследование](https://localmess.github.io/))
- **Meta Pixel** использует WebRTC STUN для сканирования localhost (SDP Munging)
- **Минцифры** разработала методику детекции VPN по открытым портам, MTU, DNS, интерфейсам
- **Роскомнадзор** блокирует VPN-протоколы на уровне ТСПУ (DPI), но детекция на устройстве — следующий этап
- Все популярные VPN-клиенты (v2rayNG, NekoBox, Hiddify) создают **SOCKS5-прокси без аутентификации** на localhost — через него можно узнать IP вашего VPN-сервера

## Что проверяет приложение

### 1. Прямые признаки (DirectSignsChecker)

| Проверка | API / Метод | Что обнаруживает |
|----------|------------|-----------------|
| **TRANSPORT_VPN** | `NetworkCapabilities.hasTransport(TRANSPORT_VPN)` | Системный флаг VPN-транспорта |
| **IS_VPN** (скрытый) | `caps.toString().contains("IS_VPN")` | Внутренний флаг Android, не в публичном API |
| **VpnTransportInfo** | `caps.toString().contains("VpnTransportInfo")` | Класс транспорта VPN |
| **HTTP прокси** | `System.getProperty("http.proxyHost")` | Системный HTTP-прокси |
| **SOCKS прокси** | `System.getProperty("socksProxyHost")` | Системный SOCKS-прокси |
| **Известные порты** | Сравнение с базой (1080, 9050, 8080...) | Прокси на стандартных портах |
| **VPN-приложения** | `PackageManager.getPackageInfo()` | 19 известных VPN-клиентов |
| **VPN-интерфейсы** | `NetworkInterface.getNetworkInterfaces()` | tun\d+, tap\d+, wg\d+, ppp\d+, ipsec.* |
| **Таблица маршрутизации** | `/proc/net/route` | Default route через нестандартный интерфейс |
| **Split tunnel** | Сравнение прямого IP и proxy IP | Per-app split bypass |

**Проверяемые VPN-приложения (19 пакетов):**
v2rayNG, sing-box (SFA), Hiddify, ClashMeta, Shadowsocks, HAPP, XrayNG, NekoBox, ByeDPI, ByeByeDPI, Outline, Psiphon, Lantern, WireGuard, strongSwan, Tor Browser, Orbot и другие.

### 2. Косвенные признаки (IndirectSignsChecker)

| Проверка | API / Метод | Логика детекции |
|----------|------------|----------------|
| **NET_CAPABILITY_NOT_VPN** | `caps.hasCapability(NET_CAPABILITY_NOT_VPN)` | Если capability отсутствует — сеть = VPN |
| **MTU аномалии** | `NetworkInterface.getMTU()` | VPN снижает MTU (1500→1400) из-за инкапсуляции |
| **DNS в частной подсети** | `LinkProperties.getDnsServers()` | DNS 192.168.x.x/10.x.x.x = возможен VPN-туннель |
| **dumpsys vpn_management** | `Runtime.exec("dumpsys ...")` | Системная информация о VPN (обычно заблокирована) |
| **dumpsys VpnService** | `Runtime.exec("dumpsys ...")` | Активные VPN-сервисы |

**MTU — почему это работает:**
- Стандартный MTU (Ethernet/WiFi): **1500**
- WireGuard: обычно **1420** (overhead 80 байт)
- OpenVPN: обычно **1400** (overhead ~100 байт)
- VLESS/Trojan (xray): **1380-1400** (зависит от транспорта)
- Если MTU < 1500 на активном интерфейсе — вероятно VPN

### 3. Анализ /proc/net/tcp (ProcNetScanner)

Парсит `/proc/net/tcp` и `/proc/net/tcp6` для обнаружения listening-портов на localhost. **Работает без root** на большинстве Android.

**Идентификация VPN-клиента по паттерну портов:**

| Порт | Клиент |
|------|--------|
| 10808 + 10809 + 19085 | v2rayNG / XrayFluent (xray SOCKS + HTTP + Stats API) |
| 2080 | NekoBox / Throne (sing-box mixed) |
| 7890 + 7891 + 9090 | Clash / mihomo (HTTP + SOCKS + API) |
| 3066 + 3067 | Karing |
| 19090 | sing-box Clash API (**утечка IP серверов через /connections!**) |

### 4. Bypass-проверки

#### 4.1 Сканер портов (PortScanner)

Сканирует **127.0.0.1** и **::1** (IPv6 localhost). Некоторые VPN-клиенты слушают только на IPv6.

- **Быстрый скан**: 40+ известных портов VPN-клиентов
- **Полный скан**: 1-65535, 32 параллельных корутины
- **Определение типа**: SOCKS5 (RFC 1928), HTTP CONNECT, gRPC (HTTP/2)

Известные порты включают: xray (10808-10810), sing-box (2080-2081, 3066-3067), mihomo (7890-7893), API (10085, 19085, 9090), порты из методички Минцифры (9000, 5555, 9050, 3128, 8080), трекинг Яндекс.Метрики (29009-29010, 30102-30103), Meta Pixel (12387-12591).

#### 4.2 SOCKS5 анализ (Socks5Probe + AuthProbe)

- Хендшейк RFC 1928: `\x05\x01\x00` → ожидание `\x05\x00` (noauth) или `\x05\x02` (password)
- HTTP CONNECT проба
- gRPC детекция (HTTP/2 preface + SETTINGS frame)
- **Брутфорс** распространённых паролей (admin/admin, test/test, proxy/proxy...)
- **UDP ASSOCIATE** bypass тест (RFC 1928 Section 7 — UDP без per-packet auth)
- **Демонстрация невозможности перехвата** — raw socket заблокирован без root

#### 4.3 Clash REST API (ClashAPIProbe)

sing-box и mihomo предоставляют Clash API на localhost (9090/19090) **без аутентификации**.

- `GET /connections` — возвращает **ВСЕ** активные соединения включая `destinationIP`
- `GET /proxies` — список прокси-серверов
- `GET /configs` — текущая конфигурация

**Это отдельная уязвимость от SOCKS5** — даже если SOCKS5 auth включён, Clash API может быть открыт.

#### 4.4 xray gRPC API (XrayAPIDetector)

xray-core предоставляет gRPC API (HandlerService) на localhost.

- Метод обнаружения: HTTP/2 connection preface + пустой SETTINGS-фрейм
- Порты: 10085, 19085, 23456, 8001, 62789, 8080, 10086
- **Позволяет дампить конфигурацию включая ключи шифрования** (Happ уязвимость)

#### 4.5 Получение exit IP (ExitIPResolver)

Через уязвимый SOCKS5 (без auth) на localhost:

```
Шпион → localhost:10808 (SOCKS5) → CONNECT api.ipify.org → получает exit IP VPN-сервера
```

Затем геолокация IP через ip-api.com: страна, город, ISP, AS, флаг proxy/hosting.

### 5. Профиль и окружение (ProfileDetector)

- Определение **Work Profile** (Android for Work)
- Обнаружение **Shelter, Island, Insular, Samsung Knox**
- **ВАЖНО**: изоляция профиля **НЕ защищает loopback** (127.0.0.1). Приложения из другого профиля могут сканировать порты.
- Детекция VPN через `TRANSPORT_VPN` + перечисление TUN-интерфейсов

## Уязвимые клиенты

| Клиент | Ядро | Порт | Auth по умолчанию | Статус |
|--------|------|------|-------------------|--------|
| **v2rayNG** | xray | 10808 | Нет | **Уязвим** |
| **NekoBox** | sing-box | 2080 | Нет | **Уязвим** |
| **Hiddify** | sing-box/xray | — | Нет | **Уязвим** |
| **v2RayTun** | xray | — | Нет | **Уязвим** |
| **Happ** | xray | — | Нет + API | **Критически уязвим — удалите немедленно** |
| **Karing** | sing-box | 3067 | Нет | **Уязвим** |
| **Husi** | sing-box | — | **Да** | Защищён (auth включён) |
| **Clash/mihomo** | mihomo | отключён | N/A | Безопасен (socks-port выключен) |
| **Shadowrocket** | — | — | **Да** | Защищён (iOS) |
| **Throne** | sing-box | — | Нет | **Уязвим** |

## Архитектура

```
ScanOrchestrator (14 фаз)
├── ProfileDetector          — профиль, изоляция, VPN-статус
├── ProcNetScanner           — /proc/net/tcp fingerprinting
├── DirectSignsChecker       — прямые признаки (6 проверок)
├── IndirectSignsChecker     — косвенные признаки (5 проверок)
├── DeviceInfoCollector      — отпечаток устройства
├── PortScanner              — TCP скан IPv4 + IPv6 localhost
├── Socks5Probe              — определение типа прокси
├── XrayAPIDetector          — xray gRPC API
├── ClashAPIProbe            — Clash REST API
├── AuthProbe                — auth анализ + brute-force + sniff demo
├── ExitIPResolver           — exit IP через SOCKS5
└── GeoLocator               — геолокация IP
```

**Стек**: Kotlin, Jetpack Compose, Material 3, Coroutines, MVVM (ViewModel + StateFlow)

## Скачать

APK автоматически публикуется в [Releases](../../releases) после каждого коммита.

## Сборка

```bash
git clone https://github.com/loop-uh/yourvpndead.git
cd yourvpndead
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Или откройте в Android Studio и запустите на устройстве.

## Разрешения

| Разрешение | Зачем |
|-----------|-------|
| `INTERNET` | Сканирование портов, GeoIP |
| `ACCESS_NETWORK_STATE` | Детекция VPN, интерфейсы |
| `QUERY_ALL_PACKAGES` | Обнаружение VPN-приложений (Android 11+) |

**Никакие данные не отправляются на серверы.** Всё сканирование локальное. Отчёт доступен только пользователю.

## Источники

- [Критическая уязвимость VLESS (Habr)](https://habr.com/ru/articles/1020080/)
- [Meta и Яндекс: сканирование localhost (USENIX Security 26)](https://localmess.github.io/)
- [CVE-2023-43644 — sing-box SOCKS5 auth bypass (CVSS 9.1)](https://github.com/advisories/GHSA-r5hm-mp3j-285g)
- [RFC 1928 — SOCKS Protocol Version 5](https://datatracker.ietf.org/doc/html/rfc1928)
- [RFC 1929 — SOCKS5 Username/Password Authentication](https://datatracker.ietf.org/doc/html/rfc1929)
- [v2rayNG issues: #275, #1911, #3670](https://github.com/nicknameisthekey/russia-v2ray-custom-routing-list)

## Лицензия

MIT
