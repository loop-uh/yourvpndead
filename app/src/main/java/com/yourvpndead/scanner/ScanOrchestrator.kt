package com.yourvpndead.scanner

import android.content.Context
import com.yourvpndead.model.*

/**
 * Оркестратор — запускает все модули скана последовательно,
 * собирает результаты и формирует итоговый ScanResult с findings.
 */
class ScanOrchestrator(context: Context) {

    private val portScanner = PortScanner()
    private val socks5Probe = Socks5Probe()
    private val authProbe = AuthProbe()
    private val exitIPResolver = ExitIPResolver()
    private val xrayAPIDetector = XrayAPIDetector()
    private val deviceInfoCollector = DeviceInfoCollector(context)
    private val geoLocator = GeoLocator()

    /**
     * Быстрый скан — только известные порты.
     * @param onPhase колбэк смены фазы скана
     * @param onProgress колбэк прогресса (0.0 - 1.0)
     */
    suspend fun quickScan(
        onPhase: (ScanPhase) -> Unit = {},
        onProgress: (Float) -> Unit = {}
    ): ScanResult {
        val findings = mutableListOf<Finding>()

        // Фаза 1: Информация об устройстве
        onPhase(ScanPhase.DEVICE_INFO)
        onProgress(0.05f)
        val device = deviceInfoCollector.collect()

        if (device.isVpnActive) {
            findings.add(Finding(
                Severity.INFO, "VPN активен",
                "Система определяет активное VPN-подключение (TRANSPORT_VPN)",
                mapOf("Прямой IP" to (device.directIP ?: "не определён"))
            ))
        }

        // Фаза 2: Скан портов
        onPhase(ScanPhase.PORT_SCAN)
        val openPorts = portScanner.scanKnownPorts { onProgress(0.1f + it * 0.3f) }

        if (openPorts.isEmpty()) {
            findings.add(Finding(
                Severity.SAFE, "Открытых прокси-портов не найдено",
                "Ни один из ${PortScanner.KNOWN_PORTS.size} известных портов не открыт на localhost"
            ))
            return ScanResult(device = device, openPorts = openPorts, findings = findings)
        }

        findings.add(Finding(
            Severity.INFO, "Найдено ${openPorts.size} открытых портов",
            "Порты: ${openPorts.joinToString { it.port.toString() }}"
        ))

        // Фаза 3: Определение типа прокси
        onPhase(ScanPhase.PROXY_PROBE)
        val proxies = openPorts.mapIndexed { idx, port ->
            onProgress(0.4f + (idx.toFloat() / openPorts.size) * 0.2f)
            socks5Probe.probe(port.port)
        }

        proxies.filter { it.vulnerable }.forEach { proxy ->
            findings.add(Finding(
                Severity.CRITICAL,
                "${proxy.type.icon} ${proxy.type.label} на порту ${proxy.port}",
                proxy.details,
                mapOf("Порт" to proxy.port.toString(), "Тип" to proxy.type.label)
            ))
        }

        proxies.filter { !it.vulnerable && it.type != ProxyType.UNKNOWN }.forEach { proxy ->
            findings.add(Finding(
                Severity.SAFE,
                "${proxy.type.icon} ${proxy.type.label} на порту ${proxy.port}",
                proxy.details
            ))
        }

        // Фаза 4: Поиск xray API
        onPhase(ScanPhase.API_DETECT)
        onProgress(0.65f)
        val xrayApi = xrayAPIDetector.detect()

        if (xrayApi != null) {
            findings.add(Finding(
                Severity.CRITICAL,
                "⚠️ xray API обнаружен на порту ${xrayApi.port}!",
                xrayApi.details,
                mapOf("Порт" to xrayApi.port.toString())
            ))
        }

        // Фаза 5: Проверка аутентификации + попытка перехвата
        onPhase(ScanPhase.AUTH_PROBE)
        val socksProxies = proxies.filter {
            it.type == ProxyType.SOCKS5_NO_AUTH || it.type == ProxyType.SOCKS5_AUTH_REQUIRED
        }
        val authResults = socksProxies.map { proxy -> authProbe.probe(proxy.port) }

        authResults.forEach { auth ->
            if (auth.bruteForceSuccess == true) {
                findings.add(Finding(
                    Severity.CRITICAL,
                    "🔑 Слабый пароль подобран на порту ${auth.port}!",
                    "Credentials: ${auth.bruteForceCredentials}\nМетод: ${auth.methodName}",
                    mapOf("Порт" to auth.port.toString(), "Пароль" to (auth.bruteForceCredentials ?: ""))
                ))
            }
            if (auth.udpBypassPossible) {
                findings.add(Finding(
                    Severity.WARNING,
                    "UDP bypass возможен на порту ${auth.port}",
                    "UDP ASSOCIATE работает без per-packet auth (RFC 1928 Section 7)"
                ))
            }
            auth.sniffAttempt?.let { sniff ->
                findings.add(Finding(
                    if (sniff.rawSocketBlocked) Severity.SAFE else Severity.CRITICAL,
                    if (sniff.rawSocketBlocked) "🛡️ Перехват пароля невозможен (порт ${auth.port})"
                    else "⚠️ Raw socket доступен — возможен перехват!",
                    sniff.conclusion,
                    buildMap {
                        put("Raw socket заблокирован", if (sniff.rawSocketBlocked) "Да ✅" else "Нет ❌")
                        put("/proc/net/tcp виден", if (sniff.procNetTcpVisible) "Да (метаданные)" else "Нет")
                        put("UDP sniff", sniff.udpSniffResult)
                    }
                ))
            }
        }

        // Фаза 6: Получение выходного IP через уязвимые прокси
        onPhase(ScanPhase.EXIT_IP)
        val exitIPs = mutableListOf<ExitIPInfo>()
        val vulnerableSocks = proxies.filter { it.type == ProxyType.SOCKS5_NO_AUTH }

        vulnerableSocks.forEachIndexed { idx, proxy ->
            onProgress(0.7f + (idx.toFloat() / maxOf(vulnerableSocks.size, 1)) * 0.15f)
            exitIPResolver.resolve(proxy.port)?.let { exitIPs.add(it) }
        }

        // Фаза 6: Геолокация
        onPhase(ScanPhase.GEO_LOOKUP)
        onProgress(0.9f)
        val exitIPsWithGeo = exitIPs.map { exitIP ->
            val geo = geoLocator.locate(exitIP.ip)
            exitIP.copy(geo = geo)
        }

        exitIPsWithGeo.forEach { exitIP ->
            val geo = exitIP.geo
            findings.add(Finding(
                Severity.CRITICAL,
                "Выходной IP VPN раскрыт: ${exitIP.ip}",
                buildString {
                    append("Получен через SOCKS5 на порту ${exitIP.port}\n")
                    if (geo != null) {
                        append("Страна: ${geo.country} (${geo.countryCode})\n")
                        append("Город: ${geo.city}\n")
                        append("Провайдер: ${geo.isp}\n")
                        append("AS: ${geo.asNumber}\n")
                        if (geo.isProxy) append("Определён как прокси/VPN: Да\n")
                        if (geo.isHosting) append("Хостинг: Да\n")
                    }
                },
                buildMap {
                    put("IP", exitIP.ip)
                    put("Порт SOCKS5", exitIP.port.toString())
                    if (geo != null) {
                        put("Страна", "${geo.country} (${geo.countryCode})")
                        put("Город", geo.city)
                        put("ISP", geo.isp)
                        put("AS", geo.asNumber)
                    }
                }
            ))
        }

        onPhase(ScanPhase.DONE)
        onProgress(1f)

        return ScanResult(
            device = device,
            openPorts = openPorts,
            proxies = proxies,
            exitIPs = exitIPsWithGeo,
            xrayAPI = xrayApi,
            authProbes = authResults,
            findings = findings
        )
    }

    /** Полный скан (все 65535 портов) */
    suspend fun fullScan(
        onPhase: (ScanPhase) -> Unit = {},
        onProgress: (Float) -> Unit = {}
    ): ScanResult {
        onPhase(ScanPhase.DEVICE_INFO)
        val device = deviceInfoCollector.collect()

        onPhase(ScanPhase.PORT_SCAN)
        val openPorts = portScanner.scanFullRange { onProgress(it * 0.5f) }

        // Далее — аналогично quickScan но с полным списком портов
        onPhase(ScanPhase.PROXY_PROBE)
        val proxies = openPorts.mapIndexed { idx, port ->
            onProgress(0.5f + (idx.toFloat() / maxOf(openPorts.size, 1)) * 0.2f)
            socks5Probe.probe(port.port)
        }

        onPhase(ScanPhase.API_DETECT)
        onProgress(0.75f)
        val xrayApi = xrayAPIDetector.detect()

        onPhase(ScanPhase.EXIT_IP)
        val exitIPs = mutableListOf<ExitIPInfo>()
        proxies.filter { it.type == ProxyType.SOCKS5_NO_AUTH }.forEach { proxy ->
            exitIPResolver.resolve(proxy.port)?.let { exitIPs.add(it) }
        }

        onPhase(ScanPhase.GEO_LOOKUP)
        onProgress(0.9f)
        val exitIPsWithGeo = exitIPs.map { it.copy(geo = geoLocator.locate(it.ip)) }

        onPhase(ScanPhase.DONE)
        onProgress(1f)

        // Findings генерируются аналогично quickScan
        val findings = buildFindings(device, openPorts, proxies, xrayApi, exitIPsWithGeo)
        return ScanResult(device = device, openPorts = openPorts, proxies = proxies,
            exitIPs = exitIPsWithGeo, xrayAPI = xrayApi, findings = findings)
    }

    private fun buildFindings(
        device: DeviceFingerprint,
        openPorts: List<OpenPort>,
        proxies: List<ProxyInfo>,
        xrayApi: XrayAPIInfo?,
        exitIPs: List<ExitIPInfo>
    ): List<Finding> {
        val findings = mutableListOf<Finding>()

        if (device.isVpnActive) {
            findings.add(Finding(Severity.INFO, "VPN активен", "TRANSPORT_VPN обнаружен"))
        }

        if (openPorts.isEmpty()) {
            findings.add(Finding(Severity.SAFE, "Открытых портов не найдено", "Устройство защищено"))
            return findings
        }

        proxies.filter { it.vulnerable }.forEach {
            findings.add(Finding(Severity.CRITICAL, "${it.type.label} на :${it.port}", it.details))
        }

        if (xrayApi != null) {
            findings.add(Finding(Severity.CRITICAL, "xray API на :${xrayApi.port}", xrayApi.details))
        }

        exitIPs.forEach { exitIP ->
            val desc = exitIP.geo?.let { "Страна: ${it.country}, ${it.city}, ISP: ${it.isp}" } ?: ""
            findings.add(Finding(Severity.CRITICAL, "Exit IP: ${exitIP.ip}", desc))
        }

        return findings
    }
}
