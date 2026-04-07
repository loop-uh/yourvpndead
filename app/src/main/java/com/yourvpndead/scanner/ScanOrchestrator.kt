package com.yourvpndead.scanner

import android.content.Context
import com.yourvpndead.model.*

/**
 * Оркестратор — запускает все модули скана последовательно,
 * собирает результаты и формирует итоговый ScanResult с findings.
 */
class ScanOrchestrator(context: Context) {

    private val profileDetector = ProfileDetector(context)
    private val procNetScanner = ProcNetScanner()
    private val portScanner = PortScanner()
    private val socks5Probe = Socks5Probe()
    private val authProbe = AuthProbe()
    private val clashAPIProbe = ClashAPIProbe()
    private val exitIPResolver = ExitIPResolver()
    private val xrayAPIDetector = XrayAPIDetector()
    private val deviceInfoCollector = DeviceInfoCollector(context)
    private val geoLocator = GeoLocator()
    private val directSignsChecker = DirectSignsChecker(context)

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

        // Фаза 0: Профиль и окружение
        onPhase(ScanPhase.PROFILE_DETECT)
        onProgress(0.02f)
        val profile = profileDetector.detect()

        if (profile.isIsolated) {
            findings.add(Finding(
                Severity.WARNING,
                "📱 Запущено в изолированном профиле: ${profile.isolationMethod}",
                "ВНИМАНИЕ: изоляция профиля НЕ защищает loopback (127.0.0.1).\n" +
                "Приложения из другого профиля могут сканировать ваши порты.",
                mapOf("User ID" to profile.currentUserId.toString(), "Профилей" to profile.profileCount.toString())
            ))
        }

        if (profile.vpn.isActive) {
            findings.add(Finding(
                Severity.INFO, "🔒 VPN активен",
                "Обнаружен через: ${profile.vpn.transportTypes.joinToString()}\n" +
                "TUN интерфейсы: ${profile.vpn.tunInterfaces.joinToString().ifEmpty { "не найдены" }}"
            ))
        }

        // Фаза 0.5: /proc/net/tcp анализ
        onPhase(ScanPhase.PROC_NET_SCAN)
        onProgress(0.04f)
        val listeningPorts = procNetScanner.scanListeningPorts()
        val clientGuesses = procNetScanner.identifyVpnClient(listeningPorts)

        if (listeningPorts.isNotEmpty()) {
            findings.add(Finding(
                Severity.INFO,
                "📊 /proc/net/tcp: ${listeningPorts.size} listening портов на localhost",
                listeningPorts.joinToString("\n") { port ->
                    val guess = port.clientGuess ?: "unknown"
                    val scope = if (port.listenAll) "0.0.0.0 ⚠️" else "127.0.0.1"
                    ":${port.port} (UID ${port.uid}, $scope) — $guess"
                }
            ))
        }

        clientGuesses.forEach { guess ->
            findings.add(Finding(
                Severity.WARNING,
                "🔍 Обнаружен: ${guess.name} (${guess.confidence}%)",
                "Доказательства: ${guess.evidence.joinToString(", ")}"
            ))
        }

        // Фаза 0.7: Прямые признаки VPN/прокси
        onPhase(ScanPhase.DIRECT_SIGNS)
        onProgress(0.06f)
        val directSigns = directSignsChecker.fullCheck()

        // VPN Transport
        if (directSigns.vpnTransport.detected) {
            val transport = directSigns.vpnTransport
            findings.add(Finding(
                Severity.INFO,
                "🔍 VPN обнаружен через NetworkCapabilities",
                buildString {
                    if (transport.hasTransportVpn) append("TRANSPORT_VPN: Да\n")
                    if (transport.hasIsVpnFlag) append("IS_VPN (скрытый флаг): Да\n")
                    if (transport.hasVpnTransportInfo) append("VpnTransportInfo: Да\n")
                },
                mapOf("capsString" to transport.capsString.take(200))
            ))
        }

        // System Proxy
        if (directSigns.systemProxy.detected) {
            val proxy = directSigns.systemProxy
            findings.add(Finding(
                Severity.WARNING,
                "⚠️ Системные прокси-переменные обнаружены",
                buildString {
                    proxy.httpProxyHost?.let { append("HTTP proxy: $it:${proxy.httpProxyPort}\n") }
                    proxy.socksProxyHost?.let { append("SOCKS proxy: $it:${proxy.socksProxyPort}\n") }
                    if (proxy.isKnownPort) append("Известный порт: ${proxy.knownPortLabel}\n")
                }
            ))
        }

        // Installed VPN apps
        val installedApps = directSigns.installedVpnApps.filter { it.installed }
        if (installedApps.isNotEmpty()) {
            findings.add(Finding(
                Severity.WARNING,
                "📦 Обнаружено ${installedApps.size} VPN-приложений",
                installedApps.joinToString("\n") { "• ${it.appName} (${it.packageName})" },
                mapOf("Количество" to installedApps.size.toString())
            ))
        }

        // VPN interfaces
        if (directSigns.interfaces.isNotEmpty()) {
            findings.add(Finding(
                Severity.WARNING,
                "🌐 VPN-интерфейсы: ${directSigns.interfaces.joinToString { it.name }}",
                directSigns.interfaces.joinToString("\n") {
                    "${it.name} (${it.type}/${it.protocol}) — IP: ${it.ips.joinToString()}"
                }
            ))
        }

        // Routing table
        val vpnRoutes = directSigns.routingEntries.filter { it.isVpnRoute }
        if (vpnRoutes.isNotEmpty()) {
            findings.add(Finding(
                Severity.WARNING,
                "🛣️ VPN-маршруты в таблице маршрутизации",
                vpnRoutes.joinToString("\n") {
                    "Default route через ${it.interfaceName} → ${it.gateway}"
                }
            ))
        }

        // Split tunnel
        directSigns.splitTunnel?.let { split ->
            if (split.isSplitTunnel) {
                findings.add(Finding(
                    Severity.WARNING,
                    "🔀 Split tunnel обнаружен",
                    split.details,
                    mapOf(
                        "Прямой IP" to (split.directIp ?: "?"),
                        "Proxy IP" to (split.proxyIp ?: "?")
                    )
                ))
            }
        }

        // Фаза 1: Информация об устройстве
        onPhase(ScanPhase.DEVICE_INFO)
        onProgress(0.08f)
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
            return ScanResult(device = device, openPorts = openPorts, directSigns = directSigns, findings = findings)
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

        // Фаза 4.5: Clash REST API
        onPhase(ScanPhase.CLASH_API)
        onProgress(0.68f)
        val clashApi = clashAPIProbe.probe()

        if (clashApi != null) {
            findings.add(Finding(
                Severity.CRITICAL,
                "🌐 Clash API обнаружен на порту ${clashApi.port}!",
                buildString {
                    append("REST API без аутентификации.\n")
                    append("Режим: ${clashApi.mode}\n")
                    append("Активных соединений: ${clashApi.connections.size}\n")
                    append("Прокси: ${clashApi.proxyNames.joinToString().take(100)}\n")
                    if (clashApi.leakedDestIPs.isNotEmpty()) {
                        append("\n🔴 УТЕЧКА IP серверов через /connections:\n")
                        clashApi.leakedDestIPs.forEach { append("  → $it\n") }
                    }
                },
                mapOf(
                    "Порт" to clashApi.port.toString(),
                    "Соединений" to clashApi.connections.size.toString(),
                    "Upload" to "${clashApi.totalUpload / 1024} KB",
                    "Download" to "${clashApi.totalDownload / 1024} KB"
                )
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
            profile = profile,
            openPorts = openPorts,
            listeningPorts = listeningPorts,
            vpnClientGuesses = clientGuesses,
            directSigns = directSigns,
            proxies = proxies,
            exitIPs = exitIPsWithGeo,
            xrayAPI = xrayApi,
            clashAPI = clashApi,
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
        val directSigns = directSignsChecker.fullCheck()

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
            directSigns = directSigns, exitIPs = exitIPsWithGeo, xrayAPI = xrayApi, findings = findings)
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
