package com.yourvpndead.model

/** Открытый порт на localhost */
data class OpenPort(
    val port: Int,
    val responseMs: Long
)

/** Тип обнаруженного прокси */
enum class ProxyType(val label: String, val icon: String) {
    SOCKS5_NO_AUTH("SOCKS5 (без auth)", "🔴"),
    SOCKS5_AUTH_REQUIRED("SOCKS5 (auth)", "🟢"),
    SOCKS5_REJECTED("SOCKS5 (отказано)", "🟢"),
    HTTP_PROXY_OPEN("HTTP proxy (открыт)", "🔴"),
    HTTP_PROXY_AUTH("HTTP proxy (auth)", "🟢"),
    GRPC_SERVICE("gRPC сервис", "⚠️"),
    UNKNOWN("Неизвестный сервис", "⚪");
}

/** Результат проверки одного порта */
data class ProxyInfo(
    val port: Int,
    val type: ProxyType,
    val vulnerable: Boolean,
    val details: String = ""
)

/** Информация о выходном IP */
data class ExitIPInfo(
    val ip: String,
    val port: Int,
    val geo: GeoInfo? = null
)

/** Геолокация IP */
data class GeoInfo(
    val ip: String,
    val country: String,
    val countryCode: String = "",
    val city: String,
    val isp: String,
    val org: String,
    val asNumber: String,
    val isProxy: Boolean,
    val isHosting: Boolean
)

/** Обнаруженный xray API */
data class XrayAPIInfo(
    val port: Int,
    val accessible: Boolean,
    val details: String = ""
)

/** Сетевой интерфейс */
data class NetInterface(
    val name: String,
    val displayName: String,
    val isUp: Boolean,
    val ips: List<String>
)

/** Отпечаток устройства */
data class DeviceFingerprint(
    val model: String,
    val manufacturer: String,
    val androidVersion: String,
    val sdkVersion: Int,
    val board: String,
    val hardware: String,
    val buildFingerprint: String,
    val isVpnActive: Boolean,
    val networkInterfaces: List<NetInterface>,
    val directIP: String?
)

/** Уровень серьёзности */
enum class Severity(val label: String, val emoji: String) {
    CRITICAL("Критическая", "🔴"),
    WARNING("Предупреждение", "🟡"),
    INFO("Информация", "🔵"),
    SAFE("Безопасно", "🟢");
}

/** Одна находка */
data class Finding(
    val severity: Severity,
    val title: String,
    val description: String,
    val details: Map<String, String> = emptyMap()
)

/** Результат проверки аутентификации */
data class AuthProbeResult(
    val port: Int,
    val supportsNoAuth: Boolean = false,
    val supportsPassword: Boolean = false,
    val authRequired: Boolean = false,
    val selectedMethod: Int = -1,
    val bruteForceSuccess: Boolean? = null,
    val bruteForceCredentials: String? = null,
    val udpBypassPossible: Boolean = false,
    val sniffAttempt: SniffAttempt? = null
) {
    val methodName: String get() = when (selectedMethod) {
        0x00 -> "NO AUTH (0x00)"
        0x01 -> "GSSAPI (0x01)"
        0x02 -> "PASSWORD (0x02)"
        0xFF -> "REJECTED (0xFF)"
        else -> "UNKNOWN (0x${selectedMethod.toString(16)})"
    }
}

/** Результат попытки перехвата трафика */
data class SniffAttempt(
    val rawSocketBlocked: Boolean = true,
    val procNetTcpVisible: Boolean = false,
    val procNetTcpData: String? = null,
    val udpSniffResult: String = "",
    val conclusion: String = ""
)

/** Информация о профиле/окружении */
data class ProfileInfo(
    val isManagedProfile: Boolean = false,
    val profileCount: Int = 1,
    val currentUserId: Int = 0,
    val isDeviceOwner: Boolean = false,
    val isProfileOwner: Boolean = false,
    val hasShelter: Boolean = false,
    val hasIsland: Boolean = false,
    val hasInsular: Boolean = false,
    val hasKnox: Boolean = false,
    val vpn: VpnInfo = VpnInfo(),
    val interfaces: List<Any> = emptyList()
) {
    val isIsolated: Boolean get() = isManagedProfile || hasShelter || hasIsland || hasInsular || hasKnox
    val isolationMethod: String get() = when {
        isManagedProfile && hasKnox -> "Samsung Knox (Work Profile)"
        isManagedProfile && hasShelter -> "Shelter (Work Profile)"
        isManagedProfile && hasIsland -> "Island (Work Profile)"
        isManagedProfile && hasInsular -> "Insular (Work Profile)"
        isManagedProfile -> "Android Work Profile"
        hasKnox -> "Samsung Knox detected (не в профиле)"
        hasShelter -> "Shelter detected (не в профиле)"
        else -> "Нет изоляции"
    }
}

/** VPN status */
data class VpnInfo(
    val isActiveByTransport: Boolean = false,
    val isActiveByInterface: Boolean = false,
    val tunInterfaces: List<String> = emptyList(),
    val transportTypes: List<String> = emptyList()
) {
    val isActive: Boolean get() = isActiveByTransport || isActiveByInterface
}

/** Clash API result */
data class ClashAPIResult(
    val port: Int,
    val accessible: Boolean = false,
    val mode: String = "",
    val connections: List<ClashConnection> = emptyList(),
    val proxyNames: List<String> = emptyList(),
    val leakedDestIPs: List<String> = emptyList(),
    val totalUpload: Long = 0,
    val totalDownload: Long = 0
)

data class ClashConnection(
    val id: String = "",
    val destinationIP: String = "",
    val host: String = "",
    val processPath: String = "",
    val network: String = "",
    val sourceIP: String = "",
    val sourcePort: String = "",
    val upload: Long = 0,
    val download: Long = 0,
    val chains: List<String> = emptyList(),
    val rule: String = "",
    val rulePayload: String = ""
)

/** Порт из /proc/net/tcp */
data class ListeningPort(
    val port: Int,
    val uid: Int,
    val isLocalhost: Boolean,
    val listenAll: Boolean,
    val clientGuess: String? = null,
    val source: String = "tcp"
)

/** Предположение о VPN-клиенте */
data class VpnClientGuess(
    val name: String,
    val confidence: Int,
    val evidence: List<String> = emptyList()
)

/** 2.1 Детекция VPN через NetworkCapabilities */
data class VpnTransportDetection(
    val hasTransportVpn: Boolean = false,
    val hasIsVpnFlag: Boolean = false,
    val hasVpnTransportInfo: Boolean = false,
    val capsString: String = "",
    val detected: Boolean = false
)

/** 2.2 Системные прокси-переменные */
data class SystemProxyDetection(
    val httpProxyHost: String? = null,
    val httpProxyPort: String? = null,
    val socksProxyHost: String? = null,
    val socksProxyPort: String? = null,
    val isKnownPort: Boolean = false,
    val knownPortLabel: String? = null,
    val detected: Boolean = false
)

/** 2.3 Установленное VPN-приложение */
data class InstalledVpnApp(
    val packageName: String,
    val appName: String,
    val installed: Boolean = false
)

/** 3.2 Обнаруженный VPN-интерфейс */
data class InterfaceDetection(
    val name: String,
    val type: String,
    val protocol: String,
    val isUp: Boolean,
    val ips: List<String> = emptyList(),
    val vpnIndicator: Boolean = false
)

/** 3.4 Запись таблицы маршрутизации */
data class RoutingEntry(
    val destination: String,
    val gateway: String,
    val interfaceName: String,
    val mask: String = "",
    val flags: String = "",
    val isDefaultRoute: Boolean = false,
    val isVpnRoute: Boolean = false
)

/** Результат проверки split tunnel */
data class SplitTunnelResult(
    val directIp: String? = null,
    val proxyIp: String? = null,
    val isSplitTunnel: Boolean = false,
    val details: String = ""
)

/** Полный результат прямых признаков */
data class DirectSignsResult(
    val vpnTransport: VpnTransportDetection = VpnTransportDetection(),
    val systemProxy: SystemProxyDetection = SystemProxyDetection(),
    val installedVpnApps: List<InstalledVpnApp> = emptyList(),
    val interfaces: List<InterfaceDetection> = emptyList(),
    val routingEntries: List<RoutingEntry> = emptyList(),
    val splitTunnel: SplitTunnelResult? = null
)

/** Полный результат скана */
data class ScanResult(
    val timestamp: Long = System.currentTimeMillis(),
    val device: DeviceFingerprint? = null,
    val profile: ProfileInfo? = null,
    val openPorts: List<OpenPort> = emptyList(),
    val listeningPorts: List<ListeningPort> = emptyList(),
    val vpnClientGuesses: List<VpnClientGuess> = emptyList(),
    val directSigns: DirectSignsResult? = null,
    val proxies: List<ProxyInfo> = emptyList(),
    val exitIPs: List<ExitIPInfo> = emptyList(),
    val xrayAPI: XrayAPIInfo? = null,
    val clashAPI: ClashAPIResult? = null,
    val authProbes: List<AuthProbeResult> = emptyList(),
    val findings: List<Finding> = emptyList()
) {
    val vulnerableCount: Int get() = proxies.count { it.vulnerable }
    val isVulnerable: Boolean get() = vulnerableCount > 0
        || xrayAPI?.accessible == true
        || clashAPI?.accessible == true
}

/** Состояние UI скана */
enum class ScanPhase(val label: String) {
    IDLE("Готов к скану"),
    PROFILE_DETECT("Определение профиля и окружения..."),
    DEVICE_INFO("Сбор информации об устройстве..."),
    PROC_NET_SCAN("Анализ /proc/net/tcp..."),
    DIRECT_SIGNS("Прямые признаки VPN/прокси..."),
    PORT_SCAN("Сканирование портов..."),
    PROXY_PROBE("Определение типов прокси..."),
    API_DETECT("Поиск xray gRPC API..."),
    CLASH_API("Поиск Clash REST API..."),
    AUTH_PROBE("Проверка аутентификации и попытка перехвата..."),
    EXIT_IP("Получение выходного IP..."),
    GEO_LOOKUP("Геолокация IP..."),
    DONE("Скан завершён");
}

data class ScanState(
    val phase: ScanPhase = ScanPhase.IDLE,
    val progress: Float = 0f,
    val result: ScanResult? = null,
    val error: String? = null,
    val isRunning: Boolean = false
)
