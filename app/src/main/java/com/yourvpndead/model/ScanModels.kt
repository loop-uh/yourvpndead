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

/** Полный результат скана */
data class ScanResult(
    val timestamp: Long = System.currentTimeMillis(),
    val device: DeviceFingerprint? = null,
    val openPorts: List<OpenPort> = emptyList(),
    val proxies: List<ProxyInfo> = emptyList(),
    val exitIPs: List<ExitIPInfo> = emptyList(),
    val xrayAPI: XrayAPIInfo? = null,
    val authProbes: List<AuthProbeResult> = emptyList(),
    val findings: List<Finding> = emptyList()
) {
    val vulnerableCount: Int get() = proxies.count { it.vulnerable }
    val isVulnerable: Boolean get() = vulnerableCount > 0 || xrayAPI?.accessible == true
}

/** Состояние UI скана */
enum class ScanPhase(val label: String) {
    IDLE("Готов к скану"),
    DEVICE_INFO("Сбор информации об устройстве..."),
    PORT_SCAN("Сканирование портов..."),
    PROXY_PROBE("Определение типов прокси..."),
    API_DETECT("Поиск xray API..."),
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
