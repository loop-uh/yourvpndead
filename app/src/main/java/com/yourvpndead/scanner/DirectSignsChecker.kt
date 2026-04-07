package com.yourvpndead.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.yourvpndead.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.NetworkInterface
import java.net.URL

/**
 * Прямые признаки VPN/прокси — системные проверки без сетевых запросов.
 *
 * Демонстрирует что ЛЮБОЕ приложение может обнаружить:
 * 1. VPN через NetworkCapabilities (включая скрытые флаги IS_VPN, VpnTransportInfo)
 * 2. Системные прокси-переменные (http.proxyHost, socksProxyHost)
 * 3. Установленные VPN-приложения через PackageManager
 * 4. VPN-интерфейсы (TUN/TAP/WireGuard/PPP/IPSec)
 * 5. Таблицу маршрутизации (/proc/net/route)
 * 6. Split tunnel через сравнение прямого и proxy IP
 */
class DirectSignsChecker(private val context: Context) {

    companion object {
        /** Известные VPN-приложения для проверки через PackageManager */
        val KNOWN_VPN_APPS = listOf(
            "com.v2ray.ang" to "v2rayNG",
            "io.nekohasekai.sfa" to "sing-box (SFA)",
            "app.hiddify.com" to "Hiddify",
            "com.github.metacubex.clash.meta" to "ClashMeta for Android",
            "com.github.shadowsocks" to "Shadowsocks",
            "com.github.shadowsocks.tv" to "Shadowsocks TV",
            "com.happproxy" to "HAPP VPN",
            "io.github.saeeddev94.xray" to "XrayNG",
            "moe.nb4a" to "NekoBox",
            "io.github.dovecoteescapee.byedpi" to "ByeDPI",
            "com.romanvht.byebyedpi" to "ByeByeDPI",
            "org.outline.android.client" to "Outline",
            "com.psiphon3" to "Psiphon",
            "org.getlantern.lantern" to "Lantern",
            "com.wireguard.android" to "WireGuard",
            "com.strongswan.android" to "strongSwan",
            "org.torproject.android" to "Tor Browser",
            "info.guardianproject.orfox" to "Orbot",
            "org.torproject.torbrowser" to "Tor Browser (official)",
            "org.amnezia.vpn" to "Amnezia VPN",
        )

        /** Известные прокси-порты */
        val KNOWN_PROXY_PORTS = mapOf(
            "1080" to "SOCKS5 default",
            "9000" to "SOCKS / v2ray",
            "5555" to "SOCKS",
            "8080" to "HTTP proxy",
            "3128" to "HTTP proxy (Squid)",
            "9050" to "Tor SOCKS",
            "9150" to "Tor Browser SOCKS",
        )

        /** Нормальные интерфейсы для default route (НЕ VPN) */
        private val NORMAL_ROUTE_PREFIXES = listOf("wlan", "rmnet", "eth", "lo")
    }

    /**
     * 2.1 NetworkCapabilities — проверка VPN через транспорт.
     *
     * TRANSPORT_VPN — публичный API.
     * IS_VPN и VpnTransportInfo — внутренние флаги Android,
     * не раскрытые в публичном API, проверяются через toString() объекта.
     */
    fun checkVpnTransport(): VpnTransportDetection {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return VpnTransportDetection()
            val network = cm.activeNetwork ?: return VpnTransportDetection()
            val caps = cm.getNetworkCapabilities(network) ?: return VpnTransportDetection()

            val hasTransport = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            val capsStr = caps.toString()
            val hasIsVpn = capsStr.contains("IS_VPN")
            val hasVpnTransportInfo = capsStr.contains("VpnTransportInfo")

            VpnTransportDetection(
                hasTransportVpn = hasTransport,
                hasIsVpnFlag = hasIsVpn,
                hasVpnTransportInfo = hasVpnTransportInfo,
                capsString = capsStr,
                detected = hasTransport || hasIsVpn || hasVpnTransportInfo
            )
        } catch (_: Exception) {
            VpnTransportDetection()
        }
    }

    /**
     * 2.2 Системные прокси-переменные.
     *
     * Любое приложение может прочитать System.getProperty("http.proxyHost") и т.д.
     * Если VPN-клиент установил системный прокси, он виден всем.
     */
    fun checkSystemProxy(): SystemProxyDetection {
        val httpHost = System.getProperty("http.proxyHost")?.takeIf { it.isNotBlank() }
        val httpPort = System.getProperty("http.proxyPort")?.takeIf { it.isNotBlank() }
        val socksHost = System.getProperty("socksProxyHost")?.takeIf { it.isNotBlank() }
        val socksPort = System.getProperty("socksProxyPort")?.takeIf { it.isNotBlank() }

        val allPorts = listOfNotNull(httpPort, socksPort)
        val knownMatch = allPorts.firstNotNullOfOrNull { port ->
            KNOWN_PROXY_PORTS[port]?.let { port to it }
        }

        return SystemProxyDetection(
            httpProxyHost = httpHost,
            httpProxyPort = httpPort,
            socksProxyHost = socksHost,
            socksProxyPort = socksPort,
            isKnownPort = knownMatch != null,
            knownPortLabel = knownMatch?.let { "${it.first} (${it.second})" },
            detected = httpHost != null || socksHost != null
        )
    }

    /**
     * 2.3 Проверка установленных VPN-приложений через PackageManager.
     *
     * На Android 11+ требует QUERY_ALL_PACKAGES или <queries> в манифесте.
     * Без этого getPackageInfo выбрасывает NameNotFoundException для скрытых пакетов.
     */
    fun checkKnownVpnApps(): List<InstalledVpnApp> {
        val pm = context.packageManager
        return KNOWN_VPN_APPS.map { (pkg, name) ->
            val installed = try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            } catch (_: Exception) {
                false
            }
            InstalledVpnApp(
                packageName = pkg,
                appName = name,
                installed = installed
            )
        }
    }

    /**
     * 3.2 Сетевые интерфейсы — расширенная проверка.
     *
     * Паттерны:
     * - tun\d+  → TUN (OpenVPN, WireGuard TUN, Android VpnService)
     * - tap\d+  → TAP (OpenVPN TAP mode)
     * - wg\d+   → WireGuard native
     * - ppp\d+  → PPP (L2TP/PPTP)
     * - ipsec.* → IPSec VPN
     */
    fun checkNetworkInterfaces(): List<InterfaceDetection> {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.asSequence()?.toList()
                ?: return emptyList()

            interfaces.filter { it.isUp }.mapNotNull { iface ->
                val name = iface.name.lowercase()
                val (type, protocol) = classifyInterface(name) ?: return@mapNotNull null

                InterfaceDetection(
                    name = iface.name,
                    type = type,
                    protocol = protocol,
                    isUp = iface.isUp,
                    ips = iface.inetAddresses.asSequence()
                        .mapNotNull { it.hostAddress?.split("%")?.first() }
                        .toList(),
                    vpnIndicator = true
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * 3.4 Таблица маршрутизации — /proc/net/route.
     *
     * Строки с destination=00000000 — маршрут по умолчанию (0.0.0.0/0).
     * Если default route идёт через интерфейс, не являющийся wlan/rmnet/eth/lo — VPN.
     */
    fun checkRoutingTable(): List<RoutingEntry> {
        return try {
            val file = File("/proc/net/route")
            if (!file.canRead()) return emptyList()

            file.readLines().drop(1) // skip header
                .mapNotNull { line -> parseRouteEntry(line) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Полная проверка: все прямые признаки + split tunnel (единственная сетевая проверка).
     */
    suspend fun fullCheck(): DirectSignsResult = withContext(Dispatchers.IO) {
        val vpnTransport = checkVpnTransport()
        val systemProxy = checkSystemProxy()
        val vpnApps = checkKnownVpnApps()
        val interfaces = checkNetworkInterfaces()
        val routes = checkRoutingTable()
        val splitTunnel = checkSplitTunnel()

        DirectSignsResult(
            vpnTransport = vpnTransport,
            systemProxy = systemProxy,
            installedVpnApps = vpnApps,
            interfaces = interfaces,
            routingEntries = routes,
            splitTunnel = splitTunnel
        )
    }

    /**
     * Split tunnel detection: сравнение прямого IP и IP через обнаруженный прокси.
     * Если они различаются — обнаружен per-app split bypass.
     */
    private suspend fun checkSplitTunnel(): SplitTunnelResult? {
        return try {
            val directIp = getDirectIP()
            if (directIp == null) return null

            // Ищем system proxy для проверки
            val proxyHost = System.getProperty("http.proxyHost")?.takeIf { it.isNotBlank() }
            val proxyPort = System.getProperty("http.proxyPort")?.toIntOrNull()

            if (proxyHost != null && proxyPort != null) {
                val proxyIp = getIPThroughProxy(proxyHost, proxyPort)
                if (proxyIp != null && proxyIp != directIp) {
                    return SplitTunnelResult(
                        directIp = directIp,
                        proxyIp = proxyIp,
                        isSplitTunnel = true,
                        details = "Прямой IP ($directIp) отличается от proxy IP ($proxyIp) — per-app split tunnel"
                    )
                }
                return SplitTunnelResult(
                    directIp = directIp,
                    proxyIp = proxyIp,
                    isSplitTunnel = false,
                    details = "Прямой и proxy IP совпадают: $directIp"
                )
            }

            SplitTunnelResult(
                directIp = directIp,
                proxyIp = null,
                isSplitTunnel = false,
                details = "Системный прокси не настроен — split tunnel не проверялся"
            )
        } catch (_: Exception) {
            null
        }
    }

    // === Private helpers ===

    private fun classifyInterface(name: String): Pair<String, String>? {
        return when {
            name.matches(Regex("^tun\\d+")) -> "TUN" to "OpenVPN / WireGuard TUN / VPN Service"
            name.matches(Regex("^tap\\d+")) -> "TAP" to "OpenVPN TAP"
            name.matches(Regex("^wg\\d+")) -> "WireGuard" to "WireGuard native"
            name.matches(Regex("^ppp\\d+")) -> "PPP" to "L2TP / PPTP"
            name.matches(Regex("^ipsec.*")) -> "IPSec" to "IPSec VPN"
            else -> null
        }
    }

    /**
     * Парсинг строки /proc/net/route.
     * Format: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
     */
    private fun parseRouteEntry(line: String): RoutingEntry? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 8) return null

        val iface = parts[0]
        val destHex = parts[1]
        val gatewayHex = parts[2]
        val flags = parts[3]
        val maskHex = parts[7]

        val isDefault = destHex == "00000000"
        val isNormalInterface = NORMAL_ROUTE_PREFIXES.any { iface.startsWith(it) }
        val isVpn = isDefault && !isNormalInterface

        return RoutingEntry(
            destination = hexToIp(destHex),
            gateway = hexToIp(gatewayHex),
            interfaceName = iface,
            mask = hexToIp(maskHex),
            flags = flags,
            isDefaultRoute = isDefault,
            isVpnRoute = isVpn
        )
    }

    /** Convert hex IP from /proc/net/route to dotted notation (little-endian) */
    private fun hexToIp(hex: String): String {
        if (hex.length != 8) return hex
        return try {
            val num = hex.toLong(16)
            "${num and 0xFF}.${(num shr 8) and 0xFF}.${(num shr 16) and 0xFF}.${(num shr 24) and 0xFF}"
        } catch (_: Exception) {
            hex
        }
    }

    /** Получить прямой IP через ifconfig.me */
    private fun getDirectIP(): String? {
        return try {
            val conn = URL("https://ifconfig.me/ip").openConnection()
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.getInputStream().bufferedReader().readText().trim()
        } catch (_: Exception) {
            // Fallback to api.ipify.org
            try {
                val conn = URL("https://api.ipify.org").openConnection()
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.getInputStream().bufferedReader().readText().trim()
            } catch (_: Exception) { null }
        }
    }

    /** Получить IP через HTTP прокси */
    private fun getIPThroughProxy(proxyHost: String, proxyPort: Int): String? {
        return try {
            val proxy = java.net.Proxy(
                java.net.Proxy.Type.HTTP,
                java.net.InetSocketAddress(proxyHost, proxyPort)
            )
            val conn = URL("https://api.ipify.org").openConnection(proxy)
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.getInputStream().bufferedReader().readText().trim()
        } catch (_: Exception) { null }
    }
}
