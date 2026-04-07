package com.yourvpndead.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.yourvpndead.model.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface

/**
 * Косвенные признаки VPN/прокси — проверки требующие интерпретации.
 *
 * В отличие от DirectSignsChecker (прямые факты), эти проверки
 * обнаруживают аномалии, которые МОГУТ указывать на VPN:
 *
 * 1. NET_CAPABILITY_NOT_VPN — если отсутствует, Android считает сеть VPN
 * 2. MTU аномалии — VPN снижает MTU из-за инкапсуляции (1500 → 1400)
 * 3. DNS в частной подсети — может указывать на VPN-туннель
 * 4. dumpsys vpn_management — системная информация о VPN (обычно заблокирована)
 * 5. dumpsys activity services VpnService — поиск активных VPN-сервисов
 */
class IndirectSignsChecker(private val context: Context) {

    companion object {
        /** Стандартный MTU для Ethernet/WiFi */
        private const val STANDARD_MTU = 1500

        /** Типичные VPN MTU значения */
        private val VPN_MTU_RANGE = 1200..1499

        /** Private IP ranges (RFC 1918 + RFC 6598) */
        private val PRIVATE_PREFIXES = listOf(
            "10.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",
            "100.64.", "100.65.", "100.66.", "100.67.",  // CGN (RFC 6598) — часто WireGuard/Tailscale
            "100.68.", "100.69.", "100.70.", "100.71.",
        )
    }

    /**
     * 1. NET_CAPABILITY_NOT_VPN
     *
     * Android добавляет capability NOT_VPN к НЕ-VPN сетям.
     * Если эта capability ОТСУТСТВУЕТ — система считает текущую сеть VPN.
     * Это более надёжно чем TRANSPORT_VPN для некоторых реализаций.
     *
     * API: NetworkCapabilities.NET_CAPABILITY_NOT_VPN (API 21+)
     * Метод: caps.hasCapability(NET_CAPABILITY_NOT_VPN)
     */
    fun checkNotVpnCapability(): NotVpnCapabilityResult {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return NotVpnCapabilityResult(error = "ConnectivityManager недоступен")
            val network = cm.activeNetwork
                ?: return NotVpnCapabilityResult(error = "Нет активной сети")
            val caps = cm.getNetworkCapabilities(network)
                ?: return NotVpnCapabilityResult(error = "NetworkCapabilities недоступны")

            val hasNotVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            val capsStr = caps.toString()

            NotVpnCapabilityResult(
                hasNotVpnCapability = hasNotVpn,
                allCapabilities = capsStr,
                detected = !hasNotVpn,
                error = null
            )
        } catch (e: Exception) {
            NotVpnCapabilityResult(error = "Ошибка: ${e.message}")
        }
    }

    /**
     * 2. MTU аномалии
     *
     * Стандартный MTU: 1500 (Ethernet/WiFi)
     * VPN снижает MTU из-за инкапсуляции:
     *   - WireGuard: обычно 1420
     *   - OpenVPN: обычно 1400
     *   - IPSec: обычно 1400-1438
     *   - VLESS/Trojan (xray): зависит от транспорта, часто 1380-1400
     *
     * Если активный интерфейс имеет MTU < 1500 и это не loopback —
     * возможно VPN.
     *
     * API: NetworkInterface.getMTU() (API 1+)
     */
    fun checkMtu(): MtuCheckResult {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.asSequence()?.toList()
                ?: return MtuCheckResult(error = "Не удалось получить интерфейсы")

            val mtuInterfaces = interfaces
                .filter { it.isUp && !it.isLoopback }
                .map { iface ->
                    val mtu = try { iface.mtu } catch (_: Exception) { 0 }
                    val isAnomaly = mtu in VPN_MTU_RANGE
                    MtuInterface(
                        name = iface.name,
                        mtu = mtu,
                        isAnomaly = isAnomaly,
                        expectedMtu = STANDARD_MTU,
                        details = when {
                            mtu == 0 -> "MTU не определён"
                            mtu in 1410..1430 -> "MTU $mtu — типично для WireGuard (encap overhead ~80 bytes)"
                            mtu in 1380..1409 -> "MTU $mtu — типично для OpenVPN/VLESS (encap overhead ~100-120 bytes)"
                            mtu in 1200..1379 -> "MTU $mtu — сильно снижен, двойная инкапсуляция?"
                            mtu >= STANDARD_MTU -> "MTU $mtu — стандартный"
                            else -> "MTU $mtu"
                        }
                    )
                }

            MtuCheckResult(
                interfaces = mtuInterfaces,
                anomalyDetected = mtuInterfaces.any { it.isAnomaly },
                error = null
            )
        } catch (e: Exception) {
            MtuCheckResult(error = "Ошибка: ${e.message}")
        }
    }

    /**
     * 3. DNS в частной подсети
     *
     * Если DNS-сервер находится в частном диапазоне (192.168.x.x, 10.x.x.x, 172.16-31.x.x),
     * это может означать:
     *   - VPN-туннель с DNS-сервером внутри туннеля
     *   - Локальный DNS-резолвер (Pi-hole, AdGuard Home)
     *   - Tailscale/WireGuard mesh с DNS внутри сети
     *
     * Также проверяем CGN диапазон 100.64.0.0/10 (Tailscale использует 100.x.x.x).
     *
     * API: ConnectivityManager.getLinkProperties().dnsServers (API 21+)
     */
    fun checkDns(): DnsCheckResult {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return DnsCheckResult(error = "ConnectivityManager недоступен")
            val network = cm.activeNetwork
                ?: return DnsCheckResult(error = "Нет активной сети")
            val linkProps = cm.getLinkProperties(network)
                ?: return DnsCheckResult(error = "LinkProperties недоступны")

            val dnsServers = linkProps.dnsServers.mapNotNull { it.hostAddress }
            val privateDns = dnsServers.filter { ip -> isPrivateIp(ip) }

            // Private DNS server
            val privateDnsServer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                linkProps.privateDnsServerName
            } else null

            DnsCheckResult(
                dnsServers = dnsServers,
                privateSubnetDns = privateDns,
                privateDnsServerName = privateDnsServer,
                detected = privateDns.isNotEmpty(),
                error = null
            )
        } catch (e: Exception) {
            DnsCheckResult(error = "Ошибка: ${e.message}")
        }
    }

    /**
     * 4-5. dumpsys проверки
     *
     * dumpsys — системная утилита Android для диагностики.
     * Обычные приложения НЕ имеют доступа к dumpsys (нужен shell или root).
     * Мы пробуем и фиксируем результат:
     *   - Если доступен → информационная утечка (на root/инженерных ROM)
     *   - Если заблокирован → нормальное поведение
     *
     * dumpsys vpn_management — список VPN-профилей
     * dumpsys activity services VpnService — активные VPN-сервисы
     */
    fun checkDumpsys(): DumpsysCheckResult {
        val vpnMgmt = tryDumpsys("vpn_management")
        val vpnService = tryDumpsys("activity", "services", "VpnService")

        return DumpsysCheckResult(
            vpnManagementAccessible = vpnMgmt.first,
            vpnManagementOutput = vpnMgmt.second,
            vpnServiceAccessible = vpnService.first,
            vpnServiceOutput = vpnService.second,
            vpnManagementError = vpnMgmt.third,
            vpnServiceError = vpnService.third
        )
    }

    /**
     * Полная проверка всех косвенных признаков.
     */
    fun fullCheck(): IndirectSignsResult {
        return IndirectSignsResult(
            notVpnCapability = checkNotVpnCapability(),
            mtuCheck = checkMtu(),
            dnsCheck = checkDns(),
            dumpsysCheck = checkDumpsys()
        )
    }

    // === Private helpers ===

    private fun isPrivateIp(ip: String): Boolean {
        return PRIVATE_PREFIXES.any { ip.startsWith(it) }
    }

    /**
     * Попытка выполнить dumpsys команду.
     * @return Triple(accessible, output, error)
     */
    private fun tryDumpsys(vararg args: String): Triple<Boolean, String?, String?> {
        return try {
            val cmd = arrayOf("dumpsys") + args
            val process = Runtime.getRuntime().exec(cmd)
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val errorReader = BufferedReader(InputStreamReader(process.errorStream))

            val output = reader.readText().take(2000)
            val error = errorReader.readText().take(500)

            val exitCode = process.waitFor()

            if (exitCode == 0 && output.isNotBlank() && !output.contains("Permission Denial")) {
                Triple(true, output, null)
            } else {
                val errorMsg = when {
                    output.contains("Permission Denial") -> "Permission Denial"
                    error.contains("Permission Denial") -> "Permission Denial"
                    error.contains("not found") -> "Service not found"
                    error.isNotBlank() -> error.take(200)
                    else -> "exit code $exitCode"
                }
                Triple(false, null, errorMsg)
            }
        } catch (e: SecurityException) {
            Triple(false, null, "SecurityException: ${e.message}")
        } catch (e: Exception) {
            Triple(false, null, "${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
