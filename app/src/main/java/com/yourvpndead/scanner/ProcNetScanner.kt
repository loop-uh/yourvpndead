package com.yourvpndead.scanner

import com.yourvpndead.model.ListeningPort
import com.yourvpndead.model.VpnClientGuess
import java.io.File

/**
 * Парсер /proc/net/tcp и /proc/net/udp для fingerprinting VPN-клиентов.
 *
 * Формат /proc/net/tcp:
 * sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
 *
 * local_address = hex IP:hex PORT (например 0100007F:2A30 = 127.0.0.1:10808)
 * st = 0A (LISTEN)
 * uid = UID процесса-владельца
 *
 * Это позволяет определить:
 * 1. Какие порты слушают на localhost
 * 2. Какой UID (= какое приложение) владеет портом
 * 3. По паттерну портов — какой VPN-клиент запущен
 */
class ProcNetScanner {

    companion object {
        private const val STATE_LISTEN = "0A"

        /** Известные паттерны портов VPN-клиентов */
        val CLIENT_SIGNATURES = mapOf(
            10808 to "v2rayNG / v2RayTun / XrayFluent (xray SOCKS5)",
            10809 to "v2rayNG / XrayFluent (xray HTTP)",
            2080 to "NekoBox / Throne (sing-box mixed)",
            7890 to "Clash / mihomo (HTTP proxy)",
            7891 to "Clash / mihomo (SOCKS5)",
            10801 to "Clash / mihomo (mixed)",
            3066 to "Karing (HTTP/SOCKS5 full proxy)",
            3067 to "Karing (SOCKS5 rule-based)",
            19085 to "xray Stats API",
            19090 to "sing-box Clash API",
            9090 to "Clash / mihomo API",
            1080 to "Generic SOCKS5 (sing-box / Throne default)",
        )
    }

    /**
     * Прочитать /proc/net/tcp и найти все LISTENING порты на localhost.
     * Работает без root на большинстве Android версий.
     */
    fun scanListeningPorts(): List<ListeningPort> {
        val tcpPorts = parseProcNet("/proc/net/tcp")
        val tcp6Ports = parseProcNet("/proc/net/tcp6")
        return (tcpPorts + tcp6Ports).distinctBy { it.port }
    }

    /**
     * Идентифицировать VPN-клиент по паттерну открытых портов.
     */
    fun identifyVpnClient(ports: List<ListeningPort>): List<VpnClientGuess> {
        val guesses = mutableListOf<VpnClientGuess>()
        val portNumbers = ports.map { it.port }.toSet()

        // xray-based (v2rayNG, v2RayTun)
        if (10808 in portNumbers) {
            val confidence = when {
                10809 in portNumbers && 19085 in portNumbers -> 95
                10809 in portNumbers -> 85
                else -> 70
            }
            guesses.add(VpnClientGuess(
                name = "xray-core клиент (v2rayNG / v2RayTun)",
                confidence = confidence,
                evidence = buildList {
                    add("SOCKS5 :10808")
                    if (10809 in portNumbers) add("HTTP :10809")
                    if (19085 in portNumbers) add("Stats API :19085")
                }
            ))
        }

        // sing-box (NekoBox, Husi, SFA)
        if (2080 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "sing-box клиент (NekoBox / Throne / Husi)",
                confidence = 80,
                evidence = listOf("Mixed :2080")
            ))
        }

        // Clash / mihomo
        if (7891 in portNumbers || 7890 in portNumbers) {
            val confidence = when {
                9090 in portNumbers -> 95
                7890 in portNumbers && 7891 in portNumbers -> 90
                else -> 75
            }
            guesses.add(VpnClientGuess(
                name = "Clash / mihomo клиент",
                confidence = confidence,
                evidence = buildList {
                    if (7890 in portNumbers) add("HTTP :7890")
                    if (7891 in portNumbers) add("SOCKS5 :7891")
                    if (9090 in portNumbers) add("API :9090")
                }
            ))
        }

        // Karing
        if (3067 in portNumbers || 3066 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "Karing",
                confidence = 85,
                evidence = buildList {
                    if (3067 in portNumbers) add("SOCKS5 :3067")
                    if (3066 in portNumbers) add("Full proxy :3066")
                }
            ))
        }

        // sing-box Clash API
        if (19090 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "sing-box Clash API (LEAK RISK)",
                confidence = 90,
                evidence = listOf("Clash API :19090 — GET /connections раскрывает IP серверов!")
            ))
        }

        return guesses
    }

    /**
     * Парсить /proc/net/tcp или /proc/net/tcp6.
     * Возвращает только LISTENING порты на localhost.
     */
    private fun parseProcNet(path: String): List<ListeningPort> {
        return try {
            val file = File(path)
            if (!file.canRead()) return emptyList()

            file.readLines().drop(1) // пропустить заголовок
                .mapNotNull { line -> parseLine(line, path.contains("6")) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseLine(line: String, isIpv6: Boolean): ListeningPort? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 10) return null

        val localAddr = parts[1]  // hex_ip:hex_port
        val state = parts[3]
        val uid = parts[7].toIntOrNull() ?: return null

        // Только LISTENING (state = 0A)
        if (state != STATE_LISTEN) return null

        val colonIdx = localAddr.lastIndexOf(':')
        if (colonIdx < 0) return null

        val hexIp = localAddr.substring(0, colonIdx)
        val hexPort = localAddr.substring(colonIdx + 1)
        val port = hexPort.toIntOrNull(16) ?: return null

        // Проверяем что это localhost
        val isLocalhost = if (isIpv6) {
            hexIp == "00000000000000000000000000000000" || // ::
            hexIp == "00000000000000000000000001000000" || // ::1
            hexIp.endsWith("0100007F")                     // ::ffff:127.0.0.1
        } else {
            hexIp == "0100007F" || // 127.0.0.1
            hexIp == "00000000"    // 0.0.0.0 (слушает на всех)
        }

        val listenAll = if (isIpv6) {
            hexIp == "00000000000000000000000000000000"
        } else {
            hexIp == "00000000"
        }

        val clientGuess = CLIENT_SIGNATURES[port]

        return ListeningPort(
            port = port,
            uid = uid,
            isLocalhost = isLocalhost && !listenAll,
            listenAll = listenAll,
            clientGuess = clientGuess,
            source = if (isIpv6) "tcp6" else "tcp"
        )
    }
}
