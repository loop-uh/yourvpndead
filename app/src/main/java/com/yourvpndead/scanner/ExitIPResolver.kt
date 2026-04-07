package com.yourvpndead.scanner

import com.yourvpndead.model.ExitIPInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Получает выходной IP VPN-сервера через уязвимый SOCKS5-прокси.
 *
 * Цепочка: localhost:SOCKS5 → CONNECT api.ipify.org:80 → HTTP GET → exit IP.
 * Именно так шпионское ПО узнаёт IP вашего VPN.
 */
class ExitIPResolver {

    companion object {
        private const val HOST = "127.0.0.1"
        private const val IP_SERVICE = "api.ipify.org"
        private const val IP_SERVICE_PORT = 80
        private const val CONNECT_TIMEOUT = 5000
        private const val READ_TIMEOUT = 10000
        private val IP_REGEX = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")
    }

    /**
     * Попытаться получить exit IP через SOCKS5 noauth на указанном порту.
     * @return ExitIPInfo или null если не удалось
     */
    suspend fun resolve(socksPort: Int): ExitIPInfo? = withContext(Dispatchers.IO) {
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, socksPort), CONNECT_TIMEOUT)
                socket.soTimeout = READ_TIMEOUT

                val out = socket.getOutputStream()
                val inp = socket.getInputStream()

                // === Шаг 1: SOCKS5 greeting (noauth) ===
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()

                val greeting = ByteArray(2)
                if (inp.read(greeting) != 2) return@withContext null
                if (greeting[0].toInt() != 0x05 || greeting[1].toInt() != 0x00) return@withContext null

                // === Шаг 2: CONNECT к api.ipify.org:80 ===
                val domain = IP_SERVICE.toByteArray()
                val connectReq = ByteArray(4 + 1 + domain.size + 2)
                connectReq[0] = 0x05  // VER
                connectReq[1] = 0x01  // CMD = CONNECT
                connectReq[2] = 0x00  // RSV
                connectReq[3] = 0x03  // ATYP = domain name
                connectReq[4] = domain.size.toByte()
                domain.copyInto(connectReq, 5)
                connectReq[5 + domain.size] = ((IP_SERVICE_PORT shr 8) and 0xFF).toByte()
                connectReq[6 + domain.size] = (IP_SERVICE_PORT and 0xFF).toByte()

                out.write(connectReq)
                out.flush()

                // Прочитать CONNECT response (минимум 10 байт)
                val connResp = ByteArray(10)
                if (inp.read(connResp) < 2) return@withContext null
                if (connResp[0].toInt() != 0x05 || connResp[1].toInt() != 0x00) return@withContext null

                // === Шаг 3: HTTP GET через туннель ===
                val httpReq = "GET / HTTP/1.1\r\nHost: $IP_SERVICE\r\nConnection: close\r\n\r\n"
                out.write(httpReq.toByteArray())
                out.flush()

                // === Шаг 4: Прочитать ответ, извлечь IP ===
                val body = inp.readBytes().decodeToString()
                val ip = IP_REGEX.find(body)?.groupValues?.get(1) ?: return@withContext null

                ExitIPInfo(ip = ip, port = socksPort)
            }
        } catch (_: Exception) {
            null
        }
    }

}
