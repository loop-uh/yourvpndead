package com.yourvpndead.scanner

import com.yourvpndead.model.OpenPort
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Параллельный TCP-сканер портов на localhost.
 *
 * Быстрый скан (~30 известных портов) — < 1 сек.
 * Полный скан (65535 портов, 32 корутины) — 3-5 сек.
 */
class PortScanner {

    companion object {
        /** Известные порты VPN-клиентов, прокси, трекеров */
        val KNOWN_PORTS = listOf(
            // xray-core (v2rayNG, v2RayTun, Hiddify, etc.)
            10808, 10809, 10810, 1080, 1081,
            // sing-box (NekoBox, Husi, SFA, Karing)
            2080, 2081, 3066, 3067,
            // mihomo / Clash
            7890, 7891, 7892, 7893, 10801,
            // xray API
            10085, 19085, 23456, 8001, 62789,
            // Яндекс.Метрика (localhost трекинг)
            29009, 29010, 30102, 30103,
            // Meta Pixel (localhost трекинг)
            12387, 12388, 12580, 12581, 12582, 12583, 12584, 12585,
            12586, 12587, 12588, 12589, 12590, 12591,
            // Из методички Минцифры
            9000, 5555, 9050, 9051, 9150,
            3128, 8080, 8081, 8888
        ).distinct().sorted()

        private const val HOST_V4 = "127.0.0.1"
        private const val HOST_V6 = "::1"
    }

    /**
     * Быстрый скан только известных портов.
     * @return список открытых портов с временем отклика
     */
    suspend fun scanKnownPorts(
        timeoutMs: Int = 300,
        onProgress: (Float) -> Unit = {}
    ): List<OpenPort> = withContext(Dispatchers.IO) {
        val results = mutableListOf<OpenPort>()
        val total = KNOWN_PORTS.size

        KNOWN_PORTS.forEachIndexed { idx, port ->
            onProgress(idx.toFloat() / total)
            // Try IPv4 first
            val result = probePort(HOST_V4, port, timeoutMs)
                ?: probePort(HOST_V6, port, timeoutMs) // Fallback to IPv6
            if (result != null) results.add(result)
        }

        onProgress(1f)
        results
    }

    /**
     * Полный скан всех 65535 портов.
     * @param parallelism количество одновременных корутин (32 оптимально для localhost)
     */
    suspend fun scanFullRange(
        timeoutMs: Int = 100,
        parallelism: Int = 32,
        onProgress: (Float) -> Unit = {}
    ): List<OpenPort> = withContext(Dispatchers.IO) {
        val results = mutableListOf<OpenPort>()
        val total = 65535

        (1..total).chunked(parallelism).forEachIndexed { chunkIdx, chunk ->
            val batch = chunk.map { port ->
                async {
                    probePort(HOST_V4, port, timeoutMs)
                        ?: probePort(HOST_V6, port, timeoutMs)
                }
            }.awaitAll().filterNotNull()

            results.addAll(batch)
            onProgress(((chunkIdx + 1) * parallelism).coerceAtMost(total).toFloat() / total)
        }

        results.sortedBy { it.port }
    }

    private fun probePort(host: String, port: Int, timeoutMs: Int): OpenPort? {
        return try {
            val start = System.currentTimeMillis()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                OpenPort(port, System.currentTimeMillis() - start)
            }
        } catch (_: Exception) {
            null
        }
    }
}
