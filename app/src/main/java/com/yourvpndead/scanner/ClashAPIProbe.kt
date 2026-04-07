package com.yourvpndead.scanner

import com.yourvpndead.model.ClashAPIResult
import com.yourvpndead.model.ClashConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Эксплуатация Clash-совместимого REST API (sing-box / mihomo).
 *
 * sing-box и mihomo предоставляют Clash API на localhost (обычно 9090 или 19090)
 * БЕЗ аутентификации. Endpoint /connections возвращает ВСЕ активные соединения
 * включая destinationIP — это прямой leak серверных IP-адресов.
 *
 * Это ОТДЕЛЬНАЯ уязвимость от SOCKS5 — даже если SOCKS5 auth включён,
 * Clash API может быть открыт.
 */
class ClashAPIProbe {

    companion object {
        /** Типичные порты Clash API */
        val API_PORTS = listOf(
            9090,   // стандартный Clash
            19090,  // sing-box в некоторых клиентах
            9091,   // альтернативный
            9097,   // Clash Verge
        )
    }

    /** Проверить все известные порты Clash API */
    suspend fun probe(): ClashAPIResult? = withContext(Dispatchers.IO) {
        for (port in API_PORTS) {
            val result = tryPort(port)
            if (result != null) return@withContext result
        }
        null
    }

    /** Проверить конкретный порт */
    private fun tryPort(port: Int): ClashAPIResult? {
        // Сначала проверяем /configs (быстрая проверка что API жив)
        val configJson = httpGet("http://127.0.0.1:$port/configs") ?: return null

        // Потом /connections — основной leak
        val connectionsJson = httpGet("http://127.0.0.1:$port/connections")

        // /proxies — список прокси
        val proxiesJson = httpGet("http://127.0.0.1:$port/proxies")

        val connections = parseConnections(connectionsJson)
        val proxyNames = parseProxyNames(proxiesJson)
        val mode = try { JSONObject(configJson).optString("mode", "unknown") } catch (_: Exception) { "unknown" }

        // Извлечь уникальные destination IP из connections
        val leakedIPs = connections
            .mapNotNull { it.destinationIP }
            .filter { it.isNotBlank() && it != "0.0.0.0" && it != "::" }
            .distinct()

        return ClashAPIResult(
            port = port,
            accessible = true,
            mode = mode,
            connections = connections,
            proxyNames = proxyNames,
            leakedDestIPs = leakedIPs,
            totalUpload = try { JSONObject(connectionsJson ?: "{}").optLong("uploadTotal", 0) } catch (_: Exception) { 0 },
            totalDownload = try { JSONObject(connectionsJson ?: "{}").optLong("downloadTotal", 0) } catch (_: Exception) { 0 }
        )
    }

    /** Парсить /connections response */
    private fun parseConnections(json: String?): List<ClashConnection> {
        if (json == null) return emptyList()
        return try {
            val root = JSONObject(json)
            val arr = root.optJSONArray("connections") ?: return emptyList()
            (0 until arr.length()).map { i ->
                val conn = arr.getJSONObject(i)
                val meta = conn.optJSONObject("metadata") ?: JSONObject()
                ClashConnection(
                    id = conn.optString("id", ""),
                    destinationIP = meta.optString("destinationIP", ""),
                    host = meta.optString("host", ""),
                    processPath = meta.optString("processPath", ""),
                    network = meta.optString("network", ""),
                    sourceIP = meta.optString("sourceIP", ""),
                    sourcePort = meta.optString("sourcePort", ""),
                    upload = conn.optLong("upload", 0),
                    download = conn.optLong("download", 0),
                    chains = parseStringArray(conn.optJSONArray("chains")),
                    rule = conn.optString("rule", ""),
                    rulePayload = conn.optString("rulePayload", "")
                )
            }
        } catch (_: Exception) { emptyList() }
    }

    /** Парсить /proxies response */
    private fun parseProxyNames(json: String?): List<String> {
        if (json == null) return emptyList()
        return try {
            val root = JSONObject(json)
            val proxies = root.optJSONObject("proxies") ?: return emptyList()
            proxies.keys().asSequence().toList()
        } catch (_: Exception) { emptyList() }
    }

    private fun parseStringArray(arr: org.json.JSONArray?): List<String> {
        if (arr == null) return emptyList()
        return (0 until arr.length()).map { arr.optString(it, "") }
    }

    /** HTTP GET с таймаутом */
    private fun httpGet(url: String): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 1000
            conn.readTimeout = 2000
            conn.requestMethod = "GET"
            if (conn.responseCode == 200) {
                conn.inputStream.bufferedReader().readText()
            } else null
        } catch (_: Exception) { null }
    }
}
