package com.yourvpndead.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.yourvpndead.model.ScanPhase
import com.yourvpndead.model.ScanResult
import com.yourvpndead.model.ScanState
import com.yourvpndead.scanner.ScanOrchestrator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class ScanViewModel(application: Application) : AndroidViewModel(application) {

    private val orchestrator = ScanOrchestrator(application.applicationContext)

    private val _state = MutableStateFlow(ScanState())
    val state = _state.asStateFlow()

    /** Быстрый скан (известные порты, ~3 сек) */
    fun quickScan() {
        if (_state.value.isRunning) return

        viewModelScope.launch {
            _state.update { it.copy(isRunning = true, error = null, phase = ScanPhase.IDLE) }

            try {
                val result = orchestrator.quickScan(
                    onPhase = { phase ->
                        _state.update { it.copy(phase = phase) }
                    },
                    onProgress = { progress ->
                        _state.update { it.copy(progress = progress) }
                    }
                )
                _state.update { it.copy(
                    isRunning = false,
                    phase = ScanPhase.DONE,
                    progress = 1f,
                    result = result
                )}
            } catch (e: Exception) {
                _state.update { it.copy(
                    isRunning = false,
                    phase = ScanPhase.IDLE,
                    error = "Ошибка скана: ${e.message}"
                )}
            }
        }
    }

    /** Полный скан (65535 портов, ~5-10 сек) */
    fun fullScan() {
        if (_state.value.isRunning) return

        viewModelScope.launch {
            _state.update { it.copy(isRunning = true, error = null, phase = ScanPhase.IDLE) }

            try {
                val result = orchestrator.fullScan(
                    onPhase = { phase ->
                        _state.update { it.copy(phase = phase) }
                    },
                    onProgress = { progress ->
                        _state.update { it.copy(progress = progress) }
                    }
                )
                _state.update { it.copy(
                    isRunning = false,
                    phase = ScanPhase.DONE,
                    progress = 1f,
                    result = result
                )}
            } catch (e: Exception) {
                _state.update { it.copy(
                    isRunning = false,
                    phase = ScanPhase.IDLE,
                    error = "Ошибка скана: ${e.message}"
                )}
            }
        }
    }

    /** Генерация текстового отчёта для Share Intent */
    fun generateReport(): String {
        val result = _state.value.result ?: return "Скан ещё не выполнен"
        val device = result.device

        return buildString {
            appendLine("═══ YourVPNDead — Scan Report ═══")
            appendLine("Date: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date(result.timestamp))}")
            appendLine()

            if (device != null) {
                appendLine("── Device ──")
                appendLine("Model: ${device.manufacturer} ${device.model}")
                appendLine("Android: ${device.androidVersion} (SDK ${device.sdkVersion})")
                appendLine("VPN Active: ${if (device.isVpnActive) "Yes" else "No"}")
                appendLine("Direct IP: ${device.directIP ?: "unknown"}")
                appendLine()

                if (device.networkInterfaces.isNotEmpty()) {
                    appendLine("── Network Interfaces ──")
                    device.networkInterfaces.filter { it.isUp }.forEach { iface ->
                        appendLine("  ${iface.name}: ${iface.ips.joinToString()} (${if (iface.isUp) "UP" else "DOWN"})")
                    }
                    appendLine()
                }
            }

            appendLine("── Open Ports: ${result.openPorts.size} ──")
            result.openPorts.forEach { appendLine("  :${it.port} (${it.responseMs}ms)") }
            appendLine()

            // Direct Signs section
            result.directSigns?.let { ds ->
                append("\n=== ПРЯМЫЕ ПРИЗНАКИ VPN/ПРОКСИ ===\n")

                // VPN Transport
                append("\n--- NetworkCapabilities ---\n")
                if (ds.vpnTransport.detected) {
                    append("TRANSPORT_VPN: ${if (ds.vpnTransport.hasTransportVpn) "Да" else "Нет"}\n")
                    append("IS_VPN (hidden): ${if (ds.vpnTransport.hasIsVpnFlag) "Да" else "Нет"}\n")
                    append("VpnTransportInfo: ${if (ds.vpnTransport.hasVpnTransportInfo) "Да" else "Нет"}\n")
                } else {
                    append("VPN не обнаружен через NetworkCapabilities\n")
                }

                // System Proxy
                append("\n--- Системные прокси ---\n")
                if (ds.systemProxy.detected) {
                    ds.systemProxy.httpProxyHost?.let { append("HTTP: $it:${ds.systemProxy.httpProxyPort}\n") }
                    ds.systemProxy.socksProxyHost?.let { append("SOCKS: $it:${ds.systemProxy.socksProxyPort}\n") }
                    if (ds.systemProxy.isKnownPort) append("Известный порт: ${ds.systemProxy.knownPortLabel}\n")
                } else {
                    append("Системный прокси не настроен\n")
                }

                // Installed VPN apps
                val installed = ds.installedVpnApps.filter { it.installed }
                append("\n--- Установленные VPN-приложения (${installed.size}) ---\n")
                if (installed.isNotEmpty()) {
                    installed.forEach { append("  • ${it.appName} (${it.packageName})\n") }
                } else {
                    append("Не обнаружены\n")
                }

                // VPN Interfaces
                append("\n--- VPN-интерфейсы ---\n")
                if (ds.interfaces.isNotEmpty()) {
                    ds.interfaces.forEach {
                        append("  ${it.name}: ${it.type}/${it.protocol}, IP: ${it.ips.joinToString()}\n")
                    }
                } else {
                    append("VPN-интерфейсы не обнаружены\n")
                }

                // Routing table
                append("\n--- Таблица маршрутизации ---\n")
                val defaultRoutes = ds.routingEntries.filter { it.isDefaultRoute }
                if (defaultRoutes.isNotEmpty()) {
                    defaultRoutes.forEach {
                        val vpnFlag = if (it.isVpnRoute) " ⚠️ VPN" else ""
                        append("  ${it.interfaceName}: ${it.destination} → ${it.gateway}$vpnFlag\n")
                    }
                } else {
                    append("Нет данных\n")
                }

                // Split tunnel
                ds.splitTunnel?.let { st ->
                    append("\n--- Split Tunnel ---\n")
                    append("Прямой IP: ${st.directIp ?: "не определён"}\n")
                    append("Proxy IP: ${st.proxyIp ?: "не проверялся"}\n")
                    append("Split tunnel: ${if (st.isSplitTunnel) "Обнаружен" else "Нет"}\n")
                    append("${st.details}\n")
                }
            }

            if (result.proxies.isNotEmpty()) {
                appendLine("── Proxies Found ──")
                result.proxies.forEach { proxy ->
                    val status = if (proxy.vulnerable) "VULNERABLE" else "OK"
                    appendLine("  :${proxy.port} ${proxy.type.label} [$status]")
                }
                appendLine()
            }

            if (result.xrayAPI != null) {
                appendLine("── xray API ──")
                appendLine("  Port: ${result.xrayAPI.port}")
                appendLine("  ${result.xrayAPI.details}")
                appendLine()
            }

            if (result.exitIPs.isNotEmpty()) {
                appendLine("── Exit IPs (LEAKED!) ──")
                result.exitIPs.forEach { exitIP ->
                    appendLine("  IP: ${exitIP.ip} (via SOCKS5 :${exitIP.port})")
                    exitIP.geo?.let { geo ->
                        appendLine("    Country: ${geo.country} (${geo.countryCode})")
                        appendLine("    City: ${geo.city}")
                        appendLine("    ISP: ${geo.isp}")
                        appendLine("    AS: ${geo.asNumber}")
                        if (geo.isProxy) appendLine("    Proxy/VPN: Yes")
                        if (geo.isHosting) appendLine("    Hosting: Yes")
                    }
                }
                appendLine()
            }

            if (result.authProbes.isNotEmpty()) {
                appendLine("── Auth Analysis ──")
                result.authProbes.forEach { auth ->
                    appendLine("  Port ${auth.port}: method=${auth.methodName}")
                    appendLine("    Auth required: ${auth.authRequired}")
                    if (auth.bruteForceSuccess == true) {
                        appendLine("    ⚠️ WEAK PASSWORD: ${auth.bruteForceCredentials}")
                    }
                    if (auth.udpBypassPossible) {
                        appendLine("    ⚠️ UDP bypass possible (no per-packet auth)")
                    }
                    auth.sniffAttempt?.let { sniff ->
                        appendLine("    Raw socket blocked: ${sniff.rawSocketBlocked}")
                        appendLine("    /proc/net/tcp visible: ${sniff.procNetTcpVisible}")
                        appendLine("    Conclusion: ${sniff.conclusion}")
                    }
                }
                appendLine()
            }

            appendLine("── Findings: ${result.findings.size} ──")
            result.findings.forEach { finding ->
                appendLine("  [${finding.severity.emoji} ${finding.severity.label}] ${finding.title}")
                if (finding.description.isNotBlank()) {
                    appendLine("    ${finding.description.replace("\n", "\n    ")}")
                }
            }

            appendLine()
            appendLine("═══ Generated by YourVPNDead ═══")
        }
    }
}
