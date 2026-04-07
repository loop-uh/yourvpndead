package com.yourvpndead.ui.screens

import android.content.Intent
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.yourvpndead.model.*
import com.yourvpndead.viewmodel.ScanViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(viewModel: ScanViewModel) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("YourVPNDead", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    titleContentColor = MaterialTheme.colorScheme.onErrorContainer
                ),
                actions = {
                    if (state.result != null) {
                        IconButton(onClick = {
                            val report = viewModel.generateReport()
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, report)
                                putExtra(Intent.EXTRA_SUBJECT, "VPN Leak Scanner Report")
                            }
                            context.startActivity(Intent.createChooser(intent, "Поделиться отчётом"))
                        }) {
                            Icon(Icons.Default.Share, "Поделиться")
                        }
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // === Кнопки скана ===
            item {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Button(
                        onClick = { viewModel.quickScan() },
                        enabled = !state.isRunning,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error
                        )
                    ) {
                        Icon(Icons.Default.Search, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Быстрый скан")
                    }

                    OutlinedButton(
                        onClick = { viewModel.fullScan() },
                        enabled = !state.isRunning,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Scanner, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Полный скан")
                    }
                }
            }

            // === Прогресс ===
            if (state.isRunning) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(state.phase.label, fontWeight = FontWeight.Medium)
                            Spacer(Modifier.height(8.dp))
                            LinearProgressIndicator(
                                progress = { state.progress },
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "${(state.progress * 100).toInt()}%",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // === Ошибка ===
            state.error?.let { error ->
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Error, null, tint = MaterialTheme.colorScheme.error)
                            Spacer(Modifier.width(12.dp))
                            Text(error, color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                    }
                }
            }

            // === Результаты ===
            state.result?.let { result ->
                // Сводка
                item {
                    SummaryCard(result)
                }

                // Устройство
                result.device?.let { device ->
                    item {
                        DeviceCard(device)
                    }
                }

                // Прямые признаки VPN/прокси
                result.directSigns?.let { ds ->
                    item {
                        DirectSignsCard(ds)
                    }
                }

                // Findings
                if (result.findings.isNotEmpty()) {
                    item {
                        Text(
                            "Находки (${result.findings.size})",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    items(result.findings) { finding ->
                        FindingCard(finding)
                    }
                }
            }

            // === Пустое состояние ===
            if (!state.isRunning && state.result == null && state.error == null) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Column(
                            Modifier.padding(24.dp).fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text("🔍", fontSize = 48.sp)
                            Spacer(Modifier.height(12.dp))
                            Text(
                                "VPN Leak Scanner",
                                style = MaterialTheme.typography.headlineSmall,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "Проверяет, может ли шпионское ПО обнаружить ваш VPN " +
                                "через уязвимость SOCKS5 на localhost",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(result: ScanResult) {
    val isVulnerable = result.isVulnerable
    val color = if (isVulnerable) MaterialTheme.colorScheme.errorContainer
                else Color(0xFF1B5E20).copy(alpha = 0.15f)

    Card(colors = CardDefaults.cardColors(containerColor = color)) {
        Column(Modifier.padding(16.dp).animateContentSize()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (isVulnerable) "⚠️" else "✅",
                    fontSize = 32.sp
                )
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        if (isVulnerable) "УЯЗВИМОСТИ НАЙДЕНЫ" else "ВСЁ ЧИСТО",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        buildString {
                            append("Портов: ${result.openPorts.size}")
                            append(" • Прокси: ${result.proxies.size}")
                            append(" • Уязвимых: ${result.vulnerableCount}")
                        },
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            if (result.exitIPs.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                HorizontalDivider()
                Spacer(Modifier.height(12.dp))
                result.exitIPs.forEach { exitIP ->
                    Text(
                        "🔴 Exit IP: ${exitIP.ip}",
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    exitIP.geo?.let { geo ->
                        Text("   ${geo.country}, ${geo.city} — ${geo.isp}")
                    }
                }
            }
        }
    }
}

@Composable
private fun DeviceCard(device: DeviceFingerprint) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("📱 Устройство", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            InfoRow("Модель", "${device.manufacturer} ${device.model}")
            InfoRow("Android", "${device.androidVersion} (SDK ${device.sdkVersion})")
            InfoRow("VPN", if (device.isVpnActive) "✅ Активен" else "❌ Не активен")
            InfoRow("Прямой IP", device.directIP ?: "не определён")

            if (device.networkInterfaces.any { it.isUp }) {
                Spacer(Modifier.height(8.dp))
                Text("Интерфейсы:", style = MaterialTheme.typography.labelMedium)
                device.networkInterfaces.filter { it.isUp }.forEach { iface ->
                    Text(
                        "  ${iface.name}: ${iface.ips.joinToString()}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun DirectSignsCard(directSigns: DirectSignsResult) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "🔍 Прямые признаки VPN/прокси",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(12.dp))

            // VPN Transport
            if (directSigns.vpnTransport.detected) {
                Text("NetworkCapabilities:", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                if (directSigns.vpnTransport.hasTransportVpn) InfoRow("TRANSPORT_VPN", "Да ✅")
                if (directSigns.vpnTransport.hasIsVpnFlag) InfoRow("IS_VPN (hidden)", "Да ⚠️")
                if (directSigns.vpnTransport.hasVpnTransportInfo) InfoRow("VpnTransportInfo", "Да ⚠️")
                Spacer(modifier = Modifier.height(8.dp))
            }

            // System Proxy
            if (directSigns.systemProxy.detected) {
                Text("Системный прокси:", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                directSigns.systemProxy.httpProxyHost?.let {
                    InfoRow("HTTP proxy", "$it:${directSigns.systemProxy.httpProxyPort}")
                }
                directSigns.systemProxy.socksProxyHost?.let {
                    InfoRow("SOCKS proxy", "$it:${directSigns.systemProxy.socksProxyPort}")
                }
                if (directSigns.systemProxy.isKnownPort) {
                    InfoRow("Известный порт", directSigns.systemProxy.knownPortLabel ?: "")
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Installed VPN Apps
            val installed = directSigns.installedVpnApps.filter { it.installed }
            if (installed.isNotEmpty()) {
                Text(
                    "📦 Установлено VPN-приложений: ${installed.size}",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.error
                )
                installed.forEach { app ->
                    Text(
                        "  • ${app.appName}",
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // VPN Interfaces
            if (directSigns.interfaces.isNotEmpty()) {
                Text("🌐 VPN-интерфейсы:", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                directSigns.interfaces.forEach { iface ->
                    InfoRow(iface.name, "${iface.type} / ${iface.protocol}")
                    if (iface.ips.isNotEmpty()) {
                        Text(
                            "    IP: ${iface.ips.joinToString()}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Routing Table
            val vpnRoutes = directSigns.routingEntries.filter { it.isVpnRoute }
            if (vpnRoutes.isNotEmpty()) {
                Text(
                    "🛣️ VPN-маршруты:",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.error
                )
                vpnRoutes.forEach { route ->
                    InfoRow(route.interfaceName, "→ ${route.gateway}")
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Also show all default routes for reference
            val defaultRoutes = directSigns.routingEntries.filter { it.isDefaultRoute && !it.isVpnRoute }
            if (defaultRoutes.isNotEmpty()) {
                Text("📋 Default routes:", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                defaultRoutes.forEach { route ->
                    Text(
                        "  ${route.interfaceName}: ${route.destination} → ${route.gateway}",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Split Tunnel
            directSigns.splitTunnel?.let { st ->
                if (st.isSplitTunnel) {
                    Text(
                        "🔀 Split Tunnel обнаружен!",
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                st.directIp?.let { InfoRow("Прямой IP", it) }
                st.proxyIp?.let { InfoRow("Proxy IP", it) }
                if (st.details.isNotBlank()) {
                    Text(st.details, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding) {
    val containerColor = when (finding.severity) {
        Severity.CRITICAL -> MaterialTheme.colorScheme.errorContainer
        Severity.WARNING -> Color(0xFFFFF3E0)
        Severity.INFO -> MaterialTheme.colorScheme.secondaryContainer
        Severity.SAFE -> Color(0xFFE8F5E9)
    }

    Card(colors = CardDefaults.cardColors(containerColor = containerColor)) {
        Column(Modifier.padding(12.dp).animateContentSize()) {
            Text(
                "${finding.severity.emoji} ${finding.title}",
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyLarge
            )
            if (finding.description.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    finding.description,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 16.sp
                )
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row {
        Text("$label: ", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}
