package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.model.CapGroup
import dev.alsatianconsulting.pocketpcap.model.CapabilityStatus
import dev.alsatianconsulting.pocketpcap.model.NetworkInterface
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CapabilityScreen(
    interfaces: List<NetworkInterface>,
    capabilities: List<CapabilityStatus>,
    rootAvailable: Boolean?,
    isRefreshing: Boolean,
    onRefresh: () -> Unit,
    diagnosticBusy: Boolean = false,
    diagnosticMessage: String? = null,
    onEnableHciSnoop: () -> Unit = {},
    onCollectHci: () -> Unit = {},
    onCollectRil: () -> Unit = {},
    onClearDiagnosticMessage: () -> Unit = {},
) {
    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Eyebrow("Sources")
                        Text("Capabilities", style = MaterialTheme.typography.headlineMedium,
                            color = WarmFgPrimary)
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh, enabled = !isRefreshing) {
                        if (isRefreshing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = AcOrange500,
                                strokeWidth = 2.dp,
                            )
                        } else {
                            Icon(Icons.Default.Refresh, "Refresh", tint = AcOrange500)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        if (isRefreshing && capabilities.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = AcOrange500)
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item { RootStatusBanner(rootAvailable) }

            if (interfaces.isNotEmpty()) {
                item {
                    PcapCard {
                        Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 8.dp)) {
                            Eyebrow("Network interfaces")
                        }
                        interfaces.forEach { iface ->
                            InterfaceDetailRow(iface)
                            if (iface != interfaces.last()) SubtleDivider()
                        }
                        Spacer(Modifier.height(4.dp))
                    }
                }
            }

            val groups = listOf(
                CapGroup.STANDARD to "Standard",
                CapGroup.ROOT     to "Root",
            )
            groups.forEach { (group, label) ->
                val items = capabilities.filter { it.group == group }
                if (items.isNotEmpty()) {
                    item {
                        PcapCard {
                            Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 8.dp)) {
                                Eyebrow(label)
                            }
                            items.forEachIndexed { idx, cap ->
                                CapabilityRow(cap.label, cap.detail, cap.state)
                                if (idx < items.lastIndex) SubtleDivider(Modifier.padding(start = 36.dp))
                            }
                            Spacer(Modifier.height(4.dp))
                        }
                    }
                }
            }

            item {
                DiagnosticsCard(
                    enabled = rootAvailable == true,
                    busy = diagnosticBusy,
                    message = diagnosticMessage,
                    onEnableHciSnoop = onEnableHciSnoop,
                    onCollectHci = onCollectHci,
                    onCollectRil = onCollectRil,
                    onClearMessage = onClearDiagnosticMessage,
                )
            }

            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

@Composable
private fun DiagnosticsCard(
    enabled: Boolean,
    busy: Boolean,
    message: String?,
    onEnableHciSnoop: () -> Unit,
    onCollectHci: () -> Unit,
    onCollectRil: () -> Unit,
    onClearMessage: () -> Unit,
) {
    PcapCard {
        Column(Modifier.padding(16.dp)) {
            Eyebrow("Diagnostic sources")
            Spacer(Modifier.height(6.dp))
            Text(
                "Collect Bluetooth HCI snoop logs (decoded as packets) and preserve raw " +
                    "RIL / modem logs. Needs root to read the radio log buffer.",
                style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onCollectHci,
                    enabled = enabled && !busy,
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                    modifier = Modifier.weight(1f),
                ) { Text("Bluetooth HCI") }
                OutlinedButton(
                    onClick = onCollectRil,
                    enabled = enabled && !busy,
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                    modifier = Modifier.weight(1f),
                ) { Text("RIL / modem") }
            }
            Spacer(Modifier.height(8.dp))
            TextButton(
                onClick = onEnableHciSnoop,
                enabled = enabled && !busy,
                colors = ButtonDefaults.textButtonColors(contentColor = WarmFgMuted),
            ) { Text("Enable Bluetooth HCI snoop logging") }

            if (busy) {
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp), color = AcOrange500, strokeWidth = 2.dp,
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("Working…", style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                }
            }
            if (!message.isNullOrBlank()) {
                Spacer(Modifier.height(10.dp))
                Box(
                    Modifier
                        .fillMaxWidth()
                        .background(WarmBg800, RoundedCornerShape(6.dp))
                        .padding(10.dp)
                ) {
                    Column {
                        Text(message, style = MaterialTheme.typography.bodySmall, color = WarmFgPrimary)
                        Spacer(Modifier.height(4.dp))
                        Text("Tap to dismiss", style = MaterialTheme.typography.labelSmall,
                            color = AcOrange400,
                            modifier = Modifier.clickable { onClearMessage() })
                    }
                }
            }
        }
    }
}

@Composable
private fun RootStatusBanner(rootAvailable: Boolean?) {
    val (textColor, heading, detail) = when (rootAvailable) {
        true  -> Triple(SemanticSuccess, "Root available",
            "Magisk root detected — live capture from a network interface is available.")
        // Not an error state: reading, decoding and analysing captures all work
        // without root, and so does rootless VPN capture. Only capturing from an
        // interface needs it, because that needs CAP_NET_RAW.
        false -> Triple(WarmFgMuted, "No root on this device",
            "Rootless VPN capture, opening capture files, decoding and analysis all " +
            "work without it. Only live capture from a network interface needs root.")
        null  -> Triple(WarmFgMuted, "Root not checked",
            "Nothing needs it yet — capture, decode and analysis all run without root.")
    }
    PcapCard {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(heading, style = MaterialTheme.typography.titleMedium, color = textColor)
            if (detail.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(detail, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
            }
        }
    }
}

@Composable
private fun InterfaceDetailRow(iface: NetworkInterface) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(8.dp)
                .background(
                    color = if (iface.isUp) SemanticSuccess else WarmFgDisabled,
                    shape = RoundedCornerShape(50),
                )
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(iface.name, style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
            Text(
                buildString {
                    append(iface.displayName)
                    if (!iface.ipv4.isNullOrEmpty()) append(" • ${iface.ipv4}")
                    if (!iface.isUp) append(" • down")
                },
                style = MaterialTheme.typography.bodySmall,
                color = WarmFgMuted,
            )
        }
        Text(
            iface.type.name.lowercase().replace('_', ' '),
            style = MaterialTheme.typography.labelSmall,
            color = AcOrange400,
        )
    }
}
