package dev.alsatianconsulting.pocketpcap.ui.screens

import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.model.CaptureSession
import dev.alsatianconsulting.pocketpcap.model.CaptureState
import dev.alsatianconsulting.pocketpcap.model.NetworkInterface
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import java.util.concurrent.TimeUnit

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CaptureScreen(
    interfaces: List<NetworkInterface>,
    session: CaptureSession?,
    onStart: (ifaces: List<String>, filter: String) -> Unit,
    onStartRootless: (filter: String) -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onStop: () -> Unit,
) {
    // A set so multiple interfaces can be captured simultaneously.
    var selectedIfaces by remember { mutableStateOf(setOf<String>()) }
    var captureMode by remember { mutableStateOf(CaptureMode.ROOTLESS_VPN) }
    var filterText by remember { mutableStateOf("") }
    val context = androidx.compose.ui.platform.LocalContext.current


    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        // Only start once Android has actually granted the VPN consent; launching
        // regardless would establish nothing and leave a phantom session.
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            onStartRootless(filterText)
        }
    }
    val isRunning = session?.state == CaptureState.RUNNING
    val isPaused  = session?.state == CaptureState.PAUSED
    val isActive  = isRunning || isPaused

    // Auto-select first available interface if nothing is chosen yet.
    LaunchedEffect(interfaces) {
        if (selectedIfaces.isEmpty() && interfaces.isNotEmpty()) {
            val first = interfaces.firstOrNull { it.isUp }?.name ?: interfaces.first().name
            selectedIfaces = setOf(first)
        }
    }


    fun startRootless() {
        val prepare = VpnService.prepare(context)
        if (prepare != null) vpnLauncher.launch(prepare)
        else onStartRootless(filterText)
    }

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Eyebrow("Capture")
                        Text("Packet capture", style = MaterialTheme.typography.headlineMedium,
                            color = WarmFgPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Status card
            PcapCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Eyebrow("Status")
                    CaptureStatusRow(session)
                    if (session != null && isActive) {
                        SubtleDivider()
                        CaptureStatsRow(session)
                    }
                }
            }

            // Interface selection
            if (!isActive) {
                PcapCard {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Eyebrow("Capture mode")
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            ModeButton(
                                text = "Root",
                                selected = captureMode == CaptureMode.ROOT_INTERFACES,
                                onClick = { captureMode = CaptureMode.ROOT_INTERFACES },
                                modifier = Modifier.weight(1f),
                            )
                            ModeButton(
                                text = "Rootless VPN",
                                selected = captureMode == CaptureMode.ROOTLESS_VPN,
                                onClick = { captureMode = CaptureMode.ROOTLESS_VPN },
                                modifier = Modifier.weight(1f),
                            )
                        }
                        Text(
                            when (captureMode) {
                                CaptureMode.ROOTLESS_VPN ->
                                    // Per-app scoping was removed with QUERY_ALL_PACKAGES; the
                                    // tunnel is device-wide apart from PocketPCAP itself.
                                    "Uses Android's VPN permission to capture local TUN packets, " +
                                        "device-wide apart from PocketPCAP's own traffic."
                                CaptureMode.ROOT_INTERFACES ->
                                    "Uses bundled dumpcap/tshark through root on selected network interfaces."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = WarmFgMuted,
                        )
                    }
                }


                PcapCard {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Eyebrow("Source interface(s)")
                        when {
                            captureMode == CaptureMode.ROOTLESS_VPN ->
                                Text("The rootless VPN backend creates its own local TUN source; no root interface selection is required.",
                                    style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                            interfaces.isEmpty() ->
                                Text("No interfaces detected. Run a capability check from the Sources tab.",
                                    style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                            else -> {
                                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    items(interfaces) { iface ->
                                        InterfaceChip(
                                            name = iface.name,
                                            isSelected = iface.name in selectedIfaces,
                                            isUp = iface.isUp,
                                            onClick = {
                                                selectedIfaces =
                                                    if (iface.name in selectedIfaces) selectedIfaces - iface.name
                                                    else selectedIfaces + iface.name
                                            },
                                        )
                                    }
                                }
                                Text(
                                    if (selectedIfaces.size > 1)
                                        "Capturing ${selectedIfaces.size} interfaces simultaneously into one file."
                                    else "Tap multiple interfaces to capture them at the same time.",
                                    style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
                                )
                            }
                        }
                    }
                }

                PcapCard {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Eyebrow("Capture filter")
                        OutlinedTextField(
                            value = filterText,
                            onValueChange = { filterText = it },
                            placeholder = {
                                Text("e.g. tcp port 443", style = MaterialTheme.typography.bodyMedium,
                                    color = WarmFgDisabled)
                            },
                            textStyle = MaterialTheme.typography.bodyMedium.copy(
                                color = WarmFgPrimary,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            ),
                            singleLine = true,
                            shape = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = AcOrange500,
                                unfocusedBorderColor = BorderSubtle,
                                cursorColor = AcOrange500,
                                focusedContainerColor = WarmBg800,
                                unfocusedContainerColor = WarmBg800,
                            ),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text("Leave empty to capture all traffic. Wireshark-compatible filter syntax.",
                            style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                        if (captureMode == CaptureMode.ROOTLESS_VPN) {
                            Text("Rootless VPN capture enforces common protocol, host, and port filters locally; full Wireshark display filters remain available after capture.",
                                style = MaterialTheme.typography.labelSmall, color = WarmFgDisabled)
                        }
                    }
                }
            }

            // Output path. Blank between the session appearing and the output file
            // being created, which is a MediaStore round trip off the caller's thread,
            // so don't draw an empty card in the gap.
            if (session != null && session.outputPath.isNotBlank()) {
                PcapCard {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Eyebrow("Output")
                        Text(session.outputPath, style = MaterialTheme.typography.labelSmall,
                            color = WarmFgMuted)
                        if (session.byteCount > 0) {
                            Text("${formatBytes(session.byteCount)} written",
                                style = MaterialTheme.typography.bodySmall, color = AcOrange400)
                        }
                    }
                }
            }

            // Controls
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                when {
                    !isActive -> PrimaryButton(
                        text = when {
                            captureMode == CaptureMode.ROOTLESS_VPN ->
                                "Start VPN capture (all apps)"
                            selectedIfaces.size > 1 -> "Start capture (${selectedIfaces.size})"
                            else -> "Start capture"
                        },
                        icon = Icons.Default.PlayArrow,
                        onClick = {
                            if (captureMode == CaptureMode.ROOTLESS_VPN) startRootless()
                            else if (selectedIfaces.isNotEmpty()) onStart(selectedIfaces.toList(), filterText)
                        },
                        enabled = when (captureMode) {
                            CaptureMode.ROOTLESS_VPN -> true
                            CaptureMode.ROOT_INTERFACES -> selectedIfaces.isNotEmpty()
                        },
                        modifier = Modifier.weight(1f),
                    )
                    isRunning -> {
                        OutlinedButton(
                            onClick = onPause,
                            shape = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
                            modifier = Modifier.weight(1f).height(44.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = WarmFgPrimary),
                        ) {
                            Icon(Icons.Default.Pause, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Pause")
                        }
                        DestructiveButton(text = "Stop", icon = Icons.Default.Stop,
                            onClick = onStop, modifier = Modifier.weight(1f))
                    }
                    isPaused -> {
                        PrimaryButton(text = "Resume", icon = Icons.Default.PlayArrow,
                            onClick = onResume, modifier = Modifier.weight(1f))
                        DestructiveButton(text = "Stop", icon = Icons.Default.Stop,
                            onClick = onStop, modifier = Modifier.weight(1f))
                    }
                }
            }

            Spacer(Modifier.height(16.dp))
        }
    }

}

private enum class CaptureMode { ROOT_INTERFACES, ROOTLESS_VPN }

/** A short human description of the selected VPN app scope. */

@Composable
private fun ModeButton(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (selected) {
        Button(
            onClick = onClick,
            shape = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AcOrange500, contentColor = WarmBg900),
            contentPadding = PaddingValues(horizontal = 6.dp),
            modifier = modifier.height(40.dp),
        ) { Text(text, style = MaterialTheme.typography.labelLarge, maxLines = 1) }
    } else {
        OutlinedButton(
            onClick = onClick,
            shape = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = WarmFgMuted),
            contentPadding = PaddingValues(horizontal = 6.dp),
            modifier = modifier.height(40.dp),
        ) { Text(text, style = MaterialTheme.typography.labelLarge, maxLines = 1) }
    }
}



@Composable
private fun CaptureStatusRow(session: CaptureSession?) {
    val (color, label) = when (session?.state) {
        CaptureState.RUNNING  -> Pair(SemanticSuccess, "Running")
        CaptureState.PAUSED   -> Pair(SemanticWarning, "Paused")
        CaptureState.STOPPING -> Pair(SemanticWarning, "Stopping…")
        CaptureState.STOPPED  -> Pair(WarmFgMuted, "Stopped")
        CaptureState.STARTING -> Pair(AcOrange500, "Starting…")
        CaptureState.ERROR    -> Pair(SemanticError, "Error")
        null                  -> Pair(WarmFgDisabled, "Idle")
        else                  -> Pair(WarmFgDisabled, "Idle")
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.foundation.Canvas(Modifier.size(10.dp)) {
            drawCircle(color)
        }
        Spacer(Modifier.width(10.dp))
        Text(label, style = MaterialTheme.typography.titleMedium, color = color)
        if (session?.interfaceName != null && session.state != CaptureState.IDLE) {
            Spacer(Modifier.width(8.dp))
            Text("on ${session.interfaceName}", style = MaterialTheme.typography.bodyMedium,
                color = WarmFgMuted)
        }
    }
}

@Composable
private fun CaptureStatsRow(session: CaptureSession) {
    val elapsed = System.currentTimeMillis() - session.startTime
    val h = TimeUnit.MILLISECONDS.toHours(elapsed)
    val m = TimeUnit.MILLISECONDS.toMinutes(elapsed) % 60
    val s = TimeUnit.MILLISECONDS.toSeconds(elapsed) % 60
    val timeStr = if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%d:%02d".format(m, s)

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        StatPair("Duration", timeStr)
        StatPair("Packets", session.packetCount.toString())
        StatPair("Written", formatBytes(session.byteCount))
    }
}

@Composable
private fun StatPair(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = MaterialTheme.typography.titleMedium, color = WarmFgPrimary)
        Text(label, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "${bytes}B"
    val units = listOf("KB", "MB", "GB")
    var v = bytes.toDouble()
    var idx = -1
    while (v >= 1024.0 && idx < units.lastIndex) { v /= 1024.0; idx++ }
    return "%.1f%s".format(v, units[idx])
}
