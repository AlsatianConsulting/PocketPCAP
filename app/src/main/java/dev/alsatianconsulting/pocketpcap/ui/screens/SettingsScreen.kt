package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.DecryptionUiState
import dev.alsatianconsulting.pocketpcap.decode.WifiKey
import dev.alsatianconsulting.pocketpcap.decode.WifiKeyType
import dev.alsatianconsulting.pocketpcap.resolve.GeoIpDatabaseInfo
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import dev.alsatianconsulting.pocketpcap.update.UpdateCheckState
import dev.alsatianconsulting.pocketpcap.update.UpdateChecker
import kotlinx.coroutines.launch

data class AppSettings(
    /** Autostop ceilings for rooted capture; 0 disables either one. */
    val maxCaptureSizeMb: Int = dev.alsatianconsulting.pocketpcap.decode.Prefs.DEFAULT_MAX_CAPTURE_MB,
    val maxCaptureMinutes: Int = 0,
    val autoScrollPackets: Boolean = true,
    val resolveHostnames: Boolean = false,
    val showRelativeTimestamps: Boolean = true,
    val keepRawLogs: Boolean = true,
    val displayMode: dev.alsatianconsulting.pocketpcap.resolve.ResolveDisplayMode =
        dev.alsatianconsulting.pocketpcap.resolve.ResolveDisplayMode.ADDRESS,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    settings: AppSettings,
    captureDir: String,
    onSettingsChange: (AppSettings) -> Unit,
    decryption: DecryptionUiState = DecryptionUiState(),
    geoIpInfo: GeoIpDatabaseInfo = GeoIpDatabaseInfo(),
    onImportKeylog: (android.net.Uri) -> Unit = {},
    onClearKeylog: () -> Unit = {},
    onTlsEnabledChange: (Boolean) -> Unit = {},
    onAddWifiKey: (WifiKeyType, String) -> String? = { _, _ -> null },
    onRemoveWifiKey: (WifiKey) -> Unit = {},
    onWifiEnabledChange: (Boolean) -> Unit = {},
    onChooseOutputDir: (String) -> Unit = {},
    onResetOutputDir: () -> Unit = {},
    onlineLookups: Boolean = false,
    onOnlineLookupsChange: (Boolean) -> Unit = {},
    onImportGeoIp: (android.net.Uri) -> Unit = {},
    onClearGeoIp: () -> Unit = {},
    onOpenHelp: () -> Unit = {},
    onOpenLicenses: () -> Unit = {},
    onOpenAliases: () -> Unit = {},
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var updateState by remember { mutableStateOf<UpdateCheckState>(UpdateCheckState.Idle) }
    val keylogPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> if (uri != null) onImportKeylog(uri) }
    val dirPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            val path = treeUriToPath(uri)
            when {
                path == null -> android.widget.Toast.makeText(
                    context, "Could not resolve that folder; using app storage.",
                    android.widget.Toast.LENGTH_LONG).show()
                // Android will not let an app create files in an arbitrary shared
                // folder, only in the standard media directories and its own. Say so
                // here rather than accepting the choice and quietly writing elsewhere.
                !SharedCaptureStore.canWrite(context, java.io.File(path)) ->
                    android.widget.Toast.makeText(
                        context,
                        "Android will not let PocketPCAP write to that folder. " +
                            "Pick one under Documents or Download.",
                        android.widget.Toast.LENGTH_LONG).show()
                else -> onChooseOutputDir(path)
            }
        }
    }
    val geoIpPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> if (uri != null) onImportGeoIp(uri) }
    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Eyebrow("Configuration")
                        Text("Settings", style = MaterialTheme.typography.headlineMedium,
                            color = WarmFgPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                PcapCard {
                    Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 4.dp)) {
                        Eyebrow("Capture")
                    }
                    SettingSwitchRow(
                        icon = Icons.Default.Dns,
                        label = "Resolve hostnames",
                        detail = "Reverse DNS lookup for IP addresses in packet list",
                        checked = settings.resolveHostnames,
                        onCheckedChange = { onSettingsChange(settings.copy(resolveHostnames = it)) },
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingSwitchRow(
                        icon = Icons.Default.Schedule,
                        label = "Relative timestamps",
                        detail = "Show time offset from capture start instead of wall clock",
                        checked = settings.showRelativeTimestamps,
                        onCheckedChange = { onSettingsChange(settings.copy(showRelativeTimestamps = it)) },
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingSwitchRow(
                        icon = Icons.Default.ArrowDownward,
                        label = "Auto-scroll to latest",
                        detail = "Scroll packet list to newest packet while capturing",
                        checked = settings.autoScrollPackets,
                        onCheckedChange = { onSettingsChange(settings.copy(autoScrollPackets = it)) },
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingSwitchRow(
                        icon = Icons.Default.SaveAlt,
                        label = "Preserve raw logs",
                        detail = "Keep raw RIL / modem / Bluetooth logs alongside PCAPNG",
                        checked = settings.keepRawLogs,
                        onCheckedChange = { onSettingsChange(settings.copy(keepRawLogs = it)) },
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingChoiceRow(
                        icon = Icons.Default.Storage,
                        label = "Stop at size",
                        detail = "dumpcap closes the capture cleanly at this size",
                        options = CAPTURE_SIZE_OPTIONS,
                        selected = settings.maxCaptureSizeMb,
                        labelFor = { if (it == 0) "Off" else if (it >= 1024) "${it / 1024} GB" else "$it MB" },
                        onSelect = { onSettingsChange(settings.copy(maxCaptureSizeMb = it)) },
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingChoiceRow(
                        icon = Icons.Default.Timer,
                        label = "Stop after",
                        detail = "Time limit for a rooted capture",
                        options = CAPTURE_TIME_OPTIONS,
                        selected = settings.maxCaptureMinutes,
                        labelFor = { if (it == 0) "Off" else if (it >= 60) "${it / 60} h" else "$it min" },
                        onSelect = { onSettingsChange(settings.copy(maxCaptureMinutes = it)) },
                    )
                    Spacer(Modifier.height(4.dp))
                }
            }

            item {
                PcapCard {
                    Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 4.dp)) {
                        Eyebrow("Name resolution")
                    }
                    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                        Text("Endpoint display", style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                        Text("How addresses are shown across the app",
                            style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                        Spacer(Modifier.height(10.dp))
                        val modes = listOf(
                            dev.alsatianconsulting.pocketpcap.resolve.ResolveDisplayMode.ADDRESS to "Address",
                            dev.alsatianconsulting.pocketpcap.resolve.ResolveDisplayMode.NAME_ADDRESS to "Name + addr",
                            dev.alsatianconsulting.pocketpcap.resolve.ResolveDisplayMode.NAME to "Name",
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            modes.forEach { (mode, lbl) ->
                                val active = settings.displayMode == mode
                                Box(
                                    Modifier.weight(1f)
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(if (active) AcOrange500 else WarmBg800)
                                        .clickable { onSettingsChange(settings.copy(displayMode = mode)) }
                                        .padding(vertical = 8.dp),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(lbl, style = MaterialTheme.typography.labelMedium,
                                        color = if (active) WarmBg900 else WarmFgMuted)
                                }
                            }
                        }
                    }
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpenAliases() }
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Default.Label, null, tint = AcOrange400, modifier = Modifier.size(24.dp))
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Endpoint aliases", style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                            Text("Assign your own names to addresses",
                                style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                        }
                        Icon(Icons.Default.ChevronRight, null, tint = WarmFgMuted)
                    }
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingSwitchRow(
                        icon = Icons.Default.TravelExplore,
                        label = "Online endpoint lookups",
                        detail = "Off by default. Sends public IP addresses from your capture, and " +
                            "your own public IP, to ipwho.is, rdap.org and api.ipify.org so the " +
                            "traffic map can place them. Those operators see which public addresses " +
                            "are in your capture; they never receive the capture itself. Private, " +
                            "link-local and multicast addresses are never sent.",
                        checked = onlineLookups,
                        onCheckedChange = onOnlineLookupsChange,
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Language, null, tint = AcOrange400, modifier = Modifier.size(24.dp))
                            Spacer(Modifier.width(16.dp))
                            Column(Modifier.weight(1f)) {
                                Text("Offline GeoIP database", style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                                Text(
                                    if (geoIpInfo.hasDatabase) "${geoIpInfo.fileName} - ${geoIpInfo.recordCount} record(s)"
                                    else "Import a custom CSV database for offline endpoint location",
                                    style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
                                )
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { geoIpPicker.launch(arrayOf("text/csv", "text/comma-separated-values", "text/plain", "application/octet-stream", "*/*")) },
                                shape = RoundedCornerShape(6.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                                modifier = Modifier.weight(1f),
                            ) { Text(if (geoIpInfo.hasDatabase) "Replace database" else "Import database") }
                            if (geoIpInfo.hasDatabase) {
                                OutlinedButton(
                                    onClick = onClearGeoIp,
                                    shape = RoundedCornerShape(6.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = SemanticError),
                                ) { Text("Clear") }
                            }
                        }
                        Text(
                            "CSV columns: cidr or start_ip/end_ip, plus country, country_code, region, city, latitude, longitude, asn, org, isp.",
                            style = MaterialTheme.typography.labelSmall,
                            color = WarmFgDisabled,
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }

            item {
                PcapCard {
                    Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 4.dp)) {
                        Eyebrow("Storage")
                    }
                    SettingValueRow(
                        icon = Icons.Default.Folder,
                        label = "Capture directory",
                        value = captureDir.removePrefix("/storage/emulated/0/"),
                    )
                    Text(
                        // Only true where the shared folder is actually in use. On
                        // Android 10 there is no usable path into shared storage, so
                        // output falls back to app-private storage - which the Files app
                        // cannot browse, and claiming otherwise sends people looking for
                        // captures in a folder that does not exist.
                        if (SharedCaptureStore.available) {
                            "Captures and exports are written here, where the Files app and a " +
                                "USB connection can both reach them."
                        } else {
                            "Captures and exports are written here. On this version of Android " +
                                "an app cannot write to shared storage, so this is app-private " +
                                "storage: use the app's own Files screen, or copy captures off " +
                                "with the share action."
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = WarmFgDisabled,
                        modifier = Modifier.padding(start = 56.dp, end = 16.dp),
                    )
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = { dirPicker.launch(null) },
                            shape = RoundedCornerShape(6.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                            modifier = Modifier.weight(1f),
                        ) { Text("Choose folder") }
                        OutlinedButton(
                            onClick = onResetOutputDir,
                            shape = RoundedCornerShape(6.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = WarmFgMuted),
                        ) { Text("Reset") }
                    }
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingValueRow(
                        icon = Icons.Default.Storage,
                        label = "Max capture file size",
                        value = "${settings.maxCaptureSizeMb} MB",
                    )
                    Spacer(Modifier.height(4.dp))
                }
            }

            item {
                PcapCard {
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpenHelp() }
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Default.MenuBook, null, tint = AcOrange400, modifier = Modifier.size(24.dp))
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Help & Wiki", style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                            Text("Reference for every screen, setting, button and menu",
                                style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                        }
                        Icon(Icons.Default.ChevronRight, null, tint = WarmFgMuted)
                    }
                }
            }

            item {
                PcapCard {
                    Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 4.dp)) {
                        Eyebrow("Decryption")
                    }
                    // TLS key log (SSLKEYLOGFILE) import
                    Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Key, null, tint = AcOrange400, modifier = Modifier.size(24.dp))
                            Spacer(Modifier.width(16.dp))
                            Column(Modifier.weight(1f)) {
                                Text("TLS key log", style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                                Text(
                                    if (decryption.tlsPresent) "${decryption.tlsLines} key(s) imported"
                                    else "Import an SSLKEYLOGFILE to decrypt TLS",
                                    style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
                                )
                            }
                            if (decryption.tlsPresent) {
                                Switch(
                                    checked = decryption.tlsEnabled,
                                    onCheckedChange = onTlsEnabledChange,
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = WarmBg900, checkedTrackColor = AcOrange500,
                                        uncheckedTrackColor = WarmBg700, uncheckedThumbColor = WarmFgMuted,
                                    ),
                                )
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { keylogPicker.launch(arrayOf("text/plain", "application/octet-stream", "*/*")) },
                                shape = RoundedCornerShape(6.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                                modifier = Modifier.weight(1f),
                            ) { Text(if (decryption.tlsPresent) "Replace key log" else "Import key log") }
                            if (decryption.tlsPresent) {
                                OutlinedButton(
                                    onClick = onClearKeylog,
                                    shape = RoundedCornerShape(6.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = SemanticError),
                                ) { Text("Clear") }
                            }
                        }
                    }
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    // 802.11 keys: WEP, WPA/WPA2 passphrase, or a raw PSK. Several
                    // can be held at once so one capture spanning networks decrypts.
                    var keyType by remember { mutableStateOf(WifiKeyType.WPA_PWD) }
                    var keyValue by remember { mutableStateOf("") }
                    var keyError by remember { mutableStateOf<String?>(null) }
                    Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Wifi, null, tint = AcOrange400, modifier = Modifier.size(24.dp))
                            Spacer(Modifier.width(16.dp))
                            Column(Modifier.weight(1f)) {
                                Text("802.11 decryption keys",
                                    style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                                Text("For captures containing raw 802.11 frames. WPA/WPA2 also " +
                                    "needs the EAPOL handshake for the session in the capture.",
                                    style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                            }
                            if (decryption.wifiKeys.isNotEmpty()) {
                                Switch(
                                    checked = decryption.wifiEnabled,
                                    onCheckedChange = onWifiEnabledChange,
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = WarmBg900, checkedTrackColor = AcOrange500,
                                        uncheckedTrackColor = WarmBg700, uncheckedThumbColor = WarmFgMuted,
                                    ),
                                )
                            }
                        }

                        decryption.wifiKeys.forEach { key ->
                            Spacer(Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(key.type.label,
                                        style = MaterialTheme.typography.bodyMedium, color = WarmFgPrimary)
                                    Text(key.masked,
                                        style = MaterialTheme.typography.labelSmall, color = WarmFgMuted)
                                }
                                IconButton(onClick = { onRemoveWifiKey(key) }) {
                                    Icon(Icons.Default.Delete, "Remove key", tint = SemanticError,
                                        modifier = Modifier.size(20.dp))
                                }
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            WifiKeyType.entries.forEach { type ->
                                val selected = type == keyType
                                Box(
                                    modifier = Modifier
                                        .background(
                                            if (selected) AcOrange500.copy(alpha = 0.15f) else Color.Transparent,
                                            RoundedCornerShape(6.dp),
                                        )
                                        .border(1.dp, if (selected) AcOrange500 else BorderSubtle,
                                            RoundedCornerShape(6.dp))
                                        .clickable { keyType = type; keyError = null }
                                        .padding(horizontal = 10.dp, vertical = 6.dp),
                                ) {
                                    Text(
                                        when (type) {
                                            WifiKeyType.WPA_PWD -> "WPA passphrase"
                                            WifiKeyType.WPA_PSK -> "WPA PSK"
                                            WifiKeyType.WEP -> "WEP"
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (selected) AcOrange500 else WarmFgPrimary,
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = keyValue,
                            onValueChange = { keyValue = it; keyError = null },
                            placeholder = { Text(keyType.hint, color = WarmFgDisabled) },
                            singleLine = true, shape = RoundedCornerShape(6.dp),
                            isError = keyError != null,
                            // A raw PSK and a WEP key are hex the operator needs to read
                            // back; only a passphrase is worth masking.
                            visualTransformation = if (keyType == WifiKeyType.WPA_PWD)
                                PasswordVisualTransformation() else VisualTransformation.None,
                            colors = decryptionFieldColors(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        if (keyError != null) {
                            Spacer(Modifier.height(4.dp))
                            Text(keyError!!, style = MaterialTheme.typography.labelSmall, color = SemanticError)
                        }
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                keyError = onAddWifiKey(keyType, keyValue)
                                if (keyError == null) keyValue = ""
                            },
                            enabled = keyValue.isNotBlank(),
                            shape = RoundedCornerShape(6.dp),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Add key") }
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }

            item {
                PcapCard {
                    Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 4.dp)) {
                        Eyebrow("About")
                    }
                    SettingValueRow(
                        icon = Icons.Default.Info,
                        label = "PocketPCAP",
                        value = "Version ${dev.alsatianconsulting.pocketpcap.BuildConfig.VERSION_NAME}",
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingValueRow(
                        icon = Icons.Default.Business,
                        label = "(c) Alsatian Consulting, LLC 2026",
                        value = "",
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    Box(Modifier.clickable(onClick = onOpenLicenses)) {
                        SettingValueRow(
                            icon = Icons.Default.Gavel,
                            label = "Licences",
                            value = "GPL-3.0-or-later - and third-party notices",
                        )
                    }
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingValueRow(
                        icon = Icons.Default.Code,
                        label = "GitHub",
                        value = "https://github.com/AlsatianConsulting",
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    SettingValueRow(
                        icon = Icons.Default.Language,
                        label = "Website",
                        value = "https://www.alsatian.consulting",
                    )
                    SubtleDivider(Modifier.padding(start = 56.dp))
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                        OutlinedButton(
                            onClick = {
                                updateState = UpdateCheckState.Checking
                                coroutineScope.launch {
                                    updateState = UpdateChecker.check(
                                        dev.alsatianconsulting.pocketpcap.BuildConfig.VERSION_NAME
                                    )
                                }
                            },
                            enabled = updateState != UpdateCheckState.Checking,
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = AcOrange500),
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            if (updateState == UpdateCheckState.Checking) {
                                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = AcOrange500)
                                Spacer(Modifier.width(8.dp))
                                Text("Checking…")
                            } else {
                                Icon(Icons.Default.SystemUpdate, null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Check for Updates")
                            }
                        }
                        when (val state = updateState) {
                            UpdateCheckState.Idle, UpdateCheckState.Checking -> Unit
                            UpdateCheckState.UpToDate -> Text(
                                "You are running the latest version.",
                                color = SemanticSuccess,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                            UpdateCheckState.Failed -> Text(
                                "Unable to check for updates. Check your internet connection or try again later.",
                                color = SemanticError,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                            is UpdateCheckState.Available -> Column(
                                Modifier.padding(top = 8.dp),
                                verticalArrangement = Arrangement.spacedBy(3.dp),
                            ) {
                                Text("Current version: ${state.currentVersion}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
                                Text("Latest version: ${state.latestVersion}", color = AcOrange400, style = MaterialTheme.typography.bodySmall)
                                Text(state.releaseUrl, color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                                TextButton(onClick = {
                                    val intent = android.content.Intent(
                                        android.content.Intent.ACTION_VIEW,
                                        android.net.Uri.parse(state.releaseUrl),
                                    )
                                    runCatching { context.startActivity(intent) }
                                }) { Text("Open release page") }
                            }
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                }
            }

            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

/**
 * Convert a SAF tree URI into a real filesystem path so root tshark can write
 * there directly. Handles primary ("primary:Sub/Dir" → /storage/emulated/0/Sub/Dir)
 * and secondary volumes ("XXXX-XXXX:Dir" → /storage/XXXX-XXXX/Dir). Returns null
 * for providers we can't map (e.g. Downloads provider, cloud), so the caller can
 * fall back to app storage.
 */
private fun treeUriToPath(uri: android.net.Uri): String? {
    return try {
        val docId = android.provider.DocumentsContract.getTreeDocumentId(uri)
        val parts = docId.split(":", limit = 2)
        val volume = parts.getOrNull(0) ?: return null
        val rel = parts.getOrNull(1) ?: ""
        when {
            volume.equals("primary", true) ->
                "/storage/emulated/0" + if (rel.isNotEmpty()) "/$rel" else ""
            volume.matches(Regex("[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}")) ->
                "/storage/$volume" + if (rel.isNotEmpty()) "/$rel" else ""
            else -> null
        }
    } catch (_: Exception) { null }
}

/** Autostop ceilings offered in Settings; 0 means no limit. */
private val CAPTURE_SIZE_OPTIONS = listOf(0, 128, 512, 2048)
private val CAPTURE_TIME_OPTIONS = listOf(0, 5, 30, 120)

/**
 * A labelled row of mutually exclusive value chips, used for the capture autostop
 * ceilings. Chips rather than a text field: these are a handful of sane presets and
 * the operator is usually one-handed on a phone mid-capture.
 */
@Composable
private fun SettingChoiceRow(
    icon: ImageVector,
    label: String,
    detail: String,
    options: List<Int>,
    selected: Int,
    labelFor: (Int) -> String,
    onSelect: (Int) -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = AcOrange400, modifier = Modifier.size(24.dp))
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                if (detail.isNotEmpty()) {
                    Text(detail, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(
            modifier = Modifier.padding(start = 40.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            options.forEach { option ->
                val isSelected = option == selected
                Box(
                    modifier = Modifier
                        .background(
                            if (isSelected) AcOrange500.copy(alpha = 0.15f) else Color.Transparent,
                            RoundedCornerShape(6.dp),
                        )
                        .border(
                            1.dp,
                            if (isSelected) AcOrange500 else BorderSubtle,
                            RoundedCornerShape(6.dp),
                        )
                        .clickable { onSelect(option) }
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Text(
                        labelFor(option),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isSelected) AcOrange500 else WarmFgPrimary,
                    )
                }
            }
        }
    }
}

@Composable
private fun SettingSwitchRow(
    icon: ImageVector,
    label: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = AcOrange400, modifier = Modifier.size(24.dp))
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
            if (detail.isNotEmpty()) {
                Text(detail, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
            }
        }
        Spacer(Modifier.width(8.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = WarmBg900,
                checkedTrackColor = AcOrange500,
                uncheckedTrackColor = WarmBg700,
                uncheckedThumbColor = WarmFgMuted,
            )
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun decryptionFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = AcOrange500,
    unfocusedBorderColor = BorderSubtle,
    cursorColor = AcOrange500,
    focusedContainerColor = WarmBg800,
    unfocusedContainerColor = WarmBg800,
    focusedTextColor = WarmFgPrimary,
    unfocusedTextColor = WarmFgPrimary,
)

@Composable
private fun SettingValueRow(
    icon: ImageVector,
    label: String,
    value: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = AcOrange400, modifier = Modifier.size(24.dp))
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
            if (value.isNotEmpty()) {
                Text(value, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
            }
        }
    }
}
