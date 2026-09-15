package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.model.CaptureFile
import dev.alsatianconsulting.pocketpcap.model.DiagnosticLog
import dev.alsatianconsulting.pocketpcap.model.RilKind
import dev.alsatianconsulting.pocketpcap.model.RilLogEntry
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun CaptureFilesScreen(
    files: List<CaptureFile>,
    onRefresh: () -> Unit,
    onDelete: (CaptureFile) -> Unit,
    onOpen: (CaptureFile) -> Unit = {},
    diagnosticLogs: List<DiagnosticLog> = emptyList(),
    onRefreshLogs: () -> Unit = {},
    onOpenLog: (DiagnosticLog) -> Unit = {},
    onDeleteLog: (DiagnosticLog) -> Unit = {},
    viewingLogName: String? = null,
    viewingLogText: String? = null,
    rilEntries: List<RilLogEntry> = emptyList(),
    onCloseLog: () -> Unit = {},
    onImportFile: (android.net.Uri) -> Unit = {},
    onMerge: (List<CaptureFile>) -> Unit = {},
) {
    val context = LocalContext.current
    // Multi-select exists only to drive merge, so it starts empty and clears
    // as soon as the merge is requested.
    var selected by remember { mutableStateOf(setOf<String>()) }

    val importPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> if (uri != null) onImportFile(uri) }

    // Refresh both lists whenever this screen is shown.
    LaunchedEffect(Unit) { onRefresh(); onRefreshLogs() }

    // Full-screen raw log viewer takes over when a diagnostic log is open.
    if (viewingLogName != null) {
        LogViewer(name = viewingLogName, text = viewingLogText, rilEntries = rilEntries, onClose = onCloseLog)
        return
    }

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Eyebrow("Storage")
                        Text("Capture files", style = MaterialTheme.typography.headlineMedium,
                            color = WarmFgPrimary)
                    }
                },
                actions = {
                    if (selected.size >= 2) {
                        IconButton(onClick = {
                            onMerge(files.filter { it.path in selected })
                            selected = emptySet()
                        }) {
                            Icon(Icons.Default.CallMerge, "Merge ${selected.size} captures",
                                tint = AcOrange500)
                        }
                    }
                    IconButton(onClick = {
                        importPicker.launch(arrayOf(
                            "application/octet-stream", "application/vnd.tcpdump.pcap",
                            "application/x-pcapng", "application/cap", "*/*",
                        ))
                    }) {
                        Icon(Icons.Default.Add, "Open a capture file", tint = AcOrange500)
                    }
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Default.Refresh, "Refresh", tint = AcOrange500)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (selected.isNotEmpty()) {
                item {
                    Text(
                        "${selected.size} selected — long-press to add, then tap merge above." +
                            if (selected.size < 2) " Pick one more to merge." else "",
                        style = MaterialTheme.typography.bodySmall, color = AcOrange400,
                    )
                    Spacer(Modifier.height(4.dp))
                }
            }
            if (files.isEmpty()) {
                item {
                    Text("No captures saved yet — start one from the Capture tab, or tap ＋ to open a .pcap or .pcapng file, including one another app is still writing.",
                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                }
            } else {
                item {
                    Text("${files.size} file${if (files.size != 1) "s" else ""}  •  ${formatTotalSize(files)}",
                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                    Spacer(Modifier.height(4.dp))
                }
                items(files, key = { it.path }) { file ->
                    val isSelected = file.path in selected
                    PcapCard {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .combinedClickable(
                                    onClick = {
                                        // While a selection is building, tapping adds to it
                                        // rather than navigating away from the list.
                                        if (selected.isEmpty()) onOpen(file)
                                        else selected = if (isSelected) selected - file.path
                                                        else selected + file.path
                                    },
                                    onLongClick = {
                                        selected = if (isSelected) selected - file.path
                                                   else selected + file.path
                                    },
                                )
                                .padding(horizontal = 12.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                if (isSelected) Icons.Default.CheckCircle else Icons.Default.Article,
                                null,
                                tint = if (isSelected) AcOrange500 else AcOrange400,
                                modifier = Modifier.size(24.dp),
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(file.name, style = MaterialTheme.typography.bodyLarge,
                                    color = WarmFgPrimary, maxLines = 1)
                                Spacer(Modifier.height(2.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text(formatFileSize(file.sizeBytes),
                                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                                    if (file.packetCount > 0) {
                                        Text("${file.packetCount} pkts",
                                            style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                                    }
                                    Text(formatDate(file.createdAt),
                                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                                }
                            }
                            Spacer(Modifier.width(8.dp))
                            IconButton(onClick = {
                                shareFile(context, file.path)
                            }) {
                                Icon(Icons.Default.Share, "Share", tint = AcOrange400,
                                    modifier = Modifier.size(20.dp))
                            }
                            IconButton(onClick = { onDelete(file) }) {
                                Icon(Icons.Default.Delete, "Delete", tint = SemanticError,
                                    modifier = Modifier.size(20.dp))
                            }
                        }
                    }
                }
            }

            if (diagnosticLogs.isNotEmpty()) {
                item {
                    Spacer(Modifier.height(12.dp))
                    Eyebrow("Diagnostic logs (RIL / modem)")
                    Spacer(Modifier.height(4.dp))
                }
                items(diagnosticLogs, key = { it.path }) { log ->
                    PcapCard {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onOpenLog(log) }
                                .padding(horizontal = 12.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Default.Description, null, tint = AcOrange400,
                                modifier = Modifier.size(24.dp))
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(log.name, style = MaterialTheme.typography.bodyLarge,
                                    color = WarmFgPrimary, maxLines = 1)
                                Spacer(Modifier.height(2.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text(formatFileSize(log.sizeBytes),
                                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                                    Text(formatDate(log.createdAt),
                                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                                }
                            }
                            Spacer(Modifier.width(8.dp))
                            IconButton(onClick = { shareFile(context, log.path) }) {
                                Icon(Icons.Default.Share, "Share", tint = AcOrange400,
                                    modifier = Modifier.size(20.dp))
                            }
                            IconButton(onClick = { onDeleteLog(log) }) {
                                Icon(Icons.Default.Delete, "Delete", tint = SemanticError,
                                    modifier = Modifier.size(20.dp))
                            }
                        }
                    }
                }
            }

            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LogViewer(
    name: String,
    text: String?,
    rilEntries: List<RilLogEntry>,
    onClose: () -> Unit,
) {
    // System back closes the viewer (clears VM state) instead of leaving the screen.
    BackHandler(enabled = true) { onClose() }
    val isRil = rilEntries.isNotEmpty()
    // RIL logs default to the parsed view. rilEntries arrive asynchronously after
    // first composition, so flip to parsed once they load (unless the user already
    // chose a view).
    var userToggled by remember(name) { mutableStateOf(false) }
    var parsed by remember(name) { mutableStateOf(false) }
    LaunchedEffect(isRil) { if (isRil && !userToggled) parsed = true }
    var kindFilter by remember(name) { mutableStateOf<RilKind?>(null) }

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onClose) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = AcOrange500)
                    }
                },
                title = {
                    Column {
                        Eyebrow(if (isRil) "RIL / modem log" else "Raw log")
                        Text(name, style = MaterialTheme.typography.titleMedium,
                            color = WarmFgPrimary, maxLines = 1)
                    }
                },
                actions = {
                    if (isRil) {
                        TextButton(onClick = { parsed = !parsed; userToggled = true },
                            colors = ButtonDefaults.textButtonColors(contentColor = AcOrange500)) {
                            Text(if (parsed) "Raw" else "Parsed")
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        when {
            text == null -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = AcOrange500)
            }
            isRil && parsed -> RilParsedView(rilEntries, kindFilter, { kindFilter = it }, Modifier.padding(padding))
            else -> Text(
                text = text,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = WarmFgPrimary,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .background(WarmBg850)
                    .verticalScroll(rememberScrollState())
                    .padding(12.dp),
            )
        }
    }
}

@Composable
private fun RilParsedView(
    entries: List<RilLogEntry>,
    kindFilter: RilKind?,
    onKindFilter: (RilKind?) -> Unit,
    modifier: Modifier = Modifier,
) {
    val shown = if (kindFilter == null) entries else entries.filter { it.kind == kindFilter }
    Column(modifier.fillMaxSize()) {
        // Summary + kind filter chips
        Column(Modifier.fillMaxWidth().background(WarmBg850).padding(horizontal = 12.dp, vertical = 8.dp)) {
            val req = entries.count { it.kind == RilKind.REQUEST }
            val resp = entries.count { it.kind == RilKind.RESPONSE }
            val unsol = entries.count { it.kind == RilKind.UNSOL }
            Text("$req requests · $resp responses · $unsol unsolicited · ${entries.size} lines",
                style = MaterialTheme.typography.labelSmall, color = WarmFgMuted)
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                RilChip("All", kindFilter == null) { onKindFilter(null) }
                RilChip("Req", kindFilter == RilKind.REQUEST) { onKindFilter(RilKind.REQUEST) }
                RilChip("Resp", kindFilter == RilKind.RESPONSE) { onKindFilter(RilKind.RESPONSE) }
                RilChip("Unsol", kindFilter == RilKind.UNSOL) { onKindFilter(RilKind.UNSOL) }
            }
        }
        LazyColumn(contentPadding = PaddingValues(vertical = 4.dp)) {
            items(shown) { e ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
                    Box(Modifier.size(8.dp).clip(RoundedCornerShape(50)).background(kindColor(e.kind))
                        .padding(top = 4.dp))
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Row {
                            Text(e.timestamp, style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                color = WarmFgMuted)
                            Spacer(Modifier.width(8.dp))
                            Text(e.tag, style = MaterialTheme.typography.labelSmall, color = AcOrange400, maxLines = 1)
                        }
                        Text(e.message, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = WarmFgPrimary)
                    }
                }
                SubtleDivider()
            }
        }
    }
}

@Composable
private fun RilChip(label: String, active: Boolean, onClick: () -> Unit) {
    Box(
        Modifier.clip(RoundedCornerShape(6.dp))
            .background(if (active) AcOrange500.copy(alpha = 0.18f) else WarmBg800)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium,
            color = if (active) AcOrange500 else WarmFgMuted)
    }
}

private fun kindColor(kind: RilKind): Color = when (kind) {
    RilKind.REQUEST  -> Color(0xFF60A5FA)
    RilKind.RESPONSE -> Color(0xFF34D399)
    RilKind.UNSOL    -> Color(0xFFFBBF24)
    RilKind.OTHER    -> Color(0xFF94A3B8)
}


private fun formatFileSize(bytes: Long): String {
    if (bytes < 1024) return "${bytes}B"
    var v = bytes.toDouble()
    val units = listOf("KB", "MB", "GB")
    var idx = -1
    while (v >= 1024 && idx < units.lastIndex) { v /= 1024; idx++ }
    return "%.1f%s".format(v, units[idx])
}

private fun formatTotalSize(files: List<CaptureFile>): String =
    formatFileSize(files.sumOf { it.sizeBytes })

private fun formatDate(ts: Long): String =
    SimpleDateFormat("MMM d, HH:mm", Locale.US).format(Date(ts))
