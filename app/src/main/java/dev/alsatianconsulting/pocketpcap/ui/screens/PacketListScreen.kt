package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.data.SavedFilterEntity
import dev.alsatianconsulting.pocketpcap.filter.FilterBuilders
import dev.alsatianconsulting.pocketpcap.filter.FilterSuggestion
import dev.alsatianconsulting.pocketpcap.analysis.AnalysisExport
import dev.alsatianconsulting.pocketpcap.decode.DecodeManager
import dev.alsatianconsulting.pocketpcap.model.PacketColor
import dev.alsatianconsulting.pocketpcap.model.PacketSummary
import dev.alsatianconsulting.pocketpcap.model.DynamicPacketColumn
import dev.alsatianconsulting.pocketpcap.resolve.EndpointLabel
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketListScreen(
    packets: List<PacketSummary>,
    selectedIndex: Int?,
    captureStartTime: Long?,
    filterText: String,
    viewingFileName: String? = null,
    filterError: String? = null,
    emptyReason: String? = null,
    suggestions: List<FilterSuggestion> = emptyList(),
    recentFilters: List<String> = emptyList(),
    savedFilters: List<SavedFilterEntity> = emptyList(),
    packetColumns: List<DynamicPacketColumn> = emptyList(),
    resolveTick: Int = 0,
    labelFor: (String) -> EndpointLabel = { EndpointLabel(it, null) },
    nameFor: (String) -> String? = { null },
    aliasFor: (String) -> String? = { null },
    onFilterChange: (String) -> Unit,
    onFilterSubmit: () -> Unit = {},
    onPickSuggestion: (FilterSuggestion) -> Unit = {},
    onSaveFilter: (String) -> Unit = {},
    onDeleteSaved: (Long) -> Unit = {},
    onClearRecents: () -> Unit = {},
    onPacketSelected: (Int) -> Unit,
    onCloseFile: () -> Unit = {},
    onReloadFile: () -> Unit = {},
    following: Boolean = false,
    onFollowChange: (Boolean) -> Unit = {},
    onExportTable: (AnalysisExport.Table, Boolean) -> Unit = { _, _ -> },
    onExportSanitised: () -> Unit = {},
    onExportWithNotes: () -> Unit = {},
    onOpenAnalysis: () -> Unit = {},
    onExportFiltered: () -> Unit = {},
    onOpenObjects: () -> Unit = {},
    onOpenTrafficMap: () -> Unit = {},
    onFollowStream: (index: Int, proto: String) -> Unit = { _, _ -> },
    onApplyFilter: (String) -> Unit = {},
    onSetAlias: (String, String) -> Unit = { _, _ -> },
    onRemoveAlias: (String) -> Unit = {},
    onLookupLocation: (String) -> Unit = {},
    onRequestStreamOptions: (Int, (List<String>) -> Unit) -> Unit = { _, cb -> cb(emptyList()) },
    onRemoveColumn: (String) -> Unit = {},
    onBookmarkPacket: (PacketSummary) -> Unit = {},
) {
    val listState = rememberLazyListState()
    var menuOpen by remember { mutableStateOf(false) }

    // Long-press packet → stream action sheet.
    var sheetPacket by remember { mutableStateOf<Int?>(null) }
    var streamOptions by remember { mutableStateOf<List<String>>(emptyList()) }
    // Tapping an endpoint address opens the endpoint action sheet.
    var endpointSheet by remember { mutableStateOf<Pair<String, String?>?>(null) } // address, peer

    // Auto-scroll to latest packet when running
    LaunchedEffect(packets.size) {
        if (packets.isNotEmpty() && selectedIndex == null) {
            listState.animateScrollToItem(packets.lastIndex)
        }
    }

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Eyebrow("Packets")
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Packet list",
                                    style = MaterialTheme.typography.headlineMedium,
                                    color = WarmFgPrimary)
                                if (packets.isNotEmpty()) {
                                    Spacer(Modifier.width(8.dp))
                                    // A decode that lands exactly on the ceiling is
                                    // almost certainly cut off, so say so rather than
                                    // presenting a partial list as the whole capture.
                                    val truncated = packets.size >= DecodeManager.PACKET_LIST_LIMIT
                                    Text(
                                        if (truncated) "first ${packets.size}" else "${packets.size}",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = if (truncated) AcOrange400 else WarmFgMuted,
                                    )
                                    if (truncated) {
                                        Spacer(Modifier.width(6.dp))
                                        Text("· filter to narrow",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = WarmFgMuted)
                                    }
                                }
                            }
                        }
                    },
                    actions = {
                        Box {
                            IconButton(onClick = { menuOpen = true }) {
                                Icon(Icons.Default.MoreVert, "Tools", tint = AcOrange500)
                            }
                            DropdownMenu(
                                expanded = menuOpen,
                                onDismissRequest = { menuOpen = false },
                                containerColor = WarmBg800,
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Protocol hierarchy & endpoints", color = WarmFgPrimary) },
                                    onClick = { menuOpen = false; onOpenAnalysis() },
                                )
                                DropdownMenuItem(
                                    text = { Text("Export filtered → file", color = WarmFgPrimary) },
                                    onClick = { menuOpen = false; onExportFiltered() },
                                )
                                DropdownMenuItem(
                                    text = { Text("Export objects (HTTP…)", color = WarmFgPrimary) },
                                    onClick = { menuOpen = false; onOpenObjects() },
                                )
                                DropdownMenuItem(
                                    text = { Text("Traffic map (GeoIP)", color = WarmFgPrimary) },
                                    onClick = { menuOpen = false; onOpenTrafficMap() },
                                )
                                SubtleDivider()
                                DropdownMenuItem(
                                    text = { Text("Share headers only (no payloads)", color = WarmFgPrimary) },
                                    onClick = { menuOpen = false; onExportSanitised() },
                                )
                                DropdownMenuItem(
                                    text = { Text("Share with my packet notes", color = WarmFgPrimary) },
                                    onClick = { menuOpen = false; onExportWithNotes() },
                                )
                                SubtleDivider()
                                DropdownMenuItem(
                                    text = { Text("Export table…", color = WarmFgMuted) },
                                    enabled = false, onClick = {},
                                )
                                AnalysisExport.Table.entries.forEach { table ->
                                    DropdownMenuItem(
                                        text = {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text(table.label, color = WarmFgPrimary,
                                                    modifier = Modifier.weight(1f))
                                                Text("CSV", color = AcOrange500,
                                                    style = MaterialTheme.typography.labelMedium,
                                                    modifier = Modifier
                                                        .clickable {
                                                            menuOpen = false
                                                            onExportTable(table, false)
                                                        }
                                                        .padding(horizontal = 6.dp))
                                                Text("JSON", color = AcOrange500,
                                                    style = MaterialTheme.typography.labelMedium,
                                                    modifier = Modifier
                                                        .clickable {
                                                            menuOpen = false
                                                            onExportTable(table, true)
                                                        }
                                                        .padding(horizontal = 6.dp))
                                            }
                                        },
                                        onClick = { menuOpen = false; onExportTable(table, false) },
                                    )
                                }
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
                )
                // Viewing-a-file banner
                if (viewingFileName != null) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .background(WarmBg800)
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.Default.FolderOpen, null, tint = AcOrange400,
                            modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Viewing $viewingFileName",
                            style = MaterialTheme.typography.bodySmall, color = WarmFgPrimary,
                            modifier = Modifier.weight(1f))
                        // Follow polls the file and reloads whenever it grows, so a
                        // capture another tool is still writing can be watched rather
                        // than repeatedly refreshed by hand.
                        Text(if (following) "Following" else "Follow",
                            style = MaterialTheme.typography.labelMedium,
                            color = if (following) SemanticSuccess else AcOrange500,
                            modifier = Modifier.clickable { onFollowChange(!following) })
                        Spacer(Modifier.width(16.dp))
                        Text("Refresh", style = MaterialTheme.typography.labelMedium,
                            color = AcOrange500,
                            modifier = Modifier.clickable { onReloadFile() })
                        Spacer(Modifier.width(16.dp))
                        Text("Close", style = MaterialTheme.typography.labelMedium,
                            color = AcOrange500,
                            modifier = Modifier.clickable { onCloseFile() })
                    }
                }
                FilterBar(
                    filterText = filterText,
                    filterError = filterError,
                    suggestions = suggestions,
                    recentFilters = recentFilters,
                    savedFilters = savedFilters,
                    onFilterChange = onFilterChange,
                    onSubmit = onFilterSubmit,
                    onPickSuggestion = onPickSuggestion,
                    onApplyFilter = onApplyFilter,
                    onSaveCurrent = onSaveFilter,
                    onDeleteSaved = onDeleteSaved,
                    onClearRecents = onClearRecents,
                )
                if (packetColumns.isNotEmpty()) {
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.fillMaxWidth().background(WarmBg850),
                    ) {
                        items(packetColumns.size) { idx ->
                            val column = packetColumns[idx]
                            InputChip(selected = true, onClick = {}, label = { Text(column.field) },
                                trailingIcon = {
                                    Icon(Icons.Default.Close, "Remove column", modifier = Modifier.size(16.dp).clickable { onRemoveColumn(column.field) })
                                })
                        }
                    }
                }
            }
        }
    ) { padding ->
        if (packets.isEmpty()) {
            EmptyPacketState(Modifier.fillMaxSize().padding(padding), reason = emptyReason)
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().padding(padding),
            ) {
                itemsIndexed(packets) { idx, packet ->
                    // resolveTick keys the label so resolved names recompose in place.
                    val srcLabel = remember(packet.src, resolveTick) { labelFor(packet.src).primary }
                    val dstLabel = remember(packet.dst, resolveTick) { labelFor(packet.dst).primary }
                    PacketRow(
                        number = packet.number,
                        time = formatPacketTime(packet.timestampUs, captureStartTime),
                        src = packet.src,
                        dst = packet.dst,
                        srcLabel = srcLabel,
                        dstLabel = dstLabel,
                        protocol = packet.protocol,
                        length = packet.length,
                        info = packet.info,
                        protocolColor = protocolColor(packet.colorHint),
                        isSelected = idx == selectedIndex,
                        onClick = { onPacketSelected(idx) },
                        onProtocolClick = {
                            FilterBuilders.protocolToFilter(packet.protocol)?.let { onApplyFilter(it) }
                        },
                        onSrcClick = {
                            if (packet.src.isNotBlank() && packet.src != "?")
                                endpointSheet = packet.src to packet.dst.takeIf { it.isNotBlank() && it != "?" }
                        },
                        onDstClick = {
                            if (packet.dst.isNotBlank() && packet.dst != "?")
                                endpointSheet = packet.dst to packet.src.takeIf { it.isNotBlank() && it != "?" }
                        },
                        onLongClick = {
                            sheetPacket = idx
                            streamOptions = emptyList()
                            onRequestStreamOptions(idx) { streamOptions = it }
                        },
                    )
                    packetColumns.forEach { column ->
                        column.values[packet.number]?.let { value ->
                            Text("${column.field}: $value", color = AcOrange400,
                                style = MaterialTheme.typography.labelSmall,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 58.dp, vertical = 1.dp))
                        }
                    }
                    if (idx < packets.lastIndex) SubtleDivider()
                }
            }
        }
    }

    // Long-press: stream actions
    val pIdx = sheetPacket
    if (pIdx != null) {
        val packet = packets.getOrNull(pIdx)
        ModalBottomSheet(onDismissRequest = { sheetPacket = null }, containerColor = WarmBg850) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                if (packet != null) {
                    Eyebrow("Packet #${packet.number} — ${packet.protocol}")
                    Spacer(Modifier.height(8.dp))
                }
                if (streamOptions.isEmpty()) {
                    Text("No followable stream (resolving…)",
                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
                        modifier = Modifier.padding(vertical = 8.dp))
                } else {
                    streamOptions.forEach { proto ->
                        SheetAction("Follow $proto stream") {
                            onFollowStream(pIdx, proto); sheetPacket = null
                        }
                    }
                }
                if (packet != null) {
                    SheetAction("Bookmark packet") {
                        onBookmarkPacket(packet); sheetPacket = null
                    }
                    val protoToken = FilterBuilders.protocolToFilter(packet.protocol)
                    if (protoToken != null) {
                        SubtleDivider(Modifier.padding(vertical = 4.dp))
                        SheetAction("Filter protocol: $protoToken") {
                            onApplyFilter(protoToken); sheetPacket = null
                        }
                    }
                }
                Spacer(Modifier.height(12.dp))
            }
        }
    }

    // Endpoint action sheet (tap on a source/destination address)
    endpointSheet?.let { (addr, peer) ->
        EndpointActionSheet(
            address = addr,
            resolvedName = nameFor(addr),
            existingAlias = aliasFor(addr),
            peer = peer,
            onApplyFilter = { onApplyFilter(it); endpointSheet = null },
            onSetAlias = onSetAlias,
            onRemoveAlias = onRemoveAlias,
            onLookupLocation = { onLookupLocation(it); endpointSheet = null },
            onDismiss = { endpointSheet = null },
        )
    }
}

@Composable
private fun SheetAction(label: String, onClick: () -> Unit) {
    Text(
        label,
        style = MaterialTheme.typography.bodyLarge,
        color = WarmFgPrimary,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
    )
}

@Composable
private fun EmptyPacketState(modifier: Modifier, reason: String? = null) {
    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(horizontal = 24.dp),
        ) {
            if (reason != null) {
                // A file is open but nothing decoded. Saying "no packets captured"
                // here would be false: the list is empty because the decode could
                // not run, and the operator needs to know which of the two it is.
                Text("Could not decode this capture.",
                    style = MaterialTheme.typography.bodyLarge, color = WarmFgMuted)
                Spacer(Modifier.height(8.dp))
                Text(reason,
                    style = MaterialTheme.typography.bodySmall, color = WarmFgDisabled)
            } else {
                Text("No packets captured yet.",
                    style = MaterialTheme.typography.bodyLarge, color = WarmFgMuted)
                Spacer(Modifier.height(8.dp))
                Text("Start a capture from the Capture tab.",
                    style = MaterialTheme.typography.bodySmall, color = WarmFgDisabled)
            }
        }
    }
}

private fun protocolColor(hint: PacketColor): Color = when (hint) {
    PacketColor.TCP      -> Color(0xFF60A5FA)
    PacketColor.UDP      -> Color(0xFF34D399)
    PacketColor.DNS      -> Color(0xFFA78BFA)
    PacketColor.HTTP     -> Color(0xFFFBBF24)
    PacketColor.TLS      -> Color(0xFFF472B6)
    PacketColor.ARP      -> Color(0xFF94A3B8)
    PacketColor.ICMP     -> Color(0xFF6EE7B7)
    PacketColor.BT       -> Color(0xFF818CF8)
    PacketColor.CELLULAR -> Color(0xFFFB923C)
    PacketColor.DEFAULT  -> WarmFgMuted
}

private fun formatPacketTime(timestampUs: Long, startUs: Long?): String {
    val t = if (timestampUs < 0) 0L else timestampUs
    val s = t / 1_000_000L
    val us = t % 1_000_000L
    return "%d.%06d".format(s, us)
}
