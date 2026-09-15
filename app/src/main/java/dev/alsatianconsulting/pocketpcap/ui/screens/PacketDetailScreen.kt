package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.alsatianconsulting.pocketpcap.model.DecodeNode
import dev.alsatianconsulting.pocketpcap.model.DecodeTree
import dev.alsatianconsulting.pocketpcap.model.HexLine
import dev.alsatianconsulting.pocketpcap.model.PacketSummary
import dev.alsatianconsulting.pocketpcap.model.RawBytes
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*

enum class DetailTab { DECODE, RAW }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketDetailScreen(
    packet: PacketSummary?,
    decodeTree: DecodeTree?,
    rawBytes: RawBytes?,
    isLoading: Boolean = false,
    onBack: () -> Unit,
    onApplyFilter: (field: String, value: String, submit: Boolean) -> Unit = { _, _, _ -> },
    onExcludeValue: (field: String, value: String) -> Unit = { _, _ -> },
    onSearchValue: (String) -> Unit = {},
    onAddColumn: (String) -> Unit = {},
) {
    var activeTab by remember { mutableStateOf(DetailTab.DECODE) }
    var selectedByteRange by remember { mutableStateOf<IntRange?>(null) }

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = AcOrange500)
                    }
                },
                title = {
                    Column {
                        Eyebrow("Packet detail")
                        if (packet != null) {
                            Text("#${packet.number} ${packet.protocol}",
                                style = MaterialTheme.typography.headlineMedium,
                                color = WarmFgPrimary)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        if (packet == null) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("Select a packet from the list.",
                    style = MaterialTheme.typography.bodyLarge, color = WarmFgMuted)
            }
            return@Scaffold
        }

        Column(Modifier.fillMaxSize().padding(padding)) {
            // Tab row
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(WarmBg850)
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                DetailTab.values().forEach { tab ->
                    val isActive = tab == activeTab
                    Box(
                        Modifier
                            .background(
                                if (isActive) AcOrange500 else WarmBg800,
                                RoundedCornerShape(6.dp),
                            )
                            .clip(RoundedCornerShape(6.dp))
                            .clickable { activeTab = tab }
                            .padding(horizontal = 14.dp, vertical = 7.dp),
                    ) {
                        Text(
                            tab.name.lowercase().replaceFirstChar { it.uppercase() },
                            style = MaterialTheme.typography.titleSmall,
                            color = if (isActive) WarmBg900 else WarmFgMuted,
                        )
                    }
                }
            }

            if (isLoading && decodeTree == null && rawBytes == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = AcOrange500)
                        Spacer(Modifier.height(12.dp))
                        Text("Decoding with tshark…",
                            style = MaterialTheme.typography.bodyMedium, color = WarmFgMuted)
                    }
                }
            } else when (activeTab) {
                DetailTab.DECODE -> DecodeTreePane(
                    packet = packet,
                    tree = decodeTree,
                    onFieldSelected = { node ->
                        if (node.byteOffset >= 0 && node.byteLength > 0) {
                            selectedByteRange = node.byteOffset until (node.byteOffset + node.byteLength)
                        }
                    },
                    onApplyFilter = { field, value -> onApplyFilter(field, value, true); onBack() },
                    onPrepareFilter = { field, value -> onApplyFilter(field, value, false) },
                    onExcludeValue = { field, value -> onExcludeValue(field, value); onBack() },
                    onSearchValue = onSearchValue,
                    onAddColumn = onAddColumn,
                )
                DetailTab.RAW    -> RawBytesPane(rawBytes, selectedByteRange)
            }
        }
    }
}

@Composable
private fun DecodeTreePane(
    packet: PacketSummary,
    tree: DecodeTree?,
    onFieldSelected: (DecodeNode) -> Unit,
    onApplyFilter: (field: String, value: String) -> Unit,
    onPrepareFilter: (field: String, value: String) -> Unit,
    onExcludeValue: (field: String, value: String) -> Unit,
    onSearchValue: (String) -> Unit,
    onAddColumn: (String) -> Unit,
) {
    if (tree == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Decode not available.", style = MaterialTheme.typography.bodyLarge,
                    color = WarmFgMuted)
                Spacer(Modifier.height(8.dp))
                Text("Could not decode this packet. Ensure root was granted.",
                    style = MaterialTheme.typography.bodySmall, color = WarmFgDisabled)
            }
        }
        return
    }

    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        // Packet summary row at top
        item {
            PcapCard {
                Column(Modifier.padding(12.dp)) {
                    Text("Frame ${packet.number}  •  ${packet.length} bytes",
                        style = MaterialTheme.typography.bodyMedium, color = WarmFgPrimary)
                    Text("${packet.src} → ${packet.dst}",
                        style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                }
            }
            Spacer(Modifier.height(8.dp))
        }
        itemsIndexed(tree.nodes) { _, node ->
            DecodeNodeRow(node = node, depth = 0, onSelected = onFieldSelected,
                onApplyFilter = onApplyFilter, onPrepareFilter = onPrepareFilter,
                onExcludeValue = onExcludeValue, onSearchValue = onSearchValue, onAddColumn = onAddColumn)
        }
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun DecodeNodeRow(
    node: DecodeNode,
    depth: Int,
    onSelected: (DecodeNode) -> Unit,
    onApplyFilter: (field: String, value: String) -> Unit,
    onPrepareFilter: (field: String, value: String) -> Unit,
    onExcludeValue: (field: String, value: String) -> Unit,
    onSearchValue: (String) -> Unit,
    onAddColumn: (String) -> Unit,
) {
    var expanded by remember(node.label) { mutableStateOf(node.isExpanded || depth == 0) }
    var menuOpen by remember { mutableStateOf(false) }
    val hasChildren = node.children.isNotEmpty()
    val clipboard = LocalClipboardManager.current

    Column {
        Box {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .combinedClickable(
                        onClick = {
                            if (hasChildren) expanded = !expanded
                            onSelected(node)
                        },
                        onLongClick = { menuOpen = true },
                    )
                    .padding(start = (depth * 16 + 12).dp, end = 12.dp, top = 5.dp, bottom = 5.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (hasChildren) {
                    Icon(
                        if (expanded) Icons.Default.ExpandMore else Icons.Default.ChevronRight,
                        contentDescription = null,
                        tint = AcOrange400,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                } else {
                    Spacer(Modifier.width(20.dp))
                }
                Text(node.label, style = MaterialTheme.typography.bodyMedium, color = WarmFgPrimary,
                    modifier = Modifier.weight(1f))
                if (node.value.isNotEmpty()) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        node.value,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = AcOrange400,
                        modifier = Modifier.clickable {
                            clipboard.setText(AnnotatedString(node.value))
                        },
                    )
                }
            }
            // Long-press context menu: copy / apply-as-filter (Wireshark style).
            DropdownMenu(
                expanded = menuOpen,
                onDismissRequest = { menuOpen = false },
                containerColor = WarmBg800,
            ) {
                if (node.fieldName.isNotBlank()) {
                    DropdownMenuItem(
                        text = { Text("Copy field name", color = WarmFgPrimary) },
                        onClick = { menuOpen = false; clipboard.setText(AnnotatedString(node.fieldName)) },
                    )
                }
                if (node.fieldValue.isNotBlank()) {
                    DropdownMenuItem(
                        text = { Text("Copy value", color = WarmFgPrimary) },
                        onClick = { menuOpen = false; clipboard.setText(AnnotatedString(node.fieldValue)) },
                    )
                }
                DropdownMenuItem(
                    text = { Text("Copy label", color = WarmFgPrimary) },
                    onClick = { menuOpen = false; clipboard.setText(AnnotatedString(node.label + if (node.value.isNotBlank()) "  ${node.value}" else "")) },
                )
                if (node.fieldName.isNotBlank()) {
                    HorizontalDivider(color = BorderSubtle)
                    DropdownMenuItem(
                        text = { Text("Apply as filter", color = AcOrange500) },
                        onClick = { menuOpen = false; onApplyFilter(node.fieldName, node.fieldValue) },
                    )
                    DropdownMenuItem(
                        text = { Text("Prepare as filter", color = WarmFgPrimary) },
                        onClick = { menuOpen = false; onPrepareFilter(node.fieldName, node.fieldValue) },
                    )
                    DropdownMenuItem(
                        text = { Text("Exclude this value", color = WarmFgPrimary) },
                        onClick = { menuOpen = false; onExcludeValue(node.fieldName, node.fieldValue) },
                    )
                    DropdownMenuItem(
                        text = { Text("Search capture for value", color = WarmFgPrimary) },
                        enabled = node.fieldValue.isNotBlank(),
                        onClick = { menuOpen = false; onSearchValue(node.fieldValue) },
                    )
                    DropdownMenuItem(
                        text = { Text("Add as packet-list column", color = WarmFgPrimary) },
                        onClick = { menuOpen = false; onAddColumn(node.fieldName) },
                    )
                }
            }
        }
        // Plain-language explanation for Bluetooth/BLE layers (and any annotated field).
        if (node.explanation.isNotBlank()) {
            Text(
                node.explanation,
                style = MaterialTheme.typography.labelSmall,
                color = WarmFgMuted,
                modifier = Modifier.padding(start = (depth * 16 + 32).dp, end = 12.dp, bottom = 4.dp),
            )
        }
        if (expanded && hasChildren) {
            node.children.forEach { child ->
                DecodeNodeRow(node = child, depth = depth + 1, onSelected = onSelected,
                    onApplyFilter = onApplyFilter, onPrepareFilter = onPrepareFilter,
                    onExcludeValue = onExcludeValue, onSearchValue = onSearchValue, onAddColumn = onAddColumn)
            }
        }
    }
}

@Composable
private fun RawBytesPane(rawBytes: RawBytes?, selectedRange: IntRange?) {
    if (rawBytes == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Raw bytes not available.", style = MaterialTheme.typography.bodyLarge,
                color = WarmFgMuted)
        }
        return
    }

    val lines = remember(rawBytes) { rawBytes.hexLines() }
    // One scroll state shared by every row, so the offset, hex and ASCII columns
    // stay aligned with each other as the dump is panned sideways.
    val columnScroll = rememberScrollState()

    LazyColumn(contentPadding = PaddingValues(12.dp)) {
        item {
            Eyebrow("${rawBytes.data.size} bytes")
            Spacer(Modifier.height(8.dp))
        }
        itemsIndexed(lines) { _, line ->
            HexLineRow(line = line, selectedRange = selectedRange, columnScroll = columnScroll)
        }
    }
}

/**
 * One row of the hex dump, laid out the way Wireshark and `tshark -x` print it:
 * offset, then sixteen bytes, then the ASCII gutter.
 *
 * The row must never wrap. Sixteen bytes plus the offset and ASCII columns are
 * wider than a phone, and the hex column previously had weight(1f) with wrapping
 * left on, so it folded onto a second line while the ASCII column did not — the
 * two columns stopped lining up and the byte offsets became unreadable. Keep the
 * canonical 16-byte row, size the columns from the monospace text itself, and pan
 * the whole dump horizontally on one shared scroll state instead.
 */
@Composable
private fun HexLineRow(line: HexLine, selectedRange: IntRange?, columnScroll: ScrollState) {
    val lineRange = line.offset until (line.offset + 16)
    val isHighlighted = selectedRange != null && lineRange.any { it in selectedRange }
    val mono = MaterialTheme.typography.labelSmall.copy(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        letterSpacing = 0.sp,
    )

    Row(
        modifier = Modifier
            .horizontalScroll(columnScroll)
            .background(
                if (isHighlighted) AcOrange500.copy(alpha = 0.1f) else androidx.compose.ui.graphics.Color.Transparent
            )
            .padding(vertical = 2.dp),
    ) {
        Text(
            "%04X".format(line.offset),
            style = mono,
            color = WarmFgMuted,
            softWrap = false,
            maxLines = 1,
        )
        Spacer(Modifier.width(10.dp))
        Text(
            // hexLines() pads to a fixed 47 characters, so short final rows keep
            // the ASCII gutter in the same column as every full row above them.
            line.hex,
            style = mono,
            color = if (isHighlighted) AcOrange400 else WarmFgPrimary,
            softWrap = false,
            maxLines = 1,
        )
        Spacer(Modifier.width(12.dp))
        Text(
            line.ascii,
            style = mono,
            color = WarmFgMuted,
            softWrap = false,
            maxLines = 1,
        )
    }
}
