package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.model.FollowStream
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import org.json.JSONArray
import org.json.JSONObject

private enum class StreamDirection(val label: String) { BOTH("Both"), CLIENT("Client → Server"), SERVER("Server → Client") }
private enum class StreamDisplay(val label: String) {
    TEXT("Text"), ASCII("ASCII"), HEX("Hex"), RAW("Raw"), HTTP("HTTP"), JSON("JSON")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FollowStreamScreen(
    stream: FollowStream?,
    loading: Boolean,
    onBack: () -> Unit,
    onShowPackets: (String) -> Unit = {},
    onBookmark: (FollowStream) -> Unit = {},
) {
    BackHandler(enabled = true) { onBack() }
    val clipboard = LocalClipboardManager.current

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
                        Eyebrow("Follow stream")
                        Text(
                            if (stream != null) "${stream.protocol} stream ${stream.streamIndex}" else "Stream",
                            style = MaterialTheme.typography.titleLarge, color = WarmFgPrimary,
                        )
                    }
                },
                actions = {
                    if (stream != null) {
                        IconButton(onClick = { onBookmark(stream) }) {
                            Icon(Icons.Default.BookmarkAdd, "Bookmark stream", tint = AcOrange400)
                        }
                        IconButton(onClick = {
                            val proto = if (stream.protocol.equals("UDP", true)) "udp" else "tcp"
                            onShowPackets("$proto.stream == ${stream.streamIndex}")
                        }) {
                            Icon(Icons.Default.FilterAlt, "Show packets", tint = AcOrange400)
                        }
                        IconButton(onClick = { clipboard.setText(AnnotatedString(stream.rawText)) }) {
                            Icon(Icons.Default.ContentCopy, "Copy all", tint = AcOrange400)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        when {
            loading -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = AcOrange500)
            }
            stream == null -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("Stream not available.", color = WarmFgMuted)
            }
            else -> Column(Modifier.fillMaxSize().padding(padding)) {
                var direction by remember { mutableStateOf(StreamDirection.BOTH) }
                var display by remember { mutableStateOf(StreamDisplay.TEXT) }
                var search by remember { mutableStateOf("") }
                // Endpoint legend
                Column(Modifier.fillMaxWidth().background(WarmBg850).padding(12.dp)) {
                    LegendRow(ClientColor, "Client", stream.nodeA)
                    Spacer(Modifier.height(4.dp))
                    LegendRow(ServerColor, "Server", stream.nodeB)
                }
                Row(Modifier.fillMaxWidth().horizontalScroll(androidx.compose.foundation.rememberScrollState()).padding(horizontal = 10.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StreamDirection.entries.forEach { value ->
                        FilterChip(selected = direction == value, onClick = { direction = value }, label = { Text(value.label) })
                    }
                }
                Row(Modifier.fillMaxWidth().horizontalScroll(androidx.compose.foundation.rememberScrollState()).padding(horizontal = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StreamDisplay.entries.forEach { value ->
                        FilterChip(selected = display == value, onClick = { display = value }, label = { Text(value.label) })
                    }
                }
                OutlinedTextField(search, { search = it }, label = { Text("Search within stream") },
                    leadingIcon = { Icon(Icons.Default.Search, null) }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp))
                val visible = remember(stream, direction, search) {
                    val compactHex = search.replace(Regex("[\\s:.-]"), "").lowercase()
                    val isHexSearch = compactHex.length >= 2 && compactHex.length % 2 == 0 &&
                        compactHex.all { it in '0'..'9' || it in 'a'..'f' }
                    stream.segments.filter { seg ->
                        (direction == StreamDirection.BOTH || (direction == StreamDirection.CLIENT && seg.fromA) ||
                            (direction == StreamDirection.SERVER && !seg.fromA)) &&
                            (search.isBlank() || seg.text.contains(search, true) ||
                                (isHexSearch && seg.rawHex.contains(compactHex)))
                    }
                }
                if (visible.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(if (search.isBlank()) "Stream is empty (no payload bytes)." else "No stream text matches the search.", color = WarmFgMuted)
                    }
                } else {
                    LazyColumn(contentPadding = PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        items(visible) { seg ->
                            Text(
                                formatSegment(seg, display),
                                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                color = if (seg.fromA) ClientColor else ServerColor,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun formatSegment(segment: dev.alsatianconsulting.pocketpcap.model.StreamSegment, display: StreamDisplay): String {
    val bytes = segment.rawHex.chunked(2).map { it.toInt(16) }
    return when (display) {
    StreamDisplay.TEXT -> segment.text
    StreamDisplay.ASCII -> bytes.map { if (it in 32..126 || it in setOf(9, 10, 13)) it.toChar() else '.' }.joinToString("")
    StreamDisplay.HEX -> bytes.chunked(16).mapIndexed { index, row ->
        "%04X  %s".format(index * 16, row.joinToString(" ") { "%02X".format(it) })
    }.joinToString("\n")
    StreamDisplay.RAW -> segment.rawHex
    StreamDisplay.HTTP -> segment.text.replace("\r\n", "\n")
    StreamDisplay.JSON -> runCatching {
        val trimmed = segment.text.trim()
        when {
            trimmed.startsWith("{") -> JSONObject(trimmed).toString(2)
            trimmed.startsWith("[") -> JSONArray(trimmed).toString(2)
            else -> segment.text
        }
    }.getOrDefault(segment.text)
    }
}

private val ClientColor = Color(0xFF60A5FA)
private val ServerColor = Color(0xFFF472B6)

@Composable
private fun LegendRow(color: Color, role: String, addr: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(10.dp).background(color, RoundedCornerShape(2.dp)))
        Spacer(Modifier.width(8.dp))
        Text("$role  ", style = MaterialTheme.typography.labelMedium, color = color)
        Text(addr, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = WarmFgPrimary)
    }
}
