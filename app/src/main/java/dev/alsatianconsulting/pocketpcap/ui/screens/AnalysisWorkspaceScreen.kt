package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.analysis.*
import dev.alsatianconsulting.pocketpcap.data.AnalysisBookmarkEntity
import dev.alsatianconsulting.pocketpcap.resolve.EndpointLabel
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import java.text.DateFormat
import java.util.Date
import kotlin.math.max

private enum class WorkspacePage(val label: String) {
    SUMMARY("Summary"), CONVERSATIONS("Conversations"), ENDPOINTS("Endpoints"),
    PROTOCOLS("Protocols"), ISSUES("Issues"), OBJECTS("Objects"),
    DNS("DNS"), TLS("TLS"), HTTP("HTTP"), STATISTICS("Statistics"),
    TIMELINE("Timeline"), SEARCH("Search"), BOOKMARKS("Bookmarks"),
}

private val primaryPages = listOf(
    WorkspacePage.SUMMARY, WorkspacePage.CONVERSATIONS, WorkspacePage.ENDPOINTS,
    WorkspacePage.PROTOCOLS, WorkspacePage.ISSUES, WorkspacePage.OBJECTS,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalysisWorkspaceScreen(
    analysis: CaptureAnalysis,
    loading: Boolean,
    error: String?,
    searchResults: List<CaptureSearchResult>,
    bookmarks: List<AnalysisBookmarkEntity>,
    resolveTick: Int,
    labelFor: (String) -> EndpointLabel,
    onSearch: (String) -> Unit,
    onOpenPackets: (String) -> Unit,
    onApplyConversationFilter: (String) -> Unit,
    onFollowStream: (String, Int) -> Unit,
    onOpenObjects: () -> Unit,
    onApplyTimeRange: (Double, Double) -> Unit,
    onBookmark: (BookmarkType, String, String, String, String, Long?) -> Unit,
    onUpdateBookmark: (Long, String) -> Unit,
    onDeleteBookmark: (Long) -> Unit,
) {
    var page by remember(analysis.metadata.filename) { mutableStateOf(WorkspacePage.SUMMARY) }
    var bookmarkTarget by remember { mutableStateOf<BookmarkTarget?>(null) }
    LaunchedEffect(searchResults) {
        if (searchResults.isNotEmpty() && page == WorkspacePage.SUMMARY) page = WorkspacePage.SEARCH
    }

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Eyebrow("Whole-capture analysis")
                        Text(analysis.metadata.filename.ifBlank { "Analysis" },
                            style = MaterialTheme.typography.titleLarge, color = WarmFgPrimary, maxLines = 1)
                    }
                },
                actions = {
                    IconButton(onClick = { page = WorkspacePage.SEARCH }) {
                        Icon(Icons.Default.Search, "Search capture", tint = AcOrange500)
                    }
                    IconButton(onClick = { page = WorkspacePage.TIMELINE }) {
                        Icon(Icons.Default.ShowChart, "Traffic timeline", tint = AcOrange500)
                    }
                    IconButton(onClick = { page = WorkspacePage.BOOKMARKS }) {
                        Icon(Icons.Default.Bookmarks, "Bookmarks", tint = AcOrange500)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            LazyRow(
                Modifier.fillMaxWidth().background(WarmBg850),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(primaryPages) { candidate ->
                    FilterChip(
                        selected = page == candidate,
                        onClick = { page = candidate },
                        label = { Text(candidate.label) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AcOrange500,
                            selectedLabelColor = WarmBg900,
                            labelColor = WarmFgMuted,
                        ),
                    )
                }
            }
            if (page !in primaryPages) {
                Row(Modifier.fillMaxWidth().background(WarmBg800).padding(horizontal = 12.dp, vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { page = WorkspacePage.SUMMARY }, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Default.ArrowBack, "Back to summary", tint = AcOrange400)
                    }
                    Text(page.label, style = MaterialTheme.typography.titleSmall, color = WarmFgPrimary)
                }
            }
            when {
                loading -> LoadingAnalysis()
                error != null -> EmptyWorkspace(error)
                analysis.metadata.packetCount == 0L -> EmptyWorkspace("No packets are available for analysis.")
                else -> when (page) {
                    WorkspacePage.SUMMARY -> SummaryPage(analysis, resolveTick, labelFor, onOpenPackets,
                        onContext = { page = it }, onBookmark = { bookmarkTarget = it })
                    WorkspacePage.CONVERSATIONS -> ConversationsPage(analysis.conversations, onOpenPackets,
                        onApplyConversationFilter, onFollowStream, { page = it }, { bookmarkTarget = it })
                    WorkspacePage.ENDPOINTS -> EndpointsPage(analysis.endpoints, resolveTick, labelFor,
                        onOpenPackets, { page = it }, { bookmarkTarget = it })
                    WorkspacePage.PROTOCOLS -> ProtocolsPage(analysis.protocols, onOpenPackets)
                    WorkspacePage.ISSUES -> IssuesPage(analysis.issues, onOpenPackets) { bookmarkTarget = it }
                    WorkspacePage.OBJECTS -> ObjectsLanding(onOpenObjects)
                    WorkspacePage.DNS -> DnsPage(analysis.dns, onOpenPackets, { page = it }) { bookmarkTarget = it }
                    WorkspacePage.TLS -> TlsPage(analysis.tls, onOpenPackets, onFollowStream, { page = it }) { bookmarkTarget = it }
                    WorkspacePage.HTTP -> HttpPage(analysis.http, onOpenPackets, onFollowStream, { page = it }) { bookmarkTarget = it }
                    WorkspacePage.STATISTICS -> StatisticsPage(analysis, resolveTick, labelFor, onOpenPackets)
                    WorkspacePage.TIMELINE -> TimelinePage(analysis.timeline, analysis.metadata.durationSeconds, onApplyTimeRange)
                    WorkspacePage.SEARCH -> SearchPage(searchResults, onSearch) { result ->
                        page = when (result.entity) {
                            SearchEntity.ENDPOINT -> WorkspacePage.ENDPOINTS
                            SearchEntity.CONVERSATION, SearchEntity.STREAM -> WorkspacePage.CONVERSATIONS
                            SearchEntity.DNS -> WorkspacePage.DNS
                            SearchEntity.HTTP -> WorkspacePage.HTTP
                            SearchEntity.TLS -> WorkspacePage.TLS
                            SearchEntity.ISSUE -> WorkspacePage.ISSUES
                            SearchEntity.PACKET, SearchEntity.FIELD -> { onOpenPackets(result.filter); WorkspacePage.SEARCH }
                        }
                    }
                    WorkspacePage.BOOKMARKS -> BookmarksPage(bookmarks, onOpenPackets, onUpdateBookmark, onDeleteBookmark)
                }
            }
        }
    }

    bookmarkTarget?.let { target ->
        BookmarkDialog(target, onDismiss = { bookmarkTarget = null }) { note ->
            onBookmark(target.type, target.id, target.label, note, target.filter, target.packet)
            bookmarkTarget = null
        }
    }
}

private data class BookmarkTarget(
    val type: BookmarkType, val id: String, val label: String, val filter: String, val packet: Long? = null,
)

@Composable
private fun LoadingAnalysis() = Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator(color = AcOrange500)
        Spacer(Modifier.height(12.dp))
        Text("Building whole-capture analysis…", color = WarmFgMuted)
    }
}

@Composable
private fun EmptyWorkspace(message: String) = Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
    Text(message, color = WarmFgMuted, modifier = Modifier.padding(24.dp))
}

@Composable
private fun SummaryPage(
    a: CaptureAnalysis,
    resolveTick: Int,
    labelFor: (String) -> EndpointLabel,
    onOpenPackets: (String) -> Unit,
    onContext: (WorkspacePage) -> Unit,
    onBookmark: (BookmarkTarget) -> Unit,
) {
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            SectionCard("Capture") {
                MetricGrid(listOf(
                    "Size" to bytes(a.metadata.sizeBytes), "Packets" to a.metadata.packetCount.toString(),
                    "Duration" to duration(a.metadata.durationSeconds),
                    "Link layer" to a.metadata.linkLayerTypes.joinToString().ifBlank { "Unavailable" },
                    "First" to epoch(a.metadata.firstTimestampEpoch), "Last" to epoch(a.metadata.lastTimestampEpoch),
                ))
            }
        }
        item {
            val ipv4 = a.endpoints.count { it.filter.startsWith("ip.addr") }
            val ipv6 = a.endpoints.count { it.filter.startsWith("ipv6.addr") }
            val mac = a.endpoints.count { it.filter.startsWith("eth.addr") || it.filter.startsWith("wlan.addr") }
            SectionCard("Endpoints & conversations", onClick = { onContext(WorkspacePage.ENDPOINTS) }) {
                MetricGrid(listOf(
                    "IPv4 endpoints" to "$ipv4", "IPv6 endpoints" to "$ipv6", "MAC addresses" to "$mac",
                    "TCP conversations" to "${a.conversations.count { it.kind == ConversationKind.TCP }}",
                    "UDP conversations" to "${a.conversations.count { it.kind == ConversationKind.UDP }}",
                ))
            }
        }
        item {
            SectionCard("Dominant protocols", onClick = { onContext(WorkspacePage.PROTOCOLS) }) {
                a.protocols.take(6).forEach { p ->
                    SummaryRow(p.name, "${p.packets} pkts · ${bytes(p.bytes)} · ${"%.1f".format(p.percentage)}%") {
                        onOpenPackets(p.filter)
                    }
                }
            }
        }
        item {
            SectionCard("Top talkers", onClick = { onContext(WorkspacePage.STATISTICS) }) {
                val capturedBytes = a.protocols.sumOf { it.bytes }
                a.endpoints.take(5).forEach { e ->
                    val label = remember(e.address, resolveTick) { labelFor(e.address).primary }
                    val pct = if (capturedBytes > 0) e.bytes * 100.0 / capturedBytes else 0.0
                    SummaryRow(label, "${bytes(e.bytes)} · ${e.packets} pkts · ${"%.1f".format(pct)}%") {
                        onOpenPackets(e.filter)
                    }
                }
            }
        }
        item {
            SectionCard("Health", onClick = { onContext(WorkspacePage.ISSUES) }) {
                if (a.issues.isEmpty()) Text("No supported issues found in captured evidence.", color = SemanticSuccess)
                a.issues.take(7).forEach { issue ->
                    SummaryRow(issue.title, issue.count.toString(), issueColor(issue.severity)) { onOpenPackets(issue.filter) }
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ContextCard("DNS", a.dns.size, Modifier.weight(1f)) { onContext(WorkspacePage.DNS) }
                ContextCard("TLS", a.tls.size, Modifier.weight(1f)) { onContext(WorkspacePage.TLS) }
                ContextCard("HTTP", a.http.size, Modifier.weight(1f)) { onContext(WorkspacePage.HTTP) }
            }
        }
        if (a.contextualFilters.isNotEmpty()) item {
            SectionCard("Suggested pivots") {
                FlowRowCompat(a.contextualFilters.map { it.label to { onOpenPackets(it.filter) } })
            }
        }
    }
}

@Composable
private fun ConversationsPage(
    conversations: List<Conversation>,
    onOpenPackets: (String) -> Unit,
    onApplyFilter: (String) -> Unit,
    onFollow: (String, Int) -> Unit,
    onContext: (WorkspacePage) -> Unit,
    onBookmark: (BookmarkTarget) -> Unit,
) {
    var sort by remember { mutableStateOf("Bytes") }
    var selected by remember { mutableStateOf<Conversation?>(null) }
    val sorted = remember(conversations, sort) { when (sort) {
        "Packets" -> conversations.sortedByDescending { it.packets }
        "Duration" -> conversations.sortedByDescending { it.durationSeconds }
        "Start" -> conversations.sortedBy { it.startSeconds }
        "Sent" -> conversations.sortedByDescending { it.bytesAToB }
        "Received" -> conversations.sortedByDescending { it.bytesBToA }
        else -> conversations.sortedByDescending { it.bytes }
    } }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("Bytes", "Packets", "Duration", "Start", "Sent", "Received").forEach { label ->
                FilterChip(selected = sort == label, onClick = { sort = label }, label = { Text(label) })
            }
        }
        LazyColumn {
            items(sorted, key = { it.id }) { c ->
                Column(Modifier.fillMaxWidth().clickable { selected = c }.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(c.kind.name, color = AcOrange400, style = MaterialTheme.typography.labelMedium)
                        Spacer(Modifier.width(8.dp))
                        Text("${c.endpointA}:${c.portA ?: "*"}", color = WarmFgPrimary,
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace), modifier = Modifier.weight(1f))
                    }
                    Text("↔ ${c.endpointB}:${c.portB ?: "*"}", color = WarmFgPrimary,
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                    Text("${c.packets} pkts · ${bytes(c.bytes)} · ↑${bytes(c.bytesAToB)} ↓${bytes(c.bytesBToA)} · ${duration(c.durationSeconds)}",
                        color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                    if (c.retransmissions > 0) Text("${c.retransmissions} retransmission(s)",
                        color = SemanticWarning, style = MaterialTheme.typography.labelSmall)
                }
                SubtleDivider()
            }
        }
    }
    selected?.let { c ->
        AlertDialog(
            onDismissRequest = { selected = null },
            title = { Text("${c.kind} conversation") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${c.endpointA}:${c.portA ?: "*"} ↔ ${c.endpointB}:${c.portB ?: "*"}")
                    Text("${c.packets} packets · ${bytes(c.bytes)} · starts ${duration(c.startSeconds)} · lasts ${duration(c.durationSeconds)}" +
                        (c.streamIndex?.let { " · stream $it" } ?: ""))
                    ActionText("Show packets") { onOpenPackets(c.filter); selected = null }
                    ActionText("Apply conversation filter") { onApplyFilter(c.filter); selected = null }
                    if (c.streamIndex != null && c.kind in listOf(ConversationKind.TCP, ConversationKind.UDP))
                        ActionText("Follow stream") { onFollow(c.kind.name, c.streamIndex); selected = null }
                    ActionText("Show endpoint A") { onOpenPackets(if (c.endpointA.contains(':')) "ipv6.addr == ${c.endpointA}" else "ip.addr == ${c.endpointA}"); selected = null }
                    ActionText("Show endpoint B") { onOpenPackets(if (c.endpointB.contains(':')) "ipv6.addr == ${c.endpointB}" else "ip.addr == ${c.endpointB}"); selected = null }
                    ActionText("Show DNS associations") { onContext(WorkspacePage.DNS); selected = null }
                    ActionText("Show TLS activity") { onContext(WorkspacePage.TLS); selected = null }
                    ActionText("Show HTTP activity") { onContext(WorkspacePage.HTTP); selected = null }
                    ActionText("Show extracted objects") { onContext(WorkspacePage.OBJECTS); selected = null }
                    ActionText("Bookmark / note") {
                        onBookmark(BookmarkTarget(BookmarkType.CONVERSATION, c.id, "${c.kind} ${c.endpointA} ↔ ${c.endpointB}", c.filter, c.packetNumbers.firstOrNull()))
                        selected = null
                    }
                }
            }, confirmButton = { TextButton(onClick = { selected = null }) { Text("Close") } },
            containerColor = WarmBg850,
        )
    }
}

@Composable
private fun EndpointsPage(
    endpoints: List<AnalysisEndpoint>, resolveTick: Int, labelFor: (String) -> EndpointLabel,
    onOpenPackets: (String) -> Unit, onContext: (WorkspacePage) -> Unit, onBookmark: (BookmarkTarget) -> Unit,
) {
    var selected by remember { mutableStateOf<AnalysisEndpoint?>(null) }
    LazyColumn {
        items(endpoints, key = { it.address }) { e ->
            val label = remember(e.address, resolveTick) { labelFor(e.address) }
            Row(Modifier.fillMaxWidth().clickable { selected = e }.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(label.primary, color = WarmFgPrimary, style = MaterialTheme.typography.bodyMedium)
                    if (label.primary != e.address) Text(e.address, color = WarmFgMuted,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace))
                    Text("↑ ${bytes(e.sentBytes)} · ↓ ${bytes(e.receivedBytes)} · TCP ${e.tcpConnections} · DNS ${e.dnsRequests}",
                        color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(bytes(e.bytes), color = AcOrange400)
                    Text("${e.packets} pkts", color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = { onBookmark(BookmarkTarget(BookmarkType.ENDPOINT, e.address, e.address, e.filter)) }) {
                    Icon(Icons.Default.BookmarkAdd, "Bookmark", tint = WarmFgMuted)
                }
            }
            SubtleDivider()
        }
    }
    selected?.let { e ->
        val prefix = when {
            e.filter.startsWith("ipv6") -> "ipv6"
            e.filter.startsWith("wlan") -> "wlan"
            e.filter.startsWith("eth") -> "eth"
            else -> "ip"
        }
        AlertDialog(onDismissRequest = { selected = null }, title = { Text(e.address) }, text = {
            Column {
                ActionText("Show all traffic") { onOpenPackets(e.filter); selected = null }
                ActionText("Show as source") { onOpenPackets("${if (prefix == "wlan") "wlan.sa" else "$prefix.src"} == ${e.address}"); selected = null }
                ActionText("Show as destination") { onOpenPackets("${if (prefix == "wlan") "wlan.da" else "$prefix.dst"} == ${e.address}"); selected = null }
                ActionText("Show conversations") { onContext(WorkspacePage.CONVERSATIONS); selected = null }
                ActionText("Show DNS") { onContext(WorkspacePage.DNS); selected = null }
                ActionText("Show HTTP") { onContext(WorkspacePage.HTTP); selected = null }
                ActionText("Show TLS") { onContext(WorkspacePage.TLS); selected = null }
                ActionText("Show objects") { onContext(WorkspacePage.OBJECTS); selected = null }
            }
        }, confirmButton = { TextButton(onClick = { selected = null }) { Text("Close") } }, containerColor = WarmBg850)
    }
}

@Composable
private fun ProtocolsPage(protocols: List<ProtocolStat>, onOpenPackets: (String) -> Unit) = LazyColumn {
    items(protocols, key = { it.name }) { p ->
        Row(Modifier.fillMaxWidth().clickable { onOpenPackets(p.filter) }.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(p.name, color = WarmFgPrimary, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            Text("${p.packets} pkts", color = WarmFgMuted)
            Spacer(Modifier.width(12.dp))
            Text(bytes(p.bytes), color = WarmFgMuted)
            Spacer(Modifier.width(12.dp))
            Text("${"%.1f".format(p.percentage)}%", color = AcOrange400)
        }
        SubtleDivider()
    }
}

@Composable
private fun IssuesPage(issues: List<AnalysisIssue>, onOpenPackets: (String) -> Unit, onBookmark: (BookmarkTarget) -> Unit) {
    if (issues.isEmpty()) return EmptyWorkspace("No supported issues were found. Findings require packet evidence.")
    LazyColumn {
        items(issues, key = { it.id }) { issue ->
            Row(Modifier.fillMaxWidth().clickable { onOpenPackets(issue.filter) }.padding(12.dp), verticalAlignment = Alignment.Top) {
                Icon(Icons.Default.ReportProblem, null, tint = issueColor(issue.severity), modifier = Modifier.padding(top = 2.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text("${issue.title} · ${issue.count}", color = WarmFgPrimary, style = MaterialTheme.typography.titleSmall)
                    Text(issue.detail, color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
                    Text("${issue.severity.name} · ${issue.category}", color = issueColor(issue.severity),
                        style = MaterialTheme.typography.labelSmall)
                    if (issue.affectedEndpoints.isNotEmpty()) Text(
                        "Endpoints ${issue.affectedEndpoints.joinToString()}",
                        color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall,
                    )
                    issue.conversationId?.let {
                        Text("Conversation $it", color = WarmFgDisabled,
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace))
                    }
                    Text("First ${duration(issue.firstOccurrenceSeconds)} · packets ${issue.packetNumbers.take(8).joinToString()}",
                        color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = { onBookmark(BookmarkTarget(BookmarkType.ISSUE, issue.id, issue.title, issue.filter, issue.packetNumbers.firstOrNull())) }) {
                    Icon(Icons.Default.BookmarkAdd, "Bookmark", tint = WarmFgMuted)
                }
            }
            SubtleDivider()
        }
    }
}

@Composable
private fun DnsPage(rows: List<DnsTransaction>, onOpenPackets: (String) -> Unit,
    onContext: (WorkspacePage) -> Unit, onBookmark: (BookmarkTarget) -> Unit) {
    var selected by remember { mutableStateOf<DnsTransaction?>(null) }
    val top = rows.groupingBy { it.queryName }.eachCount().entries.sortedByDescending { it.value }.take(5)
    val failed = rows.filter { it.result !in listOf("Success", "Response") }.groupingBy { it.queryName }.eachCount().entries.sortedByDescending { it.value }.take(5)
    val slow = rows.filter { it.latencyMs != null }.sortedByDescending { it.latencyMs }.take(5)
    val types = rows.groupingBy { it.recordType }.eachCount().entries.sortedByDescending { it.value }
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        item { MetricGrid(listOf("Queries" to "${rows.size}", "Unique domains" to "${rows.map { it.queryName }.distinct().size}",
            "Failures" to "${rows.count { it.result !in listOf("Success", "Response") }}",
            "DNS servers" to "${rows.map { it.server }.distinct().size}")) }
        if (top.isNotEmpty()) item { Text("Most queried · ${top.joinToString { "${it.key} (${it.value})" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall) }
        if (failed.isNotEmpty()) item { Text("Failed domains · ${failed.joinToString { "${it.key} (${it.value})" }}", color = SemanticError, style = MaterialTheme.typography.bodySmall) }
        if (slow.isNotEmpty()) item { Text("Slowest · ${slow.joinToString { "${it.queryName} (${"%.1f".format(it.latencyMs)} ms)" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall) }
        item { Text("Query types · ${types.joinToString { "${it.key} ${it.value}" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall) }
        item { Text("Servers · ${rows.groupingBy { it.server }.eachCount().entries.sortedByDescending { it.value }.joinToString { "${it.key} (${it.value})" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall) }
        items(rows, key = { it.id }) { d ->
            Row(Modifier.fillMaxWidth().clickable { selected = d }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(d.queryName, color = WarmFgPrimary)
                    Text("${d.recordType} · ${d.result} · ${d.client} → ${d.server}", color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                    Text("${d.responseAddresses.joinToString().ifBlank { "No response addresses" }} · ${d.latencyMs?.let { "%.1f ms".format(it) } ?: "latency unavailable"}",
                        color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                    Text("At ${duration(d.timestampSeconds)} · query #${d.queryPacket}" +
                        (d.responsePacket?.let { " · response #$it" } ?: "") +
                        (d.streamIndex?.let { " · stream $it" } ?: ""),
                        color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = { onBookmark(BookmarkTarget(BookmarkType.DNS, d.id, d.queryName, d.filter, d.queryPacket)) }) {
                    Icon(Icons.Default.BookmarkAdd, "Bookmark", tint = WarmFgMuted)
                }
            }
            SubtleDivider()
        }
    }
    selected?.let { d ->
        val endpointFilter = d.responseAddresses.joinToString(" || ") { address ->
            if (address.contains(':')) "ipv6.addr == $address" else "ip.addr == $address"
        }
        AlertDialog(onDismissRequest = { selected = null }, title = { Text(d.queryName) }, text = {
            Column {
                ActionText("Show DNS packets") { onOpenPackets(d.filter); selected = null }
                if (endpointFilter.isNotBlank()) ActionText("Show returned endpoints") { onOpenPackets(endpointFilter); selected = null }
                if (endpointFilter.isNotBlank()) ActionText("Show related conversations") { onOpenPackets("($endpointFilter) && (tcp || udp)"); selected = null }
                if (endpointFilter.isNotBlank()) ActionText("Show related HTTP") { onOpenPackets("($endpointFilter) && http"); selected = null }
                if (endpointFilter.isNotBlank()) ActionText("Show related TLS") { onOpenPackets("($endpointFilter) && tls"); selected = null }
                ActionText("Open all HTTP analysis") { onContext(WorkspacePage.HTTP); selected = null }
                ActionText("Open all TLS analysis") { onContext(WorkspacePage.TLS); selected = null }
            }
        }, confirmButton = { TextButton(onClick = { selected = null }) { Text("Close") } }, containerColor = WarmBg850)
    }
}

@Composable
private fun TlsPage(rows: List<TlsSession>, onOpenPackets: (String) -> Unit, onFollow: (String, Int) -> Unit,
    onContext: (WorkspacePage) -> Unit, onBookmark: (BookmarkTarget) -> Unit) {
    var selected by remember { mutableStateOf<TlsSession?>(null) }
    LazyColumn {
      items(rows, key = { it.id }) { t ->
        Column(Modifier.fillMaxWidth().clickable { selected = t }.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(t.sni ?: "${t.server}:${t.serverPort ?: 443}", color = WarmFgPrimary)
                    Text("${t.client} → ${t.server}:${t.serverPort ?: "?"}", color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                    Text(listOfNotNull(t.version, t.alpn, t.cipher).joinToString(" · ").ifBlank { "TLS metadata unavailable" }, color = AcOrange400, style = MaterialTheme.typography.labelSmall)
                    Text("${t.handshakeState} · ${t.packetCount} pkts · ${bytes(t.bytes)}", color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                    if (t.certificateSubject != null) Text("Certificate: ${t.certificateSubject}", color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                    if (t.certificateIssuer != null) Text("Issuer: ${t.certificateIssuer}", color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                    if (t.certificateNotBefore != null) Text("Valid from: ${t.certificateNotBefore.substringAfter('|', t.certificateNotBefore)}", color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                    if (t.certificateNotAfter != null) Text("Valid until: ${t.certificateNotAfter.substringAfter('|', t.certificateNotAfter)}", color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                    if (t.alerts.isNotEmpty()) Text("Alerts: ${t.alerts.joinToString()}", color = SemanticError, style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = { onFollow("TLS", t.tcpStream) }) { Icon(Icons.Default.Forum, "Follow stream", tint = AcOrange400) }
                IconButton(onClick = { onBookmark(BookmarkTarget(BookmarkType.TLS, t.id, t.sni ?: "TLS stream ${t.tcpStream}", t.filter, t.packetNumbers.firstOrNull())) }) {
                    Icon(Icons.Default.BookmarkAdd, "Bookmark", tint = WarmFgMuted)
                }
            }
        }
        SubtleDivider()
      }
    }
    selected?.let { t ->
        AlertDialog(onDismissRequest = { selected = null }, title = { Text(t.sni ?: "TLS stream ${t.tcpStream}") }, text = {
            Column {
                ActionText("Show packets") { onOpenPackets(t.filter); selected = null }
                ActionText("Follow TLS stream") { onFollow("TLS", t.tcpStream); selected = null }
                ActionText("Open server endpoint") { onOpenPackets(if (t.server.contains(':')) "ipv6.addr == ${t.server}" else "ip.addr == ${t.server}"); selected = null }
                ActionText("Show related DNS") { onContext(WorkspacePage.DNS); selected = null }
                ActionText("Show decrypted HTTP") { onContext(WorkspacePage.HTTP); selected = null }
            }
        }, confirmButton = { TextButton(onClick = { selected = null }) { Text("Close") } }, containerColor = WarmBg850)
    }
}

@Composable
private fun HttpPage(rows: List<HttpTransaction>, onOpenPackets: (String) -> Unit, onFollow: (String, Int) -> Unit,
    onContext: (WorkspacePage) -> Unit, onBookmark: (BookmarkTarget) -> Unit) {
    val clipboard = LocalClipboardManager.current
    var selected by remember { mutableStateOf<HttpTransaction?>(null) }
    val statuses = rows.groupingBy { it.statusCode?.div(100)?.let { family -> "${family}xx" } ?: "No response" }.eachCount()
    val hosts = rows.groupingBy { it.hostname ?: "Unknown" }.eachCount().entries.sortedByDescending { it.value }.take(5)
    val paths = rows.groupingBy { it.uri }.eachCount().entries.sortedByDescending { it.value }.take(5)
    val largest = rows.filter { it.contentLength != null }.sortedByDescending { it.contentLength }.take(3)
    val slowest = rows.filter { it.latencyMs != null }.sortedByDescending { it.latencyMs }.take(3)
    LazyColumn {
        item {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                MetricGrid(listOf("Requests" to "${rows.size}", "Hosts" to "${rows.mapNotNull { it.hostname }.distinct().size}",
                    "Status distribution" to statuses.entries.joinToString { "${it.key} ${it.value}" },
                    "Responses" to "${rows.count { it.statusCode != null }}"))
                Text("Top hosts · ${hosts.joinToString { "${it.key} (${it.value})" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
                Text("Top paths · ${paths.joinToString { "${it.key} (${it.value})" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
                if (largest.isNotEmpty()) Text("Largest · ${largest.joinToString { "${it.uri} (${bytes(it.contentLength ?: 0)})" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
                if (slowest.isNotEmpty()) Text("Slowest · ${slowest.joinToString { "${it.uri} (${"%.1f".format(it.latencyMs)} ms)" }}", color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
            }
        }
        items(rows, key = { it.id }) { h ->
            Row(Modifier.fillMaxWidth().clickable { selected = h }.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("${h.method} ${h.hostname.orEmpty()}${h.uri}", color = WarmFgPrimary, maxLines = 2)
                    Text("${h.client} → ${h.server} · ${h.statusCode ?: "No response"} · ${h.contentType ?: "type unavailable"}", color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                    Text("${h.contentLength?.let(::bytes) ?: "size unavailable"} · ${h.latencyMs?.let { "%.1f ms".format(it) } ?: "latency unavailable"}", color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                    Text("At ${duration(h.requestTimestampSeconds)} · request #${h.requestPacket}" +
                        (h.responsePacket?.let { " · response #$it" } ?: "") +
                        (h.tcpStream?.let { " · TCP stream $it" } ?: ""),
                        color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = { clipboard.setText(AnnotatedString(h.url)) }) { Icon(Icons.Default.ContentCopy, "Copy URL", tint = WarmFgMuted) }
                if (h.tcpStream != null) IconButton(onClick = { onFollow("HTTP", h.tcpStream) }) { Icon(Icons.Default.Forum, "Follow stream", tint = AcOrange400) }
                IconButton(onClick = { onBookmark(BookmarkTarget(BookmarkType.HTTP, h.id, "${h.method} ${h.url}", h.filter, h.requestPacket)) }) {
                    Icon(Icons.Default.BookmarkAdd, "Bookmark", tint = WarmFgMuted)
                }
            }
            SubtleDivider()
        }
    }
    selected?.let { h ->
        AlertDialog(onDismissRequest = { selected = null }, title = { Text("${h.method} ${h.uri}") }, text = {
            Column {
                ActionText("Show packets") { onOpenPackets(h.filter); selected = null }
                if (h.tcpStream != null) ActionText("Follow stream") { onFollow("HTTP", h.tcpStream); selected = null }
                ActionText("Copy URL") { clipboard.setText(AnnotatedString(h.url)); selected = null }
                ActionText("Open server endpoint") { onOpenPackets(if (h.server.contains(':')) "ipv6.addr == ${h.server}" else "ip.addr == ${h.server}"); selected = null }
                ActionText("Open DNS records") { onContext(WorkspacePage.DNS); selected = null }
                ActionText("Open TLS sessions") { onContext(WorkspacePage.TLS); selected = null }
                ActionText("Extract related objects") { onContext(WorkspacePage.OBJECTS); selected = null }
            }
        }, confirmButton = { TextButton(onClick = { selected = null }) { Text("Close") } }, containerColor = WarmBg850)
    }
}

@Composable
private fun StatisticsPage(a: CaptureAnalysis, resolveTick: Int, labelFor: (String) -> EndpointLabel, onOpenPackets: (String) -> Unit) =
    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item { SectionCard("Transport distribution") { MetricGrid(listOf(
            "TCP packets" to "${a.protocols.firstOrNull { it.name.equals("TCP", true) }?.packets ?: 0}",
            "UDP packets" to "${a.protocols.firstOrNull { it.name.equals("UDP", true) }?.packets ?: 0}",
            "TCP conversations" to "${a.conversations.count { it.kind == ConversationKind.TCP }}",
            "UDP conversations" to "${a.conversations.count { it.kind == ConversationKind.UDP }}")) } }
        item { StatsList("Protocol distribution", a.protocols.take(12).map {
            it.name to "${it.packets} packets · ${bytes(it.bytes)} · ${"%.1f".format(it.percentage)}%"
        }, a.protocols.take(12).map { it.filter }, onOpenPackets) }
        item { StatsList("Top senders", a.endpoints.sortedByDescending { it.sentBytes }.take(8).map {
            remember(it.address, resolveTick) { labelFor(it.address).primary } to bytes(it.sentBytes) }, a.endpoints.sortedByDescending { it.sentBytes }.take(8).map { it.filter }, onOpenPackets) }
        item { StatsList("Top receivers", a.endpoints.sortedByDescending { it.receivedBytes }.take(8).map {
            remember(it.address, resolveTick) { labelFor(it.address).primary } to bytes(it.receivedBytes) }, a.endpoints.sortedByDescending { it.receivedBytes }.take(8).map { it.filter }, onOpenPackets) }
        item { StatsList("Largest conversations", a.conversations.take(8).map { "${it.endpointA} ↔ ${it.endpointB}" to bytes(it.bytes) }, a.conversations.take(8).map { it.filter }, onOpenPackets) }
        item { StatsList("Most packets by endpoint", a.endpoints.sortedByDescending { it.packets }.take(8).map { it.address to "${it.packets} packets" },
            a.endpoints.sortedByDescending { it.packets }.take(8).map { it.filter }, onOpenPackets) }
        item { StatsList("Most TCP connections", a.endpoints.sortedByDescending { it.tcpConnections }.take(8).map { it.address to "${it.tcpConnections} connections" },
            a.endpoints.sortedByDescending { it.tcpConnections }.take(8).map { it.filter }, onOpenPackets) }
        item { StatsList("Most DNS requests", a.endpoints.filter { it.dnsRequests > 0 }.sortedByDescending { it.dnsRequests }.take(8).map { it.address to "${it.dnsRequests} requests" },
            a.endpoints.filter { it.dnsRequests > 0 }.sortedByDescending { it.dnsRequests }.take(8).map { "${it.filter} && dns" }, onOpenPackets) }
        item { StatsList("Most retransmissions", a.endpoints.filter { it.retransmissions > 0 }.sortedByDescending { it.retransmissions }.take(8).map { it.address to "${it.retransmissions} retransmissions" },
            a.endpoints.filter { it.retransmissions > 0 }.sortedByDescending { it.retransmissions }.take(8).map { "${it.filter} && tcp.analysis.retransmission" }, onOpenPackets) }
        item { StatsList("Retransmissions by conversation", a.conversations.filter { it.retransmissions > 0 }
            .sortedByDescending { it.retransmissions }.take(8).map {
                "${it.endpointA} ↔ ${it.endpointB}" to "${it.retransmissions} retransmissions"
            }, a.conversations.filter { it.retransmissions > 0 }.sortedByDescending { it.retransmissions }
                .take(8).map { "(${it.filter}) && tcp.analysis.retransmission" }, onOpenPackets) }
        item { StatsList("Most contacted domains", a.dns.groupingBy { it.queryName }.eachCount().entries.sortedByDescending { it.value }.take(8).map { it.key to "${it.value} queries" },
            a.dns.groupingBy { it.queryName }.eachCount().entries.sortedByDescending { it.value }.take(8).map { "dns.qry.name == \"${it.key}\"" }, onOpenPackets) }
    }

@Composable
private fun TimelinePage(rows: List<TimelineBucket>, duration: Double, onApply: (Double, Double) -> Unit) {
    var range by remember(duration) { mutableStateOf(0f..max(1.0, duration).toFloat()) }
    var showBytes by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Traffic per time bucket", color = WarmFgPrimary, modifier = Modifier.weight(1f))
            FilterChip(selected = !showBytes, onClick = { showBytes = false }, label = { Text("Packets/s") })
            Spacer(Modifier.width(6.dp))
            FilterChip(selected = showBytes, onClick = { showBytes = true }, label = { Text("Bytes/s") })
        }
        val maximum = max(1L, rows.maxOfOrNull { if (showBytes) it.bytes else it.packets } ?: 1L)
        Canvas(Modifier.fillMaxWidth().height(180.dp).background(WarmBg850, RoundedCornerShape(8.dp))) {
            val barWidth = if (rows.isEmpty()) size.width else size.width / rows.size
            rows.forEachIndexed { idx, bucket ->
                val value = if (showBytes) bucket.bytes else bucket.packets
                val h = size.height * value / maximum
                drawRect(AcOrange500, topLeft = androidx.compose.ui.geometry.Offset(idx * barWidth, size.height - h),
                    size = androidx.compose.ui.geometry.Size(max(1f, barWidth - 1f), h))
                if (bucket.retransmissions + bucket.tcpResets > 0) {
                    drawCircle(SemanticError, radius = 3.dp.toPx(), center = androidx.compose.ui.geometry.Offset(idx * barWidth + barWidth / 2, 6.dp.toPx()))
                }
            }
        }
        Text("Range ${duration(range.start.toDouble())} – ${duration(range.endInclusive.toDouble())}", color = WarmFgMuted)
        RangeSlider(value = range, onValueChange = { range = it }, valueRange = 0f..max(1.0, duration).toFloat())
        PrimaryButton("Filter capture to this time range", onClick = { onApply(range.start.toDouble(), range.endInclusive.toDouble()) }, modifier = Modifier.fillMaxWidth())
        Text("Orange bars: packets per bucket · red markers: retransmissions or resets. Pinch zoom is not required; the range control gives precise selection.",
            color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun SearchPage(results: List<CaptureSearchResult>, onSearch: (String) -> Unit,
    onOpenResult: (CaptureSearchResult) -> Unit) {
    var query by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(query, { query = it; onSearch(it) }, label = { Text("IP, host, URL, port, protocol, field, text or hex") },
            leadingIcon = { Icon(Icons.Default.Search, null) }, modifier = Modifier.fillMaxWidth().padding(12.dp), singleLine = true)
        LazyColumn {
            results.groupBy { it.entity }.forEach { (entity, grouped) ->
                item { Eyebrow(entity.name.lowercase().replaceFirstChar(Char::uppercase), Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) }
                items(grouped) { result ->
                    Column(Modifier.fillMaxWidth().clickable { onOpenResult(result) }.padding(horizontal = 12.dp, vertical = 8.dp)) {
                        Text(result.title, color = WarmFgPrimary)
                        Text(result.subtitle, color = WarmFgMuted, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun BookmarksPage(rows: List<AnalysisBookmarkEntity>, onOpenPackets: (String) -> Unit,
    onUpdate: (Long, String) -> Unit, onDelete: (Long) -> Unit) {
    if (rows.isEmpty()) return EmptyWorkspace("No bookmarks or analyst notes for this capture.")
    var editing by remember { mutableStateOf<AnalysisBookmarkEntity?>(null) }
    Box {
        LazyColumn {
            items(rows, key = { it.id }) { b ->
                Row(Modifier.fillMaxWidth().clickable { onOpenPackets(b.filter) }.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("${b.type.lowercase().replaceFirstChar(Char::uppercase)} · ${b.label}", color = WarmFgPrimary)
                        if (b.note.isNotBlank()) Text(b.note, color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
                        Text(b.filter, color = WarmFgDisabled, style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace))
                    }
                    IconButton(onClick = { editing = b }) { Icon(Icons.Default.EditNote, "Edit note", tint = AcOrange400) }
                    IconButton(onClick = { onDelete(b.id) }) { Icon(Icons.Default.Delete, "Delete bookmark", tint = SemanticError) }
                }
                SubtleDivider()
            }
        }
    }
    editing?.let { b ->
        var note by remember(b.id) { mutableStateOf(b.note) }
        AlertDialog(onDismissRequest = { editing = null }, title = { Text("Analyst note") },
            text = { OutlinedTextField(note, { note = it }, minLines = 3) },
            confirmButton = { TextButton(onClick = { onUpdate(b.id, note); editing = null }) { Text("Save") } },
            dismissButton = { TextButton(onClick = { editing = null }) { Text("Cancel") } }, containerColor = WarmBg850)
    }
}

@Composable
private fun ObjectsLanding(onOpenObjects: () -> Unit) = Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
        Icon(Icons.Default.Inventory2, null, tint = AcOrange500, modifier = Modifier.size(42.dp))
        Spacer(Modifier.height(12.dp))
        Text("Extract transferred objects", color = WarmFgPrimary, style = MaterialTheme.typography.titleLarge)
        Text("Uses tshark export-object support for HTTP, TFTP, SMB, IMF and DICOM. Extracted files are derived separately; the PCAP is unchanged.",
            color = WarmFgMuted, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(16.dp))
        PrimaryButton("Open object extraction", onClick = onOpenObjects)
    }
}

@Composable
private fun SectionCard(title: String, onClick: (() -> Unit)? = null, content: @Composable ColumnScope.() -> Unit) {
    PcapCard(Modifier.then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Eyebrow(title)
            content()
        }
    }
}

@Composable
private fun MetricGrid(values: List<Pair<String, String>>) {
    values.chunked(2).forEach { row ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            row.forEach { (label, value) ->
                Column(Modifier.weight(1f)) { Text(value, color = WarmFgPrimary, style = MaterialTheme.typography.titleMedium); Text(label, color = WarmFgMuted, style = MaterialTheme.typography.labelSmall) }
            }
            if (row.size == 1) Spacer(Modifier.weight(1f))
        }
    }
}

@Composable
private fun SummaryRow(label: String, value: String, valueColor: Color = WarmFgMuted, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = WarmFgPrimary, modifier = Modifier.weight(1f))
        Text(value, color = valueColor, style = MaterialTheme.typography.labelMedium)
        Icon(Icons.Default.ChevronRight, null, tint = WarmFgDisabled, modifier = Modifier.size(18.dp))
    }
}

@Composable
private fun ContextCard(label: String, count: Int, modifier: Modifier, onClick: () -> Unit) {
    Column(modifier.background(WarmBg850, RoundedCornerShape(8.dp)).clickable(onClick = onClick).padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Text("$count", color = AcOrange400, style = MaterialTheme.typography.headlineSmall)
        Text(label, color = WarmFgMuted, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun FlowRowCompat(actions: List<Pair<String, () -> Unit>>) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) { actions.forEach { (label, action) ->
        AssistChip(onClick = action, label = { Text(label) }, leadingIcon = { Icon(Icons.Default.FilterAlt, null, modifier = Modifier.size(16.dp)) })
    } }
}

@Composable
private fun ActionText(label: String, onClick: () -> Unit) = Text(label, color = AcOrange400,
    modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 4.dp))

@Composable
private fun StatsList(title: String, rows: List<Pair<String, String>>, filters: List<String>, onOpen: (String) -> Unit) {
    SectionCard(title) { rows.forEachIndexed { idx, row -> SummaryRow(row.first, row.second) { filters.getOrNull(idx)?.let(onOpen) } } }
}

@Composable
private fun BookmarkDialog(target: BookmarkTarget, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var note by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Bookmark ${target.type.name.lowercase()}") },
        text = { Column { Text(target.label); Spacer(Modifier.height(8.dp)); OutlinedTextField(note, { note = it }, label = { Text("Optional analyst note") }, minLines = 2) } },
        confirmButton = { TextButton(onClick = { onSave(note) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }, containerColor = WarmBg850)
}

private fun issueColor(severity: IssueSeverity): Color = when (severity) {
    IssueSeverity.INFO -> AcOrange400
    IssueSeverity.WARNING -> SemanticWarning
    IssueSeverity.ERROR -> SemanticError
}

private fun bytes(value: Long): String = when {
    value >= 1_000_000_000 -> "%.2f GB".format(value / 1_000_000_000.0)
    value >= 1_000_000 -> "%.2f MB".format(value / 1_000_000.0)
    value >= 1_000 -> "%.1f kB".format(value / 1_000.0)
    else -> "$value B"
}

private fun duration(seconds: Double): String = when {
    seconds >= 3600 -> "%dh %02dm %02ds".format((seconds / 3600).toInt(), ((seconds % 3600) / 60).toInt(), (seconds % 60).toInt())
    seconds >= 60 -> "%dm %02ds".format((seconds / 60).toInt(), (seconds % 60).toInt())
    else -> "%.3fs".format(seconds)
}

private fun epoch(value: Double?): String = value?.let { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(Date((it * 1000).toLong())) } ?: "Unavailable"
