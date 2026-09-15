package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.filter.FilterBuilders
import dev.alsatianconsulting.pocketpcap.model.TrafficMapRoute
import dev.alsatianconsulting.pocketpcap.model.TrafficMapState
import dev.alsatianconsulting.pocketpcap.ui.components.Eyebrow
import dev.alsatianconsulting.pocketpcap.ui.components.PcapCard
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import kotlin.math.max
import kotlin.math.pow
import kotlin.math.sqrt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrafficMapScreen(
    state: TrafficMapState,
    onApplyFilter: (String) -> Unit,
    onBack: () -> Unit,
    onExportMap: (asKml: Boolean) -> Unit = {},
) {
    var exportOpen by remember { mutableStateOf(false) }
    var selected by remember(state.routes) { mutableStateOf<TrafficMapRoute?>(state.routes.firstOrNull()) }

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
                        Eyebrow("GeoIP")
                        Text("Traffic map", style = MaterialTheme.typography.headlineMedium, color = WarmFgPrimary)
                    }
                },
                actions = {
                    if (state.routes.isNotEmpty()) {
                        Box {
                            IconButton(onClick = { exportOpen = true }) {
                                Icon(Icons.Default.Share, "Export map", tint = AcOrange500)
                            }
                            DropdownMenu(
                                expanded = exportOpen,
                                onDismissRequest = { exportOpen = false },
                                containerColor = WarmBg800,
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Export as KML", color = WarmFgPrimary) },
                                    onClick = { exportOpen = false; onExportMap(true) },
                                )
                                DropdownMenuItem(
                                    text = { Text("Export as GeoJSON", color = WarmFgPrimary) },
                                    onClick = { exportOpen = false; onExportMap(false) },
                                )
                            }
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when {
                state.loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = AcOrange500)
                }
                state.error != null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(state.error, style = MaterialTheme.typography.bodyMedium, color = WarmFgMuted)
                }
                else -> {
                    RouteMap(
                        state = state,
                        selected = selected,
                        onSelect = { selected = it },
                        modifier = Modifier.fillMaxWidth().height(310.dp),
                    )
                    selected?.let { route ->
                        RouteDetail(route, onApplyFilter)
                    }
                    RouteList(state.routes, selected, onSelect = { selected = it })
                }
            }
        }
    }
}

@Composable
private fun RouteMap(
    state: TrafficMapState,
    selected: TrafficMapRoute?,
    onSelect: (TrafficMapRoute) -> Unit,
    modifier: Modifier = Modifier,
) {
    var canvasPx by remember { mutableStateOf(IntSize.Zero) }
    val source = remember(state, canvasPx) {
        val w = max(1, canvasPx.width).toFloat()
        val h = max(1, canvasPx.height).toFloat()
        val lat = state.sourceLatitude
        val lon = state.sourceLongitude
        if (lat != null && lon != null) project(lat, lon, w, h) else Offset(w * 0.18f, h * 0.52f)
    }

    PcapCard {
        Canvas(
            modifier
                .background(WarmBg850)
                .onSizeChanged { canvasPx = it }
                .pointerInput(state.routes, canvasPx) {
                    detectTapGestures { tap ->
                        val w = max(1, canvasPx.width).toFloat()
                        val h = max(1, canvasPx.height).toFloat()
                        val hit = state.routes.minByOrNull { route ->
                            val dst = project(route.latitude, route.longitude, w, h)
                            minOf(distance(tap, dst), distanceToSegment(tap, source, dst))
                        }
                        if (hit != null) onSelect(hit)
                    }
                }
                .padding(8.dp),
        ) {
            val grid = WarmFgDisabled.copy(alpha = 0.16f)
            val dash = PathEffect.dashPathEffect(floatArrayOf(8f, 10f), 0f)
            for (i in 1 until 6) {
                val x = size.width * i / 6f
                drawLine(grid, Offset(x, 0f), Offset(x, size.height), pathEffect = dash)
            }
            for (i in 1 until 4) {
                val y = size.height * i / 4f
                drawLine(grid, Offset(0f, y), Offset(size.width, y), pathEffect = dash)
            }
            drawCircle(AcOrange500, radius = 9f, center = source)
            state.routes.forEach { route ->
                val dst = project(route.latitude, route.longitude, size.width, size.height)
                val isSelected = route.address == selected?.address
                val width = if (isSelected) 5f else 2.5f
                val alpha = if (isSelected) 0.95f else 0.45f
                drawLine(AcOrange500.copy(alpha = alpha), source, dst, strokeWidth = width)
                drawCircle(
                    color = if (isSelected) SemanticSuccess else WarmFgMuted,
                    radius = if (isSelected) 8f else 5f,
                    center = dst,
                )
            }
        }
    }
}

@Composable
private fun RouteDetail(route: TrafficMapRoute, onApplyFilter: (String) -> Unit) {
    PcapCard {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Eyebrow(route.trafficType)
            Text(route.label, style = MaterialTheme.typography.titleMedium, color = WarmFgPrimary)
            Text(locationText(route), style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
            Text(
                "${route.packets} packets / ${formatBytesShort(route.bytes)}   " +
                    "↑ ${route.txPackets}/${formatBytesShort(route.txBytes)}   " +
                    "↓ ${route.rxPackets}/${formatBytesShort(route.rxBytes)}",
                style = MaterialTheme.typography.labelMedium,
                color = AcOrange400,
            )
            Button(
                onClick = {
                    onApplyFilter(FilterBuilders.endpointFilter(route.address, FilterBuilders.EndpointAction.ALL))
                },
                colors = ButtonDefaults.buttonColors(containerColor = AcOrange500, contentColor = WarmBg900),
            ) {
                Icon(Icons.Default.FilterAlt, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Show packets")
            }
        }
    }
}

@Composable
private fun RouteList(
    routes: List<TrafficMapRoute>,
    selected: TrafficMapRoute?,
    onSelect: (TrafficMapRoute) -> Unit,
) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        items(routes) { route ->
            val active = route.address == selected?.address
            PcapCard {
                Row(
                    Modifier.fillMaxWidth().clickable { onSelect(route) }.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(route.label, style = MaterialTheme.typography.bodyMedium, color = WarmFgPrimary, maxLines = 1)
                        Text(locationText(route), style = MaterialTheme.typography.labelSmall, color = WarmFgMuted, maxLines = 1)
                    }
                    Text(
                        formatBytesShort(route.bytes),
                        style = MaterialTheme.typography.labelMedium,
                        color = if (active) AcOrange400 else WarmFgMuted,
                    )
                }
            }
        }
    }
}

private fun project(lat: Double, lon: Double, width: Float, height: Float): Offset {
    val x = ((lon + 180.0) / 360.0).toFloat() * width
    val y = ((90.0 - lat) / 180.0).toFloat() * height
    return Offset(x.coerceIn(0f, width), y.coerceIn(0f, height))
}

private fun distance(a: Offset, b: Offset): Float =
    sqrt((a.x - b.x).pow(2) + (a.y - b.y).pow(2))

private fun distanceToSegment(p: Offset, a: Offset, b: Offset): Float {
    val dx = b.x - a.x
    val dy = b.y - a.y
    if (dx == 0f && dy == 0f) return distance(p, a)
    val t = (((p.x - a.x) * dx + (p.y - a.y) * dy) / (dx * dx + dy * dy)).coerceIn(0f, 1f)
    return distance(p, Offset(a.x + t * dx, a.y + t * dy))
}

private fun locationText(route: TrafficMapRoute): String =
    listOfNotNull(route.city, route.region, route.country).joinToString(", ").ifBlank { route.address }

private fun formatBytesShort(bytes: Long): String {
    if (bytes < 1024) return "${bytes}B"
    var v = bytes.toDouble()
    val units = listOf("KB", "MB", "GB")
    var i = -1
    while (v >= 1024 && i < units.lastIndex) {
        v /= 1024
        i++
    }
    return "%.1f%s".format(v, units[i])
}
