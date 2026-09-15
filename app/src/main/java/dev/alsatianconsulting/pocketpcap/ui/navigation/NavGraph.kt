package dev.alsatianconsulting.pocketpcap.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.alsatianconsulting.pocketpcap.MainViewModel
import dev.alsatianconsulting.pocketpcap.ui.components.shareFile
import dev.alsatianconsulting.pocketpcap.ui.screens.CaptureFilesScreen
import dev.alsatianconsulting.pocketpcap.ui.screens.*
import dev.alsatianconsulting.pocketpcap.ui.theme.AcOrange500
import dev.alsatianconsulting.pocketpcap.ui.theme.WarmBg850
import dev.alsatianconsulting.pocketpcap.ui.theme.WarmBg900
import dev.alsatianconsulting.pocketpcap.ui.theme.WarmFgMuted

sealed class Screen(val route: String, val label: String, val icon: ImageVector) {
    object Sources  : Screen("sources",  "Sources",  Icons.Default.Router)
    object Capture  : Screen("capture",  "Capture",  Icons.Default.RadioButtonChecked)
    object Packets  : Screen("packets",  "Packets",  Icons.Default.ListAlt)
    object Files    : Screen("files",    "Files",    Icons.Default.FolderOpen)
    object Settings : Screen("settings", "Settings", Icons.Default.Settings)
}

private val topLevelScreens = listOf(
    Screen.Sources, Screen.Capture, Screen.Packets, Screen.Files, Screen.Settings
)

@Composable
fun AppNavGraph(viewModel: MainViewModel) {
    val navController = rememberNavController()

    val captureFiles     by viewModel.captureFiles.collectAsState()
    val interfaces       by viewModel.interfaces.collectAsState()
    val capabilities     by viewModel.capabilities.collectAsState()
    val rootAvailable    by viewModel.rootAvailable.collectAsState()
    val isRefreshing     by viewModel.isRefreshing.collectAsState()
    val session          by viewModel.session.collectAsState()
    val packets          by viewModel.packets.collectAsState()
    val selectedIndex    by viewModel.selectedPacketIndex.collectAsState()
    val filterText       by viewModel.displayFilter.collectAsState()
    val settings         by viewModel.settings.collectAsState()
    val decodeTree       by viewModel.selectedDecodeTree.collectAsState()
    val rawBytes         by viewModel.selectedRawBytes.collectAsState()
    val decodeLoading    by viewModel.decodeLoading.collectAsState()
    val viewingFileName  by viewModel.viewingFileName.collectAsState()
    val context = androidx.compose.ui.platform.LocalContext.current
    val filterError      by viewModel.filterError.collectAsState()
    val analysisError    by viewModel.analysisError.collectAsState()
    val following        by viewModel.followingFile.collectAsState()
    val followStream     by viewModel.followStream.collectAsState()
    val followLoading    by viewModel.followLoading.collectAsState()
    val outputDir        by viewModel.outputDir.collectAsState()
    val toolMessage      by viewModel.toolMessage.collectAsState()
    val suggestions      by viewModel.suggestions.collectAsState()
    val recentFilters    by viewModel.recentFilters.collectAsState()
    val savedFilters     by viewModel.savedFilters.collectAsState()
    val aliases          by viewModel.aliases.collectAsState()
    val resolveTick      by viewModel.resolveTick.collectAsState()
    val packetColumns    by viewModel.packetColumns.collectAsState()

    // One-shot tool messages (export/import results) surface as a toast.
    val ctx = androidx.compose.ui.platform.LocalContext.current
    LaunchedEffect(toolMessage) {
        toolMessage?.let {
            android.widget.Toast.makeText(ctx, it, android.widget.Toast.LENGTH_LONG).show()
            viewModel.clearToolMessage()
        }
    }

    Scaffold(
        containerColor = WarmBg900,
        bottomBar = {
            NavigationBar(containerColor = WarmBg850) {
                val currentEntry by navController.currentBackStackEntryAsState()
                val currentDest = currentEntry?.destination
                topLevelScreens.forEach { screen ->
                    NavigationBarItem(
                        selected = currentDest?.hierarchy?.any { it.route == screen.route } == true,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(screen.icon, screen.label) },
                        label = { Text(screen.label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor   = AcOrange500,
                            selectedTextColor   = AcOrange500,
                            indicatorColor      = AcOrange500.copy(alpha = 0.12f),
                            unselectedIconColor = WarmFgMuted,
                            unselectedTextColor = WarmFgMuted,
                        ),
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Sources.route,
            modifier = Modifier.padding(innerPadding),
        ) {
            composable(Screen.Sources.route) {
                val diagBusy by viewModel.diagnosticBusy.collectAsState()
                val diagMsg by viewModel.diagnosticMessage.collectAsState()
                CapabilityScreen(
                    interfaces    = interfaces,
                    capabilities  = capabilities,
                    rootAvailable = rootAvailable,
                    isRefreshing  = isRefreshing,
                    onRefresh     = { viewModel.refresh(probeRoot = true) },
                    diagnosticBusy = diagBusy,
                    diagnosticMessage = diagMsg,
                    onEnableHciSnoop = { viewModel.enableBluetoothHciSnoop() },
                    onCollectHci = { viewModel.collectBluetoothHci() },
                    onCollectRil = { viewModel.collectRilLogs() },
                    onClearDiagnosticMessage = { viewModel.clearDiagnosticMessage() },
                )
            }
            composable(Screen.Capture.route) {
                CaptureScreen(
                    interfaces = interfaces,
                    session    = session,
                    onStart    = { ifaces, filter -> viewModel.startCapture(ifaces, filter) },
                    onStartRootless = { filter -> viewModel.startRootlessVpnCapture(filter) },
                    onPause    = { viewModel.pauseCapture() },
                    onResume   = { viewModel.resumeCapture() },
                    onStop     = { viewModel.stopCapture() },
                )
            }
            composable(Screen.Packets.route) {
                val selectedPacket = selectedIndex?.let { packets.getOrNull(it) }
                when {
                    followStream != null || followLoading -> FollowStreamScreen(
                        stream  = followStream,
                        loading = followLoading,
                        onBack  = { viewModel.closeFollowStream() },
                        onShowPackets = { expr ->
                            viewModel.closeFollowStream()
                            viewModel.applyFilterExpr(expr)
                        },
                        onBookmark = { stream ->
                            val proto = if (stream.protocol.equals("UDP", true)) "udp" else "tcp"
                            viewModel.addAnalysisBookmark(
                                dev.alsatianconsulting.pocketpcap.analysis.BookmarkType.STREAM,
                                "$proto:${stream.streamIndex}",
                                "${stream.protocol} stream ${stream.streamIndex}",
                                "", "$proto.stream == ${stream.streamIndex}", null,
                            )
                        },
                    )
                    selectedPacket != null -> PacketDetailScreen(
                        packet     = selectedPacket,
                        decodeTree = decodeTree,
                        rawBytes   = rawBytes,
                        isLoading  = decodeLoading,
                        onBack     = { viewModel.clearSelectedPacket() },
                        onApplyFilter = { field, value, submit -> viewModel.applyFieldFilter(field, value, submit) },
                        onExcludeValue = { field, value -> viewModel.excludeFieldValue(field, value) },
                        onSearchValue = { value ->
                            viewModel.searchCapture(value)
                            viewModel.clearSelectedPacket()
                            navController.navigate("analysis")
                        },
                        onAddColumn = { viewModel.addPacketListColumn(it) },
                    )
                    else -> PacketListScreen(
                        packets           = packets,
                        selectedIndex     = selectedIndex,
                        captureStartTime  = session?.startTime?.times(1000L),
                        filterText        = filterText,
                        viewingFileName   = viewingFileName,
                        filterError       = filterError,
                        // A file is open but nothing decoded: the packet list explains why
                        // rather than claiming nothing was captured.
                        emptyReason      = if (viewingFileName != null) analysisError else null,
                        suggestions       = suggestions,
                        recentFilters     = recentFilters.map { it.filter },
                        savedFilters      = savedFilters,
                        packetColumns     = packetColumns,
                        resolveTick       = resolveTick,
                        labelFor          = { viewModel.labelFor(it) },
                        nameFor           = { viewModel.nameFor(it) },
                        aliasFor          = { viewModel.aliasFor(it) },
                        onFilterChange    = { viewModel.setDisplayFilter(it) },
                        onFilterSubmit    = { viewModel.submitDisplayFilter() },
                        onPickSuggestion  = { viewModel.pickSuggestion(it) },
                        onSaveFilter      = { viewModel.saveCurrentFilter(it) },
                        onDeleteSaved     = { viewModel.deleteSavedFilter(it) },
                        onClearRecents    = { viewModel.clearRecentFilters() },
                        onPacketSelected  = { viewModel.selectPacket(it) },
                        onCloseFile       = { viewModel.closeViewedFile() },
                        onReloadFile      = { viewModel.reloadViewedFile() },
                        following         = following,
                        onFollowChange    = { viewModel.setFollowingFile(it) },
                        onExportTable     = { table, asJson ->
                            viewModel.exportAnalysisTable(table, asJson) { f ->
                                shareFile(context, f.absolutePath)
                            }
                        },
                        onExportSanitised = {
                            viewModel.exportSanitised { f -> shareFile(context, f.absolutePath) }
                        },
                        onExportWithNotes = {
                            viewModel.exportWithNotes { f -> shareFile(context, f.absolutePath) }
                        },
                        onOpenAnalysis    = {
                            viewModel.loadAnalysis()
                            navController.navigate("analysis")
                        },
                        onExportFiltered  = { viewModel.exportFilteredSelection() },
                        onOpenObjects     = { navController.navigate("objects") },
                        onOpenTrafficMap  = {
                            viewModel.loadTrafficMap()
                            navController.navigate("trafficMap")
                        },
                        onFollowStream    = { idx, proto -> viewModel.followStreamForPacket(idx, proto) },
                        onApplyFilter     = { expr -> viewModel.applyFilterExpr(expr) },
                        onSetAlias        = { addr, name -> viewModel.setAlias(addr, name) },
                        onRemoveAlias     = { viewModel.removeAlias(it) },
                        onLookupLocation  = { addr ->
                            viewModel.lookupEndpointLocation(addr); navController.navigate("location")
                        },
                        onRequestStreamOptions = { idx, cb -> viewModel.streamOptionsForPacket(idx, cb) },
                        onRemoveColumn    = { viewModel.removePacketListColumn(it) },
                        onBookmarkPacket  = { packet ->
                            viewModel.addAnalysisBookmark(
                                dev.alsatianconsulting.pocketpcap.analysis.BookmarkType.PACKET,
                                packet.number.toString(), "Packet #${packet.number} ${packet.protocol}",
                                "", "frame.number == ${packet.number}", packet.number,
                            )
                        },
                    )
                }
            }
            composable(Screen.Files.route) {
                val diagnosticLogs by viewModel.diagnosticLogs.collectAsState()
                val viewingLogName by viewModel.viewingLogName.collectAsState()
                val viewingLogText by viewModel.viewingLogText.collectAsState()
                val rilEntries by viewModel.rilEntries.collectAsState()
                CaptureFilesScreen(
                    files     = captureFiles,
                    onRefresh = { viewModel.refreshCaptureFiles() },
                    onDelete  = { viewModel.deleteCaptureFile(it) },
                    onOpen    = { file ->
                        viewModel.openCaptureFile(file)
                        navController.navigate("analysis") {
                            popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                            launchSingleTop = true
                        }
                    },
                    diagnosticLogs = diagnosticLogs,
                    onRefreshLogs  = { viewModel.refreshDiagnosticLogs() },
                    onOpenLog      = { viewModel.openDiagnosticLog(it) },
                    onDeleteLog    = { viewModel.deleteDiagnosticLog(it) },
                    viewingLogName = viewingLogName,
                    viewingLogText = viewingLogText,
                    rilEntries     = rilEntries,
                    onCloseLog     = { viewModel.closeDiagnosticLog() },
                    onImportFile   = { uri ->
                        viewModel.importPcap(uri) {
                            navController.navigate("analysis") {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                            }
                        }
                    },
                    onMerge        = { viewModel.mergeCaptures(it) },
                )
            }
            composable(Screen.Settings.route) {
                val decryption by viewModel.decryption.collectAsState()
                val geoIpInfo by viewModel.geoIpDatabaseInfo.collectAsState()
                SettingsScreen(
                    settings           = settings,
                    captureDir         = outputDir,
                    onSettingsChange   = { viewModel.updateSettings(it) },
                    decryption         = decryption,
                    geoIpInfo          = geoIpInfo,
                    onImportKeylog     = { viewModel.importTlsKeylog(it) },
                    onClearKeylog      = { viewModel.clearTlsKeylog() },
                    onTlsEnabledChange = { viewModel.setTlsEnabled(it) },
                    onAddWifiKey       = { type, raw -> viewModel.addWifiKey(type, raw) },
                    onRemoveWifiKey    = { viewModel.removeWifiKey(it) },
                    onWifiEnabledChange = { viewModel.setWifiEnabled(it) },
                    onChooseOutputDir  = { viewModel.setOutputDir(it) },
                    onResetOutputDir   = { viewModel.resetOutputDir() },
                    onImportGeoIp      = { viewModel.importGeoIpDatabase(it) },
                    onClearGeoIp       = { viewModel.clearGeoIpDatabase() },
                    onOpenHelp         = { navController.navigate("help") },
                    onOpenLicenses     = { navController.navigate("licenses") },
                    onOpenAliases      = { navController.navigate("aliases") },
                )
            }
            composable("aliases") {
                AliasScreen(
                    aliases = aliases,
                    onSetAlias = { addr, name -> viewModel.setAlias(addr, name) },
                    onRemoveAlias = { viewModel.removeAlias(it) },
                    onBack = { navController.popBackStack() },
                )
            }
            composable("analysis") {
                val analysis by viewModel.captureAnalysis.collectAsState()
                val analysisLoading by viewModel.analysisLoading.collectAsState()
                val searchResults by viewModel.searchResults.collectAsState()
                val bookmarks by viewModel.bookmarks.collectAsState()
                AnalysisWorkspaceScreen(
                    analysis = analysis,
                    loading = analysisLoading,
                    error = analysisError,
                    searchResults = searchResults,
                    bookmarks = bookmarks,
                    resolveTick = resolveTick,
                    labelFor = { viewModel.labelFor(it) },
                    onSearch = { viewModel.searchCapture(it) },
                    onOpenPackets = { expr ->
                        viewModel.applyFilterExpr(expr)
                        navController.navigate(Screen.Packets.route) { launchSingleTop = true }
                    },
                    onApplyConversationFilter = { expr -> viewModel.applyFilterExpr(expr) },
                    onFollowStream = { protocol, index ->
                        viewModel.followStreamByIndex(protocol, index)
                        navController.navigate(Screen.Packets.route) { launchSingleTop = true }
                    },
                    onOpenObjects = { navController.navigate("objects") },
                    onApplyTimeRange = { start, end ->
                        viewModel.applyTimeRange(start, end)
                        navController.navigate(Screen.Packets.route) { launchSingleTop = true }
                    },
                    onBookmark = { type, id, label, note, filter, packet ->
                        viewModel.addAnalysisBookmark(type, id, label, note, filter, packet)
                    },
                    onUpdateBookmark = { id, note -> viewModel.updateBookmarkNote(id, note) },
                    onDeleteBookmark = { viewModel.deleteBookmark(it) },
                )
            }
            composable("trafficMap") {
                val trafficMap by viewModel.trafficMap.collectAsState()
                TrafficMapScreen(
                    state = trafficMap,
                    onApplyFilter = { expr ->
                        viewModel.applyFilterExpr(expr)
                        navController.popBackStack(Screen.Packets.route, inclusive = false)
                    },
                    onBack = {
                        viewModel.clearTrafficMap()
                        navController.popBackStack()
                    },
                    onExportMap = { asKml ->
                        viewModel.exportTrafficMap(asKml) { f -> shareFile(context, f.absolutePath) }
                    },
                )
            }
            composable("objects") {
                val objects by viewModel.exportedObjects.collectAsState()
                val objectsLoading by viewModel.objectsLoading.collectAsState()
                var selectedType by remember { mutableStateOf("") }
                ObjectsScreen(
                    objects = objects,
                    loading = objectsLoading,
                    selectedType = selectedType,
                    onTypeSelected = { selectedType = it; viewModel.exportObjects(it) },
                    onBack = { viewModel.clearExportedObjects(); navController.popBackStack() },
                )
            }
            composable("help") {
                HelpScreen(onBack = { navController.popBackStack() })
            }
            composable("licenses") {
                LicensesScreen(onBack = { navController.popBackStack() })
            }
            composable("location") {
                val location by viewModel.endpointLocation.collectAsState()
                val locationLoading by viewModel.locationLoading.collectAsState()
                EndpointLocationScreen(
                    location = location,
                    loading = locationLoading,
                    onBack = { viewModel.clearEndpointLocation(); navController.popBackStack() },
                )
            }
        }
    }
}
