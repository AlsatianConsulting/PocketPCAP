package dev.alsatianconsulting.pocketpcap

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.alsatianconsulting.pocketpcap.capture.CaptureManager
import dev.alsatianconsulting.pocketpcap.capture.RootlessCaptureStore
import dev.alsatianconsulting.pocketpcap.analysis.BookmarkType
import dev.alsatianconsulting.pocketpcap.analysis.AnalysisExport
import dev.alsatianconsulting.pocketpcap.analysis.CaptureAnalysis
import dev.alsatianconsulting.pocketpcap.analysis.CaptureSearch
import dev.alsatianconsulting.pocketpcap.analysis.CaptureSearchResult
import dev.alsatianconsulting.pocketpcap.decode.DecodeManager
import dev.alsatianconsulting.pocketpcap.decode.WifiKey
import dev.alsatianconsulting.pocketpcap.decode.WifiKeyType
import dev.alsatianconsulting.pocketpcap.model.*
import dev.alsatianconsulting.pocketpcap.service.CaptureService
import dev.alsatianconsulting.pocketpcap.service.VpnCaptureService
import dev.alsatianconsulting.pocketpcap.source.SourceManager
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore
import dev.alsatianconsulting.pocketpcap.data.PcapRepository
import dev.alsatianconsulting.pocketpcap.data.SavedFilterEntity
import dev.alsatianconsulting.pocketpcap.data.RecentFilterEntity
import dev.alsatianconsulting.pocketpcap.data.EndpointAliasEntity
import dev.alsatianconsulting.pocketpcap.data.AnalysisBookmarkEntity
import dev.alsatianconsulting.pocketpcap.filter.FilterSuggestion
import dev.alsatianconsulting.pocketpcap.filter.FilterSuggestionEngine
import dev.alsatianconsulting.pocketpcap.filter.SuggestionContext
import dev.alsatianconsulting.pocketpcap.resolve.AddressUtil
import dev.alsatianconsulting.pocketpcap.resolve.EndpointLabel
import dev.alsatianconsulting.pocketpcap.resolve.EndpointLocation
import dev.alsatianconsulting.pocketpcap.resolve.GeoIpDatabaseInfo
import dev.alsatianconsulting.pocketpcap.resolve.GeoIpManager
import dev.alsatianconsulting.pocketpcap.resolve.LocationLookup
import dev.alsatianconsulting.pocketpcap.resolve.NameFormat
import dev.alsatianconsulting.pocketpcap.resolve.NameResolver
import dev.alsatianconsulting.pocketpcap.resolve.ResolveDisplayMode
import dev.alsatianconsulting.pocketpcap.ui.screens.AppSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class DecryptionUiState(
    val tlsPresent: Boolean = false,
    val tlsEnabled: Boolean = false,
    val tlsLines: Int = 0,
    val wifiKeys: List<WifiKey> = emptyList(),
    val wifiEnabled: Boolean = false,
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val sourceManager = SourceManager(application)

    val interfaces: StateFlow<List<NetworkInterface>> = sourceManager.interfaces
    val capabilities: StateFlow<List<CapabilityStatus>> = sourceManager.capabilities
    val rootAvailable: StateFlow<Boolean?> = sourceManager.rootAvailable

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing

    // Capture state — sourced from bound service when available, else null
    private val _session = MutableStateFlow<CaptureSession?>(null)
    val session: StateFlow<CaptureSession?> = _session

    private val _packets = MutableStateFlow<List<PacketSummary>>(emptyList())
    val packets: StateFlow<List<PacketSummary>> = _packets

    private val _selectedPacketIndex = MutableStateFlow<Int?>(null)
    val selectedPacketIndex: StateFlow<Int?> = _selectedPacketIndex

    private val _displayFilter = MutableStateFlow("")
    val displayFilter: StateFlow<String> = _displayFilter

    private val _captureFiles = MutableStateFlow<List<dev.alsatianconsulting.pocketpcap.model.CaptureFile>>(emptyList())
    val captureFiles: StateFlow<List<dev.alsatianconsulting.pocketpcap.model.CaptureFile>> = _captureFiles

    private val _settings = MutableStateFlow(AppSettings())
    val settings: StateFlow<AppSettings> = _settings

    private val _decryption = MutableStateFlow(DecryptionUiState())
    val decryption: StateFlow<DecryptionUiState> = _decryption


    // Raw diagnostic logs (RIL/modem) and one-shot collection feedback.
    private val _diagnosticLogs = MutableStateFlow<List<dev.alsatianconsulting.pocketpcap.model.DiagnosticLog>>(emptyList())
    val diagnosticLogs: StateFlow<List<dev.alsatianconsulting.pocketpcap.model.DiagnosticLog>> = _diagnosticLogs

    private val _diagnosticMessage = MutableStateFlow<String?>(null)
    val diagnosticMessage: StateFlow<String?> = _diagnosticMessage

    private val _diagnosticBusy = MutableStateFlow(false)
    val diagnosticBusy: StateFlow<Boolean> = _diagnosticBusy

    private val _viewingLogName = MutableStateFlow<String?>(null)
    val viewingLogName: StateFlow<String?> = _viewingLogName
    private val _viewingLogText = MutableStateFlow<String?>(null)
    val viewingLogText: StateFlow<String?> = _viewingLogText

    // Decode state for the currently selected packet.
    private val _selectedDecodeTree = MutableStateFlow<DecodeTree?>(null)
    val selectedDecodeTree: StateFlow<DecodeTree?> = _selectedDecodeTree

    private val _selectedRawBytes = MutableStateFlow<RawBytes?>(null)
    val selectedRawBytes: StateFlow<RawBytes?> = _selectedRawBytes

    private val _decodeLoading = MutableStateFlow(false)
    val decodeLoading: StateFlow<Boolean> = _decodeLoading
    private val _packetColumns = MutableStateFlow<List<DynamicPacketColumn>>(emptyList())
    val packetColumns: StateFlow<List<DynamicPacketColumn>> = _packetColumns

    // File whose packets are currently shown; null means the live capture file.
    private val _viewingFileName = MutableStateFlow<String?>(null)
    val viewingFileName: StateFlow<String?> = _viewingFileName
    private var viewingFile: File? = null

    // When a tshark display filter is applied, the live stream stops overwriting the list.
    @Volatile private var filterActive = false
    private val _filterError = MutableStateFlow<String?>(null)
    val filterError: StateFlow<String?> = _filterError

    private var captureService: CaptureService? = null
    private var decodeManager: DecodeManager? = null

    private val prefs = dev.alsatianconsulting.pocketpcap.decode.Prefs(application)

    // --- Persistence + name resolution + suggestions -------------------------
    private val repo = PcapRepository(application)
    private val nameResolver = NameResolver(application, repo)
    private val geoIpManager = GeoIpManager(application)
    private val suggestionEngine = FilterSuggestionEngine()

    val aliases: StateFlow<List<EndpointAliasEntity>> =
        repo.aliases.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val recentFilters: StateFlow<List<RecentFilterEntity>> =
        repo.recentFilters.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val savedFilters: StateFlow<List<SavedFilterEntity>> =
        repo.savedFilters.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _suggestions = MutableStateFlow<List<FilterSuggestion>>(emptyList())
    val suggestions: StateFlow<List<FilterSuggestion>> = _suggestions

    // Bumped whenever a background resolution pass populates new names, so endpoint
    // labels in the UI recompose against the resolver's caches.
    private val _resolveTick = MutableStateFlow(0)
    val resolveTick: StateFlow<Int> = _resolveTick

    // Cached available stream indices for the current capture (autocomplete).
    @Volatile private var tcpStreamSet: Set<Int> = emptySet()
    @Volatile private var udpStreamSet: Set<Int> = emptySet()

    // --- Endpoint location (online GeoIP + WHOIS/RDAP) -----------------------
    private val _endpointLocation = MutableStateFlow<EndpointLocation?>(null)
    val endpointLocation: StateFlow<EndpointLocation?> = _endpointLocation
    private val _locationLoading = MutableStateFlow(false)
    val locationLoading: StateFlow<Boolean> = _locationLoading
    private val locationCache = java.util.concurrent.ConcurrentHashMap<String, EndpointLocation>()
    private val _geoIpDatabaseInfo = MutableStateFlow(GeoIpDatabaseInfo())
    val geoIpDatabaseInfo: StateFlow<GeoIpDatabaseInfo> = _geoIpDatabaseInfo

    // --- Analysis: protocol hierarchy + endpoints ----------------------------
    private val _protoHierarchy = MutableStateFlow<List<dev.alsatianconsulting.pocketpcap.model.ProtoHierarchyNode>>(emptyList())
    private val _endpoints = MutableStateFlow<List<dev.alsatianconsulting.pocketpcap.model.Endpoint>>(emptyList())
    val endpoints: StateFlow<List<dev.alsatianconsulting.pocketpcap.model.Endpoint>> = _endpoints
    private val _endpointType = MutableStateFlow("ip")
    val endpointType: StateFlow<String> = _endpointType
    private val _analysisLoading = MutableStateFlow(false)
    val analysisLoading: StateFlow<Boolean> = _analysisLoading
    private val _captureAnalysis = MutableStateFlow(CaptureAnalysis.EMPTY)
    val captureAnalysis: StateFlow<CaptureAnalysis> = _captureAnalysis
    private val _analysisError = MutableStateFlow<String?>(null)
    val analysisError: StateFlow<String?> = _analysisError
    private val _searchResults = MutableStateFlow<List<CaptureSearchResult>>(emptyList())
    val searchResults: StateFlow<List<CaptureSearchResult>> = _searchResults
    private var captureSearchJob: kotlinx.coroutines.Job? = null
    private val _bookmarks = MutableStateFlow<List<AnalysisBookmarkEntity>>(emptyList())
    val bookmarks: StateFlow<List<AnalysisBookmarkEntity>> = _bookmarks
    private val _trafficMap = MutableStateFlow(TrafficMapState())
    val trafficMap: StateFlow<TrafficMapState> = _trafficMap

    // --- Follow stream --------------------------------------------------------
    private val _followStream = MutableStateFlow<dev.alsatianconsulting.pocketpcap.model.FollowStream?>(null)
    val followStream: StateFlow<dev.alsatianconsulting.pocketpcap.model.FollowStream?> = _followStream
    private val _followLoading = MutableStateFlow(false)
    val followLoading: StateFlow<Boolean> = _followLoading

    // --- Export objects -------------------------------------------------------
    private val _exportedObjects = MutableStateFlow<List<dev.alsatianconsulting.pocketpcap.model.ExportedObject>>(emptyList())
    val exportedObjects: StateFlow<List<dev.alsatianconsulting.pocketpcap.model.ExportedObject>> = _exportedObjects
    private val _objectsLoading = MutableStateFlow(false)
    val objectsLoading: StateFlow<Boolean> = _objectsLoading

    // --- Parsed RIL entries (for the structured radio-log viewer) -------------
    private val _rilEntries = MutableStateFlow<List<dev.alsatianconsulting.pocketpcap.model.RilLogEntry>>(emptyList())
    val rilEntries: StateFlow<List<dev.alsatianconsulting.pocketpcap.model.RilLogEntry>> = _rilEntries

    // One-shot user-facing messages for export / import actions.
    private val _toolMessage = MutableStateFlow<String?>(null)
    val toolMessage: StateFlow<String?> = _toolMessage

    // Persisted output directory (where new captures are written).
    private val _onlineLookups = MutableStateFlow(prefs.onlineLookupsEnabled)
    val onlineLookups: StateFlow<Boolean> = _onlineLookups

    /**
     * Turn third-party GeoIP/RDAP lookups on or off. Enabling re-runs whatever the user
     * was looking at, so the choice takes effect where they made it.
     */
    fun setOnlineLookups(enabled: Boolean) {
        prefs.onlineLookupsEnabled = enabled
        _onlineLookups.value = enabled
        if (enabled) {
            locationCache.clear()
            if (_trafficMap.value.consentRequired) loadTrafficMap()
        }
    }

    private val _outputDir = MutableStateFlow(prefs.outputDir)
    val outputDir: StateFlow<String> = _outputDir

    val captureDir: String
        get() = _outputDir.value

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val svc = (binder as CaptureService.LocalBinder).service
            captureService = svc
            decodeManager = svc.decodeManager
            viewModelScope.launch {
                svc.captureManager.session.collect { s -> _session.value = s }
            }
            viewModelScope.launch {
                // Live capture packets feed the list unless the user is viewing a saved
                // file or has an active tshark display filter applied.
                svc.captureManager.packets.collect { live ->
                    if (viewingFile == null && !filterActive) _packets.value = live
                }
            }
            viewModelScope.launch {
            }
            // Extract the tshark bundle in the background on first run.
            viewModelScope.launch(Dispatchers.IO) { svc.decodeManager.ensureReady() }
            refreshDecryptionState()
        }
        override fun onServiceDisconnected(name: ComponentName) {
            captureService = null
            decodeManager = null
        }
    }

    init {
        // Restore persisted display/resolution preferences.
        _settings.value = _settings.value.copy(
            resolveHostnames = prefs.resolveHostnames,
            maxCaptureSizeMb = prefs.maxCaptureMb,
            maxCaptureMinutes = prefs.maxCaptureMinutes,
            displayMode = runCatching { ResolveDisplayMode.valueOf(prefs.displayMode) }
                .getOrDefault(ResolveDisplayMode.ADDRESS),
        )
        nameResolver.setResolveHostnames(prefs.resolveHostnames)
        if (prefs.resolveHostnames) nameResolver.startDiscovery()
        viewModelScope.launch(Dispatchers.IO) {
            nameResolver.prewarm()
            nameResolver.refreshAliases()
            _geoIpDatabaseInfo.value = geoIpManager.load()
            bumpResolve()
        }
        viewModelScope.launch {
            RootlessCaptureStore.session.collect { s ->
                val currentIsRootless = _session.value?.interfaceName?.startsWith("Rootless VPN") == true
                if (s != null || currentIsRootless) _session.value = s
            }
        }
        viewModelScope.launch {
            RootlessCaptureStore.packets.collect { live ->
                val currentIsRootless = _session.value?.interfaceName?.startsWith("Rootless VPN") == true
                if (currentIsRootless && viewingFile == null && !filterActive) _packets.value = live
            }
        }
        refresh(probeRoot = false)
        bindService()
    }

    private fun bumpResolve() { _resolveTick.value = _resolveTick.value + 1 }

    fun refresh(probeRoot: Boolean = true) {
        viewModelScope.launch {
            _isRefreshing.value = true
            sourceManager.refresh(probeRoot = probeRoot)
            _isRefreshing.value = false
        }
    }

    fun startCapture(iface: String, filter: String) = startCapture(listOf(iface), filter)

    /** Start a capture across one or more interfaces simultaneously. */
    fun startCapture(ifaces: List<String>, filter: String) {
        val svc = captureService ?: return
        stopRootlessVpn()
        startCaptureForeground()
        // Switch the packet list back to the live source.
        viewingFile = null
        _viewingFileName.value = null
        filterActive = false
        _displayFilter.value = ""
        _filterError.value = null
        _packets.value = emptyList()
        _packetColumns.value = emptyList()
        clearSelectedPacket()
        svc.captureManager.start(ifaces, filter)
    }

    /**
     * Start a rootless VPN capture scoped to zero or more packages.
     *
     * The tunnel is always device-wide apart from PocketPCAP itself. Scoping it to
     * chosen packages needed QUERY_ALL_PACKAGES to populate a picker, which is a Play
     * restricted permission with no use case covering network analysis, so the feature
     * was dropped rather than shipped behind a declaration unlikely to be approved.
     */
    fun startRootlessVpnCapture(filter: String) {
        // No CaptureService foreground here: the rootless path runs in
        // VpnCaptureService. Starting both was why two ongoing notifications appeared
        // for one capture, one of them from a service that was doing nothing.
        captureService?.captureManager?.stop()
        viewingFile = null
        _viewingFileName.value = null
        filterActive = false
        _displayFilter.value = ""
        _filterError.value = null
        _packets.value = emptyList()
        clearSelectedPacket()
        val intent = Intent(getApplication(), VpnCaptureService::class.java).apply {
            action = VpnCaptureService.ACTION_START
            putExtra(VpnCaptureService.EXTRA_FILTER, filter)
        }
        getApplication<Application>().startForegroundService(intent)
    }


    fun pauseCapture()  {
        if (isRootlessActive()) sendVpnAction(VpnCaptureService.ACTION_PAUSE)
        else captureService?.captureManager?.pause()
    }

    fun resumeCapture() {
        if (isRootlessActive()) sendVpnAction(VpnCaptureService.ACTION_RESUME)
        else captureService?.captureManager?.resume()
    }

    fun stopCapture() {
        if (isRootlessActive()) stopRootlessVpn()
        else captureService?.captureManager?.stop()
    }

    private fun isRootlessActive(): Boolean =
        _session.value?.interfaceName?.startsWith("Rootless VPN") == true

    private fun stopRootlessVpn() = sendVpnAction(VpnCaptureService.ACTION_STOP)

    private fun sendVpnAction(action: String) {
        getApplication<Application>().startService(
            Intent(getApplication(), VpnCaptureService::class.java).apply {
                this.action = action
            }
        )
    }

    /** The capture file backing the currently displayed packets. */
    private fun activeDecodeFile(): File? =
        viewingFile ?: _session.value?.outputPath?.let { File(it) }

    fun selectPacket(idx: Int) {
        _selectedPacketIndex.value = idx
        val packet = _packets.value.getOrNull(idx) ?: return
        val file = activeDecodeFile() ?: return
        val dm = decodeManager ?: return
        _selectedDecodeTree.value = null
        _selectedRawBytes.value = null
        _decodeLoading.value = true
        viewModelScope.launch(Dispatchers.IO) {
            val tree = dm.decodeTree(file, packet.number)
            val raw = dm.rawBytes(file, packet.number)
            _selectedDecodeTree.value = tree
            _selectedRawBytes.value = raw
            _decodeLoading.value = false
        }
    }

    fun clearSelectedPacket() {
        _selectedPacketIndex.value = null
        _selectedDecodeTree.value = null
        _selectedRawBytes.value = null
        _decodeLoading.value = false
    }

    fun setDisplayFilter(f: String) {
        _displayFilter.value = f
        recomputeSuggestions(f)
    }

    /** Recompute autocomplete suggestions for the given (in-progress) filter text. */
    private fun recomputeSuggestions(query: String) {
        viewModelScope.launch(Dispatchers.Default) {
            val ctx = SuggestionContext(
                endpoints = currentEndpointAddresses(),
                names = nameResolver.knownNames(),
                aliases = aliases.value.map { it.name }.toSet(),
                tcpStreams = tcpStreamSet.toList(),
                udpStreams = udpStreamSet.toList(),
                recentFilters = recentFilters.value.map { it.filter },
                savedFilters = savedFilters.value.map { it.name to it.filter },
            )
            _suggestions.value = suggestionEngine.suggest(query, ctx)
        }
    }

    /** Distinct endpoint addresses seen in the current packet list + analysis view. */
    private fun currentEndpointAddresses(): List<String> {
        val set = LinkedHashSet<String>()
        _endpoints.value.forEach { if (it.address.isNotBlank()) set += it.address }
        _packets.value.forEach { p ->
            if (p.src.isNotBlank() && p.src != "?") set += p.src
            if (p.dst.isNotBlank() && p.dst != "?") set += p.dst
        }
        return set.toList()
    }

    /** Resolve every visible endpoint address in the background, then bump the tick. */
    private fun resolveVisibleEndpoints() {
        viewModelScope.launch(Dispatchers.IO) {
            currentEndpointAddresses().forEach { nameResolver.resolve(it) }
            bumpResolve()
        }
    }

    /** A display label for an endpoint honouring the current display mode + caches. */
    fun labelFor(address: String): EndpointLabel =
        NameFormat.label(nameResolver.cached(address), _settings.value.displayMode)

    /** Best resolved name (alias/device/rDNS/OUI) for an endpoint, or null. */
    fun nameFor(address: String): String? = nameResolver.cached(address).name

    /** The user alias for an endpoint, if one exists. */
    fun aliasFor(address: String): String? {
        val key = PcapRepository.normalizeAddress(address)
        return aliases.value.firstOrNull { it.address == key }?.name
    }

    /** Apply a chosen autocomplete suggestion to the filter bar. */
    fun pickSuggestion(s: FilterSuggestion) {
        setDisplayFilter(s.apply)
    }

    // --- Endpoint location (online GeoIP + WHOIS) ----------------------------

    /**
     * Look up an endpoint's GeoIP + WHOIS/RDAP details online. This sends the IP to
     * external services (ipwho.is, rdap.org); it is only invoked by an explicit user
     * action. Results are cached for the session.
     */
    fun lookupEndpointLocation(address: String) {
        val addr = address.trim()
        locationCache[addr]?.let { _endpointLocation.value = it; _locationLoading.value = false; return }
        _endpointLocation.value = EndpointLocation(addr)
        _locationLoading.value = true
        viewModelScope.launch(Dispatchers.IO) {
            val loc = LocationLookup.lookup(
                addr,
                offlineGeo = geoIpManager.lookup(addr),
                allowOnline = prefs.onlineLookupsEnabled,
            )
            if (loc.hasAny || loc.isPrivate) locationCache[addr] = loc
            _endpointLocation.value = loc
            _locationLoading.value = false
        }
    }

    fun clearEndpointLocation() {
        _endpointLocation.value = null
        _locationLoading.value = false
    }

    fun loadTrafficMap() {
        val dm = decodeManager
        val file = activeDecodeFile()
        if (dm == null || file == null) {
            _trafficMap.value = TrafficMapState(error = "Open a capture first.")
            return
        }
        _trafficMap.value = TrafficMapState(loading = true)
        viewModelScope.launch(Dispatchers.IO) {
            // The map is endpoint-derived, so load endpoints here when nothing has yet.
            // Requiring the analysis workspace to have been opened first made the map
            // depend on an invisible bit of prior state, which is how it ended up
            // reachable only by a path nobody took.
            val endpointSnapshot = _endpoints.value.ifEmpty {
                val f = if (filterActive) _displayFilter.value.trim() else ""
                dm.endpoints(file, _endpointType.value, f).also { _endpoints.value = it }
            }
            if (endpointSnapshot.isEmpty()) {
                _trafficMap.value = TrafficMapState(error = "No endpoints in this capture.")
                return@launch
            }
            val online = prefs.onlineLookupsEnabled
            val publicIp = if (online) currentPublicIp() else null
            val origin = publicIp?.let {
                LocationLookup.lookup(it, offlineGeo = geoIpManager.lookup(it), allowOnline = true)
            }
            val endpointType = _endpointType.value.uppercase()
            val routes = mutableListOf<TrafficMapRoute>()
            endpointSnapshot
                .filter { AddressUtil.isPublicRoutable(it.address) }
                .sortedByDescending { it.bytes }
                .take(40)
                .forEach { endpoint ->
                    val loc = locationCache[endpoint.address]
                        ?: LocationLookup.lookup(
                            endpoint.address,
                            offlineGeo = geoIpManager.lookup(endpoint.address),
                            allowOnline = online,
                        ).also { if (it.hasAny || it.isPrivate) locationCache[endpoint.address] = it }
                    val lat = loc.latitude
                    val lon = loc.longitude
                    if (lat != null && lon != null) routes += TrafficMapRoute(
                        address = endpoint.address,
                        label = labelFor(endpoint.address).primary,
                        packets = endpoint.packets,
                        bytes = endpoint.bytes,
                        txPackets = endpoint.txPackets,
                        txBytes = endpoint.txBytes,
                        rxPackets = endpoint.rxPackets,
                        rxBytes = endpoint.rxBytes,
                        trafficType = endpointType,
                        city = loc.city,
                        region = loc.region,
                        country = loc.country,
                        latitude = lat,
                        longitude = lon,
                    )
                }
            // Offline data alone may well be enough; only ask for consent when it was
            // not, so a user with an imported GeoIP database is never nagged.
            val needsConsent = routes.isEmpty() && !online
            _trafficMap.value = TrafficMapState(
                loading = false,
                sourceAddress = publicIp,
                sourceLatitude = origin?.latitude,
                sourceLongitude = origin?.longitude,
                routes = routes,
                consentRequired = needsConsent,
                error = when {
                    needsConsent -> null
                    routes.isEmpty() -> "No public endpoints with GeoIP coordinates found."
                    else -> null
                },
            )
        }
    }

    fun clearTrafficMap() {
        _trafficMap.value = TrafficMapState()
    }

    fun importGeoIpDatabase(uri: android.net.Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val info = geoIpManager.import(uri)
            _geoIpDatabaseInfo.value = info
            locationCache.clear()
            _toolMessage.value = if (info.error == null)
                "Imported GeoIP database: ${info.recordCount} record(s)"
            else "GeoIP import failed: ${info.error}"
        }
    }

    fun clearGeoIpDatabase() {
        viewModelScope.launch(Dispatchers.IO) {
            _geoIpDatabaseInfo.value = geoIpManager.clear()
            locationCache.clear()
            _toolMessage.value = "Offline GeoIP database cleared."
        }
    }

    fun updateSettings(s: AppSettings) {
        val prev = _settings.value
        _settings.value = s
        if (s.resolveHostnames != prev.resolveHostnames) {
            prefs.resolveHostnames = s.resolveHostnames
            nameResolver.setResolveHostnames(s.resolveHostnames)
            if (s.resolveHostnames) { nameResolver.startDiscovery(); resolveVisibleEndpoints() }
            else nameResolver.stopDiscovery()
        }
        if (s.displayMode != prev.displayMode) {
            prefs.displayMode = s.displayMode.name
            bumpResolve()
        }
        // Autostop ceilings are read by CaptureManager when the next capture starts,
        // so they only need persisting here.
        if (s.maxCaptureSizeMb != prev.maxCaptureSizeMb) prefs.maxCaptureMb = s.maxCaptureSizeMb
        if (s.maxCaptureMinutes != prev.maxCaptureMinutes) prefs.maxCaptureMinutes = s.maxCaptureMinutes
    }

    // --- Endpoint aliases -----------------------------------------------------

    fun setAlias(address: String, name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repo.setAlias(address, name)
            nameResolver.refreshAliases()
            bumpResolve()
        }
    }

    fun removeAlias(address: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repo.removeAlias(address)
            nameResolver.refreshAliases()
            bumpResolve()
        }
    }

    // --- Recent + saved filters ----------------------------------------------

    fun applyFilterExpr(expr: String) {
        setDisplayFilter(expr)
        submitDisplayFilter()
    }

    fun saveCurrentFilter(name: String) {
        val f = _displayFilter.value.trim()
        if (f.isBlank()) { _toolMessage.value = "Enter a filter to save."; return }
        viewModelScope.launch(Dispatchers.IO) {
            repo.saveFilter(name, f)
            _toolMessage.value = "Saved filter: ${name.ifBlank { f }}"
        }
    }

    fun deleteSavedFilter(id: Long) {
        viewModelScope.launch(Dispatchers.IO) { repo.deleteSavedFilter(id) }
    }

    fun clearRecentFilters() {
        viewModelScope.launch(Dispatchers.IO) { repo.clearRecentFilters() }
    }

    // --- User-supplied decryption material -----------------------------------

    private fun refreshDecryptionState() {
        val d = decodeManager?.decryption ?: return
        _decryption.value = DecryptionUiState(
            tlsPresent = d.tlsKeylogPresent,
            tlsEnabled = d.tlsKeylogEnabled,
            tlsLines = d.tlsKeylogLines,
            wifiKeys = d.wifiKeys,
            wifiEnabled = d.wifiEnabled,
        )
    }

    fun importTlsKeylog(uri: android.net.Uri) {
        val d = decodeManager?.decryption ?: return
        viewModelScope.launch(Dispatchers.IO) {
            d.importKeylog(uri)
            refreshDecryptionState()
            reloadAnalysisAfterDecryptionChange()
        }
    }

    fun clearTlsKeylog() {
        decodeManager?.decryption?.clearKeylog()
        refreshDecryptionState()
        reloadAnalysisAfterDecryptionChange()
    }

    fun setTlsEnabled(enabled: Boolean) {
        decodeManager?.decryption?.tlsKeylogEnabled = enabled
        refreshDecryptionState()
        reloadAnalysisAfterDecryptionChange()
    }

    /** Add an 802.11 key. Returns a validation message, or null when accepted. */
    fun addWifiKey(type: WifiKeyType, raw: String): String? {
        val d = decodeManager?.decryption ?: return "Decoder not ready."
        val problem = WifiKey.validate(type, raw)
        if (problem != null) return problem
        d.addWifiKey(WifiKey(type, raw.trim()))
        refreshDecryptionState()
        reloadAnalysisAfterDecryptionChange()
        return null
    }

    fun removeWifiKey(key: WifiKey) {
        decodeManager?.decryption?.removeWifiKey(key)
        refreshDecryptionState()
        reloadAnalysisAfterDecryptionChange()
    }

    fun setWifiEnabled(enabled: Boolean) {
        decodeManager?.decryption?.wifiEnabled = enabled
        refreshDecryptionState()
        reloadAnalysisAfterDecryptionChange()
    }

    private fun reloadAnalysisAfterDecryptionChange() {
        val file = activeDecodeFile() ?: return
        val dm = decodeManager ?: return
        dm.clearAnalysisCache()
        _analysisLoading.value = true
        viewModelScope.launch(Dispatchers.IO) { loadCaptureAnalysis(file) }
    }

    // --- Diagnostic sources: Bluetooth HCI snoop + RIL/modem logs ------------

    /** Enable Android HCI snoop logging (root), then surface guidance to the user. */
    fun enableBluetoothHciSnoop() {
        val dm = decodeManager ?: return
        _diagnosticBusy.value = true
        viewModelScope.launch(Dispatchers.IO) {
            val r = dm.diagnostics.enableBtsnoop()
            _diagnosticMessage.value = r.message
            _diagnosticBusy.value = false
        }
    }

    /** Convert the device's btsnoop HCI log into a decoded pcapng capture. */
    fun collectBluetoothHci() {
        val dm = decodeManager ?: return
        _diagnosticBusy.value = true
        viewModelScope.launch(Dispatchers.IO) {
            val r = dm.diagnostics.collectBtsnoop()
            _diagnosticMessage.value = r.message
            if (r.ok) refreshCaptureFiles()
            _diagnosticBusy.value = false
        }
    }

    /** Snapshot the radio (RIL/modem) logcat buffer as a preserved raw log. */
    fun collectRilLogs() {
        val dm = decodeManager ?: return
        _diagnosticBusy.value = true
        viewModelScope.launch(Dispatchers.IO) {
            val r = dm.diagnostics.collectRilLogs()
            _diagnosticMessage.value = r.message
            if (r.ok) refreshDiagnosticLogs()
            _diagnosticBusy.value = false
        }
    }

    fun refreshDiagnosticLogs() {
        val dm = decodeManager ?: return
        viewModelScope.launch(Dispatchers.IO) {
            _diagnosticLogs.value = dm.diagnostics.listDiagnosticLogs().map { f ->
                dev.alsatianconsulting.pocketpcap.model.DiagnosticLog(
                    name = f.name, path = f.absolutePath,
                    sizeBytes = f.length(), createdAt = f.lastModified(),
                )
            }
        }
    }

    fun openDiagnosticLog(log: dev.alsatianconsulting.pocketpcap.model.DiagnosticLog) {
        val dm = decodeManager ?: return
        _viewingLogName.value = log.name
        _viewingLogText.value = null
        _rilEntries.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            val text = dm.diagnostics.readLog(log.path)
            _viewingLogText.value = text
            // RIL logs parse into structured request/response/unsolicited entries.
            if (log.name.startsWith("ril_", ignoreCase = true)) {
                _rilEntries.value = dev.alsatianconsulting.pocketpcap.decode.RilParser.parse(text)
            }
        }
    }

    fun closeDiagnosticLog() {
        _viewingLogName.value = null
        _viewingLogText.value = null
        _rilEntries.value = emptyList()
    }

    fun deleteDiagnosticLog(log: dev.alsatianconsulting.pocketpcap.model.DiagnosticLog) {
        viewModelScope.launch(Dispatchers.IO) {
            try { File(log.path).delete() } catch (_: Exception) {}
            refreshDiagnosticLogs()
        }
    }

    fun clearDiagnosticMessage() { _diagnosticMessage.value = null }

    /**
     * Apply the current display filter using tshark's real `-Y` engine over the
     * active capture file (full Wireshark display-filter syntax). Blank clears it.
     */
    fun submitDisplayFilter() {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: return
        val filter = _displayFilter.value.trim()
        clearSelectedPacket()
        _filterError.value = null
        if (filter.isBlank()) {
            filterActive = false
            if (viewingFile != null) {
                val cached = _captureAnalysis.value
                if (cached.metadata.filename == file.name && cached.packets.isNotEmpty()) {
                    _packets.value = cached.packets.map(::analysisPacketSummary)
                } else viewModelScope.launch(Dispatchers.IO) { _packets.value = dm.packetList(file) }
            } else {
                _packets.value = captureService?.captureManager?.packets?.value ?: emptyList()
            }
            return
        }
        // Validate the filter first so we can show a clear error for bad syntax.
        val err = dm.validateFilter(filter)
        if (err != null) { _filterError.value = err; return }
        filterActive = true
        viewModelScope.launch(Dispatchers.IO) {
            _packets.value = dm.packetList(file, filter)
            repo.recordRecentFilter(filter)
            resolveVisibleEndpoints()
        }
    }

    /** Open a saved capture file and decode its packet list into the Packets tab. */
    /**
     * Open a capture. [sourceUri] is the picker URI the file came from, or null for
     * one already in the app's own directory.
     *
     * Taking it as a parameter rather than leaving a field set from a previous open
     * is the point: the URI previously outlived the file it belonged to, so opening
     * an external file and then a local capture left Refresh copying the external
     * file over the local one and destroying it.
     */
    @JvmOverloads
    fun openCaptureFile(
        file: dev.alsatianconsulting.pocketpcap.model.CaptureFile,
        sourceUri: android.net.Uri? = null,
    ) {
        val dm = decodeManager ?: return
        viewedSourceUri = sourceUri
        viewingFile = File(file.path)
        _viewingFileName.value = file.name
        filterActive = false
        _displayFilter.value = ""
        _filterError.value = null
        clearSelectedPacket()
        _packets.value = emptyList()
        _captureAnalysis.value = CaptureAnalysis.EMPTY
        _analysisError.value = null
        _analysisLoading.value = true
        _searchResults.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            val capture = File(file.path)
            // One cached tshark pass supplies both the landing summary and packet list.
            // This avoids decoding the same large capture three times on open.
            loadCaptureAnalysis(capture)
            val analyzed = _captureAnalysis.value
            // The same ceiling packetList() applies, so the limit holds on the path
            // captures are actually opened through and the "first N" badge is honest.
            _packets.value = analyzed.packets.asSequence()
                .map(::analysisPacketSummary)
                .take(DecodeManager.PACKET_LIST_LIMIT)
                .toList()
            tcpStreamSet = analyzed.conversations.asSequence()
                .filter { it.kind == dev.alsatianconsulting.pocketpcap.analysis.ConversationKind.TCP }
                .mapNotNull { it.streamIndex }.toSet()
            udpStreamSet = analyzed.conversations.asSequence()
                .filter { it.kind == dev.alsatianconsulting.pocketpcap.analysis.ConversationKind.UDP }
                .mapNotNull { it.streamIndex }.toSet()
            if (analyzed.packets.isEmpty() && capture.length() <= 64L) {
                _toolMessage.value = "${file.name} contains no packets."
            }
            resolveVisibleEndpoints()
            _bookmarks.value = repo.bookmarksList(capture.absolutePath)
        }
    }

    fun closeViewedFile() {
        stopFollowing()
        viewedSourceUri = null
        viewingFile = null
        _viewingFileName.value = null
        filterActive = false
        _displayFilter.value = ""
        _filterError.value = null
        clearSelectedPacket()
        _captureAnalysis.value = CaptureAnalysis.EMPTY
        _analysisError.value = null
        _searchResults.value = emptyList()
        _bookmarks.value = emptyList()
        _packetColumns.value = emptyList()
        _packets.value = captureService?.captureManager?.packets?.value ?: emptyList()
    }

    fun refreshCaptureFiles() {
        viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            val svc = captureService
            if (svc != null) {
                svc.captureManager.refreshCaptureFiles()
                _captureFiles.value = svc.captureManager.captureFiles.value
            } else {
                // Scan directly when the service is not yet bound. Both the chosen
                // output directory and the app-private fallback, and through
                // SharedCaptureStore, because shared storage cannot be listed as a
                // directory - the same two places CaptureManager scans, so the list
                // does not change under the operator once the service binds.
                val app = getApplication<Application>()
                val dirs = listOf(java.io.File(prefs.outputDir), java.io.File(prefs.fallbackCaptureDir))
                    .distinctBy { it.absolutePath }
                _captureFiles.value = dirs
                    .flatMap { SharedCaptureStore.listFiles(app, it) }
                    .filter { it.extension == "pcapng" || it.extension == "pcap" }
                    .distinctBy { it.absolutePath }
                    .sortedByDescending { it.lastModified() }
                    .map { f ->
                        dev.alsatianconsulting.pocketpcap.model.CaptureFile(
                            name = f.name, path = f.absolutePath,
                            sizeBytes = f.length(), createdAt = f.lastModified(),
                            packetCount = 0L,
                        )
                    }
            }
        }
    }

    fun deleteCaptureFile(file: dev.alsatianconsulting.pocketpcap.model.CaptureFile) {
        viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            val target = java.io.File(file.path)
            target.delete()
            // Deleting the file leaves its MediaStore row behind, and the next capture
            // asking for that name would then be handed "name (1)" instead.
            SharedCaptureStore.forget(getApplication(), target)
            refreshCaptureFiles()
        }
    }

    // --- Analysis: protocol hierarchy + endpoints ----------------------------

    fun loadAnalysis() {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: run {
            _toolMessage.value = "Open a capture or start one first."; return
        }
        val filter = if (filterActive) _displayFilter.value.trim() else ""
        _analysisLoading.value = true
        viewModelScope.launch(Dispatchers.IO) {
            // Legacy hierarchy/endpoint views may reflect the active display filter.
            _protoHierarchy.value = dm.protocolHierarchy(file, filter)
            _endpoints.value = dm.endpoints(file, _endpointType.value, filter)
            // The mobile analysis workspace is explicitly whole-capture by default.
            loadCaptureAnalysis(file)
            resolveVisibleEndpoints()
        }
    }

    private fun loadCaptureAnalysis(file: File) {
        val dm = decodeManager ?: return
        _analysisLoading.value = true
        _analysisError.value = null
        val value = runCatching { dm.captureAnalysis(file) }.getOrElse { error ->
            _analysisError.value = error.message ?: "Capture analysis failed."
            CaptureAnalysis.EMPTY.copy(metadata = dev.alsatianconsulting.pocketpcap.analysis.CaptureMetadata(file.name, file.length()))
        }
        _captureAnalysis.value = value
        _analysisLoading.value = false
        // A single large fields export creates substantial short-lived parser state.
        // Reclaim it after the immutable cache has been published, not during UI work.
        Runtime.getRuntime().gc()
    }

    private fun analysisPacketSummary(packet: dev.alsatianconsulting.pocketpcap.analysis.AnalysisPacket): PacketSummary =
        PacketSummary(
            number = packet.number,
            timestampUs = (packet.timestampSeconds * 1_000_000L).toLong(),
            src = packet.source,
            dst = packet.destination,
            protocol = packet.protocol,
            length = packet.length,
            info = packet.info,
            colorHint = when {
                packet.protocol.contains("DNS", true) -> PacketColor.DNS
                packet.protocol.contains("HTTP", true) -> PacketColor.HTTP
                packet.protocol.contains("TLS", true) || packet.protocol.contains("SSL", true) -> PacketColor.TLS
                packet.protocol.contains("TCP", true) -> PacketColor.TCP
                packet.protocol.contains("UDP", true) -> PacketColor.UDP
                packet.protocol.contains("ICMP", true) -> PacketColor.ICMP
                packet.protocol.contains("ARP", true) -> PacketColor.ARP
                packet.protocol.contains("BT", true) -> PacketColor.BT
                else -> PacketColor.DEFAULT
            },
        )

    /** Entity-grouped search over the cached, whole-capture analysis. */
    fun searchCapture(query: String) {
        captureSearchJob?.cancel()
        if (query.isBlank()) { _searchResults.value = emptyList(); return }
        val aliasMap = aliases.value.associate { it.address to it.name }
        captureSearchJob = viewModelScope.launch(Dispatchers.IO) {
            kotlinx.coroutines.delay(250)
            val base = CaptureSearch.search(_captureAnalysis.value, query, aliasMap)
            val file = activeDecodeFile()
            val payload = if (file != null) decodeManager?.searchPacketPayload(file, query).orEmpty() else emptyList()
            _searchResults.value = (base + payload).distinctBy { "${it.entity}:${it.title}:${it.packetNumber}" }
        }
    }


    /** Apply a time selection using capture-relative frame timestamps. */
    fun applyTimeRange(startSeconds: Double, endSeconds: Double) {
        applyFilterExpr("frame.time_relative >= ${"%.6f".format(java.util.Locale.US, startSeconds)} && " +
            "frame.time_relative <= ${"%.6f".format(java.util.Locale.US, endSeconds)}")
    }

    fun addAnalysisBookmark(
        type: BookmarkType,
        referenceId: String,
        label: String,
        note: String,
        filter: String,
        packetNumber: Long? = null,
    ) {
        val path = activeDecodeFile()?.absolutePath ?: return
        viewModelScope.launch(Dispatchers.IO) {
            repo.addBookmark(path, type.name, referenceId, label, note, filter, packetNumber)
            _bookmarks.value = repo.bookmarksList(path)
            _toolMessage.value = "Bookmark saved."
        }
    }

    fun updateBookmarkNote(id: Long, note: String) {
        val path = activeDecodeFile()?.absolutePath ?: return
        viewModelScope.launch(Dispatchers.IO) {
            repo.updateBookmarkNote(id, note)
            _bookmarks.value = repo.bookmarksList(path)
        }
    }

    fun deleteBookmark(id: Long) {
        val path = activeDecodeFile()?.absolutePath ?: return
        viewModelScope.launch(Dispatchers.IO) {
            repo.deleteBookmark(id)
            _bookmarks.value = repo.bookmarksList(path)
        }
    }


    private fun currentPublicIp(timeoutMs: Int = 5_000): String? {
        return try {
            val conn = (URL("https://api.ipify.org").openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                setRequestProperty("User-Agent", "PocketPCAP/0.1")
            }
            conn.inputStream.bufferedReader().use { it.readText().trim().takeIf(AddressUtil::isIpAddress) }
        } catch (_: Exception) {
            null
        }
    }


    // --- Follow stream --------------------------------------------------------

    /** Follow the stream the given packet belongs to. proto: TCP/UDP/TLS/HTTP. */
    fun followStreamForPacket(packetIndex: Int, proto: String) {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: return
        val packet = _packets.value.getOrNull(packetIndex) ?: return
        _followLoading.value = true
        _followStream.value = null
        viewModelScope.launch(Dispatchers.IO) {
            val ref = dm.streamRefFor(file, packet.number)
            val p = proto.lowercase()
            val index = when (p) {
                "udp" -> ref.udpStream
                else -> ref.tcpStream   // tcp/tls/http all key off the TCP stream
            }
            if (index == null) {
                _toolMessage.value = "No $proto stream for this packet."
                _followLoading.value = false
                return@launch
            }
            _followStream.value = dm.followStream(file, proto, index)
            _followLoading.value = false
            if (_followStream.value == null) _toolMessage.value = "Stream could not be reconstructed."
        }
    }

    fun followStreamByIndex(proto: String, index: Int) {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: return
        _followLoading.value = true
        _followStream.value = null
        viewModelScope.launch(Dispatchers.IO) {
            _followStream.value = dm.followStream(file, proto, index)
            _followLoading.value = false
            if (_followStream.value == null) _toolMessage.value = "Stream could not be reconstructed."
        }
    }

    fun closeFollowStream() { _followStream.value = null; _followLoading.value = false }

    /** What stream types can this packet be followed as? */
    fun streamOptionsForPacket(packetIndex: Int, onResult: (List<String>) -> Unit) {
        val dm = decodeManager ?: return onResult(emptyList())
        val file = activeDecodeFile() ?: return onResult(emptyList())
        val packet = _packets.value.getOrNull(packetIndex) ?: return onResult(emptyList())
        viewModelScope.launch(Dispatchers.IO) {
            val ref = dm.streamRefFor(file, packet.number)
            val opts = mutableListOf<String>()
            if (ref.tcpStream != null) {
                opts += "TCP"
                val p = packet.protocol.uppercase()
                if (p.contains("TLS") || p.contains("SSL") || p.contains("HTTP")) opts += "TLS"
                if (p.contains("HTTP")) opts += "HTTP"
            }
            if (ref.udpStream != null) opts += "UDP"
            onResult(opts)
        }
    }

    // --- Decode node context: apply as filter --------------------------------

    /** Apply (or just prepare) a field==value display filter from a decode node. */
    fun applyFieldFilter(field: String, value: String, submit: Boolean) {
        if (field.isBlank()) return
        val expr = buildFieldFilter(field, value)
        _displayFilter.value = expr
        clearSelectedPacket()
        if (submit) submitDisplayFilter()
    }

    fun excludeFieldValue(field: String, value: String) {
        if (field.isBlank()) return
        val positive = buildFieldFilter(field, value)
        applyFilterExpr(if (value.isBlank()) "!($positive)" else positive.replaceFirst(" == ", " != "))
        clearSelectedPacket()
    }

    fun addPacketListColumn(field: String) {
        if (field.isBlank() || _packetColumns.value.any { it.field == field }) return
        val file = activeDecodeFile() ?: return
        val dm = decodeManager ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val values = dm.packetFieldValues(file, field)
            if (values.isEmpty()) _toolMessage.value = "No values for $field in this capture."
            else {
                _packetColumns.value = (_packetColumns.value + DynamicPacketColumn(field, values)).takeLast(3)
                _toolMessage.value = "Added packet-list column: $field"
            }
        }
    }

    fun removePacketListColumn(field: String) {
        _packetColumns.value = _packetColumns.value.filterNot { it.field == field }
    }

    private fun buildFieldFilter(field: String, value: String): String {
        if (value.isBlank()) return field   // presence filter
        // Quote non-numeric values; leave numbers/booleans bare.
        val numeric = value.toDoubleOrNull() != null
        val v = if (numeric) value else "\"" + value.replace("\"", "\\\"") + "\""
        return "$field == $v"
    }

    // --- Export: filtered subset ---------------------------------------------

    /** Export the packets matching the current display filter as a new pcapng. */
    fun exportFilteredSelection() {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: run { _toolMessage.value = "No capture to export."; return }
        val filter = _displayFilter.value.trim()
        if (filter.isBlank()) { _toolMessage.value = "Enter a display filter first."; return }
        viewModelScope.launch(Dispatchers.IO) {
            val out = newOutputFile("filtered_${dm.timestamp()}.pcapng")
            val ok = dm.exportFiltered(file, filter, out)
            _toolMessage.value = if (ok) "Exported ${out.name} (filter: $filter) — see Files."
                                 else "Export failed (no matching packets?)."
            if (ok) { publish(out); refreshCaptureFiles() }
        }
    }

    // --- Export: objects ------------------------------------------------------

    fun exportObjects(type: String) {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: run { _toolMessage.value = "No capture loaded."; return }
        _objectsLoading.value = true
        _exportedObjects.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            val dir = java.io.File(
                getApplication<Application>().getExternalFilesDir(null),
                "objects/${type}_${dm.timestamp()}"
            )
            val objs = dm.exportObjects(file, type, dir)
            _exportedObjects.value = objs
            _objectsLoading.value = false
            if (objs.isEmpty()) _toolMessage.value = "No $type objects found in this capture."
        }
    }

    fun clearExportedObjects() { _exportedObjects.value = emptyList() }

    // --- Import external pcap files ------------------------------------------

    /**
     * Open a user-picked capture file.
     *
     * The file is copied into the app's capture directory, because tshark needs a
     * real filesystem path and a content URI is not one. The URI is remembered, with
     * a persistable read grant where the provider allows it, so [reloadViewedFile]
     * can pull the file again later. That is what makes this work with a capture
     * another app is still writing, such as AndroidMonitor or ATTA.
     */
    fun importPcap(uri: android.net.Uri, onOpened: () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            if (!looksLikePcap(uri)) {
                _toolMessage.value = "That file is not a pcap or pcapng capture."
                return@launch
            }
            val dest = copyFromUri(uri) ?: return@launch
            // Keep the grant across process death so a later refresh can re-read.
            runCatching {
                getApplication<Application>().contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            refreshCaptureFiles()
            _toolMessage.value = "Opened ${dest.name}"
            openCaptureFile(
                dev.alsatianconsulting.pocketpcap.model.CaptureFile(
                    name = dest.name, path = dest.absolutePath,
                    sizeBytes = dest.length(), createdAt = dest.lastModified(), packetCount = 0L,
                ),
                sourceUri = uri,
            )
            // onOpened navigates, and NavController touches Lifecycle state, which
            // must be done on the main thread.
            withContext(Dispatchers.Main) { onOpened() }
        }
    }

    /**
     * Re-read the capture that is currently open, picking up anything appended since.
     *
     * Two cases. A file opened through the picker is pulled from its source URI again,
     * so a capture another app is still writing is re-copied at its current length. A
     * file already inside the app's own capture directory is simply re-decoded in
     * place. Either way the cached analysis is dropped first, so the summary, packet
     * list and every derived view are rebuilt from what is on disk now.
     */
    @JvmOverloads
    fun reloadViewedFile(announce: Boolean = true) {
        val current = viewingFile ?: run {
            if (announce) _toolMessage.value = "No capture file is open."
            return
        }
        if (!reloading.compareAndSet(false, true)) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
            val before = current.length()
            viewedSourceUri?.let { uri ->
                if (copyFromUri(uri, current.name) == null) return@launch
            }
            val after = java.io.File(current.absolutePath).length()
            decodeManager?.clearAnalysisCache()
            openCaptureFile(
                dev.alsatianconsulting.pocketpcap.model.CaptureFile(
                    name = current.name, path = current.absolutePath,
                    sizeBytes = after, createdAt = current.lastModified(), packetCount = 0L,
                ),
                sourceUri = viewedSourceUri,
            )
            if (announce || after > before) {
                _toolMessage.value = when {
                    after > before -> "Reloaded — grew by ${formatBytes(after - before)}"
                    else -> "Reloaded — no new data"
                }
            }
            } finally {
                reloading.set(false)
            }
        }
    }

    /** Copy a picked capture into the app capture directory. Returns the file. */
    private fun copyFromUri(uri: android.net.Uri, forceName: String? = null): java.io.File? {
        return try {
            val cr = getApplication<Application>().contentResolver
            val name = forceName ?: run {
                val raw = queryDisplayName(uri) ?: "imported_${decodeManager?.timestamp()}.pcapng"
                raw.replace(Regex("[^A-Za-z0-9._-]"), "_").let {
                    if (it.endsWith(".pcap") || it.endsWith(".pcapng") || it.endsWith(".cap")) it
                    else "$it.pcapng"
                }
            }
            val destDir = java.io.File(prefs.fallbackCaptureDir).apply { mkdirs() }
            val dest = java.io.File(destDir, name)
            cr.openInputStream(uri)?.use { input ->
                dest.outputStream().use { input.copyTo(it) }
            } ?: run {
                _toolMessage.value = "Could not read the selected file."
                return null
            }
            dest
        } catch (e: Exception) {
            _toolMessage.value = "Could not read the file: ${e.message}"
            null
        }
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "%.1f kB".format(bytes / 1024.0)
        else -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    }

    // --- Follow a capture that is still being written -------------------------

    private val _followingFile = MutableStateFlow(false)
    val followingFile: StateFlow<Boolean> = _followingFile
    private var followJob: Job? = null

    /**
     * Poll the open capture and reload it whenever it grows.
     *
     * Only a size change triggers the reload, so a file that is not being written
     * costs one `length()` call every few seconds and nothing else.
     */
    private val reloading = java.util.concurrent.atomic.AtomicBoolean(false)

    fun setFollowingFile(enabled: Boolean) {
        _followingFile.value = enabled
        followJob?.cancel()
        if (!enabled) return
        followJob = viewModelScope.launch(Dispatchers.IO) {
            var lastSize = sourceLength() ?: viewingFile?.length() ?: 0L
            while (currentCoroutineContext().isActive) {
                delay(FOLLOW_POLL_MS)
                val size = sourceLength() ?: viewingFile?.length() ?: continue
                // A reload runs a whole-file tshark pass. On a capture being written
                // fast that outlasts the poll interval, so without this guard every
                // tick queued another pass and they piled up on captureAnalysis's
                // lock, leaving the list further behind the longer it followed.
                if (size != lastSize && !reloading.get()) {
                    lastSize = size
                    reloadViewedFile(announce = false)
                }
            }
        }
    }

    /** Length of the picked source, when the open file came from the picker. */
    private fun sourceLength(): Long? {
        val uri = viewedSourceUri ?: return null
        return try {
            getApplication<Application>().contentResolver
                .openFileDescriptor(uri, "r")?.use { it.statSize.takeIf { s -> s >= 0 } }
        } catch (_: Exception) { null }
    }

    private fun stopFollowing() {
        followJob?.cancel(); followJob = null
        _followingFile.value = false
    }

    // --- Exports --------------------------------------------------------------

    /** Write one analysis table as CSV or JSON and return the file for sharing. */
    fun exportAnalysisTable(table: AnalysisExport.Table, asJson: Boolean, onReady: (File) -> Unit) {
        val analysis = _captureAnalysis.value
        if (analysis.packets.isEmpty() && analysis.conversations.isEmpty()) {
            _toolMessage.value = "Open a capture first."
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val body = if (asJson) AnalysisExport.json(analysis, table)
                       else AnalysisExport.csv(analysis, table)
            if (body.isBlank()) {
                _toolMessage.value = "No ${table.label} rows in this capture."
                return@launch
            }
            val stem = analysis.metadata.filename.substringBeforeLast('.', "capture")
            val out = newOutputFile("${stem}_${table.fileStem}.${if (asJson) "json" else "csv"}")
            out.writeText(body)
            _toolMessage.value = "Exported ${out.name}"
            withContext(Dispatchers.Main) { onReady(publish(out)) }
        }
    }

    /** Write the traffic map as KML or GeoJSON and return the file for sharing. */
    fun exportTrafficMap(asKml: Boolean, onReady: (File) -> Unit) {
        val map = _trafficMap.value
        if (map.routes.isEmpty()) {
            _toolMessage.value = "No mapped endpoints to export."
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val stem = _captureAnalysis.value.metadata.filename.substringBeforeLast('.', "capture")
            val out = newOutputFile(if (asKml) "${stem}_map.kml" else "${stem}_map.geojson")
            out.writeText(if (asKml) AnalysisExport.kml(map, stem) else AnalysisExport.geoJson(map))
            _toolMessage.value = "Exported ${out.name}"
            withContext(Dispatchers.Main) { onReady(publish(out)) }
        }
    }

    /** Merge the chosen captures into one timestamp-ordered file. */
    fun mergeCaptures(files: List<dev.alsatianconsulting.pocketpcap.model.CaptureFile>) {
        val dm = decodeManager ?: return
        if (files.size < 2) { _toolMessage.value = "Select at least two captures."; return }
        viewModelScope.launch(Dispatchers.IO) {
            val out = newOutputFile("merged_${dm.timestamp()}.pcapng")
            val ok = dm.mergeCaptures(files.map { File(it.path) }, out)
            _toolMessage.value = if (ok) "Merged ${files.size} captures into ${out.name}"
                                 else "Merge failed."
            if (ok) publish(out)
            refreshCaptureFiles()
        }
    }

    /** Copy the open capture with payloads truncated, for sharing safely. */
    fun exportSanitised(onReady: (File) -> Unit) {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: run { _toolMessage.value = "No capture to export."; return }
        viewModelScope.launch(Dispatchers.IO) {
            val out = newOutputFile("${file.nameWithoutExtension}_headers_${dm.timestamp()}.pcapng")
            val ok = dm.exportSanitised(file, out)
            _toolMessage.value = if (ok) "Wrote ${out.name} — headers only, payloads removed"
                                 else "Sanitised export failed."
            refreshCaptureFiles()
            if (ok) withContext(Dispatchers.Main) { onReady(publish(out)) }
        }
    }

    /** Copy the open capture with analyst notes written in as pcapng comments. */
    fun exportWithNotes(onReady: (File) -> Unit) {
        val dm = decodeManager ?: return
        val file = activeDecodeFile() ?: run { _toolMessage.value = "No capture to export."; return }
        viewModelScope.launch(Dispatchers.IO) {
            val comments = repo.bookmarksList(file.absolutePath)
                .filter { it.note.isNotBlank() && it.packetNumber != null }
                .associate { it.packetNumber!! to it.note }
            if (comments.isEmpty()) {
                _toolMessage.value = "No packet notes to write."
                return@launch
            }
            val out = newOutputFile("${file.nameWithoutExtension}_annotated_${dm.timestamp()}.pcapng")
            val ok = dm.exportWithComments(file, comments, out)
            _toolMessage.value = if (ok) "Wrote ${out.name} with ${comments.size} packet comments"
                                 else "Annotated export failed."
            refreshCaptureFiles()
            if (ok) withContext(Dispatchers.Main) { onReady(publish(out)) }
        }
    }

    /**
     * Create [name] in the chosen output directory and return the file to write to.
     *
     * Captures and exports land together in Documents/pocketpcap by default, which is
     * shared storage and so has to be registered with MediaStore before ordinary writes
     * work on it. That can fail - a folder the operator picked may be one MediaStore
     * cannot address - and an export is still better written somewhere than lost, so
     * app-private storage is the fallback. Either way the result is a real path, which
     * is what tshark, editcap and mergecap need, and what the share sheet resolves
     * through the FileProvider.
     */
    private fun newOutputFile(name: String): File {
        val app = getApplication<Application>()
        return SharedCaptureStore.newFile(app, File(prefs.outputDir), name)
            ?: File(File(app.getExternalFilesDir(null), "exports").apply { mkdirs() }, name)
    }

    /**
     * Tell MediaStore the file's real size after writing it directly.
     *
     * MediaStore only ever saw the empty file it created, so without this every export
     * shows up as 0 bytes in the Files app.
     */
    private fun publish(file: File): File =
        file.also { SharedCaptureStore.refresh(getApplication(), it) }

    /** Where the open capture was picked from, so a refresh can re-read it. */
    private var viewedSourceUri: android.net.Uri? = null

    private fun looksLikePcap(uri: android.net.Uri): Boolean = try {
        getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
            val magic = ByteArray(4)
            val read = input.read(magic)
            read == 4 && PCAP_MAGICS.any { it.contentEquals(magic) }
        } ?: false
    } catch (_: Exception) {
        false
    }

    private fun queryDisplayName(uri: android.net.Uri): String? = try {
        getApplication<Application>().contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    } catch (_: Exception) { null }

    // --- Output directory -----------------------------------------------------

    fun setOutputDir(path: String) {
        prefs.outputDir = path
        _outputDir.value = path
    }

    fun resetOutputDir() {
        prefs.resetOutputDir()
        _outputDir.value = prefs.outputDir
    }

    fun clearToolMessage() { _toolMessage.value = null }

    /**
     * Ask the capture service for the foreground, which it grants only for a real
     * capture. Sent as a started command because a bound service may not promote
     * itself.
     */
    private fun startCaptureForeground() {
        val intent = Intent(getApplication(), CaptureService::class.java).apply {
            action = CaptureService.ACTION_START_CAPTURE
        }
        getApplication<Application>().startForegroundService(intent)
    }

    /**
     * Bind only. Binding used to start the service in the foreground as well, which put
     * an ongoing notification on screen from app launch with nothing being captured.
     * BIND_AUTO_CREATE still creates the service, so CaptureManager is reachable.
     */
    private fun bindService() {
        val intent = Intent(getApplication(), CaptureService::class.java)
        getApplication<Application>().bindService(
            intent, serviceConnection, Context.BIND_AUTO_CREATE
        )
    }

    private companion object {
        const val FOLLOW_POLL_MS = 3_000L
        /** pcapng section header, plus pcap in both byte orders and the ns variants. */
        val PCAP_MAGICS = listOf(
            byteArrayOf(0x0A, 0x0D, 0x0D, 0x0A),
            byteArrayOf(0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0xD4.toByte()),
            byteArrayOf(0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte()),
            byteArrayOf(0xA1.toByte(), 0xB2.toByte(), 0x3C, 0x4D),
            byteArrayOf(0x4D, 0x3C, 0xB2.toByte(), 0xA1.toByte()),
        )
    }

    override fun onCleared() {
        try {
            getApplication<Application>().unbindService(serviceConnection)
        } catch (_: Exception) {}
        try { nameResolver.stopDiscovery() } catch (_: Exception) {}
        super.onCleared()
    }
}
