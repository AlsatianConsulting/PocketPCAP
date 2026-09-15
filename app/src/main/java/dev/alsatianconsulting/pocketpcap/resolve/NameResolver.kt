package dev.alsatianconsulting.pocketpcap.resolve

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import dev.alsatianconsulting.pocketpcap.data.PcapRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.GZIPInputStream

/**
 * Resolves endpoint addresses to meaningful names, combining sources in priority
 * order:
 *   1. user aliases (Room)                         — always wins
 *   2. local device discovery — mDNS / NetBIOS / LLMNR
 *   3. reverse DNS (PTR)                           — InetAddress canonical host name
 *   4. OUI vendor (MAC only)                       — bundled IEEE manuf table
 *
 * Lookups are cached. Reverse DNS, mDNS, NetBIOS and LLMNR run off the main thread;
 * the UI reads the already-cached result synchronously via [cached]. The active
 * link-local queries (NetBIOS/LLMNR) only fire for private IPv4 addresses and only
 * when hostname resolution is enabled.
 */
class NameResolver(
    private val context: Context,
    private val repo: PcapRepository,
) {
    private val rdnsCache = ConcurrentHashMap<String, String>()   // ip -> ptr name ("" = none)
    private val mdnsCache = ConcurrentHashMap<String, String>()   // ip -> mDNS service name
    private val deviceCache = ConcurrentHashMap<String, String>() // ip -> NetBIOS/LLMNR name
    private val triedLocal = ConcurrentHashMap.newKeySet<String>() // IPs already NetBIOS/LLMNR-queried
    @Volatile private var aliasCache: Map<String, String> = emptyMap()

    // Full IEEE OUI table (MA-L/MA-M/MA-S). Loaded off-thread via [prewarm].
    @Volatile private var oui: OuiData = OuiData.EMPTY

    @Volatile private var resolveHostnames = false

    private val nsdManager: NsdManager? by lazy {
        try { context.getSystemService(Context.NSD_SERVICE) as? NsdManager } catch (_: Exception) { null }
    }
    private val wifiManager: WifiManager? by lazy {
        try { context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager } catch (_: Exception) { null }
    }
    private val activeListeners = mutableListOf<NsdManager.DiscoveryListener>()

    fun setResolveHostnames(enabled: Boolean) { resolveHostnames = enabled }

    /** Load the (large) OUI table off the main thread. Call once at startup. */
    fun prewarm() { if (oui.size == 0) oui = loadOui() }

    /** Reload the alias cache from the database (call after any alias edit). */
    suspend fun refreshAliases() {
        aliasCache = repo.allAliases().associate { it.address to it.name }
    }

    // --- Synchronous (cache-only) resolution for rendering --------------------

    /**
     * Best name known *right now* without blocking. Use in Composables; pair with a
     * background [resolve] pass that populates caches and triggers recomposition.
     */
    fun cached(address: String): ResolvedName {
        val addr = address.trim()
        if (addr.isEmpty() || addr == "?") return ResolvedName(addr, null, NameSource.NONE)

        aliasCache[PcapRepository.normalizeAddress(addr)]?.let {
            return ResolvedName(addr, it, NameSource.ALIAS)
        }
        if (AddressUtil.isIpAddress(addr)) {
            mdnsCache[addr]?.let { return ResolvedName(addr, it, NameSource.DEVICE) }
            deviceCache[addr]?.let { return ResolvedName(addr, it, NameSource.DEVICE) }
            rdnsCache[addr]?.takeIf { it.isNotEmpty() }?.let {
                return ResolvedName(addr, it, NameSource.RDNS)
            }
        }
        if (AddressUtil.isMacAddress(addr)) {
            OuiTable.lookup(oui, addr)?.let { return ResolvedName(addr, it, NameSource.OUI) }
        }
        return ResolvedName(addr, null, NameSource.NONE)
    }

    // --- Background resolution (populates caches) -----------------------------

    /**
     * Resolve [address], performing a reverse-DNS lookup if enabled and not cached.
     * Returns the best available [ResolvedName]. Safe to call from a background
     * coroutine.
     */
    suspend fun resolve(address: String): ResolvedName {
        val addr = address.trim()
        val cachedHit = cached(addr)
        if (cachedHit.hasName) return cachedHit
        if (!resolveHostnames) return cachedHit

        // Active link-local discovery (NetBIOS / LLMNR) for private IPv4 hosts.
        if (AddressUtil.isPrivateIpv4(addr) && triedLocal.add(addr)) {
            val local = withContext(Dispatchers.IO) { queryLocalName(addr) }
            if (local != null) {
                deviceCache[addr] = local
                return ResolvedName(addr, local, NameSource.DEVICE)
            }
        }
        // Reverse DNS fallback.
        if (AddressUtil.isIpAddress(addr) && !rdnsCache.containsKey(addr)) {
            val ptr = reverseDns(addr)
            rdnsCache[addr] = ptr ?: ""
            if (ptr != null) return ResolvedName(addr, ptr, NameSource.RDNS)
        }
        return cached(addr)
    }

    private suspend fun reverseDns(ip: String): String? = withContext(Dispatchers.IO) {
        try {
            val inet = InetAddress.getByName(ip)
            val host = inet.canonicalHostName
            // getCanonicalHostName echoes the IP back when there's no PTR record.
            if (host.isNotBlank() && !host.equals(ip, ignoreCase = true)) host else null
        } catch (_: Exception) { null }
    }

    /**
     * Try NetBIOS (NBSTAT) then LLMNR (reverse PTR) to learn a private host's name.
     * A Wi-Fi multicast lock is held around the LLMNR query so the link-local
     * multicast reply isn't filtered.
     */
    private fun queryLocalName(ip: String): String? {
        LocalNameQuery.netbiosName(ip, NBNS_TIMEOUT_MS)?.let { return it }
        val lock = try {
            wifiManager?.createMulticastLock("pocketpcap-llmnr")?.apply {
                setReferenceCounted(false); acquire()
            }
        } catch (_: Exception) { null }
        try {
            LocalNameQuery.llmnrName(ip, LLMNR_TIMEOUT_MS)?.let { return it }
        } finally {
            try { lock?.release() } catch (_: Exception) {}
        }
        return null
    }

    // --- Local device discovery (mDNS / DNS-SD) -------------------------------

    /**
     * Browse a handful of common mDNS service types and cache discovered hosts by IP.
     * Best-effort: NsdManager only surfaces advertised services, so unmanaged hosts
     * still fall back to reverse DNS / OUI.
     */
    fun startDiscovery() {
        if (!resolveHostnames) return
        val nsd = nsdManager ?: return
        if (activeListeners.isNotEmpty()) return
        for (type in SERVICE_TYPES) {
            val listener = object : NsdManager.DiscoveryListener {
                override fun onStartDiscoveryFailed(s: String?, e: Int) {}
                override fun onStopDiscoveryFailed(s: String?, e: Int) {}
                override fun onDiscoveryStarted(s: String?) {}
                override fun onDiscoveryStopped(s: String?) {}
                override fun onServiceLost(info: NsdServiceInfo?) {}
                override fun onServiceFound(info: NsdServiceInfo?) {
                    if (info != null) resolveService(nsd, info)
                }
            }
            try {
                nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, listener)
                activeListeners += listener
            } catch (_: Exception) {}
        }
    }

    fun stopDiscovery() {
        val nsd = nsdManager ?: return
        activeListeners.forEach { l -> try { nsd.stopServiceDiscovery(l) } catch (_: Exception) {} }
        activeListeners.clear()
    }

    @Suppress("DEPRECATION")
    private fun resolveService(nsd: NsdManager, info: NsdServiceInfo) {
        try {
            nsd.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(s: NsdServiceInfo?, e: Int) {}
                override fun onServiceResolved(resolved: NsdServiceInfo?) {
                    val host = resolved?.host?.hostAddress ?: return
                    val name = resolved.serviceName?.trim().orEmpty()
                    if (name.isNotEmpty()) mdnsCache.putIfAbsent(host, name)
                }
            })
        } catch (_: Exception) {}
    }

    /**
     * Parse the bundled, gzipped IEEE `manuf` table (MA-L/MA-M/MA-S). The asset uses a
     * non-".gz" extension so the Android build doesn't transparently gunzip+rename it;
     * we decompress it explicitly here.
     */
    private fun loadOui(): OuiData = try {
        context.assets.open("manuf.bin").use { raw ->
            GZIPInputStream(raw).bufferedReader().use { OuiTable.parse(it.lineSequence()) }
        }
    } catch (_: Exception) { OuiData.EMPTY }

    /** All names currently known (aliases + discovered + rDNS) for autocomplete. */
    fun knownNames(): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        aliasCache.forEach { (addr, name) -> out += name to addr }
        mdnsCache.forEach { (addr, name) -> out += name to addr }
        deviceCache.forEach { (addr, name) -> out += name to addr }
        rdnsCache.forEach { (addr, name) -> if (name.isNotEmpty()) out += name to addr }
        return out
    }

    companion object {
        private const val NBNS_TIMEOUT_MS = 400
        private const val LLMNR_TIMEOUT_MS = 400

        private val SERVICE_TYPES = listOf(
            "_workstation._tcp.",
            "_http._tcp.",
            "_googlecast._tcp.",
            "_airplay._tcp.",
            "_ipp._tcp.",
            "_printer._tcp.",
            "_smb._tcp.",
            "_ssh._tcp.",
        )
    }
}
