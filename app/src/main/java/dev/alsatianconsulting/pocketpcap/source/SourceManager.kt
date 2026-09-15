package dev.alsatianconsulting.pocketpcap.source

import android.content.Context
import dev.alsatianconsulting.pocketpcap.decode.RootShell
import dev.alsatianconsulting.pocketpcap.decode.TsharkBundle
import dev.alsatianconsulting.pocketpcap.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.File

class SourceManager(private val context: Context) {

    private val _interfaces = MutableStateFlow<List<NetworkInterface>>(emptyList())
    val interfaces: StateFlow<List<NetworkInterface>> = _interfaces

    private val _capabilities = MutableStateFlow<List<CapabilityStatus>>(emptyList())
    val capabilities: StateFlow<List<CapabilityStatus>> = _capabilities

    private val _rootAvailable = MutableStateFlow<Boolean?>(null)
    val rootAvailable: StateFlow<Boolean?> = _rootAvailable

    suspend fun refresh(probeRoot: Boolean = true) = withContext(Dispatchers.IO) {
        // An explicit refresh is the operator asking us to look again, so discard a
        // cached probe result first: a device that has since gained root should be
        // picked up here rather than needing an app restart.
        if (probeRoot) RootShell.resetProbe()
        val hasRoot = if (probeRoot) checkRoot() else false
        _rootAvailable.value = if (probeRoot) hasRoot else null
        _interfaces.value = discoverInterfaces(hasRoot)
        _capabilities.value = buildCapabilities(hasRoot, rootChecked = probeRoot)
    }


    /** The bundled tshark is executable straight from the native library directory. */
    private fun tsharkExecutable(): Boolean =
        java.io.File(context.applicationInfo.nativeLibraryDir, "libtshark.so").canExecute()

    private fun checkRoot(): Boolean {
        // Actually invoke su (via resolved absolute path) so the first run triggers
        // the Magisk grant prompt and we confirm real root, not just a binary on disk.
        return RootShell.hasRoot()
    }

    private fun discoverInterfaces(hasRoot: Boolean): List<NetworkInterface> {
        // On Android 12+ an app (untrusted_app) cannot read /proc/net/dev or
        // /sys/class/net, so interface discovery goes through root. With root we
        // run `ip` once for links and once for addresses and join the results.
        val ifaces = mutableListOf<NetworkInterface>()

        if (hasRoot) {
            val addrMap = readIpv4Addresses()
            val linkOut = RootShell.run("ip -o link show", timeoutMs = 15_000).stdout
            // Lines: "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP ..."
            linkOut.lineSequence().forEach { line ->
                val m = Regex("""^\d+:\s+([^:@]+)[@:].*?<([^>]*)>.*?(?:state\s+(\S+))?""").find(line.trim())
                    ?: Regex("""^\d+:\s+([^:@]+):\s+<([^>]*)>""").find(line.trim())
                if (m != null) {
                    val name = m.groupValues[1].trim()
                    val flags = m.groupValues.getOrElse(2) { "" }
                    val state = m.groupValues.getOrElse(3) { "" }
                    val up = flags.contains("UP") && (state.isEmpty() || state == "UP" || state == "UNKNOWN")
                    if (name.isNotEmpty()) {
                        ifaces.add(buildInterface(name, up, flags, addrMap[name]))
                    }
                }
            }
        }

        // Last-resort fallback if root discovery yielded nothing.
        if (ifaces.isEmpty()) {
            try {
                File("/proc/net/dev").readLines().drop(2).forEach { line ->
                    val name = line.trim().substringBefore(":").trim()
                    if (name.isNotEmpty()) ifaces.add(buildInterface(name, false, "", null))
                }
            } catch (_: Exception) {}
        }

        return ifaces.distinctBy { it.name }.sortedWith(
            compareBy({ interfaceOrder(it.type) }, { it.name })
        )
    }

    /** Map interface name -> first IPv4 address, via a single root `ip` call. */
    private fun readIpv4Addresses(): Map<String, String> {
        val out = RootShell.run("ip -o -4 addr show", timeoutMs = 15_000).stdout
        val map = mutableMapOf<String, String>()
        out.lineSequence().forEach { line ->
            // "23: wlan0    inet 192.168.1.50/24 brd ... scope global wlan0"
            val m = Regex("""^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/""").find(line.trim())
            if (m != null) map.putIfAbsent(m.groupValues[1], m.groupValues[2])
        }
        return map
    }

    private fun buildInterface(name: String, isUp: Boolean, flags: String, ipv4: String?): NetworkInterface {
        val type = when {
            name.startsWith("wlan") || name.startsWith("wifi") || name.startsWith("wl") -> InterfaceType.WIFI
            name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("ppp") -> InterfaceType.CELLULAR
            name == "lo" -> InterfaceType.LOOPBACK
            name.startsWith("eth") -> InterfaceType.ETHERNET
            name.startsWith("bt") || name.startsWith("bnep") -> InterfaceType.BLUETOOTH
            name.startsWith("tun") || name.startsWith("tap") -> InterfaceType.TUN
            name.startsWith("vpn") -> InterfaceType.VPN
            else -> InterfaceType.UNKNOWN
        }
        return NetworkInterface(
            name = name,
            displayName = friendlyName(name, type),
            type = type,
            isUp = isUp,
            ipv4 = ipv4,
            flags = flags,
        )
    }

    private fun friendlyName(name: String, type: InterfaceType) = when (type) {
        InterfaceType.WIFI -> "Wi-Fi ($name)"
        InterfaceType.CELLULAR -> "Cellular ($name)"
        InterfaceType.LOOPBACK -> "Loopback"
        InterfaceType.ETHERNET -> "Ethernet ($name)"
        InterfaceType.BLUETOOTH -> "Bluetooth ($name)"
        InterfaceType.TUN -> "Tunnel ($name)"
        InterfaceType.VPN -> "VPN ($name)"
        InterfaceType.UNKNOWN -> name
    }

    private fun interfaceOrder(t: InterfaceType) = when (t) {
        InterfaceType.WIFI -> 0; InterfaceType.CELLULAR -> 1; InterfaceType.ETHERNET -> 2
        InterfaceType.BLUETOOTH -> 3; InterfaceType.TUN -> 4; InterfaceType.VPN -> 5
        InterfaceType.LOOPBACK -> 6; InterfaceType.UNKNOWN -> 7
    }

    private fun buildCapabilities(hasRoot: Boolean, rootChecked: Boolean): List<CapabilityStatus> {
        val list = mutableListOf<CapabilityStatus>()

        // Standard group
        list += CapabilityStatus(
            label = "Rootless local VPN capture",
            detail = "Android VpnService TUN capture, device-wide; no root required",
            state = CapState.AVAILABLE,
            group = CapGroup.STANDARD,
        )
        list += CapabilityStatus(
            label = "Root access",
            detail = when {
                hasRoot -> "Magisk root detected — live interface capture available"
                rootChecked -> "su not found — reading and analysing captures still works; " +
                    "only live interface capture needs root"
                else -> "Not checked yet — tap Sources refresh, or start a rooted capture to request it"
            },
            state = if (hasRoot) CapState.AVAILABLE else if (rootChecked) CapState.UNAVAILABLE else CapState.UNKNOWN,
            group = CapGroup.ROOT,
        )
        val ifaces = _interfaces.value
        list += CapabilityStatus(
            label = "Network interfaces",
            detail = "${ifaces.size} interface(s) visible",
            state = if (ifaces.isNotEmpty()) CapState.AVAILABLE else CapState.UNAVAILABLE,
            group = CapGroup.STANDARD,
        )
        val wifiIfaces = ifaces.filter { it.type == InterfaceType.WIFI }
        list += CapabilityStatus(
            label = "Wi-Fi capture",
            detail = if (wifiIfaces.isNotEmpty()) "${wifiIfaces.map { it.name }.joinToString(", ")} available"
                     else "No Wi-Fi interfaces found",
            state = if (wifiIfaces.isNotEmpty() && hasRoot) CapState.AVAILABLE
                    else if (wifiIfaces.isNotEmpty()) CapState.REQUIRES_ROOT
                    else CapState.UNAVAILABLE,
            group = CapGroup.ROOT,
        )
        val cellIfaces = ifaces.filter { it.type == InterfaceType.CELLULAR }
        list += CapabilityStatus(
            label = "Cellular interface capture",
            detail = if (cellIfaces.isNotEmpty()) "${cellIfaces.map { it.name }.joinToString(", ")} visible"
                     else "No rmnet/cellular interfaces visible",
            state = if (cellIfaces.isNotEmpty() && hasRoot) CapState.AVAILABLE
                    else if (cellIfaces.isNotEmpty()) CapState.REQUIRES_ROOT
                    else CapState.UNAVAILABLE,
            group = CapGroup.ROOT,
        )
        list += CapabilityStatus(
            label = "RIL / modem logs",
            detail = if (hasRoot) "Collectable from radio log buffer — see Diagnostic sources"
                     else "Needs root to read the radio log buffer",
            state = if (hasRoot) CapState.AVAILABLE else CapState.REQUIRES_ROOT,
            group = CapGroup.ROOT,
        )
        list += CapabilityStatus(
            label = "Bluetooth HCI snoop log",
            detail = if (hasRoot) "Collectable & decoded as HCI/BLE — see Diagnostic sources"
                     else "Enable via Developer Options > Bluetooth HCI snoop log",
            state = if (hasRoot) CapState.AVAILABLE else CapState.UNAVAILABLE,
            group = CapGroup.ROOT,
        )
        list += CapabilityStatus(
            label = "Capture backend (dumpcap)",
            detail = if (hasRoot) "Bundled dumpcap ${TsharkBundle.WIRESHARK_VERSION} — writes pcapng via root"
                     else "Needs root: capturing from an interface requires CAP_NET_RAW",
            state = if (hasRoot) CapState.AVAILABLE else CapState.REQUIRES_ROOT,
            group = CapGroup.ROOT,
        )
        // tshark ships in the native library directory, which an unprivileged app is
        // allowed to execute from, so decode and analysis need no root at all.
        list += CapabilityStatus(
            label = "tshark / Wireshark decode",
            detail = "Bundled TShark ${TsharkBundle.WIRESHARK_VERSION} — " +
                "full Wireshark dissector engine, no root required",
            state = when {
                tsharkExecutable() -> CapState.AVAILABLE
                else -> CapState.UNAVAILABLE
            },
            group = CapGroup.STANDARD,
        )

        return list
    }
}
