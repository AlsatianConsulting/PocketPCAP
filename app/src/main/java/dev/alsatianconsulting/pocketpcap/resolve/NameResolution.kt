package dev.alsatianconsulting.pocketpcap.resolve

/** How resolved endpoints are rendered in the UI. */
enum class ResolveDisplayMode { ADDRESS, NAME_ADDRESS, NAME }

/** Where a resolved name came from (priority order, highest first). */
enum class NameSource { ALIAS, DEVICE, RDNS, OUI, NONE }

/**
 * The outcome of resolving one endpoint address. [name] is null when nothing better
 * than the raw address is known. [primary]/[secondary] are pre-formatted for a chosen
 * display mode by [NameFormat.label].
 */
data class ResolvedName(
    val address: String,
    val name: String?,
    val source: NameSource,
) {
    val hasName: Boolean get() = !name.isNullOrBlank()
}

/** Two-line label parts for an endpoint, derived from a [ResolvedName] + display mode. */
data class EndpointLabel(val primary: String, val secondary: String?)

object NameFormat {
    /** Format a resolved endpoint for the given display mode. */
    fun label(resolved: ResolvedName, mode: ResolveDisplayMode): EndpointLabel {
        val name = resolved.name?.takeIf { it.isNotBlank() }
            ?: return EndpointLabel(resolved.address, null)
        return when (mode) {
            ResolveDisplayMode.ADDRESS -> EndpointLabel(resolved.address, null)
            ResolveDisplayMode.NAME -> EndpointLabel(name, null)
            ResolveDisplayMode.NAME_ADDRESS -> EndpointLabel(name, resolved.address)
        }
    }
}

object AddressUtil {
    private val MAC_RE = Regex("^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
    private val IPV4_RE = Regex("^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$")

    fun isMacAddress(s: String): Boolean = MAC_RE.matches(s.trim())

    fun isIpv4(s: String): Boolean = IPV4_RE.matches(s.trim())

    fun isIpv6(s: String): Boolean {
        val t = s.trim()
        // Cheap heuristic: contains ':' but isn't a MAC (which uses ':' too).
        return t.contains(':') && !isMacAddress(t) && t.none { it == '.' && !t.contains("::ffff") }
    }

    fun isIpAddress(s: String): Boolean = isIpv4(s) || isIpv6(s)

    /**
     * True for an IPv4 address on a local network (RFC 1918 private ranges or
     * 169.254/16 link-local). NetBIOS/LLMNR queries are only meaningful for these.
     */
    /**
     * True for an address worth asking a third party about: globally routable unicast.
     *
     * The traffic map used to exclude only private IPv4 and link-local IPv6, which let
     * every multicast and broadcast address in a capture through - 224.0.0.251 (mDNS),
     * 239.255.255.250 (SSDP), 255.255.255.255, 0.0.0.0. Those can never have a location,
     * so each one was a wasted round trip and, worse, a needless disclosure of the
     * capture's contents to an outside service that could only answer 404.
     */
    fun isPublicRoutable(s: String): Boolean {
        val t = s.trim()
        if (!isIpAddress(t)) return false
        if (isIpv4(t)) {
            val o = t.split(".").map { it.toIntOrNull() ?: return false }
            if (o.size != 4 || o.any { it !in 0..255 }) return false
            return when {
                o[0] == 0 -> false                      // unspecified / "this network"
                o[0] == 10 -> false                     // RFC 1918
                o[0] == 127 -> false                    // loopback
                o[0] == 100 && o[1] in 64..127 -> false // RFC 6598 CGNAT
                o[0] == 169 && o[1] == 254 -> false     // link-local
                o[0] == 172 && o[1] in 16..31 -> false  // RFC 1918
                o[0] == 192 && o[1] == 0 && o[2] == 0 -> false   // IETF protocol assignments
                o[0] == 192 && o[1] == 0 && o[2] == 2 -> false   // TEST-NET-1
                o[0] == 192 && o[1] == 168 -> false     // RFC 1918
                o[0] == 198 && o[1] in 18..19 -> false  // benchmarking
                o[0] == 198 && o[1] == 51 && o[2] == 100 -> false // TEST-NET-2
                o[0] == 203 && o[1] == 0 && o[2] == 113 -> false  // TEST-NET-3
                o[0] >= 224 -> false                    // multicast, reserved, broadcast
                else -> true
            }
        }
        val lower = t.lowercase().substringBefore('%')
        return when {
            lower == "::" || lower == "::1" -> false
            lower.startsWith("fe80:") -> false          // link-local
            lower.startsWith("ff") -> false             // multicast
            lower.startsWith("fc") || lower.startsWith("fd") -> false // unique local
            lower.startsWith("2001:db8") -> false       // documentation
            else -> true
        }
    }

    fun isPrivateIpv4(s: String): Boolean {
        val t = s.trim()
        if (!isIpv4(t)) return false
        val o = t.split(".").map { it.toIntOrNull() ?: return false }
        return when {
            o[0] == 10 -> true
            o[0] == 192 && o[1] == 168 -> true
            o[0] == 172 && o[1] in 16..31 -> true
            o[0] == 169 && o[1] == 254 -> true
            else -> false
        }
    }

    /** The Wireshark filter field appropriate for this address kind. */
    fun addrField(s: String): String = if (isMacAddress(s)) "eth.addr" else "ip.addr"
    fun srcField(s: String): String = if (isMacAddress(s)) "eth.src" else "ip.src"
    fun dstField(s: String): String = if (isMacAddress(s)) "eth.dst" else "ip.dst"
}

/**
 * Parsed IEEE MAC vendor data, split by allocation size:
 *   - [m24] MA-L (24-bit OUI prefix)
 *   - [m28] MA-M (28-bit prefix)
 *   - [m36] MA-S / IAB (36-bit prefix)
 * Keys are upper-case hex of the masked prefix (6, 7 and 9 nibbles respectively).
 */
class OuiData(
    val m24: Map<String, String>,
    val m28: Map<String, String>,
    val m36: Map<String, String>,
) {
    val size: Int get() = m24.size + m28.size + m36.size

    companion object { val EMPTY = OuiData(emptyMap(), emptyMap(), emptyMap()) }
}

object OuiTable {
    private val SEP = Regex("[:.\\-]")

    /**
     * Parse a Wireshark `manuf`-style table. Each non-comment line is
     * `<prefix>[/<bits>]<tab><vendor>` where bits is 24 (default), 28 or 36 per the
     * IEEE allocation size. A legacy space-separated `<hex><space><vendor>` form is
     * also accepted (treated as a 24-bit OUI).
     */
    fun parse(lines: Sequence<String>): OuiData {
        val m24 = HashMap<String, String>(45_000)
        val m28 = HashMap<String, String>(6_000)
        val m36 = HashMap<String, String>(12_000)
        for (raw in lines) {
            if (raw.isEmpty() || raw[0] == '#') continue
            val prefixRaw: String
            val vendor: String
            if (raw.indexOf('\t') >= 0) {
                // manuf format: <prefix> \t <short> [\t <full name>] — prefer full name.
                val parts = raw.split('\t')
                prefixRaw = parts[0].trim()
                vendor = parts.drop(1).map { it.trim() }.lastOrNull { it.isNotEmpty() } ?: ""
            } else {
                // legacy space-separated: <hex> <vendor…>
                val sep = raw.indexOf(' ')
                if (sep <= 0) continue
                prefixRaw = raw.substring(0, sep).trim()
                vendor = raw.substring(sep + 1).trim()
            }
            if (prefixRaw.isEmpty() || vendor.isEmpty()) continue

            var bits = 24
            var hexPart = prefixRaw
            val slash = prefixRaw.indexOf('/')
            if (slash >= 0) {
                bits = prefixRaw.substring(slash + 1).trim().toIntOrNull() ?: 24
                hexPart = prefixRaw.substring(0, slash)
            }
            val hex = hexPart.replace(SEP, "").uppercase()
            val nibbles = bits / 4
            if (hex.length < nibbles || nibbles < 6) continue
            val key = hex.substring(0, nibbles)
            when (bits) {
                36 -> m36[key] = vendor
                28 -> m28[key] = vendor
                else -> m24[key] = vendor
            }
        }
        return OuiData(m24, m28, m36)
    }

    /** Vendor for a MAC, most-specific block first (36-bit, then 28-bit, then 24-bit). */
    fun lookup(data: OuiData, mac: String): String? {
        val hex = mac.replace(SEP, "").uppercase()
        if (hex.length < 6) return null
        if (hex.length >= 9) data.m36[hex.substring(0, 9)]?.let { return it }
        if (hex.length >= 7) data.m28[hex.substring(0, 7)]?.let { return it }
        return data.m24[hex.substring(0, 6)]
    }
}
