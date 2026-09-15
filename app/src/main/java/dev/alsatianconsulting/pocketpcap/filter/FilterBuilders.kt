package dev.alsatianconsulting.pocketpcap.filter

import dev.alsatianconsulting.pocketpcap.resolve.AddressUtil

/**
 * Maps a displayed protocol/endpoint to a Wireshark display filter. Used by the
 * click-to-filter interactions so a tap anywhere a protocol or address is shown
 * applies the corresponding filter.
 */
object FilterBuilders {

    /**
     * Convert a protocol string as shown in the UI (column, hierarchy, badge) into a
     * display-filter token. Handles versioned/aliased names: "TLSv1.2" → tls,
     * "HTTP/2" → http2, "ICMPv6" → icmpv6, "MDNS" → mdns. Returns null when the
     * protocol isn't filterable.
     */
    fun protocolToFilter(displayed: String): String? {
        val p = displayed.trim().lowercase()
        if (p.isEmpty() || p == "?") return null
        // Normalise common display variants to their filter token.
        return when {
            p.startsWith("tlsv") || p == "tls" || p == "ssl" -> "tls"
            p.startsWith("http/2") || p == "http2" -> "http2"
            p.startsWith("http/3") || p == "http3" -> "http3"
            p.startsWith("http") -> "http"
            p == "icmpv6" -> "icmpv6"
            p == "dhcpv6" -> "dhcpv6"
            p == "mdns" -> "mdns"
            p == "llmnr" -> "llmnr"
            p == "nbns" || p == "netbios" -> "nbns"
            p == "quic" -> "quic"
            else -> {
                // Take the leading token before any space/slash and keep it if it's a
                // valid catalog protocol (e.g. "DNS", "ARP", "TCP", "SMB2").
                val token = p.substringBefore('/').substringBefore(' ').trim()
                if (FilterFields.find(token)?.kind == SuggestionKind.PROTOCOL) token else token.ifEmpty { null }
            }
        }
    }

    /** The five endpoint filter actions (spec §2). */
    enum class EndpointAction { ALL, SOURCE, DESTINATION, CONVERSATION, SESSIONS }

    /**
     * Build the display filter for an endpoint action. [peer] is only used for
     * CONVERSATION (traffic strictly between [address] and [peer]).
     */
    fun endpointFilter(address: String, action: EndpointAction, peer: String? = null): String {
        val addr = address.trim()
        val all = AddressUtil.addrField(addr)
        val src = AddressUtil.srcField(addr)
        val dst = AddressUtil.dstField(addr)
        return when (action) {
            EndpointAction.ALL -> "$all == $addr"
            EndpointAction.SOURCE -> "$src == $addr"
            EndpointAction.DESTINATION -> "$dst == $addr"
            EndpointAction.SESSIONS -> "$all == $addr && (tcp || udp)"
            EndpointAction.CONVERSATION ->
                if (peer.isNullOrBlank()) "$all == $addr"
                else "$all == $addr && $all == ${peer.trim()}"
        }
    }
}
