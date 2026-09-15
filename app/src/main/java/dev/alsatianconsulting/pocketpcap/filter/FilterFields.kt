package dev.alsatianconsulting.pocketpcap.filter

/** What a suggestion represents — drives its icon/colour and selection behaviour. */
enum class SuggestionKind { PROTOCOL, FIELD, ENDPOINT, HOSTNAME, ALIAS, STREAM, RECENT, SAVED }

/** A static, Wireshark-compatible filter token (protocol name or dotted field). */
data class FilterField(val token: String, val kind: SuggestionKind, val detail: String = "")

/**
 * A curated catalog of Wireshark display-filter protocols and fields. These power
 * autocomplete even when the protocol isn't present in the current capture — the
 * tokens are valid tshark display-filter syntax. This is intentionally a high-value
 * subset (not the full ~250k-field dictionary) to stay small and fast on-device.
 */
object FilterFields {

    private fun proto(name: String, detail: String) = FilterField(name, SuggestionKind.PROTOCOL, detail)
    private fun field(token: String, detail: String = "") = FilterField(token, SuggestionKind.FIELD, detail)

    val all: List<FilterField> = buildList {
        // --- Protocols --------------------------------------------------------
        add(proto("ip", "IPv4"))
        add(proto("ipv6", "IPv6"))
        add(proto("eth", "Ethernet"))
        add(proto("arp", "Address Resolution Protocol"))
        add(proto("tcp", "Transmission Control Protocol"))
        add(proto("udp", "User Datagram Protocol"))
        add(proto("icmp", "ICMP"))
        add(proto("icmpv6", "ICMPv6"))
        add(proto("http", "HTTP"))
        add(proto("http2", "HTTP/2"))
        add(proto("http3", "HTTP/3"))
        add(proto("tls", "Transport Layer Security"))
        add(proto("ssl", "TLS/SSL (legacy alias)"))
        add(proto("quic", "QUIC"))
        add(proto("dns", "Domain Name System"))
        add(proto("mdns", "Multicast DNS"))
        add(proto("llmnr", "Link-Local Multicast Name Resolution"))
        add(proto("nbns", "NetBIOS Name Service"))
        add(proto("dhcp", "DHCP (bootp)"))
        add(proto("dhcpv6", "DHCPv6"))
        add(proto("bootp", "BOOTP/DHCP"))
        add(proto("smb", "SMB"))
        add(proto("smb2", "SMB2/3"))
        add(proto("ftp", "File Transfer Protocol"))
        add(proto("ftp-data", "FTP data channel"))
        add(proto("tftp", "Trivial FTP"))
        add(proto("smtp", "Simple Mail Transfer"))
        add(proto("pop", "POP3"))
        add(proto("imap", "IMAP"))
        add(proto("ssh", "Secure Shell"))
        add(proto("telnet", "Telnet"))
        add(proto("ntp", "Network Time Protocol"))
        add(proto("snmp", "SNMP"))
        add(proto("sip", "Session Initiation Protocol"))
        add(proto("rtp", "Real-time Transport"))
        add(proto("rtcp", "RTP Control Protocol"))
        add(proto("ldap", "LDAP"))
        add(proto("kerberos", "Kerberos"))
        add(proto("radius", "RADIUS"))
        add(proto("igmp", "Internet Group Management"))
        add(proto("sctp", "Stream Control Transmission"))
        add(proto("gre", "Generic Routing Encapsulation"))
        add(proto("esp", "IPsec ESP"))
        add(proto("ah", "IPsec AH"))
        add(proto("ospf", "OSPF"))
        add(proto("bgp", "Border Gateway Protocol"))
        add(proto("stp", "Spanning Tree"))
        add(proto("vlan", "802.1Q VLAN"))
        add(proto("wg", "WireGuard"))
        add(proto("syslog", "Syslog"))
        add(proto("vxlan", "VXLAN"))
        add(proto("bthci_cmd", "Bluetooth HCI Command"))
        add(proto("bthci_evt", "Bluetooth HCI Event"))
        add(proto("btatt", "Bluetooth ATT"))
        add(proto("btle", "Bluetooth Low Energy"))

        // --- Frame / Ethernet -------------------------------------------------
        add(field("frame.number", "Packet number"))
        add(field("frame.len", "Frame length"))
        add(field("frame.time", "Capture time"))
        add(field("frame.time_relative", "Time since first frame"))
        add(field("frame.protocols", "Protocol stack"))
        add(field("eth.addr", "MAC address (src or dst)"))
        add(field("eth.src", "Source MAC"))
        add(field("eth.dst", "Destination MAC"))
        add(field("eth.type", "EtherType"))

        // --- IP ---------------------------------------------------------------
        add(field("ip.addr", "IPv4 address (src or dst)"))
        add(field("ip.src", "Source IPv4"))
        add(field("ip.dst", "Destination IPv4"))
        add(field("ip.proto", "IP protocol number"))
        add(field("ip.len", "Total length"))
        add(field("ip.ttl", "Time to live"))
        add(field("ip.flags", "IP flags"))
        add(field("ip.id", "Identification"))
        add(field("ipv6.addr", "IPv6 address (src or dst)"))
        add(field("ipv6.src", "Source IPv6"))
        add(field("ipv6.dst", "Destination IPv6"))

        // --- TCP / UDP --------------------------------------------------------
        add(field("tcp.port", "TCP port (src or dst)"))
        add(field("tcp.srcport", "TCP source port"))
        add(field("tcp.dstport", "TCP destination port"))
        add(field("tcp.flags", "TCP flags"))
        add(field("tcp.flags.syn", "SYN flag"))
        add(field("tcp.flags.ack", "ACK flag"))
        add(field("tcp.flags.reset", "RST flag"))
        add(field("tcp.seq", "Sequence number"))
        add(field("tcp.ack", "Acknowledgement number"))
        add(field("tcp.stream", "TCP stream index"))
        add(field("tcp.len", "TCP segment length"))
        add(field("tcp.analysis.retransmission", "Retransmission"))
        add(field("udp.port", "UDP port (src or dst)"))
        add(field("udp.srcport", "UDP source port"))
        add(field("udp.dstport", "UDP destination port"))
        add(field("udp.stream", "UDP stream index"))
        add(field("udp.length", "UDP length"))

        // --- DNS --------------------------------------------------------------
        add(field("dns.qry.name", "Query name"))
        add(field("dns.qry.type", "Query type"))
        add(field("dns.flags", "DNS flags"))
        add(field("dns.flags.response", "Is response"))
        add(field("dns.a", "A record answer"))
        add(field("dns.aaaa", "AAAA record answer"))
        add(field("dns.resp.name", "Response name"))
        add(field("dns.id", "Transaction ID"))

        // --- HTTP -------------------------------------------------------------
        add(field("http.host", "Host header"))
        add(field("http.request.method", "Request method"))
        add(field("http.request.uri", "Request URI"))
        add(field("http.request.full_uri", "Full request URI"))
        add(field("http.response.code", "Response status code"))
        add(field("http.user_agent", "User-Agent"))
        add(field("http.content_type", "Content-Type"))
        add(field("http.cookie", "Cookie"))
        add(field("http.referer", "Referer"))

        // --- TLS / QUIC -------------------------------------------------------
        add(field("tls.handshake.type", "Handshake message type"))
        add(field("tls.handshake.extensions_server_name", "SNI (server name)"))
        add(field("tls.record.version", "Record version"))
        add(field("tls.alert_message", "Alert"))
        add(field("quic.connection.id", "QUIC connection ID"))

        // --- DHCP -------------------------------------------------------------
        add(field("dhcp.option.dhcp", "DHCP message type"))
        add(field("dhcp.option.hostname", "Requested hostname"))
        add(field("dhcp.option.requested_ip_address", "Requested IP"))

        // --- ICMP -------------------------------------------------------------
        add(field("icmp.type", "ICMP type"))
        add(field("icmp.code", "ICMP code"))

        // --- ARP --------------------------------------------------------------
        add(field("arp.src.proto_ipv4", "Sender IP"))
        add(field("arp.dst.proto_ipv4", "Target IP"))
        add(field("arp.opcode", "ARP opcode"))
    }

    /** Just the protocol tokens (for the "tap a protocol" → filter mapping sanity). */
    val protocols: List<String> = all.filter { it.kind == SuggestionKind.PROTOCOL }.map { it.token }

    private val byToken: Map<String, FilterField> = all.associateBy { it.token }

    fun find(token: String): FilterField? = byToken[token.lowercase()]
}
