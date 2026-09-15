package dev.alsatianconsulting.pocketpcap.capture

import dev.alsatianconsulting.pocketpcap.model.PacketColor
import dev.alsatianconsulting.pocketpcap.model.PacketSummary
import java.net.InetAddress

data class RootlessPacketDetails(
    val version: Int,
    val src: String,
    val dst: String,
    val protocolNumber: Int,
    val protocol: String,
    val length: Int,
    val srcPort: Int? = null,
    val dstPort: Int? = null,
    val info: String,
    val colorHint: PacketColor,
)

object RootlessPacketParser {

    fun parse(packet: ByteArray, length: Int): RootlessPacketDetails? {
        if (length < 1) return null
        return when ((packet[0].toInt() ushr 4) and 0x0F) {
            4 -> parseIpv4(packet, length)
            6 -> parseIpv6(packet, length)
            else -> null
        }
    }

    fun summary(packetNumber: Long, startMs: Long, nowMs: Long, details: RootlessPacketDetails): PacketSummary =
        PacketSummary(
            number = packetNumber,
            timestampUs = (nowMs - startMs) * 1000L,
            src = details.src,
            dst = details.dst,
            protocol = details.protocol,
            length = details.length,
            info = details.info,
            colorHint = details.colorHint,
        )

    private fun parseIpv4(packet: ByteArray, length: Int): RootlessPacketDetails? {
        if (length < 20) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null
        val totalLen = u16(packet, 2).takeIf { it > 0 && it <= length } ?: length
        val proto = packet[9].toInt() and 0xFF
        val src = ipv4(packet, 12)
        val dst = ipv4(packet, 16)
        return transportDetails(4, src, dst, proto, packet, ihl, totalLen)
    }

    private fun parseIpv6(packet: ByteArray, length: Int): RootlessPacketDetails? {
        if (length < 40) return null
        val payloadLen = u16(packet, 4)
        val totalLen = minOf(length, 40 + payloadLen)
        val proto = packet[6].toInt() and 0xFF
        val src = ipv6(packet, 8)
        val dst = ipv6(packet, 24)
        return transportDetails(6, src, dst, proto, packet, 40, totalLen)
    }

    private fun transportDetails(
        version: Int,
        src: String,
        dst: String,
        proto: Int,
        packet: ByteArray,
        transportOffset: Int,
        length: Int,
    ): RootlessPacketDetails {
        val srcPort = if (proto == 6 || proto == 17) port(packet, transportOffset, length) else null
        val dstPort = if (proto == 6 || proto == 17) port(packet, transportOffset + 2, length) else null
        val base = when (proto) {
            6 -> "TCP"
            17 -> "UDP"
            1 -> "ICMP"
            58 -> "ICMPv6"
            else -> "IP$version"
        }
        val appProto = when {
            proto == 17 && (srcPort == 53 || dstPort == 53) -> "DNS"
            proto == 6 && (srcPort == 80 || dstPort == 80) -> "HTTP"
            proto == 6 && (srcPort == 443 || dstPort == 443) -> "TLS"
            proto == 17 && (srcPort == 443 || dstPort == 443) -> "QUIC"
            else -> base
        }
        val portText = if (srcPort != null && dstPort != null) " $srcPort -> $dstPort" else ""
        val info = "$src -> $dst$portText"
        return RootlessPacketDetails(
            version = version,
            src = src,
            dst = dst,
            protocolNumber = proto,
            protocol = appProto,
            length = length,
            srcPort = srcPort,
            dstPort = dstPort,
            info = info,
            colorHint = when (appProto) {
                "TCP" -> PacketColor.TCP
                "UDP" -> PacketColor.UDP
                "DNS" -> PacketColor.DNS
                "HTTP" -> PacketColor.HTTP
                "TLS", "QUIC" -> PacketColor.TLS
                "ICMP", "ICMPv6" -> PacketColor.ICMP
                else -> PacketColor.DEFAULT
            },
        )
    }

    private fun port(packet: ByteArray, offset: Int, length: Int): Int? =
        if (offset + 1 < length) u16(packet, offset) else null

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

    private fun ipv4(packet: ByteArray, offset: Int): String =
        (0 until 4).joinToString(".") { (packet[offset + it].toInt() and 0xFF).toString() }

    private fun ipv6(packet: ByteArray, offset: Int): String =
        runCatching { InetAddress.getByAddress(packet.copyOfRange(offset, offset + 16)).hostAddress }
            .getOrDefault("::")
}

class RootlessPacketFilter(expr: String) {
    private val text = expr.trim().lowercase()
    private val port = Regex("""(?:^|\s)(?:src\s+|dst\s+)?port\s+(\d+)(?:\s|$)""")
        .find(text)?.groupValues?.getOrNull(1)?.toIntOrNull()
    private val srcHost = Regex("""(?:^|\s)(?:src\s+host|ip\.src\s*==)\s+([0-9a-fA-F:.]+)""")
        .find(expr)?.groupValues?.getOrNull(1)
    private val dstHost = Regex("""(?:^|\s)(?:dst\s+host|ip\.dst\s*==)\s+([0-9a-fA-F:.]+)""")
        .find(expr)?.groupValues?.getOrNull(1)
    private val host = Regex("""(?:^|\s)(?:host|ip\.addr\s*==)\s+([0-9a-fA-F:.]+)""")
        .find(expr)?.groupValues?.getOrNull(1)

    fun accepts(packet: RootlessPacketDetails): Boolean {
        if (text.isBlank()) return true
        if (host != null && packet.src != host && packet.dst != host) return false
        if (srcHost != null && packet.src != srcHost) return false
        if (dstHost != null && packet.dst != dstHost) return false
        if (port != null && packet.srcPort != port && packet.dstPort != port) return false
        if ("tcp" in text && packet.protocolNumber != 6) return false
        if ("udp" in text && packet.protocolNumber != 17) return false
        if ("icmp6" in text && packet.protocolNumber != 58) return false
        if (Regex("""(^|\s)icmp(\s|$)""").containsMatchIn(text) && packet.protocolNumber != 1) return false
        if ("dns" in text && packet.srcPort != 53 && packet.dstPort != 53) return false
        if ("http" in text && packet.srcPort != 80 && packet.dstPort != 80) return false
        if (("tls" in text || "https" in text) && packet.srcPort != 443 && packet.dstPort != 443) return false
        return true
    }
}
