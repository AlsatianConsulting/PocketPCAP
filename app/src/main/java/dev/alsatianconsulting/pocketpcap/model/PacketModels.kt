package dev.alsatianconsulting.pocketpcap.model

import androidx.compose.runtime.Immutable

@Immutable
data class NetworkInterface(
    val name: String,
    val displayName: String,
    val type: InterfaceType,
    val isUp: Boolean,
    val ipv4: String? = null,
    val ipv6: String? = null,
    val flags: String = "",
)

enum class InterfaceType {
    WIFI, CELLULAR, LOOPBACK, ETHERNET, BLUETOOTH, TUN, VPN, UNKNOWN
}

@Immutable
data class CapabilityStatus(
    val label: String,
    val detail: String,
    val state: CapState,
    val group: CapGroup,
)

enum class CapState { AVAILABLE, UNAVAILABLE, UNKNOWN, REQUIRES_ROOT }
enum class CapGroup { STANDARD, ROOT }

@Immutable
data class CaptureSession(
    val id: String,
    val interfaceName: String,
    val startTime: Long,
    val packetCount: Long = 0L,
    val byteCount: Long = 0L,
    val outputPath: String,
    val filter: String = "",
    val state: CaptureState = CaptureState.IDLE,
)

enum class CaptureState { IDLE, STARTING, RUNNING, PAUSED, STOPPING, STOPPED, ERROR }

@Immutable
data class PacketSummary(
    val number: Long,
    val timestampUs: Long,
    val src: String,
    val dst: String,
    val protocol: String,
    val length: Int,
    val info: String,
    val colorHint: PacketColor = PacketColor.DEFAULT,
)

enum class PacketColor { DEFAULT, TCP, UDP, DNS, HTTP, TLS, ARP, ICMP, BT, CELLULAR }

@Immutable
data class DecodeTree(
    val nodes: List<DecodeNode>
)

@Immutable
data class DecodeNode(
    val label: String,
    val value: String = "",
    val byteOffset: Int = -1,
    val byteLength: Int = 0,
    val children: List<DecodeNode> = emptyList(),
    val isExpanded: Boolean = false,
    // Wireshark filter field name (e.g. "tcp.port") + its raw value, when this node
    // is a dissected field. Enables "Apply as filter" / "Copy field" context actions.
    val fieldName: String = "",
    val fieldValue: String = "",
    // Optional plain-language explanation shown under technical sections (e.g. for
    // Bluetooth HCI/BLE layers that are otherwise opaque to non-experts).
    val explanation: String = "",
)

@Immutable
data class RawBytes(
    val data: ByteArray,
) {
    fun hexLines(): List<HexLine> {
        return data.toList().chunked(16).mapIndexed { idx, chunk ->
            val offset = idx * 16
            val hex = chunk.joinToString(" ") { "%02X".format(it) }.padEnd(47)
            val ascii = chunk.map { b ->
                val c = (b.toInt() and 0xFF).toChar()
                if (c.code in 32..126) c else '.'
            }.joinToString("")
            HexLine(offset, hex, ascii)
        }
    }

    override fun equals(other: Any?) = other is RawBytes && data.contentEquals(other.data)
    override fun hashCode() = data.contentHashCode()
}

data class HexLine(val offset: Int, val hex: String, val ascii: String)

data class CaptureFile(
    val name: String,
    val path: String,
    val sizeBytes: Long,
    val createdAt: Long,
    val packetCount: Long,
)

@Immutable
data class DynamicPacketColumn(
    val field: String,
    val values: Map<Long, String>,
)

/** A preserved raw diagnostic log (e.g. RIL/modem logcat snapshot). */
data class DiagnosticLog(
    val name: String,
    val path: String,
    val sizeBytes: Long,
    val createdAt: Long,
)

/** One node of a Wireshark-style protocol hierarchy (Statistics → Protocol Hierarchy). */
@Immutable
data class ProtoHierarchyNode(
    val name: String,
    val depth: Int,
    val frames: Long,
    val bytes: Long,
    val percentPackets: Double = 0.0,
)

/** A traffic endpoint (Statistics → Endpoints): an address with traffic counters. */
@Immutable
data class Endpoint(
    val address: String,
    val packets: Long,
    val bytes: Long,
    val txPackets: Long,
    val txBytes: Long,
    val rxPackets: Long,
    val rxBytes: Long,
)

@Immutable
data class TrafficMapState(
    val loading: Boolean = false,
    val sourceAddress: String? = null,
    val sourceLabel: String = "Current public IP",
    val sourceLatitude: Double? = null,
    val sourceLongitude: Double? = null,
    val routes: List<TrafficMapRoute> = emptyList(),
    val error: String? = null,
)

@Immutable
data class TrafficMapRoute(
    val address: String,
    val label: String,
    val packets: Long,
    val bytes: Long,
    val txPackets: Long,
    val txBytes: Long,
    val rxPackets: Long,
    val rxBytes: Long,
    val trafficType: String,
    val city: String? = null,
    val region: String? = null,
    val country: String? = null,
    val latitude: Double,
    val longitude: Double,
)

/** Identifies a followable stream for one packet. */
@Immutable
data class StreamRef(
    val tcpStream: Int? = null,
    val udpStream: Int? = null,
) {
    val hasAny get() = tcpStream != null || udpStream != null
}

/** A reconstructed follow-stream conversation. */
@Immutable
data class FollowStream(
    val protocol: String,        // TCP / UDP / TLS / HTTP
    val streamIndex: Int,
    val nodeA: String,
    val nodeB: String,
    val segments: List<StreamSegment>,
    val rawText: String,
)

@Immutable
data class StreamSegment(
    val fromA: Boolean,          // true = nodeA → nodeB (client→server)
    val text: String,
    /** Exact payload bytes from tshark's follow-stream raw output, lower-case hex. */
    val rawHex: String = text.encodeToByteArray().joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    },
)

/** A reconstructed exported object (Wireshark: File → Export Objects). */
data class ExportedObject(
    val name: String,
    val path: String,
    val sizeBytes: Long,
)

/** A parsed RIL / radio log entry. */
@Immutable
data class RilLogEntry(
    val timestamp: String,
    val level: String,          // V/D/I/W/E
    val tag: String,
    val message: String,
    val kind: RilKind,
)

enum class RilKind { REQUEST, RESPONSE, UNSOL, OTHER }
