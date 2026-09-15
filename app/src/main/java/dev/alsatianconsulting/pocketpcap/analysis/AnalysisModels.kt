package dev.alsatianconsulting.pocketpcap.analysis

import androidx.compose.runtime.Immutable

/** Scope badge shown by every analytical view. */
enum class AnalysisScope { WHOLE_CAPTURE, DISPLAY_FILTER }

@Immutable
data class CaptureAnalysis(
    val metadata: CaptureMetadata,
    val protocols: List<ProtocolStat> = emptyList(),
    val endpoints: List<AnalysisEndpoint> = emptyList(),
    val conversations: List<Conversation> = emptyList(),
    val issues: List<AnalysisIssue> = emptyList(),
    val dns: List<DnsTransaction> = emptyList(),
    val tls: List<TlsSession> = emptyList(),
    val http: List<HttpTransaction> = emptyList(),
    val timeline: List<TimelineBucket> = emptyList(),
    val packets: List<AnalysisPacket> = emptyList(),
    val contextualFilters: List<ContextualFilter> = emptyList(),
    val scope: AnalysisScope = AnalysisScope.WHOLE_CAPTURE,
) {
    companion object {
        val EMPTY = CaptureAnalysis(CaptureMetadata())
    }
}

@Immutable
data class CaptureMetadata(
    val filename: String = "",
    val sizeBytes: Long = 0,
    val packetCount: Long = 0,
    val durationSeconds: Double = 0.0,
    val firstTimestampEpoch: Double? = null,
    val lastTimestampEpoch: Double? = null,
    val linkLayerTypes: List<String> = emptyList(),
)

@Immutable
data class ProtocolStat(
    val name: String,
    val packets: Long,
    val bytes: Long,
    val percentage: Double,
    val filter: String,
)

@Immutable
data class AnalysisEndpoint(
    val address: String,
    val packets: Long,
    val bytes: Long,
    val sentPackets: Long,
    val sentBytes: Long,
    val receivedPackets: Long,
    val receivedBytes: Long,
    val tcpConnections: Int,
    val dnsRequests: Int,
    val retransmissions: Int,
    val filter: String,
)

enum class ConversationKind { TCP, UDP, IPV4, IPV6 }

@Immutable
data class Conversation(
    val id: String,
    val kind: ConversationKind,
    val endpointA: String,
    val endpointB: String,
    val portA: Int? = null,
    val portB: Int? = null,
    val packets: Long,
    val bytes: Long,
    val packetsAToB: Long,
    val bytesAToB: Long,
    val packetsBToA: Long,
    val bytesBToA: Long,
    val startSeconds: Double,
    val durationSeconds: Double,
    val streamIndex: Int? = null,
    val packetNumbers: List<Long> = emptyList(),
    val filter: String,
    val retransmissions: Int = 0,
)

enum class IssueSeverity { INFO, WARNING, ERROR }

@Immutable
data class AnalysisIssue(
    val id: String,
    val title: String,
    val detail: String,
    val category: String,
    val severity: IssueSeverity,
    val count: Int,
    val affectedEndpoints: List<String>,
    val conversationId: String? = null,
    val firstOccurrenceSeconds: Double,
    val packetNumbers: List<Long>,
    val filter: String,
)

@Immutable
data class DnsTransaction(
    val id: String,
    val timestampSeconds: Double,
    val client: String,
    val server: String,
    val queryName: String,
    val recordType: String,
    val result: String,
    val responseAddresses: List<String>,
    val responseCode: Int?,
    val latencyMs: Double?,
    val queryPacket: Long,
    val responsePacket: Long? = null,
    val streamIndex: Int? = null,
    val filter: String,
)

@Immutable
data class TlsSession(
    val id: String,
    val client: String,
    val server: String,
    val serverPort: Int?,
    val sni: String?,
    val version: String?,
    val alpn: String?,
    val cipher: String?,
    val certificateSubject: String?,
    val certificateIssuer: String?,
    val certificateNotBefore: String?,
    val certificateNotAfter: String?,
    val handshakeState: String,
    val alerts: List<String>,
    val tcpStream: Int,
    val packetCount: Long,
    val bytes: Long,
    val packetNumbers: List<Long>,
    val firstOccurrenceSeconds: Double,
    val filter: String,
)

@Immutable
data class HttpTransaction(
    val id: String,
    val requestTimestampSeconds: Double,
    val client: String,
    val server: String,
    val method: String,
    val hostname: String?,
    val uri: String,
    val statusCode: Int?,
    val contentType: String?,
    val contentLength: Long?,
    val latencyMs: Double?,
    val tcpStream: Int?,
    val requestPacket: Long,
    val responsePacket: Long? = null,
    val filter: String,
) {
    val url: String get() = if (uri.startsWith("http://") || uri.startsWith("https://")) uri
        else "http://${hostname.orEmpty()}${if (uri.startsWith('/')) uri else "/$uri"}"
}

@Immutable
data class TimelineBucket(
    val startSeconds: Double,
    val endSeconds: Double,
    val packets: Long,
    val bytes: Long,
    val retransmissions: Long,
    val dnsRequests: Long,
    val httpRequests: Long,
    val tcpResets: Long,
)

/** Compact packet evidence retained by the analysis cache and global search. */
@Immutable
data class AnalysisPacket(
    val number: Long,
    val timestampSeconds: Double,
    val source: String,
    val destination: String,
    val protocol: String,
    val length: Int,
    val info: String,
    val searchableText: String,
)

@Immutable
data class ContextualFilter(
    val label: String,
    val filter: String,
    val evidenceCount: Int,
)

enum class SearchEntity { PACKET, ENDPOINT, CONVERSATION, DNS, HTTP, TLS, ISSUE, STREAM, FIELD }

@Immutable
data class CaptureSearchResult(
    val entity: SearchEntity,
    val title: String,
    val subtitle: String,
    val filter: String,
    val packetNumber: Long? = null,
    val streamIndex: Int? = null,
)

enum class BookmarkType { PACKET, ENDPOINT, CONVERSATION, STREAM, ISSUE, DNS, HTTP, TLS }
