package dev.alsatianconsulting.pocketpcap.analysis

import dev.alsatianconsulting.pocketpcap.filter.FilterFields

/** In-memory, entity-grouped search over the cached whole-capture analysis. */
object CaptureSearch {
    fun search(analysis: CaptureAnalysis, query: String, aliases: Map<String, String> = emptyMap()): List<CaptureSearchResult> {
        val q = query.trim()
        if (q.isEmpty()) return emptyList()
        val needle = q.lowercase()
        val out = LinkedHashMap<String, CaptureSearchResult>()
        fun add(result: CaptureSearchResult) {
            out.putIfAbsent("${result.entity}:${result.title}:${result.packetNumber}", result)
        }
        fun has(vararg values: Any?): Boolean = values.any { it?.toString()?.lowercase()?.contains(needle) == true }

        analysis.endpoints.filter { has(it.address, aliases[it.address]) }.take(30).forEach {
            add(CaptureSearchResult(SearchEntity.ENDPOINT, aliases[it.address] ?: it.address,
                "${it.packets} packets · ${it.bytes} bytes", it.filter))
        }
        analysis.conversations.filter { has(it.kind, it.endpointA, it.endpointB, it.portA, it.portB, it.streamIndex) }
            .take(30).forEach {
                add(CaptureSearchResult(SearchEntity.CONVERSATION,
                    "${it.endpointA}:${it.portA ?: "*"} ↔ ${it.endpointB}:${it.portB ?: "*"}",
                    "${it.kind} · ${it.packets} packets · ${it.bytes} bytes", it.filter,
                    it.packetNumbers.firstOrNull(), it.streamIndex))
            }
        analysis.dns.filter { has(it.queryName, it.client, it.server, it.recordType, it.result, it.responseAddresses.joinToString()) }
            .take(40).forEach {
                add(CaptureSearchResult(SearchEntity.DNS, it.queryName,
                    "${it.recordType} · ${it.result}", it.filter, it.queryPacket, it.streamIndex))
            }
        analysis.http.filter { has(it.method, it.hostname, it.uri, it.statusCode, it.contentType, it.url) }
            .take(40).forEach {
                add(CaptureSearchResult(SearchEntity.HTTP, "${it.method} ${it.hostname.orEmpty()}${it.uri}",
                    it.statusCode?.toString() ?: "No response", it.filter, it.requestPacket, it.tcpStream))
            }
        analysis.tls.filter { has(it.client, it.server, it.sni, it.version, it.alpn, it.cipher, it.certificateSubject) }
            .take(30).forEach {
                add(CaptureSearchResult(SearchEntity.TLS, it.sni ?: "${it.server}:${it.serverPort}",
                    listOfNotNull(it.version, it.alpn, it.cipher).joinToString(" · "), it.filter,
                    it.packetNumbers.firstOrNull(), it.tcpStream))
            }
        analysis.issues.filter { has(it.title, it.detail, it.category, it.affectedEndpoints.joinToString()) }
            .take(30).forEach {
                add(CaptureSearchResult(SearchEntity.ISSUE, it.title, it.detail, it.filter,
                    it.packetNumbers.firstOrNull()))
            }
        analysis.packets.filter { has(it.number, it.source, it.destination, it.protocol, it.info, it.searchableText) }
            .take(60).forEach {
                add(CaptureSearchResult(SearchEntity.PACKET, "Packet #${it.number} · ${it.protocol}",
                    "${it.source} → ${it.destination} · ${it.info}", "frame.number == ${it.number}", it.number))
            }
        FilterFields.all.asSequence().filter { has(it.token, it.detail) }.take(20).forEach {
            add(CaptureSearchResult(SearchEntity.FIELD, it.token, it.detail, it.token))
        }
        return out.values.toList()
    }
}
