package dev.alsatianconsulting.pocketpcap.analysis

import java.util.Locale

/**
 * Converts one tabular tshark pass into PocketPCAP's cached analysis graph.
 *
 * The parser is Android-free so fixture output from the same bundled tshark can be
 * regression-tested on the JVM. Empty/unknown fields remain unavailable; no packet
 * facts are guessed.
 */
object CaptureAnalysisParser {
    val fields = listOf(
        "frame.number", "frame.time_epoch", "frame.time_relative", "frame.len", "frame.encap_type",
        "eth.src", "eth.dst", "wlan.sa", "wlan.da", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "_ws.col.Protocol", "_ws.col.Info",
        "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.len",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
        "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
        "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
        "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment", "tcp.analysis.zero_window",
        "udp.srcport", "udp.dstport", "udp.stream",
        "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa",
        "dns.flags.rcode", "dns.time",
        "http.request.method", "http.host", "http.request.uri", "http.response.code",
        "http.content_type", "http.content_length", "http.time", "http.request_in", "http.response_in",
        "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
        "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.record.version", "tls.handshake.ciphersuite",
        "tls.alert_message.desc", "tls.alert_message.level", "tls.handshake.type",
        "x509af.notBefore", "x509af.notAfter", "x509af.notBeforeTime", "x509af.notAfterTime",
        "x509sat.printableString", "x509sat.uTF8String",
        "_ws.malformed", "icmp.type.error", "icmpv6.type.error",
    )

    private val index = fields.withIndex().associate { it.value to it.index }

    fun parse(
        text: String,
        filename: String,
        sizeBytes: Long,
        scope: AnalysisScope = AnalysisScope.WHOLE_CAPTURE,
    ): CaptureAnalysis {
        val rows = text.lineSequence().mapNotNull(::parseRow).toList()
        if (rows.isEmpty()) return CaptureAnalysis(CaptureMetadata(filename, sizeBytes), scope = scope)

        val firstEpoch = rows.mapNotNull { it.double("frame.time_epoch") }.minOrNull()
        val lastEpoch = rows.mapNotNull { it.double("frame.time_epoch") }.maxOrNull()
        val duration = rows.maxOfOrNull { it.relative }?.coerceAtLeast(0.0) ?: 0.0
        val totalBytes = rows.sumOf { it.length.toLong() }
        val metadata = CaptureMetadata(
            filename = filename,
            sizeBytes = sizeBytes,
            packetCount = rows.size.toLong(),
            durationSeconds = duration,
            firstTimestampEpoch = firstEpoch,
            lastTimestampEpoch = lastEpoch,
            linkLayerTypes = rows.mapNotNull { linkType(it.value("frame.encap_type")) }.distinct(),
        )
        val conversations = buildConversations(rows)
        val dns = buildDns(rows)
        val http = buildHttp(rows)
        val tls = buildTls(rows)
        val issues = buildIssues(rows, conversations, dns, http, tls)
        val endpoints = buildEndpoints(rows, conversations, dns, issues)
        val protocols = rows.groupBy { it.protocol.ifBlank { "Unknown" } }.map { (name, packets) ->
            val bytes = packets.sumOf { it.length.toLong() }
            ProtocolStat(name, packets.size.toLong(), bytes,
                if (totalBytes > 0) bytes * 100.0 / totalBytes else 0.0, protocolFilter(name))
        }.sortedByDescending { it.bytes }
        val packets = rows.map { row ->
            AnalysisPacket(row.number, row.relative, row.src, row.dst, row.protocol, row.length,
                row.info, row.searchText())
        }
        val timeline = buildTimeline(rows, duration)
        val analysis = CaptureAnalysis(metadata, protocols, endpoints, conversations, issues, dns, tls, http,
            timeline, packets, scope = scope)
        return analysis.copy(contextualFilters = contextualFilters(analysis))
    }

    private data class Row(val cols: List<String>) {
        fun value(field: String): String = cols.getOrElse(index.getValue(field)) { "" }.trim()
        fun values(field: String): List<String> = value(field).split('|').map(String::trim).filter(String::isNotEmpty)
        fun long(field: String): Long? = value(field).substringBefore('|').toLongOrNull()
        fun int(field: String): Int? = long(field)?.toInt()
        fun double(field: String): Double? = value(field).substringBefore('|').toDoubleOrNull()
        fun present(field: String): Boolean = value(field).isNotEmpty()
        val number get() = long("frame.number") ?: 0L
        val relative get() = double("frame.time_relative") ?: 0.0
        val length get() = int("frame.len") ?: 0
        val protocol get() = value("_ws.col.Protocol")
        val info get() = value("_ws.col.Info")
        val src get() = value("ip.src").ifBlank { value("ipv6.src") }.ifBlank { value("eth.src") }.ifBlank { value("wlan.sa") }
        val dst get() = value("ip.dst").ifBlank { value("ipv6.dst") }.ifBlank { value("eth.dst") }.ifBlank { value("wlan.da") }
        val isIpv6 get() = value("ipv6.src").isNotBlank()
        fun searchText(): String = fields.asSequence().map(::value).filter(String::isNotBlank)
            .joinToString(" ").take(2048)
    }

    private fun parseRow(line: String): Row? {
        if (line.isBlank()) return null
        val cols = line.split('\t').toMutableList()
        while (cols.size < fields.size) cols += ""
        val row = Row(cols)
        return row.takeIf { it.number > 0 }
    }

    private data class ConvBuilder(
        val kind: ConversationKind,
        val id: String,
        val a: String,
        val b: String,
        val portA: Int?,
        val portB: Int?,
        val stream: Int?,
        var packets: Long = 0,
        var bytes: Long = 0,
        var packetsAB: Long = 0,
        var bytesAB: Long = 0,
        var packetsBA: Long = 0,
        var bytesBA: Long = 0,
        var retransmissions: Int = 0,
        var start: Double = Double.MAX_VALUE,
        var end: Double = 0.0,
        val refs: MutableList<Long> = mutableListOf(),
    )

    private fun buildConversations(rows: List<Row>): List<Conversation> {
        val builders = linkedMapOf<String, ConvBuilder>()
        fun add(row: Row, kind: ConversationKind, srcPort: Int?, dstPort: Int?, stream: Int?) {
            if (row.src.isBlank() || row.dst.isBlank()) return
            val streamKey = if (stream != null) "stream:$stream" else canonicalKey(row.src, srcPort, row.dst, dstPort)
            val key = "$kind:$streamKey"
            val b = builders.getOrPut(key) {
                ConvBuilder(kind, key, row.src, row.dst, srcPort, dstPort, stream)
            }
            val fromA = row.src == b.a && (b.portA == null || srcPort == b.portA)
            b.packets++; b.bytes += row.length
            if (fromA) { b.packetsAB++; b.bytesAB += row.length } else { b.packetsBA++; b.bytesBA += row.length }
            if (kind == ConversationKind.TCP && row.present("tcp.analysis.retransmission")) b.retransmissions++
            b.start = minOf(b.start, row.relative); b.end = maxOf(b.end, row.relative)
            if (b.refs.size < 500) b.refs += row.number
        }
        rows.forEach { row ->
            val tcpStream = row.int("tcp.stream")
            val udpStream = row.int("udp.stream")
            if (tcpStream != null) add(row, ConversationKind.TCP, row.int("tcp.srcport"), row.int("tcp.dstport"), tcpStream)
            if (udpStream != null) add(row, ConversationKind.UDP, row.int("udp.srcport"), row.int("udp.dstport"), udpStream)
            if (row.value("ip.src").isNotBlank()) add(row, ConversationKind.IPV4, null, null, null)
            if (row.value("ipv6.src").isNotBlank()) add(row, ConversationKind.IPV6, null, null, null)
        }
        return builders.values.map { b ->
            val filter = when {
                b.kind == ConversationKind.TCP && b.stream != null -> "tcp.stream == ${b.stream}"
                b.kind == ConversationKind.UDP && b.stream != null -> "udp.stream == ${b.stream}"
                b.kind == ConversationKind.IPV6 -> "ipv6.addr == ${b.a} && ipv6.addr == ${b.b}"
                else -> "ip.addr == ${b.a} && ip.addr == ${b.b}"
            }
            Conversation(b.id, b.kind, b.a, b.b, b.portA, b.portB, b.packets, b.bytes,
                b.packetsAB, b.bytesAB, b.packetsBA, b.bytesBA, b.start,
                (b.end - b.start).coerceAtLeast(0.0), b.stream, b.refs, filter, b.retransmissions)
        }.sortedByDescending { it.bytes }
    }

    private data class DnsKey(val id: String, val name: String, val client: String, val server: String)

    private fun buildDns(rows: List<Row>): List<DnsTransaction> {
        val pending = linkedMapOf<DnsKey, Row>()
        val out = mutableListOf<DnsTransaction>()
        rows.filter { it.value("dns.id").isNotBlank() && it.value("dns.qry.name").isNotBlank() }.forEach { row ->
            val isResponse = row.value("dns.flags.response") in setOf("1", "True", "true")
            val name = row.values("dns.qry.name").firstOrNull().orEmpty()
            val key = if (isResponse) DnsKey(row.value("dns.id"), name, row.dst, row.src)
                else DnsKey(row.value("dns.id"), name, row.src, row.dst)
            if (!isResponse) {
                pending[key] = row
            } else {
                val query = pending.remove(key)
                val rcode = row.int("dns.flags.rcode")
                val addresses = (row.values("dns.a") + row.values("dns.aaaa")).distinct()
                val result = dnsResult(rcode, addresses)
                val queryRow = query ?: row
                val latency = row.double("dns.time")?.times(1000.0)
                    ?: query?.let { (row.relative - it.relative).coerceAtLeast(0.0) * 1000.0 }
                out += DnsTransaction(
                    id = "dns:${key.id}:${queryRow.number}", timestampSeconds = queryRow.relative,
                    client = key.client, server = key.server, queryName = name,
                    recordType = dnsType(row.int("dns.qry.type") ?: queryRow.int("dns.qry.type")),
                    result = result, responseAddresses = addresses, responseCode = rcode,
                    latencyMs = latency, queryPacket = queryRow.number, responsePacket = row.number,
                    streamIndex = row.int("udp.stream") ?: row.int("tcp.stream"),
                    filter = "dns.qry.name == ${quote(name)}",
                )
            }
        }
        pending.forEach { (key, row) ->
            out += DnsTransaction("dns:${key.id}:${row.number}", row.relative, key.client, key.server,
                key.name, dnsType(row.int("dns.qry.type")), "Unanswered", emptyList(), null, null,
                row.number, null, row.int("udp.stream") ?: row.int("tcp.stream"),
                "frame.number == ${row.number}")
        }
        return out.sortedBy { it.timestampSeconds }
    }

    private fun buildHttp(rows: List<Row>): List<HttpTransaction> {
        val requests = linkedMapOf<Long, HttpTransaction>()
        rows.filter { it.value("http.request.method").isNotBlank() }.forEach { row ->
            val method = row.value("http.request.method").substringBefore('|')
            val uri = row.value("http.request.uri").substringBefore('|').ifBlank { "/" }
            requests[row.number] = HttpTransaction(
                "http:${row.number}", row.relative, row.src, row.dst, method,
                row.value("http.host").substringBefore('|').ifBlank { null }, uri,
                null, null, null, null, row.int("tcp.stream"), row.number, null,
                "frame.number == ${row.number}",
            )
        }
        rows.filter { it.value("http.response.code").isNotBlank() }.forEach { row ->
            val requestNo = row.long("http.request_in")
                ?: requests.values.lastOrNull { it.tcpStream == row.int("tcp.stream") && it.responsePacket == null }?.requestPacket
            val request = requestNo?.let(requests::get) ?: return@forEach
            requests[request.requestPacket] = request.copy(
                statusCode = row.int("http.response.code"),
                contentType = row.value("http.content_type").substringBefore('|').ifBlank { null },
                contentLength = row.long("http.content_length"),
                latencyMs = row.double("http.time")?.times(1000.0)
                    ?: (row.relative - request.requestTimestampSeconds).coerceAtLeast(0.0) * 1000.0,
                responsePacket = row.number,
                filter = request.tcpStream?.let { "tcp.stream == $it && http" }
                    ?: "frame.number == ${request.requestPacket} || frame.number == ${row.number}",
            )
        }
        return requests.values.sortedBy { it.requestTimestampSeconds }
    }

    private fun buildTls(rows: List<Row>): List<TlsSession> {
        val tlsRows = rows.filter { it.int("tcp.stream") != null &&
            (it.protocol.contains("TLS", true) || it.present("tls.handshake.type") ||
                it.present("tls.record.version") || it.present("tls.alert_message.desc")) }
        return tlsRows.groupBy { it.int("tcp.stream")!! }.map { (stream, packets) ->
            val clientHello = packets.firstOrNull { "1" in it.values("tls.handshake.type") }
            val first = clientHello ?: packets.first()
            val sni = packets.asSequence().flatMap { it.values("tls.handshake.extensions_server_name").asSequence() }.firstOrNull()
            val alpn = packets.asSequence().flatMap { it.values("tls.handshake.extensions_alpn_str").asSequence() }.firstOrNull()
            val serverHello = packets.firstOrNull { "2" in it.values("tls.handshake.type") }
            val supportedRaw = (serverHello?.value("tls.handshake.extensions.supported_version")
                ?: packets.asSequence().map { it.value("tls.handshake.extensions.supported_version") }.firstOrNull { it.isNotBlank() }).orEmpty()
            val versionRaw = supportedRaw.valuesByPipe().maxByOrNull(::tlsVersionRank)
                ?: packets.asSequence().map { it.value("tls.handshake.version").ifBlank { it.value("tls.record.version") } }
                    .firstOrNull { it.isNotBlank() }
            val version = tlsVersion(versionRaw)?.let { if (serverHello == null && supportedRaw.isNotBlank()) "$it offered" else it }
            val cipher = packets.asSequence().map { it.value("tls.handshake.ciphersuite") }.firstOrNull { it.isNotBlank() }
            val alerts = packets.flatMap { it.values("tls.alert_message.desc") }.distinct()
            val handshakes = packets.flatMap { it.values("tls.handshake.type") }
            val strings = packets.flatMap { it.values("x509sat.uTF8String") + it.values("x509sat.printableString") }
                .filter { it.isNotBlank() }.distinct()
            val notBefore = packets.asSequence().map { certificateDate(it.value("x509af.notBefore"), it.value("x509af.notBeforeTime")) }.firstOrNull { it != null }
            val notAfter = packets.asSequence().map { certificateDate(it.value("x509af.notAfter"), it.value("x509af.notAfterTime")) }.firstOrNull { it != null }
            val state = when {
                alerts.isNotEmpty() && handshakes.none { it == "20" } -> "Handshake failed"
                alerts.isNotEmpty() -> "Alert observed"
                handshakes.any { it == "20" } -> "Handshake completed"
                handshakes.isNotEmpty() -> "Handshake observed"
                else -> "Encrypted records observed"
            }
            TlsSession("tls:$stream", first.src, first.dst, first.int("tcp.dstport"), sni,
                version, alpn, cipher?.let(::cipherName), strings.firstOrNull(), strings.getOrNull(1),
                notBefore, notAfter, state, alerts, stream, packets.size.toLong(),
                packets.sumOf { it.length.toLong() }, packets.map { it.number },
                packets.minOf { it.relative }, "tcp.stream == $stream && tls")
        }.sortedByDescending { it.bytes }
    }

    private fun buildIssues(
        rows: List<Row>, conversations: List<Conversation>, dns: List<DnsTransaction>,
        http: List<HttpTransaction>, tls: List<TlsSession>,
    ): List<AnalysisIssue> {
        val out = mutableListOf<AnalysisIssue>()
        data class Rule(val field: String, val title: String, val category: String, val severity: IssueSeverity,
            val filter: String, val booleanTrue: Boolean = false)
        val rules = listOf(
            Rule("tcp.analysis.retransmission", "TCP retransmissions", "TCP", IssueSeverity.WARNING, "tcp.analysis.retransmission"),
            Rule("tcp.analysis.fast_retransmission", "TCP fast retransmissions", "TCP", IssueSeverity.WARNING, "tcp.analysis.fast_retransmission"),
            Rule("tcp.analysis.duplicate_ack", "TCP duplicate ACKs", "TCP", IssueSeverity.WARNING, "tcp.analysis.duplicate_ack"),
            Rule("tcp.analysis.out_of_order", "TCP out-of-order segments", "TCP", IssueSeverity.WARNING, "tcp.analysis.out_of_order"),
            Rule("tcp.analysis.lost_segment", "TCP lost-segment indicators", "TCP", IssueSeverity.ERROR, "tcp.analysis.lost_segment"),
            Rule("tcp.analysis.ack_lost_segment", "TCP ACKed unseen segments", "TCP", IssueSeverity.WARNING, "tcp.analysis.ack_lost_segment"),
            Rule("tcp.analysis.zero_window", "TCP zero-window conditions", "TCP", IssueSeverity.ERROR, "tcp.analysis.zero_window"),
            Rule("tcp.flags.reset", "TCP resets", "TCP", IssueSeverity.WARNING, "tcp.flags.reset == 1", booleanTrue = true),
            Rule("_ws.malformed", "Malformed packets", "General", IssueSeverity.ERROR, "_ws.malformed"),
            Rule("icmp.type.error", "ICMP errors", "General", IssueSeverity.ERROR, "icmp.type.error"),
            Rule("icmpv6.type.error", "ICMPv6 errors", "General", IssueSeverity.ERROR, "icmpv6.type.error"),
        )
        rules.forEach { rule ->
            val evidence = rows.filter { if (rule.booleanTrue) it.bool(rule.field) else it.present(rule.field) }
            if (evidence.isNotEmpty()) out += issue(rule.title, rule.category, rule.severity,
                "${evidence.size} packet(s) contain ${rule.field} evidence.", evidence, rule.filter,
                evidence.mapNotNull { conversationFor(it, conversations)?.id }.distinct().singleOrNull())
        }
        dns.groupBy { it.result }.filterKeys { it != "Success" }.forEach { (result, txs) ->
            val packets = txs.flatMap { listOfNotNull(it.queryPacket, it.responsePacket) }
            out += AnalysisIssue(id = "dns:${result.lowercase()}", title = "DNS $result",
                detail = "${txs.size} DNS transaction(s) ended with $result.", category = "DNS",
                severity = if (result == "Unanswered") IssueSeverity.WARNING else IssueSeverity.ERROR,
                count = txs.size, affectedEndpoints = txs.flatMap { listOf(it.client, it.server) }.distinct(),
                conversationId = null, firstOccurrenceSeconds = txs.minOf { it.timestampSeconds },
                packetNumbers = packets, filter = dnsIssueFilter(txs.first()))
        }
        val slowDns = dns.filter { (it.latencyMs ?: 0.0) >= 1000.0 }
        if (slowDns.isNotEmpty()) out += AnalysisIssue(id = "dns:slow", title = "Slow DNS responses",
            detail = "${slowDns.size} DNS response(s) took at least one second.", category = "DNS",
            severity = IssueSeverity.WARNING, count = slowDns.size,
            affectedEndpoints = slowDns.flatMap { listOf(it.client, it.server) }.distinct(),
            conversationId = null, firstOccurrenceSeconds = slowDns.minOf { it.timestampSeconds },
            packetNumbers = slowDns.flatMap { listOfNotNull(it.queryPacket, it.responsePacket) }, filter = "dns.time >= 1")
        listOf(400..499 to "HTTP client errors", 500..599 to "HTTP server errors").forEach { (range, title) ->
            val txs = http.filter { it.statusCode in range }
            if (txs.isNotEmpty()) out += AnalysisIssue(id = "http:${range.first}", title = title,
                detail = "${txs.size} HTTP response(s) returned ${range.first / 100}xx status codes.", category = "HTTP",
                severity = if (range.first == 500) IssueSeverity.ERROR else IssueSeverity.WARNING,
                count = txs.size, affectedEndpoints = txs.flatMap { listOf(it.client, it.server) }.distinct(),
                conversationId = null, firstOccurrenceSeconds = txs.minOf { it.requestTimestampSeconds },
                packetNumbers = txs.flatMap { listOfNotNull(it.requestPacket, it.responsePacket) },
                filter = "http.response.code >= ${range.first} && http.response.code <= ${range.last}")
        }
        tls.filter { it.alerts.isNotEmpty() }.forEach { session ->
            out += AnalysisIssue(id = "${session.id}:alert",
                title = if (session.handshakeState == "Handshake failed") "TLS handshake failure" else "TLS alert",
                detail = "TLS stream ${session.tcpStream} reported ${session.alerts.joinToString()}.", category = "TLS",
                severity = IssueSeverity.ERROR, count = session.alerts.size,
                affectedEndpoints = listOf(session.client, session.server), conversationId = "TCP:stream:${session.tcpStream}",
                firstOccurrenceSeconds = session.firstOccurrenceSeconds, packetNumbers = session.packetNumbers,
                filter = "tcp.stream == ${session.tcpStream} && tls.alert_message")
        }
        tls.filter { it.version in setOf("SSL 3.0", "TLS 1.0", "TLS 1.1") }.forEach { session ->
            out += AnalysisIssue(id = "${session.id}:old", title = "Old TLS version",
                detail = "${session.version} was observed on TLS stream ${session.tcpStream}.", category = "TLS",
                severity = IssueSeverity.WARNING, count = 1,
                affectedEndpoints = listOf(session.client, session.server), conversationId = "TCP:stream:${session.tcpStream}",
                firstOccurrenceSeconds = session.firstOccurrenceSeconds, packetNumbers = session.packetNumbers,
                filter = "tcp.stream == ${session.tcpStream} && tls")
        }
        val captureEpoch = rows.mapNotNull { it.double("frame.time_epoch") }.minOrNull()
        if (captureEpoch != null) tls.filter { session ->
            session.certificateNotAfter?.substringBefore('|')?.toLongOrNull()?.let { it < captureEpoch } == true
        }.forEach { session ->
            out += AnalysisIssue(id = "${session.id}:expired", title = "Expired TLS certificate",
                detail = "The captured certificate expired before the capture began.", category = "TLS",
                severity = IssueSeverity.ERROR, count = 1,
                affectedEndpoints = listOf(session.client, session.server), conversationId = "TCP:stream:${session.tcpStream}",
                firstOccurrenceSeconds = session.firstOccurrenceSeconds, packetNumbers = session.packetNumbers,
                filter = "tcp.stream == ${session.tcpStream} && x509af.notAfter")
        }
        // Failed connection: repeated SYNs with no SYN+ACK in the same tshark TCP stream.
        rows.filter { it.int("tcp.stream") != null }.groupBy { it.int("tcp.stream")!! }.forEach { (stream, packets) ->
            val synOnly = packets.filter { it.bool("tcp.flags.syn") && !it.bool("tcp.flags.ack") }
            val synAck = packets.any { it.bool("tcp.flags.syn") && it.bool("tcp.flags.ack") }
            if (synOnly.size >= 2 && !synAck) out += AnalysisIssue(id = "tcp:$stream:failed", title = "Failed TCP connection",
                detail = "${synOnly.size} SYN attempts were observed without a SYN-ACK.", category = "TCP",
                severity = IssueSeverity.ERROR, count = synOnly.size,
                affectedEndpoints = synOnly.flatMap { listOf(it.src, it.dst) }.distinct(), conversationId = "TCP:stream:$stream",
                firstOccurrenceSeconds = synOnly.minOf { it.relative }, packetNumbers = synOnly.map { it.number },
                filter = "tcp.stream == $stream && tcp.flags.syn == 1")
        }
        conversations.filter { it.kind in listOf(ConversationKind.TCP, ConversationKind.UDP) && maxOf(it.bytesAToB, it.bytesBToA) >= 10_000_000L }
            .forEach { conversation ->
                val aToB = conversation.bytesAToB >= conversation.bytesBToA
                val source = if (aToB) conversation.endpointA else conversation.endpointB
                val destination = if (aToB) conversation.endpointB else conversation.endpointA
                val transferred = maxOf(conversation.bytesAToB, conversation.bytesBToA)
                out += AnalysisIssue(id = "${conversation.id}:transfer", title = "Large transfer", category = "General",
                    detail = "${formatEvidenceBytes(transferred)} moved from $source to $destination.",
                    severity = IssueSeverity.INFO, count = 1, affectedEndpoints = listOf(source, destination),
                    conversationId = conversation.id, firstOccurrenceSeconds = conversation.startSeconds,
                    packetNumbers = conversation.packetNumbers, filter = conversation.filter)
            }
        return out.sortedWith(compareByDescending<AnalysisIssue> { it.severity }.thenByDescending { it.count })
    }

    private fun Row.bool(field: String): Boolean = value(field).substringBefore('|') in setOf("1", "True", "true")

    private fun issue(title: String, category: String, severity: IssueSeverity, detail: String,
        rows: List<Row>, filter: String, conversationId: String?): AnalysisIssue = AnalysisIssue(
        id = "${category.lowercase()}:${filter}", title = title, detail = detail, category = category,
        severity = severity, count = rows.size,
        affectedEndpoints = rows.flatMap { listOf(it.src, it.dst) }.filter(String::isNotBlank).distinct(),
        conversationId = conversationId, firstOccurrenceSeconds = rows.minOf { it.relative },
        packetNumbers = rows.map { it.number }, filter = filter,
    )

    private fun conversationFor(row: Row, conversations: List<Conversation>): Conversation? {
        val tcp = row.int("tcp.stream")
        val udp = row.int("udp.stream")
        return conversations.firstOrNull { (tcp != null && it.kind == ConversationKind.TCP && it.streamIndex == tcp) ||
            (udp != null && it.kind == ConversationKind.UDP && it.streamIndex == udp) }
    }

    private data class EndpointBuilder(
        var packets: Long = 0, var bytes: Long = 0, var sentPackets: Long = 0, var sentBytes: Long = 0,
        var receivedPackets: Long = 0, var receivedBytes: Long = 0,
    )

    private fun buildEndpoints(rows: List<Row>, conversations: List<Conversation>, dns: List<DnsTransaction>, issues: List<AnalysisIssue>): List<AnalysisEndpoint> {
        val map = linkedMapOf<String, EndpointBuilder>()
        rows.forEach { row ->
            val layerPairs = listOf(
                row.value("eth.src") to row.value("eth.dst"),
                row.value("wlan.sa") to row.value("wlan.da"),
                row.value("ip.src") to row.value("ip.dst"),
                row.value("ipv6.src") to row.value("ipv6.dst"),
            ).distinct()
            layerPairs.forEach { (src, dst) ->
                if (src.isNotBlank()) map.getOrPut(src, ::EndpointBuilder).apply {
                    packets++; bytes += row.length; sentPackets++; sentBytes += row.length
                }
                if (dst.isNotBlank()) map.getOrPut(dst, ::EndpointBuilder).apply {
                    packets++; bytes += row.length; receivedPackets++; receivedBytes += row.length
                }
            }
        }
        return map.map { (address, b) ->
            val ipv6 = address.contains(':') && !address.matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}"))
            AnalysisEndpoint(address, b.packets, b.bytes, b.sentPackets, b.sentBytes,
                b.receivedPackets, b.receivedBytes,
                conversations.count { it.kind == ConversationKind.TCP && (it.endpointA == address || it.endpointB == address) },
                dns.count { it.client == address },
                issues.filter { it.title.contains("retransmission", true) && address in it.affectedEndpoints }.sumOf { it.count },
                if (ipv6) "ipv6.addr == $address" else if (address.count { it == ':' } == 5) {
                    val hasWlan = rows.any { it.value("wlan.sa") == address || it.value("wlan.da") == address }
                    if (hasWlan) "wlan.addr == $address" else "eth.addr == $address"
                } else "ip.addr == $address")
        }.sortedByDescending { it.bytes }
    }

    private fun buildTimeline(rows: List<Row>, duration: Double): List<TimelineBucket> {
        val width = when {
            duration <= 120 -> 1.0
            duration <= 1800 -> 10.0
            duration <= 21600 -> 60.0
            else -> 300.0
        }
        return rows.groupBy { kotlin.math.floor(it.relative / width).toLong() }.toSortedMap().map { (idx, packets) ->
            TimelineBucket(idx * width, (idx + 1) * width, packets.size.toLong(), packets.sumOf { it.length.toLong() },
                packets.count { it.present("tcp.analysis.retransmission") }.toLong(),
                packets.count { it.present("dns.id") && !it.bool("dns.flags.response") }.toLong(),
                packets.count { it.present("http.request.method") }.toLong(),
                packets.count { it.bool("tcp.flags.reset") }.toLong())
        }
    }

    private fun contextualFilters(a: CaptureAnalysis): List<ContextualFilter> = buildList {
        val priority = listOf("tcp.analysis.retransmission", "tcp.flags.reset == 1", "dns.flags.rcode == 3",
            "dns.flags.rcode == 2", "http.response.code", "tls.alert_message", "_ws.malformed")
        val ranked = a.issues.sortedWith(compareBy<AnalysisIssue> { issue ->
            priority.indexOfFirst { wanted -> issue.filter.startsWith(wanted) }.let { if (it < 0) Int.MAX_VALUE else it }
        }.thenByDescending { it.count })
        ranked.take(4).forEach { add(ContextualFilter("Show ${it.title.lowercase()}", it.filter, it.count)) }
        a.conversations.firstOrNull()?.let { add(ContextualFilter("Show largest conversation", it.filter, it.packets.toInt())) }
        a.endpoints.firstOrNull()?.let { add(ContextualFilter("Show traffic to top endpoint", it.filter, it.packets.toInt())) }
        if (a.tls.isNotEmpty()) add(ContextualFilter("Show TLS handshakes", "tls.handshake", a.tls.size))
        if (a.protocols.any { it.name.equals("QUIC", true) }) add(ContextualFilter("Show QUIC", "quic", a.protocols.first { it.name.equals("QUIC", true) }.packets.toInt()))
    }.distinctBy { it.filter }.take(8)

    private fun canonicalKey(a: String, pa: Int?, b: String, pb: Int?): String {
        val left = "$a:${pa ?: "*"}"; val right = "$b:${pb ?: "*"}"
        return if (left <= right) "$left|$right" else "$right|$left"
    }

    private fun dnsResult(rcode: Int?, addresses: List<String>): String = when (rcode) {
        null -> if (addresses.isNotEmpty()) "Success" else "Response"
        0 -> "Success"
        2 -> "SERVFAIL"
        3 -> "NXDOMAIN"
        5 -> "REFUSED"
        else -> "RCODE $rcode"
    }

    private fun dnsIssueFilter(tx: DnsTransaction): String = when (tx.responseCode) {
        2 -> "dns.flags.rcode == 2"
        3 -> "dns.flags.rcode == 3"
        null -> tx.filter
        else -> "dns.flags.rcode == ${tx.responseCode}"
    }

    private fun dnsType(type: Int?): String = when (type) {
        1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 6 -> "SOA"; 12 -> "PTR"; 15 -> "MX"
        16 -> "TXT"; 28 -> "AAAA"; 33 -> "SRV"; 64 -> "SVCB"; 65 -> "HTTPS"
        null -> "Unknown"; else -> "TYPE$type"
    }

    private fun tlsVersion(raw: String?): String? = when (raw?.lowercase(Locale.US)) {
        "0x0300", "768" -> "SSL 3.0"
        "0x0301", "769" -> "TLS 1.0"
        "0x0302", "770" -> "TLS 1.1"
        "0x0303", "771" -> "TLS 1.2"
        "0x0304", "772" -> "TLS 1.3"
        null, "" -> null
        else -> raw
    }

    private fun String.valuesByPipe(): List<String> = split('|').map(String::trim).filter(String::isNotBlank)
    private fun tlsVersionRank(raw: String): Int = when (raw.lowercase(Locale.US)) {
        "0x0304", "772" -> 4; "0x0303", "771" -> 3; "0x0302", "770" -> 2
        "0x0301", "769" -> 1; else -> 0
    }

    private fun cipherName(raw: String): String = raw.uppercase(Locale.US)

    /** Keep epoch first for deterministic expiry checks; append tshark's readable date when present. */
    private fun certificateDate(epoch: String, display: String): String? = when {
        epoch.isNotBlank() && display.isNotBlank() -> "${epoch.substringBefore('|')}|${display.substringBefore('|')}"
        epoch.isNotBlank() -> epoch.substringBefore('|')
        display.isNotBlank() -> display.substringBefore('|')
        else -> null
    }

    private fun formatEvidenceBytes(value: Long): String = when {
        value >= 1_000_000_000 -> "%.1f GB".format(Locale.US, value / 1_000_000_000.0)
        else -> "%.1f MB".format(Locale.US, value / 1_000_000.0)
    }

    private fun protocolFilter(name: String): String = when (name.lowercase(Locale.US)) {
        "ssl" -> "tls"; "mdns" -> "mdns"; "http/2" -> "http2"; "http/3" -> "http3"
        "802.11" -> "wlan"
        "http/json", "http/xml" -> "http"
        else -> name.lowercase(Locale.US).replace(Regex("[^a-z0-9_.-]"), "")
    }.let { if (it.startsWith("tlsv")) "tls" else it }

    private fun linkType(raw: String): String? = when (raw.substringBefore('|').toIntOrNull()) {
        1 -> "Ethernet"
        7 -> "Raw IP"
        20 -> "IEEE 802.11"
        23 -> "IEEE 802.11 + radiotap"
        25 -> "Linux cooked capture"
        41, 99, 102, 118, 154, 159, 160, 161, 186 -> "Bluetooth"
        129 -> "Raw IPv4"
        130 -> "Raw IPv6"
        null -> null
        else -> "Encapsulation $raw"
    }

    private fun quote(value: String): String = "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
}
