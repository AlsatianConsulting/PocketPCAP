package dev.alsatianconsulting.pocketpcap.analysis

import dev.alsatianconsulting.pocketpcap.model.TrafficMapState
import org.json.JSONArray
import org.json.JSONObject

/**
 * Serialises analysis results to formats other tools read.
 *
 * The analysis models are already parsed and derived, so this is pure formatting:
 * no tshark run, no root, nothing to fail at runtime. It exists so findings can
 * leave the phone as data — a spreadsheet, a report, a GIS layer — rather than
 * only as a 260 MB capture the recipient has to re-analyse.
 */
object AnalysisExport {

    /** Which table to write. Each maps to one CSV or one JSON array. */
    enum class Table(val label: String, val fileStem: String) {
        CONVERSATIONS("Conversations", "conversations"),
        ENDPOINTS("Endpoints", "endpoints"),
        PROTOCOLS("Protocols", "protocols"),
        ISSUES("Issues", "issues"),
        DNS("DNS", "dns"),
        TLS("TLS", "tls"),
        HTTP("HTTP", "http"),
    }

    // ---- CSV ---------------------------------------------------------------

    fun csv(analysis: CaptureAnalysis, table: Table): String {
        val rows = rows(analysis, table)
        if (rows.isEmpty()) return ""
        val headers = rows.first().keys.toList()
        return buildString {
            appendLine(headers.joinToString(",") { csvCell(it) })
            rows.forEach { row ->
                appendLine(headers.joinToString(",") { csvCell(cellText(row[it])) })
            }
        }
    }

    /**
     * RFC 4180 quoting, plus a guard against spreadsheet formula injection.
     *
     * Two separate problems. Addresses and HTTP strings routinely contain commas and
     * quotes, and an unquoted one silently shifts every later column. Separately, a
     * cell beginning =, +, -, @, tab or CR is executed as a formula by Excel,
     * LibreOffice and Sheets - and these tables carry values a remote party chooses,
     * such as a DNS query name, a TLS SNI or an HTTP Host header. Capturing hostile
     * traffic must not become a way to attack whoever opens the export, so those
     * cells are prefixed with an apostrophe, which spreadsheets treat as "literal
     * text" and strip on display.
     */
    private fun csvCell(value: String): String {
        val guarded = if (value.firstOrNull() in FORMULA_LEADERS) "'$value" else value
        return if (guarded.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            "\"" + guarded.replace("\"", "\"\"").replace("\r\n", " ").replace('\n', ' ').replace('\r', ' ') + "\""
        } else guarded
    }

    private val FORMULA_LEADERS = setOf('=', '+', '-', '@', '\t', '\r')

    /**
     * Render a cell value, rounding the seconds columns.
     *
     * These are differences between two capture timestamps, so binary floating point
     * leaves artefacts: a conversation lasting three tenths of a second exported as
     * "0.3000000000000007". Six decimal places is microsecond resolution, which is
     * finer than any timestamp in a pcap and far finer than a duration means.
     */
    private fun cellText(value: Any?): String = when (value) {
        null -> ""
        is Double -> formatSeconds(roundSeconds(value))
        is Float -> formatSeconds(roundSeconds(value.toDouble()))
        else -> value.toString()
    }

    private fun jsonValue(value: Any?): Any = when (value) {
        null -> JSONObject.NULL
        is Double -> roundSeconds(value)
        is Float -> roundSeconds(value.toDouble())
        else -> value
    }

    private fun roundSeconds(value: Double): Double =
        if (value.isFinite()) Math.round(value * 1_000_000.0) / 1_000_000.0 else value

    /** Plain decimal, never scientific notation, with no trailing zero padding. */
    private fun formatSeconds(value: Double): String =
        if (!value.isFinite()) value.toString()
        else java.math.BigDecimal(value).setScale(6, java.math.RoundingMode.HALF_UP)
            .stripTrailingZeros().toPlainString()

    // ---- JSON --------------------------------------------------------------

    fun json(analysis: CaptureAnalysis, table: Table): String {
        val array = JSONArray()
        rows(analysis, table).forEach { row ->
            val obj = JSONObject()
            row.forEach { (k, v) -> obj.put(k, jsonValue(v)) }
            array.put(obj)
        }
        return JSONObject().apply {
            put("capture", JSONObject().apply {
                put("filename", analysis.metadata.filename)
                put("packets", analysis.metadata.packetCount)
                put("bytes", analysis.metadata.sizeBytes)
                put("durationSeconds", roundSeconds(analysis.metadata.durationSeconds))
            })
            put("table", table.fileStem)
            put("rows", array)
        }.toString(2)
    }

    /** One flat row per record, ordered so the CSV header reads sensibly. */
    private fun rows(analysis: CaptureAnalysis, table: Table): List<Map<String, Any?>> = when (table) {
        Table.CONVERSATIONS -> analysis.conversations.map {
            linkedMapOf(
                "kind" to it.kind.name,
                "endpointA" to it.endpointA, "portA" to it.portA,
                "endpointB" to it.endpointB, "portB" to it.portB,
                "packets" to it.packets, "bytes" to it.bytes,
                "packetsAToB" to it.packetsAToB, "bytesAToB" to it.bytesAToB,
                "packetsBToA" to it.packetsBToA, "bytesBToA" to it.bytesBToA,
                "startSeconds" to it.startSeconds, "durationSeconds" to it.durationSeconds,
                "streamIndex" to it.streamIndex, "retransmissions" to it.retransmissions,
                "filter" to it.filter,
            )
        }
        Table.ENDPOINTS -> analysis.endpoints.map {
            linkedMapOf(
                "address" to it.address,
                "packets" to it.packets, "bytes" to it.bytes,
                "sentPackets" to it.sentPackets, "sentBytes" to it.sentBytes,
                "receivedPackets" to it.receivedPackets, "receivedBytes" to it.receivedBytes,
                "tcpConnections" to it.tcpConnections, "dnsRequests" to it.dnsRequests,
                "retransmissions" to it.retransmissions,
                "filter" to it.filter,
            )
        }
        Table.PROTOCOLS -> analysis.protocols.map {
            linkedMapOf(
                "protocol" to it.name, "packets" to it.packets,
                "bytes" to it.bytes, "percentage" to it.percentage,
                "filter" to it.filter,
            )
        }
        Table.ISSUES -> analysis.issues.map {
            linkedMapOf(
                "severity" to it.severity.name, "category" to it.category,
                "title" to it.title, "detail" to it.detail, "count" to it.count,
                "firstOccurrenceSeconds" to it.firstOccurrenceSeconds,
                "endpoints" to it.affectedEndpoints.joinToString(" "),
                "packets" to it.packetNumbers.joinToString(" "),
                "filter" to it.filter,
            )
        }
        Table.DNS -> analysis.dns.map {
            linkedMapOf(
                "timestampSeconds" to it.timestampSeconds,
                "client" to it.client, "server" to it.server,
                "queryName" to it.queryName, "recordType" to it.recordType,
                "result" to it.result,
            )
        }
        Table.TLS -> analysis.tls.map {
            linkedMapOf(
                "client" to it.client, "server" to it.server, "serverPort" to it.serverPort,
                "sni" to it.sni, "version" to it.version, "alpn" to it.alpn,
                "cipher" to it.cipher, "handshakeState" to it.handshakeState,
                "packets" to it.packetCount, "bytes" to it.bytes,
                "tcpStream" to it.tcpStream,
            )
        }
        Table.HTTP -> analysis.http.map {
            linkedMapOf(
                "requestTimestampSeconds" to it.requestTimestampSeconds,
                "client" to it.client, "server" to it.server,
                "method" to it.method, "host" to it.hostname, "uri" to it.uri,
                "url" to it.url,
                "statusCode" to it.statusCode, "contentType" to it.contentType,
                "contentLength" to it.contentLength, "latencyMs" to it.latencyMs,
                "tcpStream" to it.tcpStream,
                "requestPacket" to it.requestPacket, "responsePacket" to it.responsePacket,
            )
        }
    }

    // ---- Geo ---------------------------------------------------------------

    /**
     * The traffic map as GeoJSON: one Point per remote endpoint, plus a LineString
     * from the local origin to each, so the routes survive into QGIS or anything
     * else that reads GeoJSON.
     */
    fun geoJson(map: TrafficMapState): String {
        val features = JSONArray()
        val srcLat = map.sourceLatitude
        val srcLon = map.sourceLongitude
        map.routes.forEach { route ->
            features.put(JSONObject().apply {
                put("type", "Feature")
                put("geometry", JSONObject().apply {
                    put("type", "Point")
                    put("coordinates", JSONArray(listOf(route.longitude, route.latitude)))
                })
                put("properties", JSONObject().apply {
                    put("address", route.address); put("label", route.label)
                    put("packets", route.packets); put("bytes", route.bytes)
                    put("txBytes", route.txBytes); put("rxBytes", route.rxBytes)
                    put("trafficType", route.trafficType)
                    put("city", route.city ?: JSONObject.NULL)
                    put("region", route.region ?: JSONObject.NULL)
                    put("country", route.country ?: JSONObject.NULL)
                })
            })
            if (srcLat != null && srcLon != null) {
                features.put(JSONObject().apply {
                    put("type", "Feature")
                    put("geometry", JSONObject().apply {
                        put("type", "LineString")
                        put("coordinates", JSONArray(listOf(
                            JSONArray(listOf(srcLon, srcLat)),
                            JSONArray(listOf(route.longitude, route.latitude)),
                        )))
                    })
                    put("properties", JSONObject().apply {
                        put("address", route.address); put("bytes", route.bytes)
                    })
                })
            }
        }
        return JSONObject().apply {
            put("type", "FeatureCollection")
            put("features", features)
        }.toString(2)
    }

    /** The same routes as KML, for Google Earth. */
    fun kml(map: TrafficMapState, title: String): String = buildString {
        appendLine("""<?xml version="1.0" encoding="UTF-8"?>""")
        appendLine("""<kml xmlns="http://www.opengis.net/kml/2.2"><Document>""")
        appendLine("<name>${xml(title)}</name>")
        val srcLat = map.sourceLatitude
        val srcLon = map.sourceLongitude
        if (srcLat != null && srcLon != null) {
            appendLine("<Placemark><name>${xml(map.sourceLabel)}</name>")
            appendLine("<Point><coordinates>$srcLon,$srcLat,0</coordinates></Point></Placemark>")
        }
        map.routes.forEach { route ->
            appendLine("<Placemark>")
            appendLine("<name>${xml(route.label.ifBlank { route.address })}</name>")
            appendLine("<description>${xml(
                "${route.address} — ${route.packets} packets, ${route.bytes} bytes, ${route.trafficType}"
            )}</description>")
            appendLine("<Point><coordinates>${route.longitude},${route.latitude},0</coordinates></Point>")
            appendLine("</Placemark>")
            if (srcLat != null && srcLon != null) {
                appendLine("<Placemark><name>${xml(route.address)} route</name><LineString>")
                appendLine("<coordinates>$srcLon,$srcLat,0 ${route.longitude},${route.latitude},0</coordinates>")
                appendLine("</LineString></Placemark>")
            }
        }
        appendLine("</Document></kml>")
    }

    private fun xml(s: String): String = s
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&apos;")
}
