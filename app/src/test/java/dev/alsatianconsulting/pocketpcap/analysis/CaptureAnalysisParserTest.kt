package dev.alsatianconsulting.pocketpcap.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureAnalysisParserTest {
    private fun row(vararg values: Pair<String, String>): String {
        val map = values.toMap()
        return CaptureAnalysisParser.fields.joinToString("\t") { map[it].orEmpty() }
    }

    private val fixture = listOf(
        row("frame.number" to "1", "frame.time_epoch" to "1700000000", "frame.time_relative" to "0.0",
            "frame.len" to "60", "frame.encap_type" to "1", "ip.src" to "10.0.0.2", "ip.dst" to "93.184.216.34",
            "_ws.col.Protocol" to "TCP", "tcp.srcport" to "50000", "tcp.dstport" to "443", "tcp.stream" to "0",
            "tcp.flags.syn" to "1"),
        row("frame.number" to "2", "frame.time_epoch" to "1700000001", "frame.time_relative" to "1.0",
            "frame.len" to "60", "frame.encap_type" to "1", "ip.src" to "10.0.0.2", "ip.dst" to "93.184.216.34",
            "_ws.col.Protocol" to "TCP", "tcp.srcport" to "50000", "tcp.dstport" to "443", "tcp.stream" to "0",
            "tcp.flags.syn" to "1", "tcp.analysis.retransmission" to "1"),
        row("frame.number" to "3", "frame.time_epoch" to "1700000002", "frame.time_relative" to "2.0",
            "frame.len" to "54", "frame.encap_type" to "1", "ip.src" to "93.184.216.34", "ip.dst" to "10.0.0.2",
            "_ws.col.Protocol" to "TCP", "tcp.srcport" to "443", "tcp.dstport" to "50000", "tcp.stream" to "0",
            "tcp.flags.reset" to "1"),
        row("frame.number" to "4", "frame.time_epoch" to "1700000003", "frame.time_relative" to "3.0",
            "frame.len" to "74", "frame.encap_type" to "1", "ip.src" to "10.0.0.2", "ip.dst" to "8.8.8.8",
            "_ws.col.Protocol" to "DNS", "udp.srcport" to "53000", "udp.dstport" to "53", "udp.stream" to "0",
            "dns.id" to "4660", "dns.flags.response" to "0", "dns.qry.name" to "example.com", "dns.qry.type" to "1"),
        row("frame.number" to "5", "frame.time_epoch" to "1700000003.05", "frame.time_relative" to "3.05",
            "frame.len" to "90", "frame.encap_type" to "1", "ip.src" to "8.8.8.8", "ip.dst" to "10.0.0.2",
            "_ws.col.Protocol" to "DNS", "udp.srcport" to "53", "udp.dstport" to "53000", "udp.stream" to "0",
            "dns.id" to "4660", "dns.flags.response" to "1", "dns.qry.name" to "example.com", "dns.qry.type" to "1",
            "dns.a" to "93.184.216.34", "dns.flags.rcode" to "0", "dns.time" to "0.05"),
        row("frame.number" to "6", "frame.time_epoch" to "1700000004", "frame.time_relative" to "4.0",
            "frame.len" to "74", "frame.encap_type" to "1", "ip.src" to "10.0.0.2", "ip.dst" to "8.8.4.4",
            "_ws.col.Protocol" to "DNS", "udp.srcport" to "53001", "udp.dstport" to "53", "udp.stream" to "1",
            "dns.id" to "8755", "dns.flags.response" to "0", "dns.qry.name" to "missing.test", "dns.qry.type" to "28"),
        row("frame.number" to "7", "frame.time_epoch" to "1700000004.2", "frame.time_relative" to "4.2",
            "frame.len" to "82", "frame.encap_type" to "1", "ip.src" to "8.8.4.4", "ip.dst" to "10.0.0.2",
            "_ws.col.Protocol" to "DNS", "udp.srcport" to "53", "udp.dstport" to "53001", "udp.stream" to "1",
            "dns.id" to "8755", "dns.flags.response" to "1", "dns.qry.name" to "missing.test", "dns.qry.type" to "28",
            "dns.flags.rcode" to "3", "dns.time" to "0.2"),
        row("frame.number" to "8", "frame.time_epoch" to "1700000005", "frame.time_relative" to "5.0",
            "frame.len" to "180", "frame.encap_type" to "1", "ip.src" to "10.0.0.2", "ip.dst" to "203.0.113.8",
            "_ws.col.Protocol" to "HTTP", "tcp.srcport" to "51000", "tcp.dstport" to "80", "tcp.stream" to "2",
            "http.request.method" to "GET", "http.host" to "api.example.test", "http.request.uri" to "/health",
            "http.response_in" to "9"),
        row("frame.number" to "9", "frame.time_epoch" to "1700000005.25", "frame.time_relative" to "5.25",
            "frame.len" to "220", "frame.encap_type" to "1", "ip.src" to "203.0.113.8", "ip.dst" to "10.0.0.2",
            "_ws.col.Protocol" to "HTTP", "tcp.srcport" to "80", "tcp.dstport" to "51000", "tcp.stream" to "2",
            "http.response.code" to "503", "http.content_type" to "application/json", "http.content_length" to "72",
            "http.time" to "0.25", "http.request_in" to "8"),
        row("frame.number" to "10", "frame.time_epoch" to "1700000006", "frame.time_relative" to "6.0",
            "frame.len" to "420", "frame.encap_type" to "1", "ip.src" to "10.0.0.2", "ip.dst" to "203.0.113.9",
            "_ws.col.Protocol" to "TLSv1.2", "tcp.srcport" to "52000", "tcp.dstport" to "443", "tcp.stream" to "3",
            "tls.handshake.type" to "1", "tls.handshake.extensions_server_name" to "secure.example.test",
            "tls.handshake.extensions_alpn_str" to "h2", "tls.handshake.version" to "0x0303"),
        row("frame.number" to "11", "frame.time_epoch" to "1700000006.1", "frame.time_relative" to "6.1",
            "frame.len" to "110", "frame.encap_type" to "1", "ip.src" to "203.0.113.9", "ip.dst" to "10.0.0.2",
            "_ws.col.Protocol" to "TLSv1.2", "tcp.srcport" to "443", "tcp.dstport" to "52000", "tcp.stream" to "3",
            "tls.alert_message.desc" to "40", "tls.alert_message.level" to "2"),
        row("frame.number" to "12", "frame.time_epoch" to "1700000007", "frame.time_relative" to "7.0",
            "frame.len" to "20", "frame.encap_type" to "1", "eth.src" to "aa:bb:cc:dd:ee:ff", "eth.dst" to "11:22:33:44:55:66",
            "_ws.col.Protocol" to "Malformed", "_ws.malformed" to "1"),
    ).joinToString("\n")

    @Test
    fun parsesOutputProducedByRealTsharkFixture() {
        val text = requireNotNull(javaClass.getResourceAsStream("/analysis-fixture.tsv"))
            .bufferedReader().use { it.readText() }
        val a = CaptureAnalysisParser.parse(text, "analysis-fixture.pcapng", 1800)
        assertEquals(20, a.metadata.packetCount)
        assertEquals("Success", a.dns.first { it.queryName == "example.com" }.result)
        assertEquals("NXDOMAIN", a.dns.first { it.queryName == "missing.test" }.result)
        assertEquals("SERVFAIL", a.dns.first { it.queryName == "fail.test" }.result)
        assertEquals(503, a.http.single().statusCode)
        assertEquals(7L, a.http.single().requestPacket)
        assertEquals(8L, a.http.single().responsePacket)
        assertTrue(a.issues.any { it.title == "DNS NXDOMAIN" && it.packetNumbers == listOf(3L, 4L) })
        assertTrue(a.issues.any { it.title == "DNS SERVFAIL" && it.packetNumbers == listOf(5L, 6L) })
        assertTrue(a.issues.any { it.title == "HTTP server errors" && it.packetNumbers == listOf(7L, 8L) })
        assertEquals("secure.example.test", a.tls.single().sni)
        assertEquals("TLS 1.3 offered", a.tls.single().version)
        assertTrue(a.tls.single().alerts.contains("40"))
        assertTrue(a.issues.any { it.title == "TCP retransmissions" && 19L in it.packetNumbers })
        assertEquals(1, a.conversations.first { it.kind == ConversationKind.TCP && it.streamIndex == 3 }.retransmissions)
        assertTrue(a.issues.any { it.title == "TCP resets" && it.packetNumbers == listOf(14L) })
        assertTrue(a.issues.any { it.title == "Malformed packets" && it.packetNumbers == listOf(20L) })
        assertTrue(a.conversations.any { it.kind == ConversationKind.TCP && it.streamIndex == 3 && it.packets == 5L })
        assertTrue(a.conversations.any { it.kind == ConversationKind.UDP })
    }

    @Test
    fun buildsCorrelatedWholeCaptureAnalysisFromPacketEvidence() {
        val a = CaptureAnalysisParser.parse(fixture, "fixture.pcapng", 4096)
        assertEquals(12, a.metadata.packetCount)
        assertEquals(7.0, a.metadata.durationSeconds, 0.0001)
        assertEquals(listOf("Ethernet"), a.metadata.linkLayerTypes)
        assertTrue(a.conversations.any { it.kind == ConversationKind.TCP && it.streamIndex == 2 && it.packets == 2L })
        assertTrue(a.conversations.any { it.kind == ConversationKind.UDP && it.streamIndex == 0 })
        assertEquals(2, a.dns.size)
        assertEquals("93.184.216.34", a.dns.first { it.queryName == "example.com" }.responseAddresses.single())
        assertEquals("NXDOMAIN", a.dns.first { it.queryName == "missing.test" }.result)
        assertEquals(50.0, a.dns.first { it.queryName == "example.com" }.latencyMs!!, 0.001)
        assertEquals(503, a.http.single().statusCode)
        assertEquals(9L, a.http.single().responsePacket)
        assertEquals("secure.example.test", a.tls.single().sni)
        assertEquals("TLS 1.2", a.tls.single().version)
        assertTrue(a.tls.single().alerts.contains("40"))
    }

    @Test
    fun findingsContainTraceablePacketReferencesAndValidPivots() {
        val a = CaptureAnalysisParser.parse(fixture, "fixture.pcapng", 4096)
        val titles = a.issues.map { it.title }
        assertTrue("TCP retransmissions" in titles)
        assertTrue("TCP resets" in titles)
        assertTrue("Failed TCP connection" in titles)
        assertTrue("DNS NXDOMAIN" in titles)
        assertTrue("HTTP server errors" in titles)
        assertTrue("TLS handshake failure" in titles)
        assertTrue("Malformed packets" in titles)
        a.issues.forEach { issue ->
            assertTrue(issue.packetNumbers.isNotEmpty())
            assertTrue(issue.filter.isNotBlank())
            assertFalse(issue.detail.contains("maybe", ignoreCase = true))
        }
        val tlsFailure = a.issues.first { it.title == "TLS handshake failure" }
        assertEquals(6.0, tlsFailure.firstOccurrenceSeconds, 0.0001)
        assertEquals("TCP:stream:3", tlsFailure.conversationId)
        assertEquals(listOf(6L, 7L), a.issues.first { it.title == "DNS NXDOMAIN" }.packetNumbers)
    }

    @Test
    fun contextualFiltersOnlyReflectPresentEvidence() {
        val a = CaptureAnalysisParser.parse(fixture, "fixture.pcapng", 4096)
        assertTrue(a.contextualFilters.size in 3..8)
        assertTrue(a.contextualFilters.any { it.filter == "tcp.analysis.retransmission" })
        assertFalse(a.contextualFilters.any { it.filter == "quic" })
    }

    @Test
    fun globalSearchGroupsEntitiesAndAliases() {
        val a = CaptureAnalysisParser.parse(fixture, "fixture.pcapng", 4096)
        val dns = CaptureSearch.search(a, "missing.test")
        assertTrue(dns.any { it.entity == SearchEntity.DNS && it.packetNumber == 6L })
        val alias = CaptureSearch.search(a, "phone", mapOf("10.0.0.2" to "Test Phone"))
        assertNotNull(alias.firstOrNull { it.entity == SearchEntity.ENDPOINT })
        val field = CaptureSearch.search(a, "destination port")
        assertTrue(field.any { it.entity == SearchEntity.FIELD && it.filter == "tcp.dstport" })
    }
}
