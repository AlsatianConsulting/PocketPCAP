package dev.alsatianconsulting.pocketpcap.filter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FilterSuggestionEngineTest {

    private val engine = FilterSuggestionEngine()

    private fun displays(query: String, ctx: SuggestionContext = SuggestionContext()) =
        engine.suggest(query, ctx, max = 50).map { it.display }

    private fun applies(query: String, ctx: SuggestionContext = SuggestionContext()) =
        engine.suggest(query, ctx, max = 50).map { it.apply }

    @Test fun splitFragment_takesTrailingToken() {
        assertEquals("ip.addr == " to "192.", FilterSuggestionEngine.splitFragment("ip.addr == 192."))
        assertEquals("" to "http", FilterSuggestionEngine.splitFragment("http"))
        assertEquals("tcp && " to "ud", FilterSuggestionEngine.splitFragment("tcp && ud"))
    }

    @Test fun partialProtocol_d_suggestsDnsAndDhcp() {
        val d = displays("d")
        assertTrue("expected dns in $d", d.contains("dns"))
        assertTrue("expected dhcp in $d", d.contains("dhcp"))
        assertTrue("expected dns.qry.name in $d", d.contains("dns.qry.name"))
    }

    @Test fun ipDot_suggestsIpFields() {
        val d = displays("ip.")
        assertTrue(d.contains("ip.src"))
        assertTrue(d.contains("ip.dst"))
        assertTrue(d.contains("ip.addr"))
        // ipv6.addr must NOT match the "ip." prefix.
        assertTrue(d.none { it == "ipv6.addr" })
    }

    @Test fun http_suggestsHttpFields() {
        val d = displays("http")
        assertTrue(d.contains("http"))
        assertTrue(d.contains("http.host"))
        assertTrue(d.contains("http.request.method"))
        assertTrue(d.contains("http.user_agent"))
    }

    @Test fun partialAddress_suggestsKnownEndpoints() {
        val ctx = SuggestionContext(endpoints = listOf("192.168.1.1", "192.168.1.15", "10.0.0.5"))
        val a = applies("192.", ctx)
        assertTrue(a.contains("ip.addr == 192.168.1.1"))
        assertTrue(a.contains("ip.addr == 192.168.1.15"))
        assertTrue(a.none { it.contains("10.0.0.5") })
    }

    @Test fun partialAddress_afterFieldOperator_completesValue() {
        val ctx = SuggestionContext(endpoints = listOf("192.168.1.15"))
        val a = applies("ip.addr == 192.", ctx)
        assertTrue("expected value completion, got $a", a.contains("ip.addr == 192.168.1.15"))
    }

    @Test fun hostname_resolvesToAddressFilter() {
        val ctx = SuggestionContext(names = listOf("dns.google" to "8.8.8.8"))
        val s = engine.suggest("goo", ctx, max = 50)
        val hit = s.firstOrNull { it.display == "dns.google" }
        assertTrue("expected dns.google suggestion", hit != null)
        assertEquals("ip.addr == 8.8.8.8", hit!!.apply)
    }

    @Test fun alias_suggestedByName() {
        val ctx = SuggestionContext(
            names = listOf("Home Router" to "192.168.1.1"),
            aliases = setOf("Home Router"),
        )
        val s = engine.suggest("home", ctx, max = 50)
        val hit = s.firstOrNull { it.display == "Home Router" }
        assertTrue(hit != null)
        assertEquals(SuggestionKind.ALIAS, hit!!.kind)
        assertEquals("ip.addr == 192.168.1.1", hit.apply)
    }

    @Test fun streams_suggestedForProtocol() {
        val ctx = SuggestionContext(tcpStreams = listOf(5, 2), udpStreams = listOf(7))
        val tcp = applies("tcp", ctx)
        assertTrue(tcp.contains("tcp.stream eq 2"))
        assertTrue(tcp.contains("tcp.stream eq 5"))
        val udp = applies("udp", ctx)
        assertTrue(udp.contains("udp.stream eq 7"))
    }

    @Test fun emptyQuery_offersSavedThenRecent() {
        val ctx = SuggestionContext(
            recentFilters = listOf("tcp.port == 443"),
            savedFilters = listOf("DNS only" to "dns"),
        )
        val s = engine.suggest("", ctx, max = 50)
        assertTrue(s.any { it.kind == SuggestionKind.SAVED && it.apply == "dns" })
        assertTrue(s.any { it.kind == SuggestionKind.RECENT && it.apply == "tcp.port == 443" })
    }
}
