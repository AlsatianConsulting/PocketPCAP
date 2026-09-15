package dev.alsatianconsulting.pocketpcap.filter

import dev.alsatianconsulting.pocketpcap.filter.FilterBuilders.EndpointAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FilterBuildersTest {

    @Test fun protocolToFilter_normalisesDisplayVariants() {
        assertEquals("tls", FilterBuilders.protocolToFilter("TLSv1.2"))
        assertEquals("tls", FilterBuilders.protocolToFilter("TLS"))
        assertEquals("tls", FilterBuilders.protocolToFilter("SSL"))
        assertEquals("http2", FilterBuilders.protocolToFilter("HTTP/2"))
        assertEquals("http", FilterBuilders.protocolToFilter("HTTP"))
        assertEquals("icmpv6", FilterBuilders.protocolToFilter("ICMPv6"))
        assertEquals("mdns", FilterBuilders.protocolToFilter("MDNS"))
        assertEquals("dns", FilterBuilders.protocolToFilter("DNS"))
        assertEquals("tcp", FilterBuilders.protocolToFilter("TCP"))
        assertEquals("arp", FilterBuilders.protocolToFilter("ARP"))
    }

    @Test fun protocolToFilter_rejectsEmpty() {
        assertNull(FilterBuilders.protocolToFilter("?"))
        assertNull(FilterBuilders.protocolToFilter("  "))
    }

    @Test fun endpointFilter_ipActions() {
        val ip = "192.168.1.15"
        assertEquals("ip.addr == $ip", FilterBuilders.endpointFilter(ip, EndpointAction.ALL))
        assertEquals("ip.src == $ip", FilterBuilders.endpointFilter(ip, EndpointAction.SOURCE))
        assertEquals("ip.dst == $ip", FilterBuilders.endpointFilter(ip, EndpointAction.DESTINATION))
        assertEquals("ip.addr == $ip && (tcp || udp)", FilterBuilders.endpointFilter(ip, EndpointAction.SESSIONS))
    }

    @Test fun endpointFilter_macUsesEthField() {
        val mac = "AA:BB:CC:DD:EE:FF"
        assertEquals("eth.addr == $mac", FilterBuilders.endpointFilter(mac, EndpointAction.ALL))
        assertEquals("eth.src == $mac", FilterBuilders.endpointFilter(mac, EndpointAction.SOURCE))
    }

    @Test fun endpointFilter_conversationBetweenPeers() {
        val a = "10.0.0.5"; val b = "8.8.8.8"
        assertEquals(
            "ip.addr == $a && ip.addr == $b",
            FilterBuilders.endpointFilter(a, EndpointAction.CONVERSATION, b),
        )
    }
}
