package dev.alsatianconsulting.pocketpcap.capture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootlessPacketParserTest {

    @Test fun parsesIpv4TcpSummary() {
        val packet = ipv4Tcp("10.0.0.2", "93.184.216.34", 53124, 443)
        val details = RootlessPacketParser.parse(packet, packet.size)!!
        assertEquals("10.0.0.2", details.src)
        assertEquals("93.184.216.34", details.dst)
        assertEquals(53124, details.srcPort)
        assertEquals(443, details.dstPort)
        assertEquals("TLS", details.protocol)
    }

    @Test fun rootlessFilterSupportsProtocolHostAndPort() {
        val packet = RootlessPacketParser.parse(
            ipv4Tcp("10.0.0.2", "93.184.216.34", 53124, 443),
            40,
        )!!
        assertTrue(RootlessPacketFilter("tcp port 443").accepts(packet))
        assertTrue(RootlessPacketFilter("host 93.184.216.34").accepts(packet))
        assertFalse(RootlessPacketFilter("udp").accepts(packet))
        assertFalse(RootlessPacketFilter("dst host 1.1.1.1").accepts(packet))
    }

    private fun ipv4Tcp(src: String, dst: String, srcPort: Int, dstPort: Int): ByteArray {
        val p = ByteArray(40)
        p[0] = 0x45
        p[2] = 0
        p[3] = 40
        p[8] = 64
        p[9] = 6
        putIpv4(p, 12, src)
        putIpv4(p, 16, dst)
        p[20] = (srcPort ushr 8).toByte()
        p[21] = srcPort.toByte()
        p[22] = (dstPort ushr 8).toByte()
        p[23] = dstPort.toByte()
        return p
    }

    private fun putIpv4(packet: ByteArray, offset: Int, ip: String) {
        ip.split(".").forEachIndexed { i, part -> packet[offset + i] = part.toInt().toByte() }
    }
}
