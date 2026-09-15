package dev.alsatianconsulting.pocketpcap.decode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FollowRawParserTest {

    @Test
    fun preservesExactBytesAndDirection() {
        val output = """
            ===================================================================
            Follow: tcp,raw
            Filter: tcp.stream eq 7
            Node 0: 192.0.2.10:49152
            Node 1: 198.51.100.20:443
            50494e4700ff
            ${'\t'}485454502f312e3120323030204f4b0d0a0d0a
            ===================================================================
        """.trimIndent()

        val stream = parseRawFollow(output, "TCP", 7)!!

        assertEquals("192.0.2.10:49152", stream.nodeA)
        assertEquals("198.51.100.20:443", stream.nodeB)
        assertEquals(2, stream.segments.size)
        assertTrue(stream.segments[0].fromA)
        assertFalse(stream.segments[1].fromA)
        assertEquals("50494e4700ff", stream.segments[0].rawHex)
        assertEquals("485454502f312e3120323030204f4b0d0a0d0a", stream.segments[1].rawHex)
        assertTrue(stream.segments[0].text.startsWith("PING"))
        assertEquals("HTTP/1.1 200 OK\r\n\r\n", stream.segments[1].text)
    }

    @Test
    fun ignoresNonPayloadLinesAndRejectsBlankOutput() {
        val headerOnly = """
            Follow: udp,raw
            Filter: udp.stream eq 2
            Node 0: 192.0.2.1:1234
            Node 1: 192.0.2.2:53
            not-hex
            ===================================================================
        """.trimIndent()

        assertTrue(parseRawFollow(headerOnly, "UDP", 2)!!.segments.isEmpty())
        assertNull(parseRawFollow("", "TCP", 0))
    }
}
