package dev.alsatianconsulting.pocketpcap.resolve

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Encode/parse tests for the NetBIOS (NBSTAT) and LLMNR (reverse PTR) codecs. */
class LocalNameQueryTest {

    private fun ByteArray.u(i: Int) = this[i].toInt() and 0xFF

    @Test fun nbstat_queryEncoding() {
        val q = LocalNameQuery.buildNbstatQuery(0x1234)
        assertEquals(50, q.size)
        assertEquals(0x12, q.u(0)); assertEquals(0x34, q.u(1))   // txId
        assertEquals(0x01, q.u(5))                               // QDCOUNT = 1
        assertEquals(0x20, q.u(12))                              // name length 32
        // "*" (0x2A) first-level-encodes to 'C''K'.
        assertEquals('C'.code, q.u(13)); assertEquals('K'.code, q.u(14))
        assertEquals(0x00, q.u(45))                              // name null terminator
        assertEquals(0x21, q.u(47))                              // QTYPE = NBSTAT (0x0021)
        assertEquals(0x01, q.u(49))                              // QCLASS = IN (0x0001)
    }

    @Test fun nbstat_parseWorkstationName() {
        val base = LocalNameQuery.buildNbstatQuery(0x1234)       // 12 header + 38 question
        val ans = ByteArrayOutputStream().apply {
            write(0xC0); write(0x0C)            // answer name = pointer to question
            write(0x00); write(0x21)            // TYPE = NBSTAT
            write(0x00); write(0x01)            // CLASS = IN
            repeat(4) { write(0) }              // TTL
            val rdlen = 1 + 18                  // numNames + one 18-byte entry
            write(rdlen ushr 8); write(rdlen and 0xFF)
            write(1)                            // numNames
            write("MYPC".padEnd(15).toByteArray(Charsets.US_ASCII))  // 15-byte name
            write(0x00)                         // suffix = workstation
            write(0x04); write(0x00)            // flags: unique (group bit clear)
        }.toByteArray()
        assertEquals("MYPC", LocalNameQuery.parseNbstatResponse(base + ans))
    }

    @Test fun llmnr_ptrQueryEncoding() {
        val q = LocalNameQuery.buildLlmnrPtrQuery(0x0001, "192.168.1.5")
        // QNAME = reversed octets then in-addr.arpa.
        assertEquals(1, q.u(12)); assertEquals('5'.code, q.u(13))
        assertEquals(1, q.u(14)); assertEquals('1'.code, q.u(15))
        assertEquals(3, q.u(16))                                // "168"
        val ascii = String(q, Charsets.US_ASCII)
        assertTrue(ascii.contains("in-addr"))
        assertTrue(ascii.contains("arpa"))
        // Ends with QTYPE=PTR(0x000C), QCLASS=IN(0x0001).
        assertEquals(0x0C, q.u(q.size - 3))
        assertEquals(0x01, q.u(q.size - 1))
    }

    @Test fun llmnr_parsePtrName() {
        val base = LocalNameQuery.buildLlmnrPtrQuery(0x0001, "192.168.1.5").copyOf()
        base[6] = 0; base[7] = 1                // ANCOUNT = 1
        val rdata = ByteArrayOutputStream().apply {
            for (l in listOf("mypc", "local")) { write(l.length); write(l.toByteArray(Charsets.US_ASCII)) }
            write(0x00)
        }.toByteArray()
        val ans = ByteArrayOutputStream().apply {
            write(0xC0); write(0x0C)            // name pointer
            write(0x00); write(0x0C)            // TYPE = PTR
            write(0x00); write(0x01)            // CLASS = IN
            repeat(4) { write(0) }              // TTL
            write(rdata.size ushr 8); write(rdata.size and 0xFF)
            write(rdata)
        }.toByteArray()
        assertEquals("mypc", LocalNameQuery.parseLlmnrResponse(base + ans))
    }

    @Test fun llmnr_noAnswerReturnsNull() {
        val q = LocalNameQuery.buildLlmnrPtrQuery(0x0001, "192.168.1.5")  // ANCOUNT = 0
        assertNull(LocalNameQuery.parseLlmnrResponse(q))
    }
}
