package dev.alsatianconsulting.pocketpcap.resolve

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException

/**
 * Active local name resolution for endpoints on the link:
 *   - **NetBIOS** node-status (NBSTAT) query to UDP/137 — yields the SMB/Windows
 *     machine name.
 *   - **LLMNR** reverse (PTR) query to the link-local multicast group on UDP/5355 —
 *     yields the responder's host name.
 *
 * Both are link-local protocols, so callers restrict them to private IPv4 addresses.
 * The packet encode/parse helpers are pure (and unit-tested); the `*Name` helpers do
 * the (short, timeout-bounded) UDP I/O.
 */
object LocalNameQuery {

    const val NBNS_PORT = 137
    const val LLMNR_PORT = 5355
    const val LLMNR_GROUP_V4 = "224.0.0.252"

    // --- NetBIOS NBSTAT -------------------------------------------------------

    /**
     * Build a NetBIOS node-status request for the wildcard name "*". This is the same
     * query `nbtstat -A <ip>` sends; the response lists the host's registered names.
     */
    fun buildNbstatQuery(txId: Int): ByteArray {
        val out = ByteArrayOutputStream(50)
        out.write((txId ushr 8) and 0xFF); out.write(txId and 0xFF)
        out.write(0x00); out.write(0x00)        // flags
        out.write(0x00); out.write(0x01)        // QDCOUNT = 1
        repeat(6) { out.write(0x00) }           // AN/NS/AR counts = 0
        // QNAME: first-level-encode the 16-byte NetBIOS name "*\0\0...".
        out.write(0x20)                         // label length = 32
        val name = ByteArray(16).also { it[0] = '*'.code.toByte() }
        for (b in name) {
            val v = b.toInt() and 0xFF
            out.write('A'.code + (v ushr 4))
            out.write('A'.code + (v and 0x0F))
        }
        out.write(0x00)                         // end of name
        out.write(0x00); out.write(0x21)        // QTYPE = NBSTAT
        out.write(0x00); out.write(0x01)        // QCLASS = IN
        return out.toByteArray()
    }

    /**
     * Parse an NBSTAT response, returning the host's preferred name: the first UNIQUE
     * (non-group) workstation entry (suffix 0x00), else the first UNIQUE name.
     */
    fun parseNbstatResponse(resp: ByteArray): String? {
        try {
            var pos = 12                         // skip header
            // Skip the echoed question name (label sequence terminated by 0x00).
            while (pos < resp.size && resp[pos].toInt() != 0) pos += 1 + (resp[pos].toInt() and 0xFF)
            pos += 1                             // null terminator
            pos += 4                             // QTYPE + QCLASS
            // Answer RR name: a pointer (0xC0..) or labels.
            if (pos >= resp.size) return null
            pos += if ((resp[pos].toInt() and 0xC0) == 0xC0) 2
                   else { var p = pos; while (p < resp.size && resp[p].toInt() != 0) p += 1 + (resp[p].toInt() and 0xFF); p + 1 - pos }
            pos += 2 + 2 + 4                     // TYPE + CLASS + TTL
            pos += 2                             // RDLENGTH
            if (pos >= resp.size) return null
            val numNames = resp[pos].toInt() and 0xFF; pos += 1
            var fallback: String? = null
            for (i in 0 until numNames) {
                if (pos + 18 > resp.size) break
                val nm = String(resp, pos, 15, Charsets.US_ASCII).trim()
                val suffix = resp[pos + 15].toInt() and 0xFF
                val flags = resp[pos + 16].toInt() and 0xFF
                pos += 18
                val isGroup = (flags and 0x80) != 0
                // Skip group names and any entry containing control chars (e.g. the
                // special "__MSBROWSE__" browser name).
                if (isGroup || nm.isEmpty() || nm.any { it.code < 0x20 }) continue
                if (suffix == 0x00) return nm    // workstation service — the machine name
                if (fallback == null) fallback = nm
            }
            return fallback
        } catch (_: Exception) { return null }
    }

    /** Send an NBSTAT query to [ip] and return the resolved name, or null. */
    fun netbiosName(ip: String, timeoutMs: Int): String? {
        return try {
            val q = buildNbstatQuery(System.nanoTime().toInt() and 0xFFFF)
            DatagramSocket().use { s ->
                s.soTimeout = timeoutMs
                s.send(DatagramPacket(q, q.size, InetAddress.getByName(ip), NBNS_PORT))
                val buf = ByteArray(1024)
                val resp = DatagramPacket(buf, buf.size)
                s.receive(resp)
                parseNbstatResponse(buf.copyOf(resp.length))
            }
        } catch (_: SocketTimeoutException) { null } catch (_: Exception) { null }
    }

    // --- LLMNR reverse (PTR) --------------------------------------------------

    /** Build an LLMNR PTR query for an IPv4 address's <reverse>.in-addr.arpa name. */
    fun buildLlmnrPtrQuery(txId: Int, ipv4: String): ByteArray {
        val out = ByteArrayOutputStream(64)
        out.write((txId ushr 8) and 0xFF); out.write(txId and 0xFF)
        out.write(0x00); out.write(0x00)        // flags (standard query)
        out.write(0x00); out.write(0x01)        // QDCOUNT = 1
        repeat(6) { out.write(0x00) }
        // QNAME = reversed octets + "in-addr" + "arpa"
        val labels = ipv4.split(".").reversed() + listOf("in-addr", "arpa")
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size); out.write(bytes)
        }
        out.write(0x00)                         // end of name
        out.write(0x00); out.write(0x0C)        // QTYPE = PTR
        out.write(0x00); out.write(0x01)        // QCLASS = IN
        return out.toByteArray()
    }

    /** Parse an LLMNR/DNS response and return the first PTR target name, or null. */
    fun parseLlmnrResponse(resp: ByteArray): String? {
        try {
            val anCount = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
            if (anCount < 1) return null
            var pos = 12
            // Skip question name + QTYPE + QCLASS.
            pos = skipName(resp, pos) + 4
            // First answer RR.
            pos = skipName(resp, pos)
            val type = ((resp[pos].toInt() and 0xFF) shl 8) or (resp[pos + 1].toInt() and 0xFF)
            pos += 2 + 2 + 4                     // TYPE + CLASS + TTL
            pos += 2                             // RDLENGTH
            if (type != 0x0C) return null        // not PTR
            val name = readName(resp, pos)
            return name?.trimEnd('.')?.substringBefore('.')?.takeIf { it.isNotBlank() }
        } catch (_: Exception) { return null }
    }

    private fun skipName(resp: ByteArray, start: Int): Int {
        var pos = start
        while (pos < resp.size) {
            val len = resp[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1
                (len and 0xC0) == 0xC0 -> return pos + 2   // compression pointer
                else -> pos += 1 + len
            }
        }
        return pos
    }

    private fun readName(resp: ByteArray, start: Int): String? {
        val sb = StringBuilder()
        var pos = start
        var hops = 0
        while (pos < resp.size && hops < 64) {
            val len = resp[pos].toInt() and 0xFF
            when {
                len == 0 -> break
                (len and 0xC0) == 0xC0 -> {
                    pos = ((len and 0x3F) shl 8) or (resp[pos + 1].toInt() and 0xFF)
                    hops++
                }
                else -> {
                    if (sb.isNotEmpty()) sb.append('.')
                    sb.append(String(resp, pos + 1, len, Charsets.US_ASCII))
                    pos += 1 + len
                }
            }
        }
        return sb.toString().ifEmpty { null }
    }

    /** Send an LLMNR PTR query to the link-local multicast group; return the name. */
    fun llmnrName(ipv4: String, timeoutMs: Int): String? {
        return try {
            val q = buildLlmnrPtrQuery(System.nanoTime().toInt() and 0xFFFF, ipv4)
            DatagramSocket().use { s ->
                s.soTimeout = timeoutMs
                s.send(DatagramPacket(q, q.size, InetAddress.getByName(LLMNR_GROUP_V4), LLMNR_PORT))
                val buf = ByteArray(1024)
                val resp = DatagramPacket(buf, buf.size)
                s.receive(resp)                  // responders reply unicast to our port
                parseLlmnrResponse(buf.copyOf(resp.length))
            }
        } catch (_: SocketTimeoutException) { null } catch (_: Exception) { null }
    }
}
