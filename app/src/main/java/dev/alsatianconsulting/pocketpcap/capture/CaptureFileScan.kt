package dev.alsatianconsulting.pocketpcap.capture

import java.io.File
import java.io.InputStream

/**
 * Header-only scan of a capture file, used by the file list to show a packet count
 * without paying for a full dissect.
 *
 * Handles pcapng (Enhanced/Simple Packet Blocks) and classic pcap (fixed 16-byte
 * record headers, either byte order), since the file list accepts both extensions.
 * Anything it cannot walk confidently returns 0, which the UI renders as "no count"
 * rather than a wrong number.
 */
object CaptureFileScan {

    private const val PCAPNG_SHB = 0x0A0D0D0A
    private const val BLOCK_EPB = 0x00000006
    private const val BLOCK_SPB = 0x00000003

    // Classic pcap magics as read little-endian: LE/BE files, µs and ns variants.
    // The nanosecond magic is 0xa1b23c4d, not 0xa1b2c34d - the middle bytes are 3c,
    // not c3. Transposing them meant no nanosecond pcap ever matched and every one
    // counted zero packets, while importPcap's own magic list accepted the file.
    private val PCAP_LE = 0xA1B2C3D4.toInt()
    private val PCAP_LE_NS = 0xA1B23C4D.toInt()
    private val PCAP_BE = 0xD4C3B2A1.toInt()
    private const val PCAP_BE_NS = 0x4D3CB2A1

    private const val MAX_BLOCK = 16L * 1024 * 1024

    fun countPackets(file: File): Long {
        if (!file.exists() || file.length() < 24) return 0L
        return try {
            file.inputStream().buffered().use { countPackets(it) }
        } catch (_: Exception) {
            0L
        }
    }

    /** Scan an already-open stream positioned at the start of the file. */
    fun countPackets(stream: InputStream): Long {
        val head = ByteArray(4)
        if (!readFully(stream, head, 4)) return 0L
        return when (le32(head, 0)) {
            PCAPNG_SHB -> countPcapngBlocks(stream)
            PCAP_LE, PCAP_LE_NS -> countPcapRecords(stream, little = true)
            PCAP_BE, PCAP_BE_NS -> countPcapRecords(stream, little = false)
            else -> 0L
        }
    }

    /**
     * Count EPB/SPB blocks. The caller has already consumed the leading SHB type, so
     * read that block's length first and skip its body, then walk block headers.
     * A big-endian section makes every length fail the sanity check and yields 0.
     */
    private fun countPcapngBlocks(stream: InputStream): Long {
        val buf = ByteArray(8)
        if (!readFully(stream, buf, 4)) return 0L
        var len = le32(buf, 0).toLong() and 0xFFFFFFFFL
        if (len < 12 || len > MAX_BLOCK) return 0L
        if (!skipFully(stream, len - 8)) return 0L
        var count = 0L
        while (readFully(stream, buf, 8)) {
            val type = le32(buf, 0)
            len = le32(buf, 4).toLong() and 0xFFFFFFFFL
            if (len < 12 || len > MAX_BLOCK) break
            if (type == BLOCK_EPB || type == BLOCK_SPB) count++
            if (!skipFully(stream, len - 8)) break
        }
        return count
    }

    /** Count classic pcap records; the 4-byte magic is already consumed. */
    private fun countPcapRecords(stream: InputStream, little: Boolean): Long {
        val buf = ByteArray(16)
        if (!skipFully(stream, 20)) return 0L   // rest of the 24-byte global header
        var count = 0L
        while (readFully(stream, buf, 16)) {
            val capLen = (if (little) le32(buf, 8) else be32(buf, 8)).toLong() and 0xFFFFFFFFL
            if (capLen > MAX_BLOCK) break
            count++
            if (!skipFully(stream, capLen)) break
        }
        return count
    }

    private fun readFully(stream: InputStream, buf: ByteArray, n: Int): Boolean {
        var off = 0
        while (off < n) {
            val r = stream.read(buf, off, n - off)
            if (r < 0) return false
            off += r
        }
        return true
    }

    /**
     * InputStream.skip is allowed to skip short, and BufferedInputStream routinely
     * does: it only skips what is left in its current buffer. Ignoring the return
     * value desynchronises the walk at the first block that straddles a buffer
     * boundary and stops it early — a 597-packet capture counted 48 that way.
     */
    private fun skipFully(stream: InputStream, n: Long): Boolean {
        var left = n
        while (left > 0) {
            val skipped = stream.skip(left)
            if (skipped > 0) { left -= skipped; continue }
            // skip() made no progress; read a byte to advance or detect EOF.
            if (stream.read() < 0) return false
            left--
        }
        return true
    }

    private fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

    private fun be32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
}
