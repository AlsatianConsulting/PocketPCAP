package dev.alsatianconsulting.pocketpcap.capture

import org.junit.Assert.assertEquals
import java.io.ByteArrayOutputStream
import java.io.File
import org.junit.Test

/**
 * Regression cover for the file-list packet counter.
 *
 * The original walk ignored InputStream.skip's return value. BufferedInputStream
 * only skips what remains in its current buffer, so the scan desynchronised at the
 * first block spanning a buffer boundary and stopped early — a real 597-packet
 * capture reported 48. The fixtures here are deliberately larger than the 8 KiB
 * buffer so a short skip would show up as an undercount.
 */
class CaptureFileScanTest {

    private fun fixture(name: String): File =
        File(javaClass.classLoader!!.getResource(name)!!.toURI())

    @Test
    fun countsEveryPacketInTsharkGeneratedPcapng() {
        // analysis-fixture.pcapng is produced by scripts/generate-analysis-fixture.sh
        // via text2pcap + mergecap, so the expected count is fixed by that fixture.
        val expected = countBlocksDirectly(fixture("analysis-fixture.pcapng"))
        assertEquals(expected, CaptureFileScan.countPackets(fixture("analysis-fixture.pcapng")))
    }

    @Test
    fun countsAcrossBufferBoundaries() {
        // 400 packets of 1 KiB each: ~400 KiB, far past the 8 KiB buffer, so any
        // short skip that goes unchecked truncates the count.
        val file = writeTempPcapng(packets = 400, payload = 1024)
        assertEquals(400L, CaptureFileScan.countPackets(file))
    }

    @Test
    fun countsClassicPcapLittleEndian() {
        val file = writeTempPcap(packets = 300, payload = 1024, little = true)
        assertEquals(300L, CaptureFileScan.countPackets(file))
    }

    @Test
    fun countsClassicPcapBigEndian() {
        val file = writeTempPcap(packets = 300, payload = 1024, little = false)
        assertEquals(300L, CaptureFileScan.countPackets(file))
    }

    @Test
    fun countsNanosecondPcapLittleEndian() {
        // The nanosecond magic is 0xa1b23c4d. It was transposed to 0xa1b2c34d, so no
        // nanosecond pcap ever matched and every one of them counted zero packets -
        // including the ones this app's own rooted capture path writes.
        val file = writeTempPcap(packets = 300, payload = 1024, little = true, magic = 0xA1B23C4D.toInt())
        assertEquals(300L, CaptureFileScan.countPackets(file))
    }

    @Test
    fun countsNanosecondPcapBigEndian() {
        val file = writeTempPcap(packets = 300, payload = 1024, little = false, magic = 0xA1B23C4D.toInt())
        assertEquals(300L, CaptureFileScan.countPackets(file))
    }

    @Test
    fun returnsZeroForNonCaptureFile() {
        val file = File.createTempFile("not-a-capture", ".pcapng").apply {
            deleteOnExit(); writeBytes(ByteArray(4096) { 0x41 })
        }
        assertEquals(0L, CaptureFileScan.countPackets(file))
    }

    /** Independent full-file walk, used as the oracle for the shipped fixture. */
    private fun countBlocksDirectly(file: File): Long {
        val d = file.readBytes()
        var pos = 0
        var n = 0L
        while (pos + 8 <= d.size) {
            val type = le32(d, pos)
            val len = le32(d, pos + 4).toLong() and 0xFFFFFFFFL
            if (len < 12 || pos + len > d.size) break
            if (type == 6 || type == 3) n++
            pos += len.toInt()
        }
        return n
    }

    private fun writeTempPcapng(packets: Int, payload: Int): File {
        val out = ByteArrayOutputStream()
        // Section Header Block (28 bytes) then an Interface Description Block (20).
        out.u32(0x0A0D0D0A); out.u32(28); out.u32(0x1A2B3C4D)
        out.u16(1); out.u16(0); out.u32(-1); out.u32(-1); out.u32(28)
        out.u32(1); out.u32(20); out.u16(1); out.u16(0); out.u32(262_144); out.u32(20)
        repeat(packets) {
            val total = 32 + payload   // payload is already 4-byte aligned
            out.u32(6); out.u32(total); out.u32(0); out.u32(0); out.u32(it)
            out.u32(payload); out.u32(payload)
            out.write(ByteArray(payload))
            out.u32(total)
        }
        return File.createTempFile("scan", ".pcapng")
            .apply { deleteOnExit(); writeBytes(out.toByteArray()) }
    }

    /**
     * @param magic the file's native-order magic; big-endian files carry it byte-reversed,
     *   which is exactly how a reader tells the two apart.
     */
    private fun writeTempPcap(
        packets: Int,
        payload: Int,
        little: Boolean,
        magic: Int = 0xA1B2C3D4.toInt(),
    ): File {
        val out = ByteArrayOutputStream()
        if (little) {
            out.u32(magic); out.u16(2); out.u16(4)
            out.u32(0); out.u32(0); out.u32(262_144); out.u32(1)
        } else {
            out.b32(magic); out.b16(2); out.b16(4)
            out.b32(0); out.b32(0); out.b32(262_144); out.b32(1)
        }
        repeat(packets) {
            if (little) { out.u32(it); out.u32(0); out.u32(payload); out.u32(payload) }
            else { out.b32(it); out.b32(0); out.b32(payload); out.b32(payload) }
            out.write(ByteArray(payload))
        }
        return File.createTempFile("scan", ".pcap")
            .apply { deleteOnExit(); writeBytes(out.toByteArray()) }
    }

    private fun ByteArrayOutputStream.u16(v: Int) { write(v and 0xFF); write((v ushr 8) and 0xFF) }
    private fun ByteArrayOutputStream.u32(v: Int) {
        write(v and 0xFF); write((v ushr 8) and 0xFF)
        write((v ushr 16) and 0xFF); write((v ushr 24) and 0xFF)
    }
    private fun ByteArrayOutputStream.b16(v: Int) { write((v ushr 8) and 0xFF); write(v and 0xFF) }
    private fun ByteArrayOutputStream.b32(v: Int) {
        write((v ushr 24) and 0xFF); write((v ushr 16) and 0xFF)
        write((v ushr 8) and 0xFF); write(v and 0xFF)
    }

    private fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)
}
