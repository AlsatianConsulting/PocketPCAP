package dev.alsatianconsulting.pocketpcap.capture

import java.io.Closeable
import java.io.File
import java.io.OutputStream

/**
 * Minimal pcapng writer for rootless VPN captures. Android's VpnService gives us
 * raw IP packets from a TUN device, so the interface link type is LINKTYPE_RAW.
 */
class PcapNgWriter(file: File) : Closeable {

    private val out: OutputStream = file.outputStream().buffered()
    private val pad = ByteArray(3)

    init {
        writeSectionHeader()
        writeInterfaceDescription()
    }

    fun writePacket(packet: ByteArray, length: Int, timestampUs: Long) {
        val padded = align4(length)
        val totalLen = 32 + padded
        writeU32(0x00000006) // Enhanced Packet Block
        writeU32(totalLen)
        writeU32(0) // interface id
        writeU32((timestampUs ushr 32).toInt())
        writeU32(timestampUs.toInt())
        writeU32(length)
        writeU32(length)
        out.write(packet, 0, length)
        if (padded > length) out.write(pad, 0, padded - length)
        writeU32(totalLen)
        // Flush on a block boundary so the file on disk is always a complete,
        // readable pcapng: Wireshark can open it while the capture is still
        // running, and an unclean exit costs no packets. The rootless relay
        // produces few, large blocks, so the per-packet write(2) is cheap.
        out.flush()
    }

    override fun close() {
        out.flush()
        out.close()
    }

    private fun writeSectionHeader() {
        val totalLen = 28
        writeU32(0x0A0D0D0A)
        writeU32(totalLen)
        writeU32(0x1A2B3C4D)
        writeU16(1)
        writeU16(0)
        writeU32(-1)
        writeU32(-1)
        writeU32(totalLen)
    }

    private fun writeInterfaceDescription() {
        val totalLen = 20
        writeU32(0x00000001)
        writeU32(totalLen)
        writeU16(101) // LINKTYPE_RAW
        writeU16(0)
        writeU32(262_144)
        writeU32(totalLen)
    }

    private fun align4(n: Int): Int = (n + 3) and -4

    private fun writeU16(value: Int) {
        out.write(value and 0xFF)
        out.write((value ushr 8) and 0xFF)
    }

    private fun writeU32(value: Int) {
        out.write(value and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 24) and 0xFF)
    }
}
