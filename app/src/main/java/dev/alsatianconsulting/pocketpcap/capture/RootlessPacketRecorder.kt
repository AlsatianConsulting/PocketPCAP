package dev.alsatianconsulting.pocketpcap.capture

import dev.alsatianconsulting.pocketpcap.model.CaptureSession
import dev.alsatianconsulting.pocketpcap.model.CaptureState
import java.io.Closeable
import java.io.File
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Records rootless pass-through traffic observed at the local SOCKS relay.
 *
 * Android/tun2socks does not expose the original app-side source tuple to this relay,
 * so rootless pass-through pcapng uses a stable synthetic client address/port and the
 * real remote endpoint. Rooted interface capture remains the source for exact link-layer
 * packet captures.
 */
class RootlessPacketRecorder(
    private val session: CaptureSession,
    outFile: File,
    filterExpr: String,
) : Closeable {

    private val writer = PcapNgWriter(outFile)
    private val filter = RootlessPacketFilter(filterExpr)
    private val nextPort = AtomicInteger(40_000)
    private val packetCount = AtomicLong(0)
    private val byteCount = AtomicLong(0)
    private val lock = Any()
    private val paused = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Stop writing packets without tearing the tunnel down.
     *
     * Traffic keeps flowing for the apps in scope — only recording stops — so the
     * pcapng shows a genuine gap rather than a fabricated continuous stream.
     */
    fun pause() { paused.set(true) }

    fun resume() { paused.set(false) }

    val isPaused: Boolean get() = paused.get()

    fun newTcpFlow(remote: InetAddress, remotePort: Int): TcpFlow =
        TcpFlow(
            client = syntheticClientFor(remote),
            clientPort = nextPort.getAndUpdate { if (it >= 60_000) 40_000 else it + 1 },
            remote = remote,
            remotePort = remotePort,
        )

    fun recordTcp(flow: TcpFlow, fromClient: Boolean, data: ByteArray, length: Int) {
        if (length <= 0) return
        val packet = PacketSynthesizer.tcp(flow, fromClient, data, length)
        record(packet)
        if (fromClient) flow.clientSeq += length else flow.remoteSeq += length
    }

    fun recordUdp(remote: InetAddress, remotePort: Int, fromClient: Boolean, data: ByteArray, length: Int) {
        if (length <= 0) return
        val packet = PacketSynthesizer.udp(
            client = syntheticClientFor(remote),
            clientPort = 53_000 + (remotePort % 1000),
            remote = remote,
            remotePort = remotePort,
            fromClient = fromClient,
            payload = data,
            payloadLength = length,
        )
        record(packet)
    }

    private fun record(packet: ByteArray) {
        // Sequence numbers still advance in the caller while paused, so a resumed
        // capture stays consistent with the real byte stream and Wireshark reports
        // the gap honestly instead of silently renumbering.
        if (paused.get()) return
        val details = RootlessPacketParser.parse(packet, packet.size) ?: return
        if (!filter.accepts(details)) return
        val now = System.currentTimeMillis()
        synchronized(lock) {
            val number = packetCount.incrementAndGet()
            val bytes = byteCount.addAndGet(packet.size.toLong())
            writer.writePacket(packet, packet.size, now * 1000L)
            RootlessCaptureStore.appendPacket(
                RootlessPacketParser.summary(number, session.startTime, now, details)
            )
            RootlessCaptureStore.setSession(
                RootlessCaptureStore.session.value?.copy(
                    packetCount = number,
                    byteCount = bytes,
                    state = CaptureState.RUNNING,
                )
            )
        }
    }

    override fun close() {
        synchronized(lock) { writer.close() }
    }

    private fun syntheticClientFor(remote: InetAddress): InetAddress =
        if (remote is Inet6Address) InetAddress.getByName("fd00:215::2")
        else InetAddress.getByName("10.215.0.2")
}

data class TcpFlow(
    val client: InetAddress,
    val clientPort: Int,
    val remote: InetAddress,
    val remotePort: Int,
    var clientSeq: Int = 1,
    var remoteSeq: Int = 1,
)

private object PacketSynthesizer {

    fun tcp(flow: TcpFlow, fromClient: Boolean, payload: ByteArray, payloadLength: Int): ByteArray {
        val src = if (fromClient) flow.client else flow.remote
        val dst = if (fromClient) flow.remote else flow.client
        val srcPort = if (fromClient) flow.clientPort else flow.remotePort
        val dstPort = if (fromClient) flow.remotePort else flow.clientPort
        val seq = if (fromClient) flow.clientSeq else flow.remoteSeq
        val ack = if (fromClient) flow.remoteSeq else flow.clientSeq
        val tcp = ByteArray(20 + payloadLength)
        putU16(tcp, 0, srcPort)
        putU16(tcp, 2, dstPort)
        putU32(tcp, 4, seq)
        putU32(tcp, 8, ack)
        tcp[12] = (5 shl 4).toByte()
        tcp[13] = 0x18 // PSH + ACK
        putU16(tcp, 14, 65_535)
        System.arraycopy(payload, 0, tcp, 20, payloadLength)
        return ipPacket(src, dst, 6, tcp)
    }

    fun udp(
        client: InetAddress,
        clientPort: Int,
        remote: InetAddress,
        remotePort: Int,
        fromClient: Boolean,
        payload: ByteArray,
        payloadLength: Int,
    ): ByteArray {
        val src = if (fromClient) client else remote
        val dst = if (fromClient) remote else client
        val srcPort = if (fromClient) clientPort else remotePort
        val dstPort = if (fromClient) remotePort else clientPort
        val udp = ByteArray(8 + payloadLength)
        putU16(udp, 0, srcPort)
        putU16(udp, 2, dstPort)
        putU16(udp, 4, udp.size)
        System.arraycopy(payload, 0, udp, 8, payloadLength)
        return ipPacket(src, dst, 17, udp)
    }

    private fun ipPacket(src: InetAddress, dst: InetAddress, proto: Int, transport: ByteArray): ByteArray {
        return if (src is Inet6Address || dst is Inet6Address) ipv6(src, dst, proto, transport)
        else ipv4(src as Inet4Address, dst as Inet4Address, proto, transport)
    }

    private fun ipv4(src: Inet4Address, dst: Inet4Address, proto: Int, transport: ByteArray): ByteArray {
        val packet = ByteArray(20 + transport.size)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        putU16(packet, 4, 0)
        packet[8] = 64
        packet[9] = proto.toByte()
        System.arraycopy(src.address, 0, packet, 12, 4)
        System.arraycopy(dst.address, 0, packet, 16, 4)
        putU16(packet, 10, checksum(packet, 0, 20))
        System.arraycopy(transport, 0, packet, 20, transport.size)
        putTransportChecksum(packet, 20, src.address, dst.address, proto, transport.size)
        return packet
    }

    private fun ipv6(src: InetAddress, dst: InetAddress, proto: Int, transport: ByteArray): ByteArray {
        val packet = ByteArray(40 + transport.size)
        packet[0] = 0x60
        putU16(packet, 4, transport.size)
        packet[6] = proto.toByte()
        packet[7] = 64
        System.arraycopy(src.address, 0, packet, 8, 16)
        System.arraycopy(dst.address, 0, packet, 24, 16)
        System.arraycopy(transport, 0, packet, 40, transport.size)
        putTransportChecksum(packet, 40, src.address, dst.address, proto, transport.size)
        return packet
    }

    private fun putTransportChecksum(packet: ByteArray, offset: Int, src: ByteArray, dst: ByteArray, proto: Int, len: Int) {
        val checksumOffset = if (proto == 6) offset + 16 else offset + 6
        packet[checksumOffset] = 0
        packet[checksumOffset + 1] = 0
        val pseudo = if (src.size == 4) {
            ByteArray(12 + len).also {
                System.arraycopy(src, 0, it, 0, 4)
                System.arraycopy(dst, 0, it, 4, 4)
                it[9] = proto.toByte()
                putU16(it, 10, len)
                System.arraycopy(packet, offset, it, 12, len)
            }
        } else {
            ByteArray(40 + len).also {
                System.arraycopy(src, 0, it, 0, 16)
                System.arraycopy(dst, 0, it, 16, 16)
                putU32(it, 32, len)
                it[39] = proto.toByte()
                System.arraycopy(packet, offset, it, 40, len)
            }
        }
        putU16(packet, checksumOffset, checksum(pseudo, 0, pseudo.size))
    }

    private fun checksum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += (((bytes[i].toInt() and 0xFF) shl 8) or (bytes[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) sum += ((bytes[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }
}
