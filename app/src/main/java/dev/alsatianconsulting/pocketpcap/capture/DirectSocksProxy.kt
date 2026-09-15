package dev.alsatianconsulting.pocketpcap.capture

import android.net.VpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import java.io.EOFException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap

class DirectSocksProxy(
    private val vpnService: VpnService,
    private val scope: CoroutineScope,
    private val recorder: RootlessPacketRecorder,
) {
    private var server: ServerSocket? = null
    private var acceptJob: Job? = null
    private val udpRelays = ConcurrentHashMap<Int, UdpRelay>()

    val port: Int get() = server?.localPort ?: 0

    fun start(): Int {
        val s = ServerSocket()
        s.reuseAddress = true
        s.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        server = s
        acceptJob = scope.launch {
            while (isActive) {
                try {
                    val client = s.accept()
                    launch { handleClient(client) }
                } catch (_: Exception) {
                    if (isActive) continue else break
                }
            }
        }
        return s.localPort
    }

    /**
     * Idempotent: take the socket before closing it, so a second caller finds
     * nothing. Closing the same ServerSocket twice frees an fd that the VPN's
     * ParcelFileDescriptor may already have been handed, and fdsan aborts the
     * process for closing a descriptor it does not own.
     */
    @Synchronized
    fun stop() {
        val s = server
        server = null
        runCatching { s?.close() }
        udpRelays.values.forEach { runCatching { it.stop() } }
        udpRelays.clear()
        acceptJob?.cancel()
        acceptJob = null
    }

    private suspend fun handleClient(client: Socket) {
        client.use { socks ->
            socks.tcpNoDelay = true
            val input = socks.getInputStream().buffered()
            val output = socks.getOutputStream().buffered()
            val version = input.read()
            if (version != 0x05) return
            val methodCount = input.read()
            if (methodCount <= 0) return
            repeat(methodCount) { input.read() }
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            val requestVersion = input.read()
            if (requestVersion != 0x05) return
            val command = input.read()
            input.read() // reserved
            val host = readSocksAddress(input)
            val port = readU16(input)

            when (command) {
                0x01 -> handleConnect(socks, output, host, port)
                0x03 -> handleUdpAssociate(socks, input, output)
                else -> writeReply(output, 0x07, InetAddress.getByName("0.0.0.0"), 0)
            }
        }
    }

    private suspend fun handleConnect(client: Socket, output: java.io.OutputStream, host: String, port: Int) {
        val remote = Socket()
        vpnService.protect(remote)
        try {
            remote.tcpNoDelay = true
            remote.connect(InetSocketAddress(host, port), 15_000)
            val remoteAddress = remote.inetAddress
            val flow = recorder.newTcpFlow(remoteAddress, port)
            writeReply(output, 0x00, InetAddress.getByName("0.0.0.0"), 0)
            val a = scope.launch { copyTcp(client, remote, flow, fromClient = true) }
            val b = scope.launch { copyTcp(remote, client, flow, fromClient = false) }
            joinAll(a, b)
        } catch (_: Exception) {
            writeReply(output, 0x01, InetAddress.getByName("0.0.0.0"), 0)
        } finally {
            runCatching { remote.close() }
        }
    }

    private suspend fun handleUdpAssociate(
        control: Socket,
        input: java.io.InputStream,
        output: java.io.OutputStream,
    ) {
        val relay = UdpRelay(vpnService, scope, recorder)
        val relayPort = relay.start()
        udpRelays[relayPort] = relay
        writeReply(output, 0x00, InetAddress.getByName("127.0.0.1"), relayPort)
        val keepalive = ByteArray(1)
        try {
            while (scope.isActive && !control.isClosed && input.read(keepalive) >= 0) {
                // The TCP control connection only defines the UDP relay lifetime.
            }
        } catch (_: Exception) {
        } finally {
            udpRelays.remove(relayPort)
            relay.stop()
        }
    }

    private fun copyTcp(
        inputSocket: Socket,
        outputSocket: Socket,
        flow: TcpFlow,
        fromClient: Boolean,
    ) {
        val input = inputSocket.getInputStream()
        val output = outputSocket.getOutputStream()
        val buf = ByteArray(16 * 1024)
        try {
            while (!inputSocket.isClosed && !outputSocket.isClosed) {
                val n = input.read(buf)
                if (n <= 0) break
                output.write(buf, 0, n)
                output.flush()
                recorder.recordTcp(flow, fromClient, buf, n)
            }
        } catch (_: Exception) {
        } finally {
            runCatching { outputSocket.shutdownOutput() }
        }
    }

    private fun writeReply(output: java.io.OutputStream, code: Int, bindAddress: InetAddress, bindPort: Int) {
        val addr = bindAddress.address
        val atyp = if (addr.size == 16) 0x04 else 0x01
        output.write(byteArrayOf(0x05, code.toByte(), 0x00, atyp.toByte()))
        output.write(addr)
        output.write(byteArrayOf((bindPort ushr 8).toByte(), bindPort.toByte()))
        output.flush()
    }

    private fun readSocksAddress(input: java.io.InputStream): String {
        return when (val atyp = input.read()) {
            0x01 -> InetAddress.getByAddress(readFully(input, 4)).hostAddress ?: throw EOFException()
            0x03 -> {
                val len = input.read()
                String(readFully(input, len), Charsets.UTF_8)
            }
            0x04 -> InetAddress.getByAddress(readFully(input, 16)).hostAddress ?: throw EOFException()
            else -> throw IllegalArgumentException("Unsupported address type $atyp")
        }
    }

    private fun readU16(input: java.io.InputStream): Int {
        val hi = input.read()
        val lo = input.read()
        if (hi < 0 || lo < 0) throw EOFException()
        return (hi shl 8) or lo
    }

    private fun readFully(input: java.io.InputStream, len: Int): ByteArray {
        val out = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = input.read(out, off, len - off)
            if (n < 0) throw EOFException()
            off += n
        }
        return out
    }
}

private class UdpRelay(
    private val vpnService: VpnService,
    private val scope: CoroutineScope,
    private val recorder: RootlessPacketRecorder,
) {
    private var socket: DatagramSocket? = null
    private var job: Job? = null
    private val clients = ConcurrentHashMap<String, InetSocketAddress>()

    fun start(): Int {
        val s = DatagramSocket(null)
        vpnService.protect(s)
        s.soTimeout = 1000
        s.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        socket = s
        job = scope.launch { loop(s) }
        return s.localPort
    }

    fun stop() {
        runCatching { socket?.close() }
        socket = null
        job?.cancel()
        job = null
    }

    private fun loop(sock: DatagramSocket) {
        val buf = ByteArray(65_535)
        while (scope.isActive && !sock.isClosed) {
            try {
                val packet = DatagramPacket(buf, buf.size)
                sock.receive(packet)
                val source = packet.socketAddress as InetSocketAddress
                if (source.address.isLoopbackAddress && isSocksUdp(buf, packet.length)) {
                    val parsed = parseSocksUdp(buf, packet.length) ?: continue
                    clients[remoteKey(parsed.address, parsed.port)] = source
                    recorder.recordUdp(parsed.address, parsed.port, fromClient = true, parsed.payload, parsed.payload.size)
                    sock.send(DatagramPacket(parsed.payload, parsed.payload.size, parsed.address, parsed.port))
                } else {
                    val client = clients[remoteKey(source.address, source.port)] ?: continue
                    val wrapped = wrapSocksUdp(source.address, source.port, buf, packet.length)
                    recorder.recordUdp(source.address, source.port, fromClient = false, buf, packet.length)
                    sock.send(DatagramPacket(wrapped, wrapped.size, client.address, client.port))
                }
            } catch (_: SocketTimeoutException) {
            } catch (_: Exception) {
                if (!sock.isClosed) continue else break
            }
        }
    }

    private fun isSocksUdp(data: ByteArray, length: Int): Boolean =
        length >= 10 && data[0].toInt() == 0 && data[1].toInt() == 0 && data[2].toInt() == 0

    private fun parseSocksUdp(data: ByteArray, length: Int): UdpPayload? {
        var pos = 3
        val address = when (data[pos++].toInt() and 0xFF) {
            0x01 -> InetAddress.getByAddress(data.copyOfRange(pos, pos + 4)).also { pos += 4 }
            0x03 -> {
                val len = data[pos++].toInt() and 0xFF
                InetAddress.getByName(String(data, pos, len, Charsets.UTF_8)).also { pos += len }
            }
            0x04 -> InetAddress.getByAddress(data.copyOfRange(pos, pos + 16)).also { pos += 16 }
            else -> return null
        }
        if (pos + 2 > length) return null
        val port = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        if (pos > length) return null
        return UdpPayload(address, port, data.copyOfRange(pos, length))
    }

    private fun wrapSocksUdp(address: InetAddress, port: Int, payload: ByteArray, payloadLength: Int): ByteArray {
        val addr = address.address
        val atyp = if (addr.size == 16) 0x04 else 0x01
        val out = ByteArray(4 + addr.size + 2 + payloadLength)
        var pos = 3
        out[pos++] = atyp.toByte()
        System.arraycopy(addr, 0, out, pos, addr.size)
        pos += addr.size
        out[pos++] = (port ushr 8).toByte()
        out[pos++] = port.toByte()
        System.arraycopy(payload, 0, out, pos, payloadLength)
        return out
    }

    private fun remoteKey(address: InetAddress, port: Int): String = "${address.hostAddress}:$port"
}

private data class UdpPayload(
    val address: InetAddress,
    val port: Int,
    val payload: ByteArray,
)
