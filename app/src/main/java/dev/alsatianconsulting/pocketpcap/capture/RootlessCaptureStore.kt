package dev.alsatianconsulting.pocketpcap.capture

import dev.alsatianconsulting.pocketpcap.model.CaptureSession
import dev.alsatianconsulting.pocketpcap.model.PacketSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object RootlessCaptureStore {
    private val _session = MutableStateFlow<CaptureSession?>(null)
    val session: StateFlow<CaptureSession?> = _session

    private val _packets = MutableStateFlow<List<PacketSummary>>(emptyList())
    val packets: StateFlow<List<PacketSummary>> = _packets

    fun setSession(session: CaptureSession?) {
        _session.value = session
    }

    fun appendPacket(packet: PacketSummary) {
        val current = _packets.value
        _packets.value = if (current.size >= 10_000) current.drop(current.size - 9_999) + packet
        else current + packet
    }

    fun clearPackets() {
        _packets.value = emptyList()
    }

    fun reset() {
        _session.value = null
        _packets.value = emptyList()
    }
}
