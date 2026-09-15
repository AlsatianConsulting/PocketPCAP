package dev.alsatianconsulting.pocketpcap.decode

import dev.alsatianconsulting.pocketpcap.model.RilKind
import dev.alsatianconsulting.pocketpcap.model.RilLogEntry

/**
 * Parses an Android `radio` logcat snapshot (as collected by DiagnosticsManager)
 * into structured RIL entries. The Radio Interface Layer is how Android talks to
 * the modem; RILJ/RILC tags carry request (`> `), response (`< `) and unsolicited
 * (`UNSOL_…`) markers that we classify so the UI can colour and filter them.
 *
 * Input lines are `logcat -v time` format:
 *   06-16 12:34:56.789 D/RILJ    ( 1234): [0123]> GET_SIM_STATUS
 */
object RilParser {

    // "MM-DD HH:MM:SS.mmm L/TAG( PID): message"   (PID block is optional on some builds)
    private val LINE = Regex(
        """^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+([VDIWEF])/([^(:]+?)\s*(?:\(\s*\d+\))?\s*:\s?(.*)$"""
    )

    fun parse(raw: String): List<RilLogEntry> {
        val out = ArrayList<RilLogEntry>()
        for (line in raw.lineSequence()) {
            if (line.startsWith("#") || line.isBlank()) continue
            val m = LINE.matchEntire(line.trimEnd()) ?: continue
            val ts = m.groupValues[1]
            val level = m.groupValues[2]
            val tag = m.groupValues[3].trim()
            val msg = m.groupValues[4]
            out += RilLogEntry(ts, level, tag, msg, classify(msg))
        }
        return out
    }

    private fun classify(msg: String): RilKind {
        // RILJ uses "[token]> NAME" / "[token]< NAME"; unsolicited use "UNSOL_".
        val afterBracket = msg.substringAfter(']', msg)
        return when {
            msg.contains("UNSOL", ignoreCase = true) -> RilKind.UNSOL
            afterBracket.trimStart().startsWith(">") -> RilKind.REQUEST
            afterBracket.trimStart().startsWith("<") -> RilKind.RESPONSE
            msg.trimStart().startsWith(">") -> RilKind.REQUEST
            msg.trimStart().startsWith("<") -> RilKind.RESPONSE
            else -> RilKind.OTHER
        }
    }

}
