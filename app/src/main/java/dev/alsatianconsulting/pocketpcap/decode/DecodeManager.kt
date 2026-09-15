package dev.alsatianconsulting.pocketpcap.decode

import android.content.Context
import dev.alsatianconsulting.pocketpcap.analysis.AnalysisScope
import dev.alsatianconsulting.pocketpcap.analysis.CaptureAnalysis
import dev.alsatianconsulting.pocketpcap.analysis.CaptureAnalysisParser
import dev.alsatianconsulting.pocketpcap.analysis.CaptureSearchResult
import dev.alsatianconsulting.pocketpcap.analysis.SearchEntity
import dev.alsatianconsulting.pocketpcap.model.DecodeNode
import dev.alsatianconsulting.pocketpcap.model.DecodeTree
import dev.alsatianconsulting.pocketpcap.model.Endpoint
import dev.alsatianconsulting.pocketpcap.model.ExportedObject
import dev.alsatianconsulting.pocketpcap.model.FollowStream
import dev.alsatianconsulting.pocketpcap.model.PacketColor
import dev.alsatianconsulting.pocketpcap.model.PacketSummary
import dev.alsatianconsulting.pocketpcap.model.ProtoHierarchyNode
import dev.alsatianconsulting.pocketpcap.model.RawBytes
import dev.alsatianconsulting.pocketpcap.model.StreamRef
import dev.alsatianconsulting.pocketpcap.model.StreamSegment
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Drives the bundled tshark to decode capture files with full Wireshark protocol
 * coverage. Three operations:
 *   - packetList(file)         → summary rows for the packet list
 *   - decodeTree(file, num)    → Wireshark-style protocol tree (PDML) for one packet
 *   - rawBytes(file, num)      → raw frame bytes for the hex view
 *
 * tshark runs via `su`; output is parsed on the calling (background) thread.
 */
class DecodeManager(context: Context) {

    val bundle = TsharkBundle(context)
    val decryption = DecryptionManager(context)
    val diagnostics = DiagnosticsManager(context, bundle)

    @Volatile private var analysisCache: AnalysisCache? = null

    private data class AnalysisCache(
        val path: String,
        val size: Long,
        val modified: Long,
        val decryptionArgs: List<String>,
        val displayFilter: String,
        val value: CaptureAnalysis,
    )

    companion object {
        /** Ceiling on rows held for the packet list; see [packetList]. */
        const val PACKET_LIST_LIMIT = 50_000

        /**
         * Shown when the bundled tshark is missing or will not run.
         *
         * Decoding needs no privileges, so reaching this means the install itself is
         * wrong: the native libraries did not land, or the ABI does not match.
         */
        const val NO_TSHARK_MESSAGE =
            "The bundled tshark could not be started. This build ships it for 64-bit " +
            "ARM devices; on any other architecture, or if the install is incomplete, " +
            "decoding is unavailable. Capture still works, and the .pcapng files it " +
            "writes open normally in Wireshark on a computer."

        // Tab-separated column layout shared with live capture parsing.
        val COLUMN_ARGS = listOf(
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "_ws.col.Source",
            "-e", "_ws.col.Destination",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "_ws.col.Info",
            "-E", "separator=/t",
            "-E", "occurrence=f",
        )
    }

    /**
     * Ready means the bundled tshark is executable and its data files are unpacked.
     * No root is involved: the executables live in the app's native library
     * directory precisely so an unprivileged app may run them.
     */
    fun ensureReady(): Boolean = bundle.isExecutable() && bundle.ensureExtracted()

    /**
     * Run one whole-capture fields export and derive all mobile analysis entities.
     * Results are cached by file identity, decryption inputs and optional scope filter.
     */
    @Synchronized
    fun captureAnalysis(file: File, displayFilter: String = ""): CaptureAnalysis {
        check(ensureReady()) { NO_TSHARK_MESSAGE }
        val dec = decryption.optionArgs()
        analysisCache?.let { cached ->
            if (cached.path == file.absolutePath && cached.size == file.length() &&
                cached.modified == file.lastModified() && cached.decryptionArgs == dec &&
                cached.displayFilter == displayFilter) return cached.value
        }
        val args = mutableListOf("-r", file.absolutePath, "-n")
        args += dec
        if (displayFilter.isNotBlank()) args += listOf("-Y", displayFilter)
        args += listOf("-T", "fields")
        CaptureAnalysisParser.fields.forEach { args += listOf("-e", it) }
        args += listOf("-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n")
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 300_000)
        check(res.ok) {
            val detail = res.stderr.lineSequence().firstOrNull { it.isNotBlank() }
                ?: "exit code ${res.exitCode}"
            "tshark analysis failed: $detail"
        }
        val value = CaptureAnalysisParser.parse(
            res.stdout, file.name, file.length(),
            if (displayFilter.isBlank()) AnalysisScope.WHOLE_CAPTURE else AnalysisScope.DISPLAY_FILTER,
        )
        analysisCache = AnalysisCache(file.absolutePath, file.length(), file.lastModified(), dec, displayFilter, value)
        return value
    }

    fun clearAnalysisCache() { analysisCache = null }

    /**
     * Decode a capture file into packet summary rows, bounded by [limit].
     *
     * The list is held in memory and rendered as a LazyColumn, so an unbounded
     * decode of a very large capture would build millions of row objects. Callers
     * that need to tell the operator the view is partial can compare the result
     * size against [PACKET_LIST_LIMIT]. Note the bound applies to the parsed rows;
     * tshark's own output is still collected in full by Exec, so a genuinely
     * huge capture is best narrowed with a display filter first.
     */
    fun packetList(
        file: File,
        displayFilter: String = "",
        limit: Int = PACKET_LIST_LIMIT,
    ): List<PacketSummary> {
        if (!ensureReady()) return emptyList()
        val args = mutableListOf("-r", file.absolutePath, "-n")
        args += decryption.optionArgs()
        if (displayFilter.isNotBlank()) { args += "-Y"; args += displayFilter }
        args += COLUMN_ARGS
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 120_000)
        if (!res.ok && res.stdout.isBlank()) return emptyList()
        return res.stdout.lineSequence()
            .mapNotNull { parseColumnRow(it) }
            .take(limit)
            .toList()
    }

    /** Parse one tab-separated tshark column row into a PacketSummary. */
    fun parseColumnRow(line: String): PacketSummary? {
        if (line.isBlank()) return null
        val c = line.split("\t")
        if (c.size < 7) return null
        val number = c[0].trim().toLongOrNull() ?: return null
        val tRel = c[1].trim().toDoubleOrNull() ?: 0.0
        val proto = c[4].trim().ifBlank { "?" }
        val len = c[5].trim().toIntOrNull() ?: 0
        return PacketSummary(
            number = number,
            timestampUs = (tRel * 1_000_000L).toLong(),
            src = c[2].trim(),
            dst = c[3].trim(),
            protocol = proto,
            length = len,
            info = c[6].trim(),
            colorHint = colorFor(proto),
        )
    }

    /**
     * Validate a Wireshark display filter without decoding a file. Returns null if
     * the filter is valid, or a human-readable error message if not.
     */
    fun validateFilter(filter: String): String? {
        if (filter.isBlank()) return null
        if (!ensureReady()) return null   // can't validate yet; let decode attempt it
        // Compile the filter against an empty input. A bad filter fails compilation
        // before any file is read; the subsequent /dev/null read error is ignored.
        val res = Exec.run(bundle.tsharkArgv(listOf("-Y", filter, "-r", "/dev/null")), bundle.env(), timeoutMs = 15_000)
        val errText = res.stderr + res.stdout
        val syntaxLine = errText.lineSequence().firstOrNull {
            it.contains("not a valid protocol or protocol field", true) ||
            it.contains("neither a field nor a protocol", true) ||
            it.contains("was unexpected", true) ||
            it.contains("syntax error", true) ||
            it.contains("isn't a valid", true) ||
            it.contains("cannot be parsed", true) ||
            (it.startsWith("tshark:", true) && it.contains("filter", true) && !it.contains("/dev/null"))
        }
        return syntaxLine?.removePrefix("tshark:")?.trim()
    }

    /** Decode one packet into a Wireshark-style protocol tree via PDML. */
    fun decodeTree(file: File, frameNumber: Long): DecodeTree? {
        if (!ensureReady()) return null
        val args = mutableListOf("-r", file.absolutePath, "-n")
        args += decryption.optionArgs()
        args += listOf("-Y", "frame.number==$frameNumber", "-T", "pdml")
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 60_000)
        if (res.stdout.isBlank()) return null
        return parsePdml(res.stdout)
    }

    /** Raw frame bytes for one packet, via tshark hex output (any capture format). */
    fun rawBytes(file: File, frameNumber: Long): RawBytes? {
        if (!ensureReady()) return null
        val args = listOf(
            "-r", file.absolutePath, "-n",
            "-Y", "frame.number==$frameNumber",
            "-x",
        )
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 60_000)
        val bytes = parseHexDump(res.stdout) ?: return null
        return RawBytes(bytes)
    }

    // --- Statistics: protocol hierarchy --------------------------------------

    /**
     * Wireshark's Statistics → Protocol Hierarchy (tshark -z io,phs). Returns a
     * flat, depth-tagged list (eth → ip → tcp → tls …) with per-protocol frame and
     * byte totals. An optional display filter scopes the stats.
     */
    fun protocolHierarchy(file: File, displayFilter: String = ""): List<ProtoHierarchyNode> {
        if (!ensureReady()) return emptyList()
        val args = mutableListOf("-r", file.absolutePath, "-n", "-q")
        args += decryption.optionArgs()
        if (displayFilter.isNotBlank()) { args += "-z"; args += "io,phs,$displayFilter" }
        else { args += "-z"; args += "io,phs" }
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 120_000)
        return parseProtocolHierarchy(res.stdout)
    }

    private fun parseProtocolHierarchy(text: String): List<ProtoHierarchyNode> {
        val out = mutableListOf<ProtoHierarchyNode>()
        var inBody = false
        var total = 0L
        // Lines look like:  "  ip                    frames:170 bytes:17000"
        val rowRe = Regex("""^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+).*$""")
        for (raw in text.lineSequence()) {
            val line = raw.trimEnd()
            if (line.startsWith("Protocol Hierarchy")) { inBody = true; continue }
            if (!inBody) continue
            if (line.startsWith("=====")) break
            val m = rowRe.matchEntire(line) ?: continue
            val indent = m.groupValues[1].length
            // tshark uses 2 spaces per level; the top "frame"/"eth" rows are at 0.
            val depth = indent / 2
            val frames = m.groupValues[3].toLongOrNull() ?: 0L
            val bytes = m.groupValues[4].toLongOrNull() ?: 0L
            if (depth == 0) total = maxOf(total, frames)
            out += ProtoHierarchyNode(m.groupValues[2], depth, frames, bytes)
        }
        if (total <= 0) total = out.firstOrNull()?.frames ?: 0L
        return out.map { it.copy(percentPackets = if (total > 0) it.frames * 100.0 / total else 0.0) }
    }

    // --- Statistics: endpoints -----------------------------------------------

    /**
     * Wireshark's Statistics → Endpoints (tshark -z endpoints,<type>). type is one
     * of ip, ipv6, tcp, udp, eth. Returns address + traffic counters.
     */
    fun endpoints(file: File, type: String = "ip", displayFilter: String = ""): List<Endpoint> {
        if (!ensureReady()) return emptyList()
        val spec = if (displayFilter.isNotBlank()) "endpoints,$type,$displayFilter" else "endpoints,$type"
        val args = mutableListOf("-r", file.absolutePath, "-n", "-q", "-z", spec)
        val argsWithDec = decryption.optionArgs() + args
        val res = Exec.run(bundle.tsharkArgv(argsWithDec), bundle.env(), timeoutMs = 120_000)
        return parseEndpoints(res.stdout)
    }

    private fun parseEndpoints(text: String): List<Endpoint> {
        val out = mutableListOf<Endpoint>()
        // tshark 4.6 formats byte columns with unit suffixes and comma grouping, e.g.
        //   "10.0.0.1   5   7,210 bytes   5   7,210 bytes   0   0 bytes"
        // and TCP/UDP add a Port column before Packets. The 9 trailing tokens are
        // always: pkts, bytesNum, bytesUnit, txPkts, txBN, txBU, rxPkts, rxBN, rxBU.
        // Everything before them is the address (plus an optional port).
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("=") || line.startsWith("Filter") ||
                line.startsWith("|") || line.contains("Endpoints")) continue
            val toks = line.split(Regex("\\s+"))
            if (toks.size < 10) continue
            val stat = toks.takeLast(9)
            val pkts = intTok(stat[0]) ?: continue          // header/footer fall out here
            val bytes = bytesTok(stat[1], stat[2]) ?: continue
            val txP = intTok(stat[3]) ?: continue
            val txB = bytesTok(stat[4], stat[5]) ?: continue
            val rxP = intTok(stat[6]) ?: continue
            val rxB = bytesTok(stat[7], stat[8]) ?: continue
            val addrTokens = toks.dropLast(9)
            val address = if (addrTokens.size >= 2) addrTokens[0] + ":" + addrTokens.drop(1).joinToString(":")
                          else addrTokens.joinToString(" ")
            out += Endpoint(address, pkts, bytes, txP, txB, rxP, rxB)
        }
        return out.sortedByDescending { it.bytes }
    }

    private fun intTok(s: String): Long? = s.replace(",", "").toLongOrNull()

    /** Parse a "<num> <unit>" byte value (e.g. "7,210 bytes", "1.5 kB") into bytes. */
    private fun bytesTok(num: String, unit: String): Long? {
        val v = num.replace(",", "").toDoubleOrNull() ?: return null
        val mul = when (unit.lowercase()) {
            "bytes", "byte", "b" -> 1.0
            "kb" -> 1_000.0; "kib" -> 1_024.0
            "mb" -> 1_000_000.0; "mib" -> 1_048_576.0
            "gb" -> 1_000_000_000.0; "gib" -> 1_073_741_824.0
            else -> return null   // not a unit word → this wasn't a data row
        }
        return (v * mul).toLong()
    }

    // --- Follow stream --------------------------------------------------------

    /** Resolve the TCP/UDP stream indices a packet belongs to (for Follow Stream). */
    fun streamRefFor(file: File, frameNumber: Long): StreamRef {
        if (!ensureReady()) return StreamRef()
        val args = listOf(
            "-r", file.absolutePath, "-n",
            "-Y", "frame.number==$frameNumber",
            "-T", "fields", "-e", "tcp.stream", "-e", "udp.stream",
            "-E", "separator=/t", "-E", "occurrence=f",
        )
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 30_000)
        val cols = res.stdout.lineSequence().firstOrNull { it.isNotBlank() }?.split("\t") ?: return StreamRef()
        val tcp = cols.getOrNull(0)?.trim()?.toIntOrNull()
        val udp = cols.getOrNull(1)?.trim()?.toIntOrNull()
        return StreamRef(tcpStream = tcp, udpStream = udp)
    }


    /** Values for a user-selected PDML field, keyed by frame number. */
    fun packetFieldValues(file: File, field: String): Map<Long, String> {
        if (!ensureReady() || !field.matches(Regex("[A-Za-z0-9_.-]+"))) return emptyMap()
        val args = mutableListOf("-r", file.absolutePath, "-n")
        args += decryption.optionArgs()
        args += listOf("-T", "fields", "-e", "frame.number", "-e", field,
            "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,")
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 120_000)
        if (!res.ok && res.stdout.isBlank()) return emptyMap()
        return res.stdout.lineSequence().mapNotNull { line ->
            val parts = line.split('\t', limit = 2)
            val number = parts.firstOrNull()?.trim()?.toLongOrNull() ?: return@mapNotNull null
            number to parts.getOrElse(1) { "" }.trim()
        }.filter { it.second.isNotBlank() }.toMap()
    }

    /** Search raw packet bytes/ASCII without retaining payload copies in the analysis cache. */
    fun searchPacketPayload(file: File, query: String, limit: Int = 100): List<CaptureSearchResult> {
        val q = query.trim()
        if (q.length < 2) return emptyList()
        val compactHex = q.replace(Regex("[^0-9A-Fa-f]"), "")
        val isHex = compactHex.length >= 4 && compactHex.length % 2 == 0 &&
            q.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it in " :.-" }
        val filter = if (isHex) {
            "frame contains ${compactHex.chunked(2).joinToString(":")}"
        } else {
            val escaped = q.replace("\\", "\\\\").replace("\"", "\\\"")
            "tcp contains \"$escaped\" || udp contains \"$escaped\" || data contains \"$escaped\""
        }
        val validation = validateFilter(filter)
        if (validation != null) return emptyList()
        return packetList(file, filter).take(limit).map { packet ->
            CaptureSearchResult(SearchEntity.PACKET, "Packet #${packet.number} · ${packet.protocol}",
                "Payload match · ${packet.src} → ${packet.dst} · ${packet.info}",
                "frame.number == ${packet.number}", packet.number)
        }
    }

    /**
     * Follow a stream and reconstruct the conversation (tshark -z follow,...).
     * protocol: tcp | udp | tls | http. index is the tcp/udp stream number.
     *
     * tcp/udp follow straightforwardly. tls/http do not: tshark indexes those by
     * `tls.stream`/`http.stream`, which is a different numbering from the
     * `tcp.stream` index every caller here holds, and they emit only *decrypted*
     * payload — so on a capture with no key log they return an empty body with
     * blank node addresses, which the UI reported as "stream is empty". Attempt
     * them only when a key log is actually loaded, and otherwise fall back to the
     * TCP stream underneath, which is what Wireshark shows for an encrypted
     * conversation.
     */
    fun followStream(file: File, protocol: String, index: Int): FollowStream? {
        if (!ensureReady()) return null
        val proto = protocol.lowercase()
        val needsKeys = proto == "tls" || proto == "http"
        var direct: FollowStream? = null
        if (!needsKeys || decryption.tlsKeylogEnabled) {
            direct = runFollow(file, proto, index)
            if (direct != null && direct.segments.isNotEmpty()) return direct
        }
        if (needsKeys) {
            val tcp = runFollow(file, "tcp", index)
            if (tcp != null && tcp.segments.isNotEmpty()) {
                // Kept short: this is the Follow Stream screen's title, and a longer
                // label wraps and clips. "TCP bytes" is the honest distinction from
                // decrypted TLS payload; the README covers the why.
                return tcp.copy(protocol = "${proto.uppercase()} · TCP bytes")
            }
        }
        return direct
    }

    private fun runFollow(file: File, proto: String, index: Int): FollowStream? {
        val args = mutableListOf("-r", file.absolutePath, "-n", "-q")
        args += decryption.optionArgs()
        args += listOf("-z", "follow,$proto,raw,$index")
        val res = Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 60_000)
        return parseRawFollow(res.stdout, proto.uppercase(), index)
    }

    // --- Export: filtered subset & objects ------------------------------------

    /** Write a new pcapng containing only packets matching the display filter. */
    fun exportFiltered(file: File, displayFilter: String, outFile: File): Boolean {
        if (!ensureReady()) return false
        val args = mutableListOf("-r", file.absolutePath, "-n")
        // Without these a filter over decrypted fields (http2, decrypted tls) selects
        // nothing, so the export would silently come back empty.
        args += decryption.optionArgs()
        if (displayFilter.isNotBlank()) { args += "-Y"; args += displayFilter }
        args += listOf("-w", outFile.absolutePath, "-F", "pcapng")
        Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 120_000)
        return outFile.exists() && outFile.length() > 40
    }

    /**
     * Merge several captures into one timestamp-ordered pcapng.
     *
     * mergecap interleaves by frame time, so captures taken by different tools on
     * the same device — PocketPCAP, AndroidMonitor, ATTA — line up on one timeline
     * and can be read as a single conversation set. Mixed link layers are fine:
     * pcapng carries an interface description per source.
     */
    fun mergeCaptures(inputs: List<File>, outFile: File): Boolean {
        if (inputs.size < 2) return false
        if (!ensureReady()) return false
        val args = mutableListOf("-w", outFile.absolutePath)
        inputs.forEach { args += it.absolutePath }
        Exec.run(bundle.mergecapArgv(args), bundle.env(), timeoutMs = 180_000)
        return outFile.exists() && outFile.length() > 40
    }

    /**
     * Copy a capture with every packet truncated to [snaplen] bytes.
     *
     * Headers survive, payloads do not, so a capture can be handed to someone else
     * for protocol-level review without disclosing what was actually carried. The
     * default keeps Ethernet, IP and TCP/UDP headers plus a little slack.
     */
    fun exportSanitised(file: File, outFile: File, snaplen: Int = 96): Boolean {
        if (!ensureReady()) return false
        Exec.run(
            bundle.editcapArgv(listOf("-s", snaplen.toString(), file.absolutePath, outFile.absolutePath)),
            bundle.env(), timeoutMs = 180_000,
        )
        return outFile.exists() && outFile.length() > 40
    }

    /**
     * Write per-packet comments into a copy of the capture.
     *
     * pcapng carries comments natively and Wireshark shows them, so analyst notes
     * taken here survive the handoff to a desktop instead of staying locked in the
     * app database. editcap takes one `-a frame:comment` per annotated packet.
     */
    fun exportWithComments(file: File, comments: Map<Long, String>, outFile: File): Boolean {
        if (!ensureReady() || comments.isEmpty()) return false
        val args = mutableListOf<String>()
        comments.toSortedMap().forEach { (frame, note) ->
            // Newlines would split the argument; keep each comment on one line.
            args += "-a"
            args += "$frame:${note.replace('\n', ' ').replace('\r', ' ')}"
        }
        args += file.absolutePath
        args += outFile.absolutePath
        Exec.run(bundle.editcapArgv(args), bundle.env(), timeoutMs = 180_000)
        return outFile.exists() && outFile.length() > 40
    }

    /**
     * Reconstruct and export protocol objects (Wireshark: Export Objects).
     * type: http | tftp | smb | imf | dicom. Files land in a fresh subdirectory.
     */
    fun exportObjects(file: File, type: String, outDir: File): List<ExportedObject> {
        if (!ensureReady()) return emptyList()
        outDir.mkdirs()
        val args = mutableListOf("-r", file.absolutePath, "-n", "-q")
        args += decryption.optionArgs()
        args += listOf("--export-objects", "$type,${outDir.absolutePath}")
        Exec.run(bundle.tsharkArgv(args), bundle.env(), timeoutMs = 120_000)
        return outDir.listFiles()?.filter { it.isFile }?.sortedByDescending { it.length() }
            ?.map { ExportedObject(it.name, it.absolutePath, it.length()) } ?: emptyList()
    }


    fun timestamp(): String = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    // --- PDML parsing ---------------------------------------------------------

    /**
     * Parse tshark PDML (Packet Details Markup Language) into a DecodeTree.
     * Each <proto> becomes a top-level node; nested <field> elements become a tree.
     * The `pos`/`size` attributes give byte offsets for hex-view highlighting.
     */
    private fun parsePdml(xml: String): DecodeTree? {
        return try {
            val factory = XmlPullParserFactory.newInstance()
            val parser = factory.newPullParser()
            parser.setInput(xml.reader())

            val roots = mutableListOf<DecodeNode>()
            // Stack of (mutable children list) for the element currently open.
            val stack = ArrayDeque<MutableNode>()
            var inPacket = false

            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.START_TAG -> {
                        when (parser.name) {
                            "packet" -> inPacket = true
                            "proto", "field" -> if (inPacket) {
                                val node = nodeFromAttrs(parser, parser.name == "proto")
                                if (node != null) stack.addLast(node)
                                else stack.addLast(MutableNode("", "", -1, 0, skip = true))
                            }
                        }
                    }
                    XmlPullParser.END_TAG -> {
                        when (parser.name) {
                            "proto", "field" -> if (inPacket && stack.isNotEmpty()) {
                                val done = stack.removeLast()
                                if (!done.skip) {
                                    val built = done.toNode()
                                    val parent = stack.lastOrNull()
                                    if (parent != null) parent.children += built
                                    else roots += built
                                }
                            }
                            "packet" -> inPacket = false
                        }
                    }
                }
                event = parser.next()
            }
            if (roots.isEmpty()) null else DecodeTree(roots)
        } catch (e: Exception) {
            null
        }
    }

    private class MutableNode(
        val label: String,
        val value: String,
        val byteOffset: Int,
        val byteLength: Int,
        val children: MutableList<DecodeNode> = mutableListOf(),
        val skip: Boolean = false,
        val fieldName: String = "",
        val fieldValue: String = "",
        val explanation: String = "",
    ) {
        fun toNode(): DecodeNode = DecodeNode(
            label = label,
            value = value,
            byteOffset = byteOffset,
            byteLength = byteLength,
            children = children,
            isExpanded = false,
            fieldName = fieldName,
            fieldValue = fieldValue,
            explanation = explanation,
        )
    }

    private fun nodeFromAttrs(parser: XmlPullParser, isProto: Boolean): MutableNode? {
        var showname: String? = null
        var name: String? = null
        var show: String? = null
        var pos = -1
        var size = 0
        var hide = false
        for (i in 0 until parser.attributeCount) {
            when (parser.getAttributeName(i)) {
                "showname" -> showname = parser.getAttributeValue(i)
                "name" -> name = parser.getAttributeValue(i)
                "show" -> show = parser.getAttributeValue(i)
                "pos" -> pos = parser.getAttributeValue(i).toIntOrNull() ?: -1
                "size" -> size = parser.getAttributeValue(i).toIntOrNull() ?: 0
                "hide" -> hide = parser.getAttributeValue(i) == "yes"
            }
        }
        if (hide) return MutableNode("", "", -1, 0, skip = true)
        // Skip the synthetic "geninfo" pseudo-proto; "frame" stays.
        if (isProto && name == "geninfo") return MutableNode("", "", -1, 0, skip = true)

        val label = showname ?: name ?: return null
        // For protos the showname already contains the value; for leaf fields keep
        // the raw `show` value as a separate trailing column when it adds info.
        val value = if (isProto) "" else {
            val sv = show ?: ""
            if (sv.isNotBlank() && showname != null && !showname.endsWith(sv)) sv else ""
        }
        // The PDML `name` attribute is the Wireshark display-filter field token
        // (e.g. "tcp.port"); `show` is its current value. Both power the
        // copy-field / apply-as-filter context actions. Skip synthetic names.
        val fieldName = name?.takeIf { it.isNotBlank() && !it.startsWith("_ws.") && it != "expert" } ?: ""
        val fieldValue = show ?: ""
        val explanation = BtExplanations.lookup(name)
        return MutableNode(label, value, pos, size,
            fieldName = fieldName, fieldValue = fieldValue, explanation = explanation)
    }

    // --- hex dump parsing -----------------------------------------------------

    /**
     * Parse `tshark -x` output (offset, 16 hex bytes, ascii) into a byte array.
     * Lines look like:  0000  00 11 22 33 ...   ..."3...
     * Multiple data sources (e.g. reassembled) may appear; we take the first block.
     */
    private fun parseHexDump(text: String): ByteArray? {
        if (text.isBlank()) return null
        val out = ArrayList<Byte>(1500)
        var started = false
        for (raw in text.lineSequence()) {
            val line = raw.trimEnd()
            if (line.isEmpty()) { if (started) break else continue }
            // Expect: 4+ hex offset, two spaces, hex bytes
            val m = HEX_LINE.matchEntire(line) ?: run {
                if (started) return@run null else null
            }
            if (m == null) { if (started) break else continue }
            started = true
            val hexPart = m.groupValues[2]
            for (tok in hexPart.trim().split(" ")) {
                if (tok.length == 2) {
                    tok.toIntOrNull(16)?.let { out.add(it.toByte()) }
                }
            }
        }
        return if (out.isEmpty()) null else out.toByteArray()
    }

    private val HEX_LINE = Regex("""^([0-9a-fA-F]{4,})\s{2}((?:[0-9a-fA-F]{2} ?)+)\s*.*$""")

    private fun colorFor(proto: String): PacketColor = when (proto.uppercase()) {
        "TCP" -> PacketColor.TCP
        "UDP" -> PacketColor.UDP
        "DNS", "MDNS", "LLMNR" -> PacketColor.DNS
        "HTTP", "HTTP2", "HTTP/2", "HTTP3" -> PacketColor.HTTP
        "TLS", "SSL", "TLSV1.2", "TLSV1.3", "QUIC" -> PacketColor.TLS
        "ARP" -> PacketColor.ARP
        "ICMP", "ICMPV6" -> PacketColor.ICMP
        else -> when {
            proto.startsWith("BT", true) || proto.contains("HCI", true) -> PacketColor.BT
            else -> PacketColor.DEFAULT
        }
    }
}

/**
 * Parse `tshark -z follow,<protocol>,raw,<stream>` without losing binary bytes.
 * Each payload line is exact hexadecimal; a leading tab identifies Node 1 traffic.
 */
internal fun parseRawFollow(text: String, protocol: String, index: Int): FollowStream? {
    if (text.isBlank()) return null
    var nodeA = ""
    var nodeB = ""
    var inData = false
    val segments = mutableListOf<StreamSegment>()
    val hexLine = Regex("^[0-9a-fA-F]+$")

    for (line in text.lineSequence()) {
        when {
            line.startsWith("=====") -> if (inData) break
            line.startsWith("Follow:") || line.startsWith("Filter:") -> Unit
            line.startsWith("Node 0:") -> nodeA = line.removePrefix("Node 0:").trim()
            line.startsWith("Node 1:") -> {
                nodeB = line.removePrefix("Node 1:").trim()
                inData = true
            }
            inData -> {
                val rawHex = line.trim()
                if (rawHex.length % 2 != 0 || !hexLine.matches(rawHex)) continue
                val normalized = rawHex.lowercase(Locale.US)
                val bytes = ByteArray(normalized.length / 2) { offset ->
                    normalized.substring(offset * 2, offset * 2 + 2).toInt(16).toByte()
                }
                segments += StreamSegment(
                    fromA = !line.startsWith('\t'),
                    text = String(bytes, Charsets.UTF_8),
                    rawHex = normalized,
                )
            }
        }
    }
    if (nodeA.isEmpty() && segments.isEmpty()) return null
    val rawText = segments.joinToString("\n\n") {
        (if (it.fromA) "▶ " else "◀ ") + it.text
    }
    return FollowStream(protocol, index, nodeA, nodeB, segments, rawText)
}
