package dev.alsatianconsulting.pocketpcap.capture

import android.content.Context
import android.os.Process as AndroidProcess
import dev.alsatianconsulting.pocketpcap.decode.DecodeManager
import dev.alsatianconsulting.pocketpcap.decode.Prefs
import dev.alsatianconsulting.pocketpcap.decode.RootShell
import dev.alsatianconsulting.pocketpcap.model.CaptureFile
import dev.alsatianconsulting.pocketpcap.model.CaptureSession
import dev.alsatianconsulting.pocketpcap.model.CaptureState
import dev.alsatianconsulting.pocketpcap.model.PacketSummary
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Drives live packet capture through the bundled tshark (which uses the bundled
 * dumpcap for the actual capture). tshark writes a canonical pcapng file with -w
 * and simultaneously prints decoded summary rows to stdout (-P -T fields), which
 * we parse live into the packet list. Runs as root via `su`.
 */
class CaptureManager(
    private val context: Context,
    private val decodeManager: DecodeManager,
) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _session = MutableStateFlow<CaptureSession?>(null)
    val session: StateFlow<CaptureSession?> = _session

    private val _captureFiles = MutableStateFlow<List<CaptureFile>>(emptyList())
    val captureFiles: StateFlow<List<CaptureFile>> = _captureFiles

    // Live decoded packets for the current/last capture.
    private val _packets = MutableStateFlow<List<PacketSummary>>(emptyList())
    val packets: StateFlow<List<PacketSummary>> = _packets

    private var captureProcess: Process? = null
    private var statsJob: Job? = null
    private var stdoutJob: Job? = null
    private var stderrJob: Job? = null
    private val liveRows = mutableListOf<PacketSummary>()

    private val prefs = Prefs(context)

    /** App-private storage: the fallback when the chosen output directory will not take a file. */
    val captureDir: File get() = File(prefs.fallbackCaptureDir).apply { mkdirs() }

    /** Where captures are written: Documents/pocketpcap unless the operator chose elsewhere. */
    private fun outputDir(): File = File(prefs.outputDir)

    /**
     * Create the file this capture will be written to.
     *
     * Not a plain `File(dir, name)`, because the default output directory is now the
     * shared Documents/pocketpcap folder, which an app may not simply write into - the
     * file has to be registered with MediaStore first. If that fails for any reason the
     * capture still has to go somewhere, so it falls back to app-private storage rather
     * than failing to start.
     */
    private fun newCaptureFile(name: String): File =
        SharedCaptureStore.newFile(context, outputDir(), name) ?: File(captureDir, name)

    /** Single-interface convenience wrapper. */
    fun start(interfaceName: String, filter: String = "") = start(listOf(interfaceName), filter)

    /**
     * Start a live capture across one or more interfaces simultaneously. tshark
     * accepts repeated -i flags and merges all of them into a single pcapng with
     * per-frame interface tagging, so the multi-interface case needs no extra
     * plumbing beyond the argv.
     */
    fun start(interfaceNames: List<String>, filter: String = "") {
        if (_session.value?.state == CaptureState.RUNNING) return
        val ifaces = interfaceNames.filter { it.isNotBlank() }.distinct()
        if (ifaces.isEmpty()) return
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val tag = if (ifaces.size == 1) ifaces[0] else "multi${ifaces.size}"
        val name = "capture_${tag}_$ts.pcapng"
        _session.value = CaptureSession(
            id = UUID.randomUUID().toString(),
            interfaceName = ifaces.joinToString("+"),
            startTime = System.currentTimeMillis(),
            // Filled in below. Creating the file registers it with MediaStore, which is
            // a content-provider round trip and has no business on the caller's thread.
            outputPath = "",
            filter = filter,
            state = CaptureState.STARTING,
        )
        liveRows.clear()
        _packets.value = emptyList()
        scope.launch {
            val outFile = newCaptureFile(name)
            _session.value = _session.value?.copy(outputPath = outFile.absolutePath)
            runCapture(ifaces, outFile, filter)
        }
    }

    private suspend fun runCapture(ifaces: List<String>, outFile: File, filter: String) {
        if (!decodeManager.ensureReady()) {
            updateState(CaptureState.ERROR); return
        }
        // tshark argv: live capture across N interfaces, write pcapng, print rows.
        val args = mutableListOf<String>()
        ifaces.forEach { args += "-i"; args += it }
        args += listOf(
            "-w", outFile.absolutePath,
            "-n",                 // no name resolution (faster, fewer DNS lookups)
            "-l",                 // line-buffered stdout
            "--print",            // print summaries even though -w is set
        )
        if (filter.isNotBlank()) { args += "-f"; args += filter }
        // Autostop ceilings so a capture left running cannot fill the device.
        // dumpcap enforces these itself, closing the pcapng cleanly at the limit.
        val maxMb = prefs.maxCaptureMb
        if (maxMb > 0) { args += "-a"; args += "filesize:${maxMb * 1024}" }   // -a takes kB
        val maxMinutes = prefs.maxCaptureMinutes
        if (maxMinutes > 0) { args += "-a"; args += "duration:${maxMinutes * 60}" }
        args += DecodeManager.COLUMN_ARGS

        val command = decodeManager.bundle.tsharkCommand(args)
        try {
            captureProcess = RootShell.start(command)
            updateState(CaptureState.RUNNING)
            startStdoutReader(captureProcess!!)
            startStderrReader(captureProcess!!)
            startStatsUpdater(outFile)
            captureProcess?.waitFor()
            if (_session.value?.state == CaptureState.RUNNING) updateState(CaptureState.STOPPED)
        } catch (e: Exception) {
            updateState(CaptureState.ERROR)
        } finally {
            statsJob?.cancel(); stdoutJob?.cancel(); stderrJob?.cancel()
            finalizeFromFile(outFile)
            refreshCaptureFiles()
        }
    }

    private fun startStdoutReader(proc: Process) {
        stdoutJob = scope.launch {
            try {
                proc.inputStream.bufferedReader().forEachLine { line ->
                    decodeManager.parseColumnRow(line)?.let { row ->
                        synchronized(liveRows) {
                            liveRows.add(row)
                            _packets.value = liveRows.toList()
                            _session.value = _session.value?.copy(packetCount = liveRows.size.toLong())
                        }
                    }
                }
            } catch (_: Exception) {}
        }
    }

    private fun startStderrReader(proc: Process) {
        stderrJob = scope.launch {
            try {
                proc.errorStream.bufferedReader().forEachLine { /* drain; tshark status */ }
            } catch (_: Exception) {}
        }
    }

    private fun startStatsUpdater(outFile: File) {
        statsJob = scope.launch {
            while (isActive) {
                delay(1000)
                val size = try { outFile.length() } catch (_: Exception) { 0L }
                _session.value = _session.value?.copy(byteCount = size)
            }
        }
    }

    /** After capture ends, re-decode the saved file to backfill any rows missed live. */
    private fun finalizeFromFile(outFile: File) {
        try {
            claimFiles(listOf(outFile))
            // dumpcap wrote straight to the path, so MediaStore still believes the file
            // is the empty one it created; without this the Files app lists it as 0 B.
            SharedCaptureStore.refresh(context, outFile)
            if (!outFile.exists() || outFile.length() < 40) return
            val rows = decodeManager.packetList(outFile)
            if (rows.size >= liveRows.size && rows.isNotEmpty()) {
                synchronized(liveRows) {
                    liveRows.clear(); liveRows.addAll(rows)
                    _packets.value = liveRows.toList()
                    _session.value = _session.value?.copy(packetCount = rows.size.toLong())
                }
            }
        } catch (_: Exception) {}
    }

    /**
     * Hand root-written capture files back to the app uid.
     *
     * dumpcap runs as root, so the pcapng it creates is owned by root with mode 0600
     * and the app process cannot open it: the file list counted 0 packets and sharing
     * through FileProvider failed. chmod alone does not fix this — the external-storage
     * FUSE layer derives access from ownership — so the file has to be chown'd.
     */
    private fun claimFiles(files: List<File>) {
        if (files.isEmpty()) return
        val uid = AndroidProcess.myUid()
        val paths = files.joinToString(" ") { "'" + it.absolutePath.replace("'", "'\\''") + "'" }
        RootShell.run("chown $uid:$uid $paths 2>/dev/null; chmod 0644 $paths 2>/dev/null", timeoutMs = 10_000)
    }

    /**
     * Signal only this capture's processes.
     *
     * Every capture's tshark and dumpcap carry their unique output path in argv, so
     * matching on it hits exactly this capture. A bare `pgrep tshark` would also match
     * the tshark that DecodeManager runs for analysis — stopping a capture would have
     * killed an in-flight analysis, and pausing one would have frozen it indefinitely.
     */
    private fun signalCapture(signal: String) {
        // Blank until the output file exists. Signalling on it would leave the pattern
        // as a bare "[-]w [^ ]*", which matches every -w on the device.
        val path = _session.value?.outputPath?.takeIf { it.isNotBlank() } ?: return
        // pkill -f matches an ERE against the whole cmdline, so escape the metacharacters
        // in the file name - the dot in ".pcapng" would otherwise be a wildcard.
        val escaped = File(path).name.replace(Regex("""([\\.\[\]{}()*+?^$|])"""), """\\$1""")
        // Anchor on "-w " followed by the path. tshark and dumpcap carry it exactly
        // that way in their argv, but the `su -c "..."` that launches them carries the
        // shell-quoted form ('-w' '/path'), where "-w" is not followed by a space, so
        // the anchor matches the capture processes and not the shell running the signal.
        // Unanchored, this also matched the tshark that DecodeManager runs for analysis:
        // stopping a capture killed an in-flight analysis, and pausing one froze it.
        //
        // "-w" is written as "[-]w" because toybox parses a leading dash as options:
        // `pgrep -f "-w ..."` fails outright with "Unknown option 'w ...'". The pattern
        // is passed after "--" as well, so it can never be read as options either.
        val pattern = "[-]w [^ ]*$escaped".replace("'", "'\\''")
        // pgrep to find them, kill to signal them - deliberately not `pkill`.
        //
        // Verified on a rooted Pixel 7: `su -c "pkill -STOP ..."` leaves its own su
        // chain - the su client, the shell it spawns and Magisk's logging helper -
        // SIGSTOPped, and neither resume nor stop ever releases them, so every pause
        // stranded three stopped root processes until reboot. It is pkill itself, not
        // the pattern: it happens identically with a pattern that matches nothing, and
        // `pgrep` with the very same pattern lists only tshark and dumpcap. Splitting
        // the two steps, so the signal goes out through `kill` with explicit pids,
        // stops exactly the capture and strands nothing.
        val find = "p=${'$'}(pgrep -f -- '$pattern')"
        scope.launch {
            RootShell.run("$find; [ -n \"${'$'}{p}\" ] && kill -$signal ${'$'}{p} 2>/dev/null", timeoutMs = 5_000)
        }
    }

    fun pause() {
        signalCapture("STOP")
        updateState(CaptureState.PAUSED)
    }

    fun resume() {
        signalCapture("CONT")
        updateState(CaptureState.RUNNING)
    }

    fun stop() {
        if (_session.value == null) return
        val outPath = _session.value?.outputPath
        updateState(CaptureState.STOPPING)
        statsJob?.cancel(); stdoutJob?.cancel(); stderrJob?.cancel()
        // A paused capture ignores SIGTERM until it is resumed, so lift SIGSTOP first.
        signalCapture("CONT")
        // SIGTERM so tshark/dumpcap flush and close the pcapng cleanly.
        signalCapture("TERM")
        captureProcess?.destroy()
        captureProcess = null
        updateState(CaptureState.STOPPED)
        scope.launch {
            outPath?.let { finalizeFromFile(File(it)) }
            refreshCaptureFiles()
        }
    }


    fun refreshCaptureFiles() {
        // Scan the app default dir and the chosen output dir. SharedCaptureStore picks
        // the right way to enumerate each: shared storage has to go through MediaStore,
        // because an app has no read access to a shared directory as a directory.
        val dirs = listOf(captureDir, outputDir()).distinctBy { it.absolutePath }
        val found = dirs.flatMap { dir ->
            SharedCaptureStore.listFiles(context, dir)
                .filter { it.extension == "pcapng" || it.extension == "pcap" }
        }.distinctBy { it.absolutePath }

        // A capture that ended while the app was gone leaves its file root-owned;
        // reclaim any such strays in one call before reading them.
        claimFiles(found.filter { !it.canRead() })

        _captureFiles.value = found
            .sortedByDescending { it.lastModified() }
            .map { f ->
                CaptureFile(
                    name = f.name,
                    path = f.absolutePath,
                    sizeBytes = f.length(),
                    createdAt = f.lastModified(),
                    packetCount = CaptureFileScan.countPackets(f),
                )
            }
    }

    private fun updateState(state: CaptureState) {
        _session.value = _session.value?.copy(state = state)
    }

    fun onDestroy() {
        stop()
        scope.cancel()
    }

}
