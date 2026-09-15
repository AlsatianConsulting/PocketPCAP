package dev.alsatianconsulting.pocketpcap.decode

import java.io.BufferedReader
import java.util.concurrent.TimeUnit

/**
 * Runs commands as root via `su -c`.
 *
 * Only the operations that genuinely need privileges come through here: live
 * capture, interface discovery and the radio/DIAG probes. Reading a capture file
 * needs none of that and goes through [Exec] instead.
 */
object RootShell {

    // Apps get a minimal exec PATH (usually just /system/bin), so a bare "su" may
    // not resolve even when root is present. Resolve to an absolute path. Magisk
    // places su differently per device: /system_ext/bin/su on the Pixel 7 (panther),
    // /product/bin/su on the Pixel 5 (redfin).
    private val SU_CANDIDATES = listOf(
        "/system_ext/bin/su",
        "/product/bin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/debug_ramdisk/su",
        "/su/bin/su",
    )

    // The first probe on a fresh install blocks on the Magisk grant dialog until the
    // user taps Grant, so this must allow real human reaction time. Candidates that
    // do not exist throw IOException from start() and cost nothing, so in practice
    // only the one real su binary can ever consume this budget.
    private const val PROBE_TIMEOUT_SEC = 45L

    @Volatile private var cachedSu: String? = null

    // Remember a failed probe too. On a device with no root every candidate has to
    // be tried before giving up, and on an unrooted phone that measured ~15 seconds;
    // without this, every decode, filter and analysis paid it again.
    @Volatile private var probeFailed = false

    /**
     * Resolve a working `su` path by *executing* candidates, not by stat-ing them.
     * On some Pixel 7 SELinux policies an `untrusted_app` may exec `/system_ext/bin/su`
     * yet be denied `stat()` on it, so `File.exists()` wrongly reports it missing.
     * We probe each candidate with `-c id`: the first that launches and returns
     * `uid=0` is cached. Non-existent paths throw IOException on start() and are
     * skipped cheaply. The first working candidate triggers a single Magisk prompt.
     */
    fun suPath(): String {
        cachedSu?.let { return it }
        if (probeFailed) return "su"
        for (cand in SU_CANDIDATES + "su") {
            val out = tryExecId(cand) ?: continue
            if (out.contains("uid=0")) { cachedSu = cand; return cand }
        }
        // Nothing verified root; fall back so callers still attempt (and surface errors).
        probeFailed = true
        return "su"
    }

    /**
     * Whether a working `su` is present, probing at most once per outcome.
     *
     * Callers use this to fail with an explanation rather than letting a raw
     * "Cannot run program su: error=2" reach the UI.
     */
    fun rootAvailable(): Boolean {
        if (cachedSu != null) return true
        if (probeFailed) return false
        suPath()
        return cachedSu != null
    }

    /**
     * Forget a previous probe so the next call re-checks. Sources refresh calls this,
     * so a device that gains root (Magisk installed, or the grant finally approved)
     * is picked up without restarting the app.
     */
    fun resetProbe() {
        cachedSu = null
        probeFailed = false
    }

    /** Run `<cand> -c id` with a generous timeout; null if the binary can't be launched. */
    private fun tryExecId(cand: String): String? {
        return try {
            val proc = ProcessBuilder(cand, "-c", "id").redirectErrorStream(true).start()
            // StringBuffer: written by the drain thread, read by this one after join().
            val out = StringBuffer()
            val t = Exec.drainThread(proc.inputStream, out)
            val finished = proc.waitFor(PROBE_TIMEOUT_SEC, TimeUnit.SECONDS)
            if (!finished) proc.destroyForcibly()
            t.join(1000)
            out.toString()
        } catch (e: Exception) {
            null
        }
    }

    /** Run a shell command string as root and collect all output. */
    fun run(command: String, timeoutMs: Long = 60_000): ProcessResult =
        Exec.run(listOf(suPath(), "-c", command), timeoutMs = timeoutMs)


    /** Quick check whether root is currently grantable. */
    fun hasRoot(): Boolean = run("id", timeoutMs = 10_000).stdout.contains("uid=0")

    /**
     * Start a long-running root command, returning the live Process so the caller
     * can stream stdout (used for live capture). Caller owns the process lifecycle.
     */
    fun start(command: String): Process = Exec.start(listOf(suPath(), "-c", command))

    fun BufferedReader.drainLines(onLine: (String) -> Unit) {
        forEachLine(onLine)
    }
}
