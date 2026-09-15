package dev.alsatianconsulting.pocketpcap.decode

import java.io.InputStream
import java.util.concurrent.TimeUnit

/** Outcome of running a child process. */
data class ProcessResult(val exitCode: Int, val stdout: String, val stderr: String) {
    val ok: Boolean get() = exitCode == 0
}

/**
 * Runs child processes directly, with no shell and no root.
 *
 * This is the path used for everything that only reads a capture file: decoding,
 * analysis, filtering, follow-stream and object export. Those need no privileges
 * at all, only the ability to execute the bundled tshark, which comes from
 * shipping it in the APK's native library directory rather than app storage.
 *
 * [RootShell] builds on this for the operations that genuinely do need root, which
 * is live capture: dumpcap needs CAP_NET_RAW to open an interface.
 */
object Exec {

    fun run(
        argv: List<String>,
        env: Map<String, String> = emptyMap(),
        timeoutMs: Long = 60_000,
    ): ProcessResult {
        return try {
            val builder = ProcessBuilder(argv)
            builder.environment().putAll(env)
            val proc = builder.start()
            val out = StringBuffer()
            val err = StringBuffer()
            val tOut = drainThread(proc.inputStream, out)
            val tErr = drainThread(proc.errorStream, err)
            val finished = proc.waitFor(timeoutMs / 1000 + 1, TimeUnit.SECONDS)
            if (!finished) proc.destroyForcibly()
            tOut.join(2000); tErr.join(2000)
            ProcessResult(if (finished) proc.exitValue() else -1, out.toString(), err.toString())
        } catch (e: Exception) {
            ProcessResult(-1, "", e.message ?: "could not run ${argv.firstOrNull()}")
        }
    }

    /** Start a long-running child; the caller owns its lifecycle and streams. */
    fun start(argv: List<String>, env: Map<String, String> = emptyMap()): Process {
        val builder = ProcessBuilder(argv)
        builder.environment().putAll(env)
        return builder.start()
    }

    /**
     * Drain one process stream into [sink] on a daemon thread.
     *
     * The catch is load-bearing. When a timeout calls `destroyForcibly()` the pipe
     * is closed underneath this thread and the pending read throws here; a bare
     * Thread has no uncaught handler, so that exception would reach Android's
     * default handler and kill the process.
     */
    fun drainThread(stream: InputStream, sink: StringBuffer): Thread {
        val t = Thread {
            try {
                stream.bufferedReader().forEachLine { sink.append(it).append('\n') }
            } catch (_: Exception) {
                // Stream closed or interrupted; whatever was read already stands.
            }
        }
        t.isDaemon = true
        t.start()
        return t
    }
}
