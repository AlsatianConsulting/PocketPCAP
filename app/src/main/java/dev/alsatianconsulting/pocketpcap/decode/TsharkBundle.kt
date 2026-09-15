package dev.alsatianconsulting.pocketpcap.decode

import android.content.Context
import java.io.File
import java.util.zip.ZipInputStream

/**
 * Locates the bundled Termux aarch64 build of tshark/dumpcap (the full Wireshark
 * dissector engine) and the Wireshark data files it needs.
 *
 * The split matters. Android refuses to execute a file an app wrote into its own
 * storage, but it does allow executing files in the app's native library
 * directory, which the installer populates from the APK. So the executables and
 * every shared library they load ship as jniLibs, renamed to `lib*.so` because
 * that is the only pattern the installer extracts (see scripts/jnilib-name.py).
 * That is what lets decoding and analysis work with no root at all.
 *
 * Wireshark's data files under `share/wireshark` are read, never executed, so
 * they stay in assets and are unpacked to private storage on first use.
 *
 * Live capture still needs root, because dumpcap needs CAP_NET_RAW to open an
 * interface. That path goes through [RootShell]; everything that only reads a
 * capture file goes through [Exec].
 */
class TsharkBundle(private val context: Context) {

    companion object {
        private const val ASSET = "tshark-prefix.zip"

        /**
         * The Wireshark release the bundle is built from, for anything that reports it.
         *
         * Single source of truth on purpose: the 4.6.8 rebuild left every string in the
         * app, the README and the notices claiming 4.6.6, which is both wrong in the UI
         * and wrong in a licence notice that names the version it is offering source for.
         */
        const val WIRESHARK_VERSION = "4.6.8"

        /**
         * Bump when the bundled data changes so devices re-extract.
         *
         * This must track [WIRESHARK_VERSION]. It did not for 4.6.8: the stamp still
         * read 4.6.6, so any device that already had the app kept its 4.6.6 data files
         * and ran the new 4.6.8 binaries against them.
         */
        private const val VERSION = "tshark-$WIRESHARK_VERSION-1-data"
        private const val STAMP = ".version"
    }

    /** Where the installer put the executables and their libraries. */
    val nativeDir: File get() = File(context.applicationInfo.nativeLibraryDir)

    val tshark: File get() = File(nativeDir, "libtshark.so")
    val dumpcap: File get() = File(nativeDir, "libdumpcap.so")
    val tcpdump: File get() = File(nativeDir, "libtcpdump.so")
    val editcap: File get() = File(nativeDir, "libeditcap.so")
    val mergecap: File get() = File(nativeDir, "libmergecap.so")

    /** Extracted Wireshark data files (dissector tables, MIBs, profiles). */
    val root: File get() = File(context.filesDir, "tshark")
    val dataDir: File get() = File(root, "share/wireshark")

    /**
     * Copies of the two executables under their real names, for rooted live capture.
     *
     * tshark launches dumpcap by looking for a file literally called `dumpcap` beside
     * its own binary, resolved through /proc/self/exe. In the native library directory
     * that sibling is `libdumpcap.so`, so live capture failed with "Couldn't run
     * dumpcap in child process". Symlinks do not help, because /proc/self/exe follows
     * them back to the real path. Root is exempt from the no-exec rule on app storage
     * — that is what the old design relied on — so the rooted capture path runs a copy
     * from here instead. Only the two executables are duplicated, about 1.7 MB; the
     * shared libraries are still loaded from the native directory via LD_LIBRARY_PATH.
     */
    val captureBinDir: File get() = File(root, "bin")

    /** True when tshark is present and executable without any privilege. */
    fun isExecutable(): Boolean = tshark.canExecute()

    fun isExtracted(): Boolean {
        val stamp = File(root, STAMP)
        return dataDir.isDirectory && stamp.exists() && stamp.readText().trim() == VERSION
    }

    /** Unpack the data files if missing or out of date. Returns true on success. */
    @Synchronized
    fun ensureExtracted(): Boolean {
        if (isExtracted()) return true
        return try {
            if (root.exists()) root.deleteRecursively()
            root.mkdirs()
            context.assets.open(ASSET).use { input ->
                ZipInputStream(input.buffered()).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        val outFile = File(root, entry.name)
                        // Guard against zip path traversal
                        if (!outFile.canonicalPath.startsWith(root.canonicalPath)) {
                            entry = zis.nextEntry; continue
                        }
                        if (entry.isDirectory) {
                            outFile.mkdirs()
                        } else {
                            outFile.parentFile?.mkdirs()
                            outFile.outputStream().buffered().use { zis.copyTo(it) }
                        }
                        entry = zis.nextEntry
                    }
                }
            }
            File(root, STAMP).writeText(VERSION)
            dataDir.isDirectory
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Place `tshark` and `dumpcap` under their real names for the rooted capture
     * path. Re-copies whenever the packaged binary differs in size, so an app update
     * refreshes them. Returns false if the copies could not be made.
     */
    @Synchronized
    fun ensureCaptureBinaries(): Boolean {
        return try {
            captureBinDir.mkdirs()
            copyIfStale(tshark, File(captureBinDir, "tshark")) &&
                copyIfStale(dumpcap, File(captureBinDir, "dumpcap"))
        } catch (e: Exception) {
            false
        }
    }

    private fun copyIfStale(source: File, target: File): Boolean {
        if (!source.exists()) return false
        if (!target.exists() || target.length() != source.length()) {
            source.inputStream().use { input ->
                target.outputStream().use { input.copyTo(it) }
            }
        }
        target.setExecutable(true, false)
        target.setReadable(true, false)
        return target.exists()
    }

    /** Environment every tshark/dumpcap invocation needs, however it is launched. */
    fun env(): Map<String, String> = mapOf(
        "LD_LIBRARY_PATH" to nativeDir.absolutePath,
        "WIRESHARK_DATA_DIR" to dataDir.absolutePath,
        "HOME" to root.absolutePath,
        "TMPDIR" to context.cacheDir.absolutePath,
    )

    /** argv for running tshark directly, with no shell and no root. */
    fun tsharkArgv(args: List<String>): List<String> =
        listOf(tshark.absolutePath) + args

    /** argv for editcap: trimming, truncating and annotating an existing file. */
    fun editcapArgv(args: List<String>): List<String> =
        listOf(editcap.absolutePath) + args

    /** argv for mergecap: combining captures into one timestamp-ordered file. */
    fun mergecapArgv(args: List<String>): List<String> =
        listOf(mergecap.absolutePath) + args

    /**
     * The same invocation as a `su -c` shell command string, for the rooted live
     * capture path where dumpcap needs privileges the app does not have. Runs the
     * copy from [captureBinDir] so tshark can find dumpcap beside itself.
     */
    fun tsharkCommand(args: List<String>): String {
        ensureCaptureBinaries()
        val binary = File(captureBinDir, "tshark")
        return env().entries.joinToString("") { (k, v) -> "$k=${shellQuote(v)} " } +
            shellQuote(binary.absolutePath) + " " + args.joinToString(" ") { shellQuote(it) }
    }

    private fun shellQuote(s: String): String =
        if (s.isEmpty()) "''" else "'" + s.replace("'", "'\\''") + "'"
}
