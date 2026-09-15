package dev.alsatianconsulting.pocketpcap.storage

import android.content.ContentValues
import android.content.Context
import android.media.MediaScannerConnection
import android.os.Build
import android.provider.MediaStore
import java.io.File

/**
 * Puts captures and exports in `Documents/pocketpcap`, where a person can actually
 * find them.
 *
 * The obvious implementation - `File("/sdcard/Documents/pocketpcap").mkdirs()` - does
 * not work. Under scoped storage an app cannot create a directory in shared storage,
 * and this was confirmed rather than assumed: on a stock unrooted Android 16 image the
 * app uid gets EACCES for both the mkdir and the write. The only ways around that are
 * MANAGE_EXTERNAL_STORAGE, which is a Play restricted permission this app has no case
 * for, and MediaStore, which needs no permission at all.
 *
 * So every file here is registered with MediaStore first. That creates the directory
 * and an empty file and records this app as its `owner_package_name`, which is what
 * then allows ordinary `File` reads and writes on the real path - the FUSE layer over
 * shared storage grants an app full access to what it owns. Note this is MediaStore
 * ownership, not POSIX: on device the file's uid stays MediaProvider's, and chasing
 * `ls -l` output rather than `owner_package_name` will mislead. Handing back a real
 * path matters: the rooted capture path passes it to dumpcap as an argv, dumpcap
 * cannot write to a content:// URI, and tshark, editcap and mergecap all read and
 * write the same way.
 *
 * This is not limited to the default folder. The operator can point the output
 * directory anywhere, so [newFile] and [listFiles] take the directory and decide per
 * call: anything MediaStore can address goes through MediaStore, and anything else -
 * app-private storage above all - is an ordinary mkdir and an ordinary file.
 *
 * Ownership is the limit of all this. Files another app wrote into the same folder are
 * not ours and stay unreadable without the picker, which is what the Open action is
 * for, and an uninstall drops ownership of everything left behind.
 */
object SharedCaptureStore {

    /** Folder name under Documents/, and the default output directory. */
    const val FOLDER = "pocketpcap"

    /**
     * Whether shared storage is worth using on this device at all.
     *
     * The whole design rests on a MediaStore-owned file also being an ordinary
     * writable file, and that is an Android 11 rule. Android 10 - this app's minSdk -
     * blocks direct file-path access to shared storage outright, so there the row
     * would be created, the empty file would appear, and dumpcap would then get EACCES
     * writing to it. Nothing to gain, so everything stays in app-private storage.
     */
    val available: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    /**
     * Where the files live by default, as a plain path.
     *
     * This is only a path, not a promise that it exists or is writable: nothing is
     * created until [newFile] registers something. Callers that need the directory to
     * exist should create a file in it.
     */
    fun directory(): File = File(File(primaryRoot(), DOCUMENTS), FOLDER)

    /** App-private subdirectories, named once so they cannot drift apart. */
    const val CAPTURES = "captures"
    const val LOGS = "logs"

    /**
     * An app-private output directory: the fallback wherever shared storage cannot be
     * used, and where the diagnostics collector writes.
     *
     * Spelled out here rather than at each call site because the capture list scans
     * [CAPTURES] and several components write into it, and until this existed they
     * agreed only by all happening to build the same path by hand.
     */
    fun privateDir(context: Context, name: String): File =
        File(context.getExternalFilesDir(null), name)

    /**
     * Create [name] in [dir] and return the real path to write to, or null if it could
     * not be created and the caller should fall back somewhere else.
     *
     * Shared storage is registered with MediaStore; anywhere else is a plain mkdir.
     */
    fun newFile(context: Context, dir: File, name: String, mime: String = mimeFor(name)): File? {
        val target = mediaTargetFor(dir) ?: return plainFile(dir, name)
        // Reusing a row we can no longer write - a capture file left root-owned, say -
        // would be worse than not reusing it, and inserting again would only produce
        // "name (1)". Hand the caller its fallback instead.
        existingPath(context, target, name)?.let { return it.takeIf(::opensForWriting) }
        return try {
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, name)
                put(MediaStore.MediaColumns.MIME_TYPE, mime)
                put(MediaStore.MediaColumns.RELATIVE_PATH, target.relativePath)
            }
            val uri = context.contentResolver.insert(collection(target), values) ?: return null
            // Materialise it. The insert only creates the MediaStore row; until the
            // file is opened through the resolver once it does not exist on disk, and
            // opening the path directly then fails with EEXIST - a row is there, but
            // the app is not allowed to create the file behind it. One empty write
            // through the resolver settles that, and from then on it is an ordinary
            // file the app owns.
            context.contentResolver.openOutputStream(uri, "w")?.close()
            // Read the path back rather than assuming it: MediaStore is entitled to
            // put the file somewhere else, and a guessed path would fail at write time.
            val path = pathOf(context, uri) ?: File(dir, name).takeIf { it.exists() }
            if (path == null || !opensForWriting(path)) {
                // Leave nothing behind for the fallback to trip over.
                runCatching { context.contentResolver.delete(uri, null, null) }
                null
            } else {
                path
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Prove the path can be written before handing it to a caller that cannot fail
     * gracefully.
     *
     * [available] rules out the one version where this is known not to work, but that
     * is a claim about the platform, not about this device and this volume. Without
     * the check the MediaStore row and its empty file look like success right up until
     * dumpcap gets EACCES, and the operator is left with a capture that ran and
     * produced nothing. Appending zero bytes changes nothing and settles the question.
     *
     * The retry is not defensive padding. Reusing a name that was just deleted was
     * observed failing here with EACCES on a file that existed and that MediaStore
     * already named us the owner of: the FUSE layer over shared storage caches its
     * per-uid access decision per path, and the decision for the deleted file outlives
     * it by a moment. One transient denial must not send a capture to the fallback
     * directory for good, so give the cache a brief chance to catch up - while a path
     * that genuinely cannot be written still fails out and still falls back.
     */
    private fun opensForWriting(file: File): Boolean {
        repeat(WRITE_PROBE_ATTEMPTS) { attempt ->
            try {
                java.io.FileOutputStream(file, true).close()
                return true
            } catch (e: Exception) {
                if (attempt == WRITE_PROBE_ATTEMPTS - 1) return false
                try {
                    Thread.sleep(WRITE_PROBE_BACKOFF_MS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        }
        return false
    }

    /**
     * Whether this app can create files in [dir] at all.
     *
     * Shared storage works only where MediaStore can address it, and app-private
     * storage always works. Anywhere else - a folder the operator invented at the top
     * of the volume, say - is refused by the OS, and [newFile] returns null there so
     * the caller falls back. Settings asks this so the fallback is not a surprise.
     */
    fun canWrite(context: Context, dir: File): Boolean {
        if (mediaTargetFor(dir) != null) return true
        val path = dir.absolutePath
        return privateRoots(context).any { path == it || path.startsWith("$it/") }
    }

    /** Every capture-shaped file this app owns in [dir], however that directory works. */
    fun listFiles(context: Context, dir: File): List<File> {
        val target = mediaTargetFor(dir)
            ?: return dir.listFiles()?.toList().orEmpty()
        // An app has no read access to a shared directory as a directory, only to the
        // files in it that it owns, so listFiles() there finds nothing however many
        // captures are sitting in it. MediaStore is the only way to enumerate them.
        return try {
            context.contentResolver.query(
                collection(target), arrayOf(MediaStore.MediaColumns.DATA),
                "${MediaStore.MediaColumns.RELATIVE_PATH} IN (?, ?)",
                target.relativePathForms, null,
            )?.use { c ->
                generateSequence { if (c.moveToNext()) c.getString(0) else null }
                    .map(::File).filter { it.isFile }.toList()
            }.orEmpty()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Drop the MediaStore row for [file], if it has one.
     *
     * Deleting the file on its own leaves the row behind, and MediaStore then hands the
     * next capture of the same name a "(1)" suffix instead of the name it asked for.
     */
    fun forget(context: Context, file: File) {
        val target = mediaTargetFor(File(file.parent ?: return)) ?: return
        try {
            context.contentResolver.delete(
                collection(target),
                "${MediaStore.MediaColumns.DATA} = ?", arrayOf(file.absolutePath),
            )
        } catch (_: Exception) {
        }
    }

    /**
     * Tell MediaStore the file has changed size.
     *
     * Captures are written by dumpcap or by the tunnel recorder straight to the path,
     * and exports by an ordinary `writeText`, all behind MediaStore's back. Without
     * this the Files app lists every one of them as 0 bytes until something else
     * triggers a scan. Harmless on a file MediaStore does not track.
     */
    fun refresh(context: Context, file: File) {
        try {
            MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
        } catch (_: Exception) {
        }
    }

    /**
     * MIME type for a file name, which MediaStore needs and is stricter about than it
     * looks: given a type that disagrees with the extension it appends the one it
     * would have chosen, so `capture.pcapng` declared as `text/csv` lands on disk as
     * `capture.pcapng.csv` and the caller writes to a path nobody asked for.
     */
    fun mimeFor(name: String): String = when (name.substringAfterLast('.', "").lowercase()) {
        "csv" -> "text/csv"
        "json", "geojson" -> "application/json"
        "kml" -> "application/vnd.google-earth.kml+xml"
        "txt", "log" -> "text/plain"
        else -> "application/octet-stream"
    }

    // ---- directory classification -------------------------------------------

    /** A directory MediaStore can address: which volume, and the path within it. */
    internal data class Target(val volume: String, val relativePath: String) {
        /**
         * MediaStore stores RELATIVE_PATH with a trailing separator, but has not
         * always, and a query that guesses wrong silently returns nothing. Match both.
         */
        val relativePathForms: Array<String>
            get() = arrayOf(relativePath, relativePath.trimEnd('/'))
    }

    /**
     * Classify [path], or null when MediaStore cannot address it and it has to be
     * treated as an ordinary directory.
     *
     * MediaStore only accepts a RELATIVE_PATH under one of the standard shared-storage
     * folders, so `/storage/emulated/0/Documents/pocketpcap` qualifies and both
     * `/storage/emulated/0/Android/data/<pkg>/files/captures` and a folder the operator
     * invented at the top level do not - which is the correct answer for the first,
     * since app-private storage is writable directly.
     */
    internal fun targetFor(path: String): Target? {
        val clean = path.trimEnd('/')
        val volume: String
        val rel: String
        val primary = PRIMARY_ROOT.matchEntire(clean)
        if (primary != null) {
            // Emulated storage is per-user: the owner is 0, a secondary or work profile
            // is some other number, and either way it is the primary external volume
            // from inside that user.
            volume = MediaStore.VOLUME_EXTERNAL_PRIMARY
            rel = primary.groupValues[1]
        } else {
            // A removable volume is named after its UUID, lowercased. The document-tree
            // picker resolves such a folder to /storage/XXXX-XXXX/..., so it can reach
            // here; an insert against a volume that has since been unmounted throws and
            // the caller falls back.
            val match = REMOVABLE_ROOT.matchEntire(clean) ?: return null
            volume = match.groupValues[1].lowercase()
            rel = match.groupValues[2]
        }
        val segments = rel.split('/').filter { it.isNotEmpty() }
        if (segments.firstOrNull() !in MEDIA_DIRS) return null
        if (segments.any { it == "." || it == ".." }) return null
        return Target(volume, segments.joinToString("/", postfix = "/"))
    }

    // ---- internals -----------------------------------------------------------

    private const val DOCUMENTS = "Documents"
    private const val OWNER_ROOT = "/storage/emulated/0"

    /**
     * Budget for the write probe: four tries 40 ms apart, so a stale FUSE decision has
     * ~120 ms to clear. Short on purpose - the rootless VPN service creates its file on
     * the main thread, and this is the only path that ever sleeps.
     */
    private const val WRITE_PROBE_ATTEMPTS = 4
    private const val WRITE_PROBE_BACKOFF_MS = 40L
    private val PRIMARY_ROOT = Regex("""/storage/emulated/\d+(/.*)?""")
    private val REMOVABLE_ROOT = Regex("""/storage/([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})(/.*)?""")

    /**
     * The top-level directories MediaStore will file something under. Spelled out
     * rather than read from `Environment`, so the classification above is plain string
     * arithmetic that a JVM unit test can exercise without a device.
     */
    private val MEDIA_DIRS = setOf(
        "Documents", "Download", "DCIM", "Pictures", "Movies", "Music",
        "Alarms", "Audiobooks", "Notifications", "Podcasts", "Ringtones", "Recordings",
    )

    /**
     * The external storage root for the user the app is running as. The constant is
     * only a fallback: it is right for the device owner, and `Environment` is right
     * for everyone, but `Environment` is unavailable off-device.
     */
    private fun primaryRoot(): File =
        runCatching { android.os.Environment.getExternalStorageDirectory() }
            .getOrNull() ?: File(OWNER_ROOT)

    /** The MediaStore target for [dir], or null if it should be treated as an ordinary directory. */
    private fun mediaTargetFor(dir: File): Target? =
        if (available) targetFor(dir.absolutePath) else null

    private fun collection(target: Target) = MediaStore.Files.getContentUri(target.volume)

    /**
     * Directories the app owns outright, on every volume the device offers - the
     * removable-card copy of Android/data counts as much as the built-in one.
     */
    private fun privateRoots(context: Context): List<String> = buildList {
        add(context.filesDir.absolutePath)
        context.getExternalFilesDirs(null).forEach { it?.let { dir -> add(dir.absolutePath) } }
    }

    private fun plainFile(dir: File, name: String): File? = try {
        dir.mkdirs()
        File(dir, name).takeIf { it.parentFile?.isDirectory == true }
    } catch (e: Exception) {
        null
    }

    /**
     * Reuse an existing row for the same name rather than duplicating it, because
     * MediaStore would otherwise hand back "name (1)" and the caller would write
     * somewhere it did not ask for.
     */
    private fun existingPath(context: Context, target: Target, name: String): File? = try {
        context.contentResolver.query(
            collection(target), arrayOf(MediaStore.MediaColumns.DATA),
            "${MediaStore.MediaColumns.RELATIVE_PATH} IN (?, ?) AND " +
                "${MediaStore.MediaColumns.DISPLAY_NAME} = ?",
            target.relativePathForms + name, null,
        )?.use { c ->
            if (c.moveToFirst()) c.getString(0)?.let(::File)?.takeIf { it.exists() } else null
        }
    } catch (e: Exception) {
        null
    }

    private fun pathOf(context: Context, uri: android.net.Uri): File? = try {
        context.contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.DATA), null, null, null)
            ?.use { c -> if (c.moveToFirst()) c.getString(0)?.let(::File) else null }
    } catch (e: Exception) {
        null
    }
}
