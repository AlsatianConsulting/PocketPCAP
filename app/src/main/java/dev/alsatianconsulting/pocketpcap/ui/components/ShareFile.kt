package dev.alsatianconsulting.pocketpcap.ui.components

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.Toast
import androidx.core.content.FileProvider
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore
import java.io.File

/**
 * Hand a file to the system share sheet through the app's FileProvider.
 *
 * The grant has to reach two places: the chosen target, via the flag on the send
 * intent, and the share sheet itself, which reads the URI to draw its preview and
 * is otherwise denied. clipData plus a flag on the chooser covers both.
 */
fun shareFile(context: Context, path: String, title: String? = null) {
    // Report failures. Swallowing them hid a real bug for a whole release cycle:
    // exports/ was missing from file_paths.xml, so getUriForFile threw for every
    // analysis-table and map export and the share sheet simply never appeared,
    // with nothing in the log and a success message already on screen.
    try {
        val file = File(path)
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.provider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = SharedCaptureStore.mimeFor(file.name)
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newRawUri(file.name, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(intent, title ?: "Share ${file.name}")
        chooser.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(chooser)
    } catch (e: Exception) {
        Log.w("ShareFile", "Could not share $path", e)
        Toast.makeText(context, "Could not share that file: ${e.message}", Toast.LENGTH_LONG).show()
    }
}
